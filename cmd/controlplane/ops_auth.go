package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/example/lanyard/internal/awssecrets"
	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/opsstore"
	"github.com/example/lanyard/internal/staffsso"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pkceEntry stores the verifier and expiration for a PKCE flow.
type pkceEntry struct {
	verifier string
	expires  time.Time
}

// pkceStore holds a map of state->verifier entries with a mutex.
type pkceStore struct {
	mu      sync.Mutex
	entries map[string]pkceEntry
}

var opsPKCEStore = pkceStore{entries: map[string]pkceEntry{}}

// storePKCE saves a verifier under a state token for a short time.
func (s *pkceStore) storePKCE(state, verifier string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[state] = pkceEntry{verifier: verifier, expires: time.Now().Add(ttl)}
}

// retrieveAndDeletePKCE returns the verifier for a state and removes the entry.
func (s *pkceStore) retrieveAndDeletePKCE(state string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[state]
	if !ok || time.Now().After(entry.expires) {
		delete(s.entries, state)
		return "", false
	}
	delete(s.entries, state)
	return entry.verifier, true
}

// randomString generates a URL-safe base64 string of length >= 43.
func randomString(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// pkceChallenge returns the SHA256 base64url-encoded challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// opsAPI implements the Ops console endpoints.
type opsAPI struct {
	pool     *pgxpool.Pool
	store    *opsstore.Store
	cfg      config.Config
	verifier *staffsso.Verifier
	logger   *slog.Logger
	// httpClient for token exchange (can be nil for default)
	httpClient *http.Client
}

// authLogin initiates the PKCE login flow.
func (a *opsAPI) authLogin(w http.ResponseWriter, r *http.Request) {
	// Generate PKCE verifier and challenge.
	verifier, err := randomString(32) // yields >=43 chars after base64url encoding
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "generate pkce verifier"})
		return
	}
	challenge := pkceChallenge(verifier)
	// Generate state token.
	state, err := randomString(16)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "generate state"})
		return
	}
	// Store verifier keyed by state for later callback.
	opsPKCEStore.storePKCE(state, verifier, 5*time.Minute)

	// Build redirect URI for Cognito callback.
	redirectURI := staffsso.RedirectURI(a.cfg.OpsPublicBaseURL)
	// Load Cognito config from secret.
	cfg, err := loadCognitoConfigFn(r.Context(), a.cfg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	authURL, err := cfg.AuthorizeURL(redirectURI, state, challenge)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "build authorize url"})
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// loadCognitoConfig reads the secret and parses it.

var loadCognitoConfigFn = loadCognitoConfig

func loadCognitoConfig(ctx context.Context, cfg config.Config) (staffsso.Config, error) {
	if cfg.CognitoSecretARN == "" {
		return staffsso.Config{}, errors.New("cognito secret ARN not configured")
	}
	secReader, err := awssecrets.NewFromEnv(ctx, cfg.AWSRegion)
	if err != nil {
		return staffsso.Config{}, fmt.Errorf("load secrets manager client: %w", err)
	}
	raw, err := secReader.String(ctx, cfg.CognitoSecretARN)
	if err != nil {
		return staffsso.Config{}, fmt.Errorf("read cognito secret: %w", err)
	}
	return staffsso.ParseConfig([]byte(raw))
}

// authCallback handles the Cognito redirect with code and state.
func (a *opsAPI) authCallback(w http.ResponseWriter, r *http.Request) {
	// Expect query params: code, state
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing code or state"})
		return
	}
	verifier, ok := opsPKCEStore.retrieveAndDeletePKCE(state)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid state"})
		return
	}
	// Load Cognito configuration.
	cfg, err := loadCognitoConfigFn(r.Context(), a.cfg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	redirectURI := staffsso.RedirectURI(a.cfg.OpsPublicBaseURL)
	// Exchange code for ID token.
	client := a.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	idToken, err := staffsso.ExchangeCode(r.Context(), client, cfg, redirectURI, code, verifier)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "code exchange failed"})
		return
	}
	// Verify ID token.
	identity, err := a.verifier.Verify(r.Context(), idToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
		return
	}
	// Ensure staff group membership.
	if cfg.StaffGroup != "" && !contains(identity.Groups, cfg.StaffGroup) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "staff group required"})
		return
	}
	// Provision or fetch member.
	member, err := a.store.ProvisionMember(r.Context(), identity.Email, identity.Subject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "member provisioning failed"})
		return
	}
	// Create session token.
	token, err := newSessionToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "session token"})
		return
	}
	// Store session.
	if err := a.store.CreateSession(r.Context(), hashValue(token), member.ID, time.Now().Add(a.cfg.SessionTTL), identity.HardwareKey); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "create session"})
		return
	}
	// Set cookie.
	secure := strings.EqualFold(schemeOf(a.cfg.OpsPublicBaseURL), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(a.cfg.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
	// Respond with session info.
	writeJSON(w, http.StatusOK, map[string]any{"email": identity.Email, "role": member.Role, "hardware_key": identity.HardwareKey})
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// authMe returns the current session information.
func (a *opsAPI) authMe(w http.ResponseWriter, r *http.Request) {
	sess, ok := getOpsSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not signed in"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"email": sess.Email, "role": sess.Role, "hardware_key": sess.HardwareKey})
}

// authLogout clears the session cookie and ends the session.
func (a *opsAPI) authLogout(w http.ResponseWriter, r *http.Request) {
	// Clear cookie.
	secure := strings.EqualFold(schemeOf(a.cfg.OpsPublicBaseURL), "https")
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode})
	// End session if cookie present.
	if cookie, err := r.Cookie(sessionCookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		a.store.EndSession(r.Context(), hashValue(cookie.Value))
	}
	w.WriteHeader(http.StatusNoContent)
}

// opsSessionMiddleware validates session cookies using opsstore.
func opsSessionMiddleware(store *opsstore.Store, cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ops/auth/login", staffsso.CallbackPath, "/ops/auth/logout", "/ops/health":
				next.ServeHTTP(w, r)
				return
			}

			cookie, err := r.Cookie(sessionCookieName)
			if err != nil || strings.TrimSpace(cookie.Value) == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
				return
			}
			sess, ok, err := store.GetSession(r.Context(), hashValue(cookie.Value), cfg.SessionIdle)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid session"})
				return
			}
			// attach to context for downstream handlers.
			ctx := context.WithValue(r.Context(), "opsSession", sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// getOpsSession extracts the session from request context.
func getOpsSession(r *http.Request) (opsstore.Session, bool) {
	s, ok := r.Context().Value("opsSession").(opsstore.Session)
	return s, ok
}
