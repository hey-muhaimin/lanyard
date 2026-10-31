package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/example/lanyard/internal/authstore"
	"github.com/example/lanyard/internal/config"
)

const (
	sessionCookieName = "lanyard_session"
	loginCodeTTL      = 10 * time.Minute
	loginCodeDigits   = 6
	sessionTokenBytes = 32
)

// authStore is the narrow surface the handler needs; tests substitute a fake.
type authStore interface {
	RequestCode(ctx context.Context, email string, codeHash []byte, expires time.Time) (bool, error)
	VerifyCode(ctx context.Context, email string, codeHash []byte) (authstore.Member, bool, error)
	CreateSession(ctx context.Context, tokenHash []byte, memberID string, expires time.Time) error
	GetSession(ctx context.Context, tokenHash []byte, idle time.Duration) (authstore.Session, bool, error)
	EndSession(ctx context.Context, tokenHash []byte) error
	CreateTenantWithAdmin(ctx context.Context, tenantName, email, role string) (string, error)
}

// authPrincipal is the frozen Principal shape returned to the console.
type authPrincipal struct {
	TenantID string `json:"tenant_id"`
	MemberID string `json:"member_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

type authHandler struct {
	store        authStore
	cfg          config.Config
	logger       *slog.Logger
	origin       string
	secureCookie bool
	mux          *http.ServeMux
}

// newAuthHandler builds the /auth/* handler. It is mounted by the control plane
// at "/auth/" for both demo and production.
func newAuthHandler(store authStore, cfg config.Config, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &authHandler{
		store:        store,
		cfg:          cfg,
		logger:       logger,
		origin:       originOf(cfg.PublicBaseURL),
		secureCookie: strings.EqualFold(schemeOf(cfg.PublicBaseURL), "https"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/request", h.handleRequest)
	mux.HandleFunc("POST /auth/verify", h.handleVerify)
	mux.HandleFunc("GET /auth/me", h.handleMe)
	mux.HandleFunc("POST /auth/logout", h.handleLogout)
	mux.HandleFunc("POST /auth/register", h.handleRegister)
	h.mux = mux
	return h
}

// newAuthLogger returns the JSON logger the auth handler writes to.
func newAuthLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, nil))
}

// authUnavailableHandler is mounted when the control plane has no database.
func authUnavailableHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "authentication requires a database"})
	})
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodPost, http.MethodPatch, http.MethodDelete:
		if origin := r.Header.Get("Origin"); origin != "" && !strings.EqualFold(origin, h.origin) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "origin not allowed"})
			return
		}
	}
	h.mux.ServeHTTP(w, r)
}

// handleRequest always answers 202 so callers cannot enumerate members, throttle
// state, or database failures.
func (h *authHandler) handleRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	body := map[string]any{"status": "ok"}
	if email := normalizeEmail(req.Email); email != "" {
		h.issueLoginCode(r.Context(), email, body)
	}
	writeJSON(w, http.StatusAccepted, body)
}

// issueLoginCode generates and stores a code, then delivers it per config. It
// only delivers a code that the store actually accepted.
func (h *authHandler) issueLoginCode(ctx context.Context, email string, body map[string]any) {
	code, err := newLoginCode()
	if err != nil {
		h.logger.Error("generate login code", "error", err)
		return
	}
	stored, err := h.store.RequestCode(ctx, email, hashValue(code), time.Now().Add(loginCodeTTL))
	if err != nil {
		h.logger.Error("store login code", "error", err)
		return
	}
	if !stored {
		return
	}
	switch h.cfg.AuthCodeDelivery {
	case "response":
		if h.cfg.DevMode {
			body["dev_code"] = code
		}
	case "log":
		if h.cfg.AuthCodeLogPlaintext {
			h.logger.Info("login code issued", "email", email, "code", code)
		}
	}
}

func (h *authHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	code := strings.TrimSpace(req.Code)
	if email == "" || !validLoginCode(code) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid or expired code"})
		return
	}

	member, ok, err := h.store.VerifyCode(r.Context(), email, hashValue(code))
	if err != nil {
		h.logger.Error("verify login code", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid or expired code"})
		return
	}

	token, err := newSessionToken()
	if err != nil {
		h.logger.Error("generate session token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if err := h.store.CreateSession(r.Context(), hashValue(token), member.MemberID, time.Now().Add(h.cfg.SessionTTL)); err != nil {
		h.logger.Error("create session", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	h.setSessionCookie(w, token, int(h.cfg.SessionTTL.Seconds()))
	writeJSON(w, http.StatusOK, authPrincipal{
		TenantID: member.TenantID,
		MemberID: member.MemberID,
		Email:    email,
		Role:     member.Role,
	})
}

func (h *authHandler) handleMe(w http.ResponseWriter, r *http.Request) {
	session, ok, err := h.currentSession(r)
	if err != nil {
		h.logger.Error("load session", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not signed in"})
		return
	}
	writeJSON(w, http.StatusOK, authPrincipal{
		TenantID: session.TenantID,
		MemberID: session.MemberID,
		Email:    session.Email,
		Role:     session.Role,
	})
}

func (h *authHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		if err := h.store.EndSession(r.Context(), hashValue(cookie.Value)); err != nil {
			h.logger.Error("end session", "error", err)
		}
	}
	h.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.AllowSignup {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "signup disabled"})
		return
	}
	var req struct {
		Email      string `json:"email"`
		TenantName string `json:"tenant_name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	tenantName := strings.TrimSpace(req.TenantName)
	if !validEmail(email) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid email"})
		return
	}
	if n := utf8.RuneCountInString(tenantName); n < 1 || n > 100 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid tenant name"})
		return
	}

	if _, err := h.store.CreateTenantWithAdmin(r.Context(), tenantName, email, "admin"); err != nil {
		if isUniqueViolation(err) {
			// Do not reveal that the email is already registered, and do not
			// log the email itself: it is PII and the conflict is enough.
			h.logger.Info("registration skipped: already registered", "tenant_name_len", utf8.RuneCountInString(tenantName))
		} else {
			h.logger.Error("register tenant", "error", err)
		}
	}

	body := map[string]any{"status": "ok"}
	h.issueLoginCode(r.Context(), email, body)
	writeJSON(w, http.StatusAccepted, body)
}

func (h *authHandler) currentSession(r *http.Request) (authstore.Session, bool, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return authstore.Session{}, false, nil
	}
	return h.store.GetSession(r.Context(), hashValue(cookie.Value), h.cfg.SessionIdle)
}

func (h *authHandler) setSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *authHandler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// validEmail enforces the registration contract: at most 254 characters and
// exactly one "@".
func validEmail(email string) bool {
	return len(email) <= 254 && strings.Count(email, "@") == 1
}

func validLoginCode(code string) bool {
	if len(code) != loginCodeDigits {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func newLoginCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func newSessionToken() (string, error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashValue(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

// originOf returns the scheme://host origin of raw, or "" when raw is not an
// absolute URL. A present Origin header must match it for mutating requests.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host
}

func schemeOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
