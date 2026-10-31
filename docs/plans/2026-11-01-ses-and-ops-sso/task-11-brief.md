# Task 11 — Ops sign-in start: PKCE, state store, `/ops/auth/login`

**Where this fits:** first half of the ops auth surface. Creates the in-memory single-use
state store, PKCE generation, the shared interfaces the callback and API will use, and the
redirect to Cognito's hosted UI.

**Depends on:** 07 (`staffsso.Config.AuthorizeURL`, `staffsso.RedirectURI`).
**Blocks:** 12, 13 (interfaces), 14 (constructor).

## Files

- `cmd/controlplane/ops_auth.go` (create)
- `cmd/controlplane/ops_auth_test.go` (create)

## Contracts pinned here (12, 13 and 14 depend on these exact names)

```go
const (
	opsSessionCookie = "lanyard_ops_session"
	oauthStateTTL    = 10 * time.Minute
	pkceBytes        = 32
)

// opsStore is the narrow database surface the ops handlers need.
type opsStore interface {
	ProvisionMember(ctx context.Context, email, cognitoSub string) (opsstore.Member, error)
	CreateSession(ctx context.Context, tokenHash []byte, memberID string, expires time.Time, hardwareKey bool) error
	GetSession(ctx context.Context, tokenHash []byte, idle time.Duration) (opsstore.Session, bool, error)
	EndSession(ctx context.Context, tokenHash []byte) error
}

// tokenVerifier verifies a Cognito ID token. Tests substitute a fake.
type tokenVerifier interface {
	Verify(ctx context.Context, raw string) (staffsso.Identity, error)
}

// opsPrincipal is the authenticated staff identity carried in the request
// context by the session middleware.
type opsPrincipal struct {
	MemberID    string
	Email       string
	Role        string
	HardwareKey bool
}

type opsSessionKey struct{}

func opsPrincipalFrom(ctx context.Context) (opsPrincipal, bool) {
	p, ok := ctx.Value(opsSessionKey{}).(opsPrincipal)
	return p, ok
}

type opsSSO struct {
	cfg          config.Config
	sso          staffsso.Config
	verifier     tokenVerifier
	store        opsStore
	logger       *slog.Logger
	client       *http.Client
	redirect     string
	origin       string
	secureCookie bool
	states       *stateStore
}

func newOpsSSO(cfg config.Config, sso staffsso.Config, verifier tokenVerifier, store opsStore, logger *slog.Logger) *opsSSO

func (a *opsSSO) login(w http.ResponseWriter, r *http.Request)

// opsOriginGuard rejects cross-origin mutating requests and sets Cache-Control: no-store.
func opsOriginGuard(origin string, next http.Handler) http.Handler
```

`newOpsSSO` sets `origin = originOf(cfg.OpsPublicBaseURL)`,
`secureCookie = strings.EqualFold(schemeOf(cfg.OpsPublicBaseURL), "https")`,
`redirect = staffsso.RedirectURI(cfg.OpsPublicBaseURL)`, `client` = a
`&http.Client{Timeout: 10 * time.Second}`, `states = newStateStore(oauthStateTTL)`.

## `cmd/controlplane/ops_auth.go` — content for this task

```go
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/opsstore"
	"github.com/example/lanyard/internal/staffsso"
)

const (
	opsSessionCookie = "lanyard_ops_session"
	oauthStateTTL    = 10 * time.Minute
	pkceBytes        = 32
)

// opsStore is the narrow database surface the ops handlers need.
type opsStore interface {
	ProvisionMember(ctx context.Context, email, cognitoSub string) (opsstore.Member, error)
	CreateSession(ctx context.Context, tokenHash []byte, memberID string, expires time.Time, hardwareKey bool) error
	GetSession(ctx context.Context, tokenHash []byte, idle time.Duration) (opsstore.Session, bool, error)
	EndSession(ctx context.Context, tokenHash []byte) error
}

// tokenVerifier verifies a Cognito ID token. Tests substitute a fake.
type tokenVerifier interface {
	Verify(ctx context.Context, raw string) (staffsso.Identity, error)
}

// opsPrincipal is the authenticated staff identity carried in the request
// context by the session middleware.
type opsPrincipal struct {
	MemberID    string
	Email       string
	Role        string
	HardwareKey bool
}

type opsSessionKey struct{}

func opsPrincipalFrom(ctx context.Context) (opsPrincipal, bool) {
	p, ok := ctx.Value(opsSessionKey{}).(opsPrincipal)
	return p, ok
}

// oauthState is one in-flight sign-in: the PKCE verifier plus its creation time.
type oauthState struct {
	verifier  string
	createdAt time.Time
}

// stateStore holds in-flight OAuth states. The deployment is a single control
// plane replica, so in-memory state is sufficient and a restart only invalidates
// sign-ins that were already in progress.
type stateStore struct {
	mu     sync.Mutex
	now    func() time.Time
	ttl    time.Duration
	states map[string]oauthState
}

func newStateStore(ttl time.Duration) *stateStore {
	return &stateStore{now: time.Now, ttl: ttl, states: map[string]oauthState{}}
}

// put records a state and drops expired entries so the map cannot grow forever.
func (s *stateStore) put(state, verifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, entry := range s.states {
		if now.Sub(entry.createdAt) >= s.ttl {
			delete(s.states, key)
		}
	}
	s.states[state] = oauthState{verifier: verifier, createdAt: now}
}

// take consumes a state: the second call for the same value reports false.
func (s *stateStore) take(state string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.states[state]
	if !ok {
		return "", false
	}
	delete(s.states, state)
	if s.now().Sub(entry.createdAt) >= s.ttl {
		return "", false
	}
	return entry.verifier, true
}

func (s *stateStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.states)
}

// newPKCE returns a base64url verifier (32 random bytes, 43 chars) and its
// S256 challenge.
func newPKCE() (string, string, error) {
	raw := make([]byte, pkceBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// opsSSO owns the Cognito authorization-code flow for the ops console.
type opsSSO struct {
	cfg          config.Config
	sso          staffsso.Config
	verifier     tokenVerifier
	store        opsStore
	logger       *slog.Logger
	client       *http.Client
	redirect     string
	origin       string
	secureCookie bool
	states       *stateStore
}

func newOpsSSO(cfg config.Config, sso staffsso.Config, verifier tokenVerifier, store opsStore, logger *slog.Logger) *opsSSO {
	if logger == nil {
		logger = slog.Default()
	}
	return &opsSSO{
		cfg:          cfg,
		sso:          sso,
		verifier:     verifier,
		store:        store,
		logger:       logger,
		client:       &http.Client{Timeout: 10 * time.Second},
		redirect:     staffsso.RedirectURI(cfg.OpsPublicBaseURL),
		origin:       originOf(cfg.OpsPublicBaseURL),
		secureCookie: strings.EqualFold(schemeOf(cfg.OpsPublicBaseURL), "https"),
		states:       newStateStore(oauthStateTTL),
	}
}

// login starts a sign-in: mint PKCE + state, remember them, and send the browser
// to the Cognito hosted UI.
func (a *opsSSO) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	verifier, challenge, err := newPKCE()
	if err != nil {
		a.logger.Error("generate PKCE verifier", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "sign-in unavailable"})
		return
	}
	state, err := newSessionToken()
	if err != nil {
		a.logger.Error("generate OAuth state", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "sign-in unavailable"})
		return
	}
	a.states.put(state, verifier)

	target, err := a.sso.AuthorizeURL(a.redirect, state, challenge)
	if err != nil {
		a.logger.Error("build Cognito authorize URL", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "sign-in unavailable"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

// opsOriginGuard rejects mutating requests whose Origin is not the ops origin.
func opsOriginGuard(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if got := r.Header.Get("Origin"); got != "" && !strings.EqualFold(got, origin) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "origin not allowed"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
```

`newSessionToken()` (43-char base64url) is reused from `auth_server.go` for the state value.
Do not add another random-token helper.

## Tests — `cmd/controlplane/ops_auth_test.go`

Add these helpers (task 12 extends this file):

```go
func testOpsSSO(t *testing.T) (*opsSSO, *fakeOpsStore, *fakeVerifier) {
	t.Helper()
	cfg := config.Config{
		OpsPublicBaseURL: "https://ops.linkedqueue.cloud",
		OpsSSOEnabled:    true,
		SessionTTL:       time.Hour,
		SessionIdle:      30 * time.Minute,
	}
	ssoCfg := staffsso.Config{
		UserPoolID:     "ap-southeast-2_TESTPOOL",
		ClientID:       "test-client-id",
		ClientSecret:   "test-client-secret",
		Issuer:         "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_TESTPOOL",
		HostedUIDomain: "https://lanyard-ops-staff.auth.ap-southeast-2.amazoncognito.com",
		Region:         "ap-southeast-2",
		StaffGroup:     "staff",
	}
	store := &fakeOpsStore{}
	verifier := &fakeVerifier{}
	return newOpsSSO(cfg, ssoCfg, verifier, store, slog.New(slog.NewTextHandler(io.Discard, nil))), store, verifier
}
```

`fakeOpsStore` and `fakeVerifier` are declared in this file with the exact `opsStore` /
`tokenVerifier` methods, so tasks 12 and 13 can reuse them without editing this file:

```go
type fakeOpsStore struct {
	members   map[string]opsstore.Member
	sessions  map[string]opsstore.Session
	provErr   error
	createErr error
}

func (f *fakeOpsStore) ProvisionMember(ctx context.Context, email, sub string) (opsstore.Member, error) {
	if f.provErr != nil {
		return opsstore.Member{}, f.provErr
	}
	if f.members == nil {
		f.members = map[string]opsstore.Member{}
	}
	if m, ok := f.members[email]; ok {
		return m, nil
	}
	m := opsstore.Member{ID: "member-1", Email: email, Role: "ops_support", Status: "active", CognitoSub: sub}
	f.members[email] = m
	return m, nil
}

func (f *fakeOpsStore) CreateSession(ctx context.Context, hash []byte, memberID string, expires time.Time, hardwareKey bool) error {
	if f.createErr != nil {
		return f.createErr
	}
	if f.sessions == nil {
		f.sessions = map[string]opsstore.Session{}
	}
	f.sessions[string(hash)] = opsstore.Session{MemberID: memberID, Email: "staff@linkedqueue.cloud", Role: "ops_support", HardwareKey: hardwareKey}
	return nil
}

func (f *fakeOpsStore) GetSession(ctx context.Context, hash []byte, idle time.Duration) (opsstore.Session, bool, error) {
	s, ok := f.sessions[string(hash)]
	return s, ok, nil
}

func (f *fakeOpsStore) EndSession(ctx context.Context, hash []byte) error {
	delete(f.sessions, string(hash))
	return nil
}

type fakeVerifier struct {
	identity staffsso.Identity
	err      error
}

func (f *fakeVerifier) Verify(ctx context.Context, raw string) (staffsso.Identity, error) {
	if f.err != nil {
		return staffsso.Identity{}, f.err
	}
	return f.identity, nil
}
```

Note `fakeOpsStore.CreateSession` records `Role: "ops_support"`; task 12's happy-path test
overrides it by seeding `f.sessions` where a write-capable role is needed.

Tests:

1. `TestOpsLoginRedirectsToHostedUI` — `httptest.NewRequest(GET, "/ops/auth/login")`; expect
   `302`, `Cache-Control: no-store`, **no** `Set-Cookie`; parse `Location` and assert host
   `lanyard-ops-staff.auth.ap-southeast-2.amazoncognito.com`, path `/oauth2/authorize`,
   `response_type=code`, `client_id=test-client-id`,
   `redirect_uri=https://ops.linkedqueue.cloud/ops/auth/callback/`,
   `scope=openid email profile`, `code_challenge_method=S256`, non-empty `state` and
   `code_challenge`.
2. `TestOpsLoginVerifierMatchesChallenge` — take the `state` from the redirect, call
   `sso.states.take(state)`; assert `sha256(verifier)` base64url equals the
   `code_challenge`, and that the verifier is 43 base64url characters decoding to 32 bytes.
3. `TestOpsLoginStateIsSingleUse` — two logins produce different states; `take(state1)`
   succeeds once and then reports false.
4. `TestStateStoreExpiry` — set `store.now` to a fixed clock, `put`, advance past
   `oauthStateTTL`, `take` → false; and `len()` drops expired entries on the next `put`.
5. `TestNewPKCEIsRandom` — two calls differ and both verifiers are 43 chars.
6. `TestOpsOriginGuard` — table over
   `(method, origin, wantStatus)`:
   - `POST` + `https://ops.linkedqueue.cloud` → passes (handler writes 204)
   - `POST` + `https://evil.example` → `403` + `{"error":"origin not allowed"}`
   - `POST` + `""` → passes
   - `GET` + `https://evil.example` → passes
   - `DELETE` + `https://OPS.linkedqueue.cloud` → passes (case-insensitive)
7. `TestOpsLoginMethodNotAllowed` — `POST /ops/auth/login` → `405`.

## Verification

```sh
go test ./cmd/controlplane/ -run 'OpsLogin|StateStore|PKCE|OriginGuard' -v
go build ./... && go vet ./cmd/controlplane/```

The routes are not mounted yet — task 14 does that. `go test ./...` must still pass.
