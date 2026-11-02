package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/opsstore"
	"github.com/example/lanyard/internal/staffsso"
)

// mockLoadCognitoConfig replaces the loadCognitoConfigFn for tests.
func mockLoadCognitoConfig(t *testing.T) func() {
	original := loadCognitoConfigFn
	loadCognitoConfigFn = func(_ context.Context, _ config.Config) (staffsso.Config, error) {
		return staffsso.Config{
			UserPoolID:     "us-east-1_Example",
			ClientID:       "client-id",
			ClientSecret:   "client-secret",
			Issuer:         "https://cognito.example.com",
			HostedUIDomain: "https://cognito.example.com",
			Region:         "us-east-1",
			StaffGroup:     "admins",
		}, nil
	}
	return func() { loadCognitoConfigFn = original }
}

func TestOpsLoginSuccessRedirect(t *testing.T) {
	// Arrange
	restore := mockLoadCognitoConfig(t)
	defer restore()

	// Minimal opsAPI; store not used for login.
	api := &opsAPI{cfg: config.Config{OpsPublicBaseURL: "https://ops.example.com"}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ops/auth/login", nil)

	// Act
	api.authLogin(w, r)

	// Assert
	if w.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, w.Code)
	}
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatalf("missing Location header")
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid redirect URL: %v", err)
	}
	// Ensure redirect goes to Cognito domain.
	if !strings.Contains(parsed.Host, "cognito.example.com") {
		t.Fatalf("redirect host not Cognito: %s", parsed.Host)
	}
	q := parsed.Query()
	if q.Get("state") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("missing state or code_challenge in redirect URL")
	}
	// Verify PKCE entry stored.
	opsPKCEStore.mu.Lock()
	defer opsPKCEStore.mu.Unlock()
	entry, ok := opsPKCEStore.entries[q.Get("state")]
	if !ok {
		t.Fatalf("state not stored in PKCE store")
	}
	// Verify verifier length (>=43 after base64url encoding).
	if len(entry.verifier) < 43 {
		t.Fatalf("verifier too short: %d", len(entry.verifier))
	}
}

// TestOpsCallbackRouteAcceptsTrailingSlash proves the router matches the fixed
// Cognito callback path and that the session middleware allow-lists it. The
// callback handler rejects a request without code/state before touching the
// database, so a 400 here means the request reached authCallback (a routing or
// allow-list regression would surface as 404 or 401 instead).
func TestOpsCallbackRouteAcceptsTrailingSlash(t *testing.T) {
	restore := mockLoadCognitoConfig(t)
	defer restore()

	handler := newOpsHandler(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, staffsso.CallbackPath+"?error=access_denied&state=state123", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("GET %s = %d, want %d (body %q)", staffsso.CallbackPath, w.Code, http.StatusBadRequest, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "authentication required") {
		t.Fatalf("session middleware rejected the callback path: %s", w.Body.String())
	}
}

func TestOpsMeReturnsSession(t *testing.T) {
	// Create a dummy session and embed in request context.
	sess := opsstore.Session{Email: "user@example.com", Role: "ops_support", HardwareKey: false}
	ctx := context.WithValue(context.Background(), "opsSession", sess)
	r := httptest.NewRequest(http.MethodGet, "/ops/auth/me", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	api := &opsAPI{}
	api.authMe(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["email"] != "user@example.com" || resp["role"] != "ops_support" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
