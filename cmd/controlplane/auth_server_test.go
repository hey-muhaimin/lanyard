package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/example/lanyard/internal/authstore"
	"github.com/example/lanyard/internal/config"
)

// fakeAuthStore mirrors the authstore semantics the handler relies on.
type fakeAuthStore struct {
	codes    map[string][]byte
	members  map[string]authstore.Member // email -> member
	emails   map[string]string           // member id -> email
	sessions map[string]authstore.Session
	tenants  []string

	registerErr error
}

func newFakeAuthStore() *fakeAuthStore {
	return &fakeAuthStore{
		codes:    map[string][]byte{},
		members:  map[string]authstore.Member{},
		emails:   map[string]string{},
		sessions: map[string]authstore.Session{},
	}
}

func (f *fakeAuthStore) addMember(email string, member authstore.Member) {
	f.members[email] = member
	f.emails[member.MemberID] = email
}

func (f *fakeAuthStore) RequestCode(ctx context.Context, email string, codeHash []byte, expires time.Time) (bool, error) {
	if _, ok := f.members[email]; !ok {
		return false, nil
	}
	f.codes[email] = append([]byte(nil), codeHash...)
	return true, nil
}

func (f *fakeAuthStore) VerifyCode(ctx context.Context, email string, codeHash []byte) (authstore.Member, bool, error) {
	want, ok := f.codes[email]
	if !ok || !bytes.Equal(want, codeHash) {
		return authstore.Member{}, false, nil
	}
	delete(f.codes, email)
	return f.members[email], true, nil
}

func (f *fakeAuthStore) CreateSession(ctx context.Context, tokenHash []byte, memberID string, expires time.Time) error {
	email, ok := f.emails[memberID]
	if !ok {
		return fmt.Errorf("unknown member %s", memberID)
	}
	member := f.members[email]
	f.sessions[string(tokenHash)] = authstore.Session{
		MemberID: member.MemberID,
		TenantID: member.TenantID,
		Email:    email,
		Role:     member.Role,
	}
	return nil
}

func (f *fakeAuthStore) GetSession(ctx context.Context, tokenHash []byte, idle time.Duration) (authstore.Session, bool, error) {
	session, ok := f.sessions[string(tokenHash)]
	return session, ok, nil
}

func (f *fakeAuthStore) EndSession(ctx context.Context, tokenHash []byte) error {
	delete(f.sessions, string(tokenHash))
	return nil
}

func (f *fakeAuthStore) CreateTenantWithAdmin(ctx context.Context, tenantName, email, role string) (string, error) {
	if f.registerErr != nil {
		return "", f.registerErr
	}
	f.tenants = append(f.tenants, tenantName)
	member := authstore.Member{MemberID: "member-new", TenantID: "tenant-new", Role: role}
	f.addMember(email, member)
	return member.TenantID, nil
}

func testAuthConfig() config.Config {
	return config.Config{
		PublicBaseURL:    "http://localhost:8080",
		AuthCodeDelivery: "none",
		SessionTTL:       12 * time.Hour,
		SessionIdle:      2 * time.Hour,
	}
}

func newTestAuthHandler(store authStore, cfg config.Config) http.Handler {
	return newAuthHandler(store, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func serveAuth(h http.Handler, method, path, body string, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, request)
	return recorder
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(recorder.Body.Bytes(), target); err != nil {
		t.Fatalf("decode response body %q: %v", recorder.Body.String(), err)
	}
}

func findCookie(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("response has no %q cookie; headers=%v", name, recorder.Header())
	return nil
}

// requestDevCode drives POST /auth/request and returns the dev_code.
func requestDevCode(t *testing.T, h http.Handler, email string) string {
	t.Helper()
	recorder := serveAuth(h, http.MethodPost, "/auth/request", fmt.Sprintf(`{"email":%q}`, email), nil, nil)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("POST /auth/request status = %d, want 202; body=%q", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Status  string `json:"status"`
		DevCode string `json:"dev_code"`
	}
	decodeBody(t, recorder, &body)
	if body.Status != "ok" {
		t.Fatalf("POST /auth/request status field = %q, want ok", body.Status)
	}
	if body.DevCode == "" {
		t.Fatal("POST /auth/request returned no dev_code in response delivery mode")
	}
	return body.DevCode
}

func TestAuthRequestUnknownEmailStillAccepted(t *testing.T) {
	store := newFakeAuthStore()
	cfg := testAuthConfig()
	cfg.DevMode = true
	cfg.AuthCodeDelivery = "response"
	h := newTestAuthHandler(store, cfg)

	recorder := serveAuth(h, http.MethodPost, "/auth/request", `{"email":"nobody@example.com"}`, nil, nil)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", recorder.Code)
	}
	var body map[string]any
	decodeBody(t, recorder, &body)
	if body["status"] != "ok" {
		t.Fatalf("body = %v, want status ok", body)
	}
	if _, ok := body["dev_code"]; ok {
		t.Fatal("unknown email must not receive a dev_code")
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestAuthRequestNormalizesEmailAndStoresHash(t *testing.T) {
	store := newFakeAuthStore()
	store.addMember("alice@example.com", authstore.Member{MemberID: "m1", TenantID: "t1", Role: "admin"})
	cfg := testAuthConfig()
	cfg.DevMode = true
	cfg.AuthCodeDelivery = "response"
	h := newTestAuthHandler(store, cfg)

	code := requestDevCode(t, h, "  alice@example.com  ")
	if len(code) != loginCodeDigits {
		t.Fatalf("dev_code = %q, want %d digits", code, loginCodeDigits)
	}
	if _, ok := store.codes["alice@example.com"]; !ok {
		t.Fatal("code was not stored against the normalized email")
	}
	if len(store.codes["alice@example.com"]) != 32 {
		t.Fatalf("stored hash length = %d, want 32", len(store.codes["alice@example.com"]))
	}
}

func TestAuthVerifyHappyPathSetsCookieAndPrincipal(t *testing.T) {
	store := newFakeAuthStore()
	store.addMember("alice@example.com", authstore.Member{MemberID: "m1", TenantID: "t1", Role: "admin"})
	cfg := testAuthConfig()
	cfg.DevMode = true
	cfg.AuthCodeDelivery = "response"
	h := newTestAuthHandler(store, cfg)

	code := requestDevCode(t, h, "alice@example.com")
	recorder := serveAuth(h, http.MethodPost, "/auth/verify",
		fmt.Sprintf(`{"email":"alice@example.com","code":%q}`, code), nil, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /auth/verify status = %d, want 200; body=%q", recorder.Code, recorder.Body.String())
	}
	var principal authPrincipal
	decodeBody(t, recorder, &principal)
	want := authPrincipal{TenantID: "t1", MemberID: "m1", Email: "alice@example.com", Role: "admin"}
	if principal != want {
		t.Fatalf("principal = %#v, want %#v", principal, want)
	}

	cookie := findCookie(t, recorder, sessionCookieName)
	if cookie.Value == "" {
		t.Fatal("session cookie is empty")
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.Secure {
		t.Error("session cookie must not be Secure for an http base URL")
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want /", cookie.Path)
	}
	if want := int((12 * time.Hour).Seconds()); cookie.MaxAge != want {
		t.Errorf("MaxAge = %d, want %d", cookie.MaxAge, want)
	}
	if _, ok := store.sessions[string(hashValue(cookie.Value))]; !ok {
		t.Fatal("session was not stored under sha256(token)")
	}
}

func TestAuthVerifyWrongCodeIsUnauthorized(t *testing.T) {
	store := newFakeAuthStore()
	store.addMember("alice@example.com", authstore.Member{MemberID: "m1", TenantID: "t1", Role: "admin"})
	cfg := testAuthConfig()
	cfg.DevMode = true
	cfg.AuthCodeDelivery = "response"
	h := newTestAuthHandler(store, cfg)

	code := requestDevCode(t, h, "alice@example.com")
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	recorder := serveAuth(h, http.MethodPost, "/auth/verify",
		fmt.Sprintf(`{"email":"alice@example.com","code":%q}`, wrong), nil, nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	var body map[string]string
	decodeBody(t, recorder, &body)
	if body["error"] != "invalid or expired code" {
		t.Fatalf("error = %q", body["error"])
	}
	if len(recorder.Result().Cookies()) != 0 {
		t.Fatal("a failed verify must not set a cookie")
	}
}

func TestAuthMeAndLogout(t *testing.T) {
	store := newFakeAuthStore()
	store.addMember("alice@example.com", authstore.Member{MemberID: "m1", TenantID: "t1", Role: "approver"})
	cfg := testAuthConfig()
	cfg.DevMode = true
	cfg.AuthCodeDelivery = "response"
	h := newTestAuthHandler(store, cfg)

	if recorder := serveAuth(h, http.MethodGet, "/auth/me", "", nil, nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("GET /auth/me without cookie status = %d, want 401", recorder.Code)
	} else {
		var body map[string]string
		decodeBody(t, recorder, &body)
		if body["error"] != "not signed in" {
			t.Fatalf("error = %q, want not signed in", body["error"])
		}
	}

	code := requestDevCode(t, h, "alice@example.com")
	verify := serveAuth(h, http.MethodPost, "/auth/verify",
		fmt.Sprintf(`{"email":"alice@example.com","code":%q}`, code), nil, nil)
	cookie := findCookie(t, verify, sessionCookieName)

	me := serveAuth(h, http.MethodGet, "/auth/me", "", cookie, nil)
	if me.Code != http.StatusOK {
		t.Fatalf("GET /auth/me status = %d, want 200; body=%q", me.Code, me.Body.String())
	}
	var principal authPrincipal
	decodeBody(t, me, &principal)
	if principal.Email != "alice@example.com" || principal.Role != "approver" || principal.MemberID != "m1" {
		t.Fatalf("principal = %#v", principal)
	}

	logout := serveAuth(h, http.MethodPost, "/auth/logout", "{}", cookie, nil)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("POST /auth/logout status = %d, want 204", logout.Code)
	}
	cleared := findCookie(t, logout, sessionCookieName)
	if cleared.Value != "" {
		t.Fatalf("cleared cookie value = %q, want empty", cleared.Value)
	}
	if cleared.MaxAge >= 0 {
		t.Fatalf("cleared cookie MaxAge = %d, want negative", cleared.MaxAge)
	}
	if len(store.sessions) != 0 {
		t.Fatalf("sessions after logout = %d, want 0", len(store.sessions))
	}
	if recorder := serveAuth(h, http.MethodGet, "/auth/me", "", cookie, nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("GET /auth/me after logout status = %d, want 401", recorder.Code)
	}
}

func TestAuthOriginCheck(t *testing.T) {
	store := newFakeAuthStore()
	cfg := testAuthConfig()
	cfg.PublicBaseURL = "https://console.example.com"
	h := newTestAuthHandler(store, cfg)

	recorder := serveAuth(h, http.MethodPost, "/auth/request", `{"email":"a@b.co"}`, nil,
		map[string]string{"Origin": "https://evil.example"})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("mismatched origin status = %d, want 403", recorder.Code)
	}
	var body map[string]string
	decodeBody(t, recorder, &body)
	if body["error"] != "origin not allowed" {
		t.Fatalf("error = %q, want origin not allowed", body["error"])
	}

	recorder = serveAuth(h, http.MethodPost, "/auth/request", `{"email":"a@b.co"}`, nil,
		map[string]string{"Origin": "https://console.example.com"})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("matching origin status = %d, want 202", recorder.Code)
	}

	// Safe methods are not origin-checked.
	recorder = serveAuth(h, http.MethodGet, "/auth/me", "", nil,
		map[string]string{"Origin": "https://evil.example"})
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("GET /auth/me with foreign origin status = %d, want 401", recorder.Code)
	}
}

func TestAuthSignupDisabled(t *testing.T) {
	store := newFakeAuthStore()
	h := newTestAuthHandler(store, testAuthConfig())

	recorder := serveAuth(h, http.MethodPost, "/auth/register",
		`{"email":"new@example.com","tenant_name":"Acme"}`, nil, nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if len(store.tenants) != 0 {
		t.Fatal("registration must not run when signup is disabled")
	}
}

func TestAuthRegisterCreatesTenantAndIssuesCode(t *testing.T) {
	store := newFakeAuthStore()
	cfg := testAuthConfig()
	cfg.AllowSignup = true
	cfg.DevMode = true
	cfg.AuthCodeDelivery = "response"
	h := newTestAuthHandler(store, cfg)

	recorder := serveAuth(h, http.MethodPost, "/auth/register",
		`{"email":"New@Example.COM","tenant_name":"  Acme  "}`, nil, nil)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%q", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Status  string `json:"status"`
		DevCode string `json:"dev_code"`
	}
	decodeBody(t, recorder, &body)
	if body.Status != "ok" || body.DevCode == "" {
		t.Fatalf("body = %#v", body)
	}
	if len(store.tenants) != 1 || store.tenants[0] != "Acme" {
		t.Fatalf("created tenants = %v, want [Acme]", store.tenants)
	}

	// A code issued to the registered email must not sign in a different email.
	otherEmail := serveAuth(h, http.MethodPost, "/auth/verify",
		fmt.Sprintf(`{"email":"alice@example.com","code":%q}`, body.DevCode), nil, nil)
	if otherEmail.Code != http.StatusUnauthorized {
		t.Fatalf("POST /auth/verify with a different email status = %d, want 401; body=%q", otherEmail.Code, otherEmail.Body.String())
	}
	if len(otherEmail.Result().Cookies()) != 0 {
		t.Fatal("a verify with a different email must not set a cookie")
	}

	verify := serveAuth(h, http.MethodPost, "/auth/verify",
		fmt.Sprintf(`{"email":"New@Example.COM","code":%q}`, body.DevCode), nil, nil)
	if verify.Code != http.StatusOK {
		t.Fatalf("POST /auth/verify status = %d, want 200; body=%q", verify.Code, verify.Body.String())
	}
	var principal authPrincipal
	decodeBody(t, verify, &principal)
	if principal.Role != "admin" || principal.TenantID != "tenant-new" {
		t.Fatalf("principal = %#v, want admin in tenant-new", principal)
	}
	if principal.Email != "new@example.com" {
		t.Fatalf("principal email = %q, want the registered email", principal.Email)
	}
}

func TestAuthMalformedJSONIsBadRequest(t *testing.T) {
	for name, testCase := range map[string]struct {
		path string
		body string
	}{
		"verify":   {path: "/auth/verify", body: `{"email":"alice@example.com",`},
		"register": {path: "/auth/register", body: `{"email":"New@Example.COM",`},
	} {
		store := newFakeAuthStore()
		store.addMember("alice@example.com", authstore.Member{MemberID: "m1", TenantID: "t1", Role: "admin"})
		cfg := testAuthConfig()
		cfg.AllowSignup = true
		cfg.DevMode = true
		cfg.AuthCodeDelivery = "response"
		h := newTestAuthHandler(store, cfg)

		recorder := serveAuth(h, http.MethodPost, testCase.path, testCase.body, nil, nil)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400; body=%q", name, recorder.Code, recorder.Body.String())
		}
		var body map[string]string
		decodeBody(t, recorder, &body)
		if body["error"] != "invalid JSON" {
			t.Fatalf("%s: error = %q, want invalid JSON", name, body["error"])
		}
		if len(store.codes) != 0 || len(store.sessions) != 0 || len(store.tenants) != 0 {
			t.Fatalf("%s: malformed JSON touched the store: codes=%d sessions=%d tenants=%d",
				name, len(store.codes), len(store.sessions), len(store.tenants))
		}
	}
}

func TestAuthRegisterConflictStillAccepted(t *testing.T) {
	store := newFakeAuthStore()
	store.registerErr = &pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"}
	cfg := testAuthConfig()
	cfg.AllowSignup = true
	h := newTestAuthHandler(store, cfg)

	recorder := serveAuth(h, http.MethodPost, "/auth/register",
		`{"email":"taken@example.com","tenant_name":"Acme"}`, nil, nil)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", recorder.Code)
	}
	var body map[string]string
	decodeBody(t, recorder, &body)
	if body["status"] != "ok" {
		t.Fatalf("body = %v, want status ok", body)
	}
}

func TestAuthRegisterValidation(t *testing.T) {
	cfg := testAuthConfig()
	cfg.AllowSignup = true
	h := newTestAuthHandler(newFakeAuthStore(), cfg)

	for name, body := range map[string]string{
		"no-at":        `{"email":"not-an-email","tenant_name":"Acme"}`,
		"two-at":       `{"email":"a@@b.co","tenant_name":"Acme"}`,
		"empty-tenant": `{"email":"new@example.com","tenant_name":"   "}`,
		"long-tenant":  fmt.Sprintf(`{"email":"new@example.com","tenant_name":%q}`, strings.Repeat("x", 101)),
	} {
		recorder := serveAuth(h, http.MethodPost, "/auth/register", body, nil, nil)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, recorder.Code)
		}
	}
}

func TestAuthCookieSecureFollowsBaseURL(t *testing.T) {
	store := newFakeAuthStore()
	store.addMember("alice@example.com", authstore.Member{MemberID: "m1", TenantID: "t1", Role: "admin"})

	for name, testCase := range map[string]struct {
		baseURL string
		secure  bool
	}{
		"https": {baseURL: "https://console.example.com", secure: true},
		"http":  {baseURL: "http://localhost:8080", secure: false},
	} {
		cfg := testAuthConfig()
		cfg.PublicBaseURL = testCase.baseURL
		cfg.DevMode = true
		cfg.AuthCodeDelivery = "response"
		h := newTestAuthHandler(store, cfg)

		code := requestDevCode(t, h, "alice@example.com")
		recorder := serveAuth(h, http.MethodPost, "/auth/verify",
			fmt.Sprintf(`{"email":"alice@example.com","code":%q}`, code), nil, nil)
		cookie := findCookie(t, recorder, sessionCookieName)
		if cookie.Secure != testCase.secure {
			t.Errorf("%s: Secure = %v, want %v", name, cookie.Secure, testCase.secure)
		}
	}
}

func TestAuthMethodMismatchIs405(t *testing.T) {
	h := newTestAuthHandler(newFakeAuthStore(), testAuthConfig())
	for _, testCase := range []struct{ method, path string }{
		{http.MethodGet, "/auth/request"},
		{http.MethodGet, "/auth/verify"},
		{http.MethodPost, "/auth/me"},
		{http.MethodGet, "/auth/logout"},
		{http.MethodDelete, "/auth/register"},
	} {
		recorder := serveAuth(h, testCase.method, testCase.path, "", nil, nil)
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status = %d, want 405", testCase.method, testCase.path, recorder.Code)
		}
		if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s %s Cache-Control = %q, want no-store", testCase.method, testCase.path, got)
		}
	}
}

func TestAuthUnavailableHandler(t *testing.T) {
	recorder := serveAuth(authUnavailableHandler(), http.MethodPost, "/auth/request", `{"email":"a@b.co"}`, nil, nil)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	var body map[string]string
	decodeBody(t, recorder, &body)
	if body["error"] != "authentication requires a database" {
		t.Fatalf("error = %q", body["error"])
	}
}
