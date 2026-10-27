package main

import (
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	token "github.com/example/lanyard/internal"
	"github.com/example/lanyard/internal/logging"
	"github.com/example/lanyard/internal/vault"
	"github.com/example/lanyard/internal/revocation"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestParseUpstreamURLRequiresHTTPSAndNoCallerCredentials(t *testing.T) {
	for _, raw := range []string{
		"http://upstream.example/data",
		"https://user:password@upstream.example/data",
		"https://upstream.example/data?debug=true",
		"https://upstream.example/data?",
		"https://upstream.example/data#fragment",
		"https://upstream.example/data#",
		"//upstream.example/data",
	} {
		if _, err := parseUpstreamURL(raw); err == nil {
			t.Errorf("parseUpstreamURL(%q) unexpectedly succeeded", raw)
		}
	}
	target, err := parseUpstreamURL("https://api.example/v1/resource")
	if err != nil {
		t.Fatalf("parseUpstreamURL() error = %v", err)
	}
	if target.Host != "api.example" || target.Path != "/v1/resource" {
		t.Fatalf("parseUpstreamURL() = %v", target)
	}
}

func TestIsPublicUnicastRejectsNonPublicAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "fc00::1"} {
		if isPublicUnicast(net.ParseIP(address)) {
			t.Errorf("isPublicUnicast(%q) = true", address)
		}
	}
	if !isPublicUnicast(net.ParseIP("8.8.8.8")) {
		t.Fatal("isPublicUnicast() rejected a public IPv4 address")
	}
	if !isPublicUnicast(net.ParseIP("2001:4860:4860::8888")) {
		t.Fatal("isPublicUnicast() rejected a public IPv6 address")
	}
}

func TestProxyForwardsOnlyScopedRequestsAndScrubsCredentials(t *testing.T) {
	const (
		tenantID = "tenant-1"
		secret   = "upstream-secret"
	)
	target, err := url.Parse("https://api.example/v1/resource")
	if err != nil {
		t.Fatal(err)
	}
	store := vault.NewStore(vault.NewMemoryKMS("test-key"))
	if err := store.Put(context.Background(), "test-key", tenantID, "demo-secret", []byte(secret)); err != nil {
		t.Fatal(err)
	}

	upstreamCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		upstreamCalls++
		if request.URL.String() != target.String() || request.Method != http.MethodGet {
			t.Errorf("upstream request = %s %s", request.Method, request.URL)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+secret {
			t.Errorf("upstream Authorization = %q", got)
		}
		if request.Header.Get("Cookie") != "" || request.Header.Get("DPoP") != "" {
			t.Error("caller credentials were forwarded upstream")
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"Set-Cookie":   []string{"session=private"},
				"Location":     []string{"https://other.example"},
			},
			Body: io.NopCloser(strings.NewReader(`{"credential":"` + secret + `"}`)),
		}, nil
	})}
	handler := newProxyHandler(target, client, store, tenantID, logging.NewJSONLogger(), revocation.NewStore())
	gated := createTestGate(t, handler, true)
	request := httptest.NewRequest(http.MethodGet, "https://proxy.example/proxy", nil)
	request.Header.Set("Cookie", "session=agent-cookie")
	request.Header.Set("Authorization", "Bearer agent-token")
	request.Header.Set("DPoP", "agent-proof")
	recorder := httptest.NewRecorder()
	gated.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("proxy status = %d; body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), secret) || !strings.Contains(recorder.Body.String(), "[REDACTED]") {
		t.Fatalf("proxy response did not scrub the secret: %q", recorder.Body.String())
	}
	if recorder.Header().Get("Set-Cookie") != "" || recorder.Header().Get("Location") != "" {
		t.Fatal("proxy forwarded an unsafe upstream response header")
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
	}
}

func TestProxyDeniesMissingScopeWithoutCallingUpstream(t *testing.T) {
	target, err := url.Parse("https://api.example/v1/resource")
	if err != nil {
		t.Fatal(err)
	}
	store := vault.NewStore(vault.NewMemoryKMS("test-key"))
	if err := store.Put(context.Background(), "test-key", "tenant-1", "demo-secret", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	called := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}
	handler := newProxyHandler(target, client, store, "tenant-1", logging.NewJSONLogger(), revocation.NewStore())
	gated := createTestGate(t, handler, false)
	request := httptest.NewRequest(http.MethodGet, "https://proxy.example/proxy", nil)
	recorder := httptest.NewRecorder()
	gated.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("proxy status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if called {
		t.Fatal("proxy called upstream without matching scope")
	}
}

func createTestGate(t *testing.T, next http.Handler, includeScope bool) http.Handler {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	agentSeed := make([]byte, ed25519.SeedSize)
	for i := range agentSeed {
		agentSeed[i] = 11
	}
	agentPrivateKey := ed25519.NewKeyFromSeed(agentSeed)
	thumbprint, err := token.PublicKeyThumbprint(agentPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims{
		Issuer:    "https://issuer.example",
		Subject:   "user:alice",
		Audience:  "proxy",
		ExpiresAt: now.Add(time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		ID:        "grant-1",
		TenantID:  "tenant-1",
		Actor:     "agent-1",
		TaskID:    "task-1",
		Cnf:       map[string]string{"jkt": thumbprint},
	}
	if includeScope {
		claims.Scope = []token.ScopeEntry{{Connector: "demo", Action: "read", Resource: "demo-secret"}}
	} else {
		claims.Scope = []token.ScopeEntry{{Connector: "demo", Action: "write", Resource: "demo-secret"}}
	}
	signingSeed := make([]byte, ed25519.SeedSize)
	for i := range signingSeed {
		signingSeed[i] = 12
	}
	signer, err := token.NewSignerWithKey("key-1", ed25519.NewKeyFromSeed(signingSeed))
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := token.NewVerifier("https://issuer.example", "proxy", map[string]ed25519.PublicKey{
		"key-1": signer.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := token.NewDPoPProof(agentPrivateKey, accessToken, http.MethodGet, "https://proxy.example/proxy", "proof-1", now)
	if err != nil {
		t.Fatal(err)
	}
	gate := token.Gate(verifier, token.NewDPoPVerifier(), next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+accessToken)
		r.Header.Set("DPoP", proof)
		gate.ServeHTTP(w, r)
	})
}
