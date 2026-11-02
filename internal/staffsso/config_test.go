package staffsso

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestParseConfigAcceptsSecretShape(t *testing.T) {
	raw := []byte(`{"userPoolId":"ap-southeast-2_YdESPvFwh","clientId":"f3gcqfhc6rvmlo78ceffsfrdi","clientSecret":"test-client-secret","issuer":"https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_YdESPvFwh","hostedUiDomain":"https://lanyard-ops-staff.auth.ap-southeast-2.amazoncognito.com","region":"ap-southeast-2","staffGroup":"staff"}`)
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}
	// check round-trip JSON matches
	b, _ := json.Marshal(cfg)
	var round Config
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if cfg != round {
		t.Fatalf("round-trip mismatch: %+v vs %+v", cfg, round)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
}

func TestParseConfigRejectsMissingFields(t *testing.T) {
	base := map[string]string{
		"userPoolId":     "ap-southeast-2_YdESPvFwh",
		"clientId":       "f3gcqfhc6rvmlo78ceffsfrdi",
		"clientSecret":   "test-client-secret",
		"issuer":         "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_YdESPvFwh",
		"hostedUiDomain": "https://lanyard-ops-staff.auth.ap-southeast-2.amazoncognito.com",
		"region":         "ap-southeast-2",
		"staffGroup":     "staff",
	}
	// missing each field
	fields := []string{"userPoolId", "clientId", "staffGroup"}
	for _, f := range fields {
		m := make(map[string]string)
		for k, v := range base {
			if k != f {
				m[k] = v
			}
		}
		raw, _ := json.Marshal(m)
		if _, err := ParseConfig(raw); err == nil {
			t.Errorf("expected error when missing %s", f)
		}
	}
	// invalid issuer scheme
	m := make(map[string]string)
	for k, v := range base {
		m[k] = v
	}
	m["issuer"] = "http://bad.scheme"
	raw, _ := json.Marshal(m)
	if _, err := ParseConfig(raw); err == nil {
		t.Errorf("expected error for non‑https issuer")
	}
	// relative hostedUiDomain
	m = make(map[string]string)
	for k, v := range base {
		m[k] = v
	}
	m["hostedUiDomain"] = "/relative"
	raw, _ = json.Marshal(m)
	if _, err := ParseConfig(raw); err == nil {
		t.Errorf("expected error for relative hostedUiDomain")
	}
}

func TestRedirectURI(t *testing.T) {
	want := "https://ops.linkedqueue.cloud/ops/auth/callback/"
	for _, in := range []string{"https://ops.linkedqueue.cloud", "https://ops.linkedqueue.cloud/"} {
		got := RedirectURI(in)
		if got != want {
			t.Fatalf("RedirectURI(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestAuthorizeURL(t *testing.T) {
	cfg := Config{HostedUIDomain: "https://lanyard-ops-staff.auth.ap-southeast-2.amazoncognito.com", ClientID: "f3gcqfhc6rvmlo78ceffsfrdi"}
	redirect := "https://ops.linkedqueue.cloud/ops/auth/callback/"
	state := "state123"
	challenge := "challengeABC"
	raw, err := cfg.AuthorizeURL(redirect, state, challenge)
	if err != nil {
		t.Fatalf("AuthorizeURL error: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if u.Host != "lanyard-ops-staff.auth.ap-southeast-2.amazoncognito.com" {
		t.Fatalf("host %s", u.Host)
	}
	if u.Path != "/oauth2/authorize" {
		t.Fatalf("path %s", u.Path)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != cfg.ClientID || q.Get("redirect_uri") != redirect || q.Get("scope") != Scope || q.Get("state") != state || q.Get("code_challenge") != challenge || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("unexpected query params: %v", q)
	}
	// empty challenge
	if _, err := cfg.AuthorizeURL(redirect, state, ""); err == nil {
		t.Fatalf("expected error on empty challenge")
	}
}

func TestTokenAndJWKSURLs(t *testing.T) {
	cfg := Config{HostedUIDomain: "https://example.com/", Issuer: "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_YdESPvFwh"}
	if got := cfg.TokenURL(); got != "https://example.com/oauth2/token" {
		t.Fatalf("TokenURL got %s", got)
	}
	if got := cfg.JWKSURL(); got != "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_YdESPvFwh/.well-known/jwks.json" {
		t.Fatalf("JWKSURL got %s", got)
	}
}
