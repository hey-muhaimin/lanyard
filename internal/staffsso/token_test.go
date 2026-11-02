package staffsso

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExchangeCodeSendsBasicAuthAndForm(t *testing.T) {
	// Expect client_id:test-client-id, client_secret:test-client-secret
	clientID := "test-client-id"
	clientSecret := "test-client-secret"
	var capturedMethod, capturedPath string
	var capturedAuth string
	var capturedForm url.Values

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		if user, pass, ok := r.BasicAuth(); ok {
			capturedAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
			if user != clientID || pass != clientSecret {
				t.Errorf("basic auth credentials mismatch: got %s:%s", user, pass)
			}
		} else {
			t.Error("missing basic auth")
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		capturedForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id_token":"header.payload.sig"}`))
	}))
	defer srv.Close()

	cfg := Config{ClientID: clientID, ClientSecret: clientSecret, HostedUIDomain: srv.URL}
	client := srv.Client()
	redirectURI := "https://ops.linkedqueue.cloud/ops/auth/callback/"
	code := "authcode"
	verifier := "pkceverifier"

	token, err := ExchangeCode(context.Background(), client, cfg, redirectURI, code, verifier)
	if err != nil {
		t.Fatalf("ExchangeCode error: %v", err)
	}
	if token != "header.payload.sig" {
		t.Fatalf("unexpected token: %s", token)
	}
	if capturedMethod != http.MethodPost {
		t.Fatalf("method %s", capturedMethod)
	}
	if capturedPath != "/oauth2/token" {
		t.Fatalf("path %s", capturedPath)
	}
	// verify form fields
	if capturedForm.Get("grant_type") != "authorization_code" || capturedForm.Get("client_id") != clientID || capturedForm.Get("code") != code || capturedForm.Get("redirect_uri") != redirectURI || capturedForm.Get("code_verifier") != verifier {
		t.Fatalf("form fields incorrect: %v", capturedForm)
	}
	// verify auth header matches what we captured manually using BasicAuth
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
	if capturedAuth != expectedAuth {
		t.Fatalf("auth header mismatch: got %s want %s", capturedAuth, expectedAuth)
	}
}

func TestExchangeCodeRejectsFailures(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		respBody  string
		expectErr bool
	}{
		{"bad status", http.StatusBadRequest, `{"error":"bad"}`, true},
		{"invalid json", http.StatusOK, `notjson`, true},
		{"missing id_token", http.StatusOK, `{}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.respBody))
			}))
			defer srv.Close()
			cfg := Config{ClientID: "c", ClientSecret: "s", HostedUIDomain: srv.URL}
			token, err := ExchangeCode(context.Background(), srv.Client(), cfg, "https://example.com/cb", "code", "ver")
			if (err != nil) != tt.expectErr {
				t.Fatalf("expected error %v, got %v", tt.expectErr, err)
			}
			if !tt.expectErr && token == "" {
				t.Fatalf("expected token, got empty")
			}
		})
	}
}

func TestExchangeCodeRequiresInputs(t *testing.T) {
	cfg := Config{ClientID: "c", ClientSecret: "s", HostedUIDomain: "https://example.com"}
	// nil client
	if _, err := ExchangeCode(context.Background(), nil, cfg, "cb", "code", "ver"); err == nil {
		t.Errorf("expected error for nil client")
	}
	// empty code
	if _, err := ExchangeCode(context.Background(), http.DefaultClient, cfg, "cb", "", "ver"); err == nil {
		t.Errorf("expected error for empty code")
	}
	// empty verifier
	if _, err := ExchangeCode(context.Background(), http.DefaultClient, cfg, "cb", "code", ""); err == nil {
		t.Errorf("expected error for empty verifier")
	}
}
