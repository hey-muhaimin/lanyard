package token

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testKeyPair(t *testing.T, seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func testClaims(t *testing.T, now time.Time, publicKey ed25519.PublicKey) Claims {
	t.Helper()
	thumbprint, err := PublicKeyThumbprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return Claims{
		Issuer:    "https://issuer.example",
		Subject:   "user:alice",
		Audience:  "lanyard-proxy",
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		ID:        "grant-1",
		TenantID:  "tenant-1",
		Actor:     "agent-1",
		TaskID:    "task-1",
		Scope:     []ScopeEntry{{Connector: "demo", Action: "read", Resource: "demo-secret"}},
		PolicyVer: 1,
		Cnf:       map[string]string{"jkt": thumbprint},
	}
}

func TestJWTSigningJWKSAndVerification(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	publicKey, privateKey := testKeyPair(t, 1)
	signer, err := NewSignerWithKey("key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signer.Sign(testClaims(t, now, publicKey))
	if err != nil {
		t.Fatal(err)
	}
	publicJWKS, err := PublicJWKS(signer.KeyID(), signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := VerifierFromJWKS("https://issuer.example", "lanyard-proxy", publicJWKS)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ID != "grant-1" || claims.TenantID != "tenant-1" {
		t.Fatalf("Verify() claims = %#v", claims)
	}

	if _, err := verifier.Verify(raw, now.Add(6*time.Minute)); err == nil {
		t.Fatal("Verify() accepted an expired token")
	}
	if _, err := NewVerifier("https://other.example", "lanyard-proxy", map[string]ed25519.PublicKey{"key-1": publicKey}); err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
}

func TestDPoPProofRejectsReplayAndMismatches(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	publicKey, privateKey := testKeyPair(t, 2)
	thumbprint, err := PublicKeyThumbprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	const accessToken = "access-token"
	const target = "https://proxy.example/proxy"
	proof, err := NewDPoPProof(privateKey, accessToken, http.MethodGet, target, "proof-1", now)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewDPoPVerifier()
	if err := verifier.Verify(proof, accessToken, thumbprint, http.MethodGet, target, now); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if err := verifier.Verify(proof, accessToken, thumbprint, http.MethodGet, target, now); err == nil {
		t.Fatal("Verify() accepted a replayed proof")
	}
	if err := NewDPoPVerifier().Verify(proof, "other-token", thumbprint, http.MethodGet, target, now); err == nil {
		t.Fatal("Verify() accepted a proof bound to another access token")
	}
	if err := NewDPoPVerifier().Verify(proof, accessToken, thumbprint, http.MethodPost, target, now); err == nil {
		t.Fatal("Verify() accepted a proof bound to another method")
	}
	if err := NewDPoPVerifier().Verify(proof, accessToken, thumbprint, http.MethodGet, target, now.Add(2*time.Minute)); err == nil {
		t.Fatal("Verify() accepted a stale proof")
	}
}

func TestDPoPRequestProofAuthenticatesRegisteredAgent(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	publicKey, privateKey := testKeyPair(t, 8)
	thumbprint, err := PublicKeyThumbprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	const target = "https://controlplane.example/grant"
	proof, err := NewDPoPRequestProof(privateKey, http.MethodPost, target, "grant-proof-1", now)
	if err != nil {
		t.Fatalf("NewDPoPRequestProof() error = %v", err)
	}
	verifier := NewDPoPVerifier()
	if err := verifier.VerifyRequest(proof, thumbprint, http.MethodPost, target, now); err != nil {
		t.Fatalf("VerifyRequest() error = %v", err)
	}
	if err := verifier.VerifyRequest(proof, thumbprint, http.MethodPost, target, now); err == nil {
		t.Fatal("VerifyRequest() accepted a replayed proof")
	}
	if err := NewDPoPVerifier().VerifyRequest(proof, thumbprint, http.MethodGet, target, now); err == nil {
		t.Fatal("VerifyRequest() accepted a proof bound to another method")
	}
	otherKey, _ := testKeyPair(t, 9)
	otherThumbprint, err := PublicKeyThumbprint(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDPoPVerifier().VerifyRequest(proof, otherThumbprint, http.MethodPost, target, now); err == nil {
		t.Fatal("VerifyRequest() accepted a proof from another agent key")
	}
}

func TestDPoPConcurrentReplayOnlyAcceptedOnce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	publicKey, privateKey := testKeyPair(t, 6)
	thumbprint, err := PublicKeyThumbprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	target := "https://proxy.example/proxy"
	proof, err := NewDPoPProof(privateKey, "access-token", http.MethodGet, target, "concurrent-proof", now)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewDPoPVerifier()
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 12 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := verifier.Verify(proof, "access-token", thumbprint, http.MethodGet, target, now); err == nil {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted concurrent replays = %d, want 1", got)
	}
}

func TestGateAuthenticatesAndAttachesClaims(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	_, privateKey := testKeyPair(t, 3)
	signer, err := NewSignerWithKey("key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	// Use a distinct key for DPoP; the access-token signer is not the agent key.
	agentPublicKey, agentPrivateKey := testKeyPair(t, 4)
	claims := testClaims(t, now, agentPublicKey)
	raw, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier("https://issuer.example", "lanyard-proxy", map[string]ed25519.PublicKey{"key-1": signer.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, ok := ClaimsFromRequest(r)
		if !ok || received.ID != "grant-1" {
			t.Errorf("ClaimsFromRequest() = %#v, %v", received, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Gate(verifier, NewDPoPVerifier(), next)
	req := httptest.NewRequest(http.MethodGet, "http://proxy.example/proxy", nil)
	proof, err := NewDPoPProof(agentPrivateKey, raw, req.Method, "http://proxy.example/proxy", "proof-gate", now)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("DPoP", proof)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("Gate() status = %d, want %d; body=%q", recorder.Code, http.StatusNoContent, recorder.Body.String())
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "http://proxy.example/proxy", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("Gate() without credentials status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}
}

func TestDecodeEd25519PrivateKey(t *testing.T) {
	_, privateKey := testKeyPair(t, 7)
	tests := []struct {
		name    string
		encoded string
		want    ed25519.PrivateKey
		wantErr bool
	}{
		{name: "32-byte seed", encoded: base64.RawURLEncoding.EncodeToString(privateKey.Seed()), want: privateKey},
		{name: "64-byte full key", encoded: base64.RawURLEncoding.EncodeToString(privateKey), want: privateKey},
		{name: "wrong length", encoded: base64.RawURLEncoding.EncodeToString(privateKey.Seed()[:16]), wantErr: true},
		{name: "malformed base64", encoded: "not*valid*base64", wantErr: true},
		{name: "empty", encoded: "", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodeEd25519PrivateKey(test.encoded)
			if (err != nil) != test.wantErr {
				t.Fatalf("DecodeEd25519PrivateKey() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if !bytes.Equal(got, test.want) {
				t.Fatal("DecodeEd25519PrivateKey() returned the wrong key")
			}
		})
	}
}

func TestThumbprintFromBase64AndScopeBoundary(t *testing.T) {
	publicKey, _ := testKeyPair(t, 5)
	encoded := base64.RawURLEncoding.EncodeToString(publicKey)
	thumbprint, err := PublicKeyThumbprintFromBase64(encoded)
	if err != nil {
		t.Fatal(err)
	}
	claims := Claims{Scope: []ScopeEntry{{Connector: "crm", Action: "read", Resource: "accounts"}}}
	if !HasScope(claims, "crm", "read", "accounts/42") {
		t.Fatal("HasScope() denied a child resource")
	}
	if HasScope(claims, "crm", "read", "accounts-elsewhere") {
		t.Fatal("HasScope() accepted a sibling resource")
	}
	if thumbprint == "" {
		t.Fatal("PublicKeyThumbprintFromBase64() returned an empty thumbprint")
	}
}
