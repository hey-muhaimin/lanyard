package staffsso

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "encoding/base64"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "sync/atomic"
    "testing"
    "time"

    "math/big"

    "github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_TESTPOOL"
const testClientID = "test-client-id"

// jwksServer returns a JWKS JSON containing the given key under the given kid.
func jwksServer(t *testing.T, kid string, key *rsa.PrivateKey) (*httptest.Server, *int32) {
    var count int32
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        atomic.AddInt32(&count, 1)
        n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
        e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
        jwks := map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": kid, "n": n, "e": e}}}
        data, _ := json.Marshal(jwks)
        w.Header().Set("Content-Type", "application/json")
        w.Write(data)
    }))
    return srv, &count
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
    t.Helper()
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatalf("generate RSA key: %v", err)
    }
    return key
}

func TestVerifyAcceptsValidIDToken(t *testing.T) {
    key := newRSAKey(t)
    kid := "kid-1"
    srv, _ := jwksServer(t, kid, key)
    defer srv.Close()
    verifier := NewVerifier(testIssuer, testClientID, srv.URL, nil)
    // create token
    now := time.Now()
    claims := idTokenClaims{TokenUse: "id", Email: "alice@linkedqueue.cloud", EmailVerified: true, CognitoUser: "alice", Groups: []string{"staff"}, AMR: []string{"pwd", "hwk"}, RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Audience: []string{testClientID}, Subject: "sub-1", ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(now)}}
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    token.Header["kid"] = kid
    raw, err := token.SignedString(key)
    if err != nil {
        t.Fatalf("sign token: %v", err)
    }
    id, err := verifier.Verify(context.Background(), raw)
    if err != nil {
        t.Fatalf("verify error: %v", err)
    }
    if id.Subject != "sub-1" || id.Email != "alice@linkedqueue.cloud" || len(id.Groups) != 1 || id.Groups[0] != "staff" || !id.HardwareKey {
        t.Fatalf("unexpected identity: %+v", id)
    }
}

func TestVerifyWithoutHardwareKey(t *testing.T) {
    key := newRSAKey(t)
    kid := "kid-1"
    srv, _ := jwksServer(t, kid, key)
    defer srv.Close()
    verifier := NewVerifier(testIssuer, testClientID, srv.URL, nil)
    now := time.Now()
    claims := idTokenClaims{TokenUse: "id", Email: "bob@linkedqueue.cloud", EmailVerified: true, CognitoUser: "bob", Groups: []string{"staff"}, AMR: []string{"pwd"}, RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Audience: []string{testClientID}, Subject: "sub-2", ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(now)}}
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    token.Header["kid"] = kid
    raw, _ := token.SignedString(key)
    id, err := verifier.Verify(context.Background(), raw)
    if err != nil {
        t.Fatalf("verify error: %v", err)
    }
    if id.HardwareKey {
        t.Fatalf("expected hardwareKey false, got true")
    }
}

func TestVerifyRejectsBadTokens(t *testing.T) {
    // Shared valid key and JWKS server
    key := newRSAKey(t)
    kid := "kid-1"
    srv, _ := jwksServer(t, kid, key)
    defer srv.Close()
    verifier := NewVerifier(testIssuer, testClientID, srv.URL, nil)
    now := time.Now()
    // helper to create token with overrides
    makeToken := func(modify func(*idTokenClaims)) string {
        claims := idTokenClaims{TokenUse: "id", Email: "alice@linkedqueue.cloud", EmailVerified: true, CognitoUser: "alice", Groups: []string{"staff"}, AMR: []string{"pwd", "hwk"}, RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Audience: []string{testClientID}, Subject: "sub-1", ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(now)}}
        modify(&claims)
        token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
        token.Header["kid"] = kid
        raw, _ := token.SignedString(key)
        return raw
    }
    cases := []struct {
        name  string
        token string
    }{
        {"wrong audience", func() string { tkn := makeToken(func(c *idTokenClaims) { c.Audience = []string{"bad-aud"} }); return tkn }()},
        {"wrong issuer", func() string { tkn := makeToken(func(c *idTokenClaims) { c.Issuer = "https://bad-issuer" }); return tkn }()},
        {"expired", func() string { tkn := makeToken(func(c *idTokenClaims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-5 * time.Minute)) }); return tkn }()},
        {"no exp", func() string { tkn := makeToken(func(c *idTokenClaims) { c.ExpiresAt = nil }); return tkn }()},
        {"not id token", func() string { tkn := makeToken(func(c *idTokenClaims) { c.TokenUse = "access" }); return tkn }()},
        {"missing email", func() string { tkn := makeToken(func(c *idTokenClaims) { c.Email = "" }); return tkn }()},
        {"hs256 signed", func() string { // sign with HS256 using client secret as key
            hsKey := []byte("test-client-secret")
            claims := jwt.MapClaims{"iss": testIssuer, "aud": testClientID, "sub": "sub-1", "exp": now.Add(5 * time.Minute).Unix(), "token_use": "id", "email": "alice@linkedqueue.cloud"}
            token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
            token.Header["kid"] = kid
            raw, _ := token.SignedString(hsKey)
            return raw
        }()},
        {"different key same kid", func() string { otherKey := newRSAKey(t); token := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims{TokenUse: "id", Email: "alice@linkedqueue.cloud", EmailVerified: true, CognitoUser: "alice", Groups: []string{"staff"}, AMR: []string{"pwd", "hwk"}, RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Audience: []string{testClientID}, Subject: "sub-1", ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(now)}}); token.Header["kid"] = kid; raw, _ := token.SignedString(otherKey); return raw }()},
        {"garbage", "not-a-token"},
    }
    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            _, err := verifier.Verify(context.Background(), c.token)
            if err == nil {
                t.Fatalf("expected error for case %s", c.name)
            }
        })
    }
}

func TestVerifyRefreshesUnknownKidOncePerMinute(t *testing.T) {
    key1 := newRSAKey(t)
    kid1 := "kid-1"
    srv, count := jwksServer(t, kid1, key1)
    defer srv.Close()
    verifier := NewVerifier(testIssuer, testClientID, srv.URL, nil)
    // set custom now function for control
    now := time.Now()
    verifier.now = func() time.Time { return now }

    // token with unknown kid-2
    key2 := newRSAKey(t)
    claims := idTokenClaims{TokenUse: "id", Email: "alice@linkedqueue.cloud", EmailVerified: true, CognitoUser: "alice", Groups: []string{"staff"}, AMR: []string{"pwd", "hwk"}, RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Audience: []string{testClientID}, Subject: "sub-1", ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(now)}}
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    token.Header["kid"] = "kid-2"
    raw, _ := token.SignedString(key2)
    // first verify fails due to unknown kid, should fetch JWKS once
    if _, err := verifier.Verify(context.Background(), raw); err == nil {
        t.Fatalf("expected error for unknown kid")
    }
    if got := atomic.LoadInt32(count); got != 1 {
        t.Fatalf("expected 1 JWKS request, got %d", got)
    }
    // second verify immediately, should not fetch again
    if _, err := verifier.Verify(context.Background(), raw); err == nil {
        t.Fatalf("expected error again for unknown kid")
    }
    if got := atomic.LoadInt32(count); got != 1 {
        t.Fatalf("expected still 1 JWKS request, got %d", got)
    }
    // advance time beyond minJWKSRefresh and add kid-2 to JWKS server response
    // We'll replace the server with a new one containing both keys.
    srv2, count2 := jwksServer(t, "kid-2", key2)
    // Update verifier jwksURL to new server; also update its fetchedAt to past time to force refresh.
    verifier.jwksURL = srv2.URL
    now = now.Add(2 * time.Minute)
    // Now verification should succeed and fetch JWKS again.
    if _, err := verifier.Verify(context.Background(), raw); err != nil {
        t.Fatalf("expected success after adding kid, got %v", err)
    }
    if got := atomic.LoadInt32(count2); got != 1 {
        t.Fatalf("expected 1 JWKS request on second server, got %d", got)
    }
}

func TestVerifyCachesKeys(t *testing.T) {
    key := newRSAKey(t)
    kid := "kid-1"
    srv, count := jwksServer(t, kid, key)
    defer srv.Close()
    verifier := NewVerifier(testIssuer, testClientID, srv.URL, nil)
    now := time.Now()
    verifier.now = func() time.Time { return now }
    // token 1
    claims1 := idTokenClaims{TokenUse: "id", Email: "a@b.c", EmailVerified: true, CognitoUser: "a", Groups: []string{"staff"}, AMR: []string{"pwd"}, RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Audience: []string{testClientID}, Subject: "sub1", ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(now)}}
    token1 := jwt.NewWithClaims(jwt.SigningMethodRS256, claims1)
    token1.Header["kid"] = kid
    raw1, _ := token1.SignedString(key)
    if _, err := verifier.Verify(context.Background(), raw1); err != nil {
        t.Fatalf("first verify error: %v", err)
    }
    // token 2 same kid
    claims2 := claims1
    claims2.Subject = "sub2"
    token2 := jwt.NewWithClaims(jwt.SigningMethodRS256, claims2)
    token2.Header["kid"] = kid
    raw2, _ := token2.SignedString(key)
    if _, err := verifier.Verify(context.Background(), raw2); err != nil {
        t.Fatalf("second verify error: %v", err)
    }
    if got := atomic.LoadInt32(count); got != 1 {
        t.Fatalf("expected 1 JWKS request, got %d", got)
    }
}

func TestVerifyJWKSFailure(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
    defer srv.Close()
    verifier := NewVerifier(testIssuer, testClientID, srv.URL, nil)
    now := time.Now()
    verifier.now = func() time.Time { return now }
    // token signed with any key
    key := newRSAKey(t)
    claims := idTokenClaims{TokenUse: "id", Email: "a@b.c", EmailVerified: true, CognitoUser: "a", Groups: []string{"staff"}, AMR: []string{"pwd"}, RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Audience: []string{testClientID}, Subject: "sub", ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(now)}}
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    token.Header["kid"] = "kid"
    raw, _ := token.SignedString(key)
    _, err := verifier.Verify(context.Background(), raw)
    if err == nil {
        t.Fatalf("expected error due to JWKS failure")
    }
}
