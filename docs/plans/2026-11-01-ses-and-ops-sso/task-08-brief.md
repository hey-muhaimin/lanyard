# Task 08 — `internal/staffsso`: code exchange + ID-token verification

**Where this fits:** second half of the Cognito client. Exchanges the authorization code
using the client secret and PKCE verifier, then verifies the returned ID token against the
pool JWKS. Both are offline-testable with `httptest`.

**Depends on:** 07 (`Config`, `TokenURL`, `JWKSURL`).
**Blocks:** 12.

## Files

- `internal/staffsso/token.go` (create)
- `internal/staffsso/verify.go` (create)
- `internal/staffsso/token_test.go` (create)
- `internal/staffsso/verify_test.go` (create)
- `go.mod`, `go.sum`

## Dependency

```sh
go get github.com/golang-jwt/jwt/v5@v5.2.1
go mod tidy
```

Commit whatever `go mod tidy` resolves for `github.com/golang-jwt/jwt/v5`.

## `internal/staffsso/token.go`

```go
package staffsso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxTokenResponseBytes bounds the token endpoint response we will read.
const maxTokenResponseBytes = 1 << 20

// ExchangeCode redeems an authorization code for an ID token. Errors never contain
// the response body, the code, or the client secret.
func ExchangeCode(ctx context.Context, client *http.Client, cfg Config, redirectURI, code, codeVerifier string) (string, error) {
	if client == nil {
		return "", errors.New("code exchange requires an HTTP client")
	}
	if code == "" || codeVerifier == "" {
		return "", errors.New("code exchange requires a code and PKCE verifier")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", cfg.ClientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("exchange authorization code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", errors.New("token endpoint returned malformed JSON")
	}
	if payload.IDToken == "" {
		return "", errors.New("token endpoint returned no id_token")
	}
	return payload.IDToken, nil
}
```

## `internal/staffsso/verify.go`

```go
package staffsso

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// jwksTTL is how long fetched signing keys are reused.
	jwksTTL = time.Hour
	// minJWKSRefresh throttles refetches triggered by an unknown kid.
	minJWKSRefresh = time.Minute
	// maxJWKSBytes bounds the JWKS response we are willing to parse.
	maxJWKSBytes = 1 << 20
)

// Identity is the verified staff identity extracted from a Cognito ID token.
type Identity struct {
	Subject     string
	Email       string
	Groups      []string
	HardwareKey bool
}

// Verifier validates Cognito ID tokens against the user pool's JWKS.
type Verifier struct {
	issuer   string
	clientID string
	jwksURL  string
	client   *http.Client
	now      func() time.Time
	ttl      time.Duration

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// NewVerifier builds a verifier. A nil client gets a 5-second-timeout client.
func NewVerifier(issuer, clientID, jwksURL string, client *http.Client) *Verifier {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Verifier{
		issuer:   issuer,
		clientID: clientID,
		jwksURL:  jwksURL,
		client:   client,
		now:      time.Now,
		ttl:      jwksTTL,
		keys:     map[string]*rsa.PublicKey{},
	}
}

// idTokenClaims is the subset of Cognito ID-token claims the ops console needs.
type idTokenClaims struct {
	TokenUse      string   `json:"token_use"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	CognitoUser   string   `json:"cognito:username"`
	Groups        []string `json:"cognito:groups"`
	AMR           []string `json:"amr"`
	jwt.RegisteredClaims
}

// Verify checks signature, algorithm, issuer, audience and expiry, then extracts
// the staff identity. It does not check group membership; the caller does.
func (v *Verifier) Verify(ctx context.Context, raw string) (Identity, error) {
	if raw == "" {
		return Identity{}, errors.New("id token is required")
	}
	claims := &idTokenClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.clientID),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
	)
	token, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("id token has no kid header")
		}
		return v.keyFor(ctx, kid)
	})
	if err != nil {
		return Identity{}, fmt.Errorf("verify id token: %w", err)
	}
	if !token.Valid {
		return Identity{}, errors.New("id token is not valid")
	}
	if claims.TokenUse != "id" {
		return Identity{}, errors.New("token is not an ID token")
	}
	if claims.Subject == "" || claims.Email == "" {
		return Identity{}, errors.New("id token is missing sub or email")
	}
	return Identity{
		Subject:     claims.Subject,
		Email:       claims.Email,
		Groups:      claims.Groups,
		HardwareKey: slices.Contains(claims.AMR, "hwk"),
	}, nil
}

// keyFor returns the RSA key for kid, refreshing the JWKS when the cache is stale
// or the kid is unknown (throttled to once a minute).
func (v *Verifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if key, ok := v.keys[kid]; ok && v.now().Sub(v.fetchedAt) < v.ttl {
		return key, nil
	}
	if v.now().Sub(v.fetchedAt) < minJWKSRefresh {
		return nil, fmt.Errorf("id token kid %q is not in the pool JWKS", kid)
	}
	if err := v.refreshLocked(ctx); err != nil {
		return nil, err
	}
	key, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("id token kid %q is not in the pool JWKS", kid)
	}
	return key, nil
}

func (v *Verifier) refreshLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return fmt.Errorf("read JWKS: %w", err)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return errors.New("JWKS response is not valid JSON")
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		exponent, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exponent).Int64()),
		}
	}
	if len(keys) == 0 {
		return errors.New("JWKS response contains no RSA signing keys")
	}
	v.keys = keys
	v.fetchedAt = v.now()
	return nil
}
```

## Tests

Shared helper for both test files (`token_test.go` or a small `helpers_test.go`):

```go
const testIssuer = "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_TESTPOOL"
const testClientID = "test-client-id"

// jwksServer serves the public half of key under kid and counts requests.
func jwksServer(t *testing.T, kid string, key *rsa.PrivateKey) (*httptest.Server, *int32)
```

Encode `n`/`e` with `base64.RawURLEncoding` from `key.PublicKey.N.Bytes()` and
`big.NewInt(int64(key.PublicKey.E)).Bytes()`.

`token_test.go`:

1. `TestExchangeCodeSendsBasicAuthAndForm` — `httptest` server asserts
   `Authorization: Basic base64("test-client-id:test-client-secret")`, `Content-Type`,
   and form values `grant_type=authorization_code`, `client_id`, `code`,
   `redirect_uri`, `code_verifier`; returns `{"id_token":"header.payload.sig"}`; assert the
   returned string matches.
2. `TestExchangeCodeRejectsFailures` — table: 400 response, 200 with invalid JSON, 200 with
   empty `id_token`. Each returns an error; no error string contains `code-123`, the client
   secret, or the response body.
3. `TestExchangeCodeRequiresInputs` — nil client, empty code, empty verifier all error
   without making a request.

`verify_test.go`:

4. `TestVerifyAcceptsValidIDToken` — token claims: `iss=testIssuer`, `aud=testClientID`,
   `sub="sub-1"`, `email="alice@linkedqueue.cloud"`, `email_verified=true`,
   `token_use="id"`, `cognito:groups=["staff"]`, `amr=["pwd","hwk"]`, `exp=now+5m`,
   `iat=now`. Assert `Identity{Subject:"sub-1", Email:"alice@linkedqueue.cloud",
   Groups:["staff"], HardwareKey:true}`.
5. `TestVerifyWithoutHardwareKey` — `amr=["pwd"]` → `HardwareKey == false`.
6. `TestVerifyRejectsBadTokens` — table, each must error:
   - wrong `aud`
   - wrong `iss`
   - `exp` in the past
   - no `exp`
   - `token_use="access"`
   - missing `email`
   - signed with HS256 using the client secret (must be rejected by valid-methods)
   - signed with a *different* RSA key but the same kid
   - truncated/garbage string
7. `TestVerifyRefreshesUnknownKidOncePerMinute` — server serves only `kid-1`; verify a
   `kid-2` token → error and exactly one JWKS request; immediately verify again → still one
   request (throttle). Advance the injected `now` by 2 minutes and add `kid-2` to the
   served set → verify succeeds and the request count is 2.
8. `TestVerifyCachesKeys` — two successful verifies with `kid-1` → one JWKS request.
9. `TestVerifyJWKSFailure` — JWKS endpoint returns 500 → error mentioning status, no panic.

Sign tokens in tests with:

```go
token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
token.Header["kid"] = "kid-1"
raw, err := token.SignedString(privateKey)
```

Use `rsa.GenerateKey(rand.Reader, 2048)` in `t.TempDir`-style helpers; generation takes a
moment, so generate once per test file via a package-level `sync.Once` helper.

## Verification

```sh
go test ./internal/staffsso/ -v
go vet ./internal/staffsso/ && go build ./...
```

All tests are offline; no Cognito credentials are needed.
