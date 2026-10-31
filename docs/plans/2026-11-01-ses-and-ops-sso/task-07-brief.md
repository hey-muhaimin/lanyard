# Task 07 — `internal/staffsso`: secret parsing + authorize URL

**Where this fits:** first half of the Cognito client. Turns the Secrets Manager JSON into a
validated config and builds the hosted-UI authorization redirect. No network calls here.

**Depends on:** nothing.
**Blocks:** 08, 11.

## Files

- `internal/staffsso/config.go` (create)
- `internal/staffsso/config_test.go` (create)

## Secret shape (from Secrets Manager `production/lanyard/cognito`)

```json
{
  "userPoolId": "ap-southeast-2_YdESPvFwh",
  "clientId": "f3gcqfhc6rvmlo78ceffsfrdi",
  "clientSecret": "<confidential client secret>",
  "issuer": "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_YdESPvFwh",
  "hostedUiDomain": "https://lanyard-ops-staff.auth.ap-southeast-2.amazoncognito.com",
  "region": "ap-southeast-2",
  "staffGroup": "staff"
}
```

**Never** put a real `clientSecret` in source, tests, or docs. Tests use
`"test-client-secret"`.

## `internal/staffsso/config.go`

```go
// Package staffsso implements the Cognito authorization-code + PKCE flow the ops
// console uses to sign staff in. It never logs tokens, codes, or client secrets.
package staffsso

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Config is the JSON payload stored in the Cognito Secrets Manager secret
// (production/lanyard/cognito).
type Config struct {
	UserPoolID     string `json:"userPoolId"`
	ClientID       string `json:"clientId"`
	ClientSecret   string `json:"clientSecret"`
	Issuer         string `json:"issuer"`
	HostedUIDomain string `json:"hostedUiDomain"`
	Region         string `json:"region"`
	StaffGroup     string `json:"staffGroup"`
}

const (
	// CallbackPath is the callback registered on the Cognito app client. The
	// trailing slash must match the registered URL exactly.
	CallbackPath = "/ops/auth/callback/"
	// Scope is the fixed OIDC scope string requested from the hosted UI.
	Scope = "openid email profile"
)

// ParseConfig decodes and validates a Cognito secret payload.
func ParseConfig(raw []byte) (Config, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode Cognito secret: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate enforces the fields the flow cannot work without.
func (c Config) Validate() error {
	issuer, err := url.Parse(c.Issuer)
	if err != nil || !strings.EqualFold(issuer.Scheme, "https") || issuer.Host == "" {
		return errors.New("Cognito issuer must be an absolute https URL")
	}
	hosted, err := url.Parse(c.HostedUIDomain)
	if err != nil || !strings.EqualFold(hosted.Scheme, "https") || hosted.Host == "" {
		return errors.New("Cognito hostedUiDomain must be an absolute https URL")
	}
	switch {
	case c.UserPoolID == "":
		return errors.New("Cognito secret is missing userPoolId")
	case c.ClientID == "":
		return errors.New("Cognito secret is missing clientId")
	case c.ClientSecret == "":
		return errors.New("Cognito secret is missing clientSecret")
	case c.StaffGroup == "":
		return errors.New("Cognito secret is missing staffGroup")
	}
	return nil
}

// RedirectURI joins the public ops origin with CallbackPath, with exactly one slash.
func RedirectURI(base string) string {
	return strings.TrimSuffix(strings.TrimSpace(base), "/") + CallbackPath
}

// AuthorizeURL builds the hosted-UI authorization request.
func (c Config) AuthorizeURL(redirectURI, state, codeChallenge string) (string, error) {
	if redirectURI == "" || state == "" || codeChallenge == "" {
		return "", errors.New("authorize URL requires redirect URI, state and PKCE challenge")
	}
	u, err := url.Parse(strings.TrimSuffix(c.HostedUIDomain, "/") + "/oauth2/authorize")
	if err != nil {
		return "", fmt.Errorf("build authorize URL: %w", err)
	}
	query := u.Query()
	query.Set("response_type", "code")
	query.Set("client_id", c.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", Scope)
	query.Set("state", state)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")
	u.RawQuery = query.Encode()
	return u.String(), nil
}

// TokenURL is the hosted-UI token endpoint.
func (c Config) TokenURL() string {
	return strings.TrimSuffix(c.HostedUIDomain, "/") + "/oauth2/token"
}

// JWKSURL is the pool's signing-key set.
func (c Config) JWKSURL() string {
	return strings.TrimSuffix(c.Issuer, "/") + "/.well-known/jwks.json"
}
```

## `internal/staffsso/config_test.go`

Required cases:

1. `TestParseConfigAcceptsSecretShape` — decode a literal with the real
   `userPoolId`/`clientId`/`issuer`/`hostedUiDomain`/`staffGroup` above and
   `clientSecret: "test-client-secret"`; assert every field round-trips and `Validate()`
   is nil.
2. `TestParseConfigRejectsMissingFields` — table: drop each of `userPoolId`, `clientId`,
   `clientSecret`, `staffGroup`; also `issuer: "http://…"` and `hostedUiDomain: "/relative"`.
   Each must return an error, and no error string may contain the secret value.
3. `TestRedirectURI` — `RedirectURI("https://ops.linkedqueue.cloud")` and
   `RedirectURI("https://ops.linkedqueue.cloud/")` both equal
   `https://ops.linkedqueue.cloud/ops/auth/callback/`.
4. `TestAuthorizeURL` — parse the result and assert:
   - host `lanyard-ops-staff.auth.ap-southeast-2.amazoncognito.com`, path `/oauth2/authorize`
   - `response_type=code`, `client_id=f3gcqfhc6rvmlo78ceffsfrdi`
   - `redirect_uri=https://ops.linkedqueue.cloud/ops/auth/callback/`
   - `scope=openid email profile`
   - `code_challenge_method=S256`
   - `state` and `code_challenge` equal the values passed in
   - empty state or challenge returns an error.
5. `TestTokenAndJWKSURLs` —
   `TokenURL() == "https://lanyard-ops-staff.auth.ap-southeast-2.amazoncognito.com/oauth2/token"`,
   `JWKSURL() == "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_YdESPvFwh/.well-known/jwks.json"`.
   Also assert a trailing slash on `hostedUiDomain`/`issuer` does not double up.

## Verification

```sh
go test ./internal/staffsso/ -v
go vet ./internal/staffsso/
```

No test may perform network I/O.
