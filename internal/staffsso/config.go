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
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", Scope)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
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
