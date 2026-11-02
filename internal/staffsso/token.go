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
	if strings.TrimSpace(cfg.ClientSecret) != "" {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}

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
