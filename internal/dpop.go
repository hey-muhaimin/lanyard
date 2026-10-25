package token

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultDPoPWindow = 60 * time.Second
	maxProofSize      = 8 * 1024
	maxReplayEntries  = 100000
)

type proofHeader struct {
	Algorithm string          `json:"alg"`
	Type      string          `json:"typ"`
	JWK       json.RawMessage `json:"jwk"`
}

type proofJWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	Key     string `json:"x"`
}

type proofClaims struct {
	Method    string `json:"htm"`
	TargetURL string `json:"htu"`
	IssuedAt  int64  `json:"iat"`
	ID        string `json:"jti"`
	TokenHash string `json:"ath"`
}

type DPoPVerifier struct {
	window      time.Duration
	mu          sync.Mutex
	seen        map[string]time.Time
	lastCleanup time.Time
}

func NewDPoPVerifier() *DPoPVerifier {
	return &DPoPVerifier{window: defaultDPoPWindow, seen: make(map[string]time.Time)}
}

func (v *DPoPVerifier) Verify(proof, accessToken, expectedThumbprint, method, targetURL string, now time.Time) error {
	if len(proof) == 0 || len(proof) > maxProofSize {
		return errors.New("invalid DPoP proof size")
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return errors.New("malformed DPoP proof")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("malformed DPoP proof header")
	}
	var header proofHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil ||
		header.Algorithm != "EdDSA" || header.Type != "dpop+jwt" || len(header.JWK) == 0 {
		return errors.New("unsupported DPoP proof header")
	}
	var headerFields map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &headerFields); err != nil || len(headerFields) != 3 {
		return errors.New("unsupported DPoP proof header")
	}
	for _, name := range []string{"alg", "typ", "jwk"} {
		if _, ok := headerFields[name]; !ok {
			return errors.New("unsupported DPoP proof header")
		}
	}
	var keyFields map[string]json.RawMessage
	if err := json.Unmarshal(header.JWK, &keyFields); err != nil || len(keyFields) != 3 {
		return errors.New("invalid DPoP public key")
	}
	var publicJWK proofJWK
	if err := json.Unmarshal(header.JWK, &publicJWK); err != nil ||
		publicJWK.KeyType != "OKP" || publicJWK.Curve != "Ed25519" {
		return errors.New("invalid DPoP public key")
	}
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(publicJWK.Key)
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize {
		return errors.New("invalid DPoP public key")
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)
	thumbprint, err := PublicKeyThumbprint(publicKey)
	if err != nil || thumbprint != expectedThumbprint {
		return errors.New("DPoP key does not match access token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return errors.New("invalid DPoP proof signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("malformed DPoP proof claims")
	}
	var claims proofClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return errors.New("malformed DPoP proof claims")
	}
	if claims.Method == "" || claims.Method != method {
		return errors.New("DPoP HTTP method mismatch")
	}
	if claims.TargetURL == "" || claims.TargetURL != targetURL || !isAbsoluteURL(claims.TargetURL) {
		return errors.New("DPoP target URL mismatch")
	}
	if claims.ID == "" || claims.IssuedAt <= 0 {
		return errors.New("DPoP proof ID and issue time are required")
	}
	if delta := now.Sub(time.Unix(claims.IssuedAt, 0)); delta > v.window || delta < -v.window {
		return errors.New("DPoP proof is outside the allowed time window")
	}
	tokenHash := sha256.Sum256([]byte(accessToken))
	if claims.TokenHash != base64.RawURLEncoding.EncodeToString(tokenHash[:]) {
		return errors.New("DPoP access-token hash mismatch")
	}
	return v.remember(thumbprint+":"+claims.ID, now)
}

func (v *DPoPVerifier) remember(key string, now time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if now.Sub(v.lastCleanup) >= v.window/2 || len(v.seen) >= maxReplayEntries {
		for id, expiry := range v.seen {
			if !expiry.After(now) {
				delete(v.seen, id)
			}
		}
		v.lastCleanup = now
	}
	if expiry, ok := v.seen[key]; ok && expiry.After(now) {
		return errors.New("DPoP proof replay detected")
	}
	if len(v.seen) >= maxReplayEntries {
		return errors.New("DPoP replay cache is full")
	}
	v.seen[key] = now.Add(v.window)
	return nil
}

func isAbsoluteURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.IsAbs() && parsed.Host != "" && parsed.Fragment == ""
}

func NewDPoPProof(privateKey ed25519.PrivateKey, accessToken, method, targetURL, proofID string, now time.Time) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid Ed25519 private key size")
	}
	if method == "" || !isAbsoluteURL(targetURL) || proofID == "" {
		return "", errors.New("method, absolute target URL, and proof ID are required")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	header, err := json.Marshal(struct {
		Algorithm string   `json:"alg"`
		Type      string   `json:"typ"`
		JWK       proofJWK `json:"jwk"`
	}{
		Algorithm: "EdDSA",
		Type:      "dpop+jwt",
		JWK:       proofJWK{KeyType: "OKP", Curve: "Ed25519", Key: base64.RawURLEncoding.EncodeToString(publicKey)},
	})
	if err != nil {
		return "", fmt.Errorf("marshal DPoP header: %w", err)
	}
	tokenHash := sha256.Sum256([]byte(accessToken))
	payload, err := json.Marshal(proofClaims{
		Method: method, TargetURL: targetURL, IssuedAt: now.Unix(), ID: proofID,
		TokenHash: base64.RawURLEncoding.EncodeToString(tokenHash[:]),
	})
	if err != nil {
		return "", fmt.Errorf("marshal DPoP claims: %w", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(unsigned))), nil
}
