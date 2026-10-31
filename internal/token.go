package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	maxTokenSize           = 16 * 1024
	maxAccessTokenLifetime = 10 * time.Minute
)

type ScopeEntry struct {
	Connector string `json:"connector"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	MaxRows   int    `json:"max_rows"`
}

// Claims contains the signed task-grant claims and standard JWT timestamps.
type Claims struct {
	Issuer    string            `json:"iss"`
	Subject   string            `json:"sub"`
	Audience  string            `json:"aud"`
	ExpiresAt int64             `json:"exp"`
	IssuedAt  int64             `json:"iat"`
	ID        string            `json:"jti"`
	TenantID  string            `json:"tid"`
	Actor     string            `json:"act"`
	ChainID   string            `json:"chn,omitempty"`
	TaskID    string            `json:"tsk"`
	Scope     []ScopeEntry      `json:"scp"`
	PolicyVer int               `json:"pv"`
	Cnf       map[string]string `json:"cnf"`
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type jwk struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	Key       string `json:"x"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Private   string `json:"d,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type Signer struct {
	keyID string
	key   ed25519.PrivateKey
}

func NewSigner(keyID string) (*Signer, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	return NewSignerWithKey(keyID, privateKey)
}

func NewSignerWithKey(keyID string, privateKey ed25519.PrivateKey) (*Signer, error) {
	if keyID == "" {
		return nil, errors.New("key ID is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key size")
	}
	return &Signer{keyID: keyID, key: append(ed25519.PrivateKey(nil), privateKey...)}, nil
}

func (s *Signer) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.key.Public().(ed25519.PublicKey)...)
}

func (s *Signer) KeyID() string {
	return s.keyID
}

func (s *Signer) Sign(claims Claims) (string, error) {
	if err := validateClaims(claims); err != nil {
		return "", err
	}
	header, err := json.Marshal(jwtHeader{Algorithm: "EdDSA", KeyID: s.keyID, Type: "JWT"})
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal JWT claims: %w", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(s.key, []byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type Verifier struct {
	issuer   string
	audience string
	keys     map[string]ed25519.PublicKey
}

func NewVerifier(issuer, audience string, keys map[string]ed25519.PublicKey) (*Verifier, error) {
	if issuer == "" || audience == "" {
		return nil, errors.New("issuer and audience are required")
	}
	if len(keys) == 0 {
		return nil, errors.New("at least one verification key is required")
	}
	verifiedKeys := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, key := range keys {
		if keyID == "" || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 verification key %q", keyID)
		}
		verifiedKeys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return &Verifier{issuer: issuer, audience: audience, keys: verifiedKeys}, nil
}

func (v *Verifier) Verify(raw string, now time.Time) (Claims, error) {
	var claims Claims
	if len(raw) == 0 || len(raw) > maxTokenSize {
		return claims, errors.New("invalid access token size")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return claims, errors.New("malformed access token")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, errors.New("malformed access token header")
	}
	var headerFields map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &headerFields); err != nil || len(headerFields) != 3 {
		return claims, errors.New("malformed access token header")
	}
	for _, name := range []string{"alg", "kid", "typ"} {
		if _, ok := headerFields[name]; !ok {
			return claims, errors.New("malformed access token header")
		}
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil ||
		header.Algorithm != "EdDSA" || header.Type != "JWT" || header.KeyID == "" {
		return claims, errors.New("unsupported access token header")
	}
	key, ok := v.keys[header.KeyID]
	if !ok {
		return claims, errors.New("unknown access token key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return claims, errors.New("malformed access token signature")
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return claims, errors.New("invalid access token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, errors.New("malformed access token claims")
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, errors.New("malformed access token claims")
	}
	if err := validateClaims(claims); err != nil {
		return Claims{}, err
	}
	if claims.Issuer != v.issuer || claims.Audience != v.audience {
		return Claims{}, errors.New("access token issuer or audience mismatch")
	}
	nowUnix := now.Unix()
	if claims.ExpiresAt <= nowUnix {
		return Claims{}, errors.New("access token expired")
	}
	if claims.IssuedAt > nowUnix {
		return Claims{}, errors.New("access token issued in the future")
	}
	return claims, nil
}

func validateClaims(claims Claims) error {
	if claims.Issuer == "" || claims.Subject == "" || claims.Audience == "" ||
		claims.ID == "" || claims.TenantID == "" || claims.Actor == "" ||
		claims.TaskID == "" || claims.ExpiresAt <= 0 || claims.IssuedAt <= 0 {
		return errors.New("required access token claims are missing")
	}
	if claims.ExpiresAt <= claims.IssuedAt {
		return errors.New("access token expiry must follow its issue time")
	}
	if claims.ExpiresAt-claims.IssuedAt > int64(maxAccessTokenLifetime.Seconds()) {
		return errors.New("access token lifetime exceeds ten minutes")
	}
	if len(claims.Scope) == 0 {
		return errors.New("access token scope is required")
	}
	for _, scope := range claims.Scope {
		if scope.Connector == "" || scope.Action == "" || strings.Trim(scope.Resource, "/") == "" || scope.MaxRows < 0 {
			return errors.New("access token scope entry is malformed")
		}
	}
	jkt := claims.Cnf["jkt"]
	decoded, err := base64.RawURLEncoding.DecodeString(jkt)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("access token confirmation thumbprint is malformed")
	}
	return nil
}

func PublicJWKS(keyID string, publicKey ed25519.PublicKey) ([]byte, error) {
	if keyID == "" || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("valid key ID and Ed25519 public key are required")
	}
	return json.Marshal(jwks{Keys: []jwk{{
		KeyType: "OKP", Curve: "Ed25519", Key: base64.RawURLEncoding.EncodeToString(publicKey),
		KeyID: keyID, Use: "sig", Algorithm: "EdDSA",
	}}})
}

func VerifierFromJWKS(issuer, audience string, data []byte) (*Verifier, error) {
	var set jwks
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(set.Keys))
	for _, item := range set.Keys {
		if item.Private != "" {
			return nil, fmt.Errorf("JWKS key %q contains private key material", item.KeyID)
		}
		if item.KeyType != "OKP" || item.Curve != "Ed25519" || item.Use != "sig" || item.Algorithm != "EdDSA" {
			return nil, fmt.Errorf("unsupported JWKS key %q", item.KeyID)
		}
		if item.KeyID == "" {
			return nil, errors.New("JWKS key ID is required")
		}
		key, err := base64.RawURLEncoding.DecodeString(item.Key)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid JWKS key %q", item.KeyID)
		}
		if _, duplicate := keys[item.KeyID]; duplicate {
			return nil, fmt.Errorf("duplicate JWKS key ID %q", item.KeyID)
		}
		keys[item.KeyID] = ed25519.PublicKey(key)
	}
	return NewVerifier(issuer, audience, keys)
}

func PublicKeyThumbprint(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("invalid Ed25519 public key size")
	}
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(publicKey) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// PublicKeyThumbprintFromBase64 accepts base64url (padded or unpadded) and
// standard base64 (padded or unpadded) agent public keys.
func PublicKeyThumbprintFromBase64(encoded string) (string, error) {
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.StdEncoding,
		base64.RawStdEncoding,
	} {
		key, err := encoding.DecodeString(encoded)
		if err != nil || len(key) != ed25519.PublicKeySize {
			continue
		}
		return PublicKeyThumbprint(ed25519.PublicKey(key))
	}
	return "", errors.New("decode agent public key: must be a 32-byte base64 value")
}

// DecodeEd25519PrivateKey accepts base64url (unpadded) key material of either
// 32 bytes (Ed25519 seed) or 64 bytes (full private key) and returns a private key.
func DecodeEd25519PrivateKey(encoded string) (ed25519.PrivateKey, error) {
	if encoded == "" {
		return nil, errors.New("Ed25519 private key material is required")
	}
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode Ed25519 private key: %w", err)
	}
	switch len(key) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(key), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(key), nil
	default:
		return nil, fmt.Errorf("Ed25519 private key must be a %d-byte seed or a %d-byte private key, got %d bytes",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(key))
	}
}

func DecodeEd25519PublicKey(encoded string) (ed25519.PublicKey, error) {
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("TOKEN_PUBLIC_KEY must be a base64url Ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}
