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

type Identity struct {
    Subject     string
    Email       string
    Groups        []string
    HardwareKey   bool
    EmailVerified bool
}

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
        Subject:       claims.Subject,
        Email:         claims.Email,
        Groups:        claims.Groups,
        HardwareKey:   slices.Contains(claims.AMR, "hwk"),
        EmailVerified: claims.EmailVerified,
    }, nil
}

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
        keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(new(big.Int).SetBytes(exponent).Int64())}
    }
    if len(keys) == 0 {
        return errors.New("JWKS response contains no RSA signing keys")
    }
    v.keys = keys
    v.fetchedAt = v.now()
    return nil
}
