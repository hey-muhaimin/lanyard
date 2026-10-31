package config

import (
	"fmt"
	"net/url"
	"os"
	"time"
)

// Config holds the runtime settings for the Lanyard services.
type Config struct {
	Host                     string
	Port                     string
	LogLevel                 string
	TenantID                 string
	VaultKeyID               string
	KMSKeyID                 string // env KMS_KEY_ID
	AWSRegion                string // env AWS_REGION
	DatabaseURL              string // env DATABASE_URL
	DatabaseSecretARN        string // env DATABASE_SECRET_ARN
	TokenPrivateKeySecretARN string // env TOKEN_PRIVATE_KEY_SECRET_ARN
	UpstreamSecretARN        string // env UPSTREAM_SECRET_ARN
	ProxyConnectorID         string // env PROXY_CONNECTOR_ID
	ProxySecretID            string // env PROXY_SECRET_ID
	DevMode                  bool   // env ALLOW_INSECURE_DEMO == "true"

	// Customer console authentication.
	PublicBaseURL        string        // env PUBLIC_BASE_URL
	AuthCodeDelivery     string        // env AUTH_CODE_DELIVERY: none|log|response
	AuthCodeLogPlaintext bool          // env AUTH_CODE_LOG_PLAINTEXT == "true"
	AllowSignup          bool          // env ALLOW_SIGNUP == "true"
	SessionTTL           time.Duration // env SESSION_TTL
	SessionIdle          time.Duration // env SESSION_IDLE

	tokenKeyID    string // env TOKEN_KEY_ID
	tokenIssuer   string // env TOKEN_ISSUER
	tokenAudience string // env TOKEN_AUDIENCE
}

// Load reads environment variables and fails fast when required values are missing.
func Load() Config {
	cfg := Config{
		Host:                     getEnv("HOST", "0.0.0.0"),
		Port:                     getEnv("PORT", "8080"),
		LogLevel:                 getEnv("LOG_LEVEL", "info"),
		TenantID:                 getEnv("TENANT_ID", "tenant-demo"),
		VaultKeyID:               getEnv("VAULT_KEY_ID", "local-dev-key"),
		KMSKeyID:                 getEnv("KMS_KEY_ID", ""),
		AWSRegion:                getEnv("AWS_REGION", ""),
		DatabaseURL:              getEnv("DATABASE_URL", ""),
		DatabaseSecretARN:        getEnv("DATABASE_SECRET_ARN", ""),
		TokenPrivateKeySecretARN: getEnv("TOKEN_PRIVATE_KEY_SECRET_ARN", ""),
		UpstreamSecretARN:        getEnv("UPSTREAM_SECRET_ARN", ""),
		ProxyConnectorID:         getEnv("PROXY_CONNECTOR_ID", ""),
		ProxySecretID:            getEnv("PROXY_SECRET_ID", ""),
		DevMode:                  os.Getenv("ALLOW_INSECURE_DEMO") == "true",

		PublicBaseURL:        getEnv("PUBLIC_BASE_URL", "http://localhost:8080"),
		AuthCodeDelivery:     getEnv("AUTH_CODE_DELIVERY", "none"),
		AuthCodeLogPlaintext: os.Getenv("AUTH_CODE_LOG_PLAINTEXT") == "true",
		AllowSignup:          os.Getenv("ALLOW_SIGNUP") == "true",
		SessionTTL:           durationEnv("SESSION_TTL", 12*time.Hour),
		SessionIdle:          durationEnv("SESSION_IDLE", 2*time.Hour),

		tokenKeyID:    getEnv("TOKEN_KEY_ID", "local-dev-key"),
		tokenIssuer:   getEnv("TOKEN_ISSUER", "lanyard-controlplane"),
		tokenAudience: getEnv("TOKEN_AUDIENCE", "lanyard-proxy"),
	}

	if value, ok := os.LookupEnv("PORT"); ok && value == "" {
		panic("PORT is required")
	}
	if value, ok := os.LookupEnv("TENANT_ID"); ok && value == "" {
		panic("TENANT_ID is required")
	}
	if value, ok := os.LookupEnv("VAULT_KEY_ID"); ok && value == "" {
		panic("VAULT_KEY_ID is required")
	}
	if cfg.Port == "" {
		panic("PORT is required")
	}
	if cfg.TenantID == "" {
		panic("TENANT_ID is required")
	}
	if cfg.VaultKeyID == "" {
		panic("VAULT_KEY_ID is required")
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

// durationEnv parses a duration env var, falling back when unset. Invalid or
// non-positive values panic, matching Load's fail-fast semantics for config.
func durationEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		panic(key + " must be a positive duration")
	}
	return parsed
}

func (c Config) Address() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}

// TokenKeyID returns the key ID used to sign issued access tokens.
func (c Config) TokenKeyID() string {
	return c.tokenKeyID
}

// Issuer returns the JWT issuer claim for issued access tokens.
func (c Config) Issuer() string {
	return c.tokenIssuer
}

// Audience returns the JWT audience claim for issued access tokens.
func (c Config) Audience() string {
	return c.tokenAudience
}

// ValidateProduction returns an error when not in dev mode and KMS is not configured.
func (c Config) ValidateProduction() error {
	if !c.DevMode && (c.KMSKeyID == "" || c.AWSRegion == "") {
		return fmt.Errorf("production requires KMS configuration")
	}
	return nil
}

// Validate checks cross-field configuration that Load cannot express with its
// panic-on-empty semantics. Callers should invoke it at startup and exit on
// error. AUTH_CODE_DELIVERY=response is rejected outside dev mode because it
// returns login codes in the HTTP response.
func (c Config) Validate() error {
	switch c.AuthCodeDelivery {
	case "none", "log", "response":
	default:
		return fmt.Errorf("AUTH_CODE_DELIVERY must be one of none, log, response")
	}
	if c.AuthCodeDelivery == "response" && !c.DevMode {
		return fmt.Errorf("AUTH_CODE_DELIVERY=response requires ALLOW_INSECURE_DEMO=true")
	}
	base, err := url.Parse(c.PublicBaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return fmt.Errorf("PUBLIC_BASE_URL must be an absolute URL")
	}
	if c.SessionTTL <= 0 || c.SessionIdle <= 0 {
		return fmt.Errorf("SESSION_TTL and SESSION_IDLE must be positive")
	}
	return nil
}
