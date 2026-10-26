package config

import (
    "fmt"
    "os"
)

// Config holds the runtime settings for the Lanyard services.
type Config struct {
    Host       string
    Port       string
    LogLevel   string
    TenantID   string
    VaultKeyID string
}

// Load reads environment variables and fails fast when required values are missing.
func Load() Config {
    cfg := Config{
        Host:       getEnv("HOST", "0.0.0.0"),
        Port:       getEnv("PORT", "8080"),
        LogLevel:   getEnv("LOG_LEVEL", "info"),
        TenantID:   getEnv("TENANT_ID", "tenant-demo"),
        VaultKeyID: getEnv("VAULT_KEY_ID", "local-dev-key"),
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

func (c Config) Address() string {
    return fmt.Sprintf("%s:%s", c.Host, c.Port)
}
