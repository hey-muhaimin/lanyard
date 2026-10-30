package config

import "testing"

func TestLoadPanicsForEmptyRequiredSettings(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("TENANT_ID", "")
	t.Setenv("VAULT_KEY_ID", "")
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("Load() did not panic when required env vars were empty")
		}
	}()
	Load()
}

func TestLoadTokenSettings(t *testing.T) {
	t.Setenv("PORT", "8080")
	t.Setenv("TENANT_ID", "tenant-test")
	t.Setenv("VAULT_KEY_ID", "vault-test")
	t.Setenv("TOKEN_KEY_ID", "")
	t.Setenv("TOKEN_ISSUER", "")
	t.Setenv("TOKEN_AUDIENCE", "")

	cfg := Load()
	if cfg.TokenKeyID() != "local-dev-key" {
		t.Fatalf("TokenKeyID() = %q, want %q", cfg.TokenKeyID(), "local-dev-key")
	}
	if cfg.Issuer() != "lanyard-controlplane" {
		t.Fatalf("Issuer() = %q, want %q", cfg.Issuer(), "lanyard-controlplane")
	}
	if cfg.Audience() != "lanyard-proxy" {
		t.Fatalf("Audience() = %q, want %q", cfg.Audience(), "lanyard-proxy")
	}

	t.Setenv("TOKEN_KEY_ID", "kid-1")
	t.Setenv("TOKEN_ISSUER", "issuer-1")
	t.Setenv("TOKEN_AUDIENCE", "audience-1")

	cfg = Load()
	if cfg.TokenKeyID() != "kid-1" || cfg.Issuer() != "issuer-1" || cfg.Audience() != "audience-1" {
		t.Fatalf("token settings = (%q, %q, %q), want (%q, %q, %q)",
			cfg.TokenKeyID(), cfg.Issuer(), cfg.Audience(), "kid-1", "issuer-1", "audience-1")
	}
}

func TestValidateProduction(t *testing.T) {
	t.Setenv("PORT", "8080")
	t.Setenv("TENANT_ID", "tenant-demo")
	t.Setenv("VAULT_KEY_ID", "local-dev-key")
	// Dev mode defers KMS; clear it so the check is exercised.
	t.Setenv("ALLOW_INSECURE_DEMO", "")
	t.Setenv("KMS_KEY_ID", "")
	t.Setenv("AWS_REGION", "")

	cfg := Load()
	if err := cfg.ValidateProduction(); err == nil {
		t.Fatalf("ValidateProduction() = nil, want error (dev mode default)")
	}

	t.Setenv("ALLOW_INSECURE_DEMO", "true")
	if err := cfg.ValidateProduction(); err == nil {
		t.Fatalf("ValidateProduction() = nil, want error (dev mode defers KMS)")
	}

	t.Setenv("ALLOW_INSECURE_DEMO", "")
	t.Setenv("KMS_KEY_ID", "alias/lanyard-kms")
	t.Setenv("AWS_REGION", "ap-southeast-2")
	cfg = Load()
	if err := cfg.ValidateProduction(); err != nil {
		t.Fatalf("ValidateProduction() = %v, want nil (production KMS configured)", err)
	}
}
