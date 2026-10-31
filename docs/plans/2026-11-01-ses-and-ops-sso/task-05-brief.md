# Task 05 — Config: ops SSO settings

**Where this fits:** the control plane must fail at startup, not at the first sign-in, when
ops SSO is enabled without its secret ARN or public origin.

**Depends on:** nothing.
**Blocks:** 14.

## Files

- `internal/config/config.go` (edit)
- `internal/config/config_test.go` (edit)

## Tests first

```go
func TestValidateOpsSSO(t *testing.T) {
	base := func() Config {
		return Config{
			PublicBaseURL:    "https://console.linkedqueue.cloud",
			AuthCodeDelivery: "none",
			SessionTTL:       time.Hour,
			SessionIdle:      time.Minute,
			OpsSSOEnabled:    true,
			CognitoSecretARN: "arn:aws:secretsmanager:ap-southeast-2:459321894716:secret:production/lanyard/cognito-AbCdEf",
			OpsPublicBaseURL: "https://ops.linkedqueue.cloud",
		}
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	noARN := base()
	noARN.CognitoSecretARN = ""
	if err := noARN.Validate(); err == nil {
		t.Fatal("Validate() accepted ops SSO without COGNITO_SECRET_ARN")
	}

	noURL := base()
	noURL.OpsPublicBaseURL = ""
	if err := noURL.Validate(); err == nil {
		t.Fatal("Validate() accepted ops SSO without OPS_PUBLIC_BASE_URL")
	}

	relative := base()
	relative.OpsPublicBaseURL = "/ops"
	if err := relative.Validate(); err == nil {
		t.Fatal("Validate() accepted a non-absolute OPS_PUBLIC_BASE_URL")
	}

	insecure := base()
	insecure.OpsPublicBaseURL = "http://ops.linkedqueue.cloud"
	if err := insecure.Validate(); err == nil {
		t.Fatal("Validate() accepted an http OPS_PUBLIC_BASE_URL outside demo mode")
	}
	insecure.DevMode = true
	if err := insecure.Validate(); err != nil {
		t.Fatalf("Validate() in demo mode = %v, want nil", err)
	}

	disabled := base()
	disabled.OpsSSOEnabled = false
	disabled.CognitoSecretARN = ""
	disabled.OpsPublicBaseURL = ""
	if err := disabled.Validate(); err != nil {
		t.Fatalf("Validate() with SSO disabled = %v, want nil", err)
	}
}

func TestLoadOpsSSOSettings(t *testing.T) {
	t.Setenv("PORT", "8080")
	t.Setenv("TENANT_ID", "tenant-test")
	t.Setenv("VAULT_KEY_ID", "vault-test")
	t.Setenv("OPS_SSO_ENABLED", "true")
	t.Setenv("COGNITO_SECRET_ARN", "arn:aws:secretsmanager:ap-southeast-2:459321894716:secret:production/lanyard/cognito")
	t.Setenv("OPS_PUBLIC_BASE_URL", "https://ops.linkedqueue.cloud")

	cfg := Load()
	if !cfg.OpsSSOEnabled || cfg.CognitoSecretARN == "" || cfg.OpsPublicBaseURL != "https://ops.linkedqueue.cloud" {
		t.Fatalf("ops SSO settings = (%v, %q, %q)", cfg.OpsSSOEnabled, cfg.CognitoSecretARN, cfg.OpsPublicBaseURL)
	}

	t.Setenv("OPS_SSO_ENABLED", "")
	if Load().OpsSSOEnabled {
		t.Fatal("OPS_SSO_ENABLED must default to false")
	}
}
```

## Implementation

1. Add to `Config` after the customer-auth block:

```go
	// Internal ops console SSO (Amazon Cognito).
	OpsSSOEnabled    bool   // env OPS_SSO_ENABLED == "true"
	CognitoSecretARN string // env COGNITO_SECRET_ARN
	OpsPublicBaseURL string // env OPS_PUBLIC_BASE_URL, e.g. https://ops.linkedqueue.cloud
```

2. In `Load()`, after `SessionIdle`:

```go
		OpsSSOEnabled:    os.Getenv("OPS_SSO_ENABLED") == "true",
		CognitoSecretARN: getEnv("COGNITO_SECRET_ARN", ""),
		OpsPublicBaseURL: getEnv("OPS_PUBLIC_BASE_URL", ""),
```

3. In `Validate()`, after the `PUBLIC_BASE_URL` parse block and before the session-duration
   check:

```go
	if c.OpsSSOEnabled {
		if c.CognitoSecretARN == "" {
			return fmt.Errorf("OPS_SSO_ENABLED requires COGNITO_SECRET_ARN")
		}
		ops, err := url.Parse(c.OpsPublicBaseURL)
		if err != nil || ops.Scheme == "" || ops.Host == "" {
			return fmt.Errorf("OPS_PUBLIC_BASE_URL must be an absolute URL when OPS_SSO_ENABLED is true")
		}
		if !strings.EqualFold(ops.Scheme, "https") && !c.DevMode {
			return fmt.Errorf("OPS_PUBLIC_BASE_URL must use https outside demo mode")
		}
	}
```

`net/url` and `strings` are already imported; if not, add them.

Do not add a staff-group env var — the group name comes from the Cognito secret.

## Verification

```sh
go test ./internal/config/ -run 'OpsSSO|Validate' -v
go test ./internal/config/ && go vet ./internal/config/
```
