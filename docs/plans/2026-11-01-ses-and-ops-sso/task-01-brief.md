# Task 01 — Config: `AUTH_CODE_DELIVERY=email`

**Where this fits:** first step of the SES feature. Nothing else may send email until
the config accepts the new delivery mode.

**Depends on:** nothing.
**Blocks:** 03.

## Files

- `internal/config/config.go` (edit)
- `internal/config/config_test.go` (edit)

## Write the tests first

Add to `internal/config/config_test.go` (they must fail before the code change):

```go
func TestValidateAuthEmailDelivery(t *testing.T) {
	base := func() Config {
		return Config{
			PublicBaseURL:    "https://console.linkedqueue.cloud",
			AuthCodeDelivery: "email",
			AuthEmailFrom:    "no-reply@linkedqueue.cloud",
			AWSRegion:        "ap-southeast-2",
			SessionTTL:       time.Hour,
			SessionIdle:      time.Minute,
		}
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	noRegion := base()
	noRegion.AWSRegion = ""
	if err := noRegion.Validate(); err == nil {
		t.Fatal("Validate() accepted email delivery without AWS_REGION")
	}

	for name, from := range map[string]string{
		"no-at":    "no-reply",
		"two-at":   "a@b@c",
		"space":    "no reply@linkedqueue.cloud",
		"empty":    "",
		"too-long": strings.Repeat("a", 250) + "@x.io",
	} {
		cfg := base()
		cfg.AuthEmailFrom = from
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate() accepted AUTH_EMAIL_FROM %q", name, from)
		}
	}
}

func TestValidateRejectsUnknownAuthCodeDelivery(t *testing.T) {
	cfg := Config{
		PublicBaseURL:    "http://localhost:8080",
		AuthCodeDelivery: "smtp",
		SessionTTL:       time.Hour,
		SessionIdle:      time.Minute,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted an unknown AUTH_CODE_DELIVERY")
	}
}

func TestLoadDefaultsAuthEmailFrom(t *testing.T) {
	t.Setenv("PORT", "8080")
	t.Setenv("TENANT_ID", "tenant-test")
	t.Setenv("VAULT_KEY_ID", "vault-test")
	t.Setenv("AUTH_EMAIL_FROM", "")

	if got := Load().AuthEmailFrom; got != "no-reply@linkedqueue.cloud" {
		t.Fatalf("AuthEmailFrom = %q, want no-reply@linkedqueue.cloud", got)
	}
}
```

Add `"strings"` and `"time"` to the test file imports as needed.

## Implementation

1. In `Config`, immediately after `AuthCodeDelivery`, add:

```go
	AuthEmailFrom        string        // env AUTH_EMAIL_FROM, used when AUTH_CODE_DELIVERY=email
```

   and change the `AuthCodeDelivery` comment to `// env AUTH_CODE_DELIVERY: none|log|response|email`.

2. In `Load()`, after the `AuthCodeDelivery` line, add:

```go
		AuthEmailFrom:        getEnv("AUTH_EMAIL_FROM", "no-reply@linkedqueue.cloud"),
```

3. In `Validate()` replace the delivery switch with:

```go
	switch c.AuthCodeDelivery {
	case "none", "log", "response", "email":
	default:
		return fmt.Errorf("AUTH_CODE_DELIVERY must be one of none, log, response, email")
	}
	if c.AuthCodeDelivery == "response" && !c.DevMode {
		return fmt.Errorf("AUTH_CODE_DELIVERY=response requires ALLOW_INSECURE_DEMO=true")
	}
	if c.AuthCodeDelivery == "email" {
		if c.AWSRegion == "" {
			return fmt.Errorf("AUTH_CODE_DELIVERY=email requires AWS_REGION")
		}
		if !validEmailFrom(c.AuthEmailFrom) {
			return fmt.Errorf("AUTH_EMAIL_FROM must be an email address")
		}
	}
```

4. Add near the other unexported helpers at the bottom of `config.go`:

```go
// validEmailFrom enforces the SES sender contract: at most 254 characters,
// exactly one "@", and no whitespace.
func validEmailFrom(value string) bool {
	return len(value) <= 254 &&
		strings.Count(value, "@") == 1 &&
		!strings.ContainsAny(value, " \t\r\n")
}
```

   Add `"strings"` to the imports.

Do **not** change `AuthCodeLogPlaintext`, `DevMode`, or any other validation rule.

## Verification

```sh
go test ./internal/config/ -run 'Email|Delivery' -v
go test ./internal/config/ && go vet ./internal/config/
```

Expect the three new tests to pass and all pre-existing config tests to stay green.
