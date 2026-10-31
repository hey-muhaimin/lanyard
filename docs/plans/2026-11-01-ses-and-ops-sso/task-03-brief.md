# Task 03 — Wire email delivery into the tenant auth handler

**Where this fits:** turns `AUTH_CODE_DELIVERY=email` into an actual email. The handler
gets a narrow `loginCodeSender` dependency so tests never touch SES.

**Depends on:** 01 (config field + validation), 02 (`mailer.LoginCodeSender`).
**Blocks:** 15.

## Files

- `cmd/controlplane/auth_server.go` (edit)
- `cmd/controlplane/auth_server_test.go` (edit)
- `cmd/controlplane/main.go` (edit)
- `cmd/controlplane/main_test.go` (edit — one call site)

## Behaviour to implement

`issueLoginCode` becomes a boolean: `true` means "nothing went wrong", `false` means
"the caller must not claim success".

| Situation | Result |
|---|---|
| code generation error | `false`, log error |
| store error | `false`, log error |
| `stored == false` (unknown email / throttled) | `true` — 202, no delivery (no enumeration) |
| `AUTH_CODE_DELIVERY=response` | as today (dev only) |
| `AUTH_CODE_DELIVERY=log` | as today |
| `AUTH_CODE_DELIVERY=email`, sender nil | `false`, log `"login code delivery is not configured"` |
| `AUTH_CODE_DELIVERY=email`, send error | `false`, log error (no code in the log line) |
| `AUTH_CODE_DELIVERY=email`, send ok | `true` |
| `AUTH_CODE_DELIVERY=none` | `true` |

Callers (`handleRequest`, `handleRegister`) return
`503 {"error":"unable to send sign-in code"}` when it is `false`.

## Tests first (`auth_server_test.go`)

Add the fake next to `fakeAuthStore`:

```go
// fakeSender records login-code deliveries; tests assert on calls and inject failures.
type fakeSender struct {
	calls []struct{ to, code string }
	err   error
}

func (f *fakeSender) SendLoginCode(ctx context.Context, to, code string) error {
	f.calls = append(f.calls, struct{ to, code string }{to: to, code: code})
	return f.err
}
```

Update the existing helper (all existing tests keep working):

```go
func newTestAuthHandler(store authStore, cfg config.Config) http.Handler {
	return newAuthHandler(store, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &fakeSender{})
}
```

Add a logger-injecting variant for the log test:

```go
func newTestAuthHandlerWithLogger(store authStore, cfg config.Config, logger *slog.Logger, sender loginCodeSender) http.Handler {
	return newAuthHandler(store, cfg, logger, sender)
}
```

Required new tests:

1. `TestAuthRequestEmailDeliverySendsCode`
   - store has member `alice@example.com`; `cfg.AuthCodeDelivery = "email"`.
   - POST `/auth/request` `{"email":"  Alice@Example.COM  "}`.
   - expect `202`; body has `status == "ok"` and **no** `dev_code` key.
   - `sender.calls` has exactly 1 entry: `to == "alice@example.com"`, `len(code) == 6`,
     all digits; and `store.codes["alice@example.com"]` equals `hashValue(code)`.
2. `TestAuthRequestEmailDeliveryFailureIsNotSuccess`
   - `sender.err = errors.New("SES is unavailable")`.
   - expect `503`, body `{"error":"unable to send sign-in code"}`, no `dev_code`,
     no `Set-Cookie`, and the response body does not contain the code.
3. `TestAuthRequestEmailDeliveryUnknownEmailSendsNothing`
   - unknown email; expect `202`, `status == "ok"`, `len(sender.calls) == 0`.
4. `TestAuthRequestEmailDeliveryNeverLogsCode`
   - handler built with `slog.New(slog.NewJSONHandler(&buf, nil))` and a working fake.
   - after a successful request, assert `!strings.Contains(buf.String(), code)` and
     `!strings.Contains(buf.String(), "dev_code")`.
5. `TestAuthRegisterEmailDeliveryFailureIsNotSuccess`
   - `AllowSignup = true`, `AuthCodeDelivery = "email"`, failing sender.
   - expect `503` and no `dev_code` (the tenant row may still have been created; that is
     accepted and must be documented in the handler comment).

## Implementation — `auth_server.go`

1. Add the interface and the field:

```go
// loginCodeSender delivers a sign-in code. Tests substitute a fake; production
// uses mailer.SES.
type loginCodeSender interface {
	SendLoginCode(ctx context.Context, to, code string) error
}
```

```go
type authHandler struct {
	store        authStore
	cfg          config.Config
	logger       *slog.Logger
	sender       loginCodeSender
	origin       string
	secureCookie bool
	mux          *http.ServeMux
}
```

2. Change the constructor:

```go
func newAuthHandler(store authStore, cfg config.Config, logger *slog.Logger, sender loginCodeSender) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &authHandler{
		store:        store,
		cfg:          cfg,
		logger:       logger,
		sender:       sender,
		origin:       originOf(cfg.PublicBaseURL),
		secureCookie: strings.EqualFold(schemeOf(cfg.PublicBaseURL), "https"),
	}
	// ... unchanged mux wiring
}
```

3. Replace `issueLoginCode` with:

```go
// issueLoginCode generates and stores a code, then delivers it per config. It
// reports false when the caller must not claim success: a generation or store
// failure, or an email delivery failure. It returns true when there was nothing
// to deliver (unknown email or throttled request), so callers cannot enumerate
// members.
func (h *authHandler) issueLoginCode(ctx context.Context, email string, body map[string]any) bool {
	code, err := newLoginCode()
	if err != nil {
		h.logger.Error("generate login code", "error", err)
		return false
	}
	stored, err := h.store.RequestCode(ctx, email, hashValue(code), time.Now().Add(loginCodeTTL))
	if err != nil {
		h.logger.Error("store login code", "error", err)
		return false
	}
	if !stored {
		return true
	}
	switch h.cfg.AuthCodeDelivery {
	case "response":
		if h.cfg.DevMode {
			body["dev_code"] = code
		}
	case "log":
		if h.cfg.AuthCodeLogPlaintext {
			h.logger.Info("login code issued", "email", email, "code", code)
		}
	case "email":
		if h.sender == nil {
			h.logger.Error("login code delivery is not configured", "delivery", "email")
			return false
		}
		if err := h.sender.SendLoginCode(ctx, email, code); err != nil {
			// The error text may name the recipient; the code is never logged.
			h.logger.Error("deliver login code", "delivery", "email", "error", err)
			return false
		}
	}
	return true
}
```

4. In `handleRequest`:

```go
	body := map[string]any{"status": "ok"}
	if email := normalizeEmail(req.Email); email != "" {
		if !h.issueLoginCode(r.Context(), email, body) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unable to send sign-in code"})
			return
		}
	}
	writeJSON(w, http.StatusAccepted, body)
```

5. In `handleRegister`, replace the trailing `h.issueLoginCode(...)` + 202 with:

```go
	body := map[string]any{"status": "ok"}
	if !h.issueLoginCode(r.Context(), email, body) {
		// The tenant may already exist; only the code delivery failed.
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unable to send sign-in code"})
		return
	}
	writeJSON(w, http.StatusAccepted, body)
```

## Implementation — `main.go`

1. Import `"github.com/example/lanyard/internal/mailer"`.
2. In `main()`, before building the server:

```go
	var sender loginCodeSender
	if cfg.AuthCodeDelivery == "email" {
		sesSender, err := mailer.NewSES(context.Background(), cfg.AWSRegion, cfg.AuthEmailFrom)
		if err != nil {
			logger.Error("failed to create SES mailer", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
		sender = sesSender
	}
```

3. Change the signature and the call site:

```go
func newControlPlaneHandler(gs *grant.Service, signer *token.Signer, cfg config.Config, pool *pgxpool.Pool, mail loginCodeSender) http.Handler {
```

```go
		mux.Handle("/auth/", newAuthHandler(authstore.New(pool), cfg, newAuthLogger(), mail))
```

   and in `main()`: `Handler: newControlPlaneHandler(gs, signer, cfg, pool, sender),`

## Implementation — `main_test.go`

Update the single call site:

```go
	return newControlPlaneHandler(service, signer, cfg, nil, nil), signer
```

## Verification

```sh
go test ./cmd/controlplane/ -run 'Auth' -v
go test ./... && go build ./... && go vet ./...
```

Manual spot check (optional, needs AWS credentials and a verified identity):

```sh
AUTH_CODE_DELIVERY=email AUTH_EMAIL_FROM=no-reply@linkedqueue.cloud AWS_REGION=ap-southeast-2 \
  go run ./cmd/controlplane   # then POST /auth/request; expect 202 and an email
```
