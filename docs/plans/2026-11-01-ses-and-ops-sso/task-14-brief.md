# Task 14 — Startup wiring: load the Cognito secret and mount `/ops/`

**Where this fits:** the last Go task. Composes the ops auth routes and the protected API,
loads the Cognito secret from Secrets Manager, and mounts the result at `/ops/` **only** when
`OPS_SSO_ENABLED=true`. Until this task, `/ops/*` stays 404, which `AGENTS.md` requires.

**Depends on:** 05 (`OpsSSOEnabled`, `CognitoSecretARN`, `OpsPublicBaseURL`), 12 (callback /
me / logout), 13 (`requireOpsSession`, `newOpsAPI`).
**Blocks:** 15.

## Files

- `cmd/controlplane/ops_wire.go` (create)
- `cmd/controlplane/main.go` (edit)
- `cmd/controlplane/main_test.go` (edit)

## `cmd/controlplane/ops_wire.go`

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/example/lanyard/internal/awssecrets"
	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/opsstore"
	"github.com/example/lanyard/internal/staffsso"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newOpsHandler builds the complete /ops/* surface behind Cognito SSO. It is
// only called when OPS_SSO_ENABLED is true; any other configuration leaves /ops
// unmounted so the routes stay 404.
func newOpsHandler(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) (http.Handler, error) {
	if pool == nil {
		return nil, errors.New("ops SSO requires a database pool")
	}
	secrets, err := awssecrets.NewFromEnv(ctx, cfg.AWSRegion)
	if err != nil {
		return nil, fmt.Errorf("create secrets client for ops SSO: %w", err)
	}
	raw, err := secrets.String(ctx, cfg.CognitoSecretARN)
	if err != nil {
		return nil, fmt.Errorf("load Cognito secret: %w", err)
	}
	ssoCfg, err := staffsso.ParseConfig([]byte(raw))
	if err != nil {
		return nil, err
	}

	store := opsstore.New(pool)
	verifier := staffsso.NewVerifier(ssoCfg.Issuer, ssoCfg.ClientID, ssoCfg.JWKSURL(), nil)
	sso := newOpsSSO(cfg, ssoCfg, verifier, store, logger)
	api := newOpsAPI(store, logger)
	guard := func(next http.Handler) http.Handler {
		return requireOpsSession(store, cfg.SessionIdle, logger)(next)
	}

	root := http.NewServeMux()
	// Unauthenticated: the browser has no ops session yet.
	root.HandleFunc("GET /ops/auth/login", sso.login)
	root.HandleFunc("GET /ops/auth/callback/", sso.callback)
	root.HandleFunc("POST /ops/auth/logout", sso.logout)
	// Authenticated.
	root.Handle("GET /ops/auth/me", guard(http.HandlerFunc(sso.me)))
	root.Handle("/ops/health", guard(api))
	root.Handle("/ops/tenants", guard(api))
	root.Handle("/ops/actions", guard(api))
	root.Handle("/ops/actions/", guard(api))

	return opsOriginGuard(originOf(cfg.OpsPublicBaseURL), cspMiddleware(root)), nil
}
```

Note: the inner mux receives the full path — `mux.Handle("/ops/", ops)` does not strip the
prefix.

## `cmd/controlplane/main.go`

1. After the signer is built in `main()`, add:

```go
	var opsHandler http.Handler
	if cfg.OpsSSOEnabled {
		handler, err := newOpsHandler(context.Background(), cfg, pool, newAuthLogger())
		if err != nil {
			logger.Error("failed to initialize ops SSO", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
		opsHandler = handler
	}
```

2. Change the call site:

```go
		Handler:           newControlPlaneHandler(gs, signer, cfg, pool, mail, opsHandler),
```

3. Change the signature and mount conditionally, immediately **before** the final
   `return cspMiddleware(mux)`:

```go
func newControlPlaneHandler(gs *grant.Service, signer *token.Signer, cfg config.Config, pool *pgxpool.Pool, mail loginCodeSender, ops http.Handler) http.Handler {
```

```go
	// The ops console is mounted only when real staff SSO is configured; any
	// other configuration keeps /ops/* at 404 (see AGENTS.md).
	if ops != nil {
		mux.Handle("/ops/", ops)
	}
	// Wrap the entire mux with CSP middleware for the static console apps.
	return cspMiddleware(mux)
```

`mail` is the parameter added in task 03 — do not rename it.

## `cmd/controlplane/main_test.go`

1. Update the helper call:

```go
	return newControlPlaneHandler(service, signer, cfg, nil, nil, nil), signer
```

2. Add:

```go
func TestControlPlaneMountsOpsOnlyWhenProvided(t *testing.T) {
	handler, _ := newTestHandlerWithMode(t, false)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/ops/health", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("GET /ops/health without ops handler = %d, want %d", recorder.Code, http.StatusNotFound)
	}

	cfg := config.Load()
	cfg.DevMode = false
	privateKey, err := token.DecodeEd25519PrivateKey(devTokenSigningSeed)
	if err != nil {
		t.Fatalf("DecodeEd25519PrivateKey() error = %v", err)
	}
	signer, err := token.NewSignerWithKey(cfg.TokenKeyID(), privateKey)
	if err != nil {
		t.Fatalf("NewSignerWithKey() error = %v", err)
	}
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	mounted := newControlPlaneHandler(&grant.Service{}, signer, cfg, nil, nil, stub)
	recorder = httptest.NewRecorder()
	mounted.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/ops/health", nil))
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("GET /ops/health with ops handler = %d, want %d", recorder.Code, http.StatusTeapot)
	}
}
```

If `grant.NewService` cannot be constructed from zero values, reuse the `service` built in
`newTestHandlerWithMode` by extracting that construction into a small helper — do **not**
duplicate the Cedar setup.

3. Keep `TestProductionHandlerDoesNotExposeInMemoryAdminRoutes` unchanged: it asserts
   `/ops/auth/login` is 404 in production mode without ops wiring.

## Verification

```sh
go test ./cmd/controlplane/ -v
go build ./... && go vet ./... && go test ./...
```

Startup smoke test without AWS (must fail loudly, not silently skip):

```sh
OPS_SSO_ENABLED=true \
COGNITO_SECRET_ARN='arn:aws:secretsmanager:ap-southeast-2:459321894716:secret:production/lanyard/cognito' \
OPS_PUBLIC_BASE_URL='https://ops.linkedqueue.cloud' \
DATABASE_URL='postgres://...' AWS_REGION='ap-southeast-2' \
ALLOW_INSECURE_DEMO=false \
  go run ./cmd/controlplane
```

Expect either a credential/secret error logged and exit code 1, or a listening server. It
must never start with `/ops/*` silently absent while `OPS_SSO_ENABLED=true`.
