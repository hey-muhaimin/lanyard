# Task 13 — Real ops session middleware and `/ops` API

**Where this fits:** replaces the prototype `cmd/controlplane/ops_handler.go` (which accepts
any non-empty token and queries columns that do not exist) with a session-validated API
backed by `opsstore`.

**Depends on:** 09 (`opsstore`), 10 (`ops_list_tenants()`), 11 (`opsPrincipal`,
`opsSessionKey`, `opsSessionCookie`).
**Blocks:** 14.

## Files

- `cmd/controlplane/ops_handler.go` (**rewrite the whole file** — delete the old contents)
- `cmd/controlplane/ops_handler_test.go` (create)
- `internal/opsstore/store.go` (append tenant + action methods and types)

## Contracts pinned here (task 14 mounts these)

```go
func requireOpsSession(store opsStore, idle time.Duration, logger *slog.Logger) func(http.Handler) http.Handler
func newOpsAPI(store opsAPIStore, logger *slog.Logger) http.Handler
```

`newOpsAPI` mounts exactly: `GET /ops/health`, `GET /ops/tenants`, `GET /ops/actions`,
`POST /ops/actions`, `POST /ops/actions/{id}/decide`. It does **not** mount
`/ops/auth/*` — task 14 does that.

Write actions require both a non-read-only role and `principal.HardwareKey`; otherwise
`403` — `{"error":"insufficient role"}` for `ops_support`, `{"error":"hardware key required"}`
when no hardware key was used. (`web/ops/README.md`: `ops_support` is read-only, and write
actions require a hardware-key sign-in.)

## `internal/opsstore/store.go` — append

Add `"github.com/jackc/pgx/v5/pgconn"` to the imports and append:

```go
// Tenant is one row of the platform-wide ops listing (migration 007).
type Tenant struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Plan   string `json:"plan"`
	Agents int64  `json:"agents"`
	Grants int64  `json:"grants"`
	State  string `json:"state"`
}

// Action is one row of the two-person ops write queue.
type Action struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	TenantID    string    `json:"tenant_id"`
	Reason      string    `json:"reason"`
	RequestedBy string    `json:"requested_by"`
	Status      string    `json:"status"`
	DecidedBy   string    `json:"decided_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

var (
	// ErrActionNotFound means no ops_actions row has that id.
	ErrActionNotFound = errors.New("ops action not found")
	// ErrActionDecided means the action is no longer pending.
	ErrActionDecided = errors.New("ops action already decided")
	// ErrSelfDecide means the requester tried to decide their own action.
	ErrSelfDecide = errors.New("ops action cannot be decided by its requester")
)

// ListTenants returns every tenant through ops_list_tenants(), which bypasses
// the tenant_self RLS policy for ops staff only.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, plan, agents, grants, state FROM ops_list_tenants()`)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	tenants := make([]Tenant, 0, 16)
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Plan, &t.Agents, &t.Grants, &t.State); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	return tenants, nil
}

// ListActions returns the most recent actions, optionally scoped to one tenant.
// ops_actions.tenant_id is TEXT in 005 (a lookup key, not an FK), so compare as text.
func (s *Store) ListActions(ctx context.Context, tenantID string) ([]Action, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, type, tenant_id, reason, requested_by, status,
		        COALESCE(decided_by, ''), created_at, expires_at
		   FROM ops_actions
		  WHERE $1 = '' OR tenant_id = $1
		  ORDER BY created_at DESC
		  LIMIT 200`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list ops actions: %w", err)
	}
	defer rows.Close()

	actions := make([]Action, 0, 16)
	for rows.Next() {
		var a Action
		if err := rows.Scan(&a.ID, &a.Type, &a.TenantID, &a.Reason, &a.RequestedBy,
			&a.Status, &a.DecidedBy, &a.CreatedAt, &a.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan ops action: %w", err)
		}
		actions = append(actions, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list ops actions: %w", err)
	}
	return actions, nil
}

// CreateAction enqueues a pending action that expires in 30 days.
func (s *Store) CreateAction(ctx context.Context, typ, tenantID, reason, requestedBy string) (Action, error) {
	var a Action
	err := s.pool.QueryRow(ctx,
		`INSERT INTO ops_actions (type, tenant_id, reason, requested_by, status, expires_at)
		 VALUES ($1, $2, $3, $4, 'pending', now() + interval '30 days')
		 RETURNING id, type, tenant_id, reason, requested_by, status,
		           COALESCE(decided_by, ''), created_at, expires_at`,
		typ, tenantID, reason, requestedBy,
	).Scan(&a.ID, &a.Type, &a.TenantID, &a.Reason, &a.RequestedBy,
		&a.Status, &a.DecidedBy, &a.CreatedAt, &a.ExpiresAt)
	if err != nil {
		return Action{}, fmt.Errorf("create ops action: %w", err)
	}
	return a, nil
}

// DecideAction records a decision. "approved" maps to the stored status
// "executed" because ops_actions.status only allows pending/executed/denied/expired.
func (s *Store) DecideAction(ctx context.Context, id, decision, decidedBy string) (Action, error) {
	status := "denied"
	if decision == "approved" {
		status = "executed"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Action{}, fmt.Errorf("begin ops decision transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var requester, current string
	err = tx.QueryRow(ctx,
		`SELECT requested_by, status FROM ops_actions WHERE id = $1::uuid FOR UPDATE`, id,
	).Scan(&requester, &current)
	if errors.Is(err, pgx.ErrNoRows) || isInvalidUUID(err) {
		return Action{}, ErrActionNotFound
	}
	if err != nil {
		return Action{}, fmt.Errorf("lock ops action: %w", err)
	}
	if current != "pending" {
		return Action{}, ErrActionDecided
	}
	if requester == decidedBy {
		return Action{}, ErrSelfDecide
	}

	var a Action
	err = tx.QueryRow(ctx,
		`UPDATE ops_actions
		    SET status = $1, decided_by = $2, decided_at = now()
		  WHERE id = $3::uuid
		 RETURNING id, type, tenant_id, reason, requested_by, status,
		           COALESCE(decided_by, ''), created_at, expires_at`,
		status, decidedBy, id,
	).Scan(&a.ID, &a.Type, &a.TenantID, &a.Reason, &a.RequestedBy,
		&a.Status, &a.DecidedBy, &a.CreatedAt, &a.ExpiresAt)
	if err != nil {
		return Action{}, fmt.Errorf("decide ops action: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Action{}, fmt.Errorf("commit ops decision: %w", err)
	}
	return a, nil
}

// isInvalidUUID reports whether err is Postgres rejecting a malformed uuid.
func isInvalidUUID(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "22P02"
}
```

## `cmd/controlplane/ops_handler.go` — full replacement

```go
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/example/lanyard/internal/opsstore"
)

// opsAPIStore is the database surface of the ops API; tests substitute a fake.
type opsAPIStore interface {
	ListTenants(ctx context.Context) ([]opsstore.Tenant, error)
	ListActions(ctx context.Context, tenantID string) ([]opsstore.Action, error)
	CreateAction(ctx context.Context, typ, tenantID, reason, requestedBy string) (opsstore.Action, error)
	DecideAction(ctx context.Context, id, decision, decidedBy string) (opsstore.Action, error)
}

// requireOpsSession validates the lanyard_ops_session cookie and attaches the
// staff principal to the request context. Every failure is fail-closed.
func requireOpsSession(store opsStore, idle time.Duration, logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(opsSessionCookie)
			if err != nil || strings.TrimSpace(cookie.Value) == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
				return
			}
			session, ok, err := store.GetSession(r.Context(), hashValue(cookie.Value), idle)
			if err != nil {
				logger.Error("load ops session", "error", err)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
				return
			}
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
				return
			}
			principal := opsPrincipal{
				MemberID:    session.MemberID,
				Email:       session.Email,
				Role:        session.Role,
				HardwareKey: session.HardwareKey,
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), opsSessionKey{}, principal)))
		})
	}
}

type opsAPI struct {
	store  opsAPIStore
	logger *slog.Logger
	mux    *http.ServeMux
}

// newOpsAPI builds the session-protected ops API. /ops/auth/* is mounted by the
// composition in ops_wire.go.
func newOpsAPI(store opsAPIStore, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	api := &opsAPI{store: store, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ops/health", api.health)
	mux.HandleFunc("GET /ops/tenants", api.tenants)
	mux.HandleFunc("GET /ops/actions", api.listActions)
	mux.HandleFunc("POST /ops/actions", api.createAction)
	mux.HandleFunc("POST /ops/actions/{id}/decide", api.decideAction)
	api.mux = mux
	return api
}

func (a *opsAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

// opsCanWrite reports whether the role may queue or decide actions. ops_support
// is read-only; ops_admin and ops_oncall may write (subject to the hardware-key
// check that follows).
func opsCanWrite(principal opsPrincipal) bool {
	return principal.Role != "ops_support"
}

// health still returns the prototype's static numbers; wiring real metrics is
// out of scope for this change.
func (a *opsAPI) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"proxy_p99_ms":     12,
		"revocation_lag_s": 0.5,
		"event_backlog":    3,
		"uptime_30d_pct":   99.9,
		"updated_at":       time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *opsAPI) tenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := a.store.ListTenants(r.Context())
	if err != nil {
		a.logger.Error("list tenants", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, tenants)
}

func (a *opsAPI) listActions(w http.ResponseWriter, r *http.Request) {
	actions, err := a.store.ListActions(r.Context(), strings.TrimSpace(r.URL.Query().Get("tenant_id")))
	if err != nil {
		a.logger.Error("list ops actions", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, actions)
}

func (a *opsAPI) createAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := opsPrincipalFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if !opsCanWrite(principal) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "insufficient role"})
		return
	}
	if !principal.HardwareKey {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "hardware key required"})
		return
	}
	var body struct {
		Type     string `json:"type"`
		TenantID string `json:"tenant_id"`
		Reason   string `json:"reason"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	body.Type = strings.TrimSpace(body.Type)
	body.TenantID = strings.TrimSpace(body.TenantID)
	body.Reason = strings.TrimSpace(body.Reason)
	switch body.Type {
	case "suspend_tenant", "rotate_signing_key", "view_as_customer":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid action type"})
		return
	}
	if body.TenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tenant_id is required"})
		return
	}
	if len([]rune(body.Reason)) < 20 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "reason must be at least 20 characters"})
		return
	}

	action, err := a.store.CreateAction(r.Context(), body.Type, body.TenantID, body.Reason, principal.Email)
	if err != nil {
		a.logger.Error("create ops action", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusCreated, action)
}

func (a *opsAPI) decideAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := opsPrincipalFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if !opsCanWrite(principal) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "insufficient role"})
		return
	}
	if !principal.HardwareKey {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "hardware key required"})
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid action id"})
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Status != "approved" && body.Status != "denied" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "status must be approved or denied"})
		return
	}

	action, err := a.store.DecideAction(r.Context(), id, body.Status, principal.Email)
	switch {
	case errors.Is(err, opsstore.ErrActionNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "action not found"})
		return
	case errors.Is(err, opsstore.ErrActionDecided):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "action already decided"})
		return
	case errors.Is(err, opsstore.ErrSelfDecide):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "requester cannot decide own action"})
		return
	case err != nil:
		a.logger.Error("decide ops action", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, action)
}
```

Removed with the old file: `opsSessionMiddleware`, `getOpsSession`, `newOpsHandler`, the
`authstore`/`database/sql`/`pgxpool` imports, the placeholder login route, and the
`err.Error()` echoes to clients.

## `cmd/controlplane/ops_handler_test.go`

Reuse `fakeOpsStore` from `ops_auth_test.go` for the middleware tests and add:

```go
type fakeOpsAPIStore struct {
	tenants   []opsstore.Tenant
	actions   []opsstore.Action
	tenantArg string
	created   *opsstore.Action
	decision  [2]string // decision, decidedBy
	err       error
}

func (f *fakeOpsAPIStore) ListTenants(ctx context.Context) ([]opsstore.Tenant, error) {
	return f.tenants, f.err
}

func (f *fakeOpsAPIStore) ListActions(ctx context.Context, tenantID string) ([]opsstore.Action, error) {
	f.tenantArg = tenantID
	return f.actions, f.err
}

func (f *fakeOpsAPIStore) CreateAction(ctx context.Context, typ, tenantID, reason, requestedBy string) (opsstore.Action, error) {
	if f.err != nil {
		return opsstore.Action{}, f.err
	}
	action := opsstore.Action{ID: "action-1", Type: typ, TenantID: tenantID, Reason: reason,
		RequestedBy: requestedBy, Status: "pending"}
	f.created = &action
	return action, nil
}

func (f *fakeOpsAPIStore) DecideAction(ctx context.Context, id, decision, decidedBy string) (opsstore.Action, error) {
	if f.err != nil {
		return opsstore.Action{}, f.err
	}
	f.decision = [2]string{decision, decidedBy}
	return opsstore.Action{ID: id, Status: "executed"}, nil
}

func withPrincipal(r *http.Request, p opsPrincipal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), opsSessionKey{}, p))
}

func staffPrincipal() opsPrincipal {
	return opsPrincipal{MemberID: "member-1", Email: "staff@linkedqueue.cloud", Role: "ops_oncall", HardwareKey: true}
}
```

Tests:

1. `TestRequireOpsSessionRejectsMissingCookie` → `401` `{"error":"authentication required"}`,
   next handler never called.
2. `TestRequireOpsSessionRejectsUnknownToken` — cookie set, empty `fakeOpsStore.sessions`
   → `401`, next not called.
3. `TestRequireOpsSessionAttachesPrincipal` — seed
   `store.sessions[string(hashValue("token-1"))]`; the next handler asserts
   `opsPrincipalFrom` returns the seeded values and writes 204.
4. `TestRequireOpsSessionStoreError` — declare a local
   `type errOpsStore struct{ fakeOpsStore }` with
   `func (e errOpsStore) GetSession(...) (opsstore.Session, bool, error) { return opsstore.Session{}, false, errors.New("boom") }`;
   → `500` `{"error":"internal error"}` and the body does not contain `boom`.
5. `TestOpsHealth` → 200 with keys `proxy_p99_ms`, `revocation_lag_s`, `event_backlog`,
   `uptime_30d_pct`, `updated_at`.
6. `TestOpsTenants` — two tenants → 200 JSON array; assert keys `id,name,plan,agents,grants,state`.
7. `TestOpsTenantsStoreError` → 500 `{"error":"internal error"}`, body must not contain `"boom"`.
8. `TestOpsListActionsFiltersByTenant` — `GET /ops/actions?tenant_id=tenant-1` →
   `fake.tenantArg == "tenant-1"`, 200.
9. `TestOpsCreateActionRequiresHardwareKey` — principal `{Role:"ops_oncall", HardwareKey:false}`
   → `403` `{"error":"hardware key required"}`, `fake.created == nil`.
9b. `TestOpsCreateActionRejectsReadOnlyRole` — principal `{Role:"ops_support", HardwareKey:true}`
   → `403` `{"error":"insufficient role"}`, `fake.created == nil`.
10. `TestOpsCreateActionValidation` — table of bodies → 400: invalid `type`, empty
    `tenant_id`, 19-character reason, malformed JSON.
11. `TestOpsCreateAction` — valid body → 201; `fake.created.RequestedBy ==
    "staff@linkedqueue.cloud"`.
12. `TestOpsDecideAction` — `POST /ops/actions/action-1/decide` `{"status":"approved"}` →
    200; `fake.decision == [2]string{"approved","staff@linkedqueue.cloud"}`.
13. `TestOpsDecideActionErrors` — table: `opsstore.ErrActionNotFound`→404,
    `opsstore.ErrActionDecided`→409, `opsstore.ErrSelfDecide`→400.
13b. `TestOpsDecideActionRejectsReadOnlyRole` — principal `{Role:"ops_support",
    HardwareKey:true}` → `403` `{"error":"insufficient role"}`.
14. `TestOpsDecideActionRejectsBadStatus` — `{"status":"maybe"}` → 400.
15. `TestOpsActionsMethodNotAllowed` — `PUT /ops/actions` → 405.

## Verification

```sh
go test ./cmd/controlplane/ -run 'Ops|RequireOpsSession' -v
go test ./internal/opsstore/ -v
go build ./... && go vet ./...
```

`go test ./...` must still pass: `main_test.go` expects `/ops/auth/login` to be `404` when
ops SSO is disabled, which stays true until task 14 mounts it conditionally.
