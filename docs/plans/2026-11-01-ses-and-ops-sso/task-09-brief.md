# Task 09 — `internal/opsstore`: ops member and session adapter

**Where this fits:** the only place the ops HTTP layer touches the database. It wraps the
`ops_*` SECURITY DEFINER functions from migrations 005/006, so handlers never write SQL.

**Depends on:** 06 (`cognito_sub`, 4-argument `ops_create_session`, `hardware_key` in
`ops_get_session`).
**Blocks:** 12, 13.

## Files

- `internal/opsstore/store.go` (create)
- `internal/opsstore/store_test.go` (create)

## Contracts (pinned — tasks 12 and 13 call these exact names)

```go
package opsstore

type Member struct {
	ID         string
	Email      string
	Role       string
	Status     string // "active" | "suspended"
	CognitoSub string
}

type Session struct {
	MemberID    string
	Email       string
	Role        string
	HardwareKey bool
}

// ErrIdentityConflict means the email already belongs to a different Cognito subject.
var ErrIdentityConflict = errors.New("ops member is bound to a different identity")

func New(pool *pgxpool.Pool) *Store
func (s *Store) ProvisionMember(ctx context.Context, email, cognitoSub string) (Member, error)
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, memberID string, expires time.Time, hardwareKey bool) error
func (s *Store) GetSession(ctx context.Context, tokenHash []byte, idle time.Duration) (Session, bool, error)
func (s *Store) EndSession(ctx context.Context, tokenHash []byte) error
```

Rules:

- `ProvisionMember` creates a missing member with role `ops_support`, status `active`; it
  **only** ever sets `cognito_sub` on an existing row, never `role` or `status`.
- A member bound to a different `cognito_sub` → `ErrIdentityConflict`.
- Suspended members are returned as-is (the caller denies); they are never reactivated.
- `GetSession` returns `(Session{}, false, nil)` for unknown/expired/idle/revoked — mirror
  `authstore.GetSession`.

## `internal/opsstore/store.go`

```go
// Package opsstore is a thin adapter over the SECURITY DEFINER functions in
// migrations/005_console_ops.sql and 006_ops_sso.sql. Tokens are hashed by the
// caller; this package never reimplements throttling or expiry logic that lives
// in SQL, and never reads ops_sessions or ops_login_codes directly.
package opsstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// provisionRole is the least-privileged role given to a member created by SSO.
// Promotion is a manual database change and is never done from a token.
const provisionRole = "ops_support"

// Member is the ops_members row the ops console needs.
type Member struct {
	ID         string
	Email      string
	Role       string
	Status     string
	CognitoSub string
}

// Session is the subset of ops_sessions/ops_members returned by ops_get_session.
type Session struct {
	MemberID    string
	Email       string
	Role        string
	HardwareKey bool
}

// ErrIdentityConflict means the email already belongs to a different Cognito subject.
var ErrIdentityConflict = errors.New("ops member is bound to a different identity")

// Store adapts a pgx pool to the ops SQL functions.
type Store struct {
	pool *pgxpool.Pool
}

// New constructs a Store backed by the supplied pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ProvisionMember resolves the member for a verified Cognito identity, creating
// it as an active ops_support member on first sign-in. Existing members keep
// their role and status; only a missing cognito_sub is filled in.
func (s *Store) ProvisionMember(ctx context.Context, email, cognitoSub string) (Member, error) {
	email = strings.TrimSpace(email)
	cognitoSub = strings.TrimSpace(cognitoSub)
	if email == "" || cognitoSub == "" {
		return Member{}, errors.New("email and cognito subject are required")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Member{}, fmt.Errorf("begin ops member transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO ops_members (email, role, status, cognito_sub)
		 VALUES ($1, $2, 'active', $3)
		 ON CONFLICT (email) DO UPDATE
		    SET cognito_sub = COALESCE(ops_members.cognito_sub, EXCLUDED.cognito_sub)
		  WHERE ops_members.cognito_sub IS NULL
		     OR ops_members.cognito_sub = EXCLUDED.cognito_sub`,
		email, provisionRole, cognitoSub,
	); err != nil {
		return Member{}, fmt.Errorf("provision ops member: %w", err)
	}

	var member Member
	var sub *string
	if err := tx.QueryRow(ctx,
		`SELECT id, email, role, status, cognito_sub FROM ops_members WHERE email = $1`,
		email,
	).Scan(&member.ID, &member.Email, &member.Role, &member.Status, &sub); err != nil {
		return Member{}, fmt.Errorf("read ops member: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Member{}, fmt.Errorf("commit ops member transaction: %w", err)
	}

	if sub != nil {
		member.CognitoSub = *sub
	}
	if member.CognitoSub != cognitoSub {
		return Member{}, ErrIdentityConflict
	}
	return member, nil
}

// CreateSession stores sha256(token) for an active member.
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, memberID string, expires time.Time, hardwareKey bool) error {
	if _, err := s.pool.Exec(ctx,
		`SELECT ops_create_session($1, $2::uuid, $3, $4)`,
		tokenHash, memberID, expires, hardwareKey,
	); err != nil {
		return fmt.Errorf("create ops session: %w", err)
	}
	return nil
}

// GetSession resolves a live session, refreshing its last-seen timestamp. It
// reports false when the token is unknown, expired, idle, or the member is no
// longer active.
func (s *Store) GetSession(ctx context.Context, tokenHash []byte, idle time.Duration) (Session, bool, error) {
	var session Session
	err := s.pool.QueryRow(ctx,
		`SELECT member_id, email, role, hardware_key FROM ops_get_session($1, make_interval(secs => $2))`,
		tokenHash, idle.Seconds(),
	).Scan(&session.MemberID, &session.Email, &session.Role, &session.HardwareKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, fmt.Errorf("get ops session: %w", err)
	}
	return session, true, nil
}

// EndSession deletes a session. Unknown tokens are a no-op.
func (s *Store) EndSession(ctx context.Context, tokenHash []byte) error {
	if _, err := s.pool.Exec(ctx, `SELECT ops_end_session($1)`, tokenHash); err != nil {
		return fmt.Errorf("end ops session: %w", err)
	}
	return nil
}
```

## `internal/opsstore/store_test.go`

1. `TestNewReturnsStore` — `New(nil) != nil`.
2. `TestProvisionMemberRejectsEmptyInput` — empty email, empty subject, whitespace-only:
   error, and no pool is touched (`New(nil)` must not panic).
3. `TestProvisionRoleIsLeastPrivileged` — `provisionRole == "ops_support"`.
4. `TestOpsStoreIntegration` — gated exactly like `authstore`:

```go
func connectOpsIntegration(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL must be set in CI")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect to TEST_DATABASE_URL: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
```

   Steps (use a `time.Now().UnixNano()` suffix in the email; leave rows behind like
   `authstore` does — `lanyard_app` has no DELETE on `ops_members`):

   - `ProvisionMember(ctx, email, "sub-"+suffix)` → `Role == "ops_support"`,
     `Status == "active"`, `CognitoSub` matches, `ID` non-empty.
   - call it again with the same sub → same `ID` (idempotent).
   - call it with `"other-sub"` → `errors.Is(err, ErrIdentityConflict)`.
   - suspend the member through the admin pool, then `ProvisionMember` with the same sub →
     `Status == "suspended"` and `Role` unchanged (never reactivated).
     Admin connection:

```go
func connectOpsAdmin(t *testing.T) *pgxpool.Pool {
	t.Helper()
	adminURL := os.Getenv("TEST_ADMIN_DATABASE_URL")
	if adminURL == "" {
		t.Skip("TEST_ADMIN_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), adminURL)
	if err != nil {
		t.Fatalf("connect to TEST_ADMIN_DATABASE_URL: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
```

   - `CreateSession` with `hardwareKey: true` → `GetSession` returns
     `HardwareKey == true`, `Email`, `Role`, `MemberID`.
   - `CreateSession` for the **suspended** member → `GetSession` reports `false`
     (the SQL function only inserts for active members).
   - `EndSession` → `GetSession` reports `false`.
   - `GetSession` with a random 32-byte hash → `false, nil`.

Use `sha256.Sum256([]byte(fmt.Sprintf("ops-token-%d", suffix)))` for token hashes.

## Verification

```sh
go test ./internal/opsstore/ -v                       # unit tests pass, integration skipped
go build ./... && go vet ./internal/opsstore/
# with a migrated database:
TEST_DATABASE_URL='postgres://lanyard_app:...@localhost:5432/lanyard' \
TEST_ADMIN_DATABASE_URL='postgres://postgres:...@localhost:5432/lanyard' \
  go test ./internal/opsstore/ -run Integration -v
```
