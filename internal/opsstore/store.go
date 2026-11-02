// Package opsstore is a thin adapter over the SECURITY DEFINER functions in
// migrations/005_console_ops.sql and 006_ops_sso.sql. Tokens are hashed by the
// caller; this package never re‑implements throttling or expiry logic that lives
// in SQL, and never reads ops_sessions or ops_login_codes directly.
package opsstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// provisionRole is the least‑privileged role given to a member created by SSO.
// Promotion is a manual database change and is never done from a token.
const provisionRole = "ops_support"

// Member is the ops_members row the ops console needs.
type Member struct {
	ID         string
	Email      string
	Role       string
	Status     string // "active" | "suspended"
	CognitoSub string
}

// Session is the subset of ops_sessions/ops_members returned by ops_get_session.
type Session struct {
	MemberID    string
	Email       string
	Role        string
	HardwareKey bool
}

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
	// ErrIdentityConflict means the email already belongs to a different Cognito subject.
	ErrIdentityConflict = errors.New("ops member is bound to a different identity")
	// ErrActionNotFound means no ops_actions row has that id.
	ErrActionNotFound = errors.New("ops action not found")
	// ErrActionDecided means the action is no longer pending.
	ErrActionDecided = errors.New("ops action already decided")
	// ErrSelfDecide means the requester tried to decide their own action.
	ErrSelfDecide = errors.New("ops action cannot be decided by its requester")
)

// Store adapts a pgx pool to the ops SQL functions.
type Store struct {
	pool *pgxpool.Pool
}

// New constructs a Store backed by the supplied pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ProvisionMember resolves the member for a verified Cognito identity, creating
// it as an active ops_support member on first sign‑in. Existing members keep
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

// GetSession resolves a live session, refreshing its last‑seen timestamp. It
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

// EndSession deletes a session. Unknown tokens are a no‑op.
func (s *Store) EndSession(ctx context.Context, tokenHash []byte) error {
	if _, err := s.pool.Exec(ctx, `SELECT ops_end_session($1)`, tokenHash); err != nil {
		return fmt.Errorf("end ops session: %w", err)
	}
	return nil
}

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
