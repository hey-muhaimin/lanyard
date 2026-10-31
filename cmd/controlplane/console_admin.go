package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example/lanyard/internal/auth"
	"github.com/example/lanyard/internal/authstore"
	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/db"
	"github.com/example/lanyard/internal/events"
)

// sessionLookup is the narrow authstore surface the console admin middleware
// needs. Tests substitute a fake.
type sessionLookup interface {
	GetSession(ctx context.Context, tokenHash []byte, idle time.Duration) (authstore.Session, bool, error)
}

// consolePrincipal is the authenticated caller derived only from the session;
// request headers such as X-Tenant-ID are deliberately ignored.
type consolePrincipal struct {
	TenantID string
	MemberID string
	Email    string
	Role     string
}

type consolePrincipalKey struct{}

func principalFromContext(ctx context.Context) (consolePrincipal, bool) {
	principal, ok := ctx.Value(consolePrincipalKey{}).(consolePrincipal)
	return principal, ok
}

// Store errors mapped to HTTP responses by the handlers.
var (
	errDuplicateAgent     = errors.New("duplicate agent")
	errTenantNotFound     = errors.New("tenant not found")
	errApprovalNotFound   = errors.New("approval not found")
	errApprovalNotPending = errors.New("approval is not pending")
	errApprovalExpired    = errors.New("approval has expired")
	errSelfApproval       = errors.New("requesters cannot approve their own request")
)

type agentRecord struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	OwnerSubject string `json:"owner_subject"`
	PublicKey    string `json:"public_key"`
	Status       string `json:"status"`
}

type createAgentInput struct {
	ID           string
	OwnerSubject string
	PublicKey    string
}

type tenantRecord struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	ContactEmail *string   `json:"contact_email"`
	Status       string    `json:"status"`
	Plan         string    `json:"plan"`
	CreatedAt    time.Time `json:"created_at"`
}

type approvalRecord struct {
	ID          string          `json:"id"`
	TaskID      string          `json:"task_id"`
	ChainID     string          `json:"chain_id"`
	RequesterID string          `json:"requester_id"`
	RequestedBy *string         `json:"requested_by"`
	Action      string          `json:"action"`
	Parameters  json.RawMessage `json:"parameters"`
	Status      string          `json:"status"`
	ExpiresAt   time.Time       `json:"expires_at"`
	DecidedBy   *string         `json:"decided_by"`
}

type eventRecord struct {
	Seq      int64           `json:"seq"`
	Type     string          `json:"type"`
	TS       time.Time       `json:"ts"`
	Payload  json.RawMessage `json:"payload"`
	Hash     string          `json:"hash"`
	PrevHash string          `json:"prev_hash"`
}

// consoleStore is the narrow persistence surface the console API needs. All
// implementations must scope every query to tenantID.
type consoleStore interface {
	ListAgents(ctx context.Context, tenantID string) ([]agentRecord, error)
	CreateAgent(ctx context.Context, tenantID, actor string, input createAgentInput) (agentRecord, error)
	GetTenant(ctx context.Context, tenantID string) (tenantRecord, error)
	UpdateTenant(ctx context.Context, tenantID, actor string, name, contactEmail *string) (tenantRecord, error)
	ListApprovals(ctx context.Context, tenantID string) ([]approvalRecord, error)
	GetApproval(ctx context.Context, tenantID, id string) (approvalRecord, error)
	DecideApproval(ctx context.Context, tenantID, id, status, decidedBy, sessionEmail string, parameters []byte) (approvalRecord, error)
	Revoke(ctx context.Context, tenantID, actor, scopeType, scopeID string) error
	ListEvents(ctx context.Context, tenantID string) ([]eventRecord, error)
}

type consoleAdminHandler struct {
	sessions sessionLookup
	store    consoleStore
	cfg      config.Config
	logger   *slog.Logger
	mux      *http.ServeMux
}

// newConsoleAdminHandler builds the session-authenticated console admin API.
// The returned handler is mounted for /admin/, /approve, /revoke and /events/.
func newConsoleAdminHandler(sessions sessionLookup, store consoleStore, cfg config.Config, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &consoleAdminHandler{sessions: sessions, store: store, cfg: cfg, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/tenant", h.authenticate(h.handleGetTenant))
	mux.HandleFunc("PATCH /admin/tenant", h.authenticate(h.require(auth.PermissionMembersManage, h.handleUpdateTenant)))
	mux.HandleFunc("GET /admin/agents", h.authenticate(h.require(auth.PermissionAgentsRead, h.handleListAgents)))
	mux.HandleFunc("POST /admin/agents", h.authenticate(h.require(auth.PermissionAgentsWrite, h.handleCreateAgent)))
	mux.HandleFunc("GET /approve", h.authenticate(h.require(auth.PermissionApprovalsRead, h.handleListApprovals)))
	mux.HandleFunc("POST /approve", h.authenticate(h.require(auth.PermissionApprovalsDecide, h.handleDecideApproval)))
	mux.HandleFunc("POST /revoke", h.authenticate(h.require(auth.PermissionRevoke, h.handleRevoke)))
	mux.HandleFunc("GET /events/replay", h.authenticate(h.require(auth.PermissionEventsRead, h.handleReplayEvents)))
	h.mux = mux
	return h
}

func (h *consoleAdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	h.mux.ServeHTTP(w, r)
}

// authenticate resolves the session cookie and attaches the principal. Any
// lookup failure is a 401: unauthorized callers learn nothing else.
func (h *consoleAdminHandler) authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not signed in"})
			return
		}
		session, ok, err := h.sessions.GetSession(r.Context(), hashValue(cookie.Value), h.cfg.SessionIdle)
		if err != nil {
			h.logger.Error("load console session", "error", err)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not signed in"})
			return
		}
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not signed in"})
			return
		}
		principal := consolePrincipal{
			TenantID: session.TenantID,
			MemberID: session.MemberID,
			Email:    session.Email,
			Role:     session.Role,
		}
		next(w, r.WithContext(context.WithValue(r.Context(), consolePrincipalKey{}, principal)))
	}
}

func (h *consoleAdminHandler) require(permission auth.Permission, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not signed in"})
			return
		}
		if !auth.Can(principal.Role, string(permission)) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
			return
		}
		next(w, r)
	}
}

var agentIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

func validAgentID(id string) bool {
	return len(id) >= 1 && len(id) <= 64 && agentIDPattern.MatchString(id)
}

func validOwnerSubject(owner string) bool {
	return len(owner) >= 1 && len(owner) <= 254
}

// decodeAgentPublicKey accepts base64url, padded base64url, raw standard and
// padded standard base64 and requires exactly one Ed25519 public key.
func decodeAgentPublicKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("public key is required")
	}
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.StdEncoding,
		base64.RawStdEncoding,
	} {
		decoded, err := encoding.DecodeString(encoded)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, errors.New("public key must decode to 32 bytes")
}

func standardBase64ToURL(encoded string) string {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (h *consoleAdminHandler) handleListAgents(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFromContext(r.Context())
	agents, err := h.store.ListAgents(r.Context(), principal.TenantID)
	if err != nil {
		h.logger.Error("list agents", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

func (h *consoleAdminHandler) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFromContext(r.Context())
	var req struct {
		ID           string `json:"id"`
		OwnerSubject string `json:"owner_subject"`
		PublicKey    string `json:"public_key"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validAgentID(req.ID) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id must be 1-64 characters matching [a-z0-9][a-z0-9._-]*"})
		return
	}
	if !validOwnerSubject(req.OwnerSubject) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "owner_subject must be 1-254 characters"})
		return
	}
	if _, err := decodeAgentPublicKey(req.PublicKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "public_key must decode to 32 bytes"})
		return
	}

	agent, err := h.store.CreateAgent(r.Context(), principal.TenantID, principal.Email, createAgentInput{
		ID:           req.ID,
		OwnerSubject: req.OwnerSubject,
		PublicKey:    req.PublicKey,
	})
	switch {
	case errors.Is(err, errDuplicateAgent):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "an agent with that name already exists"})
	case err != nil:
		h.logger.Error("create agent", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
	default:
		writeJSON(w, http.StatusCreated, agent)
	}
}

func (h *consoleAdminHandler) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFromContext(r.Context())
	tenant, err := h.store.GetTenant(r.Context(), principal.TenantID)
	switch {
	case errors.Is(err, errTenantNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "tenant not found"})
	case err != nil:
		h.logger.Error("get tenant", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
	default:
		writeJSON(w, http.StatusOK, tenant)
	}
}

func (h *consoleAdminHandler) handleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFromContext(r.Context())
	var req struct {
		Name         *string `json:"name"`
		ContactEmail *string `json:"contact_email"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Name != nil {
		if n := utf8.RuneCountInString(*req.Name); n < 1 || n > 100 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name must be 1-100 characters"})
			return
		}
	}
	if req.ContactEmail != nil {
		email := *req.ContactEmail
		if len(email) > 254 || (email != "" && !strings.Contains(email, "@")) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "contact_email must be empty or a valid address"})
			return
		}
	}

	tenant, err := h.store.UpdateTenant(r.Context(), principal.TenantID, principal.Email, req.Name, req.ContactEmail)
	switch {
	case errors.Is(err, errTenantNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "tenant not found"})
	case err != nil:
		h.logger.Error("update tenant", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
	default:
		writeJSON(w, http.StatusOK, tenant)
	}
}

func (h *consoleAdminHandler) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFromContext(r.Context())
	approvals, err := h.store.ListApprovals(r.Context(), principal.TenantID)
	if err != nil {
		h.logger.Error("list approvals", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, approvals)
}

func (h *consoleAdminHandler) handleDecideApproval(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFromContext(r.Context())
	var req struct {
		ID         string          `json:"id"`
		Status     string          `json:"status"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id is required"})
		return
	}
	if req.Status != "approved" && req.Status != "denied" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "status must be approved or denied"})
		return
	}

	approval, err := h.store.GetApproval(r.Context(), principal.TenantID, req.ID)
	if errors.Is(err, errApprovalNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "approval not found"})
		return
	}
	if err != nil {
		h.logger.Error("load approval", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}

	// Reject before calling the store so a self-approval can never mutate the
	// request; the store repeats the check under SELECT ... FOR UPDATE.
	if err := validateApprovalDecision(approval, principal.Email, time.Now()); err != nil {
		writeApprovalDecisionError(w, err)
		return
	}

	decided, err := h.store.DecideApproval(r.Context(), principal.TenantID, req.ID, req.Status, principal.Email, principal.Email, req.Parameters)
	if err != nil {
		if errors.Is(err, errSelfApproval) || errors.Is(err, errApprovalNotPending) || errors.Is(err, errApprovalExpired) {
			writeApprovalDecisionError(w, err)
			return
		}
		if errors.Is(err, errApprovalNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "approval not found"})
			return
		}
		h.logger.Error("decide approval", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, decided)
}

func validateApprovalDecision(approval approvalRecord, sessionEmail string, now time.Time) error {
	if approval.Status != "pending" {
		return errApprovalNotPending
	}
	if !approval.ExpiresAt.After(now) {
		return errApprovalExpired
	}
	if requesterIsSessionUser(approval, sessionEmail) {
		return errSelfApproval
	}
	return nil
}

func requesterIsSessionUser(approval approvalRecord, email string) bool {
	email = strings.TrimSpace(email)
	if email == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(approval.RequesterID), email) {
		return true
	}
	return approval.RequestedBy != nil && strings.EqualFold(strings.TrimSpace(*approval.RequestedBy), email)
}

func writeApprovalDecisionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errSelfApproval):
		writeJSON(w, http.StatusConflict, map[string]any{"error": errSelfApproval.Error()})
	case errors.Is(err, errApprovalExpired):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "approval has expired"})
	default:
		writeJSON(w, http.StatusConflict, map[string]any{"error": "approval is no longer pending"})
	}
}

type revokeRequest struct {
	AgentID string `json:"agent_id"`
	TaskID  string `json:"task_id"`
	ChainID string `json:"chain_id"`
	TokenID string `json:"token_id"`
}

func revokeScope(req revokeRequest) (scopeType, scopeID string, err error) {
	candidates := []struct {
		scopeType string
		scopeID   string
	}{
		{"agent", strings.TrimSpace(req.AgentID)},
		{"task", strings.TrimSpace(req.TaskID)},
		{"chain", strings.TrimSpace(req.ChainID)},
		{"token", strings.TrimSpace(req.TokenID)},
	}
	found := 0
	for _, candidate := range candidates {
		if candidate.scopeID == "" {
			continue
		}
		found++
		scopeType, scopeID = candidate.scopeType, candidate.scopeID
	}
	if found != 1 {
		return "", "", errors.New("exactly one of agent_id, task_id, chain_id, token_id is required")
	}
	return scopeType, scopeID, nil
}

func (h *consoleAdminHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFromContext(r.Context())
	var req revokeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	scopeType, scopeID, err := revokeScope(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := h.store.Revoke(r.Context(), principal.TenantID, principal.Email, scopeType, scopeID); err != nil {
		h.logger.Error("revoke", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (h *consoleAdminHandler) handleReplayEvents(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFromContext(r.Context())
	stored, err := h.store.ListEvents(r.Context(), principal.TenantID)
	if err != nil {
		h.logger.Error("list events", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

// pgConsoleStore is the PostgreSQL-backed consoleStore. Every method runs inside
// db.WithTenant so RLS scopes rows to the session tenant.
type pgConsoleStore struct {
	pool *pgxpool.Pool
}

func newConsoleStore(pool *pgxpool.Pool) *pgConsoleStore {
	return &pgConsoleStore{pool: pool}
}

const agentColumns = `COALESCE(slug, id::text), tenant_id::text, owner_subject, encode(public_key, 'base64'), status`

func (s *pgConsoleStore) ListAgents(ctx context.Context, tenantID string) ([]agentRecord, error) {
	agents := make([]agentRecord, 0)
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+agentColumns+` FROM agents ORDER BY created_at, slug`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var agent agentRecord
			if err := rows.Scan(&agent.ID, &agent.TenantID, &agent.OwnerSubject, &agent.PublicKey, &agent.Status); err != nil {
				return err
			}
			agent.PublicKey = standardBase64ToURL(agent.PublicKey)
			agents = append(agents, agent)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	return agents, nil
}

func (s *pgConsoleStore) CreateAgent(ctx context.Context, tenantID, actor string, input createAgentInput) (agentRecord, error) {
	rawKey, err := decodeAgentPublicKey(input.PublicKey)
	if err != nil {
		return agentRecord{}, err
	}
	var agent agentRecord
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO agents (id, tenant_id, name, owner_subject, public_key, status, slug)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, 'active', $5)
			RETURNING `+agentColumns,
			tenantID, input.ID, input.OwnerSubject, rawKey, input.ID,
		).Scan(&agent.ID, &agent.TenantID, &agent.OwnerSubject, &agent.PublicKey, &agent.Status); err != nil {
			return err
		}
		agent.PublicKey = standardBase64ToURL(agent.PublicKey)
		return appendEvent(ctx, tx, "agent.created", map[string]any{
			"agent_id":      agent.ID,
			"owner_subject": agent.OwnerSubject,
			"status":        agent.Status,
			"actor":         actor,
		})
	})
	if err != nil {
		if isUniqueViolation(err) {
			return agentRecord{}, errDuplicateAgent
		}
		return agentRecord{}, fmt.Errorf("create agent: %w", err)
	}
	return agent, nil
}

const tenantColumns = `id::text, name, contact_email, status, COALESCE(settings->>'plan', 'alpha'), created_at`

func scanTenant(row pgx.Row, tenant *tenantRecord) error {
	return row.Scan(&tenant.ID, &tenant.Name, &tenant.ContactEmail, &tenant.Status, &tenant.Plan, &tenant.CreatedAt)
}

func (s *pgConsoleStore) GetTenant(ctx context.Context, tenantID string) (tenantRecord, error) {
	var tenant tenantRecord
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return scanTenant(tx.QueryRow(ctx, `SELECT `+tenantColumns+` FROM tenants WHERE id = $1`, tenantID), &tenant)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantRecord{}, errTenantNotFound
	}
	if err != nil {
		return tenantRecord{}, fmt.Errorf("get tenant: %w", err)
	}
	return tenant, nil
}

func (s *pgConsoleStore) UpdateTenant(ctx context.Context, tenantID, actor string, name, contactEmail *string) (tenantRecord, error) {
	var tenant tenantRecord
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		sets := make([]string, 0, 2)
		args := make([]any, 0, 3)
		changed := make([]string, 0, 2)
		if name != nil {
			args = append(args, *name)
			sets = append(sets, fmt.Sprintf("name = $%d", len(args)))
			changed = append(changed, "name")
		}
		if contactEmail != nil {
			args = append(args, *contactEmail)
			sets = append(sets, fmt.Sprintf("contact_email = $%d", len(args)))
			changed = append(changed, "contact_email")
		}

		query := `SELECT ` + tenantColumns + ` FROM tenants WHERE id = $1`
		if len(sets) > 0 {
			args = append(args, tenantID)
			query = fmt.Sprintf(`UPDATE tenants SET %s WHERE id = $%d RETURNING %s`,
				strings.Join(sets, ", "), len(args), tenantColumns)
		}
		if err := scanTenant(tx.QueryRow(ctx, query, args...), &tenant); err != nil {
			return err
		}
		if len(changed) == 0 {
			return nil
		}
		return appendEvent(ctx, tx, "tenant.updated", map[string]any{
			"tenant_id": tenantID,
			"fields":    changed,
			"actor":     actor,
		})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantRecord{}, errTenantNotFound
	}
	if err != nil {
		return tenantRecord{}, fmt.Errorf("update tenant: %w", err)
	}
	return tenant, nil
}

const approvalColumns = `id::text, task_id, chain_id, requester_id, requested_by, action, parameters, status, expires_at, decided_by`

func scanApproval(row pgx.Row, approval *approvalRecord) error {
	var parameters []byte
	if err := row.Scan(&approval.ID, &approval.TaskID, &approval.ChainID, &approval.RequesterID,
		&approval.RequestedBy, &approval.Action, &parameters, &approval.Status, &approval.ExpiresAt,
		&approval.DecidedBy); err != nil {
		return err
	}
	approval.Parameters = parameters
	return nil
}

func (s *pgConsoleStore) ListApprovals(ctx context.Context, tenantID string) ([]approvalRecord, error) {
	approvals := make([]approvalRecord, 0)
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+approvalColumns+` FROM approval_requests ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var approval approvalRecord
			if err := scanApproval(rows, &approval); err != nil {
				return err
			}
			approvals = append(approvals, approval)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list approvals: %w", err)
	}
	return approvals, nil
}

func (s *pgConsoleStore) GetApproval(ctx context.Context, tenantID, id string) (approvalRecord, error) {
	var approval approvalRecord
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return scanApproval(tx.QueryRow(ctx, `SELECT `+approvalColumns+` FROM approval_requests WHERE id = $1`, id), &approval)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return approvalRecord{}, errApprovalNotFound
	}
	if err != nil {
		return approvalRecord{}, fmt.Errorf("get approval: %w", err)
	}
	return approval, nil
}

func (s *pgConsoleStore) DecideApproval(ctx context.Context, tenantID, id, status, decidedBy, sessionEmail string, parameters []byte) (approvalRecord, error) {
	var approval approvalRecord
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var current approvalRecord
		if err := scanApproval(tx.QueryRow(ctx, `SELECT `+approvalColumns+` FROM approval_requests WHERE id = $1 FOR UPDATE`, id), &current); err != nil {
			return err
		}
		// The authoritative check happens while the row is locked, before any UPDATE.
		if err := validateApprovalDecision(current, sessionEmail, time.Now()); err != nil {
			return err
		}
		if len(parameters) == 0 {
			parameters = current.Parameters
		}
		if err := scanApproval(tx.QueryRow(ctx, `
			UPDATE approval_requests
			SET status = $2, decided_by = $3, decided_at = now(), parameters = $4
			WHERE id = $1
			RETURNING `+approvalColumns,
			id, status, decidedBy, parameters), &approval); err != nil {
			return err
		}
		return appendEvent(ctx, tx, "approval.decided", map[string]any{
			"approval_id": approval.ID,
			"status":      approval.Status,
			"decided_by":  decidedBy,
		})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return approvalRecord{}, errApprovalNotFound
	}
	if err != nil {
		return approvalRecord{}, err
	}
	return approval, nil
}

func (s *pgConsoleStore) Revoke(ctx context.Context, tenantID, actor, scopeType, scopeID string) error {
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO revocations (tenant_id, scope_type, scope_id, expires_at)
			VALUES ($1, $2, $3, now() + interval '24 hours')
			ON CONFLICT (tenant_id, scope_type, scope_id)
			DO UPDATE SET expires_at = EXCLUDED.expires_at
		`, tenantID, scopeType, scopeID); err != nil {
			return err
		}
		if scopeType == "agent" {
			if _, err := tx.Exec(ctx, `UPDATE agents SET status = 'suspended' WHERE slug = $1`, scopeID); err != nil {
				return err
			}
		}
		return appendEvent(ctx, tx, "revocation.created", map[string]any{
			"scope_type": scopeType,
			"scope_id":   scopeID,
			"actor":      actor,
		})
	})
	if err != nil {
		return fmt.Errorf("revoke %s %s: %w", scopeType, scopeID, err)
	}
	return nil
}

func (s *pgConsoleStore) ListEvents(ctx context.Context, tenantID string) ([]eventRecord, error) {
	records := make([]eventRecord, 0)
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT seq, type, ts, payload, encode(hash, 'base64'), encode(prev_hash, 'base64')
			FROM events ORDER BY seq
		`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var record eventRecord
			var payload []byte
			if err := rows.Scan(&record.Seq, &record.Type, &record.TS, &payload, &record.Hash, &record.PrevHash); err != nil {
				return err
			}
			record.Payload = payload
			records = append(records, record)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	return records, nil
}

// appendEvent extends the tenant's hash chain using the events package hash
// helper. internal/events exposes hash primitives but no database append entry
// point, so the INSERT lives here (see the build report).
func appendEvent(ctx context.Context, tx pgx.Tx, eventType string, payload map[string]any) error {
	// Serialize appends per tenant so tenant_seq and prev_hash cannot race.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(current_tenant()::text, 0))`); err != nil {
		return fmt.Errorf("lock event chain: %w", err)
	}
	previous := []byte{}
	var tenantSeq int64
	err := tx.QueryRow(ctx, `SELECT hash, tenant_seq FROM events ORDER BY seq DESC LIMIT 1`).Scan(&previous, &tenantSeq)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("load previous event: %w", err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		previous = []byte{}
		tenantSeq = 0
	}
	hash, err := events.NextHash(previous, payload)
	if err != nil {
		return fmt.Errorf("hash event: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO events (tenant_id, type, payload, prev_hash, hash, tenant_seq)
		VALUES (current_tenant(), $1, $2, $3, $4, $5)
	`, eventType, payload, previous, hash, tenantSeq+1); err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	return nil
}
