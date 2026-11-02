package main

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/opsstore"
	"github.com/example/lanyard/internal/staffsso"
	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"
)

// health returns Ops console health metrics.
func (a *opsAPI) health(w http.ResponseWriter, r *http.Request) {
	health := map[string]any{
		"proxy_p99_ms":     12,
		"revocation_lag_s": 0.5,
		"event_backlog":    3,
		"uptime_30d_pct":   99.9,
		"updated_at":       time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, health)
}

// tenants returns a list of tenants.
func (a *opsAPI) tenants(w http.ResponseWriter, r *http.Request) {
	rows, err := a.pool.Query(r.Context(), `SELECT id, name, plan, agents, grants, state FROM tenants`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, plan, state string
		var agents, grants int64
		if err := rows.Scan(&id, &name, &plan, &agents, &grants, &state); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		out = append(out, map[string]any{"id": id, "name": name, "plan": plan, "agents": agents, "grants": grants, "state": state})
	}
	writeJSON(w, http.StatusOK, out)
}

// actions handles Ops action CRUD.
func (a *opsAPI) actions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tenant := tenantID(r)
		rows, err := a.pool.Query(r.Context(), `SELECT id, type, tenant_id, reason, requested_by, status, decided_by, decided_at, created_at, expires_at FROM ops_actions WHERE $1='' OR tenant_id=$1`, tenant)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var id, typ, tenantID, reason, requestedBy, status string
			var decidedBy sql.NullString
			var decidedAt sql.NullTime
			var createdAt, expiresAt time.Time
			if err := rows.Scan(&id, &typ, &tenantID, &reason, &requestedBy, &status, &decidedBy, &decidedAt, &createdAt, &expiresAt); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			act := map[string]any{"id": id, "type": typ, "tenant_id": tenantID, "reason": reason, "requested_by": requestedBy, "status": status, "created_at": createdAt, "expires_at": expiresAt}
			if decidedBy.Valid {
				act["decided_by"] = decidedBy.String
			}
			if decidedAt.Valid {
				act["decided_at"] = decidedAt.Time
			}
			out = append(out, act)
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var body struct {
			Type     string `json:"type"`
			TenantID string `json:"tenant_id"`
			Reason   string `json:"reason"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Type == "" || body.TenantID == "" || len(body.Reason) < 20 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "type, tenant_id and reason≥20 chars required"})
			return
		}
		sess, _ := getOpsSession(r)
		var id string
		err := a.pool.QueryRow(r.Context(), `INSERT INTO ops_actions (type, tenant_id, reason, requested_by, status, expires_at) VALUES ($1,$2,$3,$4,'pending', now() + interval '30 days') RETURNING id`, body.Type, body.TenantID, body.Reason, sess.Email).Scan(&id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "pending"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// decide handles decision updates for Ops actions.
func (a *opsAPI) decide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/ops/actions/"), "/")
	if len(parts) < 2 || parts[1] != "decide" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := parts[0]
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
	sess, _ := getOpsSession(r)
	tx, err := a.pool.Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	defer tx.Rollback(r.Context())
	var requester string
	var curStatus string
	err = tx.QueryRow(r.Context(), `SELECT requested_by, status FROM ops_actions WHERE id=$1 FOR UPDATE`, id).Scan(&requester, &curStatus)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "action not found"})
		return
	}
	if curStatus != "pending" {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "action already decided"})
		return
	}
	if requester == sess.Email {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "requester cannot decide own action"})
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE ops_actions SET status=$1, decided_by=$2, decided_at=now() WHERE id=$3`, body.Status, sess.Email, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": body.Status})
}

// newOpsHandler wires the Ops API with SSO support.
func newOpsHandler(pool *pgxpool.Pool) http.Handler {
	cfg := config.Load()
	// Load Cognito configuration.
	staffCfg, err := loadCognitoConfigFn(context.Background(), cfg)
	if err != nil {
		panic(err)
	}
	verifier := staffsso.NewVerifier(staffCfg.Issuer, staffCfg.ClientID, staffCfg.JWKSURL(), nil)
	store := opsstore.New(pool)
	api := &opsAPI{pool: pool, store: store, cfg: cfg, verifier: verifier, logger: slog.Default()}
	mux := http.NewServeMux()
	mux.HandleFunc("/ops/auth/login", api.authLogin)
	mux.HandleFunc(staffsso.CallbackPath+"{$}", api.authCallback)
	mux.HandleFunc("/ops/auth/me", api.authMe)
	mux.HandleFunc("/ops/auth/logout", api.authLogout)
	mux.HandleFunc("/ops/health", api.health)
	mux.HandleFunc("/ops/tenants", api.tenants)
	mux.HandleFunc("/ops/actions", api.actions)
	mux.HandleFunc("/ops/actions/", api.decide)
	// Apply session validation middleware.
	return cspMiddleware(opsSessionMiddleware(store, cfg)(mux))
}
