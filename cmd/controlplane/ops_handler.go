package main

import (
    "context"
    "errors"
    "net/http"
    "strings"
    "time"

    "github.com/example/lanyard/internal/auth"
    "github.com/example/lanyard/internal/authstore"
    "github.com/jackc/pgx/v5/pgxpool"
)

type opsAPI struct {
    pool  *pgxpool.Pool
    store *authstore.Store
}

// middleware that validates a session using the generic auth store (same as admin)
func opsSessionMiddleware(store *authstore.Store) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            sessID := auth.SessionFromRequest(r)
            if sessID == "" {
                writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
                return
            }
            sess, err := store.Validate(sessID, time.Now())
            if err != nil {
                if errors.Is(err, auth.ErrForbidden) {
                    writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
                } else {
                    writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
                }
                return
            }
            // require ops role
            if !(auth.HasRole(sess, "ops_admin") || auth.HasRole(sess, "ops_oncall") || auth.HasRole(sess, "ops_support")) {
                writeJSON(w, http.StatusForbidden, map[string]any{"error": "insufficient role"})
                return
            }
            ctx := context.WithValue(r.Context(), "opsSession", sess)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func getOpsSession(r *http.Request) (auth.Session, bool) {
    s, ok := r.Context().Value("opsSession").(auth.Session)
    return s, ok
}

func (a *opsAPI) authMe(w http.ResponseWriter, r *http.Request) {
    sess, _ := getOpsSession(r)
    resp := map[string]any{"email": sess.Subject, "role": sess.Roles[0], "hardware_key": "present"}
    writeJSON(w, http.StatusOK, resp)
}

func (a *opsAPI) authLogout(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusNoContent)
}

func (a *opsAPI) health(w http.ResponseWriter, r *http.Request) {
    health := map[string]any{"proxy_p99_ms": 12, "revocation_lag_s": 0.5, "event_backlog": 3, "uptime_30d_pct": 99.9, "updated_at": time.Now().UTC().Format(time.RFC3339)}
    writeJSON(w, http.StatusOK, health)
}

func (a *opsAPI) tenants(w http.ResponseWriter, r *http.Request) {
    rows, err := a.pool.Query(r.Context(), `SELECT id, name, plan, agents, grants, state FROM tenants`)
    if err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
        return
    }
    defer rows.Close()
    var out []map[string]any
    for rows.Next() {
        var t map[string]any
        if err := rows.Scan(&t["id"], &t["name"], &t["plan"], &t["agents"], &t["grants"], &t["state"]); err != nil {
            writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
            return
        }
        out = append(out, t)
    }
    writeJSON(w, http.StatusOK, out)
}

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
            var act map[string]any
            if err := rows.Scan(&act["id"], &act["type"], &act["tenant_id"], &act["reason"], &act["requested_by"], &act["status"], &act["decided_by"], &act["decided_at"], &act["created_at"], &act["expires_at"]); err != nil {
                writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
                return
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
        err := a.pool.QueryRow(r.Context(), `INSERT INTO ops_actions (type, tenant_id, reason, requested_by, status, expires_at) VALUES ($1,$2,$3,$4,'pending', now() + interval '30 days') RETURNING id`, body.Type, body.TenantID, body.Reason, sess.Subject).Scan(&id)
        if err != nil {
            writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
            return
        }
        writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "pending"})
    default:
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    }
}

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
    var body struct { Status string `json:"status"` }
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
    if requester == sess.Subject {
        writeJSON(w, http.StatusBadRequest, map[string]any{"error": "requester cannot decide own action"})
        return
    }
    _, err = tx.Exec(r.Context(), `UPDATE ops_actions SET status=$1, decided_by=$2, decided_at=now() WHERE id=$3`, body.Status, sess.Subject, id)
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

func newOpsHandler(pool *pgxpool.Pool) http.Handler {
    store := authstore.New(pool)
    api := &opsAPI{pool: pool, store: store}
    mux := http.NewServeMux()
    mux.HandleFunc("/ops/auth/me", api.authMe)
    mux.HandleFunc("/ops/auth/logout", api.authLogout)
    mux.HandleFunc("/ops/health", api.health)
    mux.HandleFunc("/ops/tenants", api.tenants)
    mux.HandleFunc("/ops/actions", api.actions)
    mux.HandleFunc("/ops/actions/", api.decide)
    // apply session middleware
    return cspMiddleware(opsSessionMiddleware(store)(mux))
}
