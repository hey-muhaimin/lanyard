package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/example/lanyard/internal/approvals"
	"github.com/example/lanyard/internal/events"
	"github.com/example/lanyard/internal/revocation"
)

type controlPlaneAPI struct {
	mu          sync.RWMutex
	tenants     map[string]map[string]any
	agents      map[string]map[string]any
	connectors  map[string]map[string]any
	approvals   *approvals.Store
	revocations *revocation.Store
	events      map[string][]events.StoredEvent
}

func newControlPlaneAPI() *controlPlaneAPI {
	return &controlPlaneAPI{
		tenants: map[string]map[string]any{}, agents: map[string]map[string]any{}, connectors: map[string]map[string]any{},
		approvals: approvals.NewStore(), revocations: revocation.NewStore(), events: map[string][]events.StoredEvent{},
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return false
	}
	return true
}

func tenantID(r *http.Request) string { return strings.TrimSpace(r.Header.Get("X-Tenant-ID")) }

func (api *controlPlaneAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/tenants", api.tenantsHandler)
	mux.HandleFunc("/admin/agents", api.agentsHandler)
	mux.HandleFunc("/admin/connectors", api.connectorsHandler)
	mux.HandleFunc("/approve", api.approveHandler)
	mux.HandleFunc("/revoke", api.revokeHandler)
	mux.HandleFunc("/events/replay", api.replayHandler)
	return mux
}

func (api *controlPlaneAPI) tenantsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body map[string]any
		if !decodeJSON(w, r, &body) {
			return
		}
		id, _ := body["id"].(string)
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id is required"})
			return
		}
		api.mu.Lock()
		api.tenants[id] = body
		api.mu.Unlock()
		writeJSON(w, http.StatusCreated, body)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	api.mu.RLock()
	defer api.mu.RUnlock()
	items := make([]map[string]any, 0, len(api.tenants))
	for _, item := range api.tenants {
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (api *controlPlaneAPI) agentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body map[string]any
		if !decodeJSON(w, r, &body) {
			return
		}
		id, _ := body["id"].(string)
		tenant, _ := body["tenant_id"].(string)
		if id == "" || tenant == "" || body["owner_subject"] == "" || body["public_key"] == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id, tenant_id, owner_subject, and public_key are required"})
			return
		}
		api.mu.RLock()
		_, tenantExists := api.tenants[tenant]
		api.mu.RUnlock()
		if !tenantExists {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown tenant"})
			return
		}
		api.mu.Lock()
		api.agents[id] = body
		api.mu.Unlock()
		writeJSON(w, http.StatusCreated, body)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	api.mu.RLock()
	defer api.mu.RUnlock()
	items := make([]map[string]any, 0, len(api.agents))
	for _, item := range api.agents {
		if tenantID(r) == "" || item["tenant_id"] == tenantID(r) {
			items = append(items, item)
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (api *controlPlaneAPI) connectorsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]any
	if !decodeJSON(w, r, &body) {
		return
	}
	id, _ := body["id"].(string)
	tenant, _ := body["tenant_id"].(string)
	if id == "" || tenant == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id and tenant_id are required"})
		return
	}
	api.mu.RLock()
	_, ok := api.tenants[tenant]
	api.mu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown tenant"})
		return
	}
	api.mu.Lock()
	api.connectors[id] = body
	api.mu.Unlock()
	writeJSON(w, http.StatusCreated, body)
}

func (api *controlPlaneAPI) approveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tenant := tenantID(r)
		writeJSON(w, http.StatusOK, api.approvals.List(tenant))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID          string         `json:"id"`
		Status      string         `json:"status"`
		Parameters  map[string]any `json:"parameters"`
		TenantID    string         `json:"tenant_id"`
		TaskID      string         `json:"task_id"`
		ChainID     string         `json:"chain_id"`
		RequesterID string         `json:"requester_id"`
		Action      string         `json:"action"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	tenant := body.TenantID
	if tenant == "" {
		tenant = tenantID(r)
	}
	if body.Status == "approved" || body.Status == "denied" {
		request, err := api.approvals.Decide(body.ID, tenant, body.Status, body.Parameters, time.Now())
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, request)
		return
	}
	request, err := api.approvals.Create(approvals.Request{
		ID: body.ID, TenantID: tenant, TaskID: body.TaskID, ChainID: body.ChainID,
		RequesterID: body.RequesterID, Action: body.Action, Parameters: body.Parameters,
	}, time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, request)
}

func (api *controlPlaneAPI) revokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		AgentID   string    `json:"agent_id"`
		TaskID    string    `json:"task_id"`
		ChainID   string    `json:"chain_id"`
		TokenID   string    `json:"token_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.ExpiresAt.IsZero() {
		body.ExpiresAt = time.Now().Add(10 * time.Minute)
	}
	if err := api.revocations.Revoke(revocation.Scope{AgentID: body.AgentID, TaskID: body.TaskID, ChainID: body.ChainID, TokenID: body.TokenID}, body.ExpiresAt); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "revoked"})
}

func (api *controlPlaneAPI) replayHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant := tenantID(r)
	if tenant == "" {
		tenant = r.URL.Query().Get("tenant_id")
	}
	api.mu.RLock()
	chain := append([]events.StoredEvent(nil), api.events[tenant]...)
	api.mu.RUnlock()
	if err := events.VerifyChain(chain); err != nil && len(chain) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, chain)
}
