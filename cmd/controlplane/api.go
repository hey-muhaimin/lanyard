package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/example/lanyard/internal/approvals"
	"github.com/example/lanyard/internal/events"
	"github.com/example/lanyard/internal/revocation"
)

type controlPlaneAPI struct {
	mu               sync.RWMutex
	tenants          map[string]map[string]any
	agents           map[string]map[string]any
	connectors       map[string]map[string]any
	modelConnections map[string]map[string]any
	approvals        *approvals.Store
	revocations      *revocation.Store
	events           map[string][]events.StoredEvent
}

func newControlPlaneAPI() *controlPlaneAPI {
	return &controlPlaneAPI{
		tenants: map[string]map[string]any{}, agents: map[string]map[string]any{}, connectors: map[string]map[string]any{},
		modelConnections: map[string]map[string]any{},
		approvals:        approvals.NewStore(), revocations: revocation.NewStore(), events: map[string][]events.StoredEvent{},
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
	mux.HandleFunc("/connect", api.connectHandler)
	mux.HandleFunc("/models", api.modelsHandler)
	mux.HandleFunc("/approve", api.approveHandler)
	mux.HandleFunc("/revoke", api.revokeHandler)
	mux.HandleFunc("/events/replay", api.replayHandler)

	return mux
}

func generateID() string {
	// Simple placeholder ID generator – in production use a UUID.
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

// agentsHandler implements creation of agents for a tenant in dev mode.
func (api *controlPlaneAPI) agentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID           string `json:"id"`
		TenantID     string `json:"tenant_id"`
		OwnerSubject string `json:"owner_subject"`
		PublicKey    string `json:"public_key"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.ID == "" || body.TenantID == "" || body.OwnerSubject == "" || body.PublicKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id, tenant_id, owner_subject, and public_key are required"})
		return
	}
	// Verify tenant exists
	api.mu.RLock()
	_, ok := api.tenants[body.TenantID]
	api.mu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown tenant"})
		return
	}
	// Store agent
	api.mu.Lock()
	if api.agents == nil {
		api.agents = map[string]map[string]any{}
	}
	api.agents[body.ID] = map[string]any{"id": body.ID, "tenant_id": body.TenantID, "owner_subject": body.OwnerSubject, "public_key": body.PublicKey}
	api.mu.Unlock()
	writeJSON(w, http.StatusCreated, api.agents[body.ID])
}

// tenantsHandler is a stub implementation for the /admin/tenants endpoint.
func (api *controlPlaneAPI) tenantsHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]any{"error": "tenants handler not implemented"})
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

// defaultModelBaseURL returns the default API base URL for a provider.
func defaultModelBaseURL(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "anthropic":
		return "https://api.anthropic.com/v1"
	case "openai", "":
		return "https://api.openai.com/v1"
	default:
		return ""
	}
}

// connectHandler connects a model provider by storing its API credentials.
// POST /connect  body: {"provider":"openai","api_key":"...","base_url":"...","name":"..."}
func (api *controlPlaneAPI) connectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Provider string `json:"provider"`
		APIKey   string `json:"api_key"`
		BaseURL  string `json:"base_url"`
		Name     string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Provider) == "" || strings.TrimSpace(body.APIKey) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "provider and api_key are required"})
		return
	}
	baseURL := strings.TrimSpace(body.BaseURL)
	if baseURL == "" {
		baseURL = defaultModelBaseURL(body.Provider)
		if baseURL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "base_url is required for this provider"})
			return
		}
	}
	id := fmt.Sprintf("conn-%d", time.Now().UnixNano())
	api.mu.Lock()
	if api.modelConnections == nil {
		api.modelConnections = map[string]map[string]any{}
	}
	api.modelConnections[id] = map[string]any{
		"id":         id,
		"provider":   strings.ToLower(strings.TrimSpace(body.Provider)),
		"base_url":   baseURL,
		"name":       body.Name,
		"api_key":    body.APIKey,
		"status":     "connected",
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}
	api.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":       id,
		"provider": strings.ToLower(strings.TrimSpace(body.Provider)),
		"base_url": baseURL,
		"name":     body.Name,
		"status":   "connected",
	})
}

// modelsHandler lists available models.
// GET /models
//
//	?connection_id=<id>  -> fetch models from the connected provider
//	?provider=<name>     -> static catalog for that provider (or all if omitted)
func (api *controlPlaneAPI) modelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	connID := strings.TrimSpace(r.URL.Query().Get("connection_id"))
	if connID != "" {
		api.mu.RLock()
		conn, ok := api.modelConnections[connID]
		api.mu.RUnlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown connection"})
			return
		}
		models, err := fetchProviderModels(conn)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"connection_id": connID, "provider": conn["provider"], "models": models})
		return
	}
	provider := strings.TrimSpace(r.URL.Query().Get("provider"))
	writeJSON(w, http.StatusOK, map[string]any{"models": staticModelCatalog(provider)})
}

// staticModelCatalog returns a small built-in catalog of known models.
func staticModelCatalog(provider string) []map[string]any {
	type m struct{ ID, Provider string }
	all := []m{
		{"gpt-4o", "openai"}, {"gpt-4o-mini", "openai"}, {"gpt-4-turbo", "openai"},
		{"o1", "openai"}, {"o1-mini", "openai"},
		{"claude-3-5-sonnet-latest", "anthropic"}, {"claude-3-5-haiku-latest", "anthropic"}, {"claude-3-opus-latest", "anthropic"},
	}
	p := strings.ToLower(provider)
	out := []map[string]any{}
	for _, mm := range all {
		if p != "" && mm.Provider != p {
			continue
		}
		out = append(out, map[string]any{"id": mm.ID, "provider": mm.Provider})
	}
	return out
}

// fetchProviderModels queries a connected provider's models endpoint.
func fetchProviderModels(conn map[string]any) ([]string, error) {
	baseURL, _ := conn["base_url"].(string)
	apiKey, _ := conn["api_key"].(string)
	provider, _ := conn["provider"].(string)
	if baseURL == "" || apiKey == "" {
		return nil, fmt.Errorf("connection is missing base_url or api_key")
	}
	baseURL = strings.TrimRight(baseURL, "/")
	var reqURL, headerKey, headerVal string
	switch provider {
	case "anthropic":
		reqURL = baseURL + "/models"
		headerKey = "x-api-key"
		headerVal = apiKey
	default:
		reqURL = baseURL + "/models"
		headerKey = "Authorization"
		headerVal = "Bearer " + apiKey
	}
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(headerKey, headerVal)
	if provider == "anthropic" {
		req.Header.Set("anthropic-version", "2023-06-01")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned status %d", resp.StatusCode)
	}
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("invalid provider response")
	}
	ids := []string{}
	for _, d := range payload.Data {
		if d.ID != "" {
			ids = append(ids, d.ID)
		}
	}
	for _, m := range payload.Models {
		if m.ID != "" {
			ids = append(ids, m.ID)
		}
	}
	return ids, nil
}

func (api *controlPlaneAPI) opsHealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	health := map[string]any{
		"proxy_p99_ms":     12,
		"revocation_lag_s": 0.5,
		"event_backlog":    3,
		"uptime_30d_pct":   99.9,
		"updated_at":       time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, health)
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
		if request.RequesterID != "" && body.RequesterID != "" && request.RequesterID == body.RequesterID {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "requester cannot approve their own request"})
			return
		}
		writeJSON(w, http.StatusOK, request)
		return
	}
	request, err := api.approvals.Create(approvals.Request{ID: body.ID, TenantID: tenant, TaskID: body.TaskID, ChainID: body.ChainID, RequesterID: body.RequesterID, Action: body.Action, Parameters: body.Parameters}, time.Now())
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

func (api *controlPlaneAPI) opsTenantsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	api.mu.RLock()
	defer api.mu.RUnlock()
	items := make([]map[string]any, 0, len(api.tenants))
	for _, t := range api.tenants {
		items = append(items, t)
	}
	writeJSON(w, http.StatusOK, items)
}

func (api *controlPlaneAPI) opsActionsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// List actions (approvals) for the tenant, or all if no tenant header
		tenant := tenantID(r)
		writeJSON(w, http.StatusOK, api.approvals.List(tenant))
		return
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
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "type, tenant_id, and reason (≥20 chars) are required"})
			return
		}
		// Use approvals store to create a pending request
		req := approvals.Request{ID: generateID(), TenantID: body.TenantID, Action: body.Type, Parameters: map[string]any{"reason": body.Reason}}
		// ID generation simple placeholder
		created, err := api.approvals.Create(req, time.Now())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *controlPlaneAPI) opsActionDecideHandler(w http.ResponseWriter, r *http.Request) {
	// Expected path: /ops/actions/{id}/decide
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Extract id from URL path
	// URL pattern: /ops/actions/<id>/decide
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
	tenant := tenantID(r)
	// Decision uses empty parameters (no extra data needed)
	updated, err := api.approvals.Decide(id, tenant, body.Status, nil, time.Now())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (api *controlPlaneAPI) replayHandler(w http.ResponseWriter, r *http.Request) {
	// Verify Origin header for admin routes (placeholder check)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "https://trusted.example.com" {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "invalid origin"})
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
