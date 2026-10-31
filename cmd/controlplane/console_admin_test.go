package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/lanyard/internal/authstore"
	"github.com/example/lanyard/internal/config"
)

type fakeSessionStore struct {
	session authstore.Session
	ok      bool
	err     error
}

func (f *fakeSessionStore) GetSession(_ context.Context, _ []byte, _ time.Duration) (authstore.Session, bool, error) {
	return f.session, f.ok, f.err
}

type revokedScope struct {
	scopeType string
	scopeID   string
	actor     string
}

type fakeConsoleStore struct {
	agents     map[string]agentRecord
	tenants    map[string]tenantRecord
	approvals  map[string]approvalRecord
	events     []eventRecord
	revoked    []revokedScope
	decideHits int
	lastTenant string
}

func newFakeConsoleStore() *fakeConsoleStore {
	tenantID := "tenant-a"
	email := "old@example.com"
	return &fakeConsoleStore{
		agents:    map[string]agentRecord{},
		tenants:   map[string]tenantRecord{tenantID: {ID: tenantID, Name: "Acme", ContactEmail: &email, Status: "active", Plan: "alpha", CreatedAt: time.Unix(1_700_000_000, 0).UTC()}},
		approvals: map[string]approvalRecord{},
	}
}

func (f *fakeConsoleStore) ListAgents(_ context.Context, tenantID string) ([]agentRecord, error) {
	f.lastTenant = tenantID
	agents := make([]agentRecord, 0, len(f.agents))
	for _, agent := range f.agents {
		agents = append(agents, agent)
	}
	return agents, nil
}

func (f *fakeConsoleStore) CreateAgent(_ context.Context, tenantID, actor string, input createAgentInput) (agentRecord, error) {
	f.lastTenant = tenantID
	if _, exists := f.agents[input.ID]; exists {
		return agentRecord{}, errDuplicateAgent
	}
	key, err := decodeAgentPublicKey(input.PublicKey)
	if err != nil {
		return agentRecord{}, err
	}
	agent := agentRecord{
		ID:           input.ID,
		TenantID:     tenantID,
		OwnerSubject: input.OwnerSubject,
		PublicKey:    base64.RawURLEncoding.EncodeToString(key),
		Status:       "active",
	}
	f.agents[agent.ID] = agent
	return agent, nil
}

func (f *fakeConsoleStore) GetTenant(_ context.Context, tenantID string) (tenantRecord, error) {
	f.lastTenant = tenantID
	tenant, ok := f.tenants[tenantID]
	if !ok {
		return tenantRecord{}, errTenantNotFound
	}
	return tenant, nil
}

func (f *fakeConsoleStore) UpdateTenant(_ context.Context, tenantID, actor string, name, contactEmail *string) (tenantRecord, error) {
	f.lastTenant = tenantID
	tenant, ok := f.tenants[tenantID]
	if !ok {
		return tenantRecord{}, errTenantNotFound
	}
	if name != nil {
		tenant.Name = *name
	}
	if contactEmail != nil {
		value := *contactEmail
		tenant.ContactEmail = &value
	}
	f.tenants[tenantID] = tenant
	return tenant, nil
}

func (f *fakeConsoleStore) ListApprovals(_ context.Context, tenantID string) ([]approvalRecord, error) {
	f.lastTenant = tenantID
	approvals := make([]approvalRecord, 0, len(f.approvals))
	for _, approval := range f.approvals {
		approvals = append(approvals, approval)
	}
	return approvals, nil
}

func (f *fakeConsoleStore) GetApproval(_ context.Context, tenantID, id string) (approvalRecord, error) {
	f.lastTenant = tenantID
	approval, ok := f.approvals[id]
	if !ok {
		return approvalRecord{}, errApprovalNotFound
	}
	return approval, nil
}

func (f *fakeConsoleStore) DecideApproval(_ context.Context, tenantID, id, status, decidedBy, _ string, _ []byte) (approvalRecord, error) {
	f.decideHits++
	f.lastTenant = tenantID
	approval, ok := f.approvals[id]
	if !ok {
		return approvalRecord{}, errApprovalNotFound
	}
	approval.Status = status
	approval.DecidedBy = &decidedBy
	f.approvals[id] = approval
	return approval, nil
}

func (f *fakeConsoleStore) Revoke(_ context.Context, tenantID, actor, scopeType, scopeID string) error {
	f.lastTenant = tenantID
	f.revoked = append(f.revoked, revokedScope{scopeType: scopeType, scopeID: scopeID, actor: actor})
	return nil
}

func (f *fakeConsoleStore) ListEvents(_ context.Context, tenantID string) ([]eventRecord, error) {
	f.lastTenant = tenantID
	return f.events, nil
}

func testSession(role string) authstore.Session {
	return authstore.Session{
		TenantID: "tenant-a",
		MemberID: "member-a",
		Email:    "Alice@Example.com",
		Role:     role,
	}
}

func newConsoleTestHandler(session authstore.Session, store *fakeConsoleStore) http.Handler {
	cfg := config.Config{SessionIdle: time.Hour, SessionTTL: 12 * time.Hour}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newConsoleAdminHandler(&fakeSessionStore{session: session, ok: true}, store, cfg, logger)
}

func consoleRequest(method, path, body string, signedIn bool) *http.Request {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	if signedIn {
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	}
	return request
}

func TestConsoleAdminRequiresSessionAndIgnoresTenantHeader(t *testing.T) {
	store := newFakeConsoleStore()
	handler := newConsoleTestHandler(testSession("admin"), store)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, consoleRequest(http.MethodGet, "/admin/tenant", "", false))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned GET /admin/tenant status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(recorder.Body.String(), `"not signed in"`) {
		t.Fatalf("unsigned body = %q", recorder.Body.String())
	}

	request := consoleRequest(http.MethodGet, "/admin/tenant", "", true)
	request.Header.Set("X-Tenant-ID", "tenant-b")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("signed GET /admin/tenant status = %d; body=%q", recorder.Code, recorder.Body.String())
	}
	if store.lastTenant != "tenant-a" {
		t.Fatalf("handler used tenant %q, want session tenant tenant-a", store.lastTenant)
	}
}

func TestConsoleAdminRejectsInvalidSession(t *testing.T) {
	store := newFakeConsoleStore()
	cfg := config.Config{SessionIdle: time.Hour}
	handler := newConsoleAdminHandler(&fakeSessionStore{ok: false}, store, cfg, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, consoleRequest(http.MethodGet, "/admin/agents", "", true))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("invalid session status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestConsoleAdminPermissionMatrix(t *testing.T) {
	validKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	approval := approvalRecord{ID: "approval-1", Status: "pending", RequesterID: "someone-else", ExpiresAt: time.Now().Add(time.Hour)}

	tests := []struct {
		name   string
		role   string
		method string
		path   string
		body   string
		want   int
	}{
		{name: "admin lists agents", role: "admin", method: http.MethodGet, path: "/admin/agents", want: http.StatusOK},
		{name: "auditor lists agents", role: "auditor", method: http.MethodGet, path: "/admin/agents", want: http.StatusOK},
		{name: "auditor cannot create agent", role: "auditor", method: http.MethodPost, path: "/admin/agents", body: `{"id":"agent-a","owner_subject":"user:a","public_key":"` + validKey + `"}`, want: http.StatusForbidden},
		{name: "agent owner creates agent", role: "agent_owner", method: http.MethodPost, path: "/admin/agents", body: `{"id":"agent-a","owner_subject":"user:a","public_key":"` + validKey + `"}`, want: http.StatusCreated},
		{name: "agent owner cannot list approvals", role: "agent_owner", method: http.MethodGet, path: "/approve", want: http.StatusForbidden},
		{name: "approver lists approvals", role: "approver", method: http.MethodGet, path: "/approve", want: http.StatusOK},
		{name: "approver cannot revoke", role: "approver", method: http.MethodPost, path: "/revoke", body: `{"task_id":"task-1"}`, want: http.StatusForbidden},
		{name: "security revokes", role: "security", method: http.MethodPost, path: "/revoke", body: `{"task_id":"task-1"}`, want: http.StatusOK},
		{name: "agent owner reads events", role: "agent_owner", method: http.MethodGet, path: "/events/replay", want: http.StatusOK},
		{name: "approver cannot read events", role: "approver", method: http.MethodGet, path: "/events/replay", want: http.StatusForbidden},
		{name: "admin updates tenant", role: "admin", method: http.MethodPatch, path: "/admin/tenant", body: `{"name":"New Name"}`, want: http.StatusOK},
		{name: "security cannot update tenant", role: "security", method: http.MethodPatch, path: "/admin/tenant", body: `{"name":"New Name"}`, want: http.StatusForbidden},
		{name: "admin reads tenant", role: "admin", method: http.MethodGet, path: "/admin/tenant", want: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeConsoleStore()
			store.approvals["approval-1"] = approval
			handler := newConsoleTestHandler(testSession(test.role), store)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, consoleRequest(test.method, test.path, test.body, true))
			if recorder.Code != test.want {
				t.Fatalf("%s %s as %s = %d, want %d; body=%q", test.method, test.path, test.role, recorder.Code, test.want, recorder.Body.String())
			}
		})
	}
}

func TestConsoleAdminAgentValidation(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	longID := strings.Repeat("a", 65)
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "uppercase id", body: `{"id":"Agent","owner_subject":"user:a","public_key":"` + base64.RawURLEncoding.EncodeToString(key) + `"}`, want: http.StatusBadRequest},
		{name: "id too long", body: `{"id":"` + longID + `","owner_subject":"user:a","public_key":"` + base64.RawURLEncoding.EncodeToString(key) + `"}`, want: http.StatusBadRequest},
		{name: "empty owner", body: `{"id":"agent-a","owner_subject":"","public_key":"` + base64.RawURLEncoding.EncodeToString(key) + `"}`, want: http.StatusBadRequest},
		{name: "malformed key", body: `{"id":"agent-a","owner_subject":"user:a","public_key":"not*base64"}`, want: http.StatusBadRequest},
		{name: "short key", body: `{"id":"agent-a","owner_subject":"user:a","public_key":"` + base64.RawURLEncoding.EncodeToString(key[:16]) + `"}`, want: http.StatusBadRequest},
		{name: "base64url key", body: `{"id":"agent-url","owner_subject":"user:a","public_key":"` + base64.RawURLEncoding.EncodeToString(key) + `"}`, want: http.StatusCreated},
		{name: "padded standard key", body: `{"id":"agent-std","owner_subject":"user:a","public_key":"` + base64.StdEncoding.EncodeToString(key) + `"}`, want: http.StatusCreated},
		{name: "raw standard key", body: `{"id":"agent-raw","owner_subject":"user:a","public_key":"` + base64.RawStdEncoding.EncodeToString(key) + `"}`, want: http.StatusCreated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newConsoleTestHandler(testSession("admin"), newFakeConsoleStore())
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, consoleRequest(http.MethodPost, "/admin/agents", test.body, true))
			if recorder.Code != test.want {
				t.Fatalf("POST /admin/agents = %d, want %d; body=%q", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}
}

func TestConsoleAdminDuplicateAgent(t *testing.T) {
	store := newFakeConsoleStore()
	handler := newConsoleTestHandler(testSession("admin"), store)
	body := `{"id":"agent-a","owner_subject":"user:a","public_key":"` + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + `"}`
	for _, want := range []int{http.StatusCreated, http.StatusConflict} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, consoleRequest(http.MethodPost, "/admin/agents", body, true))
		if recorder.Code != want {
			t.Fatalf("POST /admin/agents = %d, want %d; body=%q", recorder.Code, want, recorder.Body.String())
		}
		if want == http.StatusConflict && !strings.Contains(recorder.Body.String(), "an agent with that name already exists") {
			t.Fatalf("duplicate body = %q", recorder.Body.String())
		}
	}
}

func TestConsoleAdminTenantValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "empty name", body: `{"name":""}`, want: http.StatusBadRequest},
		{name: "name too long", body: `{"name":"` + strings.Repeat("x", 101) + `"}`, want: http.StatusBadRequest},
		{name: "bad email", body: `{"contact_email":"not-an-email"}`, want: http.StatusBadRequest},
		{name: "email too long", body: `{"contact_email":"` + strings.Repeat("x", 250) + `@example.com"}`, want: http.StatusBadRequest},
		{name: "valid name", body: `{"name":"New Name"}`, want: http.StatusOK},
		{name: "empty email allowed", body: `{"contact_email":""}`, want: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeConsoleStore()
			handler := newConsoleTestHandler(testSession("admin"), store)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, consoleRequest(http.MethodPatch, "/admin/tenant", test.body, true))
			if recorder.Code != test.want {
				t.Fatalf("PATCH /admin/tenant = %d, want %d; body=%q", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}

	t.Run("only provided fields change", func(t *testing.T) {
		store := newFakeConsoleStore()
		handler := newConsoleTestHandler(testSession("admin"), store)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, consoleRequest(http.MethodPatch, "/admin/tenant", `{"name":"Renamed"}`, true))
		if recorder.Code != http.StatusOK {
			t.Fatalf("PATCH /admin/tenant = %d; body=%q", recorder.Code, recorder.Body.String())
		}
		tenant := store.tenants["tenant-a"]
		if tenant.Name != "Renamed" || tenant.ContactEmail == nil || *tenant.ContactEmail != "old@example.com" {
			t.Fatalf("tenant after patch = %#v", tenant)
		}
	})

	t.Run("missing tenant", func(t *testing.T) {
		store := newFakeConsoleStore()
		delete(store.tenants, "tenant-a")
		handler := newConsoleTestHandler(testSession("admin"), store)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, consoleRequest(http.MethodPatch, "/admin/tenant", `{"name":"Renamed"}`, true))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("PATCH /admin/tenant missing = %d, want %d", recorder.Code, http.StatusNotFound)
		}
	})
}

func TestConsoleAdminSelfApprovalHasNoMutation(t *testing.T) {
	tests := []struct {
		name      string
		requester string
		requested *string
	}{
		{name: "requester_id", requester: "alice@example.com"},
		{name: "requested_by", requester: "someone-else", requested: func() *string { value := "ALICE@example.com"; return &value }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeConsoleStore()
			store.approvals["approval-1"] = approvalRecord{
				ID:          "approval-1",
				RequesterID: test.requester,
				RequestedBy: test.requested,
				Status:      "pending",
				ExpiresAt:   time.Now().Add(time.Hour),
			}
			handler := newConsoleTestHandler(testSession("approver"), store)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, consoleRequest(http.MethodPost, "/approve", `{"id":"approval-1","status":"approved"}`, true))
			if recorder.Code != http.StatusConflict {
				t.Fatalf("self-approval status = %d, want %d; body=%q", recorder.Code, http.StatusConflict, recorder.Body.String())
			}
			if store.decideHits != 0 {
				t.Fatalf("self-approval called DecideApproval %d times, want 0", store.decideHits)
			}
			if got := store.approvals["approval-1"].Status; got != "pending" {
				t.Fatalf("self-approval mutated status to %q", got)
			}
		})
	}
}

func TestConsoleAdminApprovalDecision(t *testing.T) {
	store := newFakeConsoleStore()
	store.approvals["approval-1"] = approvalRecord{
		ID:          "approval-1",
		RequesterID: "owner@example.com",
		Status:      "pending",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	handler := newConsoleTestHandler(testSession("approver"), store)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, consoleRequest(http.MethodPost, "/approve", `{"id":"approval-1","status":"denied","parameters":{"reason":"no"}}`, true))
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /approve = %d; body=%q", recorder.Code, recorder.Body.String())
	}
	if store.decideHits != 1 || store.approvals["approval-1"].Status != "denied" {
		t.Fatalf("decide hits = %d, status = %q", store.decideHits, store.approvals["approval-1"].Status)
	}

	for name, body := range map[string]string{
		"invalid status": `{"id":"approval-1","status":"maybe"}`,
		"missing id":     `{"id":"","status":"approved"}`,
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, consoleRequest(http.MethodPost, "/approve", body, true))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("POST /approve = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
		})
	}

	t.Run("non pending", func(t *testing.T) {
		store := newFakeConsoleStore()
		store.approvals["approval-1"] = approvalRecord{ID: "approval-1", RequesterID: "other", Status: "approved", ExpiresAt: time.Now().Add(time.Hour)}
		handler := newConsoleTestHandler(testSession("approver"), store)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, consoleRequest(http.MethodPost, "/approve", `{"id":"approval-1","status":"denied"}`, true))
		if recorder.Code != http.StatusConflict || store.decideHits != 0 {
			t.Fatalf("non-pending status = %d, decide hits = %d", recorder.Code, store.decideHits)
		}
	})

	t.Run("expired", func(t *testing.T) {
		store := newFakeConsoleStore()
		store.approvals["approval-1"] = approvalRecord{ID: "approval-1", RequesterID: "other", Status: "pending", ExpiresAt: time.Now().Add(-time.Minute)}
		handler := newConsoleTestHandler(testSession("approver"), store)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, consoleRequest(http.MethodPost, "/approve", `{"id":"approval-1","status":"denied"}`, true))
		if recorder.Code != http.StatusConflict || store.decideHits != 0 {
			t.Fatalf("expired status = %d, decide hits = %d", recorder.Code, store.decideHits)
		}
	})
}

func TestConsoleAdminRevokeScopeMapping(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		scopeType string
		scopeID   string
	}{
		{name: "agent", body: `{"agent_id":"agent-a"}`, scopeType: "agent", scopeID: "agent-a"},
		{name: "task", body: `{"task_id":"task-1"}`, scopeType: "task", scopeID: "task-1"},
		{name: "chain", body: `{"chain_id":"chain-1"}`, scopeType: "chain", scopeID: "chain-1"},
		{name: "token", body: `{"token_id":"token-1"}`, scopeType: "token", scopeID: "token-1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeConsoleStore()
			handler := newConsoleTestHandler(testSession("security"), store)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, consoleRequest(http.MethodPost, "/revoke", test.body, true))
			if recorder.Code != http.StatusOK {
				t.Fatalf("POST /revoke = %d; body=%q", recorder.Code, recorder.Body.String())
			}
			if len(store.revoked) != 1 || store.revoked[0].scopeType != test.scopeType || store.revoked[0].scopeID != test.scopeID {
				t.Fatalf("revoked = %#v", store.revoked)
			}
		})
	}

	for name, body := range map[string]string{
		"zero scopes": `{}`,
		"two scopes":  `{"agent_id":"agent-a","task_id":"task-1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakeConsoleStore()
			handler := newConsoleTestHandler(testSession("security"), store)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, consoleRequest(http.MethodPost, "/revoke", body, true))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("POST /revoke = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
			if len(store.revoked) != 0 {
				t.Fatalf("invalid revoke mutated the store: %#v", store.revoked)
			}
		})
	}
}

func TestConsoleAdminReplayEvents(t *testing.T) {
	store := newFakeConsoleStore()
	store.events = []eventRecord{{
		Seq:      1,
		Type:     "agent.created",
		TS:       time.Unix(1_700_000_000, 0).UTC(),
		Payload:  json.RawMessage(`{"agent_id":"agent-a"}`),
		Hash:     "aGFzaA==",
		PrevHash: "",
	}}
	handler := newConsoleTestHandler(testSession("auditor"), store)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, consoleRequest(http.MethodGet, "/events/replay", "", true))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /events/replay = %d; body=%q", recorder.Code, recorder.Body.String())
	}
	var decoded []map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	if len(decoded) != 1 || decoded[0]["type"] != "agent.created" || decoded[0]["hash"] != "aGFzaA==" {
		t.Fatalf("events = %#v", decoded)
	}
}
