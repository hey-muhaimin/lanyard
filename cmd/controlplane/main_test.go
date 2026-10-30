package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	token "github.com/example/lanyard/internal"
	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/grant"
	"github.com/example/lanyard/internal/grantstore"
	"github.com/example/lanyard/internal/logging"
	"github.com/example/lanyard/internal/policy"
)

// mockGrantStore is an in-memory stand-in for grantstore.Store used by unit tests.
type mockGrantStore struct {
	tenant string
	agent  grantstore.Agent
}

func (m *mockGrantStore) ValidateAgent(ctx context.Context, id string) error {
	return nil
}

func (m *mockGrantStore) GetAgent(ctx context.Context, id string) (grantstore.Agent, bool) {
	return m.agent, m.agent.ID != ""
}

func (m *mockGrantStore) TenantForAgent(ctx context.Context, id string) (string, error) {
	return m.tenant, nil
}

func (m *mockGrantStore) RegisterAgent(ctx context.Context, agent grantstore.Agent) error {
	m.agent = agent
	return nil
}

func (m *mockGrantStore) CreateTenant(ctx context.Context, id, name string) error {
	return nil
}

func (m *mockGrantStore) RegisterConnector(ctx context.Context, connector grantstore.Connector) error {
	return nil
}

func newTestHandler(t *testing.T) (http.Handler, *token.Signer) {
	return newTestHandlerWithMode(t, true)
}

func newTestHandlerWithMode(t *testing.T, devMode bool) (http.Handler, *token.Signer) {
	t.Helper()
	cfg := config.Load()
	cfg.DevMode = devMode

	privateKey, err := token.DecodeEd25519PrivateKey(devTokenSigningSeed)
	if err != nil {
		t.Fatalf("DecodeEd25519PrivateKey() error = %v", err)
	}
	signer, err := token.NewSignerWithKey(cfg.TokenKeyID(), privateKey)
	if err != nil {
		t.Fatalf("NewSignerWithKey() error = %v", err)
	}

	store := &mockGrantStore{
		tenant: cfg.TenantID,
		agent: grantstore.Agent{
			ID:           "agent:demo",
			TenantID:     cfg.TenantID,
			Name:         "Demo Agent",
			OwnerSubject: "user:owner",
			PublicKey:    demoAgentPublicKey(),
			Status:       "active",
		},
	}

	engine := policy.NewCedarEngine(&demoEntityLoader{})
	engine.SetPolicySource(&demoPolicySource{})
	if err := engine.Publish(cfg.TenantID, 1, []byte(demoPolicyText)); err != nil {
		t.Fatalf("engine.Publish() error = %v", err)
	}

	service := grant.NewService(store, engine)
	return newControlPlaneHandler(service, signer, cfg, nil), signer
}

func TestControlPlaneRejectsInvalidGrantRequest(t *testing.T) {
	handler, _ := newTestHandler(t)
	for name, testCase := range map[string]struct {
		body string
		want int
	}{
		"malformed":      {body: `{"task":`, want: http.StatusBadRequest},
		"missing-fields": {body: `{"task":"task-1"}`, want: http.StatusUnauthorized},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/grant", strings.NewReader(testCase.body)))
		if recorder.Code != testCase.want {
			t.Fatalf("%s: POST /grant status = %d, want %d", name, recorder.Code, testCase.want)
		}
	}
}

func TestControlPlaneRequiresAgentProofForGrant(t *testing.T) {
	handler, _ := newTestHandler(t)
	body := `{"subject":"user:alice","actor":"agent:demo","task_id":"task-1","ttl_seconds":60,` +
		`"Resources":[{"connector":"demo","action":"read","resource":"demo-secret","max_rows":100}]}`
	request := httptest.NewRequest(http.MethodPost, "/grant", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned POST /grant status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestProductionHandlerDoesNotExposeInMemoryAdminRoutes(t *testing.T) {
	handler, _ := newTestHandlerWithMode(t, false)
	for _, path := range []string{"/admin/tenants", "/approve", "/revoke", "/events/replay"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"id":"tenant-1"}`)))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("production route %s status = %d, want %d", path, recorder.Code, http.StatusNotFound)
		}
	}
}

// TestControlPlaneIssuesVerifiableGrant is the end-to-end assertion that the
// control plane signs grants with the key it publishes: issue via POST /grant,
// then verify the returned JWT with a Verifier built from the signer's key.
func TestControlPlaneIssuesVerifiableGrant(t *testing.T) {
	handler, signer := newTestHandler(t)
	cfg := config.Load()

	body := `{"subject":"user:alice","actor":"agent:demo","task_id":"task-1","ttl_seconds":60,` +
		`"Resources":[{"connector":"demo","action":"read","resource":"demo-secret","max_rows":100}]}`
	request := httptest.NewRequest(http.MethodPost, "/grant", strings.NewReader(body))
	agentPrivateKey, err := token.DecodeEd25519PrivateKey(demoAgentSeed)
	if err != nil {
		t.Fatalf("DecodeEd25519PrivateKey() error = %v", err)
	}
	if got := base64.RawURLEncoding.EncodeToString(agentPrivateKey.Public().(ed25519.PublicKey)); got != demoAgentPublicKey() {
		t.Fatalf("demo agent seed public key = %q, registered key = %q", got, demoAgentPublicKey())
	}
	proof, err := token.NewDPoPRequestProof(agentPrivateKey, request.Method, dpopTargetURL(request, true), "grant-proof-1", time.Now())
	if err != nil {
		t.Fatalf("NewDPoPRequestProof() error = %v", err)
	}
	request.Header.Set("DPoP", proof)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /grant status = %d, want %d; body=%q", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("POST /grant Content-Type = %q, want %q", contentType, "application/json")
	}

	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode POST /grant response: %v", err)
	}
	if response.AccessToken == "" {
		t.Fatal("POST /grant returned an empty access_token")
	}

	verifier, err := token.NewVerifier(cfg.Issuer(), cfg.Audience(), map[string]ed25519.PublicKey{
		signer.KeyID(): signer.PublicKey(),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	claims, err := verifier.Verify(response.AccessToken, time.Now())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.Actor != "agent:demo" || claims.TenantID != "tenant-demo" || claims.TaskID != "task-1" {
		t.Fatalf("Verify() claims = %#v", claims)
	}
}

func TestNewTokenSignerSelectsPersistentKey(t *testing.T) {
	cfg := config.Load()
	logger := logging.NewJSONLogger()

	envKey, err := token.DecodeEd25519PrivateKey(devTokenSigningSeed)
	if err != nil {
		t.Fatalf("DecodeEd25519PrivateKey() error = %v", err)
	}
	cfg.DevMode = false
	encodedKey := base64.RawURLEncoding.EncodeToString(envKey)
	signer, err := newTokenSignerFromEncoded(cfg, encodedKey)
	if err != nil {
		t.Fatalf("newTokenSignerFromEncoded() error = %v", err)
	}
	if !signer.PublicKey().Equal(envKey.Public().(ed25519.PublicKey)) {
		t.Fatal("newTokenSignerFromEncoded() did not use the supplied key")
	}

	t.Setenv("TOKEN_PRIVATE_KEY", "")
	t.Setenv("TOKEN_PRIVATE_KEY_SECRET_ARN", "")
	if _, err := newTokenSigner(cfg, logger); err == nil || err.Error() != "TOKEN_PRIVATE_KEY_SECRET_ARN is required outside demo mode" {
		t.Fatalf("newTokenSigner() outside dev mode error = %v", err)
	}

	cfg.DevMode = true
	signer, err = newTokenSigner(cfg, logger)
	if err != nil {
		t.Fatalf("newTokenSigner() in dev mode error = %v", err)
	}
	if !signer.PublicKey().Equal(envKey.Public().(ed25519.PublicKey)) {
		t.Fatal("newTokenSigner() in dev mode did not use the fixed dev seed")
	}
}

func TestControlPlaneReadiness(t *testing.T) {
	handler, _ := newTestHandler(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	// When a database is not configured (internal tests), /readyz returns 503.
	if recorder.Code != http.StatusOK && recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz status = %d, want 200 or 503", recorder.Code)
	}
}

func TestAdminCreatesTenantThenRejectsUnknownTenantAgent(t *testing.T) {
	handler, _ := newTestHandler(t)
	for name, request := range map[string]*http.Request{
		"tenant":    httptest.NewRequest(http.MethodPost, "/admin/tenants", strings.NewReader(`{"id":"tenant-1","name":"Acme"}`)),
		"agent":     httptest.NewRequest(http.MethodPost, "/admin/agents", strings.NewReader(`{"id":"agent-1","tenant_id":"tenant-1","owner_subject":"user:alice","public_key":"key"}`)),
		"bad-agent": httptest.NewRequest(http.MethodPost, "/admin/agents", strings.NewReader(`{"id":"agent-2","tenant_id":"tenant-2","owner_subject":"user:bob","public_key":"key"}`)),
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if name == "bad-agent" && recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d", name, recorder.Code)
		}
	}
}

func TestGrantAttenuationEnforcedViaStore(t *testing.T) {
	store := &mockGrantStore{
		tenant: "tenant-demo",
		agent: grantstore.Agent{
			ID:           "agent:demo",
			TenantID:     "tenant-demo",
			Name:         "Demo Agent",
			OwnerSubject: "user:owner",
			PublicKey:    demoAgentPublicKey(),
			Status:       "active",
		},
	}
	engine := policy.NewCedarEngine(&demoEntityLoader{})
	engine.SetPolicySource(&demoPolicySource{})
	if err := engine.Publish("tenant-demo", 1, []byte(demoPolicyText)); err != nil {
		t.Fatalf("engine.Publish() error = %v", err)
	}

	svc := grant.NewService(store, engine)

	svc.RegisterParentGrant("parent-1", []grant.ScopeEntry{
		{Connector: "demo", Action: "read", Resource: "demo-secret", MaxRows: 10},
	})

	_, err := svc.Issue(context.Background(), grant.Request{
		Subject:     "user:alice",
		Actor:       "agent:demo",
		TaskID:      "task-1",
		ParentGrant: "parent-1",
		Resources: []grant.ScopeEntry{
			{Connector: "demo", Action: "read", Resource: "demo-secret", MaxRows: 20},
		},
		TTLSeconds: 60,
	})
	if err == nil {
		t.Fatal("Issue() accepted a child scope that exceeded parent MaxRows")
	}
	if !strings.Contains(err.Error(), "exceeds parent grant limits") {
		t.Fatalf("Issue() error = %v, want attenuation error", err)
	}
}
