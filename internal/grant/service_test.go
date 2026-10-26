package grant

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/example/lanyard/internal/policy"
	"github.com/example/lanyard/internal/registry"
)

func TestIssueGrant(t *testing.T) {
	reg := registry.New()
	if err := reg.CreateTenant("tenant-1", "Acme"); err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}
	if err := reg.RegisterAgent(registry.Agent{
		ID:           "agent-1",
		TenantID:     "tenant-1",
		Name:         "support-bot",
		OwnerSubject: "user:alice",
		PublicKey:    testPublicKey(),
		Status:       "active",
	}); err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	svc := NewService(reg, policy.SimpleEngine{})
	claims, err := svc.Issue(context.Background(), Request{
		Subject:    "user:alice",
		Actor:      "agent-1",
		TaskID:     "task-42",
		Purpose:    "crm-read",
		Resources:  []ScopeEntry{{Connector: "crm", Action: "read", Resource: "accounts/42", MaxRows: 10}},
		TTLSeconds: 300,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if claims.TenantID != "tenant-1" {
		t.Fatalf("Issue() tenant = %q, want %q", claims.TenantID, "tenant-1")
	}
	if claims.Cnf["jkt"] == "" || claims.Cnf["jkt"] == "sha256:agent-1" {
		t.Fatalf("Issue() confirmation thumbprint = %q, want a public-key thumbprint", claims.Cnf["jkt"])
	}
}

func TestIssueRejectsWiderChildScope(t *testing.T) {
	reg := registry.New()
	if err := reg.CreateTenant("tenant-1", "Acme"); err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}
	if err := reg.RegisterAgent(registry.Agent{ID: "agent-1", TenantID: "tenant-1", Name: "support-bot", OwnerSubject: "user:alice", PublicKey: testPublicKey(), Status: "active"}); err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	svc := NewService(reg, policy.SimpleEngine{})
	svc.RegisterParentGrant("parent-1", []ScopeEntry{{Connector: "crm", Action: "read", Resource: "accounts", MaxRows: 10}})

	_, err := svc.Issue(context.Background(), Request{
		Subject:     "user:alice",
		Actor:       "agent-1",
		TaskID:      "task-43",
		Purpose:     "crm-read",
		ParentGrant: "parent-1",
		Resources:   []ScopeEntry{{Connector: "crm", Action: "read", Resource: "accounts/99", MaxRows: 50}},
		TTLSeconds:  300,
	})
	if err == nil {
		t.Fatal("Issue() accepted a child scope that exceeded parent scope")
	}
}

func TestIssueParentScopeRequiresSegmentBoundedAttenuation(t *testing.T) {
	tests := []struct {
		name      string
		parent    string
		requested string
		wantErr   bool
	}{
		{name: "child resource allowed", parent: "accounts", requested: "accounts/42"},
		{name: "exact resource allowed", parent: "accounts/42", requested: "accounts/42"},
		{name: "parent resource cannot be broadened", parent: "accounts/42", requested: "accounts", wantErr: true},
		{name: "sibling prefix is rejected", parent: "accounts/4", requested: "accounts/42", wantErr: true},
		{name: "sibling path is rejected", parent: "accounts/42", requested: "accounts/43", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			svc := newTestService(t, policy.SimpleEngine{})
			svc.RegisterParentGrant("parent-1", []ScopeEntry{{
				Connector: "crm",
				Action:    "read",
				Resource:  test.parent,
				MaxRows:   20,
			}})
			_, err := svc.Issue(context.Background(), Request{
				Subject:     "user:alice",
				Actor:       "agent-1",
				TaskID:      "task-44",
				ParentGrant: "parent-1",
				Resources: []ScopeEntry{{
					Connector: "crm",
					Action:    "read",
					Resource:  test.requested,
					MaxRows:   10,
				}},
				TTLSeconds: 300,
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("Issue() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestIssueEvaluatesEveryScopeAndOnlyAllowsAllowDecision(t *testing.T) {
	tests := []struct {
		name      string
		decisions map[string]policy.Decision
		wantErr   string
	}{
		{
			name: "denies a later resource",
			decisions: map[string]policy.Decision{
				"accounts/42": {Effect: "allow"},
				"accounts/43": {Effect: "deny", Reason: "not permitted"},
			},
			wantErr: "grant denied: not permitted",
		},
		{
			name: "does not issue approval-pending grant",
			decisions: map[string]policy.Decision{
				"accounts/42": {Effect: "allow"},
				"accounts/43": {Effect: "approve", Reason: "human review required"},
			},
			wantErr: "grant requires approval: human review required",
		},
		{
			name: "rejects unknown effect",
			decisions: map[string]policy.Decision{
				"accounts/42": {Effect: "allow"},
				"accounts/43": {Effect: "unexpected"},
			},
			wantErr: `policy returned unsupported effect "unexpected"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := decisionEngine(func(_ context.Context, req policy.Request) (policy.Decision, error) {
				return test.decisions[req.Resource], nil
			})
			svc := newTestService(t, engine)
			_, err := svc.Issue(context.Background(), Request{
				Subject: "user:alice",
				Actor:   "agent-1",
				TaskID:  "task-45",
				Resources: []ScopeEntry{
					{Connector: "crm", Action: "read", Resource: "accounts/42", MaxRows: 10},
					{Connector: "crm", Action: "read", Resource: "accounts/43", MaxRows: 15},
				},
				TTLSeconds: 300,
			})
			if err == nil || err.Error() != test.wantErr {
				t.Fatalf("Issue() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestIssuePassesEachScopeLimitsToPolicy(t *testing.T) {
	calls := 0
	engine := decisionEngine(func(_ context.Context, req policy.Request) (policy.Decision, error) {
		calls++
		if req.Action != "read" || req.MaxRows != calls*10 || req.Resource != fmt.Sprintf("accounts/%d", calls) {
			t.Errorf("policy request %d = %#v", calls, req)
		}
		return policy.Decision{Effect: "allow"}, nil
	})
	svc := newTestService(t, engine)
	_, err := svc.Issue(context.Background(), Request{
		Subject: "user:alice",
		Actor:   "agent-1",
		TaskID:  "task-46",
		Resources: []ScopeEntry{
			{Connector: "crm", Action: "read", Resource: "accounts/1", MaxRows: 10},
			{Connector: "crm", Action: "read", Resource: "accounts/2", MaxRows: 20},
		},
		TTLSeconds: 300,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("policy calls = %d, want 2", calls)
	}
}

func TestRequestValidateRequiresWellFormedScope(t *testing.T) {
	base := Request{Subject: "user:alice", Actor: "agent-1", TaskID: "task-47", TTLSeconds: 300}
	tests := []struct {
		name      string
		resources []ScopeEntry
		wantErr   bool
	}{
		{name: "missing scope", wantErr: true},
		{name: "missing connector", resources: []ScopeEntry{{Action: "read", Resource: "accounts"}}, wantErr: true},
		{name: "empty resource", resources: []ScopeEntry{{Connector: "crm", Action: "read"}}, wantErr: true},
		{name: "negative row limit", resources: []ScopeEntry{{Connector: "crm", Action: "read", Resource: "accounts", MaxRows: -1}}, wantErr: true},
		{name: "valid scope", resources: []ScopeEntry{{Connector: "crm", Action: "read", Resource: "accounts"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			request.Resources = test.resources
			err := request.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func testPublicKey() string {
	return base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
}

type decisionEngine func(context.Context, policy.Request) (policy.Decision, error)

func (engine decisionEngine) Decide(ctx context.Context, req policy.Request) (policy.Decision, error) {
	return engine(ctx, req)
}

func newTestService(t *testing.T, engine policy.Engine) *Service {
	t.Helper()
	reg := registry.New()
	if err := reg.CreateTenant("tenant-1", "Acme"); err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}
	if err := reg.RegisterAgent(registry.Agent{
		ID: "agent-1", TenantID: "tenant-1", Name: "support-bot",
		OwnerSubject: "user:alice", PublicKey: testPublicKey(),
	}); err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}
	return NewService(reg, engine)
}
