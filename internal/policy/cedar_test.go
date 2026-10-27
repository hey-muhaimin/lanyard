package policy

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
)

const goldenCedarPolicies = `
permit (
  principal is Agent,
  action,
  resource is Resource
) when {
  principal.status == "active" &&
	context.connector == resource.connector &&
  context.rowLimit <= 1000 &&
  context.ttlSeconds <= 600
};

forbid (
  principal is Agent,
  action,
  resource is Resource
) unless {
  context.approval.status == "granted"
};
`

type goldenEntityLoader struct{}

func (goldenEntityLoader) LoadTenantEntities(_ context.Context, tenantID, actor, connector, resource string) (cedar.EntityMap, error) {
	encoded, err := json.Marshal([]map[string]any{{
		"uid":     map[string]string{"type": "Agent", "id": actor},
		"attrs":   map[string]any{"status": "active", "tenantId": tenantID},
		"parents": []any{},
	}, {
		"uid":     map[string]string{"type": "Connector", "id": connector},
		"attrs":   map[string]any{"tenantId": tenantID},
		"parents": []any{},
	}})
	if err != nil {
		return nil, err
	}
	var entities cedar.EntityMap
	if err := json.Unmarshal(encoded, &entities); err != nil {
		return nil, err
	}
	return entities, nil
}

func TestCedarEngineGoldenDecisions(t *testing.T) {
	engine := NewCedarEngine(goldenEntityLoader{})
	if err := engine.Publish("tenant-1", 1, []byte(goldenCedarPolicies)); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	base := Request{TenantID: "tenant-1", Actor: "agent-1", Subject: "user:alice", TaskID: "task-1", Connector: "crm", Action: "read", Resource: "accounts/7", MaxRows: 10, TTLSeconds: 300}

	decision, err := engine.Decide(context.Background(), base)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Effect != "deny" {
		t.Fatalf("unapproved decision = %q, want deny", decision.Effect)
	}

	base.ApprovalID = "approval-1"
	engine.SetApprovalVerifier(alwaysApproved{})
	decision, err = engine.Decide(context.Background(), base)
	if err != nil {
		t.Fatalf("approved Decide() error = %v", err)
	}
	if decision.Effect != "allow" {
		t.Fatalf("approved decision = %q, want allow", decision.Effect)
	}

	base.MaxRows = 1001
	decision, err = engine.Decide(context.Background(), base)
	if err != nil {
		t.Fatalf("row-limit Decide() error = %v", err)
	}
	if decision.Effect != "deny" {
		t.Fatalf("row-limit decision = %q, want deny", decision.Effect)
	}
}

type alwaysApproved struct{}

func (alwaysApproved) IsApproved(context.Context, string, string, string, any) bool { return true }

func TestCedarEngineFailsClosedWithoutPublishedVersion(t *testing.T) {
	engine := NewCedarEngine(goldenEntityLoader{})
	decision, err := engine.Decide(context.Background(), Request{TenantID: "tenant-1"})
	if err == nil || decision.Effect != "deny" {
		t.Fatalf("decision = %#v, error = %v; want deny and error", decision, err)
	}
}

func TestRepositoryPolicyBundleUsesTrustedApprovalContext(t *testing.T) {
	policyText, err := os.ReadFile("../../policies/default.cedar")
	if err != nil {
		t.Fatal(err)
	}
	engine := NewCedarEngine(goldenEntityLoader{})
	if err := engine.Publish("tenant-1", 1, policyText); err != nil {
		t.Fatalf("publish repository policy: %v", err)
	}
	request := Request{TenantID: "tenant-1", Actor: "agent-1", Subject: "user:alice", TaskID: "task-1", Connector: "crm", Action: "read", Resource: "accounts/7", MaxRows: 10, TTLSeconds: 300}
	decision, err := engine.Decide(context.Background(), request)
	if err != nil || decision.Effect != "deny" {
		t.Fatalf("unapproved decision = %#v, %v; want deny", decision, err)
	}
	request.ApprovalID = "approval-1"
	engine.SetApprovalVerifier(alwaysApproved{})
	decision, err = engine.Decide(context.Background(), request)
	if err != nil || decision.Effect != "allow" {
		t.Fatalf("approved decision = %#v, %v; want allow", decision, err)
	}
}
