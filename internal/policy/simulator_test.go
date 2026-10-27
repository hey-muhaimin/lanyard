package policy

import (
	"context"
	"testing"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
)

const stricterSimulationPolicy = `
permit (principal is Agent, action, resource is Resource) when {
  principal.status == "active" && context.rowLimit <= 0 && context.approval.status == "granted"
};
forbid (principal, action, resource) unless { context.approval.status == "granted" };
`

type historicalSourceStub struct {
	records []HistoricalDecision
	since   time.Time
}

func (s *historicalSourceStub) LoadDecisions(_ context.Context, _ string, since time.Time) ([]HistoricalDecision, error) {
	s.since = since
	return s.records, nil
}

func TestCedarPolicySimulatorReportsChangedEffect(t *testing.T) {
	engine := NewCedarEngine(goldenEntityLoader{})
	engine.SetApprovalVerifier(alwaysApproved{})
	source := &historicalSourceStub{records: []HistoricalDecision{{EventID: "42", TenantID: "tenant-1", Effect: "allow", Request: Request{TenantID: "tenant-1", Actor: "agent-1", Subject: "user:alice", TaskID: "task-1", Connector: "crm", Action: "read", Resource: "accounts/7", MaxRows: 10, TTLSeconds: 300, ApprovalID: "approval-1"}}}}
	simulator := CedarPolicySimulator{Engine: engine, Source: source}
	changes, err := simulator.Simulate(context.Background(), "tenant-1", []byte(stricterSimulationPolicy), time.Now().Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].EventID != "42" || changes[0].PreviousEffect != "allow" || changes[0].CandidateEffect != "deny" {
		t.Fatalf("simulation changes = %#v", changes)
	}
}

func TestCedarPolicySimulatorRejectsCrossTenantEvent(t *testing.T) {
	source := &historicalSourceStub{records: []HistoricalDecision{{EventID: "foreign", TenantID: "tenant-b", Request: Request{TenantID: "tenant-b"}}}}
	simulator := CedarPolicySimulator{Engine: NewCedarEngine(goldenEntityLoader{}), Source: source}
	if _, err := simulator.Simulate(context.Background(), "tenant-a", []byte(goldenCedarPolicies), time.Now().Add(-7*24*time.Hour)); err == nil {
		t.Fatal("simulator accepted a cross-tenant historical event")
	}
	_ = cedar.Allow
}
