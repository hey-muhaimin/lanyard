package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
)

const lifecyclePolicy = `permit (principal, action, resource);`

type testValidator struct{ err error }

func (v testValidator) Validate(context.Context, []byte) error { return v.err }

type testSimulator struct {
	since   time.Time
	changes []SimulationChange
	err     error
}

func (s *testSimulator) Simulate(_ context.Context, _ string, _ []byte, since time.Time) ([]SimulationChange, error) {
	s.since = since
	return s.changes, s.err
}

type testLoader struct{}

func (testLoader) LoadTenantEntities(context.Context, string, string, string, string) (cedar.EntityMap, error) {
	return cedar.EntityMap{}, nil
}

type testPublisher struct{ err error }

func (p testPublisher) Publish(context.Context, string, []byte) error { return p.err }

func TestPolicyLifecycleRequiresValidationAndSimulationBeforePublish(t *testing.T) {
	engine := NewCedarEngine(testLoader{})
	simulator := &testSimulator{changes: []SimulationChange{{EventID: "e1", PreviousEffect: "allow", CandidateEffect: "deny"}}}
	lifecycle := NewPolicyLifecycle(engine, testValidator{}, simulator, nil)
	if err := lifecycle.CreateDraft("tenant-a", 1, []byte(lifecyclePolicy)); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Stage("tenant-a", 1); err == nil {
		t.Fatal("staged unvalidated policy")
	}
	if err := lifecycle.Validate(context.Background(), "tenant-a", 1); err != nil {
		t.Fatal(err)
	}
	changes, err := lifecycle.Simulate(context.Background(), "tenant-a", 1)
	if err != nil || len(changes) != 1 {
		t.Fatalf("simulate = %v, %v", changes, err)
	}
	if time.Since(simulator.since) < 7*24*time.Hour-time.Minute {
		t.Fatalf("simulation window start = %v", simulator.since)
	}
	if err := lifecycle.Stage("tenant-a", 1); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Publish(context.Background(), "tenant-a", 1); err != nil {
		t.Fatal(err)
	}
	if version, ok := engine.ActiveVersion("tenant-a"); !ok || version != 1 {
		t.Fatalf("active version = %d, %v", version, ok)
	}
}

func TestPolicyLifecycleFailsClosedOnValidationOrInvalidationError(t *testing.T) {
	ctx := context.Background()
	engine := NewCedarEngine(testLoader{})
	lifecycle := NewPolicyLifecycle(engine, testValidator{err: errors.New("schema error")}, &testSimulator{}, nil)
	if err := lifecycle.CreateDraft("tenant-a", 1, []byte(lifecyclePolicy)); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Validate(ctx, "tenant-a", 1); err == nil {
		t.Fatal("invalid policy validated")
	}
	if _, ok := engine.ActiveVersion("tenant-a"); ok {
		t.Fatal("invalid policy became active")
	}

	lifecycle = NewPolicyLifecycle(engine, testValidator{}, &testSimulator{}, testPublisher{err: errors.New("NATS unavailable")})
	if err := lifecycle.CreateDraft("tenant-a", 2, []byte(lifecyclePolicy)); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Validate(ctx, "tenant-a", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Simulate(ctx, "tenant-a", 2); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Stage("tenant-a", 2); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Publish(ctx, "tenant-a", 2); err == nil {
		t.Fatal("publish succeeded without invalidation")
	}
	if _, ok := engine.ActiveVersion("tenant-a"); ok {
		t.Fatal("cache remained active after invalidation failure")
	}
}
