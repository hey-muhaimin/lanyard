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

type testPolicyRepository struct {
	versions map[string]map[int]PolicyVersion
}

func (r *testPolicyRepository) CreatePolicyVersion(_ context.Context, entry PolicyVersion) error {
	if r.versions[entry.TenantID] == nil {
		r.versions[entry.TenantID] = make(map[int]PolicyVersion)
	}
	if _, exists := r.versions[entry.TenantID][entry.Version]; exists {
		return errors.New("policy version already exists")
	}
	r.versions[entry.TenantID][entry.Version] = entry
	return nil
}

func (r *testPolicyRepository) GetPolicyVersion(_ context.Context, tenantID string, version int) (PolicyVersion, error) {
	entry, exists := r.versions[tenantID][version]
	if !exists {
		return PolicyVersion{}, errors.New("policy version not found")
	}
	return entry, nil
}

func (r *testPolicyRepository) SetPolicyVersionState(_ context.Context, tenantID string, version int, state VersionState, changes []SimulationChange, expected VersionState) error {
	entry, exists := r.versions[tenantID][version]
	if !exists || entry.State != expected {
		return errors.New("policy version missing or state transition conflict")
	}
	entry.State = state
	entry.Changes = append([]SimulationChange(nil), changes...)
	r.versions[tenantID][version] = entry
	return nil
}

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

func TestPersistentPolicyLifecycleDoesNotRequireProcessCache(t *testing.T) {
	ctx := context.Background()
	repository := &testPolicyRepository{versions: make(map[string]map[int]PolicyVersion)}
	creator := NewPersistentPolicyLifecycle(nil, nil, nil, nil, repository)
	if err := creator.CreateDraft("tenant-a", 1, []byte(lifecyclePolicy)); err != nil {
		t.Fatal(err)
	}

	engine := NewCedarEngine(testLoader{})
	lifecycle := NewPersistentPolicyLifecycle(engine, testValidator{}, &testSimulator{}, nil, repository)
	if err := lifecycle.Validate(ctx, "tenant-a", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Simulate(ctx, "tenant-a", 1); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.StageContext(ctx, "tenant-a", 1); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Publish(ctx, "tenant-a", 1); err != nil {
		t.Fatal(err)
	}
	if state := repository.versions["tenant-a"][1].State; state != VersionPublished {
		t.Fatalf("persistent policy state = %q, want %q", state, VersionPublished)
	}
}
