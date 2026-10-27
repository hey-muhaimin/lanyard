package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type VersionState string

const (
	VersionDraft     VersionState = "draft"
	VersionValidated VersionState = "validated"
	VersionSimulated VersionState = "simulated"
	VersionStaged    VersionState = "staged"
	VersionPublished VersionState = "published"
)

type SimulationChange struct {
	EventID         string `json:"event_id"`
	PreviousEffect  string `json:"previous_effect"`
	CandidateEffect string `json:"candidate_effect"`
}

type PolicyVersion struct {
	TenantID  string             `json:"tenant_id"`
	Version   int                `json:"version"`
	Body      []byte             `json:"-"`
	State     VersionState       `json:"state"`
	Changes   []SimulationChange `json:"changes,omitempty"`
	CreatedAt time.Time          `json:"created_at"`
}

type PolicyValidator interface {
	Validate(context.Context, []byte) error
}

type PolicySimulator interface {
	Simulate(context.Context, string, []byte, time.Time) ([]SimulationChange, error)
}

type PolicyInvalidationPublisher interface {
	Publish(context.Context, string, []byte) error
}

type PolicyVersionRepository interface {
	CreatePolicyVersion(context.Context, PolicyVersion) error
	GetPolicyVersion(context.Context, string, int) (PolicyVersion, error)
	SetPolicyVersionState(context.Context, string, int, VersionState, []SimulationChange, VersionState) error
}

type PolicyLifecycle struct {
	mu         sync.RWMutex
	engine     *CedarEngine
	validator  PolicyValidator
	simulator  PolicySimulator
	publisher  PolicyInvalidationPublisher
	repository PolicyVersionRepository
	versions   map[string]map[int]PolicyVersion
}

func NewPolicyLifecycle(engine *CedarEngine, validator PolicyValidator, simulator PolicySimulator, publisher PolicyInvalidationPublisher) *PolicyLifecycle {
	return &PolicyLifecycle{engine: engine, validator: validator, simulator: simulator, publisher: publisher, versions: make(map[string]map[int]PolicyVersion)}
}

func NewPersistentPolicyLifecycle(engine *CedarEngine, validator PolicyValidator, simulator PolicySimulator, publisher PolicyInvalidationPublisher, repository PolicyVersionRepository) *PolicyLifecycle {
	lifecycle := NewPolicyLifecycle(engine, validator, simulator, publisher)
	lifecycle.repository = repository
	return lifecycle
}

func (l *PolicyLifecycle) CreateDraft(tenantID string, version int, body []byte) error {
	if tenantID == "" || version <= 0 || len(body) == 0 {
		return errors.New("tenant, positive version, and policy body are required")
	}
	if _, err := compilePolicySet(tenantID, version, body); err != nil {
		return err
	}
	entry := PolicyVersion{TenantID: tenantID, Version: version, Body: append([]byte(nil), body...), State: VersionDraft, CreatedAt: time.Now().UTC()}
	if l.repository != nil {
		if err := l.repository.CreatePolicyVersion(context.Background(), entry); err != nil {
			return err
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.versions[tenantID] == nil {
		l.versions[tenantID] = make(map[int]PolicyVersion)
	}
	if _, exists := l.versions[tenantID][version]; exists {
		return fmt.Errorf("policy version %d already exists", version)
	}
	l.versions[tenantID][version] = entry
	return nil
}

func (l *PolicyLifecycle) Validate(ctx context.Context, tenantID string, version int) error {
	entry, err := l.get(ctx, tenantID, version, VersionDraft)
	if err != nil {
		return err
	}
	if l.validator == nil {
		return errors.New("Cedar CLI validator is not configured")
	}
	if err := l.validator.Validate(ctx, entry.Body); err != nil {
		return fmt.Errorf("validate Cedar policy: %w", err)
	}
	return l.setState(ctx, tenantID, version, VersionValidated, nil, VersionDraft)
}

func (l *PolicyLifecycle) Simulate(ctx context.Context, tenantID string, version int) ([]SimulationChange, error) {
	entry, err := l.get(ctx, tenantID, version, VersionValidated)
	if err != nil {
		return nil, err
	}
	if l.simulator == nil {
		return nil, errors.New("policy simulator is not configured")
	}
	changes, err := l.simulator.Simulate(ctx, tenantID, entry.Body, time.Now().Add(-7*24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("simulate Cedar policy: %w", err)
	}
	if l.repository != nil {
		if err := l.repository.SetPolicyVersionState(ctx, tenantID, version, VersionSimulated, changes, VersionValidated); err != nil {
			return nil, err
		}
		return append([]SimulationChange(nil), changes...), nil
	}
	l.mu.Lock()
	entry.State = VersionSimulated
	entry.Changes = append([]SimulationChange(nil), changes...)
	l.versions[tenantID][version] = entry
	l.mu.Unlock()
	return changes, nil
}

func (l *PolicyLifecycle) Stage(tenantID string, version int) error {
	return l.StageContext(context.Background(), tenantID, version)
}

func (l *PolicyLifecycle) StageContext(ctx context.Context, tenantID string, version int) error {
	return l.setState(ctx, tenantID, version, VersionStaged, nil, VersionSimulated)
}

func (l *PolicyLifecycle) Publish(ctx context.Context, tenantID string, version int) error {
	entry, err := l.get(ctx, tenantID, version, VersionStaged)
	if err != nil {
		return err
	}
	if l.engine == nil {
		return errors.New("Cedar engine is not configured")
	}
	if err := l.engine.Publish(tenantID, version, entry.Body); err != nil {
		return err
	}
	if l.publisher != nil {
		payload := []byte(fmt.Sprintf(`{"tenant_id":%q,"version":%d}`, tenantID, version))
		if err := l.publisher.Publish(ctx, "lanyard.policy.invalidate", payload); err != nil {
			l.engine.InvalidateTenant(tenantID)
			return fmt.Errorf("publish policy cache invalidation: %w", err)
		}
	}
	return l.setState(ctx, tenantID, version, VersionPublished, nil, VersionStaged)
}

func (l *PolicyLifecycle) Version(tenantID string, version int) (PolicyVersion, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	entry, ok := l.versions[tenantID][version]
	entry.Body = append([]byte(nil), entry.Body...)
	entry.Changes = append([]SimulationChange(nil), entry.Changes...)
	return entry, ok
}

func (l *PolicyLifecycle) get(ctx context.Context, tenantID string, version int, expected VersionState) (PolicyVersion, error) {
	if l.repository != nil {
		entry, err := l.repository.GetPolicyVersion(ctx, tenantID, version)
		if err != nil {
			return PolicyVersion{}, err
		}
		if entry.State != expected {
			return PolicyVersion{}, fmt.Errorf("policy version state is %q, want %q", entry.State, expected)
		}
		return entry, nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	entry, ok := l.versions[tenantID][version]
	if !ok {
		return PolicyVersion{}, errors.New("policy version not found")
	}
	if entry.State != expected {
		return PolicyVersion{}, fmt.Errorf("policy version state is %q, want %q", entry.State, expected)
	}
	entry.Body = append([]byte(nil), entry.Body...)
	return entry, nil
}

func (l *PolicyLifecycle) setState(ctx context.Context, tenantID string, version int, target VersionState, changes []SimulationChange, expected ...VersionState) error {
	if l.repository != nil {
		if len(expected) != 1 {
			return errors.New("expected policy state is required for persistent lifecycle")
		}
		return l.repository.SetPolicyVersionState(ctx, tenantID, version, target, changes, expected[0])
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.versions[tenantID][version]
	if !ok {
		return errors.New("policy version not found")
	}
	if len(expected) > 0 && entry.State != expected[0] {
		return fmt.Errorf("policy version state is %q, want %q", entry.State, expected[0])
	}
	entry.State = target
	l.versions[tenantID][version] = entry
	return nil
}

// CedarCLIValidator delegates schema validation to the Cedar Rust CLI.
type CedarCLIValidator struct {
	Binary     string
	SchemaPath string
}

func (v CedarCLIValidator) Validate(ctx context.Context, policy []byte) error {
	binary := v.Binary
	if binary == "" {
		binary = "cedar"
	}
	if v.SchemaPath == "" {
		return errors.New("Cedar schema path is required")
	}
	file, err := os.CreateTemp("", "lanyard-policy-*.cedar")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(policy); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, binary, "validate", "--schema", filepath.Clean(v.SchemaPath), "--schema-format", "json", "--policies", name, "--policy-format", "cedar")
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cedar validate: %w: %s", err, output)
	}
	return nil
}
