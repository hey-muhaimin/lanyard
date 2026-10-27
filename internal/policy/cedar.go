package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	cedar "github.com/cedar-policy/cedar-go"
)

var ErrNoPublishedPolicy = errors.New("no published Cedar policy set")

type TenantEntityLoader interface {
	LoadTenantEntities(context.Context, string, string, string, string) (cedar.EntityMap, error)
}

type ApprovalVerifier interface {
	IsApproved(context.Context, string, string, string, any) bool
}

type compiledPolicy struct {
	version int
	set     *cedar.PolicySet
}

type CedarEngine struct {
	loader    TenantEntityLoader
	policies  PublishedPolicySource
	approvals ApprovalVerifier
	mu        sync.RWMutex
	active    map[string]int
	sets      map[string]map[int]*cedar.PolicySet
}

func NewCedarEngine(loader TenantEntityLoader) *CedarEngine {
	return &CedarEngine{loader: loader, active: make(map[string]int), sets: make(map[string]map[int]*cedar.PolicySet)}
}

func (e *CedarEngine) SetApprovalVerifier(verifier ApprovalVerifier) {
	e.mu.Lock()
	e.approvals = verifier
	e.mu.Unlock()
}

func (e *CedarEngine) SetPolicySource(source PublishedPolicySource) {
	e.mu.Lock()
	e.policies = source
	e.mu.Unlock()
}

func (e *CedarEngine) Publish(tenantID string, version int, policyText []byte) error {
	if tenantID == "" || version <= 0 {
		return errors.New("tenant ID and positive policy version are required")
	}
	set, err := compilePolicySet(tenantID, version, policyText)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sets[tenantID] == nil {
		e.sets[tenantID] = make(map[int]*cedar.PolicySet)
	}
	e.sets[tenantID][version] = set
	e.active[tenantID] = version
	return nil
}

func compilePolicySet(tenantID string, version int, policyText []byte) (*cedar.PolicySet, error) {
	set, err := cedar.NewPolicySetFromBytes(fmt.Sprintf("tenant-%s-v%d.cedar", tenantID, version), policyText)
	if err != nil {
		return nil, fmt.Errorf("parse Cedar policy set: %w", err)
	}
	return set, nil
}

func (e *CedarEngine) InvalidateTenant(tenantID string) {
	e.mu.Lock()
	delete(e.active, tenantID)
	delete(e.sets, tenantID)
	e.mu.Unlock()
}

func (e *CedarEngine) ActiveVersion(tenantID string) (int, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	version, ok := e.active[tenantID]
	return version, ok
}

func (e *CedarEngine) Decide(ctx context.Context, req Request) (Decision, error) {
	deny := Decision{Effect: "deny", PolicyIDs: []string{"cedar-deny-default"}, Reason: "Cedar denied the request"}
	e.mu.RLock()
	version, active := e.active[req.TenantID]
	var set *cedar.PolicySet
	if active {
		set = e.sets[req.TenantID][version]
	}
	e.mu.RUnlock()
	if !active || set == nil {
		e.mu.RLock()
		source := e.policies
		e.mu.RUnlock()
		if source == nil {
			return deny, ErrNoPublishedPolicy
		}
		published, err := source.LoadPublishedPolicy(ctx, req.TenantID)
		if err != nil {
			return deny, fmt.Errorf("load active Cedar policy: %w", err)
		}
		set, err = compilePolicySet(req.TenantID, published.Version, published.Body)
		if err != nil {
			return deny, fmt.Errorf("compile loaded Cedar policy: %w", err)
		}
		e.mu.Lock()
		if e.sets[req.TenantID] == nil {
			e.sets[req.TenantID] = make(map[int]*cedar.PolicySet)
		}
		e.sets[req.TenantID][published.Version] = set
		e.active[req.TenantID] = published.Version
		e.mu.Unlock()
	}
	return e.decideAgainst(ctx, set, req)
}

func (e *CedarEngine) decideAgainst(ctx context.Context, set *cedar.PolicySet, req Request) (Decision, error) {
	deny := Decision{Effect: "deny", PolicyIDs: []string{"cedar-deny-default"}, Reason: "Cedar denied the request"}
	if req.TenantID == "" || req.Actor == "" || req.Connector == "" || req.Action == "" || req.Resource == "" || req.Subject == "" || req.TaskID == "" {
		deny.Reason = "tenant, agent, action, resource, subject, and task are required"
		return deny, nil
	}
	if e.loader == nil {
		return deny, errors.New("tenant entity loader is not configured")
	}
	entities, err := e.loader.LoadTenantEntities(ctx, req.TenantID, req.Actor, req.Connector, req.Resource)
	if err != nil {
		return deny, fmt.Errorf("load Cedar entities in tenant context: %w", err)
	}
	if entities == nil {
		entities = cedar.EntityMap{}
	}
	if err := addRequestEntities(entities, req); err != nil {
		return deny, err
	}
	actionID := req.Connector + ":" + req.Action
	approvalStatus := "pending"
	e.mu.RLock()
	approvalVerifier := e.approvals
	e.mu.RUnlock()
	if approvalVerifier != nil && req.ApprovalID != "" && approvalVerifier.IsApproved(ctx, req.TenantID, req.ApprovalID, actionID, req.ApprovalParams) {
		approvalStatus = "granted"
	}
	contextRecord := cedar.NewRecord(cedar.RecordMap{
		"rowLimit":   cedar.Long(req.MaxRows),
		"ttlSeconds": cedar.Long(req.TTLSeconds),
		"subject":    cedar.String(req.Subject),
		"taskId":     cedar.String(req.TaskID),
		"tenantId":   cedar.String(req.TenantID),
		"connector":  cedar.String(req.Connector),
		"approval": cedar.NewRecord(cedar.RecordMap{
			"status": cedar.String(approvalStatus),
		}),
	})
	cedarRequest := cedar.Request{
		Principal: cedar.NewEntityUID("Agent", cedar.String(req.Actor)),
		Action:    cedar.NewEntityUID("Action", cedar.String(actionID)),
		Resource:  cedar.NewEntityUID("Resource", cedar.String(req.Connector+"/"+req.Resource)),
		Context:   contextRecord,
	}
	decision, diagnostic := cedar.Authorize(set, entities, cedarRequest)
	if len(diagnostic.Errors) > 0 {
		return deny, fmt.Errorf("Cedar evaluation failed: %s", diagnostic.Errors[0].String())
	}
	if decision != cedar.Allow {
		if len(diagnostic.Reasons) > 0 {
			deny.PolicyIDs = []string{string(diagnostic.Reasons[0].PolicyID)}
		}
		return deny, nil
	}
	policyIDs := make([]string, 0, len(diagnostic.Reasons))
	for _, reason := range diagnostic.Reasons {
		policyIDs = append(policyIDs, string(reason.PolicyID))
	}
	return Decision{Effect: "allow", PolicyIDs: policyIDs, Reason: "Cedar permit policy matched"}, nil
}

func addRequestEntities(entities cedar.EntityMap, req Request) error {
	actionID := req.Connector + ":" + req.Action
	resourceID := req.Connector + "/" + req.Resource
	data, err := json.Marshal([]map[string]any{
		{"uid": map[string]string{"type": "Action", "id": actionID}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": resourceID}, "attrs": map[string]any{"connector": req.Connector, "path": req.Resource}, "parents": []any{}},
	})
	if err != nil {
		return err
	}
	var requestEntities cedar.EntityMap
	if err := json.Unmarshal(data, &requestEntities); err != nil {
		return fmt.Errorf("construct Cedar request entities: %w", err)
	}
	for uid, entity := range requestEntities {
		entities[uid] = entity
	}
	return nil
}
