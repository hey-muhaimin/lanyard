package grant

import (
	"context"
	"fmt"
	"strings"

	token "github.com/example/lanyard/internal"
	"github.com/example/lanyard/internal/policy"
	"github.com/example/lanyard/internal/registry"
)

// Service turns a valid request into a task-scoped grant with policy evaluation.
type Service struct {
	registry     *registry.Registry
	policyEngine policy.Engine
	parentGrants map[string][]ScopeEntry
}

func NewService(r *registry.Registry, engine policy.Engine) *Service {
	return &Service{
		registry:     r,
		policyEngine: engine,
		parentGrants: map[string][]ScopeEntry{},
	}
}

func (s *Service) RegisterParentGrant(grantID string, scope []ScopeEntry) {
	s.parentGrants[grantID] = append([]ScopeEntry(nil), scope...)
}

func (s *Service) Issue(ctx context.Context, req Request) (Claims, error) {
	if err := req.Validate(); err != nil {
		return Claims{}, err
	}
	if err := s.registry.ValidateAgent(req.Actor); err != nil {
		return Claims{}, err
	}

	agent, ok := s.registry.GetAgent(req.Actor)
	if !ok {
		return Claims{}, fmt.Errorf("unknown agent %s", req.Actor)
	}
	thumbprint, err := token.PublicKeyThumbprintFromBase64(agent.PublicKey)
	if err != nil {
		return Claims{}, fmt.Errorf("agent %s has an invalid public key: %w", req.Actor, err)
	}

	tenantID, err := s.registry.TenantForAgent(req.Actor)
	if err != nil {
		return Claims{}, err
	}

	if req.ParentGrant != "" {
		if err := s.validateAttenuation(req.ParentGrant, req.Resources); err != nil {
			return Claims{}, err
		}
	}

	approvalStatus := req.ApprovalStatus
	if approvalStatus == "" {
		approvalStatus = "approved"
	}
	for _, scope := range req.Resources {
		decision, err := s.policyEngine.Decide(ctx, policy.Request{
			Actor:          req.Actor,
			Subject:        req.Subject,
			TaskID:         req.TaskID,
			Action:         scope.Action,
			Resource:       scope.Resource,
			MaxRows:        scope.MaxRows,
			ApprovalStatus: approvalStatus,
		})
		if err != nil {
			return Claims{}, fmt.Errorf("evaluate policy for %s:%s: %w", scope.Connector, scope.Resource, err)
		}
		switch decision.Effect {
		case "allow":
		case "approve":
			return Claims{}, fmt.Errorf("grant requires approval: %s", decision.Reason)
		case "deny":
			return Claims{}, fmt.Errorf("grant denied: %s", decision.Reason)
		default:
			return Claims{}, fmt.Errorf("policy returned unsupported effect %q", decision.Effect)
		}
	}

	return Claims{
		TenantID:  tenantID,
		Actor:     req.Actor,
		TaskID:    req.TaskID,
		Scope:     append([]ScopeEntry(nil), req.Resources...),
		PolicyVer: 1,
		Cnf: map[string]string{
			"jkt": thumbprint,
		},
	}, nil
}

func (s *Service) validateAttenuation(parentGrantID string, requested []ScopeEntry) error {
	parentScope, ok := s.parentGrants[parentGrantID]
	if !ok {
		return fmt.Errorf("unknown parent grant %s", parentGrantID)
	}
	for _, item := range requested {
		matchedResource := false
		matchedLimits := false
		for _, parentItem := range parentScope {
			if parentItem.Connector != item.Connector || parentItem.Action != item.Action {
				continue
			}
			if !resourceWithin(parentItem.Resource, item.Resource) {
				continue
			}
			matchedResource = true
			if item.MaxRows <= parentItem.MaxRows {
				matchedLimits = true
				break
			}
		}
		if !matchedResource {
			return fmt.Errorf("requested scope %s:%s exceeds parent grant", item.Connector, item.Action)
		}
		if !matchedLimits {
			return fmt.Errorf("requested scope %s:%s exceeds parent grant limits", item.Connector, item.Action)
		}
	}
	return nil
}

func resourceWithin(parent, requested string) bool {
	parent = strings.TrimSuffix(parent, "/")
	requested = strings.TrimSuffix(requested, "/")
	return parent != "" && requested != "" &&
		(requested == parent || strings.HasPrefix(requested, parent+"/"))
}
