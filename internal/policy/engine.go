package policy

import (
    "context"
    "fmt"
    "strings"
)

// Decision expresses the allow/deny/approval result returned by the policy engine.
type Decision struct {
    Effect    string
    PolicyIDs []string
    Reason    string
}

// Request models the policy decision input for a task-scoped grant.
type Request struct {
    Actor          string
    Subject        string
    TaskID         string
    Action         string
    Resource       string
    MaxRows        int
    ApprovalStatus string
}

// Engine decides whether a request is approved, denied, or requires approval.
type Engine interface {
    Decide(ctx context.Context, req Request) (Decision, error)
}

// SimpleEngine is a deterministic, in-memory engine suited to local development and unit tests.
type SimpleEngine struct{}

func (SimpleEngine) Decide(_ context.Context, req Request) (Decision, error) {
    if req.Actor == "" || req.Subject == "" || req.TaskID == "" {
        return Decision{Effect: "deny", PolicyIDs: []string{"missing-identity"}, Reason: "agent subject and task must be present"}, nil
    }
    if req.Action == "" {
        return Decision{Effect: "deny", PolicyIDs: []string{"missing-action"}, Reason: "action is required"}, nil
    }
    if strings.Contains(req.Resource, "admin") && !strings.HasPrefix(req.Actor, "agent:") {
        return Decision{Effect: "deny", PolicyIDs: []string{"admin-resource-policy"}, Reason: "admin resource requires a registered agent identity"}, nil
    }
    if req.MaxRows > 1000 {
        return Decision{Effect: "deny", PolicyIDs: []string{"row-limit-policy"}, Reason: "requested row count exceeds the configured limit"}, nil
    }
    if req.ApprovalStatus == "pending" {
        return Decision{Effect: "approve", PolicyIDs: []string{"approval-required"}, Reason: "approval is required before execution"}, nil
    }
    return Decision{Effect: "allow", PolicyIDs: []string{"default-allow"}, Reason: fmt.Sprintf("grant request for %s accepted", req.Action)}, nil
}
