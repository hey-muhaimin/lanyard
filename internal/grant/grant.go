package grant

import (
	"fmt"
	"strings"
)

// ScopeEntry identifies a connector, action, and resource in a task-scoped grant.
type ScopeEntry struct {
	Connector string `json:"connector"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	MaxRows   int    `json:"max_rows"`
}

// Claims represent the signed grant data for a task-scoped credential.
type Claims struct {
	TenantID  string            `json:"tid"`
	Actor     string            `json:"act"`
	TaskID    string            `json:"tsk"`
	Scope     []ScopeEntry      `json:"scp"`
	PolicyVer int               `json:"pv"`
	Cnf       map[string]string `json:"cnf"`
}

// Request captures the data required to create a task-scoped grant.
type Request struct {
	Subject        string       `json:"subject"`
	Actor          string       `json:"actor"`
	TaskID         string       `json:"task_id"`
	Purpose        string       `json:"purpose,omitempty"`
	Resources      []ScopeEntry `json:"resources"`
	TTLSeconds     int          `json:"ttl_seconds"`
	ParentGrant    string       `json:"parent_grant,omitempty"`
	ApprovalID     string       `json:"approval_id,omitempty"`
	ApprovalParams any          `json:"approval_params,omitempty"`
}

func (r Request) Validate() error {
	if r.Subject == "" || r.Actor == "" || r.TaskID == "" {
		return fmt.Errorf("subject, actor, and task ID are required")
	}
	if r.TTLSeconds <= 0 {
		return fmt.Errorf("TTL must be greater than zero")
	}
	if len(r.Resources) == 0 {
		return fmt.Errorf("at least one resource scope is required")
	}
	for _, resource := range r.Resources {
		if resource.Connector == "" || resource.Action == "" || strings.Trim(resource.Resource, "/") == "" {
			return fmt.Errorf("resource scope connector, action, and resource are required")
		}
		if resource.MaxRows < 0 {
			return fmt.Errorf("resource scope max rows cannot be negative")
		}
	}
	return nil
}
