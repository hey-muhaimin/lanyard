package registry

import (
	"fmt"
	"sync"
)

// Tenant is the top-level identity boundary for Lanyard.
type Tenant struct {
	ID   string
	Name string
}

// Agent is a workload or service account acting under a human subject.
type Agent struct {
	ID           string
	TenantID     string
	Name         string
	OwnerSubject string
	PublicKey    string // Raw-url-base64 Ed25519 public key.
	Status       string
}

// Connector describes a governed upstream integration.
type Connector struct {
	ID           string
	TenantID     string
	Kind         string
	AllowedHosts []string
	Config       map[string]any
}

// Registry stores the control-plane objects needed by the grant service.
type Registry struct {
	mu         sync.RWMutex
	tenants    map[string]Tenant
	agents     map[string]Agent
	connectors map[string]Connector
}

func New() *Registry {
	return &Registry{
		tenants:    map[string]Tenant{},
		agents:     map[string]Agent{},
		connectors: map[string]Connector{},
	}
}

func (r *Registry) CreateTenant(id, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id == "" || name == "" {
		return fmt.Errorf("tenant id and name are required")
	}
	r.tenants[id] = Tenant{ID: id, Name: name}
	return nil
}

func (r *Registry) RegisterAgent(agent Agent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if agent.ID == "" || agent.TenantID == "" {
		return fmt.Errorf("agent id and tenant id are required")
	}
	if _, ok := r.tenants[agent.TenantID]; !ok {
		return fmt.Errorf("unknown tenant %s", agent.TenantID)
	}
	if agent.Status == "" {
		agent.Status = "active"
	}
	r.agents[agent.ID] = agent
	return nil
}

func (r *Registry) GetAgent(id string) (Agent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	agent, ok := r.agents[id]
	return agent, ok
}

func (r *Registry) ValidateAgent(id string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	agent, ok := r.agents[id]
	if !ok {
		return fmt.Errorf("unknown agent %s", id)
	}
	if agent.Status != "active" {
		return fmt.Errorf("agent %s is not active", id)
	}
	return nil
}

func (r *Registry) RegisterConnector(connector Connector) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if connector.ID == "" || connector.TenantID == "" {
		return fmt.Errorf("connector id and tenant id are required")
	}
	if _, ok := r.tenants[connector.TenantID]; !ok {
		return fmt.Errorf("unknown tenant %s", connector.TenantID)
	}
	r.connectors[connector.ID] = connector
	return nil
}

func (r *Registry) TenantForAgent(agentID string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	agent, ok := r.agents[agentID]
	if !ok {
		return "", fmt.Errorf("unknown agent %s", agentID)
	}
	return agent.TenantID, nil
}
