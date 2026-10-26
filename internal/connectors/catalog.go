package connectors

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

type Spec struct {
	Name            string            `json:"name" yaml:"name"`
	AuthType        string            `json:"auth_type" yaml:"auth_type"`
	AllowedHosts    []string          `json:"allowed_hosts" yaml:"allowed_hosts"`
	BaseURL         string            `json:"base_url" yaml:"base_url"`
	ScopeActions    map[string]string `json:"scope_actions" yaml:"scope_actions"`
	ParameterSchema map[string]any    `json:"parameter_schema" yaml:"parameter_schema"`
	ScrubPatterns   []string          `json:"scrub_patterns" yaml:"scrub_patterns"`
}

type Catalog struct {
	mu    sync.RWMutex
	specs map[string]Spec
}

func NewCatalog() *Catalog { return &Catalog{specs: make(map[string]Spec)} }

func (c *Catalog) Register(spec Spec) error {
	if spec.Name == "" || spec.AuthType == "" || len(spec.AllowedHosts) == 0 || spec.BaseURL == "" {
		return errors.New("connector name, auth, allowed hosts, and base URL are required")
	}
	encoded, err := json.Marshal(spec.ParameterSchema)
	if err != nil {
		return err
	}
	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil || len(schema) == 0 {
		return fmt.Errorf("parameter schema must be an object")
	}
	c.mu.Lock()
	c.specs[spec.Name] = spec
	c.mu.Unlock()
	return nil
}

func (c *Catalog) Get(name string) (Spec, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	spec, ok := c.specs[name]
	return spec, ok
}
