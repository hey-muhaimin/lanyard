package mcp

import (
	"errors"
	"sync"
)

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type Gateway struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

func NewGateway() *Gateway { return &Gateway{tools: make(map[string]Tool)} }

func (g *Gateway) Register(tool Tool) error {
	if tool.Name == "" || tool.Parameters == nil {
		return errors.New("MCP tool name and parameter schema are required")
	}
	g.mu.Lock()
	g.tools[tool.Name] = tool
	g.mu.Unlock()
	return nil
}

func (g *Gateway) Tool(name string) (Tool, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	tool, ok := g.tools[name]
	return tool, ok
}

func MapToolToGrant(tool Tool) (connector, action, resource string) {
	return tool.Name, "invoke", tool.Name
}
