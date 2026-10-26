package mcp

import "testing"

func TestGatewayRegistersToolSchema(t *testing.T) {
	gateway := NewGateway()
	if err := gateway.Register(Tool{Name: "crm.search", Parameters: map[string]any{"type": "object"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := gateway.Tool("crm.search"); !ok {
		t.Fatal("tool missing")
	}
	if err := gateway.Register(Tool{Name: "", Parameters: map[string]any{}}); err == nil {
		t.Fatal("empty tool accepted")
	}
}
