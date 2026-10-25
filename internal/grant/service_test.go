package grant

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/example/lanyard/internal/policy"
	"github.com/example/lanyard/internal/registry"
)

func TestIssueGrant(t *testing.T) {
	reg := registry.New()
	if err := reg.CreateTenant("tenant-1", "Acme"); err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}
	if err := reg.RegisterAgent(registry.Agent{
		ID:           "agent-1",
		TenantID:     "tenant-1",
		Name:         "support-bot",
		OwnerSubject: "user:alice",
		PublicKey:    testPublicKey(),
		Status:       "active",
	}); err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	svc := NewService(reg, policy.SimpleEngine{})
	claims, err := svc.Issue(context.Background(), Request{
		Subject:    "user:alice",
		Actor:      "agent-1",
		TaskID:     "task-42",
		Purpose:    "crm-read",
		Resources:  []ScopeEntry{{Connector: "crm", Action: "read", Resource: "accounts/42", MaxRows: 10}},
		TTLSeconds: 300,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if claims.TenantID != "tenant-1" {
		t.Fatalf("Issue() tenant = %q, want %q", claims.TenantID, "tenant-1")
	}
	if claims.Cnf["jkt"] == "" || claims.Cnf["jkt"] == "sha256:agent-1" {
		t.Fatalf("Issue() confirmation thumbprint = %q, want a public-key thumbprint", claims.Cnf["jkt"])
	}
}

func TestIssueRejectsWiderChildScope(t *testing.T) {
	reg := registry.New()
	if err := reg.CreateTenant("tenant-1", "Acme"); err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}
	if err := reg.RegisterAgent(registry.Agent{ID: "agent-1", TenantID: "tenant-1", Name: "support-bot", OwnerSubject: "user:alice", PublicKey: testPublicKey(), Status: "active"}); err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	svc := NewService(reg, policy.SimpleEngine{})
	svc.RegisterParentGrant("parent-1", []ScopeEntry{{Connector: "crm", Action: "read", Resource: "accounts", MaxRows: 10}})

	_, err := svc.Issue(context.Background(), Request{
		Subject:     "user:alice",
		Actor:       "agent-1",
		TaskID:      "task-43",
		Purpose:     "crm-read",
		ParentGrant: "parent-1",
		Resources:   []ScopeEntry{{Connector: "crm", Action: "read", Resource: "accounts/99", MaxRows: 50}},
		TTLSeconds:  300,
	})
	if err == nil {
		t.Fatal("Issue() accepted a child scope that exceeded parent scope")
	}
}

func testPublicKey() string {
	return base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
}
