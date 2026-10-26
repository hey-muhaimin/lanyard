package approvals

import (
	"errors"
	"testing"
	"time"
)

func TestApprovalParameterBinding(t *testing.T) {
	store := NewStore()
	now := time.Now()
	request, err := store.Create(Request{
		ID: "approval-1", TenantID: "tenant-1", TaskID: "task-1", ChainID: "chain-1",
		RequesterID: "agent-1", Action: "payments:approve", Parameters: map[string]any{"amount": 100, "currency": "USD"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.Decide(request.ID, "tenant-1", "approved", map[string]any{"amount": 101, "currency": "USD"}, now); !errors.Is(err, ErrParameterMismatch) {
		t.Fatalf("changed parameters error = %v, want parameter mismatch", err)
	}
	approved, err := store.Decide(request.ID, "tenant-1", "approved", map[string]any{"currency": "USD", "amount": 100}, now)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != "approved" {
		t.Fatalf("status = %q", approved.Status)
	}
}

func TestApprovalExpires(t *testing.T) {
	store := NewStore()
	now := time.Now()
	request, err := store.Create(Request{ID: "approval-2", TenantID: "tenant-1", TaskID: "task-1", Action: "test", Parameters: map[string]any{"x": 1}, ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(request.ID, "tenant-1", "approved", map[string]any{"x": 1}, now.Add(2*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired approval error = %v, want expired", err)
	}
}
