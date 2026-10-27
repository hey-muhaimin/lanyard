package auth

import (
	"testing"
	"time"
)

func TestSessionValidation(t *testing.T) {
	store := NewStore()
	now := time.Now()
	store.Create(Session{ID: "s1", TenantID: "t1", Subject: "u1", Roles: []string{"admin"}, ExpiresAt: now.Add(time.Hour)})

	if _, err := store.Validate("missing", now); err == nil {
		t.Fatal("expected error for missing session")
	}
	if _, err := store.Validate("s1", now); err != nil {
		t.Fatal(err)
	}
	store.Revoke("s1")
	if _, err := store.Validate("s1", now); err == nil {
		t.Fatal("expected error for revoked session")
	}
	store.Create(Session{ID: "s2", TenantID: "t2", Subject: "u2", Roles: []string{"admin"}, ExpiresAt: now.Add(time.Minute)})
	if _, err := store.Validate("s2", now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected error for expired session")
	}
}
