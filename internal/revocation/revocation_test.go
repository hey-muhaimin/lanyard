package revocation

import (
	"testing"
	"time"
)

func TestDeniedMatchesEveryScopeAndExpires(t *testing.T) {
	store := NewStore()
	now := time.Now()
	if err := store.Revoke(Scope{ChainID: "chain-1"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !store.Denied(Scope{AgentID: "agent-1", ChainID: "chain-1"}, now) {
		t.Fatal("active chain revocation did not match")
	}
	if store.Denied(Scope{ChainID: "chain-1"}, now.Add(2*time.Minute)) {
		t.Fatal("expired chain revocation remained active")
	}
}

func TestRevokeRequiresScope(t *testing.T) {
	if err := NewStore().Revoke(Scope{}, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("revoke accepted an empty scope")
	}
}
