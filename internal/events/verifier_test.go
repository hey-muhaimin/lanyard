package events

import "testing"

func TestVerifyChainDetectsTamperingAndDeletion(t *testing.T) {
	first := StoredEvent{Sequence: 1, TenantID: "tenant-1", Payload: map[string]any{"type": "grant.issued"}}
	firstHash, err := NextHash(nil, first.Payload)
	if err != nil {
		t.Fatal(err)
	}
	first.Hash = firstHash
	second := StoredEvent{Sequence: 2, TenantID: "tenant-1", Payload: map[string]any{"type": "call.proxied"}, PrevHash: firstHash}
	secondHash, err := NextHash(firstHash, second.Payload)
	if err != nil {
		t.Fatal(err)
	}
	second.Hash = secondHash

	chain := []StoredEvent{first, second}
	if err := VerifyChain(chain); err != nil {
		t.Fatalf("valid chain: %v", err)
	}
	chain[1].Payload["type"] = "call.blocked"
	if err := VerifyChain(chain); err == nil {
		t.Fatal("tampered payload was accepted")
	}
	deleted := []StoredEvent{first, {
		Sequence: 3, TenantID: "tenant-1", Payload: second.Payload, PrevHash: firstHash, Hash: secondHash,
	}}
	if err := VerifyChain(deleted); err == nil {
		t.Fatal("sequence gap was accepted")
	}
}
