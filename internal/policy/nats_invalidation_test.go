package policy

import (
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
)

func TestNATSInvalidationEvictsOnlyNamedTenant(t *testing.T) {
	engine := NewCedarEngine(testLoader{})
	if err := engine.Publish("tenant-a", 1, []byte("permit (principal, action, resource);")); err != nil {
		t.Fatal(err)
	}
	if err := engine.Publish("tenant-b", 1, []byte("permit (principal, action, resource);")); err != nil {
		t.Fatal(err)
	}
	invalidator := NATSInvalidator{Engine: engine}
	invalidator.Handle([]byte(`{"tenant_id":"tenant-a","version":2}`))
	if _, ok := engine.ActiveVersion("tenant-a"); ok {
		t.Fatal("tenant-a cache was not invalidated")
	}
	if version, ok := engine.ActiveVersion("tenant-b"); !ok || version != 1 {
		t.Fatalf("tenant-b cache changed: version=%d active=%v", version, ok)
	}
	_ = cedar.EntityMap{}
}
