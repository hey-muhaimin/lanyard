package config

import "testing"

func TestLoadPanicsForEmptyRequiredSettings(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("TENANT_ID", "")
	t.Setenv("VAULT_KEY_ID", "")
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("Load() did not panic when required env vars were empty")
		}
	}()
	Load()
}
