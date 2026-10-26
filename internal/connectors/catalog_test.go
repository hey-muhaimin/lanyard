package connectors

import "testing"

func TestCatalogValidatesRequiredFields(t *testing.T) {
	catalog := NewCatalog()
	if err := catalog.Register(Spec{Name: "github", AuthType: "api_key", AllowedHosts: []string{"api.github.com"}, BaseURL: "https://api.github.com", ParameterSchema: map[string]any{"type": "object"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := catalog.Get("github"); !ok {
		t.Fatal("connector missing")
	}
	if err := catalog.Register(Spec{Name: "broken"}); err == nil {
		t.Fatal("incomplete connector accepted")
	}
}
