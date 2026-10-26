package github

import (
	"os"
	"strings"
	"testing"
)

func TestGitHubSpecIsComplete(t *testing.T) {
	data, err := os.ReadFile("spec.yaml")
	if err != nil { t.Fatal(err) }
	for _, required := range []string{"name: github", "auth_type: api_key", "api.github.com", "parameter_schema:"} {
		if !strings.Contains(string(data), required) { t.Fatalf("spec missing %q", required) }
	}
}
