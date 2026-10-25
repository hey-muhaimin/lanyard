package logging

import "testing"

func TestRedactReplacesSecretStrings(t *testing.T) {
    got := Redact("secret=super-secret-value", "super-secret-value")
    if got != "secret=[REDACTED]" {
        t.Fatalf("Redact() = %q, want %q", got, "secret=[REDACTED]")
    }
}
