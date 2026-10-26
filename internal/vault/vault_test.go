package vault

import (
    "context"
    "testing"
)

func TestSealAndOpenRoundTrip(t *testing.T) {
    kms := NewMemoryKMS("local-dev-key")
    store := NewStore(kms)

    plaintext := []byte("top-secret")
    if err := store.Put("local-dev-key", "tenant-a", "secret-1", plaintext); err != nil {
        t.Fatalf("Put() error = %v", err)
    }

    got, err := store.UseOnce(context.Background(), "secret-1", "tenant-a")
    if err != nil {
        t.Fatalf("UseOnce() error = %v", err)
    }
    if string(got) != string(plaintext) {
        t.Fatalf("UseOnce() = %q, want %q", got, plaintext)
    }
}

func TestUseOnceConsumesTheSecret(t *testing.T) {
    kms := NewMemoryKMS("local-dev-key")
    store := NewStore(kms)
    if err := store.Put("local-dev-key", "tenant-a", "secret-1", []byte("top-secret")); err != nil {
        t.Fatalf("Put() error = %v", err)
    }

    if got, err := store.UseOnce(context.Background(), "secret-1", "tenant-a"); err != nil || string(got) != "top-secret" {
        t.Fatalf("UseOnce() = %q, %v, want %q, nil", got, err, "top-secret")
    }
    if _, err := store.UseOnce(context.Background(), "secret-1", "tenant-a"); err == nil {
        t.Fatal("UseOnce() allowed a second fetch of the same secret")
    }
}

func TestSealRejectsWrongTenant(t *testing.T) {
    kms := NewMemoryKMS("local-dev-key")
    ciphertext, _, err := Seal(context.Background(), kms, "local-dev-key", "tenant-a", []byte("secret"))
    if err != nil {
        t.Fatalf("Seal() error = %v", err)
    }

    _, err = Open(ciphertext, []byte("not-the-key"), "tenant-b")
    if err == nil {
        t.Fatal("Open() succeeded with mismatched tenant and key")
    }
}

func TestTamperDetectionFails(t *testing.T) {
    kms := NewMemoryKMS("local-dev-key")
    ciphertext, _, err := Seal(context.Background(), kms, "local-dev-key", "tenant-a", []byte("secret"))
    if err != nil {
        t.Fatalf("Seal() error = %v", err)
    }

    ciphertext[0] ^= 0xFF
    _, err = Open(ciphertext, []byte("local-dev-key"), "tenant-a")
    if err == nil {
        t.Fatal("Open() succeeded on tampered ciphertext")
    }
}
