package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestSealAndOpenRoundTrip(t *testing.T) {
	ctx := context.Background()
	kms := NewMemoryKMS("local-dev-key")
	store := NewStore(kms)

	plaintext := []byte("top-secret")
	if err := store.Put(ctx, "local-dev-key", "tenant-a", "secret-1", plaintext); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := store.Get(ctx, "secret-1", "tenant-a")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("Get() = %q, want %q", got, plaintext)
	}

	ciphertext, wrappedDEK, err := Seal(ctx, kms, "local-dev-key", "tenant-a", plaintext)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	opened, err := Open(ctx, kms, "local-dev-key", "tenant-a", ciphertext, wrappedDEK)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open() = %q, want %q", opened, plaintext)
	}
}

func TestGetIsNonDestructive(t *testing.T) {
	ctx := context.Background()
	store := NewStore(NewMemoryKMS("local-dev-key"))
	if err := store.Put(ctx, "local-dev-key", "tenant-a", "secret-1", []byte("top-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	first, err := store.Get(ctx, "secret-1", "tenant-a")
	if err != nil {
		t.Fatalf("first Get() error = %v", err)
	}
	second, err := store.Get(ctx, "secret-1", "tenant-a")
	if err != nil {
		t.Fatalf("second Get() error = %v", err)
	}
	if string(first) != "top-secret" || string(second) != "top-secret" {
		t.Fatalf("Get() = %q then %q, want %q twice", first, second, "top-secret")
	}
}

func TestGetRejectsWrongTenant(t *testing.T) {
	ctx := context.Background()
	store := NewStore(NewMemoryKMS("local-dev-key"))
	if err := store.Put(ctx, "local-dev-key", "tenant-a", "secret-1", []byte("top-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	if _, err := store.Get(ctx, "secret-1", "tenant-b"); err == nil {
		t.Fatal("Get() allowed a cross-tenant read")
	}
	if got, err := store.Get(ctx, "secret-1", "tenant-a"); err != nil || string(got) != "top-secret" {
		t.Fatalf("Get() after rejected read = %q, %v, want %q, nil", got, err, "top-secret")
	}
}

func TestGetUnknownSecretFails(t *testing.T) {
	store := NewStore(NewMemoryKMS("local-dev-key"))
	if _, err := store.Get(context.Background(), "missing", "tenant-a"); err == nil {
		t.Fatal("Get() succeeded for an unknown id")
	}
}

func TestPutIsIdempotentPerID(t *testing.T) {
	ctx := context.Background()
	store := NewStore(NewMemoryKMS("local-dev-key"))
	if err := store.Put(ctx, "local-dev-key", "tenant-a", "secret-1", []byte("first")); err != nil {
		t.Fatalf("first Put() error = %v", err)
	}
	if err := store.Put(ctx, "local-dev-key", "tenant-a", "secret-2", []byte("other")); err != nil {
		t.Fatalf("second Put() error = %v", err)
	}
	if err := store.Put(ctx, "local-dev-key", "tenant-a", "secret-1", []byte("second")); err != nil {
		t.Fatalf("overwrite Put() error = %v", err)
	}

	got, err := store.Get(ctx, "secret-1", "tenant-a")
	if err != nil {
		t.Fatalf("Get(secret-1) error = %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("Get(secret-1) = %q, want %q", got, "second")
	}

	other, err := store.Get(ctx, "secret-2", "tenant-a")
	if err != nil {
		t.Fatalf("Get(secret-2) error = %v", err)
	}
	if string(other) != "other" {
		t.Fatalf("Get(secret-2) = %q, want %q", other, "other")
	}
}

func TestOpenRejectsWrongTenant(t *testing.T) {
	ctx := context.Background()
	kms := NewMemoryKMS("local-dev-key")
	ciphertext, wrappedDEK, err := Seal(ctx, kms, "local-dev-key", "tenant-a", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	if _, err := Open(ctx, kms, "local-dev-key", "tenant-b", ciphertext, wrappedDEK); err == nil {
		t.Fatal("Open() succeeded for the wrong tenant")
	}
}

func TestTamperDetectionFails(t *testing.T) {
	ctx := context.Background()
	kms := NewMemoryKMS("local-dev-key")
	ciphertext, wrappedDEK, err := Seal(ctx, kms, "local-dev-key", "tenant-a", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	ciphertext[len(ciphertext)-1] ^= 0xFF
	if _, err := Open(ctx, kms, "local-dev-key", "tenant-a", ciphertext, wrappedDEK); err == nil {
		t.Fatal("Open() succeeded on tampered ciphertext")
	}
}

func TestTamperedWrappedDEKFails(t *testing.T) {
	ctx := context.Background()
	kms := NewMemoryKMS("local-dev-key")
	ciphertext, wrappedDEK, err := Seal(ctx, kms, "local-dev-key", "tenant-a", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	wrappedDEK[len(wrappedDEK)-1] ^= 0xFF
	if _, err := Open(ctx, kms, "local-dev-key", "tenant-a", ciphertext, wrappedDEK); err == nil {
		t.Fatal("Open() succeeded on a tampered wrapped data key")
	}
}

func TestStoreRejectsCiphertextAndWrappedKeySwap(t *testing.T) {
	ctx := context.Background()
	kms := NewMemoryKMS("local-dev-key")
	store := NewStore(kms)

	if err := store.Put(ctx, "local-dev-key", "tenant-a", "secret-a", []byte("alpha")); err != nil {
		t.Fatalf("Put(secret-a) error = %v", err)
	}
	if err := store.Put(ctx, "local-dev-key", "tenant-a", "secret-b", []byte("bravo")); err != nil {
		t.Fatalf("Put(secret-b) error = %v", err)
	}

	a := store.items["secret-a"]
	b := store.items["secret-b"]
	a.Ciphertext, b.Ciphertext = b.Ciphertext, a.Ciphertext
	a.WrappedKey, b.WrappedKey = b.WrappedKey, a.WrappedKey
	store.items["secret-a"] = a
	store.items["secret-b"] = b

	if _, err := store.Get(ctx, "secret-a", "tenant-a"); err == nil {
		t.Fatal("Get(secret-a) succeeded after records were swapped")
	}
}

func TestDecryptRejectsChangedEncryptionContext(t *testing.T) {
	ctx := context.Background()
	kms := NewMemoryKMS("local-dev-key")
	_, wrappedDEK, err := kms.GenerateDataKey(ctx, "local-dev-key", EncryptionContext("tenant-a", "secret"))
	if err != nil {
		t.Fatalf("GenerateDataKey() error = %v", err)
	}

	cases := map[string]map[string]string{
		"other tenant":  EncryptionContext("tenant-b", "secret"),
		"other purpose": EncryptionContext("tenant-a", "other"),
		"empty context": {},
	}
	for name, encryptionContext := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := kms.Decrypt(ctx, "local-dev-key", wrappedDEK, encryptionContext)
			if !errors.Is(err, ErrKMSTenantMismatch) {
				t.Fatalf("Decrypt() error = %v, want %v", err, ErrKMSTenantMismatch)
			}
		})
	}
}

func TestDecryptRejectsUnknownKey(t *testing.T) {
	ctx := context.Background()
	kms := NewMemoryKMS("local-dev-key")
	_, wrappedDEK, err := kms.GenerateDataKey(ctx, "local-dev-key", EncryptionContext("tenant-a", "secret"))
	if err != nil {
		t.Fatalf("GenerateDataKey() error = %v", err)
	}

	_, err = kms.Decrypt(ctx, "other-key", wrappedDEK, EncryptionContext("tenant-a", "secret"))
	if !errors.Is(err, ErrKMSNotFound) {
		t.Fatalf("Decrypt() error = %v, want %v", err, ErrKMSNotFound)
	}

	if _, _, err := kms.GenerateDataKey(ctx, "other-key", EncryptionContext("tenant-a", "secret")); !errors.Is(err, ErrKMSNotFound) {
		t.Fatalf("GenerateDataKey() error = %v, want %v", err, ErrKMSNotFound)
	}
}

func TestMemoryKMSNeverReturnsTheDEKVerbatim(t *testing.T) {
	ctx := context.Background()
	kms := NewMemoryKMS("local-dev-key")
	encryptionContext := EncryptionContext("tenant-a", "secret")

	dek, wrappedDEK, err := kms.GenerateDataKey(ctx, "local-dev-key", encryptionContext)
	if err != nil {
		t.Fatalf("GenerateDataKey() error = %v", err)
	}
	if len(dek) != dekSize {
		t.Fatalf("GenerateDataKey() plaintext DEK length = %d, want %d", len(dek), dekSize)
	}
	if bytes.Equal(dek, wrappedDEK) || bytes.Contains(wrappedDEK, dek) {
		t.Fatal("GenerateDataKey() returned the plaintext DEK inside the wrapped blob")
	}

	opened, err := kms.Decrypt(ctx, "local-dev-key", wrappedDEK, encryptionContext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(opened, dek) {
		t.Fatal("Decrypt() did not recover the generated DEK")
	}

	secondDEK, _, err := kms.GenerateDataKey(ctx, "local-dev-key", encryptionContext)
	if err != nil {
		t.Fatalf("second GenerateDataKey() error = %v", err)
	}
	if bytes.Equal(dek, secondDEK) {
		t.Fatal("GenerateDataKey() reused a DEK")
	}
}

func TestEncryptionContext(t *testing.T) {
	got := EncryptionContext("tenant-a", "secret")
	if got["tenant_id"] != "tenant-a" || got["purpose"] != "secret" || len(got) != 2 {
		t.Fatalf("EncryptionContext() = %#v", got)
	}

	for name, build := range map[string]func(){
		"empty tenant":  func() { EncryptionContext("", "secret") },
		"empty purpose": func() { EncryptionContext("tenant-a", "") },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("EncryptionContext() did not reject empty inputs")
				}
			}()
			build()
		})
	}
}

// shortDEKKMS returns a DEK that is not usable for AES-256 so Seal must reject it.
type shortDEKKMS struct{}

func (shortDEKKMS) GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, error) {
	return make([]byte, 16), []byte("wrapped"), nil
}

func (shortDEKKMS) Decrypt(context.Context, string, []byte, map[string]string) ([]byte, error) {
	return make([]byte, 16), nil
}

func TestSealRejectsUnusableDEK(t *testing.T) {
	if _, _, err := Seal(context.Background(), shortDEKKMS{}, "key", "tenant-a", []byte("secret")); err == nil {
		t.Fatal("Seal() accepted a 16-byte DEK")
	}
}

func TestOpenRejectsCrossWrappedKeyDifferentTenant(t *testing.T) {
	ctx := context.Background()
	kms := NewMemoryKMS("local-dev-key")
	ctA, _, err := Seal(ctx, kms, "local-dev-key", "tenant-a", []byte("secret-a"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	_, wrappedB, err := Seal(ctx, kms, "local-dev-key", "tenant-b", []byte("secret-b"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if _, err := Open(ctx, kms, "local-dev-key", "tenant-a", ctA, wrappedB); !errors.Is(err, ErrKMSTenantMismatch) {
		t.Fatalf("Open() error = %v, want %v", err, ErrKMSTenantMismatch)
	}
}

func TestOpenRejectsWrappedKeyFromDifferentSealSameTenant(t *testing.T) {
	ctx := context.Background()
	kms := NewMemoryKMS("local-dev-key")
	ct1, _, err := Seal(ctx, kms, "local-dev-key", "tenant-a", []byte("secret-1"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	_, wrapped2, err := Seal(ctx, kms, "local-dev-key", "tenant-a", []byte("secret-2"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if _, err := Open(ctx, kms, "local-dev-key", "tenant-a", ct1, wrapped2); err == nil {
		t.Fatal("Open() succeeded with mismatched wrapped key for same tenant")
	}
}

func TestUseOnceIsNonDestructive(t *testing.T) {
	ctx := context.Background()
	store := NewStore(NewMemoryKMS("local-dev-key"))
	if err := store.Put(ctx, "local-dev-key", "tenant-a", "secret-1", []byte("top-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	first, err := store.UseOnce(ctx, "secret-1", "tenant-a")
	if err != nil {
		t.Fatalf("first UseOnce() error = %v", err)
	}
	second, err := store.UseOnce(ctx, "secret-1", "tenant-a")
	if err != nil {
		t.Fatalf("second UseOnce() error = %v", err)
	}
	if string(first) != "top-secret" || string(second) != "top-secret" {
		t.Fatalf("UseOnce() = %q then %q, want %q twice", first, second, "top-secret")
	}
}

func TestGetRejectsUnsupportedVersion(t *testing.T) {
	ctx := context.Background()
	store := NewStore(NewMemoryKMS("local-dev-key"))
	store.mu.Lock()
	store.items["secret-1"] = SecretRecord{
		TenantID:   "tenant-a",
		KMSKeyID:   "local-dev-key",
		Ciphertext: []byte("x"),
		WrappedKey: []byte("y"),
		Version:    2,
	}
	store.mu.Unlock()

	_, err := store.Get(ctx, "secret-1", "tenant-a")
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("Get() error = %v, want %v", err, ErrUnsupportedVersion)
	}
}
