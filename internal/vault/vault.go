package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

const (
	// dekSize is the AES-256 data key length requested from the KMS.
	dekSize = 32
	// secretVersion is the on-record format version written by Store.Put.
	secretVersion = 1
	// purposeSecret is the encryption-context purpose for service secrets.
	purposeSecret = "secret"
)

// Sentinel errors returned by KMS implementations. Callers may test them with
// errors.Is; implementations must wrap them with %w and may add detail.
var (
	ErrKMSUnavailable     = errors.New("kms unavailable")
	ErrKMSNotFound        = errors.New("kms key not found")
	ErrKMSDenied          = errors.New("kms access denied")
	ErrKMSTenantMismatch  = errors.New("kms encryption context mismatch")
	ErrInvalidTenant      = errors.New("invalid tenant")
	ErrUnsupportedVersion = errors.New("unsupported secret record version")
)

// KMS is the provider-agnostic key-management seam. Implementations generate
// data keys and unwrap them later, binding each wrapped key to the encryption
// context supplied at generation time.
type KMS interface {
	// GenerateDataKey returns a fresh plaintext DEK and its KMS-wrapped form.
	GenerateDataKey(ctx context.Context, keyID string, encryptionContext map[string]string) (plaintextDEK []byte, wrappedDEK []byte, err error)
	// Decrypt unwraps a DEK. Returns ErrKMSTenantMismatch when the encryption
	// context does not match the one used at generation.
	Decrypt(ctx context.Context, keyID string, wrappedDEK []byte, encryptionContext map[string]string) ([]byte, error)
}

// EncryptionContext builds the mandatory encryption context for a tenant-scoped
// secret. It panics on empty inputs because an absent context would remove the
// KMS-side tenant binding entirely.
func EncryptionContext(tenantID, purpose string) map[string]string {
	if tenantID == "" {
		panic("vault: EncryptionContext requires a tenant ID")
	}
	if purpose == "" {
		panic("vault: EncryptionContext requires a purpose")
	}
	return map[string]string{
		"tenant_id": tenantID,
		"purpose":   purpose,
	}
}

// contextHash returns a deterministic digest of an encryption context so test
// doubles (and any other in-process implementation) can detect context changes.
func contextHash(encryptionContext map[string]string) string {
	keys := make([]string, 0, len(encryptionContext))
	for k := range encryptionContext {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(encryptionContext[k]))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// memoryWrappedDEK is the wrapped-key envelope produced by MemoryKMS. It embeds
// the key id and the encryption-context digest, and carries the DEK only in
// encrypted form.
type memoryWrappedDEK struct {
	KeyID       string `json:"key_id"`
	ContextHash string `json:"context_hash"`
	Payload     []byte `json:"payload"`
}

// MemoryKMS is a context-tagged test double. It never stores or returns a DEK in
// the clear: data keys are wrapped with AES-256-GCM under a per-key wrapping key
// derived from the constructor material, with the context digest as AAD.
// It must not be used in production.
type MemoryKMS struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewMemoryKMS registers a single key id (the key material itself, matching the
// existing local-demo configuration) with a derived in-memory wrapping key.
func NewMemoryKMS(keyMaterial string) *MemoryKMS {
	k := &MemoryKMS{keys: make(map[string][]byte, 1)}
	k.keys[keyMaterial] = memoryWrappingKey(keyMaterial, keyMaterial)
	return k
}

func memoryWrappingKey(keyMaterial, keyID string) []byte {
	sum := sha256.Sum256([]byte("lanyard-memory-kms\x00" + keyMaterial + "\x00" + keyID))
	return sum[:]
}

// GenerateDataKey returns a random 32-byte DEK plus an enveloped, encrypted form
// of it that is bound to keyID and the encryption context.
func (k *MemoryKMS) GenerateDataKey(_ context.Context, keyID string, encryptionContext map[string]string) (dek []byte, wrappedDEK []byte, err error) {
	k.mu.RLock()
	wrappingKey, ok := k.keys[keyID]
	k.mu.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("vault: memory kms: unknown key id %q: %w", keyID, ErrKMSNotFound)
	}

	dek = make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("vault: memory kms: generate data key: %w", ErrKMSUnavailable)
	}
	success := false
	defer func() {
		if !success {
			clear(dek)
		}
	}()

	digest := contextHash(encryptionContext)
	payload, err := sealWithKey(wrappingKey, dek, []byte(digest))
	if err != nil {
		return nil, nil, fmt.Errorf("vault: memory kms: wrap data key: %w", ErrKMSUnavailable)
	}
	wrappedDEK, err = json.Marshal(memoryWrappedDEK{KeyID: keyID, ContextHash: digest, Payload: payload})
	if err != nil {
		return nil, nil, fmt.Errorf("vault: memory kms: encode wrapped data key: %w", ErrKMSUnavailable)
	}
	success = true
	return dek, wrappedDEK, nil
}

// Decrypt unwraps a DEK produced by GenerateDataKey. It fails with
// ErrKMSTenantMismatch when the encryption context changed and ErrKMSNotFound
// when the key id is unknown.
func (k *MemoryKMS) Decrypt(_ context.Context, keyID string, wrappedDEK []byte, encryptionContext map[string]string) (dek []byte, err error) {
	k.mu.RLock()
	wrappingKey, ok := k.keys[keyID]
	k.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("vault: memory kms: unknown key id %q: %w", keyID, ErrKMSNotFound)
	}

	var blob memoryWrappedDEK
	if err := json.Unmarshal(wrappedDEK, &blob); err != nil {
		return nil, fmt.Errorf("vault: memory kms: malformed wrapped data key: %w", ErrKMSUnavailable)
	}
	if blob.KeyID != keyID {
		return nil, fmt.Errorf("vault: memory kms: wrapped data key belongs to key id %q: %w", blob.KeyID, ErrKMSNotFound)
	}
	if blob.ContextHash != contextHash(encryptionContext) {
		return nil, fmt.Errorf("vault: memory kms: encryption context changed since generation: %w", ErrKMSTenantMismatch)
	}

	dek, err = openWithKey(wrappingKey, blob.Payload, []byte(blob.ContextHash))
	if err != nil {
		if dek != nil {
			clear(dek)
		}
		return nil, fmt.Errorf("vault: memory kms: unwrap data key: %w", ErrKMSUnavailable)
	}
	return dek, nil
}

// SecretRecord stores the encrypted payload and the wrapped data key used to decrypt it.
type SecretRecord struct {
	TenantID   string
	KMSKeyID   string
	Ciphertext []byte
	WrappedKey []byte
	Version    int
}

// Store keeps sealed secrets in memory. Retrieval is non-destructive; the
// KMS-wrapped DEK stored alongside each record is the only way back to the
// plaintext.
type Store struct {
	mu    sync.RWMutex
	kms   KMS
	items map[string]SecretRecord
}

func NewStore(kms KMS) *Store {
	return &Store{kms: kms, items: map[string]SecretRecord{}}
}

// Put seals plaintext and records it under id. It is idempotent on id: a repeat
// Put replaces that record only.
func (s *Store) Put(ctx context.Context, keyID, tenantID, id string, plaintext []byte) error {
	if id == "" {
		return errors.New("vault: secret id is required")
	}
	if tenantID == "" {
		return ErrInvalidTenant
	}

	ciphertext, wrappedKey, err := Seal(ctx, s.kms, keyID, tenantID, plaintext)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[id] = SecretRecord{
		TenantID:   tenantID,
		KMSKeyID:   keyID,
		Ciphertext: ciphertext,
		WrappedKey: wrappedKey,
		Version:    secretVersion,
	}
	return nil
}

// Get returns the plaintext for id without consuming it. It rejects records that
// belong to another tenant.
func (s *Store) Get(ctx context.Context, id, tenantID string) ([]byte, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenant
	}
	s.mu.RLock()
	item, ok := s.items[id]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("vault: secret %q not found", id)
	}
	if item.TenantID != tenantID {
		return nil, fmt.Errorf("vault: secret %q belongs to another tenant", id)
	}
	if item.Version != secretVersion {
		return nil, fmt.Errorf("vault: secret %q has unsupported version %d: %w", id, item.Version, ErrUnsupportedVersion)
	}

	return Open(ctx, s.kms, item.KMSKeyID, item.TenantID, item.Ciphertext, item.WrappedKey)
}

// UseOnce is superseded by the non-destructive Get.
//
// Deprecated: this shim exists only so the local demo proxy keeps compiling;
// it delegates to Get and no longer consumes the secret. New code must call Get.
func (s *Store) UseOnce(ctx context.Context, id, tenantID string) ([]byte, error) {
	return s.Get(ctx, id, tenantID)
}

// Seal encrypts plaintext under a KMS-generated DEK and binds the ciphertext to
// the tenant as GCM AAD (independent of the KMS encryption context).
func Seal(ctx context.Context, kms KMS, keyID, tenantID string, plaintext []byte) (ciphertext []byte, wrappedDEK []byte, err error) {
	if tenantID == "" {
		return nil, nil, ErrInvalidTenant
	}
	if kms == nil {
		return nil, nil, fmt.Errorf("vault: seal requires a kms: %w", ErrKMSUnavailable)
	}

	dek, wrappedDEK, err := kms.GenerateDataKey(ctx, keyID, EncryptionContext(tenantID, purposeSecret))
	if err != nil {
		return nil, nil, err
	}
	success := false
	defer func() {
		if !success {
			clear(dek)
		}
	}()

	if len(dek) != dekSize {
		return nil, nil, errors.New("vault: kms returned a data key with unexpected length")
	}

	ciphertext, err = sealWithKey(dek, plaintext, []byte(tenantID))
	if err != nil {
		return nil, nil, fmt.Errorf("vault: seal secret: %w", err)
	}
	success = true
	return ciphertext, wrappedDEK, nil
}

// Open decrypts a record by unwrapping its DEK with the same encryption context
// used by Seal, then verifying the tenant-bound GCM ciphertext.
func Open(ctx context.Context, kms KMS, keyID, tenantID string, ciphertext, wrappedDEK []byte) (plaintext []byte, err error) {
	if tenantID == "" {
		return nil, ErrInvalidTenant
	}
	if kms == nil {
		return nil, fmt.Errorf("vault: open requires a kms: %w", ErrKMSUnavailable)
	}

	dek, err := kms.Decrypt(ctx, keyID, wrappedDEK, EncryptionContext(tenantID, purposeSecret))
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			clear(dek)
		}
	}()

	if len(dek) != dekSize {
		return nil, errors.New("vault: kms returned a data key with unexpected length")
	}

	plaintext, err = openWithKey(dek, ciphertext, []byte(tenantID))
	if err != nil {
		return nil, fmt.Errorf("vault: open secret: %w", err)
	}
	success = true
	return plaintext, nil
}

func sealWithKey(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func openWithKey(key, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, aad)
}
