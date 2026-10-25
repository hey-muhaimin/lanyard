package vault

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "fmt"
    "sync"
)

// KMS exposes the wrap/unwrap operations needed to encrypt service secrets.
type KMS interface {
    Wrap(ctx context.Context, keyID string, dek []byte) ([]byte, error)
    Unwrap(ctx context.Context, keyID string, wrapped []byte) ([]byte, error)
}

// MemoryKMS is intentionally simple and should only be used in local development.
type MemoryKMS struct {
    mu   sync.RWMutex
    keys map[string][]byte
}

func NewMemoryKMS(keyMaterial string) *MemoryKMS {
    return &MemoryKMS{keys: map[string][]byte{keyMaterial: []byte(keyMaterial)}}
}

func (k *MemoryKMS) Wrap(_ context.Context, keyID string, dek []byte) ([]byte, error) {
    k.mu.RLock()
    _, ok := k.keys[keyID]
    k.mu.RUnlock()
    if !ok {
        return nil, fmt.Errorf("unknown key id: %s", keyID)
    }
    return append([]byte(nil), dek...), nil
}

func (k *MemoryKMS) Unwrap(_ context.Context, keyID string, wrapped []byte) ([]byte, error) {
    k.mu.RLock()
    _, ok := k.keys[keyID]
    k.mu.RUnlock()
    if !ok {
        return nil, fmt.Errorf("unknown key id: %s", keyID)
    }
    return append([]byte(nil), wrapped...), nil
}

// SecretRecord stores the encrypted payload and the wrapped data key used to decrypt it.
type SecretRecord struct {
    TenantID   string
    KMSKeyID   string
    Ciphertext []byte
    WrappedKey []byte
}

// Store exposes only Put and UseOnce, matching the design requirement that callers cannot fetch plaintext directly.
type Store struct {
    mu    sync.RWMutex
    kms   KMS
    items map[string]SecretRecord
}

func NewStore(kms KMS) *Store {
    return &Store{kms: kms, items: map[string]SecretRecord{}}
}

func (s *Store) Put(keyID, tenantID, id string, plaintext []byte) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    ct, wrapped, err := Seal(context.Background(), s.kms, keyID, tenantID, plaintext)
    if err != nil {
        return err
    }
    s.items[id] = SecretRecord{
        TenantID:   tenantID,
        KMSKeyID:   keyID,
        Ciphertext: ct,
        WrappedKey: wrapped,
    }
    return nil
}

func (s *Store) UseOnce(ctx context.Context, id, tenantID string) ([]byte, error) {
    s.mu.RLock()
    item, ok := s.items[id]
    s.mu.RUnlock()
    if !ok {
        return nil, fmt.Errorf("secret %s not found", id)
    }
    if item.TenantID != tenantID {
        return nil, errors.New("tenant mismatch")
    }

    dek, err := s.kms.Unwrap(ctx, item.KMSKeyID, item.WrappedKey)
    if err != nil {
        return nil, err
    }
    return Open(item.Ciphertext, dek, tenantID)
}

// Seal encrypts plaintext with a random DEK and binds it to the tenant as AAD.
func Seal(ctx context.Context, kms KMS, keyID, tenantID string, plaintext []byte) ([]byte, []byte, error) {
    dek := make([]byte, 32)
    if _, err := rand.Read(dek); err != nil {
        return nil, nil, err
    }

    block, err := aes.NewCipher(dek)
    if err != nil {
        return nil, nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = rand.Read(nonce); err != nil {
        return nil, nil, err
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, []byte(tenantID))
    wrapped, err := kms.Wrap(ctx, keyID, dek)
    if err != nil {
        return nil, nil, err
    }

    return ciphertext, wrapped, nil
}

// Open decrypts and verifies the tenant-bound ciphertext.
func Open(ciphertext, wrappedDEK []byte, tenantID string) ([]byte, error) {
    block, err := aes.NewCipher(wrappedDEK)
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
    return gcm.Open(nil, nonce, ct, []byte(tenantID))
}
