package events

import (
    "crypto/sha256"
    "encoding/json"
    "fmt"
)

// Event is a structured audit record with a deterministic hash chain.
type Event struct {
    Type     string         `json:"type"`
    TenantID string         `json:"tenant_id"`
    Payload  map[string]any `json:"payload"`
    PrevHash []byte         `json:"prev_hash,omitempty"`
    Hash     []byte         `json:"hash,omitempty"`
}

func (e *Event) ComputeHash() error {
    canonical, err := canonicalJSON(e.Payload)
    if err != nil {
        return err
    }
    h := sha256.New()
    h.Write(e.PrevHash)
    h.Write(canonical)
    e.Hash = h.Sum(nil)
    return nil
}

func canonicalJSON(v any) ([]byte, error) {
    return json.Marshal(v)
}

func NextHash(prev []byte, payload map[string]any) ([]byte, error) {
    canonical, err := canonicalJSON(payload)
    if err != nil {
        return nil, err
    }
    h := sha256.New()
    h.Write(prev)
    h.Write(canonical)
    return h.Sum(nil), nil
}

func (e Event) String() string {
    return fmt.Sprintf("%s:%s", e.Type, e.TenantID)
}
