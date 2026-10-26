package events

import (
	"bytes"
	"fmt"
)

type StoredEvent struct {
	Sequence int64
	TenantID string
	Payload  map[string]any
	PrevHash []byte
	Hash     []byte
}

func VerifyChain(events []StoredEvent) error {
	var previous []byte
	for index, event := range events {
		if !bytes.Equal(event.PrevHash, previous) {
			return fmt.Errorf("sequence %d: previous hash mismatch", event.Sequence)
		}
		calculated, err := NextHash(previous, event.Payload)
		if err != nil {
			return fmt.Errorf("sequence %d: calculate hash: %w", event.Sequence, err)
		}
		if !bytes.Equal(calculated, event.Hash) {
			return fmt.Errorf("sequence %d: event hash mismatch", event.Sequence)
		}
		if index > 0 && event.Sequence != events[index-1].Sequence+1 {
			return fmt.Errorf("sequence %d: event sequence gap", event.Sequence)
		}
		previous = event.Hash
	}
	return nil
}
