package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go"
)

const PolicyInvalidationSubject = "lanyard.policy.invalidate"

type NATSInvalidator struct {
	Conn   *nats.Conn
	Engine *CedarEngine
}

func (n NATSInvalidator) Publish(ctx context.Context, subject string, payload []byte) error {
	if n.Conn == nil {
		return errors.New("NATS connection is required")
	}
	if subject == "" {
		subject = PolicyInvalidationSubject
	}
	if err := n.Conn.Publish(subject, payload); err != nil {
		return fmt.Errorf("publish policy invalidation: %w", err)
	}
	if err := n.Conn.FlushWithContext(ctx); err != nil {
		return fmt.Errorf("flush policy invalidation: %w", err)
	}
	return nil
}

func (n NATSInvalidator) Subscribe(ctx context.Context) (*nats.Subscription, error) {
	if n.Conn == nil || n.Engine == nil {
		return nil, errors.New("NATS connection and Cedar engine are required")
	}
	subscription, err := n.Conn.Subscribe(PolicyInvalidationSubject, func(message *nats.Msg) {
		n.Handle(message.Data)
	})
	if err != nil {
		return nil, fmt.Errorf("subscribe to policy invalidations: %w", err)
	}
	if err := n.Conn.FlushWithContext(ctx); err != nil {
		_ = subscription.Unsubscribe()
		return nil, fmt.Errorf("flush policy subscription: %w", err)
	}
	return subscription, nil
}

func (n NATSInvalidator) Handle(payload []byte) {
	if n.Engine == nil {
		return
	}
	var invalidation struct {
		TenantID string `json:"tenant_id"`
	}
	if json.Unmarshal(payload, &invalidation) != nil || invalidation.TenantID == "" {
		return
	}
	n.Engine.InvalidateTenant(invalidation.TenantID)
}
