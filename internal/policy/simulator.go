package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/example/lanyard/internal/db"
	"github.com/jackc/pgx/v5"
)

type HistoricalDecision struct {
	EventID  string  `json:"event_id"`
	TenantID string  `json:"tenant_id"`
	Request  Request `json:"request"`
	Effect   string  `json:"effect"`
}

type HistoricalDecisionSource interface {
	LoadDecisions(context.Context, string, time.Time) ([]HistoricalDecision, error)
}

type CedarPolicySimulator struct {
	Engine *CedarEngine
	Source HistoricalDecisionSource
}

func (s CedarPolicySimulator) Simulate(ctx context.Context, tenantID string, body []byte, since time.Time) ([]SimulationChange, error) {
	if s.Engine == nil || s.Source == nil {
		return nil, errors.New("Cedar engine and historical decision source are required")
	}
	if tenantID == "" || len(body) == 0 {
		return nil, errors.New("tenant ID and candidate policy are required")
	}
	decisions, err := s.Source.LoadDecisions(ctx, tenantID, since)
	if err != nil {
		return nil, fmt.Errorf("load historical policy decisions: %w", err)
	}
	candidate, err := compilePolicySet(tenantID, 1, body)
	if err != nil {
		return nil, err
	}
	changes := make([]SimulationChange, 0)
	for _, historical := range decisions {
		if historical.TenantID != tenantID || historical.Request.TenantID != tenantID {
			return nil, errors.New("historical decision escaped tenant scope")
		}
		decision, err := s.Engine.decideAgainst(ctx, candidate, historical.Request)
		if err != nil {
			return nil, fmt.Errorf("replay event %s: %w", historical.EventID, err)
		}
		if historical.Effect != decision.Effect {
			changes = append(changes, SimulationChange{EventID: historical.EventID, PreviousEffect: historical.Effect, CandidateEffect: decision.Effect})
		}
	}
	return changes, nil
}

type PostgresDecisionReplaySource struct {
	Pool TenantDB
}

func (s PostgresDecisionReplaySource) LoadDecisions(ctx context.Context, tenantID string, since time.Time) ([]HistoricalDecision, error) {
	decisions := make([]HistoricalDecision, 0)
	err := db.WithTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT seq::text, payload FROM events WHERE tenant_id = $1::uuid AND ts >= $2 AND type = 'policy.decision' ORDER BY seq`, tenantID, since)
		if err != nil {
			return fmt.Errorf("query policy decision events: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var payload []byte
			if err := rows.Scan(&id, &payload); err != nil {
				return err
			}
			var decision HistoricalDecision
			if err := json.Unmarshal(payload, &decision); err != nil {
				return fmt.Errorf("decode policy decision event %s: %w", id, err)
			}
			if decision.EventID == "" {
				decision.EventID = id
			}
			if decision.TenantID == "" {
				decision.TenantID = tenantID
			}
			decisions = append(decisions, decision)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return decisions, nil
}

var _ PolicySimulator = CedarPolicySimulator{}
var _ HistoricalDecisionSource = PostgresDecisionReplaySource{}
