package revocation

import (
	"fmt"
	"sync"
	"time"
)

// Scope identifies the dimension of a grant that a revocation denies.
type Scope struct {
	AgentID string
	TaskID  string
	ChainID string
	TokenID string
}

// Store tracks active deny entries in memory until their grant lifetime expires.
type Store struct {
	mu      sync.RWMutex
	entries map[string]time.Time
}

func NewStore() *Store {
	return &Store{entries: make(map[string]time.Time)}
}

func key(scope Scope) string {
	switch {
	case scope.TokenID != "":
		return "token:" + scope.TokenID
	case scope.ChainID != "":
		return "chain:" + scope.ChainID
	case scope.TaskID != "":
		return "task:" + scope.TaskID
	case scope.AgentID != "":
		return "agent:" + scope.AgentID
	default:
		return ""
	}
}

func (s *Store) Revoke(scope Scope, expiresAt time.Time) error {
	entry := key(scope)
	if entry == "" {
		return fmt.Errorf("revocation scope is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[entry] = expiresAt
	return nil
}

func (s *Store) Denied(scope Scope, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, 4)
	if scope.AgentID != "" {
		keys = append(keys, "agent:"+scope.AgentID)
	}
	if scope.TaskID != "" {
		keys = append(keys, "task:"+scope.TaskID)
	}
	if scope.ChainID != "" {
		keys = append(keys, "chain:"+scope.ChainID)
	}
	if scope.TokenID != "" {
		keys = append(keys, "token:"+scope.TokenID)
	}
	for _, candidate := range keys {
		if expiresAt, ok := s.entries[candidate]; ok {
			if expiresAt.After(now) {
				return true
			}
			delete(s.entries, candidate)
		}
	}
	return false
}
