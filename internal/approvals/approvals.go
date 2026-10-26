package approvals

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("approval not found")
var ErrExpired = errors.New("approval expired")
var ErrParameterMismatch = errors.New("approval parameters changed")

const defaultTTL = 10 * time.Minute

type Request struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	TaskID        string    `json:"task_id"`
	ChainID       string    `json:"chain_id"`
	RequesterID   string    `json:"requester_id"`
	Action        string    `json:"action"`
	Parameters    any       `json:"parameters"`
	ParameterHash string    `json:"parameter_hash"`
	Status        string    `json:"status"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type Store struct {
	mu       sync.RWMutex
	requests map[string]Request
}

func NewStore() *Store { return &Store{requests: make(map[string]Request)} }

func ParameterHash(parameters any) (string, error) {
	encoded, err := json.Marshal(parameters)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}

func (s *Store) Create(request Request, now time.Time) (Request, error) {
	if request.ID == "" || request.TenantID == "" || request.TaskID == "" || request.Action == "" {
		return Request{}, errors.New("approval identity, task, tenant, and action are required")
	}
	hash, err := ParameterHash(request.Parameters)
	if err != nil {
		return Request{}, err
	}
	request.ParameterHash = hash
	if request.ExpiresAt.IsZero() {
		request.ExpiresAt = now.Add(defaultTTL)
	}
	if request.Status == "" {
		request.Status = "pending"
	}
	s.mu.Lock()
	s.requests[request.ID] = request
	s.mu.Unlock()
	return request, nil
}

func (s *Store) List(tenantID string) []Request {
	s.mu.RLock()
	defer s.mu.RUnlock()
	requests := make([]Request, 0)
	for _, request := range s.requests {
		if tenantID == "" || request.TenantID == tenantID {
			requests = append(requests, request)
		}
	}
	return requests
}

func (s *Store) Decide(id, tenantID, status string, parameters any, now time.Time) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[id]
	if !ok || request.TenantID != tenantID {
		return Request{}, ErrNotFound
	}
	if !request.ExpiresAt.After(now) {
		return Request{}, ErrExpired
	}
	hash, err := ParameterHash(parameters)
	if err != nil {
		return Request{}, err
	}
	if hash != request.ParameterHash {
		return Request{}, ErrParameterMismatch
	}
	if status != "approved" && status != "denied" {
		return Request{}, errors.New("approval status must be approved or denied")
	}
	request.Status = status
	s.requests[id] = request
	return request, nil
}
