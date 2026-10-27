package auth

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

var ErrUnauthenticated = errors.New("unauthenticated")
var ErrForbidden = errors.New("forbidden")

type Session struct {
	ID        string
	TenantID  string
	Subject   string
	Roles     []string
	ExpiresAt time.Time
	Revoked   bool
}

type Store struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

func NewStore() *Store {
	return &Store{sessions: map[string]Session{}}
}

func (s *Store) Create(sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

func (s *Store) Get(id string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	return sess, true
}

func (s *Store) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.Revoked = true
		s.sessions[id] = sess
	}
}

func (s *Store) Validate(id string, now time.Time) (Session, error) {
	sess, ok := s.Get(id)
	if !ok {
		return Session{}, ErrUnauthenticated
	}
	if sess.Revoked {
		return Session{}, ErrForbidden
	}
	if !sess.ExpiresAt.IsZero() && now.After(sess.ExpiresAt) {
		return Session{}, ErrForbidden
	}
	return sess, nil
}

func SessionFromRequest(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if cookie, err := r.Cookie("session"); err == nil {
		return strings.TrimSpace(cookie.Value)
	}
	return strings.TrimSpace(r.Header.Get("X-Session-ID"))
}

func HasRole(sess Session, role string) bool {
	for _, r := range sess.Roles {
		if r == role {
			return true
		}
	}
	return false
}
