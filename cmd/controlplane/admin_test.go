package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/example/lanyard/internal/auth"
)

func TestAdminRequiresAuth(t *testing.T) {
	api := newControlPlaneAPI()
	sessions := auth.NewStore()
	handler := newAdminHandler(api, sessions)
	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAdminRejectsCrossTenant(t *testing.T) {
	api := newControlPlaneAPI()
	sessions := auth.NewStore()
	sessions.Create(auth.Session{ID: "s1", TenantID: "t1", Subject: "u1", Roles: []string{"admin"}, ExpiresAt: time.Now().Add(time.Hour)})
	handler := newAdminHandler(api, sessions)
	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	req.Header.Set("Authorization", "Bearer s1")
	req.Header.Set("X-Tenant-ID", "t2")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}
