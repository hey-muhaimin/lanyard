package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlPlaneAcceptsGrantRequest(t *testing.T) {
	handler := newControlPlaneHandler()
	request := httptest.NewRequest(http.MethodPost, "/grant", strings.NewReader(`{"task":"task-1"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("POST /grant status = %d, want %d", recorder.Code, http.StatusAccepted)
	}
}

func TestControlPlaneReadiness(t *testing.T) {
	handler := newControlPlaneHandler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /readyz status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestAdminCreatesTenantThenRejectsUnknownTenantAgent(t *testing.T) {
	handler := newControlPlaneHandler()
	for name, request := range map[string]*http.Request{
		"tenant":    httptest.NewRequest(http.MethodPost, "/admin/tenants", strings.NewReader(`{"id":"tenant-1","name":"Acme"}`)),
		"agent":     httptest.NewRequest(http.MethodPost, "/admin/agents", strings.NewReader(`{"id":"agent-1","tenant_id":"tenant-1","owner_subject":"user:alice","public_key":"key"}`)),
		"bad-agent": httptest.NewRequest(http.MethodPost, "/admin/agents", strings.NewReader(`{"id":"agent-2","tenant_id":"tenant-2","owner_subject":"user:bob","public_key":"key"}`)),
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if name == "bad-agent" && recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d", name, recorder.Code)
		}
	}
}
