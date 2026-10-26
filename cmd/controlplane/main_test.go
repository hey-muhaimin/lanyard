package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlPlaneDoesNotAcceptUnimplementedGrants(t *testing.T) {
	handler := newControlPlaneHandler()
	request := httptest.NewRequest(http.MethodPost, "/grant", strings.NewReader(`{"task":"task-1"}`))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("POST /grant status = %d, want %d", recorder.Code, http.StatusNotImplemented)
	}
	if strings.Contains(recorder.Body.String(), "accepted") {
		t.Fatalf("POST /grant returned success-shaped response: %q", recorder.Body.String())
	}
}

func TestControlPlaneReadinessFailsClosedUntilGrantIssuanceIsConfigured(t *testing.T) {
	handler := newControlPlaneHandler()
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
}
