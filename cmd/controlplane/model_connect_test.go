package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConnectAndModels(t *testing.T) {
	api := newControlPlaneAPI()
	// connect
	body := []byte(`{"provider":"openai","api_key":"sk-test","name":"c1"}`)
	req := httptest.NewRequest(http.MethodPost, "/connect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	api.connectHandler(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("connect status=%d body=%s", rr.Code, rr.Body.String())
	}
	var conn map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &conn); err != nil {
		t.Fatal(err)
	}
	id, _ := conn["id"].(string)
	if id == "" {
		t.Fatal("missing id")
	}
	if _, ok := conn["api_key"]; ok {
		t.Fatal("api_key leaked in response")
	}

	// models (static)
	req2 := httptest.NewRequest(http.MethodGet, "/models?provider=openai", nil)
	rr2 := httptest.NewRecorder()
	api.modelsHandler(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("models status=%d", rr2.Code)
	}

	// models via connection (will fail upstream since fake key, expect 502)
	req3 := httptest.NewRequest(http.MethodGet, "/models?connection_id="+id, nil)
	rr3 := httptest.NewRecorder()
	api.modelsHandler(rr3, req3)
	if rr3.Code != http.StatusBadGateway && rr3.Code != http.StatusOK {
		t.Fatalf("models conn status=%d body=%s", rr3.Code, rr3.Body.String())
	}

	// validation
	req4 := httptest.NewRequest(http.MethodPost, "/connect", bytes.NewReader([]byte(`{"provider":"openai"}`)))
	rr4 := httptest.NewRecorder()
	api.connectHandler(rr4, req4)
	if rr4.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr4.Code)
	}

	// method not allowed
	req5 := httptest.NewRequest(http.MethodGet, "/connect", nil)
	rr5 := httptest.NewRecorder()
	api.connectHandler(rr5, req5)
	if rr5.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr5.Code)
	}
}
