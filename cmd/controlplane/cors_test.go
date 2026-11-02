package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/example/lanyard/internal/config"
)

const corsTestOrigin = "https://ops.linkedqueue.cloud"
const consoleCorsTestOrigin = "https://console.linkedqueue.cloud"

// corsTestHandler records whether the wrapped handler was invoked.
func corsTestHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

func TestCORSMiddlewareMatchingOrigin(t *testing.T) {
	called := false
	handler := corsMiddleware(&config.Config{OpsConsoleOrigin: corsTestOrigin})(corsTestHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/ops/health", nil)
	request.Header.Set("Origin", corsTestOrigin)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("wrapped handler was not called for a matching origin")
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != corsTestOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, corsTestOrigin)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want %q", got, "true")
	}
	if got := recorder.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want %q", got, "Origin")
	}
}

func TestCORSMiddlewarePreflight(t *testing.T) {
	called := false
	handler := corsMiddleware(&config.Config{OpsConsoleOrigin: corsTestOrigin})(corsTestHandler(&called))

	request := httptest.NewRequest(http.MethodOptions, "/ops/actions", nil)
	request.Header.Set("Origin", corsTestOrigin)
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("wrapped handler was called for a preflight request")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	for name, want := range map[string]string{
		"Access-Control-Allow-Origin":      corsTestOrigin,
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Allow-Methods":     "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers":     "Content-Type",
		"Access-Control-Max-Age":           "600",
	} {
		if got := recorder.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if got := recorder.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want %q", got, "Origin")
	}
}

func TestCORSMiddlewareCustomerConsolePreflight(t *testing.T) {
	called := false
	handler := corsMiddleware(&config.Config{ConsoleOrigin: consoleCorsTestOrigin})(corsTestHandler(&called))

	request := httptest.NewRequest(http.MethodOptions, "/auth/register", nil)
	request.Header.Set("Origin", consoleCorsTestOrigin)
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("wrapped handler was called for a preflight request")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != consoleCorsTestOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, consoleCorsTestOrigin)
	}
}

func TestCORSMiddlewareNonMatchingOrigin(t *testing.T) {
	called := false
	handler := corsMiddleware(&config.Config{OpsConsoleOrigin: corsTestOrigin})(corsTestHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/ops/health", nil)
	request.Header.Set("Origin", "https://evil.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("wrapped handler was not called for a non-matching origin")
	}
	assertNoCORSHeaders(t, recorder)
}

func TestCORSMiddlewareEmptyConfig(t *testing.T) {
	called := false
	handler := corsMiddleware(&config.Config{})(corsTestHandler(&called))

	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		called = false
		request := httptest.NewRequest(method, "/ops/health", nil)
		request.Header.Set("Origin", corsTestOrigin)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)

		if !called {
			t.Fatalf("%s with an empty configured origin did not call the wrapped handler", method)
		}
		assertNoCORSHeaders(t, recorder)
	}
}

func assertNoCORSHeaders(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	for _, name := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Access-Control-Max-Age",
		"Vary",
	} {
		if got := recorder.Header().Get(name); got != "" {
			t.Fatalf("%s = %q, want no CORS header", name, got)
		}
	}
}
