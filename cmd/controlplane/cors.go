package main

import (
	"net/http"

	"github.com/example/lanyard/internal/config"
)

// corsMiddleware applies the configured console single-origin CORS policies. It is
// fail-closed: when no origin is configured the handler is returned unchanged
// and no CORS headers are emitted, and only an exact Origin match is echoed
// back (never "*") so credentialed requests work.
func corsMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowedOrigin := ""
			if origin == cfg.ConsoleOrigin && cfg.ConsoleOrigin != "" {
				allowedOrigin = cfg.ConsoleOrigin
			} else if origin == cfg.OpsConsoleOrigin && cfg.OpsConsoleOrigin != "" {
				allowedOrigin = cfg.OpsConsoleOrigin
			}
			if allowedOrigin == "" {
				next.ServeHTTP(w, r)
				return
			}
			header := w.Header()
			header.Set("Access-Control-Allow-Origin", allowedOrigin)
			header.Set("Access-Control-Allow-Credentials", "true")
			header.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				header.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				header.Set("Access-Control-Allow-Headers", "Content-Type")
				header.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
