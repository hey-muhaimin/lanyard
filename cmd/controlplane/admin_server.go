package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/example/lanyard/internal/auth"
)

func newAdminHandler(api *controlPlaneAPI, sessions *auth.Store) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/admin/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessID := auth.SessionFromRequest(r)
		if sessID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		sess, err := sessions.Validate(sessID, time.Now())
		if err != nil {
			if errors.Is(err, auth.ErrForbidden) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
			return
		}
		if !auth.HasRole(sess, "admin") && !auth.HasRole(sess, "tenant-admin") {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "insufficient role"})
			return
		}
		// Enforce tenant isolation from session
		if r.Header.Get("X-Tenant-ID") != "" && r.Header.Get("X-Tenant-ID") != sess.TenantID {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-tenant access denied"})
			return
		}
		r.Header.Set("X-Tenant-ID", sess.TenantID)
		api.handler().ServeHTTP(w, r)
	}))
	return mux
}

func startAdminServer(_ context.Context, addr string, handler http.Handler, logger interface{ Info(string, map[string]any); Error(string, map[string]any) }) *http.Server {
	if addr == "" {
		logger.Error("admin listener misconfigured", map[string]any{"error": "admin address required"})
		os.Exit(1)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	go func() {
		logger.Info("admin listening", map[string]any{"address": addr})
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("admin failed", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
	}()
	return srv
}
