package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/logging"
)

func main() {
	cfg := config.Load()
	logger := logging.NewJSONLogger()

	srv := &http.Server{
		Addr:              cfg.Address(),
		Handler:           newControlPlaneHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		logger.Info("controlplane listening", map[string]any{"address": cfg.Address()})
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("controlplane failed", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Info("controlplane shutting down", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown failed", map[string]any{"error": err.Error()})
	}
	logger.Info("controlplane stopped", nil)
}

func newControlPlaneHandler() http.Handler {
	api := newControlPlaneAPI()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if tenantID(r) == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("/grant", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "task": "configured"})
	})
	mux.Handle("/admin/", api.handler())
	mux.Handle("/approve", api.handler())
	mux.Handle("/revoke", api.handler())
	mux.Handle("/events/", api.handler())
	return mux
}
