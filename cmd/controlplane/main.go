package main

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
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

    mux := http.NewServeMux()
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("ok"))
    })
    mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("ready"))
    })
    mux.HandleFunc("/grant", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        var payload map[string]any
        if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        logger.Info("grant request accepted", map[string]any{"tenant_id": cfg.TenantID, "task_id": payload["task"]})
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        _ = json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "tenant_id": cfg.TenantID})
    })

    srv := &http.Server{
        Addr:    cfg.Address(),
        Handler: mux,
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
    fmt.Println("controlplane stopped")
}
