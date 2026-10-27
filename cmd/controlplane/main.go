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

	"github.com/cedar-policy/cedar-go"
	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/grant"
	"github.com/example/lanyard/internal/logging"
	"github.com/example/lanyard/internal/policy"
	"github.com/example/lanyard/internal/registry"
	token "github.com/example/lanyard/internal"
)

func main() {
	cfg := config.Load()
	logger := logging.NewJSONLogger()

	reg := registry.New()
	// Seed demo data for local development
	_ = reg.CreateTenant("tenant-demo", "Demo Tenant")
	_ = reg.RegisterAgent(registry.Agent{
		ID:        "agent:demo",
		TenantID:  "tenant-demo",
		Name:      "Demo Agent",
		PublicKey: "Y29udGVudC1zZWN1cmUtZGVtby1rZXktb3V0LWFnZW50LWFpLXB1YmxpY11rZXk=", // Replace with real base64 Ed25519 public key
		Status:    "active",
	})

	engine := policy.NewCedarEngine(&demoEntityLoader{})
	engine.SetPolicySource(&demoPolicySource{})

	// Publish a demo policy to ensure the engine is active
	demoPolicy := `
permit (
    principal in Agent::"agent:demo",
    action == Action::"demo:read",
    resource in Resource::"demo-secret"
) when { context.rowLimit <= 100 };
`
	_ = engine.Publish("tenant-demo", 1, []byte(demoPolicy))

	gs := grant.NewService(reg, engine)

	signer, err := token.NewSigner(cfg.TokenKeyID())
	if err != nil {
		logger.Error("failed to create signer", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              cfg.Address(),
		Handler:           newControlPlaneHandler(gs, signer, cfg),
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

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func tenantID(r *http.Request) string {
	return r.Header.Get("X-Tenant-ID")
}

type demoEntityLoader struct{}

func (l *demoEntityLoader) LoadTenantEntities(ctx context.Context, tenantID, actor, connector, resource string) (cedar.EntityMap, error) {
	// In a real implementation, this would query the registry/DB
	return cedar.EntityMap{
		cedar.NewEntityUID("Agent", actor): cedar.Entity{
			Attrs: map[string]any{"tenant_id": tenantID},
		},
	}, nil
}

type demoPolicySource struct{}

func (s *demoPolicySource) LoadPublishedPolicy(ctx context.Context, tenantID string) (*policy.PublishedPolicy, error) {
	if tenantID == "tenant-demo" {
		return &policy.PublishedPolicy{
			Version: 1,
			Body: []byte(`
permit (
    principal in Agent::"agent:demo",
    action == Action::"demo:read",
    resource in Resource::"demo-secret"
) when { context.rowLimit <= 100 };
`),
		}, nil
	}
	return nil, fmt.Errorf("no policy found for tenant %s", tenantID)
}

func (s *demoPolicySource) ListPublishedPolicies(ctx context.Context, tenantID string) ([]*policy.PublishedPolicy, error) {
	p, err := s.LoadPublishedPolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return []*policy.PublishedPolicy{p}, nil
}
func newControlPlaneHandler(gs *grant.Service, signer *token.Signer, cfg *config.Config) http.Handler {
	api := newControlPlaneAPI()
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

		var req grant.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "malformed request body", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		claims, err := gs.Issue(ctx, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		tokenClaims := token.Claims{
			Issuer:    cfg.Issuer(),
			Subject:   claims.Actor,
			Audience:  cfg.Audience(),
			ExpiresAt: time.Now().Add(time.Duration(req.TTLSeconds) * time.Second).Unix(),
			IssuedAt:  time.Now().Unix(),
			ID:        fmt.Sprintf("grant-%d", time.Now().UnixNano()),
			TenantID:  claims.TenantID,
			Actor:     claims.Actor,
			TaskID:    claims.TaskID,
			Scope:     claims.Scope,
			PolicyVer: claims.PolicyVer,
			Cnf:       claims.Cnf,
		}

		jwt, err := signer.Sign(tokenClaims)
		if err != nil {
			http.Error(w, "failed to sign token", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"access_token": jwt, "token_type": "Bearer", "expires_in": req.TTLSeconds})
	})
	mux.Handle("/admin/", api.handler())
	mux.Handle("/approve", api.handler())
	mux.Handle("/revoke", api.handler())
	mux.Handle("/events/", api.handler())
	if webFileServer := http.FileServer(http.Dir("web")); webFileServer != nil {
		mux.Handle("/", webFileServer)
	}
	return mux
}
