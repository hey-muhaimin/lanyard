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
	token "github.com/example/lanyard/internal"
	"github.com/example/lanyard/internal/authstore"
	"github.com/example/lanyard/internal/awssecrets"
	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/grant"
	"github.com/example/lanyard/internal/grantstore"
	"github.com/example/lanyard/internal/logging"
	"github.com/example/lanyard/internal/policy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The seeds below are fixed, well-known base64url (unpadded) Ed25519 seeds used
// only for local demo mode. They are not secret and must never be used outside
// development; production requires TOKEN_PRIVATE_KEY.
const (
	// devTokenSigningSeed signs grants when ALLOW_INSECURE_DEMO=true and
	// TOKEN_PRIVATE_KEY is unset, so issued grants survive a restart.
	devTokenSigningSeed = "bGFueWFyZC1kZXYtc2lnbi1zZWVkLTMyLWJ5dGVzISE"
	// demoAgentSeed is the seed whose public key is registered for "agent:demo".
	demoAgentSeed = "bGFueWFyZC1kZW1vLWFnZW50LXNlZWQtMzItYnl0ZSE"
)

// demoPolicyText permits the demo agent to read demo-secret with at most 100
// rows. Cedar resource entities are identified as "<connector>/<resource>".
const demoPolicyText = `
permit (
    principal in Agent::"agent:demo",
    action == Action::"demo:read",
    resource == Resource::"demo/demo-secret"
) when { context.rowLimit <= 100 };
`

func main() {
	cfg := config.Load()
	logger := logging.NewJSONLogger()

	if err := cfg.Validate(); err != nil {
		logger.Error("invalid controlplane configuration", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	if err := cfg.ValidateProduction(); err != nil {
		logger.Error("invalid controlplane production configuration", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	pool, err := newDBPool(cfg)
	if err != nil {
		logger.Error("failed to create database pool", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	defer pool.Close()

	gs, err := newGrantService(cfg, pool)
	if err != nil {
		logger.Error("failed to create grant service", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	signer, err := newTokenSigner(cfg, logger)
	if err != nil {
		logger.Error("failed to create signer", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              cfg.Address(),
		Handler:           newControlPlaneHandler(gs, signer, cfg, pool),
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

// newDBPool opens the PostgreSQL connection pool from the configured URL.
func newDBPool(cfg config.Config) (*pgxpool.Pool, error) {
	databaseURL := cfg.DatabaseURL
	if !cfg.DevMode {
		if cfg.DatabaseSecretARN == "" {
			return nil, errors.New("DATABASE_SECRET_ARN is required outside demo mode")
		}
		secrets, err := awssecrets.NewFromEnv(context.Background(), cfg.AWSRegion)
		if err != nil {
			return nil, err
		}
		databaseURL, err = secrets.PostgresURL(context.Background(), cfg.DatabaseSecretARN)
		if err != nil {
			return nil, fmt.Errorf("load database credentials from Secrets Manager: %w", err)
		}
	} else if databaseURL == "" {
		return nil, errors.New("DATABASE_URL is required in demo mode")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return pool, nil
}

// newGrantService wires the persistent, tenant-scoped grant store and the Cedar
// policy engine used by the control plane.
func newGrantService(cfg config.Config, pool *pgxpool.Pool) (*grant.Service, error) {
	store := grantstore.NewStore(pool)

	var engine *policy.CedarEngine
	if cfg.DevMode {
		// Seed the demo agent into the database-backed store when in dev mode.
		agent := grantstore.Agent{
			ID:           "agent:demo",
			TenantID:     cfg.TenantID,
			Name:         "Demo Agent",
			OwnerSubject: "user:owner",
			PublicKey:    demoAgentPublicKey(),
			Status:       "active",
		}
		if err := store.RegisterAgent(context.Background(), agent); err != nil {
			return nil, fmt.Errorf("register demo agent: %w", err)
		}
		engine = policy.NewCedarEngine(&demoEntityLoader{})
		engine.SetPolicySource(&demoPolicySource{})
		if err := engine.Publish(cfg.TenantID, 1, []byte(demoPolicyText)); err != nil {
			return nil, fmt.Errorf("publish demo policy: %w", err)
		}
	} else {
		engine = policy.NewCedarEngine(policy.PostgresEntityLoader{Pool: pool})
		engine.SetPolicySource(policy.PostgresPolicySource{Pool: pool})
	}

	return grant.NewService(store, engine), nil
}

// demoAgentPublicKey returns the Ed25519 public key for the demo agent (dev mode).
func demoAgentPublicKey() string {
	// 32-byte Ed25519 public key, base64url (unpadded)
	return "Ll-PUozWHWsgBgaMrGinzeFP4BNUCprjPDqgjkczCoc"
}

// newTokenSigner loads the production signing key from Secrets Manager. Demo
// mode alone may use an environment value or the fixed local development seed.
func newTokenSigner(cfg config.Config, logger *logging.Logger) (*token.Signer, error) {
	if !cfg.DevMode {
		if cfg.TokenPrivateKeySecretARN == "" {
			return nil, errors.New("TOKEN_PRIVATE_KEY_SECRET_ARN is required outside demo mode")
		}
		secrets, err := awssecrets.NewFromEnv(context.Background(), cfg.AWSRegion)
		if err != nil {
			return nil, err
		}
		encoded, err := secrets.String(context.Background(), cfg.TokenPrivateKeySecretARN)
		if err != nil {
			return nil, fmt.Errorf("load token signing key from Secrets Manager: %w", err)
		}
		return newTokenSignerFromEncoded(cfg, encoded)
	}
	if encoded := os.Getenv("TOKEN_PRIVATE_KEY"); encoded != "" {
		return newTokenSignerFromEncoded(cfg, encoded)
	}
	logger.Warn("using well-known development signing key", map[string]any{
		"reason": "ALLOW_INSECURE_DEMO=true and TOKEN_PRIVATE_KEY is unset",
	})
	privateKey, err := token.DecodeEd25519PrivateKey(devTokenSigningSeed)
	if err != nil {
		return nil, fmt.Errorf("decode development signing seed: %w", err)
	}
	return token.NewSignerWithKey(cfg.TokenKeyID(), privateKey)
}

func newTokenSignerFromEncoded(cfg config.Config, encoded string) (*token.Signer, error) {
	privateKey, err := token.DecodeEd25519PrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode token signing key: %w", err)
	}
	return token.NewSignerWithKey(cfg.TokenKeyID(), privateKey)
}

type demoEntityLoader struct{}

func (l *demoEntityLoader) LoadTenantEntities(ctx context.Context, tenantID, actor, connector, resource string) (cedar.EntityMap, error) {
	// In a real implementation, this would query the registry/DB
	uid := cedar.NewEntityUID(cedar.EntityType("Agent"), cedar.String(actor))
	return cedar.EntityMap{
		uid: {
			UID:        uid,
			Parents:    cedar.NewEntityUIDSet(),
			Attributes: cedar.NewRecord(cedar.RecordMap{cedar.String("tenant_id"): cedar.String(tenantID)}),
		},
	}, nil
}

type demoPolicySource struct{}

func (s *demoPolicySource) LoadPublishedPolicy(ctx context.Context, tenantID string) (policy.PublishedPolicy, error) {
	if tenantID == "tenant-demo" {
		return policy.PublishedPolicy{Version: 1, Body: []byte(demoPolicyText)}, nil
	}
	return policy.PublishedPolicy{}, fmt.Errorf("no policy found for tenant %s", tenantID)
}

func newControlPlaneHandler(gs *grant.Service, signer *token.Signer, cfg config.Config, pool *pgxpool.Pool) http.Handler {
	api := newControlPlaneAPI()
	dpopVerifier := token.NewDPoPVerifier()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// /readyz is 503 until the database pool is confirmed healthy.
		if pool == nil {
			http.Error(w, "internal: pool not configured", http.StatusServiceUnavailable)
			return
		}
		if err := pool.Ping(context.Background()); err != nil {
			http.Error(w, "database not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.Handle("/jwks.json", token.JWKSHandler(signer.KeyID(), signer.PublicKey()))
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

		ctx := context.WithValue(r.Context(), grantstore.TenantKey{}, cfg.TenantID)
		encodedPublicKey, err := gs.AgentPublicKey(ctx, req.Actor)
		if err != nil {
			http.Error(w, "agent authentication failed", http.StatusUnauthorized)
			return
		}
		agentThumbprint, err := token.PublicKeyThumbprintFromBase64(encodedPublicKey)
		if err != nil || dpopVerifier.VerifyRequest(r.Header.Get("DPoP"), agentThumbprint, r.Method, dpopTargetURL(r, cfg.DevMode), time.Now()) != nil {
			http.Error(w, "agent authentication failed", http.StatusUnauthorized)
			return
		}
		claims, err := gs.Issue(ctx, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		scope := make([]token.ScopeEntry, 0, len(claims.Scope))
		for _, entry := range claims.Scope {
			scope = append(scope, token.ScopeEntry{
				Connector: entry.Connector,
				Action:    entry.Action,
				Resource:  entry.Resource,
				MaxRows:   entry.MaxRows,
			})
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
			Scope:     scope,
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
	if pool != nil {
		// Session-authenticated, database-backed admin API used by the console.
		consoleAdmin := newConsoleAdminHandler(authstore.New(pool), newConsoleStore(pool), cfg, newAuthLogger())
		mux.Handle("/admin/", consoleAdmin)
		mux.Handle("/approve", consoleAdmin)
		mux.Handle("/revoke", consoleAdmin)
		mux.Handle("/events/", consoleAdmin)
		// Ops console routes (session‑auth, same store).
		opsHandler := newOpsHandler(authstore.New(pool))
		mux.Handle("/ops/", opsHandler)
	} else if cfg.DevMode {
		mux.Handle("/admin/", api.handler())
		mux.Handle("/approve", api.handler())
		mux.Handle("/revoke", api.handler())
		mux.Handle("/events/", api.handler())
	} else {
*** End Patch		mux.HandleFunc("/admin/", http.NotFound)
		mux.HandleFunc("/approve", http.NotFound)
		mux.HandleFunc("/revoke", http.NotFound)
		mux.HandleFunc("/events/", http.NotFound)
	}
	// Customer console session auth is available in demo and production; it
	// needs the database-backed SECURITY DEFINER functions.
	if pool != nil {
		mux.Handle("/auth/", newAuthHandler(authstore.New(pool), cfg, newAuthLogger()))
	} else {
		mux.Handle("/auth/", authUnavailableHandler())
	}
	// Wrap the entire mux with CSP middleware for the static console apps.
	return cspMiddleware(mux)
}

func dpopTargetURL(r *http.Request, devMode bool) string {
	scheme := "https"
	if devMode && r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + r.URL.EscapedPath()
}
