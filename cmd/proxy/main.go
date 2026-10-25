package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	token "github.com/example/lanyard/internal"
	"github.com/example/lanyard/internal/config"
	"github.com/example/lanyard/internal/logging"
	"github.com/example/lanyard/internal/vault"
)

func main() {
	cfg := config.Load()
	logger := logging.NewJSONLogger()
	tokenKeyID := os.Getenv("TOKEN_KEY_ID")
	tokenIssuer := os.Getenv("TOKEN_ISSUER")
	tokenAudience := os.Getenv("TOKEN_AUDIENCE")
	tokenPublicKeyText := os.Getenv("TOKEN_PUBLIC_KEY")

	var tokenPublicKey ed25519.PublicKey
	var tokenVerifier *token.Verifier
	hasTokenConfig := tokenKeyID != "" || tokenIssuer != "" || tokenAudience != "" || tokenPublicKeyText != ""
	if hasTokenConfig {
		if tokenKeyID == "" || tokenIssuer == "" || tokenAudience == "" || tokenPublicKeyText == "" {
			logger.Error("incomplete proxy token configuration", nil)
			os.Exit(1)
		}
		publicKey, err := token.DecodeEd25519PublicKey(tokenPublicKeyText)
		if err != nil {
			logger.Error("invalid proxy token configuration", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
		tokenPublicKey = publicKey
		tokenVerifier, err = token.NewVerifier(tokenIssuer, tokenAudience, map[string]ed25519.PublicKey{
			tokenKeyID: publicKey,
		})
		if err != nil {
			logger.Error("invalid proxy token configuration", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
	} else {
		logger.Warn("proxy token authentication is not configured; protected routes will be unavailable", nil)
	}

	kms := vault.NewMemoryKMS(cfg.VaultKeyID)
	secretStore := vault.NewStore(kms)

	if err := secretStore.Put(cfg.VaultKeyID, cfg.TenantID, "demo-secret", []byte("super-secret-value")); err != nil {
		logger.Error("secret put failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if tokenVerifier == nil {
			http.Error(w, "proxy token authentication is not configured", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.Handle("/jwks.json", token.JWKSHandler(tokenKeyID, tokenPublicKey))
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		claims, ok := token.ClaimsFromRequest(r)
		if !ok || !token.HasScope(claims, "demo", "read", "demo-secret") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		secret, err := secretStore.UseOnce(r.Context(), "demo-secret", cfg.TenantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			logger.Error("proxy secret fetch failed", map[string]any{"error": err.Error()})
			return
		}
		redacted := logging.Redact(string(secret), "super-secret-value")
		logger.Info("proxy call handled", map[string]any{"tenant_id": cfg.TenantID, "secret_preview": redacted})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf("{\"tenant_id\":\"%s\",\"secret_preview\":\"%s\"}", cfg.TenantID, strings.ReplaceAll(redacted, "\n", ""))))
	})
	mux.Handle("/proxy", token.Gate(tokenVerifier, token.NewDPoPVerifier(), proxyHandler))

	srv := &http.Server{Addr: cfg.Address(), Handler: mux}
	go func() {
		logger.Info("proxy listening", map[string]any{"address": cfg.Address()})
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("proxy failed", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Info("proxy shutting down", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("proxy shutdown failed", map[string]any{"error": err.Error()})
	}
	fmt.Println("proxy stopped")
}
