package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	token "github.com/example/lanyard/internal"
	"github.com/example/lanyard/internal/config"
	kmsimpl "github.com/example/lanyard/internal/kms"
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
	upstreamURLText := os.Getenv("UPSTREAM_URL")

	var tokenPublicKey ed25519.PublicKey
	var tokenVerifier *token.Verifier
	var upstreamURL *url.URL
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
	if upstreamURLText != "" {
		var err error
		upstreamURL, err = parseUpstreamURL(upstreamURLText)
		if err != nil {
			logger.Error("invalid proxy upstream configuration", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
	}
	upstreamClient := newUpstreamClient()

	if err := cfg.ValidateProduction(); err != nil {
		logger.Error("invalid proxy KMS configuration", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	var kms vault.KMS
	if cfg.DevMode {
		kms = vault.NewMemoryKMS(cfg.VaultKeyID)
	} else {
		var err error
		kms, err = kmsimpl.NewFromEnv(context.Background(), cfg.KMSKeyID, cfg.AWSRegion)
		if err != nil {
			logger.Error("failed to initialize production KMS", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
	}
	secretStore := vault.NewStore(kms)

	if cfg.DevMode {
		if err := secretStore.Put(context.Background(), cfg.VaultKeyID, cfg.TenantID, "demo-secret", []byte("super-secret-value")); err != nil {
			logger.Error("secret put failed", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if tokenVerifier == nil || upstreamURL == nil {
			http.Error(w, "proxy authentication or upstream is not configured", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.Handle("/jwks.json", token.JWKSHandler(tokenKeyID, tokenPublicKey))
	proxyHandler := newProxyHandler(upstreamURL, upstreamClient, secretStore, cfg.TenantID, logger)
	mux.Handle("/proxy", token.Gate(tokenVerifier, token.NewDPoPVerifier(), proxyHandler))

	srv := &http.Server{
		Addr:              cfg.Address(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
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
	logger.Info("proxy stopped", nil)
}

const maxUpstreamResponseSize = 1 << 20

func parseUpstreamURL(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" ||
		target.User != nil || target.RawQuery != "" || target.ForceQuery ||
		target.Fragment != "" || strings.Contains(raw, "#") || target.Opaque != "" {
		return nil, errors.New("UPSTREAM_URL must be an HTTPS URL without credentials, query, or fragment")
	}
	if port := target.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, errors.New("UPSTREAM_URL has an invalid port")
		}
	}
	return target, nil
}

func newUpstreamClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve upstream host: %w", err)
			}
			if len(ips) == 0 {
				return nil, errors.New("upstream host resolved to no addresses")
			}
			for _, resolved := range ips {
				if !isPublicUnicast(resolved.IP) {
					return nil, errors.New("upstream host resolved to a non-public address")
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func isPublicUnicast(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

func newProxyHandler(upstreamURL *url.URL, client *http.Client, secretStore *vault.Store, tenantID string, logger *logging.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if upstreamURL == nil || client == nil {
			http.Error(w, "proxy upstream is not configured", http.StatusServiceUnavailable)
			return
		}
		claims, ok := token.ClaimsFromRequest(r)
		if !ok || claims.TenantID != tenantID || !token.HasScope(claims, "demo", "read", "demo-secret") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		secret, err := secretStore.UseOnce(r.Context(), "demo-secret", tenantID)
		if err != nil || len(secret) == 0 {
			http.Error(w, "proxy secret unavailable", http.StatusInternalServerError)
			if err != nil {
				logger.Error("proxy secret fetch failed", map[string]any{"error": err.Error()})
			} else {
				logger.Error("proxy secret fetch failed", map[string]any{"error": "secret is empty"})
			}
			return
		}
		defer clear(secret)

		upstreamRequest, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL.String(), nil)
		if err != nil {
			http.Error(w, "upstream request failed", http.StatusBadGateway)
			logger.Error("proxy request construction failed", map[string]any{"error": err.Error()})
			return
		}
		upstreamRequest.Header.Set("Authorization", "Bearer "+string(secret))
		upstreamRequest.Header.Set("Accept", "application/json")

		response, err := client.Do(upstreamRequest)
		if err != nil {
			http.Error(w, "upstream request failed", http.StatusBadGateway)
			logger.Error("proxy upstream request failed", map[string]any{"error": err.Error()})
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, maxUpstreamResponseSize+1))
		if err != nil {
			http.Error(w, "upstream response failed", http.StatusBadGateway)
			logger.Error("proxy upstream response read failed", map[string]any{"error": err.Error()})
			return
		}
		if len(body) > maxUpstreamResponseSize {
			http.Error(w, "upstream response too large", http.StatusBadGateway)
			return
		}
		body = []byte(logging.Redact(string(body), string(secret)))
		contentType := response.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(response.StatusCode)
		if _, err := w.Write(body); err != nil {
			logger.Error("proxy response write failed", map[string]any{"error": err.Error()})
		}
	})
}
