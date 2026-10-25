package token

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"time"
)

type claimsContextKey struct{}

func ClaimsFromRequest(r *http.Request) (Claims, bool) {
	claims, ok := r.Context().Value(claimsContextKey{}).(Claims)
	return claims, ok
}

func Gate(verifier *Verifier, proofs *DPoPVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verifier == nil || proofs == nil {
			http.Error(w, "proxy authentication is not configured", http.StatusServiceUnavailable)
			return
		}
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		now := time.Now()
		claims, err := verifier.Verify(fields[1], now)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := proofs.Verify(r.Header.Get("DPoP"), fields[1], claims.Cnf["jkt"], r.Method, requestTargetURL(r), now); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsContextKey{}, claims)))
	})
}

func requestTargetURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

func JWKSHandler(keyID string, publicKey ed25519.PublicKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		encoded, err := PublicJWKS(keyID, publicKey)
		if err != nil {
			http.Error(w, "signing key is not configured", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encoded)
	})
}

func HasScope(claims Claims, connector, action, resource string) bool {
	for _, entry := range claims.Scope {
		if entry.Connector == connector && entry.Action == action && strings.Trim(entry.Resource, "/") != "" &&
			(resource == entry.Resource || strings.HasPrefix(resource, strings.TrimSuffix(entry.Resource, "/")+"/")) {
			return true
		}
	}
	return false
}
