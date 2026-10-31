package main

import "net/http"

// cspMiddleware injects a temporary Content-Security-Policy header allowing unsafe-inline scripts and styles.
func cspMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Header matches the temporary policy described in project docs.
        w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        next.ServeHTTP(w, r)
    })
}
