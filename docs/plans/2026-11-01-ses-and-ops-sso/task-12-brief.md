# Task 12 — Ops callback, `/ops/auth/me`, `/ops/auth/logout`

**Where this fits:** finishes the sign-in loop. Consumes the single-use state, exchanges the
code, verifies the ID token, enforces the `staff` group, provisions/validates the member, and
issues the ops session cookie. `/ops/auth/me` and logout complete the UI contract.

**Depends on:** 08 (`ExchangeCode`, `Verifier`), 09 (`opsstore`), 11 (`opsSSO`, `stateStore`,
`opsPrincipal`).
**Blocks:** 14.

## Files

- `cmd/controlplane/ops_auth.go` (edit — append handlers and cookie helpers)
- `cmd/controlplane/ops_auth_test.go` (edit — fill in fakes, add tests)

## Failure map (fail closed — no cookie in any of these rows)

| Condition | Status | Body |
|---|---|---|
| non-GET callback | 405 | `{"error":"method not allowed"}` |
| `error` query param present | 400 | `{"error":"invalid sign-in request"}` |
| missing `code` or `state` | 400 | `{"error":"invalid sign-in request"}` |
| state unknown / already used / expired | 400 | `{"error":"invalid sign-in request"}` |
| code exchange fails | 502 | `{"error":"sign-in failed"}` |
| ID token verification fails | 401 | `{"error":"sign-in failed"}` |
| `cognito:groups` lacks `staffGroup` | 403 | `{"error":"not authorized"}` |
| ID token email missing/invalid | 403 | `{"error":"not authorized"}` |
| `ProvisionMember` → `opsstore.ErrIdentityConflict` | 403 | `{"error":"not authorized"}` |
| provisioned member `Status != "active"` | 403 | `{"error":"not authorized"}` |
| `CreateSession` fails | 500 | `{"error":"sign-in failed"}` |
| success | 303 | `Location: /`, session cookie |

Never include the code, the ID token, the client secret, or upstream error text in a
response body. Log at most the error and the member id — **never** the email.

## Code to append to `cmd/controlplane/ops_auth.go`

Add imports: `errors`, `slices`, `github.com/example/lanyard/internal/opsstore`.

```go
// callback completes a sign-in: single-use state, code exchange, ID-token
// verification, staff-group check, member provisioning, then a session cookie.
func (a *opsSSO) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	query := r.URL.Query()
	if query.Get("error") != "" {
		// The description may contain account identifiers; log only the code.
		a.logger.Info("ops sign-in rejected by Cognito", "error_code", query.Get("error"))
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid sign-in request"})
		return
	}
	state, code := query.Get("state"), query.Get("code")
	if state == "" || code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid sign-in request"})
		return
	}
	verifier, ok := a.states.take(state)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid sign-in request"})
		return
	}

	idToken, err := staffsso.ExchangeCode(r.Context(), a.client, a.sso, a.redirect, code, verifier)
	if err != nil {
		a.logger.Error("exchange ops authorization code", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "sign-in failed"})
		return
	}
	identity, err := a.verifier.Verify(r.Context(), idToken)
	if err != nil {
		a.logger.Error("verify ops ID token", "error", err)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "sign-in failed"})
		return
	}
	if !slices.Contains(identity.Groups, a.sso.StaffGroup) {
		a.logger.Info("ops sign-in rejected: not in staff group")
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "not authorized"})
		return
	}
	email := normalizeEmail(identity.Email)
	if !validEmail(email) {
		a.logger.Info("ops sign-in rejected: unusable email claim")
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "not authorized"})
		return
	}

	member, err := a.store.ProvisionMember(r.Context(), email, identity.Subject)
	if err != nil {
		if errors.Is(err, opsstore.ErrIdentityConflict) {
			a.logger.Info("ops sign-in rejected: identity conflict")
		} else {
			a.logger.Error("provision ops member", "error", err)
		}
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "not authorized"})
		return
	}
	if member.Status != "active" {
		a.logger.Info("ops sign-in rejected: member not active", "member_id", member.ID)
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "not authorized"})
		return
	}

	token, err := newSessionToken()
	if err != nil {
		a.logger.Error("generate ops session token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "sign-in failed"})
		return
	}
	if err := a.store.CreateSession(r.Context(), hashValue(token), member.ID, time.Now().Add(a.cfg.SessionTTL), identity.HardwareKey); err != nil {
		a.logger.Error("create ops session", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "sign-in failed"})
		return
	}
	a.setSessionCookie(w, token)
	a.logger.Info("ops sign-in", "member_id", member.ID, "role", member.Role, "hardware_key", identity.HardwareKey)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// me returns the authenticated staff principal. The session middleware has
// already validated the cookie; this only renders it.
func (a *opsSSO) me(w http.ResponseWriter, r *http.Request) {
	principal, ok := opsPrincipalFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"email":        principal.Email,
		"role":         principal.Role,
		"hardware_key": principal.HardwareKey,
	})
}

// logout deletes the session behind the cookie. It is idempotent.
func (a *opsSSO) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if cookie, err := r.Cookie(opsSessionCookie); err == nil && strings.TrimSpace(cookie.Value) != "" {
		if err := a.store.EndSession(r.Context(), hashValue(cookie.Value)); err != nil {
			a.logger.Error("end ops session", "error", err)
		}
	}
	a.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (a *opsSSO) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     opsSessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(a.cfg.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *opsSSO) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     opsSessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}
```

## Tests — extend `cmd/controlplane/ops_auth_test.go`

The fakes (`fakeOpsStore`, `fakeVerifier`) and their methods are declared in task 11 —
reuse them unchanged. Each callback test seeds `sso.states` and `verifier.identity`.

Helper for a working token endpoint:

```go
func fakeTokenEndpoint(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"fake-id-token"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}
```

In each callback test, point the client at the fake endpoint and seed a state:

```go
sso, store, verifier := testOpsSSO(t)
endpoint := fakeTokenEndpoint(t)
sso.sso.HostedUIDomain = endpoint.URL
sso.client = endpoint.Client()
state := "state-under-test"
sso.states.put(state, "verifier-under-test")
verifier.identity = staffsso.Identity{Subject: "sub-1", Email: "Staff@LinkedQueue.Cloud",
	Groups: []string{"staff"}, HardwareKey: true}
```

Tests:

1. `TestOpsCallbackHappyPath` — GET
   `/ops/auth/callback/?code=abc&state=<state>`; expect `303`, `Location: /`,
   `Cache-Control: no-store`; exactly one `Set-Cookie` named `lanyard_ops_session` with
   `Path=/`, `HttpOnly`, `SameSite=Strict`, `Secure`, `Max-Age=3600`, non-empty value;
   `store.sessions[string(hashValue(cookieValue))]` exists with `HardwareKey == true` and
   `MemberID == "member-1"`; `store.members["staff@linkedqueue.cloud"].CognitoSub == "sub-1"`
   (email normalised to lower case).
2. `TestOpsCallbackRejectsUnknownState` — `state=never-issued` → 400, no `Set-Cookie`,
   `len(store.members) == 0`.
3. `TestOpsCallbackStateIsSingleUse` — run the happy path, then repeat the same state →
   second response is 400 with no cookie.
4. `TestOpsCallbackRejectsNonStaff` — `Groups: []string{"customers"}` → 403
   `{"error":"not authorized"}`, no cookie, no member provisioned.
5. `TestOpsCallbackRejectsSuspendedMember` — pre-seed
   `store.members["staff@linkedqueue.cloud"] = opsstore.Member{ID:"member-1", Email:..., Role:"ops_support", Status:"suspended", CognitoSub:"sub-1"}`
   → 403, no cookie, `len(store.sessions) == 0`.
6. `TestOpsCallbackRejectsIdentityConflict` — `store.provErr = opsstore.ErrIdentityConflict`
   → 403, no cookie.
7. `TestOpsCallbackRejectsVerificationFailure` — `verifier.err = errors.New("bad signature")`
   → 401 `{"error":"sign-in failed"}`, no cookie, body does not contain "bad signature".
8. `TestOpsCallbackRejectsExchangeFailure` — point `HostedUIDomain` at an `httptest` server
   returning 400; → 502, no cookie.
9. `TestOpsCallbackRejectsErrorParam` — `?error=access_denied&state=<state>` → 400, no
   cookie.
10. `TestOpsCallbackRejectsMissingParams` — `?code=abc` (no state) and `?state=x` (no code)
    → 400, no cookie.
11. `TestOpsCallbackMethodNotAllowed` — POST → 405.
12. `TestOpsCallbackRejectsInvalidEmailClaim` — identity email `"not-an-email"` → 403, no
    cookie.
13. `TestOpsLogoutDeletesSession` — seed `store.sessions[hash]`, send POST with the cookie;
    expect 204, `EndSession` removed it, and `Set-Cookie` is the clearing cookie
    (`Max-Age=0` after parsing — Go renders `MaxAge: -1` as `Max-Age=0`).
14. `TestOpsLogoutWithoutCookie` — POST with no cookie → 204, no error, clearing cookie set.
15. `TestOpsLogoutMethodNotAllowed` — GET → 405.
16. `TestOpsMeReturnsPrincipal` — wrap `sso.me` with a handler that puts
    `opsPrincipal{MemberID:"member-1", Email:"staff@linkedqueue.cloud", Role:"ops_oncall", HardwareKey:true}`
    into the context via `context.WithValue(r.Context(), opsSessionKey{}, principal)`;
    expect 200 `{"email":"staff@linkedqueue.cloud","role":"ops_oncall","hardware_key":true}`.
17. `TestOpsMeRequiresPrincipal` — no context value → 401
    `{"error":"authentication required"}`.

## Verification

```sh
go test ./cmd/controlplane/ -run 'OpsCallback|OpsLogout|OpsMe' -v
go test ./... && go build ./... && go vet ./...
```

The routes are mounted in task 14; the tests here call the handlers directly.
