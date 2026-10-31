# Console frontend: registration + tenant profile

## Status

Complete. Typecheck, tests, and static export all pass.

## Files changed

- `web/console/src/lib/types.ts` — added `Tenant` (`id`, `name`, `contact_email`, `status`, `plan`, `created_at`).
- `web/console/src/lib/api.ts` — added `register` and `tenant.get` / `tenant.update`; reused the existing `request`, `post`, `ApiError`, and 401 `UNAUTHENTICATED_EVENT` handling unchanged.
- `web/console/src/components/login-form.tsx` — added the "Create an account" link to `/register/` under the email step.
- `web/console/src/app/(console)/settings/page.tsx` — replaced the `ComingSoon` stub with the tenant profile form and read-only tenant details.

## Files created

- `web/console/src/app/(auth)/register/page.tsx` — client register page using the login page's Card layout (form left, primary product panel right). Fields: work email, organisation name. Success state says a sign-in code was issued for the email and links to `/login/`.

## Assumed request/response shapes

Taken verbatim from `build/console-spec.md` and the task brief:

- `POST /auth/register` body `{ email, tenant_name }` → `202 {"status":"ok"}`. Client treats any 2xx as success and does not read the body besides typing it as `{ status: string }`.
- `GET /admin/tenant` → `{ id, name, contact_email, status, plan, created_at }` (`Tenant`, all strings; `contact_email` may be empty).
- `PATCH /admin/tenant` body `{ name?, contact_email? }` → updated `Tenant`. The form always sends both trimmed fields (`contact_email: ""` when cleared), which is the contract's optional-field shape.
- Errors: non-2xx responses with an optional `{ error }` body, surfaced through the existing `ApiError` path.

## States covered

Register:
- idle/disabled (`Create account` disabled until both trimmed fields are non-empty, and while pending)
- loading (`Creating…`, inputs/button disabled)
- error (inline `role="alert"` paragraph with the API message)
- success (confirmation view with the email and a `/login/` link)

Settings:
- loading (`RowsSkeleton`)
- error (`ErrorState` with retry, reusing `states.tsx`)
- empty (`EmptyState` with retry if the API returns no profile)
- no-access (non-`admin` users still see the profile and read-only rows; Save is disabled and an explanatory note is shown)
- inline validation: name required, trimmed 1–100 chars; contact email optional but must contain `@` when non-empty
- pending: inputs disabled, button shows `Saving…`
- save failure: inline `role="alert"` message with the API error
- save success: `toast.success("Workspace profile saved")` then `reload()` of the resource

All user/server text is rendered as React children; there is no `dangerouslySetInnerHTML` or raw HTML injection.

## Verification

`cd web/console && npm run typecheck`

```text
> lanyard-console@0.1.0 typecheck
> tsc --noEmit
```

`cd web/console && npm test`

```text
> lanyard-console@0.1.0 test
> vitest run

 RUN  v3.2.7  V:/lanyard/web/console

 ✓ src/lib/roles.test.ts (4 tests) 3ms

 Test Files  1 passed (1)
      Tests  4 passed (4)
   Duration  770ms
```

`cd web/console && npm run build:static`

```text
> lanyard-console@0.1.0 build:static
> cross-env NEXT_OUTPUT=export next build

▲ Next.js 16.4.3 (Turbopack)
- Environments: .env.local
✓ Running next.config.mjs took 23ms

  Creating an optimized production build ...
✓ Compiled successfully in 1223ms
  Running TypeScript ...
  Finished TypeScript in 2.8s ...
✓ Generating static pages using 7 workers (13/13) in 537ms
  Finalizing page optimization ...

Route (app)
┌ ○ /
├ ○ /_not-found
├ ○ /activity
├ ○ /agents
├ ○ /approvals
├ ○ /audit
├ ○ /connectors
├ ○ /login
├ ○ /overview
├ ○ /policies
├ ○ /register
└ ○ /settings

○  (Static)  prerendered as static content
```

## Not verified

- No live Go control plane was running, so `/auth/register` and `/admin/tenant` were not exercised end to end. The UI is wired to the frozen contract above.
- No browser/visual pass was run. Recommended for Vision: `/register` success state at mobile and desktop widths, and `/settings` as a non-admin role to confirm the profile still renders and Save is disabled.

## Concerns

- Pre-existing: `web/console/src/components/login-form.tsx` (and the agents sheet) contain a literal `you@company.com` placeholder in the email field. The new register page uses `placeholder="Your work email"` instead, but I left the login file's placeholder alone because it is outside this task's scope. It should be cleaned up before shipping.
- Per the brief, Settings loads for every signed-in role and only the Save button is gated. Non-admin users can type in the fields but cannot submit; this is deliberate per "gate only the Save button". If the desired UX is fully read-only inputs for non-admins, that is a one-line change (`readOnly={!canManage}`).
- `created_at` is rendered as the raw API string in IBM Plex Mono to avoid locale-dependent server/client hydration differences.
