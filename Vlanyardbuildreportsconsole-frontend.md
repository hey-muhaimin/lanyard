
## Fixes applied

1. `src/components/app-sidebar.tsx` — Removed `permission: "members.manage"` from the Settings nav item so non-admins can reach the read-only settings page; other items unchanged.
2. `src/app/(auth)/register/page.tsx` — Implemented inline 6-digit verification on the success view using `InputOTP` (same as login), stores submitted email in state, calls `api.verifyCode(email, code)` on complete/Verify, `router.push("/overview/")` on success, shows inline `role="alert"` on failure with retry, added secondary link to `/login/`, no `useSearchParams`. Also added `disabled={busy}` on inputs, early return if busy, `role="status"` on success container.
3. Replaced placeholder `you@company.com` with `alice@example.com` in `src/components/login-form.tsx` and `src/app/(console)/agents/page.tsx`.
4. `src/app/(console)/settings/page.tsx` — Builds PATCH body with only changed trimmed fields (diffs against loaded tenant; sends `contact_email: null` when cleared). If nothing changed, shows "No changes to save" and does not call API.
5. `src/app/(auth)/register/page.tsx` (minor) — `disabled={busy}` on inputs, early return if busy, `role="status"` on success container.
6. `src/app/(console)/settings/page.tsx` (minor) — `readOnly={!canManage}` on both inputs, `aria-describedby` linking disabled-Save note to button, renders raw status value with fallback "Unknown".
7. `src/lib/types.ts` — `contact_email: string | null`.
