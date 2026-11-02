import { ApiError } from "./errors";
import { mock } from "./mock";
import type { Api } from "./types";

export { ApiError };
export const UNAUTHENTICATED_EVENT = "lanyard-ops:unauthenticated";
export const isMock = process.env.NEXT_PUBLIC_OPS_MOCK === "1";
// Absolute origin of the control plane's public API (ALB behind api.linkedqueue.cloud).
// The static console is served from a different host, so requests must not be root-relative.
const rawBase = (process.env.NEXT_PUBLIC_API_BASE || "").trim();
export const API_BASE = rawBase ? rawBase.replace(/\/*$/, "") : "https://api.linkedqueue.cloud";

// Only the live client calls request(); mock mode short-circuits at the `api` export below.
async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const url = isMock ? path : `${API_BASE}${path}`;
  const response = await fetch(url, {
    // Cross-origin but same-site, so session cookies still ride along.
    credentials: "include",
    ...init,
    headers: { "Content-Type": "application/json", ...init.headers },
  });
  if (!response.ok) {
    let message = response.statusText || "Request failed";
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      /* non-JSON error body */
    }
    if (response.status === 401 && typeof window !== "undefined") window.dispatchEvent(new Event(UNAUTHENTICATED_EVENT));
    throw new ApiError(response.status, message);
  }
  return (response.status === 204 ? undefined : await response.json()) as T;
}

const post = (body: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(body) });

// The /ops/* endpoints are served by the Go control‑plane on the API host (api.linkedqueue.cloud).
const live: Api = {
  me: () => request("/ops/auth/me"),
  logout: () => request("/ops/auth/logout", post({})),
  health: () => request("/ops/health"),
  tenants: { list: () => request("/ops/tenants") },
  actions: {
    list: () => request("/ops/actions"),
    create: (input) => request("/ops/actions", post(input)),
    decide: (id, status) => request(`/ops/actions/${encodeURIComponent(id)}/decide`, post({ status })),
  },
};

export const api: Api = isMock ? mock : live;
