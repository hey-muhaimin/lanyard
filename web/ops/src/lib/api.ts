import { ApiError } from "./errors";
import { mock } from "./mock";
import type { Api } from "./types";

export { ApiError };
export const UNAUTHENTICATED_EVENT = "lanyard-ops:unauthenticated";
export const isMock = process.env.NEXT_PUBLIC_OPS_MOCK === "1";

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
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

// The /ops/* endpoints are a proposal: the control plane does not serve them yet (see README).
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
