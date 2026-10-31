import type { Agent, ApprovalRequest, Principal, RevokeScope, StoredEvent, Tenant } from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export const UNAUTHENTICATED_EVENT = "lanyard:unauthenticated";

// Same-origin only: the session cookie is HttpOnly + SameSite=Strict and the server checks Origin.
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
    if (response.status === 401 && typeof window !== "undefined") {
      window.dispatchEvent(new Event(UNAUTHENTICATED_EVENT));
    }
    throw new ApiError(response.status, message);
  }
  return (response.status === 204 ? undefined : await response.json()) as T;
}

const post = (body: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(body) });

export const api = {
  me: () => request<Principal>("/auth/me"),
  requestCode: (email: string) => request<{ status: string }>("/auth/request", post({ email })),
  verifyCode: (email: string, code: string) => request<Principal>("/auth/verify", post({ email, code })),
  logout: () => request<void>("/auth/logout", post({})),
  register: (input: { email: string; tenant_name: string }) => request<{ status: string }>("/auth/register", post(input)),

  tenant: {
    get: () => request<Tenant>("/admin/tenant"),
    update: (input: { name?: string; contact_email?: string | null }) =>
      request<Tenant>("/admin/tenant", { method: "PATCH", body: JSON.stringify(input) }),
  },
  agents: {
    list: () => request<Agent[]>("/admin/agents"),
    create: (agent: { id: string; owner_subject: string; public_key: string }) =>
      request<Agent>("/admin/agents", post(agent)),
  },
  approvals: {
    list: () => request<ApprovalRequest[]>("/approve"),
    decide: (id: string, status: "approved" | "denied", parameters: unknown) =>
      request<ApprovalRequest>("/approve", post({ id, status, parameters })),
  },
  revoke: (scope: RevokeScope, id: string) => request<{ status: string }>("/revoke", post({ [scope]: id })),
  events: {
    replay: () => request<StoredEvent[]>("/events/replay"),
  },
};
