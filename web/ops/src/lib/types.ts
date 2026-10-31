export type OpsRole = "ops_admin" | "ops_oncall" | "ops_support";

export interface OpsPrincipal {
  email: string;
  role: OpsRole;
  /** True only when the staff sign-in used a hardware security key. Write actions require it. */
  hardware_key: boolean;
}

export interface Health {
  proxy_p99_ms: number;
  revocation_lag_s: number;
  event_backlog: number;
  uptime_30d_pct: number;
  updated_at: string;
}

export interface Tenant {
  id: string;
  name: string;
  plan: string;
  agents: number;
  grants: number;
  state: "active" | "suspended" | "over_quota";
}

export type ActionType = "suspend_tenant" | "rotate_signing_key" | "view_as_customer";

export interface OpsAction {
  id: string;
  type: ActionType;
  /** Tenant id, or "*" for platform-wide actions such as rotating the signing key. */
  tenant_id: string;
  reason: string;
  requested_by: string;
  status: "pending" | "executed" | "denied" | "expired";
  decided_by?: string;
  created_at: string;
  expires_at: string;
}

export interface Api {
  me(): Promise<OpsPrincipal>;
  logout(): Promise<void>;
  health(): Promise<Health>;
  tenants: { list(): Promise<Tenant[]> };
  actions: {
    list(): Promise<OpsAction[]>;
    create(input: { type: ActionType; tenant_id: string; reason: string }): Promise<OpsAction>;
    decide(id: string, status: "approved" | "denied"): Promise<OpsAction>;
  };
}
