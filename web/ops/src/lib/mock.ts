import { ApiError } from "./errors";
import type { Api, OpsAction, OpsPrincipal, Tenant } from "./types";

// Fixture backend for UI work (NEXT_PUBLIC_OPS_MOCK=1). It mimics the rules the real API must enforce.
const me: OpsPrincipal = { email: "oncall.a@lanyard.dev", role: "ops_oncall", hardware_key: true };
const hour = 3_600_000;
const iso = (offset: number) => new Date(Date.now() + offset).toISOString();

const tenants: Tenant[] = [
  { id: "acme", name: "Acme", plan: "Team", agents: 12, grants: 128, state: "active" },
  { id: "northwind", name: "Northwind", plan: "Enterprise", agents: 64, grants: 940, state: "active" },
  { id: "initech", name: "Initech", plan: "Free", agents: 3, grants: 12, state: "over_quota" },
  { id: "globex", name: "Globex", plan: "Team", agents: 7, grants: 0, state: "suspended" },
];

let actions: OpsAction[] = [
  {
    id: "act-1", type: "suspend_tenant", tenant_id: "initech", requested_by: "oncall.b@lanyard.dev", status: "pending",
    reason: "Free plan far over quota and calling a blocked host. Suspending until the owner responds.",
    created_at: iso(-hour), expires_at: iso(hour),
  },
  {
    id: "act-0", type: "rotate_signing_key", tenant_id: "*", requested_by: "admin@lanyard.dev", status: "executed",
    decided_by: "oncall.b@lanyard.dev", reason: "Quarterly signing key rotation.", created_at: iso(-72 * hour), expires_at: iso(-71 * hour),
  },
];

const wait = <T>(value: T): Promise<T> => new Promise((resolve) => setTimeout(() => resolve(structuredClone(value)), 150));

export const mock: Api = {
  me: () => wait(me),
  logout: () => wait(undefined),
  health: () => wait({ proxy_p99_ms: 31, revocation_lag_s: 1.8, event_backlog: 0, uptime_30d_pct: 99.98, updated_at: iso(0) }),
  tenants: { list: () => wait(tenants) },
  actions: {
    list: () => wait(actions),
    async create(input) {
      const action: OpsAction = {
        id: `act-${actions.length + 1}`, ...input, requested_by: me.email, status: "pending",
        created_at: iso(0), expires_at: iso(hour),
      };
      actions = [action, ...actions];
      return wait(action);
    },
    async decide(id, status) {
      const action = actions.find((item) => item.id === id);
      if (!action) throw new ApiError(404, "Action not found.");
      if (action.requested_by === me.email) throw new ApiError(403, "You cannot decide an action you requested.");
      if (action.status !== "pending") throw new ApiError(409, "This action was already decided.");
      action.status = status === "approved" ? "executed" : "denied";
      action.decided_by = me.email;
      return wait(action);
    },
  },
};
