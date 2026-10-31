import type { OpsRole } from "./types";

// Mirror of the server's rules, used only to decide what to show. The server enforces them,
// including that nobody can decide an action they requested.
export type OpsPermission = "health.read" | "tenants.read" | "actions.read" | "actions.request" | "actions.decide";

const matrix: Record<OpsPermission, OpsRole[]> = {
  "health.read": ["ops_admin", "ops_oncall", "ops_support"],
  "tenants.read": ["ops_admin", "ops_oncall", "ops_support"],
  "actions.read": ["ops_admin", "ops_oncall", "ops_support"],
  "actions.request": ["ops_admin", "ops_oncall"],
  "actions.decide": ["ops_admin", "ops_oncall"],
};

export function can(role: OpsRole | undefined, permission: OpsPermission): boolean {
  return role !== undefined && matrix[permission].includes(role);
}

export const roleLabels: Record<OpsRole, string> = {
  ops_admin: "Ops admin",
  ops_oncall: "On-call engineer",
  ops_support: "Support",
};
