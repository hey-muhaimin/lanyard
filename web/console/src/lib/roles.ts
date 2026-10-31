import type { Role } from "./types";

// Mirror of the permission matrix in the Go control plane (internal/auth/auth.go).
// The server is the authority; this only decides what to show.
export type Permission =
  | "agents.read"
  | "agents.write"
  | "connectors.write"
  | "approvals.read"
  | "approvals.request"
  | "approvals.decide"
  | "revoke"
  | "events.read"
  | "members.manage";

const matrix: Record<Permission, Role[]> = {
  "agents.read": ["admin", "security", "agent_owner", "approver", "auditor"],
  "agents.write": ["admin", "agent_owner"],
  "connectors.write": ["admin", "security"],
  "approvals.read": ["admin", "security", "approver", "auditor"],
  "approvals.request": ["admin", "agent_owner"],
  "approvals.decide": ["admin", "approver"],
  revoke: ["admin", "security"],
  "events.read": ["admin", "security", "agent_owner", "auditor"],
  "members.manage": ["admin"],
};

export function can(role: Role | undefined, permission: Permission): boolean {
  return role !== undefined && matrix[permission].includes(role);
}

export const roleLabels: Record<Role, string> = {
  admin: "Admin",
  security: "Security",
  agent_owner: "Agent owner",
  approver: "Approver",
  auditor: "Auditor",
};
