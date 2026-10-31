export type Role = "admin" | "security" | "agent_owner" | "approver" | "auditor";

export interface Principal {
  tenant_id: string;
  member_id: string;
  email: string;
  role: Role;
}

export interface Tenant {
  id: string;
  name: string;
  contact_email: string | null;
  status: string;
  plan: string;
  created_at: string;
}

export interface Agent {
  id: string;
  tenant_id: string;
  owner_subject: string;
  public_key: string;
  status: string;
}

export interface ApprovalRequest {
  id: string;
  task_id: string;
  chain_id: string;
  requester_id: string;
  requested_by?: string;
  action: string;
  parameters: unknown;
  status: "pending" | "approved" | "denied" | "expired" | string;
  expires_at: string;
  decided_by?: string;
}

export interface StoredEvent {
  seq?: number;
  payload?: Record<string, unknown>;
  hash?: string;
  prev_hash?: string;
}

export type RevokeScope = "agent_id" | "task_id" | "chain_id" | "token_id";
