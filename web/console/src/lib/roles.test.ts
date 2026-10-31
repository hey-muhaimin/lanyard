import { describe, expect, it } from "vitest";
import { can } from "./roles";

describe("can", () => {
  it("lets auditors read but not write", () => {
    expect(can("auditor", "agents.read")).toBe(true);
    expect(can("auditor", "agents.write")).toBe(false);
    expect(can("auditor", "approvals.decide")).toBe(false);
  });
  it("limits approval decisions to admins and approvers", () => {
    expect(can("approver", "approvals.decide")).toBe(true);
    expect(can("security", "approvals.decide")).toBe(false);
  });
  it("limits revoking to admins and security", () => {
    expect(can("security", "revoke")).toBe(true);
    expect(can("agent_owner", "revoke")).toBe(false);
  });
  it("denies everyone when there is no role", () => {
    expect(can(undefined, "agents.read")).toBe(false);
  });
});
