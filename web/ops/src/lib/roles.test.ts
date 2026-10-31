import { describe, expect, it } from "vitest";
import { can } from "./roles";

describe("can", () => {
  it("makes support read-only", () => {
    expect(can("ops_support", "tenants.read")).toBe(true);
    expect(can("ops_support", "actions.request")).toBe(false);
    expect(can("ops_support", "actions.decide")).toBe(false);
  });
  it("lets on-call engineers request and decide", () => {
    expect(can("ops_oncall", "actions.request")).toBe(true);
    expect(can("ops_oncall", "actions.decide")).toBe(true);
  });
  it("denies everything without a role", () => {
    expect(can(undefined, "health.read")).toBe(false);
  });
});
