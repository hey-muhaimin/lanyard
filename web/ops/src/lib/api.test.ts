import { afterEach, describe, expect, it, vi } from "vitest";

const DEFAULT_API_BASE = "https://api.linkedqueue.cloud";
const ENV_KEY = "NEXT_PUBLIC_API_BASE";

// The module reads the env var at import time, so reload it after each env change.
async function importApiBase(): Promise<string> {
  vi.resetModules();
  const { API_BASE } = await import("./api");
  return API_BASE;
}

describe("API_BASE", () => {
  const original = process.env[ENV_KEY];

  afterEach(() => {
    if (original === undefined) delete process.env[ENV_KEY];
    else process.env[ENV_KEY] = original;
    vi.resetModules();
  });

  it("falls back to the default when NEXT_PUBLIC_API_BASE is undefined", async () => {
    delete process.env[ENV_KEY];
    await expect(importApiBase()).resolves.toBe(DEFAULT_API_BASE);
  });

  it("falls back to the default when NEXT_PUBLIC_API_BASE is an empty string", async () => {
    process.env[ENV_KEY] = "";
    await expect(importApiBase()).resolves.toBe(DEFAULT_API_BASE);
  });
});
