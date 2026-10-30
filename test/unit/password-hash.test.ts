import { describe, it, expect, vi } from "vitest";
import { isPasswordReused } from "../../src/password-hash.ts";

const PASSWORD = "pw";

const unreadable = new Error("Invalid password hash");

const verify = vi.fn(async ({ hash, password }: { hash: string; password: string }) => {
  if (hash === "bad") {
    throw unreadable;
  }
  return hash === `ok:${password}`;
});

describe("isPasswordReused", () => {
  it("skips a hash the verifier throws on, reports it once and keeps checking", async () => {
    const onUnreadableHash = vi.fn();

    const reused = await isPasswordReused(PASSWORD, ["bad", "ok:pw"], verify, onUnreadableHash);

    expect(reused).toBe(true);
    expect(onUnreadableHash).toHaveBeenCalledTimes(1);
    expect(onUnreadableHash).toHaveBeenCalledWith(unreadable);
  });

  it("is false when every hash throws", async () => {
    const onUnreadableHash = vi.fn();

    const reused = await isPasswordReused(PASSWORD, ["bad", "bad"], verify, onUnreadableHash);

    expect(reused).toBe(false);
    expect(onUnreadableHash).toHaveBeenCalledTimes(2);
  });

  it("stops at the first match", async () => {
    const onUnreadableHash = vi.fn();

    const reused = await isPasswordReused(PASSWORD, ["ok:pw", "bad"], verify, onUnreadableHash);

    expect(reused).toBe(true);
    expect(onUnreadableHash).not.toHaveBeenCalled();
  });
});
