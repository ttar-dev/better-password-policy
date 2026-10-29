import { describe, it, expect } from "vitest";
import { createHmac, hkdfSync } from "node:crypto";
import {
  LOCKOUT_MODEL,
  createDeviceId,
  deviceCookieBinding,
  lockoutDeviceKey,
  lockoutDeviceKeyPrefix,
  lockoutIdentifierKey,
} from "../../src/lockout-keys.ts";

const SECRET = "a-test-secret-with-more-than-thirty-two-characters";
const OTHER_SECRET = "another-test-secret-with-more-than-thirty-two-characters";

const expectedHmac = (secret: string, message: string): string => {
  const key = Buffer.from(
    hkdfSync("sha256", secret, "@ttar-dev/better-password-policy", "sign-in-lockout:v1", 32),
  );
  return createHmac("sha256", key).update(message).digest("hex");
};

describe("LOCKOUT_MODEL", () => {
  it("is the signInLockout model name", () => {
    expect(LOCKOUT_MODEL).toBe("signInLockout");
  });
});

describe("lockoutIdentifierKey", () => {
  it("is i1: followed by the independently computed HKDF-keyed HMAC of the canonical identifier", async () => {
    expect(await lockoutIdentifierKey(SECRET, "email:alice@example.com")).toBe(
      `i1:${expectedHmac(SECRET, "identifier:email:alice@example.com")}`,
    );
  });

  it("matches the independent computation for username and phone identifiers", async () => {
    expect(await lockoutIdentifierKey(SECRET, "username:alice")).toBe(
      `i1:${expectedHmac(SECRET, "identifier:username:alice")}`,
    );
    expect(await lockoutIdentifierKey(SECRET, "phone:+66812345678")).toBe(
      `i1:${expectedHmac(SECRET, "identifier:phone:+66812345678")}`,
    );
  });

  it("hashes non-ASCII input as UTF-8", async () => {
    expect(await lockoutIdentifierKey(SECRET, "username:สมชาย")).toBe(
      `i1:${expectedHmac(SECRET, "identifier:username:สมชาย")}`,
    );
  });

  it("is 67 lowercase characters and never contains the readable identifier", async () => {
    const key = await lockoutIdentifierKey(SECRET, "email:alice@example.com");
    expect(key).toMatch(/^i1:[0-9a-f]{64}$/);
    expect(key).toHaveLength(67);
    expect(key).not.toContain("alice");
    expect(key).not.toContain("example.com");
  });

  it("is deterministic across repeated and concurrent calls", async () => {
    const first = await lockoutIdentifierKey(SECRET, "email:alice@example.com");
    const results = await Promise.all([
      lockoutIdentifierKey(SECRET, "email:alice@example.com"),
      lockoutIdentifierKey(SECRET, "email:alice@example.com"),
      lockoutIdentifierKey(SECRET, "email:alice@example.com"),
    ]);
    expect(results).toEqual([first, first, first]);
  });

  it("produces a different key for a different secret", async () => {
    expect(await lockoutIdentifierKey(SECRET, "email:alice@example.com")).not.toBe(
      await lockoutIdentifierKey(OTHER_SECRET, "email:alice@example.com"),
    );
  });

  it("produces a different key for a different identifier", async () => {
    expect(await lockoutIdentifierKey(SECRET, "email:alice@example.com")).not.toBe(
      await lockoutIdentifierKey(SECRET, "email:bob@example.com"),
    );
  });

  it("does not equal the plain HMAC of the identifier under the raw secret", async () => {
    const plain = createHmac("sha256", SECRET).update("email:alice@example.com").digest("hex");
    expect(await lockoutIdentifierKey(SECRET, "email:alice@example.com")).not.toContain(plain);
  });
});

describe("lockoutDeviceKeyPrefix", () => {
  it("is d1: followed by the HMAC of the user id and a trailing colon", async () => {
    expect(await lockoutDeviceKeyPrefix(SECRET, "user-1")).toBe(
      `d1:${expectedHmac(SECRET, "user:user-1")}:`,
    );
  });

  it("has the shape d1:<64 hex>: and hides the user id", async () => {
    const prefix = await lockoutDeviceKeyPrefix(SECRET, "user-1");
    expect(prefix).toMatch(/^d1:[0-9a-f]{64}:$/);
    expect(prefix).not.toContain("user-1");
  });

  it("differs per user and per secret", async () => {
    const base = await lockoutDeviceKeyPrefix(SECRET, "user-1");
    expect(await lockoutDeviceKeyPrefix(SECRET, "user-2")).not.toBe(base);
    expect(await lockoutDeviceKeyPrefix(OTHER_SECRET, "user-1")).not.toBe(base);
  });

  it("is a different value from the identifier key of the same text", async () => {
    const prefix = await lockoutDeviceKeyPrefix(SECRET, "email:alice@example.com");
    const identifierKey = await lockoutIdentifierKey(SECRET, "email:alice@example.com");
    expect(prefix.slice(3, -1)).not.toBe(identifierKey.slice(3));
  });
});

describe("lockoutDeviceKey", () => {
  const deviceId = "0123456789abcdef0123456789abcdef";

  it("is the user prefix followed by the device id", async () => {
    expect(await lockoutDeviceKey(SECRET, "user-1", deviceId)).toBe(
      `d1:${expectedHmac(SECRET, "user:user-1")}:${deviceId}`,
    );
  });

  it("starts with the user prefix and has the shape d1:<64 hex>:<32 hex>", async () => {
    const key = await lockoutDeviceKey(SECRET, "user-1", deviceId);
    expect(key.startsWith(await lockoutDeviceKeyPrefix(SECRET, "user-1"))).toBe(true);
    expect(key).toMatch(/^d1:[0-9a-f]{64}:[0-9a-f]{32}$/);
    expect(key).toHaveLength(100);
  });

  it("differs per device, per user and per secret", async () => {
    const base = await lockoutDeviceKey(SECRET, "user-1", deviceId);
    expect(await lockoutDeviceKey(SECRET, "user-1", "f".repeat(32))).not.toBe(base);
    expect(await lockoutDeviceKey(SECRET, "user-2", deviceId)).not.toBe(base);
    expect(await lockoutDeviceKey(OTHER_SECRET, "user-1", deviceId)).not.toBe(base);
  });
});

describe("deviceCookieBinding", () => {
  const deviceId = "0123456789abcdef0123456789abcdef";

  it("is the HMAC of device, expiry, password epoch and user id joined by colons", async () => {
    expect(await deviceCookieBinding(SECRET, "user-1", deviceId, 1893456000, "1700000000000")).toBe(
      expectedHmac(SECRET, `device:${deviceId}:1893456000:1700000000000:user-1`),
    );
  });

  it("matches the independent computation when the password epoch is none", async () => {
    expect(await deviceCookieBinding(SECRET, "user-1", deviceId, 1893456000, "none")).toBe(
      expectedHmac(SECRET, `device:${deviceId}:1893456000:none:user-1`),
    );
  });

  it("is 64 lowercase hex characters", async () => {
    expect(await deviceCookieBinding(SECRET, "user-1", deviceId, 1893456000, "none")).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });

  it("changes when any bound input changes", async () => {
    const base = await deviceCookieBinding(SECRET, "user-1", deviceId, 1893456000, "1700000000000");
    expect(await deviceCookieBinding(OTHER_SECRET, "user-1", deviceId, 1893456000, "1700000000000")).not.toBe(base);
    expect(await deviceCookieBinding(SECRET, "user-2", deviceId, 1893456000, "1700000000000")).not.toBe(base);
    expect(await deviceCookieBinding(SECRET, "user-1", "f".repeat(32), 1893456000, "1700000000000")).not.toBe(base);
    expect(await deviceCookieBinding(SECRET, "user-1", deviceId, 1893456001, "1700000000000")).not.toBe(base);
    expect(await deviceCookieBinding(SECRET, "user-1", deviceId, 1893456000, "1700000000001")).not.toBe(base);
    expect(await deviceCookieBinding(SECRET, "user-1", deviceId, 1893456000, "none")).not.toBe(base);
  });

  it("is deterministic", async () => {
    expect(await deviceCookieBinding(SECRET, "user-1", deviceId, 1893456000, "none")).toBe(
      await deviceCookieBinding(SECRET, "user-1", deviceId, 1893456000, "none"),
    );
  });
});

describe("createDeviceId", () => {
  it("returns 32 lowercase hex characters", () => {
    expect(createDeviceId()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("returns a different value on every call", () => {
    const ids = new Set(Array.from({ length: 200 }, () => createDeviceId()));
    expect(ids.size).toBe(200);
  });
});
