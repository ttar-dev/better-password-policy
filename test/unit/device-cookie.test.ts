import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { createHmac, hkdfSync } from "node:crypto";
import {
  DEVICE_COOKIE_NAME,
  formatDeviceCookieValue,
  issueDeviceCookie,
  parseDeviceCookieValue,
  passwordEpochOf,
  readDeviceCookie,
} from "../../src/device-cookie.ts";
import type { SignInHookContext } from "../../src/device-cookie.ts";

const SECRET = "a-test-secret-with-more-than-thirty-two-characters";
const DEVICE_ID = "0123456789abcdef0123456789abcdef";
const BINDING = "ab".repeat(32);

const expectedBinding = (
  deviceId: string,
  expiresAt: number,
  passwordEpoch: string,
  userId: string,
): string => {
  const key = Buffer.from(
    hkdfSync("sha256", SECRET, "@ttar-dev/better-password-policy", "sign-in-lockout:v1", 32),
  );
  return createHmac("sha256", key)
    .update(`device:${deviceId}:${expiresAt}:${passwordEpoch}:${userId}`)
    .digest("hex");
};

describe("DEVICE_COOKIE_NAME", () => {
  it("is password_policy_device", () => {
    expect(DEVICE_COOKIE_NAME).toBe("password_policy_device");
  });
});

describe("formatDeviceCookieValue", () => {
  it("joins version, device id, expiry and binding with colons", () => {
    expect(
      formatDeviceCookieValue({ deviceId: DEVICE_ID, expiresAt: 1893456000, binding: BINDING }),
    ).toBe(`v1:${DEVICE_ID}:1893456000:${BINDING}`);
  });
});

describe("parseDeviceCookieValue", () => {
  it("round-trips a formatted value", () => {
    const value = { deviceId: DEVICE_ID, expiresAt: 1893456000, binding: BINDING };
    expect(parseDeviceCookieValue(formatDeviceCookieValue(value))).toEqual(value);
  });

  it("returns expiresAt as a number", () => {
    const parsed = parseDeviceCookieValue(`v1:${DEVICE_ID}:1893456000:${BINDING}`);
    expect(parsed?.expiresAt).toBe(1893456000);
    expect(typeof parsed?.expiresAt).toBe("number");
  });

  it("accepts the smallest and the largest allowed expiry", () => {
    expect(parseDeviceCookieValue(`v1:${DEVICE_ID}:1:${BINDING}`)?.expiresAt).toBe(1);
    expect(parseDeviceCookieValue(`v1:${DEVICE_ID}:999999999999:${BINDING}`)?.expiresAt).toBe(
      999999999999,
    );
  });

  it.each([
    ["an empty string", ""],
    ["another version", `v2:${DEVICE_ID}:1893456000:${BINDING}`],
    ["a missing version", `${DEVICE_ID}:1893456000:${BINDING}`],
    ["an uppercase version", `V1:${DEVICE_ID}:1893456000:${BINDING}`],
    ["an uppercase device id", `v1:${DEVICE_ID.toUpperCase()}:1893456000:${BINDING}`],
    ["an uppercase binding", `v1:${DEVICE_ID}:1893456000:${BINDING.toUpperCase()}`],
    ["a non-hex device id", `v1:${"g".repeat(32)}:1893456000:${BINDING}`],
    ["a device id that is one character short", `v1:${DEVICE_ID.slice(1)}:1893456000:${BINDING}`],
    ["a device id that is one character long", `v1:${DEVICE_ID}0:1893456000:${BINDING}`],
    ["a binding that is one character short", `v1:${DEVICE_ID}:1893456000:${BINDING.slice(1)}`],
    ["a binding that is one character long", `v1:${DEVICE_ID}:1893456000:${BINDING}0`],
    ["an extra trailing segment", `v1:${DEVICE_ID}:1893456000:${BINDING}:extra`],
    ["an extra leading segment", `x:v1:${DEVICE_ID}:1893456000:${BINDING}`],
    ["a missing binding", `v1:${DEVICE_ID}:1893456000`],
    ["a non-numeric expiry", `v1:${DEVICE_ID}:soon:${BINDING}`],
    ["an empty expiry", `v1:${DEVICE_ID}::${BINDING}`],
    ["a negative expiry", `v1:${DEVICE_ID}:-1893456000:${BINDING}`],
    ["a fractional expiry", `v1:${DEVICE_ID}:1.5:${BINDING}`],
    ["an exponent expiry", `v1:${DEVICE_ID}:1e9:${BINDING}`],
    ["a zero expiry", `v1:${DEVICE_ID}:0:${BINDING}`],
    ["an expiry with a leading zero", `v1:${DEVICE_ID}:01893456000:${BINDING}`],
    ["an expiry of thirteen digits", `v1:${DEVICE_ID}:1000000000000:${BINDING}`],
    ["a trailing newline", `v1:${DEVICE_ID}:1893456000:${BINDING}\n`],
    ["a leading space", ` v1:${DEVICE_ID}:1893456000:${BINDING}`],
  ])("returns null for %s", (_name, raw) => {
    expect(parseDeviceCookieValue(raw)).toBeNull();
  });
});

describe("passwordEpochOf", () => {
  it("is the millisecond timestamp of a Date passwordChangedAt", () => {
    expect(passwordEpochOf({ passwordChangedAt: new Date("2025-01-02T03:04:05.678Z") })).toBe(
      String(Date.parse("2025-01-02T03:04:05.678Z")),
    );
  });

  it("is the millisecond timestamp of an ISO string passwordChangedAt", () => {
    expect(passwordEpochOf({ passwordChangedAt: "2025-01-02T03:04:05.678Z" })).toBe(
      String(Date.parse("2025-01-02T03:04:05.678Z")),
    );
  });

  it("is identical for the same instant given as a Date or as an ISO string", () => {
    const iso = "2025-06-07T08:09:10.111Z";
    expect(passwordEpochOf({ passwordChangedAt: new Date(iso) })).toBe(
      passwordEpochOf({ passwordChangedAt: iso }),
    );
  });

  it("differs when the password changed at another instant", () => {
    expect(passwordEpochOf({ passwordChangedAt: new Date(1000) })).not.toBe(
      passwordEpochOf({ passwordChangedAt: new Date(1001) }),
    );
  });

  it.each([
    ["null", null],
    ["undefined", undefined],
    ["an unparsable string", "not a date"],
    ["an invalid Date", new Date(Number.NaN)],
    ["an empty string", ""],
  ])("is none when passwordChangedAt is %s", (_name, value) => {
    expect(passwordEpochOf({ passwordChangedAt: value })).toBe("none");
  });

  it("is none when the user has no passwordChangedAt key", () => {
    expect(passwordEpochOf({ id: "user-1" })).toBe("none");
  });
});

interface FakeContextOptions {
  signed?: unknown;
  getSignedCookieError?: Error;
}

const createFakeContext = (options: FakeContextOptions = {}) => {
  const createAuthCookie = vi.fn((name: string, attributes?: { maxAge?: number }) => ({
    name: `better-auth.${name}`,
    attributes: { httpOnly: true, sameSite: "lax", path: "/", ...attributes },
  }));
  const getSignedCookie = vi.fn(async () => {
    if (options.getSignedCookieError) throw options.getSignedCookieError;
    return options.signed;
  });
  const setSignedCookie = vi.fn(async () => undefined);
  const ctx = {
    context: { secret: SECRET, createAuthCookie },
    getSignedCookie,
    setSignedCookie,
  } as unknown as SignInHookContext;
  return { ctx, createAuthCookie, getSignedCookie, setSignedCookie };
};

describe("readDeviceCookie", () => {
  const NOW_MS = Date.parse("2030-01-01T00:00:00.000Z");
  const NOW_S = NOW_MS / 1000;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW_MS);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const valueExpiringAt = (expiresAt: number) =>
    formatDeviceCookieValue({ deviceId: DEVICE_ID, expiresAt, binding: BINDING });

  it("returns the parsed value of a signed cookie that has not expired", async () => {
    const { ctx } = createFakeContext({ signed: valueExpiringAt(NOW_S + 60) });
    expect(await readDeviceCookie(ctx)).toEqual({
      deviceId: DEVICE_ID,
      expiresAt: NOW_S + 60,
      binding: BINDING,
    });
  });

  it("reads the cookie named after the device cookie name", async () => {
    const { ctx, createAuthCookie, getSignedCookie } = createFakeContext({
      signed: valueExpiringAt(NOW_S + 60),
    });
    await readDeviceCookie(ctx);
    expect(createAuthCookie).toHaveBeenCalledWith(DEVICE_COOKIE_NAME);
    expect(getSignedCookie).toHaveBeenCalledWith(`better-auth.${DEVICE_COOKIE_NAME}`, SECRET);
  });

  it("returns null when the cookie is absent or its signature is invalid", async () => {
    expect(await readDeviceCookie(createFakeContext({ signed: null }).ctx)).toBeNull();
    expect(await readDeviceCookie(createFakeContext({ signed: false }).ctx)).toBeNull();
    expect(await readDeviceCookie(createFakeContext({ signed: undefined }).ctx)).toBeNull();
  });

  it("returns null when the signed value is not a string", async () => {
    expect(await readDeviceCookie(createFakeContext({ signed: 123 }).ctx)).toBeNull();
    expect(await readDeviceCookie(createFakeContext({ signed: {} }).ctx)).toBeNull();
  });

  it("returns null when the signed value is malformed", async () => {
    expect(await readDeviceCookie(createFakeContext({ signed: "garbage" }).ctx)).toBeNull();
  });

  it("returns null when the expiry equals the current second", async () => {
    expect(
      await readDeviceCookie(createFakeContext({ signed: valueExpiringAt(NOW_S) }).ctx),
    ).toBeNull();
  });

  it("returns null when the expiry is in the past", async () => {
    expect(
      await readDeviceCookie(createFakeContext({ signed: valueExpiringAt(NOW_S - 1) }).ctx),
    ).toBeNull();
  });

  it("returns a value expiring one second from now", async () => {
    expect(
      await readDeviceCookie(createFakeContext({ signed: valueExpiringAt(NOW_S + 1) }).ctx),
    ).not.toBeNull();
  });

  it("returns null instead of throwing when reading the cookie fails", async () => {
    const { ctx } = createFakeContext({ getSignedCookieError: new Error("boom") });
    await expect(readDeviceCookie(ctx)).resolves.toBeNull();
  });
});

describe("issueDeviceCookie", () => {
  const NOW_MS = Date.parse("2030-01-01T00:00:00.000Z");
  const NOW_S = NOW_MS / 1000;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW_MS);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const issuedValue = (setSignedCookie: ReturnType<typeof createFakeContext>["setSignedCookie"]) => {
    const call = setSignedCookie.mock.calls[0] as unknown as [string, string, string, unknown];
    return call;
  };

  it("sets one signed cookie with the secret, the cookie name and the max age attribute", async () => {
    const { ctx, createAuthCookie, setSignedCookie } = createFakeContext();
    await issueDeviceCookie(
      ctx,
      { id: "user-1", passwordChangedAt: new Date(1700000000000) },
      2592000,
    );
    expect(createAuthCookie).toHaveBeenCalledWith(DEVICE_COOKIE_NAME, { maxAge: 2592000 });
    expect(setSignedCookie).toHaveBeenCalledTimes(1);
    const [name, , secret, attributes] = issuedValue(setSignedCookie);
    expect(name).toBe(`better-auth.${DEVICE_COOKIE_NAME}`);
    expect(secret).toBe(SECRET);
    expect(attributes).toMatchObject({ maxAge: 2592000, httpOnly: true, sameSite: "lax", path: "/" });
  });

  it("signs a value that expires max age seconds from now and is bound to the user and password epoch", async () => {
    const { ctx, setSignedCookie } = createFakeContext();
    await issueDeviceCookie(
      ctx,
      { id: "user-1", passwordChangedAt: new Date(1700000000000) },
      3600,
    );
    const parsed = parseDeviceCookieValue(issuedValue(setSignedCookie)[1]);
    expect(parsed).not.toBeNull();
    expect(parsed?.expiresAt).toBe(NOW_S + 3600);
    expect(parsed?.binding).toBe(
      expectedBinding(parsed?.deviceId ?? "", NOW_S + 3600, "1700000000000", "user-1"),
    );
  });

  it("uses the none epoch when the user has no passwordChangedAt", async () => {
    const { ctx, setSignedCookie } = createFakeContext();
    await issueDeviceCookie(ctx, { id: "user-1" }, 3600);
    const parsed = parseDeviceCookieValue(issuedValue(setSignedCookie)[1]);
    expect(parsed?.binding).toBe(
      expectedBinding(parsed?.deviceId ?? "", NOW_S + 3600, "none", "user-1"),
    );
  });

  it("rotates the device id on every call", async () => {
    const first = createFakeContext();
    const second = createFakeContext();
    const user = { id: "user-1", passwordChangedAt: new Date(1700000000000) };
    await issueDeviceCookie(first.ctx, user, 3600);
    await issueDeviceCookie(second.ctx, user, 3600);
    expect(parseDeviceCookieValue(issuedValue(first.setSignedCookie)[1])?.deviceId).not.toBe(
      parseDeviceCookieValue(issuedValue(second.setSignedCookie)[1])?.deviceId,
    );
  });

  it.each([
    ["missing", {}],
    ["empty", { id: "" }],
    ["not a string", { id: 7 }],
  ])("sets no cookie when the user id is %s", async (_name, user) => {
    const { ctx, setSignedCookie } = createFakeContext();
    await issueDeviceCookie(ctx, user, 3600);
    expect(setSignedCookie).not.toHaveBeenCalled();
  });
});
