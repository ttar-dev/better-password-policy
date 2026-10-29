import { describe, it, expect } from "vitest";
import { resolveLockoutPlatformSettings, resolvePasswordPolicyOptions } from "../../src/options.ts";
import { passwordPolicy } from "../../src/index.ts";
import type { PasswordPolicyOptions } from "../../src/index.ts";
import { validateTenantPasswordPolicyOverride } from "../../src/tenant-policy.ts";

const resolveSettings = (option: PasswordPolicyOptions["lockout"]) =>
  resolveLockoutPlatformSettings(option, resolvePasswordPolicyOptions({ lockout: option }).lockout);

const captureError = (run: () => unknown): unknown => {
  try {
    run();
  } catch (error) {
    return error;
  }
  throw new Error("expected the call to throw");
};

const expectPolicyTypeError = (option: PasswordPolicyOptions["lockout"]) => {
  const error = captureError(() => resolveSettings(option));
  expect(error).toBeInstanceOf(TypeError);
  expect((error as TypeError).message.startsWith("password-policy:")).toBe(true);
  return (error as TypeError).message;
};

describe("resolveLockoutPlatformSettings defaults", () => {
  it("defaults both retention and the device cookie max age to 30 days", () => {
    expect(resolveSettings(undefined)).toEqual({
      retentionSeconds: 2592000,
      deviceCookieMaxAgeSeconds: 2592000,
    });
  });

  it("resolves an empty lockout object to the same defaults", () => {
    expect(resolveSettings({})).toEqual({
      retentionSeconds: 2592000,
      deviceCookieMaxAgeSeconds: 2592000,
    });
  });

  it("keeps the defaults when only maxAttempts and duration are set", () => {
    expect(resolveSettings({ maxAttempts: 3, duration: 600 })).toEqual({
      retentionSeconds: 2592000,
      deviceCookieMaxAgeSeconds: 2592000,
    });
  });

  it("resolves an empty deviceCookie object to the default max age", () => {
    expect(resolveSettings({ deviceCookie: {} })?.deviceCookieMaxAgeSeconds).toBe(2592000);
  });
});

describe("resolveLockoutPlatformSettings switches", () => {
  it("returns null when lockout is false", () => {
    expect(resolveLockoutPlatformSettings(false, null)).toBeNull();
  });

  it("returns null when the resolved lockout is null", () => {
    expect(resolveLockoutPlatformSettings(undefined, null)).toBeNull();
  });

  it("disables retention with false and keeps the device cookie", () => {
    expect(resolveSettings({ retention: false })).toEqual({
      retentionSeconds: null,
      deviceCookieMaxAgeSeconds: 2592000,
    });
  });

  it("disables the device cookie with false and keeps retention", () => {
    expect(resolveSettings({ deviceCookie: false })).toEqual({
      retentionSeconds: 2592000,
      deviceCookieMaxAgeSeconds: null,
    });
  });

  it("disables both when both are false", () => {
    expect(resolveSettings({ retention: false, deviceCookie: false })).toEqual({
      retentionSeconds: null,
      deviceCookieMaxAgeSeconds: null,
    });
  });
});

describe("resolveLockoutPlatformSettings accepted boundaries", () => {
  it.each([86400, 315360000, 604800])("accepts retention %s", (retention) => {
    expect(resolveSettings({ retention })?.retentionSeconds).toBe(retention);
  });

  it.each([1, 34560000, 3600])("accepts deviceCookie maxAge %s", (maxAge) => {
    expect(resolveSettings({ deviceCookie: { maxAge } })?.deviceCookieMaxAgeSeconds).toBe(maxAge);
  });

  it("accepts a retention equal to the lockout duration", () => {
    expect(resolveSettings({ duration: 172800, retention: 172800 })?.retentionSeconds).toBe(172800);
  });

  it("accepts a retention above the lockout duration", () => {
    expect(resolveSettings({ duration: 172800, retention: 172801 })?.retentionSeconds).toBe(172801);
  });

  it("accepts a retention shorter than the lockout duration", () => {
    expect(resolveSettings({ duration: 172800, retention: 86400 })?.retentionSeconds).toBe(86400);
  });

  it("accepts a lockout duration of 31 days with the default retention", () => {
    expect(resolveSettings({ duration: 2678400 })).toEqual({
      retentionSeconds: 2592000,
      deviceCookieMaxAgeSeconds: 2592000,
    });
  });

  it("accepts the maximum retention with a lockout duration far longer than it", () => {
    expect(resolveSettings({ duration: 400000000, retention: 315360000 })?.retentionSeconds).toBe(315360000);
  });

  it("lets passwordPolicy be created with a duration longer than the default retention", () => {
    expect(() => passwordPolicy({ lockout: { duration: 2678400 } })).not.toThrow();
  });

  it("lets passwordPolicy be created with a duration longer than an explicit maximum retention", () => {
    expect(() => passwordPolicy({ lockout: { duration: 400000000, retention: 315360000 } })).not.toThrow();
  });
});

describe("resolveLockoutPlatformSettings rejects", () => {
  const retentionMessage =
    "password-policy: lockout.retention must be false or an integer between 86400 and 315360000";
  const maxAgeMessage =
    "password-policy: lockout.deviceCookie.maxAge must be an integer between 1 and 34560000";

  it.each([
    ["one below the minimum", 86399],
    ["one above the maximum", 315360001],
    ["a fraction", 1.5],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["zero", 0],
    ["a negative number", -1],
    ["a numeric string", "86400"],
    ["true", true],
  ])("retention that is %s", (_name, retention) => {
    expect(expectPolicyTypeError({ retention: retention as never })).toBe(retentionMessage);
  });

  it.each([
    ["zero", 0],
    ["a negative number", -1],
    ["a fraction", 1.5],
    ["one above the maximum", 34560001],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["a numeric string", "60"],
  ])("deviceCookie maxAge that is %s", (_name, maxAge) => {
    expect(expectPolicyTypeError({ deviceCookie: { maxAge: maxAge as never } })).toBe(maxAgeMessage);
  });
});

describe("validateTenantPasswordPolicyOverride with platform-only lockout settings", () => {
  const issuePaths = (input: unknown): string[] => {
    const result = validateTenantPasswordPolicyOverride(input);
    if (result.success) throw new Error("expected the override to be rejected");
    return result.issues.map((issue) => issue.path);
  };

  it("rejects lockout.retention at the path lockout.retention", () => {
    expect(issuePaths({ lockout: { retention: 86400 } })).toEqual(["lockout.retention"]);
  });

  it("rejects lockout.deviceCookie at the path lockout.deviceCookie", () => {
    expect(issuePaths({ lockout: { deviceCookie: false } })).toEqual(["lockout.deviceCookie"]);
  });
});
