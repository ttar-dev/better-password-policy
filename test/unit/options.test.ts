import { describe, it, expect } from "vitest";
import { resolvePasswordPolicyOptions } from "../../src/options.ts";
import type { PasswordPolicyOptions } from "../../src/index.ts";

const captureError = (run: () => unknown): unknown => {
  try {
    run();
  } catch (error) {
    return error;
  }
  throw new Error("expected the call to throw");
};

describe("resolvePasswordPolicyOptions defaults", () => {
  it("resolves every feature to its documented default", () => {
    expect(resolvePasswordPolicyOptions()).toEqual({
      complexity: {
        requireUppercase: true,
        requireLowercase: true,
        requireDigit: true,
        requireSymbol: false,
        rejectPersonalInfo: true,
        validate: null,
      },
      historyCount: 5,
      maxAgeSeconds: null,
      lockout: { maxAttempts: 5, durationSeconds: 900 },
    });
  });

  it("resolves empty option objects to the same defaults", () => {
    expect(resolvePasswordPolicyOptions({ complexity: {}, history: {}, lockout: {} })).toEqual(
      resolvePasswordPolicyOptions(),
    );
  });
});

describe("resolvePasswordPolicyOptions partial objects", () => {
  it("fills the rest of a partial complexity object from the defaults", () => {
    const resolved = resolvePasswordPolicyOptions({
      complexity: { requireSymbol: true, requireUppercase: false },
    });
    expect(resolved.complexity).toEqual({
      requireUppercase: false,
      requireLowercase: true,
      requireDigit: true,
      requireSymbol: true,
      rejectPersonalInfo: true,
      validate: null,
    });
  });

  it("passes a custom validate function through unchanged", () => {
    const validate = async () => true;
    expect(resolvePasswordPolicyOptions({ complexity: { validate } }).complexity?.validate).toBe(
      validate,
    );
  });

  it("keeps the default duration when only maxAttempts is given", () => {
    expect(resolvePasswordPolicyOptions({ lockout: { maxAttempts: 3 } }).lockout).toEqual({
      maxAttempts: 3,
      durationSeconds: 900,
    });
  });

  it("keeps the default maxAttempts when only duration is given", () => {
    expect(resolvePasswordPolicyOptions({ lockout: { duration: 60 } }).lockout).toEqual({
      maxAttempts: 5,
      durationSeconds: 60,
    });
  });

  it("accepts history count zero and keeps it as zero", () => {
    expect(resolvePasswordPolicyOptions({ history: { count: 0 } }).historyCount).toBe(0);
  });

  it("accepts the lowest allowed maxAttempts of one", () => {
    expect(resolvePasswordPolicyOptions({ lockout: { maxAttempts: 1 } }).lockout?.maxAttempts).toBe(
      1,
    );
  });

  it("converts expiration maxAge into maxAgeSeconds", () => {
    expect(resolvePasswordPolicyOptions({ expiration: { maxAge: 3600 } }).maxAgeSeconds).toBe(
      3600,
    );
  });
});

describe("resolvePasswordPolicyOptions with a feature switched off", () => {
  it("resolves complexity false to null", () => {
    expect(resolvePasswordPolicyOptions({ complexity: false }).complexity).toBeNull();
  });

  it("resolves history false to a null history count", () => {
    expect(resolvePasswordPolicyOptions({ history: false }).historyCount).toBeNull();
  });

  it("resolves expiration false to null max age", () => {
    expect(resolvePasswordPolicyOptions({ expiration: false }).maxAgeSeconds).toBeNull();
  });

  it("resolves lockout false to null", () => {
    expect(resolvePasswordPolicyOptions({ lockout: false }).lockout).toBeNull();
  });

  it("switching one feature off leaves the others at their defaults", () => {
    const resolved = resolvePasswordPolicyOptions({ lockout: false });
    expect(resolved.historyCount).toBe(5);
    expect(resolved.complexity?.requireUppercase).toBe(true);
  });
});

describe("resolvePasswordPolicyOptions validation", () => {
  const invalidOptions: [string, PasswordPolicyOptions][] = [
    ["history.count negative", { history: { count: -1 } }],
    ["history.count fractional", { history: { count: 1.5 } }],
    ["history.count NaN", { history: { count: Number.NaN } }],
    ["expiration.maxAge zero", { expiration: { maxAge: 0 } }],
    ["expiration.maxAge negative", { expiration: { maxAge: -1 } }],
    ["expiration.maxAge infinite", { expiration: { maxAge: Number.POSITIVE_INFINITY } }],
    ["expiration.maxAge NaN", { expiration: { maxAge: Number.NaN } }],
    ["lockout.maxAttempts zero", { lockout: { maxAttempts: 0 } }],
    ["lockout.maxAttempts negative", { lockout: { maxAttempts: -2 } }],
    ["lockout.maxAttempts fractional", { lockout: { maxAttempts: 1.5 } }],
    ["lockout.duration zero", { lockout: { duration: 0 } }],
    ["lockout.duration negative", { lockout: { duration: -5 } }],
    ["lockout.duration infinite", { lockout: { duration: Number.POSITIVE_INFINITY } }],
    ["lockout.duration NaN", { lockout: { duration: Number.NaN } }],
  ];

  it.each(invalidOptions)("throws a password-policy TypeError for %s", (_name, options) => {
    const error = captureError(() => resolvePasswordPolicyOptions(options));
    expect(error).toBeInstanceOf(TypeError);
    expect((error as TypeError).message.startsWith("password-policy:")).toBe(true);
  });
});
