import { describe, it, expect } from "vitest";
import { resolvePasswordNormalizationOption, resolvePasswordPolicyOptions } from "../../src/options.ts";
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
        minLength: null,
        requireUppercase: true,
        requireLowercase: true,
        requireDigit: true,
        requireSymbol: false,
        rejectPersonalInfo: true,
        caselessLettersSatisfyCase: false,
        validate: null,
      },
      historyCount: 5,
      maxAgeSeconds: null,
      expirationDisabled: false,
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
      minLength: null,
      requireUppercase: false,
      requireLowercase: true,
      requireDigit: true,
      requireSymbol: true,
      rejectPersonalInfo: true,
      caselessLettersSatisfyCase: false,
      validate: null,
    });
  });

  it("resolves caselessLettersSatisfyCase true and keeps the rest at the defaults", () => {
    const resolved = resolvePasswordPolicyOptions({
      complexity: { caselessLettersSatisfyCase: true },
    });
    expect(resolved.complexity).toEqual({
      minLength: null,
      requireUppercase: true,
      requireLowercase: true,
      requireDigit: true,
      requireSymbol: false,
      rejectPersonalInfo: true,
      caselessLettersSatisfyCase: true,
      validate: null,
    });
  });

  it.each([
    ["omitted", {}, false],
    ["false", { caselessLettersSatisfyCase: false }, false],
    ["true", { caselessLettersSatisfyCase: true }, true],
  ] as const)("resolves caselessLettersSatisfyCase %s to %s", (_name, complexity, expected) => {
    expect(resolvePasswordPolicyOptions({ complexity }).complexity?.caselessLettersSatisfyCase).toBe(
      expected,
    );
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

  it.each([1, 8, 128])("resolves complexity minLength %i as given", (minLength) => {
    expect(resolvePasswordPolicyOptions({ complexity: { minLength } }).complexity?.minLength).toBe(
      minLength,
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

  it("leaves expirationDisabled false when expiration is omitted", () => {
    expect(resolvePasswordPolicyOptions().expirationDisabled).toBe(false);
  });

  it("leaves expirationDisabled false when expiration has a maxAge", () => {
    expect(resolvePasswordPolicyOptions({ expiration: { maxAge: 3600 } }).expirationDisabled).toBe(
      false,
    );
  });

  it("sets expirationDisabled true when expiration is false", () => {
    expect(resolvePasswordPolicyOptions({ expiration: false }).expirationDisabled).toBe(true);
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
    ["complexity.minLength zero", { complexity: { minLength: 0 } }],
    ["complexity.minLength negative", { complexity: { minLength: -1 } }],
    ["complexity.minLength fractional", { complexity: { minLength: 1.5 } }],
    ["complexity.minLength NaN", { complexity: { minLength: Number.NaN } }],
    ["complexity.minLength infinite", { complexity: { minLength: Number.POSITIVE_INFINITY } }],
    ["complexity.minLength above 128", { complexity: { minLength: 129 } }],
  ];

  it.each(invalidOptions)("throws a password-policy TypeError for %s", (_name, options) => {
    const error = captureError(() => resolvePasswordPolicyOptions(options));
    expect(error).toBeInstanceOf(TypeError);
    expect((error as TypeError).message.startsWith("password-policy:")).toBe(true);
  });
});

describe("resolvePasswordNormalizationOption", () => {
  it.each([
    ["undefined", undefined],
    ["false", false],
  ])("resolves %s to null", (_name, option) => {
    expect(resolvePasswordNormalizationOption(option)).toBeNull();
  });

  it("resolves NFKC to NFKC", () => {
    expect(resolvePasswordNormalizationOption("NFKC")).toBe("NFKC");
  });

  it.each([
    ["true", true],
    ["NFKD", "NFKD"],
    ["NFC", "NFC"],
    ["lowercase nfkc", "nfkc"],
    ["null", null],
    ["a number", 1],
    ["an empty string", ""],
    ["an object", { form: "NFKC" }],
  ])("throws a password-policy TypeError for %s", (_name, option) => {
    const error = captureError(() => resolvePasswordNormalizationOption(option));
    expect(error).toBeInstanceOf(TypeError);
    expect((error as TypeError).message).toBe(
      'password-policy: passwordNormalization must be false or "NFKC"',
    );
  });
});

describe("resolvePasswordPolicyOptions with passwordNormalization", () => {
  it("leaves the resolved policy unchanged", () => {
    expect(resolvePasswordPolicyOptions({ passwordNormalization: "NFKC" })).toEqual(
      resolvePasswordPolicyOptions(),
    );
    expect(resolvePasswordPolicyOptions({ passwordNormalization: false })).toEqual(
      resolvePasswordPolicyOptions(),
    );
  });
});
