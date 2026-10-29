import { describe, it, expect } from "vitest";
import {
  TENANT_PASSWORD_POLICY_LIMITS,
  mergeTenantPasswordPolicy,
  toEffectivePasswordPolicy,
  validateTenantPasswordPolicyOverride,
} from "../../src/tenant-policy.ts";
import { resolvePasswordPolicyOptions } from "../../src/options.ts";
import type { PasswordPolicyOptions, TenantPasswordPolicyOverride } from "../../src/index.ts";

const invalidPaths = (input: unknown): string[] => {
  const result = validateTenantPasswordPolicyOverride(input);
  if (result.success) throw new Error("expected the override to be rejected");
  return result.issues.map((issue) => issue.path).sort();
};

const baseFrom = (options?: PasswordPolicyOptions) => resolvePasswordPolicyOptions(options);

const merged = (options: PasswordPolicyOptions | undefined, override: TenantPasswordPolicyOverride) =>
  mergeTenantPasswordPolicy(baseFrom(options), override);

const DEFAULT_LENGTHS = { minPasswordLength: 8, maxPasswordLength: 128 };

describe("TENANT_PASSWORD_POLICY_LIMITS", () => {
  it("pins the documented inclusive bounds", () => {
    expect(TENANT_PASSWORD_POLICY_LIMITS).toEqual({
      complexity: { minLength: { min: 1, max: 128 } },
      history: { count: { min: 0, max: 24 } },
      expiration: { maxAge: { min: 86400, max: 315360000 } },
      lockout: { maxAttempts: { min: 1, max: 100 }, duration: { min: 1, max: 86400 } },
    });
  });
});

describe("validateTenantPasswordPolicyOverride accepts", () => {
  it("an empty object", () => {
    const result = validateTenantPasswordPolicyOverride({});
    expect(result.success).toBe(true);
  });

  it("a full override and returns it as data", () => {
    const override: TenantPasswordPolicyOverride = {
      complexity: {
        minLength: 12,
        requireUppercase: true,
        requireLowercase: true,
        requireDigit: true,
        requireSymbol: true,
        rejectPersonalInfo: true,
        caselessLettersSatisfyCase: true,
      },
      history: { count: 10 },
      expiration: { maxAge: 7776000 },
      lockout: { maxAttempts: 3, duration: 1800 },
    };
    const result = validateTenantPasswordPolicyOverride(override);
    expect(result).toEqual({ success: true, data: override });
  });

  it.each([
    ["complexity.minLength lower bound", { complexity: { minLength: 1 } }],
    ["complexity.minLength upper bound", { complexity: { minLength: 128 } }],
    ["history.count lower bound", { history: { count: 0 } }],
    ["history.count upper bound", { history: { count: 24 } }],
    ["expiration.maxAge lower bound", { expiration: { maxAge: 86400 } }],
    ["expiration.maxAge upper bound", { expiration: { maxAge: 315360000 } }],
    ["lockout.maxAttempts lower bound", { lockout: { maxAttempts: 1 } }],
    ["lockout.maxAttempts upper bound", { lockout: { maxAttempts: 100 } }],
    ["lockout.duration lower bound", { lockout: { duration: 1 } }],
    ["lockout.duration upper bound", { lockout: { duration: 86400 } }],
  ])("%s", (_name, override) => {
    expect(validateTenantPasswordPolicyOverride(override)).toEqual({ success: true, data: override });
  });

  it("boolean false on every complexity flag", () => {
    const override = {
      complexity: {
        requireUppercase: false,
        requireLowercase: false,
        requireDigit: false,
        requireSymbol: false,
        rejectPersonalInfo: false,
      },
    };
    expect(validateTenantPasswordPolicyOverride(override)).toEqual({ success: true, data: override });
  });
});

describe("validateTenantPasswordPolicyOverride caselessLettersSatisfyCase", () => {
  it.each([true, false])("accepts caselessLettersSatisfyCase %s and returns it as data", (value) => {
    const override = { complexity: { caselessLettersSatisfyCase: value } };
    expect(validateTenantPasswordPolicyOverride(override)).toEqual({ success: true, data: override });
  });

  it.each([
    ["a string", "true"],
    ["a number", 1],
    ["null", null],
  ])("rejects %s with the dotted path", (_name, value) => {
    expect(invalidPaths({ complexity: { caselessLettersSatisfyCase: value } })).toEqual([
      "complexity.caselessLettersSatisfyCase",
    ]);
  });

  it("still rejects a misspelled sibling key", () => {
    expect(
      invalidPaths({ complexity: { caselessLettersSatisfyCase: true, requireNumber: true } }),
    ).toEqual(["complexity.requireNumber"]);
  });
});

describe("validateTenantPasswordPolicyOverride rejects", () => {
  it.each([
    ["null", null],
    ["an array", []],
    ["a string", "strict"],
  ])("%s at the root path", (_name, input) => {
    expect(invalidPaths(input)).toEqual([""]);
  });

  it("an unknown top-level key by its name", () => {
    expect(invalidPaths({ foo: 1 })).toEqual(["foo"]);
  });

  it("an unknown complexity key by its dotted path", () => {
    expect(invalidPaths({ complexity: { requireNumber: true } })).toEqual(["complexity.requireNumber"]);
  });

  it("complexity.validate because custom validators are platform-only", () => {
    expect(invalidPaths({ complexity: { validate: () => true } })).toEqual(["complexity.validate"]);
  });

  it("complexity set to false", () => {
    expect(invalidPaths({ complexity: false })).toEqual(["complexity"]);
  });

  it("expiration set to false", () => {
    expect(invalidPaths({ expiration: false })).toEqual(["expiration"]);
  });

  it.each([
    ["complexity.requireUppercase", { complexity: { requireUppercase: null } }],
    ["complexity.minLength", { complexity: { minLength: null } }],
    ["history.count", { history: { count: null } }],
    ["expiration.maxAge", { expiration: { maxAge: null } }],
    ["lockout.maxAttempts", { lockout: { maxAttempts: null } }],
    ["lockout.duration", { lockout: { duration: null } }],
  ])("a null value at %s", (path, input) => {
    expect(invalidPaths(input)).toEqual([path]);
  });

  it.each([
    ["0", 0],
    ["129", 129],
    ["1.5", 1.5],
    ['"12"', "12"],
  ])("complexity.minLength %s", (_name, minLength) => {
    expect(invalidPaths({ complexity: { minLength } })).toEqual(["complexity.minLength"]);
  });

  it.each([
    ["-1", -1],
    ["25", 25],
  ])("history.count %s", (_name, count) => {
    expect(invalidPaths({ history: { count } })).toEqual(["history.count"]);
  });

  it.each([
    ["86399", 86399],
    ["315360001", 315360001],
  ])("expiration.maxAge %s", (_name, maxAge) => {
    expect(invalidPaths({ expiration: { maxAge } })).toEqual(["expiration.maxAge"]);
  });

  it.each([
    ["0", 0],
    ["101", 101],
  ])("lockout.maxAttempts %s", (_name, maxAttempts) => {
    expect(invalidPaths({ lockout: { maxAttempts } })).toEqual(["lockout.maxAttempts"]);
  });

  it.each([
    ["0", 0],
    ["86401", 86401],
  ])("lockout.duration %s", (_name, duration) => {
    expect(invalidPaths({ lockout: { duration } })).toEqual(["lockout.duration"]);
  });

  it("every problem at once with one issue per path", () => {
    expect(
      invalidPaths({
        complexity: { minLength: 0 },
        history: { count: -1 },
        foo: 1,
      }),
    ).toEqual(["complexity.minLength", "foo", "history.count"]);
  });

  it("two unknown keys as two issues", () => {
    expect(invalidPaths({ complexity: { a: true, b: true } })).toEqual([
      "complexity.a",
      "complexity.b",
    ]);
  });
});

describe("mergeTenantPasswordPolicy complexity flags", () => {
  const flags = [
    "requireUppercase",
    "requireLowercase",
    "requireDigit",
    "requireSymbol",
    "rejectPersonalInfo",
  ] as const;

  it.each(flags)("%s turned on by the tenant wins over a platform that has it off", (flag) => {
    const result = merged({ complexity: { [flag]: false } }, { complexity: { [flag]: true } });
    expect(result.complexity?.[flag]).toBe(true);
  });

  it.each(flags)("%s turned off by the tenant is ignored when the platform has it on", (flag) => {
    const result = merged({ complexity: { [flag]: true } }, { complexity: { [flag]: false } });
    expect(result.complexity?.[flag]).toBe(true);
  });
});

describe("mergeTenantPasswordPolicy caselessLettersSatisfyCase", () => {
  const tenantOverride = (tenant: boolean | undefined): TenantPasswordPolicyOverride =>
    tenant === undefined ? {} : { complexity: { caselessLettersSatisfyCase: tenant } };

  it.each([
    [false, true, false],
    [false, undefined, false],
    [true, undefined, true],
    [true, true, true],
    [true, false, false],
  ])("platform %s with tenant %s merges to %s", (platform, tenant, expected) => {
    const result = merged({ complexity: { caselessLettersSatisfyCase: platform } }, tenantOverride(tenant));
    expect(result.complexity?.caselessLettersSatisfyCase).toBe(expected);
  });

  it("keeps a platform that omits the option at false even when the tenant sends true", () => {
    expect(merged(undefined, tenantOverride(true)).complexity?.caselessLettersSatisfyCase).toBe(false);
  });

  it("keeps the platform value when the tenant sends an empty complexity object", () => {
    const result = merged({ complexity: { caselessLettersSatisfyCase: true } }, { complexity: {} });
    expect(result.complexity?.caselessLettersSatisfyCase).toBe(true);
  });

  it("keeps complexity null and ignores the override when the platform switched complexity off", () => {
    expect(merged({ complexity: false }, tenantOverride(true)).complexity).toBeNull();
    expect(merged({ complexity: false }, tenantOverride(false)).complexity).toBeNull();
  });

  it("does not let a tenant turning the option off change the OR-merged flags", () => {
    const result = merged(
      { complexity: { caselessLettersSatisfyCase: true, requireSymbol: false } },
      { complexity: { caselessLettersSatisfyCase: false, requireSymbol: true } },
    );
    expect(result.complexity?.caselessLettersSatisfyCase).toBe(false);
    expect(result.complexity?.requireSymbol).toBe(true);
  });
});

describe("mergeTenantPasswordPolicy numeric rules", () => {
  it("takes the larger complexity.minLength when the tenant is stricter", () => {
    expect(merged({ complexity: { minLength: 10 } }, { complexity: { minLength: 12 } }).complexity?.minLength).toBe(12);
  });

  it("keeps the platform complexity.minLength when the tenant is looser", () => {
    expect(merged({ complexity: { minLength: 12 } }, { complexity: { minLength: 10 } }).complexity?.minLength).toBe(12);
  });

  it("uses the tenant complexity.minLength when the platform sets none", () => {
    expect(merged(undefined, { complexity: { minLength: 9 } }).complexity?.minLength).toBe(9);
  });

  it("keeps complexity.minLength null when neither side sets it", () => {
    expect(merged(undefined, { complexity: {} }).complexity?.minLength).toBeNull();
  });

  it("keeps the platform complexity.minLength when the tenant sets none", () => {
    expect(merged({ complexity: { minLength: 10 } }, {}).complexity?.minLength).toBe(10);
  });

  it("takes the larger history.count when the tenant is stricter", () => {
    expect(merged({ history: { count: 5 } }, { history: { count: 8 } }).historyCount).toBe(8);
  });

  it("keeps the platform history.count when the tenant is looser", () => {
    expect(merged({ history: { count: 8 } }, { history: { count: 5 } }).historyCount).toBe(8);
  });

  it("lets a tenant raise a platform history.count of zero", () => {
    expect(merged({ history: { count: 0 } }, { history: { count: 3 } }).historyCount).toBe(3);
  });

  it("takes the shorter expiration.maxAge when the tenant is stricter", () => {
    expect(merged({ expiration: { maxAge: 2592000 } }, { expiration: { maxAge: 86400 } }).maxAgeSeconds).toBe(86400);
  });

  it("keeps the platform expiration.maxAge when the tenant is looser", () => {
    expect(merged({ expiration: { maxAge: 2592000 } }, { expiration: { maxAge: 5184000 } }).maxAgeSeconds).toBe(2592000);
  });

  it("uses the tenant expiration.maxAge when the platform sets none", () => {
    const result = merged(undefined, { expiration: { maxAge: 86400 } });
    expect(result.maxAgeSeconds).toBe(86400);
    expect(result.expirationDisabled).toBe(false);
  });

  it("takes the smaller lockout.maxAttempts when the tenant is stricter", () => {
    expect(merged({ lockout: { maxAttempts: 5 } }, { lockout: { maxAttempts: 2 } }).lockout?.maxAttempts).toBe(2);
  });

  it("keeps the platform lockout.maxAttempts when the tenant is looser", () => {
    expect(merged({ lockout: { maxAttempts: 5 } }, { lockout: { maxAttempts: 9 } }).lockout?.maxAttempts).toBe(5);
  });

  it("takes the longer lockout.duration when the tenant is stricter", () => {
    expect(merged({ lockout: { duration: 900 } }, { lockout: { duration: 3600 } }).lockout?.durationSeconds).toBe(3600);
  });

  it("keeps the platform lockout.duration when the tenant is looser", () => {
    expect(merged({ lockout: { duration: 900 } }, { lockout: { duration: 60 } }).lockout?.durationSeconds).toBe(900);
  });
});

describe("mergeTenantPasswordPolicy with a platform feature switched off", () => {
  it("keeps complexity null whatever the tenant sends", () => {
    expect(merged({ complexity: false }, { complexity: { requireSymbol: true, minLength: 20 } }).complexity).toBeNull();
  });

  it("keeps the history count null whatever the tenant sends", () => {
    expect(merged({ history: false }, { history: { count: 10 } }).historyCount).toBeNull();
  });

  it("keeps lockout null whatever the tenant sends", () => {
    expect(merged({ lockout: false }, { lockout: { maxAttempts: 1, duration: 3600 } }).lockout).toBeNull();
  });

  it("keeps expiry disabled with no max age whatever the tenant sends", () => {
    const result = merged({ expiration: false }, { expiration: { maxAge: 86400 } });
    expect(result.maxAgeSeconds).toBeNull();
    expect(result.expirationDisabled).toBe(true);
  });
});

describe("mergeTenantPasswordPolicy carry-over and purity", () => {
  it("returns an equal policy for an empty override", () => {
    const base = baseFrom();
    expect(mergeTenantPasswordPolicy(base, {})).toEqual(base);
  });

  it("carries the platform validate function into the merged complexity", () => {
    const validate = async () => true;
    const result = merged({ complexity: { validate } }, { complexity: { requireSymbol: true } });
    expect(result.complexity?.validate).toBe(validate);
  });

  it("does not mutate the base policy", () => {
    const base = baseFrom({
      expiration: { maxAge: 2592000 },
      complexity: { caselessLettersSatisfyCase: true },
    });
    const snapshot = structuredClone(base);
    const result = mergeTenantPasswordPolicy(base, {
      complexity: {
        minLength: 20,
        requireSymbol: true,
        requireUppercase: true,
        requireLowercase: true,
        requireDigit: true,
        rejectPersonalInfo: true,
        caselessLettersSatisfyCase: false,
      },
      history: { count: 20 },
      expiration: { maxAge: 86400 },
      lockout: { maxAttempts: 1, duration: 86400 },
    });
    expect(base).toEqual(snapshot);
    expect(base.complexity?.caselessLettersSatisfyCase).toBe(true);
    expect(result.complexity?.caselessLettersSatisfyCase).toBe(false);
    expect(result).not.toBe(base);
    expect(result.complexity).not.toBe(base.complexity);
    expect(result.lockout).not.toBe(base.lockout);
  });

  it("does not leak one tenant's override into the next merge of the same base", () => {
    const base = baseFrom();
    mergeTenantPasswordPolicy(base, { complexity: { requireSymbol: true, minLength: 20 }, history: { count: 20 } });
    const second = mergeTenantPasswordPolicy(base, {});
    expect(second.complexity?.requireSymbol).toBe(false);
    expect(second.complexity?.minLength).toBeNull();
    expect(second.historyCount).toBe(5);
  });
});

describe("toEffectivePasswordPolicy", () => {
  it("renders the default policy as the documented JSON shape", () => {
    expect(toEffectivePasswordPolicy(baseFrom(), DEFAULT_LENGTHS)).toEqual({
      minLength: 8,
      maxLength: 128,
      complexity: {
        requireUppercase: true,
        requireLowercase: true,
        requireDigit: true,
        requireSymbol: false,
        rejectPersonalInfo: true,
        caselessLettersSatisfyCase: false,
        customValidation: false,
      },
      history: { count: 5 },
      expiration: null,
      lockout: { maxAttempts: 5, duration: 900 },
    });
  });

  it("places caselessLettersSatisfyCase after rejectPersonalInfo and before customValidation", () => {
    const keys = Object.keys(toEffectivePasswordPolicy(baseFrom(), DEFAULT_LENGTHS).complexity ?? {});
    expect(keys.indexOf("caselessLettersSatisfyCase")).toBe(keys.indexOf("rejectPersonalInfo") + 1);
    expect(keys.indexOf("customValidation")).toBe(keys.indexOf("caselessLettersSatisfyCase") + 1);
  });

  it.each([
    ["the platform value true", { caselessLettersSatisfyCase: true }, {}, true],
    ["the tenant switching it off", { caselessLettersSatisfyCase: true }, { caselessLettersSatisfyCase: false }, false],
    ["a tenant that cannot switch it on", {}, { caselessLettersSatisfyCase: true }, false],
  ])("reports caselessLettersSatisfyCase from %s", (_name, platform, tenant, expected) => {
    const policy = merged({ complexity: platform }, { complexity: tenant });
    expect(toEffectivePasswordPolicy(policy, DEFAULT_LENGTHS).complexity?.caselessLettersSatisfyCase).toBe(expected);
  });

  it("uses the larger of Better Auth's minimum and the plugin minLength", () => {
    const policy = baseFrom({ complexity: { minLength: 12 } });
    expect(toEffectivePasswordPolicy(policy, { minPasswordLength: 8, maxPasswordLength: 128 }).minLength).toBe(12);
    expect(toEffectivePasswordPolicy(policy, { minPasswordLength: 14, maxPasswordLength: 128 }).minLength).toBe(14);
  });

  it("uses Better Auth's minimum when complexity is off", () => {
    expect(toEffectivePasswordPolicy(baseFrom({ complexity: false }), DEFAULT_LENGTHS).minLength).toBe(8);
  });

  it("reports Better Auth's maximum password length", () => {
    expect(
      toEffectivePasswordPolicy(baseFrom(), { minPasswordLength: 8, maxPasswordLength: 64 }).maxLength,
    ).toBe(64);
  });

  it("flags customValidation when the platform has a validate function", () => {
    const policy = baseFrom({ complexity: { validate: async () => true } });
    expect(toEffectivePasswordPolicy(policy, DEFAULT_LENGTHS).complexity?.customValidation).toBe(true);
  });

  it("reports expiration maxAge in seconds when the policy has one", () => {
    const policy = baseFrom({ expiration: { maxAge: 7776000 } });
    expect(toEffectivePasswordPolicy(policy, DEFAULT_LENGTHS).expiration).toEqual({ maxAge: 7776000 });
  });

  it("reports null for every switched-off feature", () => {
    const policy = baseFrom({ complexity: false, history: false, expiration: false, lockout: false });
    const effective = toEffectivePasswordPolicy(policy, DEFAULT_LENGTHS);
    expect(effective.complexity).toBeNull();
    expect(effective.history).toBeNull();
    expect(effective.expiration).toBeNull();
    expect(effective.lockout).toBeNull();
  });

  it("survives a JSON round trip unchanged even with a validate function", () => {
    const policy = mergeTenantPasswordPolicy(
      baseFrom({ complexity: { validate: async () => true }, expiration: { maxAge: 2592000 } }),
      { complexity: { minLength: 12 }, lockout: { maxAttempts: 3 } },
    );
    const effective = toEffectivePasswordPolicy(policy, DEFAULT_LENGTHS);
    expect(JSON.parse(JSON.stringify(effective))).toEqual(effective);
  });
});
