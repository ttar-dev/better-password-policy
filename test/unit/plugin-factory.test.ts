import { describe, it, expect } from "vitest";
import {
  passwordPolicy,
  passwordPolicySchema,
  PASSWORD_POLICY_ERROR_CODES,
  PASSWORD_CHANGE_EXEMPT_PATHS,
  getPasswordChangeRequirement,
  getPasswordExpiresAt,
  validateTenantPasswordPolicyOverride,
  TENANT_PASSWORD_POLICY_LIMITS,
} from "../../src/index.ts";
import {
  passwordPolicyClient,
  PASSWORD_POLICY_ERROR_CODES as CLIENT_ERROR_CODES,
  getPasswordChangeRequirement as clientGetPasswordChangeRequirement,
  getPasswordExpiresAt as clientGetPasswordExpiresAt,
  validateTenantPasswordPolicyOverride as clientValidateTenantPasswordPolicyOverride,
  TENANT_PASSWORD_POLICY_LIMITS as CLIENT_TENANT_PASSWORD_POLICY_LIMITS,
} from "../../src/client.ts";

describe("passwordPolicy factory", () => {
  it("has the plugin id password-policy", () => {
    expect(passwordPolicy().id).toBe("password-policy");
  });

  it("declares the user extension and the two plugin tables", () => {
    expect(Object.keys(passwordPolicy().schema).sort()).toEqual(
      ["passwordHistory", "signInLockout", "user"].sort(),
    );
    expect(Object.keys(passwordPolicy().schema.user.fields).sort()).toEqual(
      ["mustChangePassword", "passwordChangedAt"].sort(),
    );
  });

  it("applies schema overrides such as a custom model name", () => {
    const plugin = passwordPolicy({ schema: { passwordHistory: { modelName: "pw_history" } } });
    expect((plugin.schema.passwordHistory as { modelName?: string }).modelName).toBe("pw_history");
  });

  it("exposes exactly the three admin endpoints", () => {
    expect(Object.keys(passwordPolicy().endpoints).sort()).toEqual(
      ["getPasswordPolicyStatus", "setPasswordChangeRequired", "unlockSignIn"].sort(),
    );
  });

  it("registers every endpoint as server-only with no http path", () => {
    const endpoints = passwordPolicy().endpoints as Record<
      string,
      { path?: string; options: { metadata?: { SERVER_ONLY?: boolean } } }
    >;
    for (const endpoint of Object.values(endpoints)) {
      expect(endpoint.path).toBeUndefined();
      expect(endpoint.options.metadata?.SERVER_ONLY).toBe(true);
    }
  });

  it("registers gate, lockout and admin create-user before-hooks and the lockout after-hook by default", () => {
    const plugin = passwordPolicy();
    expect(plugin.hooks.before).toHaveLength(3);
    expect(plugin.hooks.after).toHaveLength(1);
  });

  it("drops the lockout hooks when lockout is off", () => {
    const plugin = passwordPolicy({ lockout: false });
    expect(plugin.hooks.before).toHaveLength(2);
    expect(plugin.hooks.after).toHaveLength(0);
  });

  it("registers the same hook counts with every lockout hardening option set", () => {
    const plugin = passwordPolicy({
      lockout: { retention: 86400, deviceCookie: { maxAge: 3600 } },
    });
    expect(plugin.hooks.before).toHaveLength(3);
    expect(plugin.hooks.after).toHaveLength(1);
  });

  it("registers the same hook counts when retention and the device cookie are switched off", () => {
    const plugin = passwordPolicy({ lockout: { retention: false, deviceCookie: false } });
    expect(plugin.hooks.before).toHaveLength(3);
    expect(plugin.hooks.after).toHaveLength(1);
  });

  it("drops the lockout hooks when lockout is off even if nothing else is configured", () => {
    const plugin = passwordPolicy({ lockout: false, complexity: false });
    expect(plugin.hooks.before).toHaveLength(1);
    expect(plugin.hooks.after).toHaveLength(0);
  });

  it("throws a password-policy TypeError when lockout.retention is below the minimum", () => {
    let thrown: unknown;
    try {
      passwordPolicy({ lockout: { retention: 10 } });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(TypeError);
    expect((thrown as TypeError).message.startsWith("password-policy:")).toBe(true);
  });

  it("drops the admin create-user hook when complexity is off", () => {
    const plugin = passwordPolicy({ complexity: false });
    expect(plugin.hooks.before).toHaveLength(2);
    expect(plugin.hooks.after).toHaveLength(1);
  });

  it("keeps only the gate when lockout and complexity are both off", () => {
    const plugin = passwordPolicy({ lockout: false, complexity: false });
    expect(plugin.hooks.before).toHaveLength(1);
    expect(plugin.hooks.after).toHaveLength(0);
  });

  it("publishes the error code table as $ERROR_CODES", () => {
    expect(passwordPolicy().$ERROR_CODES).toEqual(PASSWORD_POLICY_ERROR_CODES);
  });

  it("throws a password-policy TypeError for invalid options at construction", () => {
    expect(() => passwordPolicy({ lockout: { maxAttempts: 0 } })).toThrow(TypeError);
  });
});

describe("passwordPolicy factory with tenantPolicy", () => {
  const tenantPolicy = () => null;

  it("registers the same hook counts as without tenantPolicy by default", () => {
    const plugin = passwordPolicy({ tenantPolicy });
    expect(plugin.hooks.before).toHaveLength(3);
    expect(plugin.hooks.after).toHaveLength(1);
  });

  it("drops the lockout hooks when lockout is off", () => {
    const plugin = passwordPolicy({ tenantPolicy, lockout: false });
    expect(plugin.hooks.before).toHaveLength(2);
    expect(plugin.hooks.after).toHaveLength(0);
  });

  it("drops the admin create-user hook when complexity is off", () => {
    const plugin = passwordPolicy({ tenantPolicy, complexity: false });
    expect(plugin.hooks.before).toHaveLength(2);
    expect(plugin.hooks.after).toHaveLength(1);
  });

  it("keeps only the gate when lockout and complexity are both off", () => {
    const plugin = passwordPolicy({ tenantPolicy, lockout: false, complexity: false });
    expect(plugin.hooks.before).toHaveLength(1);
    expect(plugin.hooks.after).toHaveLength(0);
  });

  it("still exposes exactly three server-only endpoints without an http path", () => {
    const endpoints = passwordPolicy({ tenantPolicy }).endpoints as Record<
      string,
      { path?: string; options: { metadata?: { SERVER_ONLY?: boolean } } }
    >;
    expect(Object.keys(endpoints).sort()).toEqual(
      ["getPasswordPolicyStatus", "setPasswordChangeRequired", "unlockSignIn"].sort(),
    );
    for (const endpoint of Object.values(endpoints)) {
      expect(endpoint.path).toBeUndefined();
      expect(endpoint.options.metadata?.SERVER_ONLY).toBe(true);
    }
  });

  it.each([
    ["a string", "tenant-a"],
    ["an object", {}],
    ["a number", 1],
    ["true", true],
  ])("throws a password-policy TypeError when tenantPolicy is %s", (_name, value) => {
    let thrown: unknown;
    try {
      passwordPolicy({ tenantPolicy: value as never });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(TypeError);
    expect((thrown as TypeError).message.startsWith("password-policy:")).toBe(true);
  });

  it("accepts an omitted or undefined tenantPolicy", () => {
    expect(() => passwordPolicy({})).not.toThrow();
    expect(() => passwordPolicy({ tenantPolicy: undefined })).not.toThrow();
  });
});

describe("passwordPolicy factory with passwordNormalization", () => {
  it("registers the same hook counts as without the option", () => {
    const plugin = passwordPolicy({ passwordNormalization: "NFKC" });
    expect(plugin.hooks.before).toHaveLength(3);
    expect(plugin.hooks.after).toHaveLength(1);
  });

  it("registers the same hook counts when the option is false", () => {
    const plugin = passwordPolicy({ passwordNormalization: false });
    expect(plugin.hooks.before).toHaveLength(3);
    expect(plugin.hooks.after).toHaveLength(1);
  });

  it("keeps only the gate when lockout and complexity are off", () => {
    const plugin = passwordPolicy({ passwordNormalization: "NFKC", lockout: false, complexity: false });
    expect(plugin.hooks.before).toHaveLength(1);
    expect(plugin.hooks.after).toHaveLength(0);
  });

  it("keeps the schema and the endpoints the same", () => {
    const plugin = passwordPolicy({ passwordNormalization: "NFKC" });
    expect(Object.keys(plugin.schema).sort()).toEqual(Object.keys(passwordPolicy().schema).sort());
    expect(Object.keys(plugin.endpoints).sort()).toEqual(Object.keys(passwordPolicy().endpoints).sort());
  });

  it.each([
    ["true", true],
    ["NFKD", "NFKD"],
    ["nfkc", "nfkc"],
    ["null", null],
    ["a number", 1],
  ])("throws a password-policy TypeError at construction when the option is %s", (_name, value) => {
    let thrown: unknown;
    try {
      passwordPolicy({ passwordNormalization: value as never });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(TypeError);
    expect((thrown as TypeError).message.startsWith("password-policy:")).toBe(true);
  });

  it("rejects passwordNormalization in a tenant override", () => {
    expect(validateTenantPasswordPolicyOverride({ passwordNormalization: "NFKC" }).success).toBe(false);
  });
});

describe("passwordPolicySchema", () => {
  it("defines the user columns as optional and not settable by input", () => {
    expect(passwordPolicySchema.user.fields.mustChangePassword).toMatchObject({
      type: "boolean",
      required: false,
      defaultValue: false,
      input: false,
    });
    expect(passwordPolicySchema.user.fields.passwordChangedAt).toMatchObject({
      type: "date",
      required: false,
      input: false,
    });
  });

  it("defines passwordHistory with a cascading user reference and an index", () => {
    const fields = passwordPolicySchema.passwordHistory.fields;
    expect(fields.userId).toMatchObject({
      type: "string",
      required: true,
      references: { model: "user", field: "id", onDelete: "cascade" },
      index: true,
    });
    expect(fields.passwordHash).toMatchObject({ type: "string", required: true });
    expect(fields.createdAt).toMatchObject({ type: "date", required: true });
  });

  it("defines signInLockout with a unique identifier and zero default attempts", () => {
    const fields = passwordPolicySchema.signInLockout.fields;
    expect(fields.identifier).toMatchObject({ type: "string", required: true, unique: true });
    expect(fields.failedAttempts).toMatchObject({
      type: "number",
      required: true,
      defaultValue: 0,
    });
    expect(fields.lockedUntil).toMatchObject({ type: "date", required: false });
    expect(fields.lastAttemptAt).toMatchObject({ type: "date", required: true });
  });

  it("indexes signInLockout.lastAttemptAt so the retention purge can scan by age", () => {
    expect(passwordPolicySchema.signInLockout.fields.lastAttemptAt).toMatchObject({ index: true });
  });
});

describe("PASSWORD_POLICY_ERROR_CODES", () => {
  const expectedMessages: Record<string, string> = {
    PASSWORD_MISSING_UPPERCASE: "Password must contain at least one uppercase letter",
    PASSWORD_MISSING_LOWERCASE: "Password must contain at least one lowercase letter",
    PASSWORD_MISSING_DIGIT: "Password must contain at least one digit",
    PASSWORD_MISSING_SYMBOL: "Password must contain at least one symbol",
    PASSWORD_CONTAINS_PERSONAL_INFO: "Password must not contain your name or email",
    PASSWORD_REJECTED: "Password does not meet the password policy",
    PASSWORD_REUSED: "Password was used recently, choose a different password",
    PASSWORD_CHANGE_REQUIRED: "Password change required",
    PASSWORD_EXPIRED: "Password expired, change it to continue",
    SIGN_IN_LOCKED: "Too many failed sign-in attempts, try again later",
    PASSWORD_POLICY_UNAVAILABLE: "Password policy is unavailable, try again later",
  };

  it("defines exactly the documented keys", () => {
    expect(Object.keys(PASSWORD_POLICY_ERROR_CODES).sort()).toEqual(
      Object.keys(expectedMessages).sort(),
    );
  });

  it.each(Object.entries(expectedMessages))("%s carries its own key as code and the documented message", (key, message) => {
    const entry = (PASSWORD_POLICY_ERROR_CODES as Record<string, { code: string; message: string }>)[key];
    expect(entry.code).toBe(key);
    expect(entry.message).toBe(message);
  });
});

describe("PASSWORD_CHANGE_EXEMPT_PATHS", () => {
  it("contains every path the spec requires to stay reachable while a change is pending", () => {
    expect(PASSWORD_CHANGE_EXEMPT_PATHS).toEqual(
      expect.arrayContaining([
        "/change-password",
        "/sign-out",
        "/get-session",
        "/sign-in/email",
        "/sign-in/username",
        "/sign-in/phone-number",
        "/sign-in/social",
        "/sign-in/email-otp",
        "/callback/:id",
        "/sign-up/email",
        "/request-password-reset",
        "/reset-password",
        "/reset-password/:token",
        "/email-otp/send-verification-otp",
        "/email-otp/check-verification-otp",
        "/email-otp/verify-email",
        "/email-otp/request-password-reset",
        "/forget-password/email-otp",
        "/email-otp/reset-password",
        "/phone-number/request-password-reset",
        "/phone-number/reset-password",
        "/verify-email",
        "/send-verification-email",
        "/ok",
        "/error",
      ]),
    );
  });

  it("does not exempt ordinary authenticated routes", () => {
    expect(PASSWORD_CHANGE_EXEMPT_PATHS).not.toContain("/list-sessions");
    expect(PASSWORD_CHANGE_EXEMPT_PATHS).not.toContain("/update-user");
  });
});

describe("passwordPolicyClient", () => {
  it("has the plugin id password-policy", () => {
    expect(passwordPolicyClient().id).toBe("password-policy");
  });

  it("publishes the same error codes as the server entry point", () => {
    expect(passwordPolicyClient().$ERROR_CODES).toEqual(PASSWORD_POLICY_ERROR_CODES);
    expect(CLIENT_ERROR_CODES).toEqual(PASSWORD_POLICY_ERROR_CODES);
  });

  it("re-exports the pure requirement helpers", () => {
    expect(clientGetPasswordChangeRequirement).toBe(getPasswordChangeRequirement);
    expect(clientGetPasswordExpiresAt).toBe(getPasswordExpiresAt);
  });

  it("re-exports the tenant override validator and limits as the same references", () => {
    expect(clientValidateTenantPasswordPolicyOverride).toBe(validateTenantPasswordPolicyOverride);
    expect(CLIENT_TENANT_PASSWORD_POLICY_LIMITS).toBe(TENANT_PASSWORD_POLICY_LIMITS);
  });
});
