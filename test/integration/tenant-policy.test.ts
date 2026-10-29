import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthRegistry,
  expectBadRequest,
  expectServiceUnavailable,
  pause,
  DEFAULT_EMAIL,
  DEFAULT_NAME,
  DEFAULT_PASSWORD,
  GOOD_PASSWORDS,
  WEAK_NO_UPPERCASE,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";
import type { TenantPasswordPolicyContext, TenantPasswordPolicyResolver } from "../../src/index.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const [P0, P1, P2, P3] = GOOD_PASSWORDS;
const ORIGINAL_HASH = `fast:${DEFAULT_PASSWORD}`;
const STRICT_HEADERS = () => new Headers({ "x-tenant": "strict" });
const THAI_PASSWORD = "\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19\u0e44\u0e17\u0e22123";

type Decider = (context: TenantPasswordPolicyContext) => unknown;

const createProbe = (initial: Decider) => {
  const calls: TenantPasswordPolicyContext[] = [];
  let decide = initial;
  const tenantPolicy = ((context: TenantPasswordPolicyContext) => {
    calls.push(context);
    return decide(context);
  }) as TenantPasswordPolicyResolver;
  return {
    calls,
    tenantPolicy,
    decideWith: (next: Decider) => {
      decide = next;
    },
  };
};

const fixed = (override: unknown): Decider => () => override;

const failures: [string, Decider][] = [
  [
    "throws synchronously",
    () => {
      throw new Error("tenant store down");
    },
  ],
  ["rejects", () => Promise.reject(new Error("tenant store down"))],
  ["returns an unknown key", fixed({ complexity: { requireNumber: true } })],
  ["returns an out-of-range value", fixed({ history: { count: 99 } })],
  ["returns false", fixed(false)],
];

const change = async (t: TestAuth, headers: Headers, currentPassword: string, newPassword: string) => {
  await pause();
  return t.auth.api.changePassword({ body: { currentPassword, newPassword }, headers });
};

const signUpNew = (t: TestAuth, headers?: Headers, email = "nina@example.com", password = DEFAULT_PASSWORD) =>
  t.auth.api.signUpEmail({
    body: { email, name: "Nina Park", password },
    ...(headers ? { headers } : {}),
  });

const settledUser = async (t: TestAuth, userId: string) => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if ((await t.getUser(userId)).passwordChangedAt !== null) return;
    await pause(10);
  }
  throw new Error("passwordChangedAt was never recorded");
};

const seedHistory = async (t: TestAuth, userId: string, count: number) => {
  for (let index = 0; index < count; index += 1) {
    await t.adapter.create({
      model: "passwordHistory",
      data: {
        userId,
        passwordHash: `fast:Seeded${index}Password`,
        createdAt: new Date(Date.now() - (count - index) * 60_000),
      },
    });
  }
};

const credentialWriteOutsideEndpoint = async (t: TestAuth, userId: string) => {
  await t.context.internalAdapter.createAccount({
    userId,
    providerId: "credential",
    accountId: userId,
    password: `fast:${P1}`,
  });
  await settledUser(t, userId);
};

describe("tenant override on sign-up", () => {
  it("hands the callback a null user, the lowercase email, the path and a copy of the headers", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await signUpNew(t, STRICT_HEADERS(), "Nina@Example.COM");
    expect(probe.calls).toHaveLength(1);
    expect(probe.calls[0]).toMatchObject({
      user: null,
      email: "nina@example.com",
      path: "/sign-up/email",
      request: null,
    });
    expect(probe.calls[0]?.headers?.get("x-tenant")).toBe("strict");
  });

  it("enforces an override chosen from the header and creates no user when it fails", async () => {
    const probe = createProbe((context) =>
      context.headers?.get("x-tenant") === "strict" ? { complexity: { requireSymbol: true } } : null,
    );
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await expectBadRequest(() => signUpNew(t, STRICT_HEADERS()), "PASSWORD_MISSING_SYMBOL");
    expect(await t.context.internalAdapter.findUserByEmail("nina@example.com")).toBeNull();
  });

  it("applies only the platform policy when the header selects no tenant", async () => {
    const probe = createProbe((context) =>
      context.headers?.get("x-tenant") === "strict" ? { complexity: { requireSymbol: true } } : null,
    );
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const result = await signUpNew(t);
    expect(result.user.email).toBe("nina@example.com");
  });

  it("calls the callback once per sign-up", async () => {
    const probe = createProbe(fixed({ complexity: { requireSymbol: false } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await signUpNew(t);
    expect(probe.calls).toHaveLength(1);
  });
});

describe("tenant override of caselessLettersSatisfyCase on sign-up", () => {
  const tenantTurnsOff = (context: TenantPasswordPolicyContext) =>
    context.headers?.get("x-tenant") === "strict" ? { complexity: { caselessLettersSatisfyCase: false } } : null;

  it("rejects a Thai-only password for a tenant that switches the platform option off", async () => {
    const probe = createProbe(tenantTurnsOff);
    const t = await open({
      policy: { tenantPolicy: probe.tenantPolicy, complexity: { caselessLettersSatisfyCase: true } },
    });
    await expectBadRequest(
      () => signUpNew(t, STRICT_HEADERS(), "nina@example.com", THAI_PASSWORD),
      "PASSWORD_MISSING_UPPERCASE",
    );
    expect(await t.context.internalAdapter.findUserByEmail("nina@example.com")).toBeNull();
  });

  it("accepts a Thai-only password for a tenant that does not switch the option off", async () => {
    const probe = createProbe(tenantTurnsOff);
    const t = await open({
      policy: { tenantPolicy: probe.tenantPolicy, complexity: { caselessLettersSatisfyCase: true } },
    });
    const result = await signUpNew(t, undefined, "nina@example.com", THAI_PASSWORD);
    expect(result.user.email).toBe("nina@example.com");
  });

  it("still rejects a Thai-only password when the tenant tries to switch the option on", async () => {
    const probe = createProbe(fixed({ complexity: { caselessLettersSatisfyCase: true } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await expectBadRequest(
      () => signUpNew(t, undefined, "nina@example.com", THAI_PASSWORD),
      "PASSWORD_MISSING_UPPERCASE",
    );
  });
});

describe("tenant override on change-password", () => {
  it("hands the callback the session user, their email and the path", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.calls.length = 0;
    await change(t, user.headers, DEFAULT_PASSWORD, P1);
    expect(probe.calls).toHaveLength(1);
    expect(probe.calls[0]?.user?.id).toBe(user.id);
    expect(probe.calls[0]?.email).toBe(DEFAULT_EMAIL);
    expect(probe.calls[0]?.path).toBe("/change-password");
  });

  it("enforces a tenant minLength with PASSWORD_TOO_SHORT and leaves the hash unchanged", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.decideWith(fixed({ complexity: { minLength: 20 } }));
    await expectBadRequest(() => change(t, user.headers, DEFAULT_PASSWORD, P1), "PASSWORD_TOO_SHORT");
    expect((await t.getCredentialAccount(user.id)).password).toBe(ORIGINAL_HASH);
  });

  it("enforces a tenant history count above the platform count and keeps four rows", async () => {
    const probe = createProbe(fixed({ history: { count: 3 } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy, history: { count: 1 } } });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P1);
    await change(t, user.headers, P1, P2);
    await change(t, user.headers, P2, P3);
    await expectBadRequest(() => change(t, user.headers, P3, P0), "PASSWORD_REUSED");
    expect(await t.historyRows(user.id)).toHaveLength(4);
  });

  it("calls the callback once for a request that also prunes history", async () => {
    const probe = createProbe(fixed({ history: { count: 3 } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy, history: { count: 1 } } });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P1);
    probe.calls.length = 0;
    await change(t, user.headers, P1, P2);
    expect(await t.historyRows(user.id)).toHaveLength(3);
    expect(probe.calls).toHaveLength(1);
  });
});

describe("tenant override on reset-password", () => {
  it("hands the callback the token owner and the path", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    const token = await t.requestResetToken(user.email);
    probe.calls.length = 0;
    await t.auth.api.resetPassword({ body: { newPassword: P1, token } });
    const call = probe.calls.find((entry) => entry.path === "/reset-password");
    expect(call?.user?.id).toBe(user.id);
    expect(call?.email).toBe(DEFAULT_EMAIL);
  });

  it("enforces the tenant rule and leaves the hash unchanged", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp({ password: P0 });
    const token = await t.requestResetToken(user.email);
    probe.decideWith(fixed({ complexity: { requireSymbol: true } }));
    await expectBadRequest(
      () => t.auth.api.resetPassword({ body: { newPassword: P1, token } }),
      "PASSWORD_MISSING_SYMBOL",
    );
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${P0}`);
  });
});

describe("tenant override on admin create-user", () => {
  it("hands the callback a null user, the lowercase email and the path", async () => {
    const probe = createProbe(fixed({ complexity: { requireSymbol: true } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await expectBadRequest(
      () =>
        t.auth.api.createUser({
          body: { email: "Made@Example.COM", password: P1, name: "Made Up", role: "user" },
        }),
      "PASSWORD_MISSING_SYMBOL",
    );
    const call = probe.calls.find((entry) => entry.path === "/admin/create-user");
    expect(call).toMatchObject({ user: null, email: "made@example.com", path: "/admin/create-user" });
  });

  it("creates no user when the tenant rule fails", async () => {
    const probe = createProbe(fixed({ complexity: { requireSymbol: true } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await expectBadRequest(
      () =>
        t.auth.api.createUser({
          body: { email: "made@example.com", password: P1, name: "Made Up", role: "user" },
        }),
      "PASSWORD_MISSING_SYMBOL",
    );
    expect(await t.context.internalAdapter.findUserByEmail("made@example.com")).toBeNull();
  });
});

describe("tenant policy can only tighten", () => {
  it("ignores an override that switches a platform complexity rule off", async () => {
    const probe = createProbe(fixed({ complexity: { requireUppercase: false } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await expectBadRequest(
      () => signUpNew(t, undefined, "nina@example.com", WEAK_NO_UPPERCASE),
      "PASSWORD_MISSING_UPPERCASE",
    );
  });

  it("ignores an override that lowers the platform history count", async () => {
    const probe = createProbe(fixed({ history: { count: 0 } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy, history: { count: 2 } } });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P1);
    await change(t, user.headers, P1, P2);
    await expectBadRequest(() => change(t, user.headers, P2, P0), "PASSWORD_REUSED");
  });
});

describe("tenant policy with a platform feature switched off", () => {
  it("accepts a weak password and never calls the callback when complexity is false", async () => {
    const probe = createProbe(fixed({ complexity: { requireSymbol: true } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy, complexity: false } });
    const result = await signUpNew(t, undefined, "nina@example.com", WEAK_NO_UPPERCASE);
    expect(result.user.email).toBe("nina@example.com");
    expect(probe.calls).toHaveLength(0);
  });

  it("writes no history rows and allows reuse when history is false", async () => {
    const probe = createProbe(fixed({ history: { count: 3 } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy, history: false } });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P0);
    expect(await t.allHistoryRows()).toHaveLength(0);
  });
});

describe("tenant policy with no override", () => {
  it.each([
    ["null", null],
    ["undefined", undefined],
    ["an empty object", {}],
  ])("falls back to the platform policy when the callback returns %s", async (_name, value) => {
    const probe = createProbe(fixed(value));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await expectBadRequest(
      () => signUpNew(t, undefined, "nina@example.com", WEAK_NO_UPPERCASE),
      "PASSWORD_MISSING_UPPERCASE",
    );
    const result = await signUpNew(t, undefined, "nina@example.com", P0);
    expect(result.user.email).toBe("nina@example.com");
  });

  it("falls back to the platform policy when the callback resolves to null asynchronously", async () => {
    const probe = createProbe(async () => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await expectBadRequest(
      () => signUpNew(t, undefined, "nina@example.com", WEAK_NO_UPPERCASE),
      "PASSWORD_MISSING_UPPERCASE",
    );
  });
});

describe("tenant policy that fails closed", () => {
  describe.each(failures)("when the callback %s", (_name, failure) => {
    it("answers 503 PASSWORD_POLICY_UNAVAILABLE on sign-up and creates no user", async () => {
      const probe = createProbe(failure);
      const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
      await expectServiceUnavailable(() => signUpNew(t), "PASSWORD_POLICY_UNAVAILABLE");
      expect(await t.context.internalAdapter.findUserByEmail("nina@example.com")).toBeNull();
    });

    it("answers 503 PASSWORD_POLICY_UNAVAILABLE on change-password and records no new history row", async () => {
      const probe = createProbe(fixed(null));
      const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
      const user = await t.signUp();
      const rowsBefore = await t.historyRows(user.id);
      probe.decideWith(failure);
      await expectServiceUnavailable(
        () => change(t, user.headers, DEFAULT_PASSWORD, P1),
        "PASSWORD_POLICY_UNAVAILABLE",
      );
      expect((await t.getCredentialAccount(user.id)).password).toBe(ORIGINAL_HASH);
      expect(await t.historyRows(user.id)).toHaveLength(rowsBefore.length);
    });

    it("answers 503 PASSWORD_POLICY_UNAVAILABLE on admin create-user and creates no user", async () => {
      const probe = createProbe(failure);
      const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
      await expectServiceUnavailable(
        () =>
          t.auth.api.createUser({
            body: { email: "made@example.com", password: P1, name: DEFAULT_NAME, role: "user" },
          }),
        "PASSWORD_POLICY_UNAVAILABLE",
      );
      expect(await t.context.internalAdapter.findUserByEmail("made@example.com")).toBeNull();
    });
  });
});

describe("history pruning in the database hook", () => {
  it("keeps every row but still records passwordChangedAt when the callback throws", async () => {
    const probe = createProbe(() => {
      throw new Error("tenant store down");
    });
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy, history: { count: 1 } } });
    const user = await t.createSessionOnlyUser("sam@example.com", "Sam Setter");
    await seedHistory(t, user.id, 6);
    await credentialWriteOutsideEndpoint(t, user.id);
    expect(await t.historyRows(user.id)).toHaveLength(7);
    expect((await t.getUser(user.id)).passwordChangedAt).not.toBeNull();
  });

  it("prunes to the tenant count plus one when the tenant count exceeds the platform count", async () => {
    const probe = createProbe(fixed({ history: { count: 3 } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy, history: { count: 1 } } });
    const user = await t.createSessionOnlyUser("sam@example.com", "Sam Setter");
    await seedHistory(t, user.id, 6);
    await credentialWriteOutsideEndpoint(t, user.id);
    expect(await t.historyRows(user.id)).toHaveLength(4);
  });

  it("hands the callback the user and a null path when the write happens outside an endpoint", async () => {
    const probe = createProbe(fixed({ history: { count: 3 } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy, history: { count: 1 } } });
    const user = await t.createSessionOnlyUser("sam@example.com", "Sam Setter");
    await seedHistory(t, user.id, 6);
    probe.calls.length = 0;
    await credentialWriteOutsideEndpoint(t, user.id);
    expect(probe.calls.at(-1)?.user?.id).toBe(user.id);
    expect(probe.calls.at(-1)?.email).toBe("sam@example.com");
    expect(probe.calls.at(-1)?.path).toBeNull();
  });

  it("prunes to the platform count plus one when there is no tenantPolicy", async () => {
    const t = await open({ policy: { history: { count: 1 } } });
    const user = await t.createSessionOnlyUser("sam@example.com", "Sam Setter");
    await seedHistory(t, user.id, 6);
    await credentialWriteOutsideEndpoint(t, user.id);
    expect(await t.historyRows(user.id)).toHaveLength(2);
  });
});

describe("getPasswordPolicyStatus policy field", () => {
  const strict = {
    complexity: { minLength: 12, requireSymbol: true },
    history: { count: 7 },
    expiration: { maxAge: 7776000 },
    lockout: { maxAttempts: 3, duration: 3600 },
  };

  it("reports the merged effective policy for the user", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.decideWith(fixed(strict));
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.policy).toEqual({
      minLength: 12,
      maxLength: 128,
      complexity: {
        requireUppercase: true,
        requireLowercase: true,
        requireDigit: true,
        requireSymbol: true,
        rejectPersonalInfo: true,
        caselessLettersSatisfyCase: false,
        customValidation: false,
      },
      history: { count: 7 },
      expiration: { maxAge: 7776000 },
      lockout: { maxAttempts: 3, duration: 3600 },
    });
  });

  it("reports caselessLettersSatisfyCase true when the platform has it on and the tenant sends nothing", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({
      policy: { tenantPolicy: probe.tenantPolicy, complexity: { caselessLettersSatisfyCase: true } },
    });
    const user = await t.signUp();
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.policy.complexity?.caselessLettersSatisfyCase).toBe(true);
  });

  it("reports caselessLettersSatisfyCase false when the platform has it on and the tenant switches it off", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({
      policy: { tenantPolicy: probe.tenantPolicy, complexity: { caselessLettersSatisfyCase: true } },
    });
    const user = await t.signUp();
    probe.decideWith(fixed({ complexity: { caselessLettersSatisfyCase: false } }));
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.policy.complexity?.caselessLettersSatisfyCase).toBe(false);
  });

  it("reports caselessLettersSatisfyCase false when the platform has it off and the tenant sends true", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.decideWith(fixed({ complexity: { caselessLettersSatisfyCase: true } }));
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.policy.complexity?.caselessLettersSatisfyCase).toBe(false);
  });

  it("keeps Better Auth's minimum when the tenant minLength is lower", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.decideWith(fixed({ complexity: { minLength: 6 } }));
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.policy.minLength).toBe(8);
  });

  it("reports the platform policy when there is no tenantPolicy", async () => {
    const t = await open();
    const user = await t.signUp();
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.policy).toEqual({
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

  it("hands the callback the user, a null path and null headers when none are passed", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.calls.length = 0;
    await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(probe.calls).toHaveLength(1);
    expect(probe.calls[0]?.user?.id).toBe(user.id);
    expect(probe.calls[0]?.email).toBe(DEFAULT_EMAIL);
    expect(probe.calls[0]?.path).toBeNull();
    expect(probe.calls[0]?.headers).toBeNull();
  });

  it("hands the callback a copy of the headers that were passed", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.calls.length = 0;
    const headers = STRICT_HEADERS();
    await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id }, headers });
    const received = probe.calls[0]?.headers;
    expect(received?.get("x-tenant")).toBe("strict");
    expect(received).not.toBe(headers);
  });

  it("answers 503 PASSWORD_POLICY_UNAVAILABLE when the callback throws", async () => {
    const probe = createProbe(fixed(null));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.decideWith(failures[0]![1]);
    await expectServiceUnavailable(
      () => t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } }),
      "PASSWORD_POLICY_UNAVAILABLE",
    );
  });
});
