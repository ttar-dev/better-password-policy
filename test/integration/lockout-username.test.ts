import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthRegistry,
  deviceCookieHeadersFrom,
  expectTooManyRequests,
  expectUnauthorized,
  DEFAULT_EMAIL,
  DEFAULT_PASSWORD,
  GOOD_PASSWORDS,
  WRONG_PASSWORD,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";
import type { TenantPasswordPolicyContext, TenantPasswordPolicyResolver } from "../../src/index.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const policy = { lockout: { maxAttempts: 3 } };
const [, P1] = GOOD_PASSWORDS;
const OTHER_EMAIL = "alice-two@example.com";

const stripLeadingX = (value: string) => value.replace(/^x/, "");
const stripDots = (value: string) => value.replace(/\./g, "");

const wrongUsername = (t: TestAuth, username: string, headers?: Headers) =>
  expectUnauthorized(
    () =>
      t.auth.api.signInUsername({
        body: { username, password: WRONG_PASSWORD },
        ...(headers ? { headers } : {}),
      }),
    "INVALID_USERNAME_OR_PASSWORD",
  );

const lockedUsername = (t: TestAuth, username: string) =>
  expectTooManyRequests(
    () => t.auth.api.signInUsername({ body: { username, password: WRONG_PASSWORD } }),
    "SIGN_IN_LOCKED",
  );

const wrongTimes = async (count: number, run: () => Promise<unknown>) => {
  for (let attempt = 0; attempt < count; attempt += 1) {
    await run();
  }
};

describe("username lockout with the default username plugin", () => {
  it("counts attempts under one row regardless of the case typed", async () => {
    const t = await open({ policy });
    await t.signUp({ username: "alice_smith" });
    await wrongUsername(t, "ALICE_SMITH");
    await wrongUsername(t, "alice_smith");
    await wrongUsername(t, "Alice_Smith");
    expect(await t.lockoutRows()).toHaveLength(1);
    expect((await t.lockoutRow("username:alice_smith"))?.failedAttempts).toBe(3);
    await lockedUsername(t, "aLiCe_SmItH");
  });
});

describe("username lockout with a normalizer applied twice by pre-normalization", () => {
  const usernameOptions = {
    usernameNormalization: stripLeadingX,
    validationOrder: { username: "pre-normalization" },
  } as const;

  const prepare = async () => {
    const t = await open({ policy, usernameOptions });
    const user = await t.signUp({ username: "xAlice_Smith" });
    const stored = (await t.getUser(user.id)).username;
    return { t, user, stored };
  };

  it("stores the username normalized once", async () => {
    const { stored } = await prepare();
    expect(stored).toBe("Alice_Smith");
  });

  it("counts a failed sign-in under the lowercased stored username", async () => {
    const { t, stored } = await prepare();
    await wrongUsername(t, "xxAlice_Smith");
    await wrongUsername(t, "xxAlice_Smith");
    const row = await t.lockoutRow(`username:${stored!.toLowerCase()}`);
    expect(row?.failedAttempts).toBe(2);
    expect(await t.lockoutRows()).toHaveLength(1);
  });

  it("locks the stored username after maxAttempts and refuses the correct password", async () => {
    const { t } = await prepare();
    await wrongTimes(3, () => wrongUsername(t, "xxAlice_Smith"));
    await expectTooManyRequests(
      () =>
        t.auth.api.signInUsername({ body: { username: "xxAlice_Smith", password: DEFAULT_PASSWORD } }),
      "SIGN_IN_LOCKED",
    );
  });

  it("clears the counter when the correct password follows failures", async () => {
    const { t, stored } = await prepare();
    await wrongTimes(2, () => wrongUsername(t, "xxAlice_Smith"));
    const result = await t.auth.api.signInUsername({
      body: { username: "xxAlice_Smith", password: DEFAULT_PASSWORD },
    });
    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(await t.lockoutRow(`username:${stored!.toLowerCase()}`)).toBeNull();
  });

  it("is found by unlockSignIn", async () => {
    const { t, user } = await prepare();
    await wrongTimes(3, () => wrongUsername(t, "xxAlice_Smith"));
    await t.auth.api.unlockSignIn({ body: { userId: user.id } });
    expect(await t.lockoutRows()).toHaveLength(0);
    const result = await t.auth.api.signInUsername({
      body: { username: "xxAlice_Smith", password: DEFAULT_PASSWORD },
    });
    expect(result.user.id).toBe(user.id);
  });

  it("is reported by getPasswordPolicyStatus", async () => {
    const { t, user } = await prepare();
    await wrongTimes(2, () => wrongUsername(t, "xxAlice_Smith"));
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.failedSignInAttempts).toBe(2);
    expect(status.lockedUntil).toBeNull();
  });

  it("is cleared when the password is reset", async () => {
    const { t } = await prepare();
    await wrongTimes(3, () => wrongUsername(t, "xxAlice_Smith"));
    expect(await t.lockoutRows()).toHaveLength(1);
    const token = await t.requestResetToken(DEFAULT_EMAIL);
    await t.auth.api.resetPassword({ body: { newPassword: P1, token } });
    expect(await t.lockoutRows()).toHaveLength(0);
    const result = await t.auth.api.signInUsername({
      body: { username: "xxAlice_Smith", password: P1 },
    });
    expect(result.user.email).toBe(DEFAULT_EMAIL);
  });
});

describe("username lockout with a normalizer that keeps case", () => {
  const usernameOptions = { usernameNormalization: stripDots } as const;

  const prepare = async () => {
    const t = await open({ policy, usernameOptions });
    const user = await t.signUp({ username: "Al.Ice" });
    return { t, user };
  };

  it("stores AlIce and counts failures under username:alice", async () => {
    const { t, user } = await prepare();
    expect((await t.getUser(user.id)).username).toBe("AlIce");
    await wrongUsername(t, "Al.Ice");
    await wrongUsername(t, "A.l.I.c.e");
    expect((await t.lockoutRow("username:alice"))?.failedAttempts).toBe(2);
    expect(await t.lockoutRows()).toHaveLength(1);
  });

  it("is found by unlockSignIn", async () => {
    const { t, user } = await prepare();
    await wrongTimes(3, () => wrongUsername(t, "Al.Ice"));
    await lockedUsername(t, "Al.Ice");
    await t.auth.api.unlockSignIn({ body: { userId: user.id } });
    expect(await t.lockoutRows()).toHaveLength(0);
  });

  it("is reported by getPasswordPolicyStatus", async () => {
    const { t, user } = await prepare();
    await wrongTimes(3, () => wrongUsername(t, "Al.Ice"));
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.failedSignInAttempts).toBe(3);
    expect(status.lockedUntil).toBeInstanceOf(Date);
  });

  it("is cleared when the password is reset", async () => {
    const { t } = await prepare();
    await wrongTimes(3, () => wrongUsername(t, "Al.Ice"));
    const token = await t.requestResetToken(DEFAULT_EMAIL);
    await t.auth.api.resetPassword({ body: { newPassword: P1, token } });
    expect(await t.lockoutRows()).toHaveLength(0);
  });

  it("clears the counter when the correct password is used", async () => {
    const { t } = await prepare();
    await wrongTimes(2, () => wrongUsername(t, "Al.Ice"));
    await t.auth.api.signInUsername({ body: { username: "Al.Ice", password: DEFAULT_PASSWORD } });
    expect(await t.lockoutRow("username:alice")).toBeNull();
  });
});

describe("username lockout with usernameNormalization false", () => {
  const usernameOptions = { usernameNormalization: false } as const;

  const prepare = async (extra: Parameters<typeof open>[0] = {}) => {
    const t = await open({ policy, usernameOptions, ...extra });
    const upper = await t.signUp({ username: "Alice" });
    const lower = await t.signUp({ email: OTHER_EMAIL, name: "Alice Two", username: "alice" });
    return { t, upper, lower };
  };

  it("stores both usernames as typed", async () => {
    const { t, upper, lower } = await prepare();
    expect((await t.getUser(upper.id)).username).toBe("Alice");
    expect((await t.getUser(lower.id)).username).toBe("alice");
  });

  it("makes usernames that differ only in case share one counter", async () => {
    const { t } = await prepare();
    await wrongUsername(t, "Alice");
    await wrongUsername(t, "alice");
    await wrongUsername(t, "Alice");
    expect(await t.lockoutRows()).toHaveLength(1);
    expect((await t.lockoutRow("username:alice"))?.failedAttempts).toBe(3);
    await lockedUsername(t, "alice");
  });

  it("counts a wrong password sent with the device cookie of the typed user in that user's device row", async () => {
    const { t, upper, lower } = await prepare();
    const device = deviceCookieHeadersFrom(
      (
        await t.auth.api.signInEmail({
          body: { email: DEFAULT_EMAIL, password: DEFAULT_PASSWORD },
          returnHeaders: true,
        })
      ).headers,
    );
    await wrongUsername(t, "Alice", device);
    await wrongUsername(t, "Alice", device);
    const upperRows = await t.deviceLockoutRows(upper.id);
    expect(upperRows).toHaveLength(1);
    expect(upperRows[0]?.failedAttempts).toBe(2);
    expect(await t.deviceLockoutRows(lower.id)).toHaveLength(0);
    expect(await t.lockoutRow("username:alice")).toBeNull();
  });

  it("applies the tenant override of the user found by the typed username", async () => {
    let upperId = "";
    const tenantPolicy = ((context: TenantPasswordPolicyContext) =>
      context.user?.id === upperId ? { lockout: { maxAttempts: 2 } } : null) as TenantPasswordPolicyResolver;
    const { t, upper } = await prepare({ policy: { tenantPolicy } });
    upperId = upper.id;
    await wrongUsername(t, "Alice");
    await wrongUsername(t, "Alice");
    expect((await t.lockoutRow("username:alice"))?.lockedUntil).toBeInstanceOf(Date);
    await lockedUsername(t, "Alice");
  });
});
