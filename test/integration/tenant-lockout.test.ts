import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthRegistry,
  deviceCookieHeadersFrom,
  deviceSetCookieFrom,
  expectServiceUnavailable,
  expectTooManyRequests,
  expectUnauthorized,
  DEFAULT_EMAIL,
  DEFAULT_PASSWORD,
  WRONG_PASSWORD,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";
import type { TenantPasswordPolicyContext, TenantPasswordPolicyResolver } from "../../src/index.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const EMAIL_IDENTIFIER = `email:${DEFAULT_EMAIL}`;
const PHONE = "+66812345678";
const USERNAME = "alice_smith";

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

const strictFor = (userIds: () => string[], lockout: { maxAttempts?: number; duration?: number }): Decider =>
  (context) => (context.user && userIds().includes(context.user.id) ? { lockout } : null);

const wrongEmailSignIn = (t: TestAuth, email = DEFAULT_EMAIL) =>
  expectUnauthorized(
    () => t.auth.api.signInEmail({ body: { email, password: WRONG_PASSWORD } }),
    "INVALID_EMAIL_OR_PASSWORD",
  );

const correctEmailSignIn = (t: TestAuth, email = DEFAULT_EMAIL) =>
  t.auth.api.signInEmail({ body: { email, password: DEFAULT_PASSWORD } });

const lockedEmailSignIn = (t: TestAuth, email = DEFAULT_EMAIL) =>
  expectTooManyRequests(
    () => t.auth.api.signInEmail({ body: { email, password: WRONG_PASSWORD } }),
    "SIGN_IN_LOCKED",
  );

describe("tenant lockout thresholds", () => {
  it("locks a tenant user after the tenant maxAttempts of two when the platform allows five", async () => {
    let strictId = "";
    const probe = createProbe(strictFor(() => [strictId], { maxAttempts: 2 }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    strictId = (await t.signUp()).id;
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.lockedUntil).toBeInstanceOf(Date);
    await lockedEmailSignIn(t);
  });

  it("does not lock a user without a tenant override before the platform limit", async () => {
    let strictId = "";
    const probe = createProbe(strictFor(() => [strictId], { maxAttempts: 2 }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    strictId = (await t.signUp()).id;
    await t.signUp({ email: "bob@example.com", name: "Bob Jones" });
    await wrongEmailSignIn(t, "bob@example.com");
    await wrongEmailSignIn(t, "bob@example.com");
    await wrongEmailSignIn(t, "bob@example.com");
    expect((await t.lockoutRow("email:bob@example.com"))?.failedAttempts).toBe(3);
  });

  it("still locks a non-existent identifier at the platform limit of five", async () => {
    let strictId = "";
    const probe = createProbe(strictFor(() => [strictId], { maxAttempts: 2 }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    strictId = (await t.signUp()).id;
    const ghost = "ghost@example.com";
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await wrongEmailSignIn(t, ghost);
    }
    await lockedEmailSignIn(t, ghost);
  });

  it("uses the platform limit when the tenant allows more attempts", async () => {
    let strictId = "";
    const probe = createProbe(strictFor(() => [strictId], { maxAttempts: 10 }));
    const t = await open({
      policy: { tenantPolicy: probe.tenantPolicy, lockout: { maxAttempts: 3 } },
    });
    strictId = (await t.signUp()).id;
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    await lockedEmailSignIn(t);
  });

  it("sets lockedUntil about the tenant duration ahead when the tenant duration is longer", async () => {
    let strictId = "";
    const probe = createProbe(strictFor(() => [strictId], { maxAttempts: 2, duration: 3600 }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    strictId = user.id;
    const startedAt = Date.now();
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.lockedUntil).toBeInstanceOf(Date);
    expect(status.lockedUntil!.getTime()).toBeGreaterThanOrEqual(startedAt + 3590_000);
    expect(status.lockedUntil!.getTime()).toBeLessThanOrEqual(Date.now() + 3605_000);
  });

  it("resets the counter on a correct password so the tenant limit starts over", async () => {
    let strictId = "";
    const probe = createProbe(strictFor(() => [strictId], { maxAttempts: 2 }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    strictId = (await t.signUp()).id;
    await wrongEmailSignIn(t);
    const result = await correctEmailSignIn(t);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
    await wrongEmailSignIn(t);
    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(1);
  });
});

describe("tenant lockout callback context", () => {
  it("hands the callback the found user, their email and the sign-in path for an existing email", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.calls.length = 0;
    await wrongEmailSignIn(t, "ALICE@example.com");
    expect(probe.calls).toHaveLength(1);
    expect(probe.calls[0]?.user?.id).toBe(user.id);
    expect(probe.calls[0]?.email).toBe(DEFAULT_EMAIL);
    expect(probe.calls[0]?.path).toBe("/sign-in/email");
  });

  it("hands the callback a null user and the lowercase email for a non-existent email", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await t.signUp();
    probe.calls.length = 0;
    await wrongEmailSignIn(t, "Ghost@Example.COM");
    expect(probe.calls).toHaveLength(1);
    expect(probe.calls[0]).toMatchObject({
      user: null,
      email: "ghost@example.com",
      path: "/sign-in/email",
    });
  });

  it("finds the user from a username sign-in", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp({ username: USERNAME });
    probe.calls.length = 0;
    await expectUnauthorized(
      () => t.auth.api.signInUsername({ body: { username: USERNAME, password: WRONG_PASSWORD } }),
      "INVALID_USERNAME_OR_PASSWORD",
    );
    expect(probe.calls).toHaveLength(1);
    expect(probe.calls[0]?.user?.id).toBe(user.id);
    expect(probe.calls[0]?.email).toBe(DEFAULT_EMAIL);
    expect(probe.calls[0]?.path).toBe("/sign-in/username");
  });

  it("hands the callback a null user and a null email for a non-existent username", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await t.signUp({ username: USERNAME });
    probe.calls.length = 0;
    await expectUnauthorized(
      () => t.auth.api.signInUsername({ body: { username: "nobody_here", password: WRONG_PASSWORD } }),
      "INVALID_USERNAME_OR_PASSWORD",
    );
    expect(probe.calls[0]).toMatchObject({ user: null, email: null });
  });

  it("finds the user from a phone-number sign-in", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    await t.markPhoneNumber(user.id, PHONE);
    probe.calls.length = 0;
    await expectUnauthorized(
      () => t.auth.api.signInPhoneNumber({ body: { phoneNumber: PHONE, password: WRONG_PASSWORD } }),
      "INVALID_PHONE_NUMBER_OR_PASSWORD",
    );
    expect(probe.calls).toHaveLength(1);
    expect(probe.calls[0]?.user?.id).toBe(user.id);
    expect(probe.calls[0]?.path).toBe("/sign-in/phone-number");
  });

  it("locks the tenant user through a username sign-in at the tenant limit", async () => {
    let strictId = "";
    const probe = createProbe(strictFor(() => [strictId], { maxAttempts: 2 }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    strictId = (await t.signUp({ username: USERNAME })).id;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await expectUnauthorized(
        () => t.auth.api.signInUsername({ body: { username: USERNAME, password: WRONG_PASSWORD } }),
        "INVALID_USERNAME_OR_PASSWORD",
      );
    }
    await expectTooManyRequests(
      () => t.auth.api.signInUsername({ body: { username: USERNAME, password: DEFAULT_PASSWORD } }),
      "SIGN_IN_LOCKED",
    );
  });

  it("calls the callback exactly once per attempt including the after-hook", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await t.signUp();
    probe.calls.length = 0;
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    expect(probe.calls).toHaveLength(2);
  });

  it("does not call the callback while the identifier is locked", async () => {
    let strictId = "";
    const probe = createProbe(strictFor(() => [strictId], { maxAttempts: 2 }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    strictId = (await t.signUp()).id;
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    probe.calls.length = 0;
    await lockedEmailSignIn(t);
    expect(probe.calls).toHaveLength(0);
  });
});

describe("tenant lockout when the callback fails", () => {
  const unavailable = (t: TestAuth, email = DEFAULT_EMAIL) =>
    expectServiceUnavailable(
      () => t.auth.api.signInEmail({ body: { email, password: WRONG_PASSWORD } }),
      "PASSWORD_POLICY_UNAVAILABLE",
    );

  it("answers 503, creates no lockout row and verifies no password for a first attempt", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await t.signUp();
    probe.decideWith(() => {
      throw new Error("tenant store down");
    });
    const verifyCallsBefore = t.verifyCalls();
    await unavailable(t);
    expect(await t.lockoutRows()).toHaveLength(0);
    expect(t.verifyCalls()).toBe(verifyCallsBefore);
  });

  it("answers 503 for an invalid override too", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await t.signUp();
    probe.decideWith(() => ({ lockout: { maxAttempts: 0 } }));
    await unavailable(t);
    expect(await t.lockoutRows()).toHaveLength(0);
  });

  it("leaves the existing count untouched on 503 and continues counting once the callback recovers", async () => {
    let strictId = "";
    const healthy = (context: TenantPasswordPolicyContext) =>
      strictFor(() => [strictId], { maxAttempts: 2 })(context);
    const probe = createProbe(healthy);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    strictId = (await t.signUp()).id;
    await wrongEmailSignIn(t);
    probe.decideWith(() => Promise.reject(new Error("tenant store down")));
    const verifyCallsBefore = t.verifyCalls();
    await unavailable(t);
    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(1);
    expect(t.verifyCalls()).toBe(verifyCallsBefore);
    probe.decideWith(healthy);
    await wrongEmailSignIn(t);
    const row = await t.lockoutRow(EMAIL_IDENTIFIER);
    expect(row?.failedAttempts).toBe(2);
    expect(row?.lockedUntil).toBeInstanceOf(Date);
  });
});

describe("tenant lockout with lockout switched off", () => {
  it("writes no rows and never calls the callback", async () => {
    const probe = createProbe(() => ({ lockout: { maxAttempts: 1 } }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy, lockout: false } });
    await t.signUp();
    probe.calls.length = 0;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      await wrongEmailSignIn(t);
    }
    expect(await t.lockoutRows()).toHaveLength(0);
    expect(probe.calls).toHaveLength(0);
  });
});

describe("tenant lockout on the trusted device path", () => {
  const obtainDevice = async (t: TestAuth) =>
    deviceCookieHeadersFrom(
      (
        await t.auth.api.signInEmail({
          body: { email: DEFAULT_EMAIL, password: DEFAULT_PASSWORD },
          returnHeaders: true,
        })
      ).headers,
    );

  const wrongWith = (t: TestAuth, device: Headers) =>
    expectUnauthorized(
      () =>
        t.auth.api.signInEmail({
          body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD },
          headers: device,
        }),
      "INVALID_EMAIL_OR_PASSWORD",
    );

  it("locks the device at the tenant maxAttempts with the tenant duration and leaves the identifier row untouched", async () => {
    let strictId = "";
    const probe = createProbe(strictFor(() => [strictId], { maxAttempts: 2, duration: 3600 }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    strictId = user.id;
    const device = await obtainDevice(t);
    const startedAt = Date.now();
    await wrongWith(t, device);
    await wrongWith(t, device);

    const [deviceRow] = await t.deviceLockoutRows(user.id);
    expect(deviceRow?.failedAttempts).toBe(2);
    expect(deviceRow?.lockedUntil).toBeInstanceOf(Date);
    expect(deviceRow!.lockedUntil!.getTime()).toBeGreaterThanOrEqual(startedAt + 3590_000);
    expect(deviceRow!.lockedUntil!.getTime()).toBeLessThanOrEqual(Date.now() + 3605_000);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
  });

  it("calls the callback exactly once per trusted attempt", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await t.signUp();
    const device = await obtainDevice(t);
    probe.calls.length = 0;
    await wrongWith(t, device);
    await wrongWith(t, device);
    expect(probe.calls).toHaveLength(2);
  });

  it("does not call the callback and verifies no password while the device is locked", async () => {
    let strictId = "";
    const probe = createProbe(strictFor(() => [strictId], { maxAttempts: 2 }));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    strictId = (await t.signUp()).id;
    const device = await obtainDevice(t);
    await wrongWith(t, device);
    await wrongWith(t, device);
    probe.calls.length = 0;
    const verifyCallsBefore = t.verifyCalls();
    await expectTooManyRequests(
      () =>
        t.auth.api.signInEmail({
          body: { email: DEFAULT_EMAIL, password: DEFAULT_PASSWORD },
          headers: device,
        }),
      "SIGN_IN_LOCKED",
    );
    expect(probe.calls).toHaveLength(0);
    expect(t.verifyCalls()).toBe(verifyCallsBefore);
  });

  it("answers 503, creates no device row and verifies no password when the callback throws for a trusted request", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    probe.decideWith(() => {
      throw new Error("tenant store down");
    });
    const verifyCallsBefore = t.verifyCalls();
    await expectServiceUnavailable(
      () =>
        t.auth.api.signInEmail({
          body: { email: DEFAULT_EMAIL, password: DEFAULT_PASSWORD },
          headers: device,
        }),
      "PASSWORD_POLICY_UNAVAILABLE",
    );
    expect(await t.deviceLockoutRows(user.id)).toHaveLength(0);
    expect(await t.lockoutRows()).toHaveLength(0);
    expect(t.verifyCalls()).toBe(verifyCallsBefore);
  });

  it("sets no device cookie on the 503 answer", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    await t.signUp();
    probe.decideWith(() => {
      throw new Error("tenant store down");
    });
    const response = await t.signInResponse("/sign-in/email", {
      email: DEFAULT_EMAIL,
      password: DEFAULT_PASSWORD,
    });
    expect(response.status).toBe(503);
    expect(deviceSetCookieFrom(response.headers)).toBeUndefined();
  });
});
