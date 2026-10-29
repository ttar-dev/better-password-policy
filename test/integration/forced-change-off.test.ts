import { describe, it, expect, afterEach, vi } from "vitest";
import {
  createAuthRegistry,
  deviceCookieHeadersFrom,
  expectBadRequest,
  expectForbidden,
  expectUnauthorized,
  pause,
  DEFAULT_EMAIL,
  DEFAULT_PASSWORD,
  GOOD_PASSWORDS,
  WRONG_PASSWORD,
} from "../harness/create-test-auth.ts";
import type { TestAuth, TestAuthOptions } from "../harness/create-test-auth.ts";
import type { PasswordPolicyOptions } from "../../src/index.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  vi.restoreAllMocks();
  await registry.closeAll();
});

const [, P1] = GOOD_PASSWORDS;
const TWO_HOURS = 7200;
const TWO_DAYS = 2 * 86400;
const FORCED_OFF_CODE = "FORCED_PASSWORD_CHANGE_DISABLED";
const EMAIL_IDENTIFIER = `email:${DEFAULT_EMAIL}`;

const flag = (t: TestAuth, userId: string, required: boolean) =>
  t.auth.api.setPasswordChangeRequired({ body: { userId, required } });

const setStoredFlag = (t: TestAuth, userId: string) =>
  t.updateUserRow(userId, { mustChangePassword: true });

const countSessionLookups = async (t: TestAuth, headers: Headers): Promise<number> => {
  const spy = vi.spyOn(t.context.internalAdapter, "findSession");
  try {
    const sessions = await t.auth.api.listSessions({ headers });
    expect(sessions.length).toBeGreaterThan(0);
    return spy.mock.calls.length;
  } finally {
    spy.mockRestore();
  }
};

const wrongEmail = (t: TestAuth, headers?: Headers) =>
  expectUnauthorized(
    () =>
      t.auth.api.signInEmail({
        body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD },
        ...(headers ? { headers } : {}),
      }),
    "INVALID_EMAIL_OR_PASSWORD",
  );

describe("forcedChange false with expiration false", () => {
  const policy: PasswordPolicyOptions = { forcedChange: false, expiration: false };

  it("does not block a user whose mustChangePassword is true in the database", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await setStoredFlag(t, user.id);
    expect((await t.getUser(user.id)).mustChangePassword).toBe(true);
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
    const renamed = await t.auth.api.updateUser({
      body: { name: "Renamed Person" },
      headers: user.headers,
    });
    expect(renamed.status).toBe(true);
  });

  it("adds no session lookup to an authenticated request", async () => {
    const baseline = await open({ withoutPolicy: true });
    const off = await open({ policy });
    const control = await open();
    const baselineUser = await baseline.signUp();
    const offUser = await off.signUp();
    const controlUser = await control.signUp();

    const baselineCount = await countSessionLookups(baseline, baselineUser.headers);
    const offCount = await countSessionLookups(off, offUser.headers);
    const controlCount = await countSessionLookups(control, controlUser.headers);

    expect(baselineCount).toBeGreaterThan(0);
    expect(offCount).toBe(baselineCount);
    expect(controlCount).toBeGreaterThan(baselineCount);
  });

  it("adds no session lookup to a bearer-authenticated request", async () => {
    const baseline = await open({ withoutPolicy: true, bearerPosition: "after-policy" });
    const off = await open({ policy, bearerPosition: "after-policy" });
    const control = await open({ bearerPosition: "after-policy" });
    const baselineUser = await baseline.signUp();
    const offUser = await off.signUp();
    const controlUser = await control.signUp();
    const baselineBearer = await baseline.signInBearerHeaders(baselineUser.email, baselineUser.password);
    const offBearer = await off.signInBearerHeaders(offUser.email, offUser.password);
    const controlBearer = await control.signInBearerHeaders(controlUser.email, controlUser.password);

    const baselineCount = await countSessionLookups(baseline, baselineBearer);
    const offCount = await countSessionLookups(off, offBearer);
    const controlCount = await countSessionLookups(control, controlBearer);

    expect(baselineCount).toBeGreaterThan(0);
    expect(offCount).toBe(baselineCount);
    expect(controlCount).toBeGreaterThan(baselineCount);
  });

  it("records passwordChangedAt on sign-up and change-password and leaves the stored flag as it is", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    const signedUp = (await t.getUser(user.id)).passwordChangedAt;
    expect(signedUp).toBeInstanceOf(Date);
    await setStoredFlag(t, user.id);
    await pause();
    await t.auth.api.changePassword({
      body: { currentPassword: DEFAULT_PASSWORD, newPassword: P1 },
      headers: user.headers,
    });
    const row = await t.getUser(user.id);
    expect(row.passwordChangedAt!.getTime()).toBeGreaterThan(signedUp!.getTime());
    expect(row.mustChangePassword).toBe(true);
  });

  it("answers 400 FORCED_PASSWORD_CHANGE_DISABLED from setPasswordChangeRequired and writes nothing", async () => {
    const t = await open({ policy });
    const flagged = await t.signUp();
    const clean = await t.signUp({ email: "bob@example.com", name: "Bob Jones" });
    await setStoredFlag(t, flagged.id);
    const findUserById = vi.spyOn(t.context.internalAdapter, "findUserById");
    const updateUser = vi.spyOn(t.context.internalAdapter, "updateUser");

    await expectBadRequest(() => flag(t, flagged.id, true), FORCED_OFF_CODE);
    await expectBadRequest(() => flag(t, flagged.id, false), FORCED_OFF_CODE);
    await expectBadRequest(() => flag(t, clean.id, true), FORCED_OFF_CODE);
    await expectBadRequest(() => flag(t, "no-such-user", true), FORCED_OFF_CODE);
    await expectBadRequest(() => flag(t, "no-such-user", false), FORCED_OFF_CODE);

    expect(findUserById).not.toHaveBeenCalled();
    expect(updateUser).not.toHaveBeenCalled();
    expect((await t.getUser(flagged.id)).mustChangePassword).toBe(true);
    expect((await t.getUser(clean.id)).mustChangePassword).toBe(false);
  });

  it("reports mustChangePassword false and no requirement in the status for a flagged user", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await setStoredFlag(t, user.id);
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.mustChangePassword).toBe(false);
    expect(status.passwordChangeRequirement).toBeNull();
  });

  it("stops trusting the device cookie after change-password", async () => {
    const t = await open({
      policy: { ...policy, lockout: { maxAttempts: 3 } },
    });
    const user = await t.signUp();
    const signIn = await t.auth.api.signInEmail({
      body: { email: DEFAULT_EMAIL, password: DEFAULT_PASSWORD },
      returnHeaders: true,
    });
    const device = deviceCookieHeadersFrom(signIn.headers);

    await wrongEmail(t, device);
    expect((await t.deviceLockoutRows(user.id))[0]?.failedAttempts).toBe(1);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();

    await pause();
    await t.auth.api.changePassword({
      body: { currentPassword: DEFAULT_PASSWORD, newPassword: P1 },
      headers: user.headers,
    });

    await wrongEmail(t, device);
    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(1);
    expect(await t.deviceLockoutRows(user.id)).toHaveLength(0);
  });
});

describe("forcedChange false with expiration maxAge", () => {
  const policy: PasswordPolicyOptions = { forcedChange: false, expiration: { maxAge: 3600 } };

  it("does not block a flagged user whose password is fresh", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await setStoredFlag(t, user.id);
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
  });

  it("blocks a flagged user with an old password as PASSWORD_EXPIRED, not PASSWORD_CHANGE_REQUIRED", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await setStoredFlag(t, user.id);
    await t.backdatePassword(user.id, TWO_HOURS);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: user.headers }),
      "PASSWORD_EXPIRED",
    );
  });

  it("reports expired with mustChangePassword false for a flagged user with an old password", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await setStoredFlag(t, user.id);
    await t.backdatePassword(user.id, TWO_HOURS);
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.passwordChangeRequirement).toBe("expired");
    expect(status.mustChangePassword).toBe(false);
  });
});

describe("forcedChange false with a tenant maxAge and expiration omitted", () => {
  const policy: PasswordPolicyOptions = {
    forcedChange: false,
    tenantPolicy: () => ({ expiration: { maxAge: 86400 } }),
  };

  it("blocks a user whose password is older than the tenant maxAge as PASSWORD_EXPIRED", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.backdatePassword(user.id, TWO_DAYS);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: user.headers }),
      "PASSWORD_EXPIRED",
    );
  });

  it("does not block a flagged user whose password is fresh", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await setStoredFlag(t, user.id);
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
  });
});

describe.each<[string, PasswordPolicyOptions]>([
  ["forcedChange omitted", {}],
  ["forcedChange true", { forcedChange: true }],
])("forced change stays on with %s", (_name, extra) => {
  const options: TestAuthOptions = { policy: { ...extra, expiration: false } };

  it("blocks a flagged user with PASSWORD_CHANGE_REQUIRED", async () => {
    const t = await open(options);
    const user = await t.signUp();
    await setStoredFlag(t, user.id);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: user.headers }),
      "PASSWORD_CHANGE_REQUIRED",
    );
  });

  it("lets setPasswordChangeRequired set and clear the flag", async () => {
    const t = await open(options);
    const user = await t.signUp();
    expect(await flag(t, user.id, true)).toEqual({ status: true });
    expect((await t.getUser(user.id)).mustChangePassword).toBe(true);
    expect(await flag(t, user.id, false)).toEqual({ status: true });
    expect((await t.getUser(user.id)).mustChangePassword).toBe(false);
  });

  it("clears the flag when the user changes the password", async () => {
    const t = await open(options);
    const user = await t.signUp();
    await flag(t, user.id, true);
    await t.auth.api.changePassword({
      body: { currentPassword: DEFAULT_PASSWORD, newPassword: P1 },
      headers: user.headers,
    });
    expect((await t.getUser(user.id)).mustChangePassword).toBe(false);
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
  });
});
