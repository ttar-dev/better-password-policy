import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthRegistry,
  captureApiError,
  expectBadRequest,
  expectForbidden,
  expectNotFound,
  pause,
  DEFAULT_PASSWORD,
  GOOD_PASSWORDS,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const [, P1] = GOOD_PASSWORDS;
const TWO_HOURS = 7200;
const PHONE = "+66812345678";

const flag = (t: TestAuth, userId: string, required: boolean) =>
  t.auth.api.setPasswordChangeRequired({ body: { userId, required } });

describe("passwordChangedAt and mustChangePassword on sign-up", () => {
  it("records passwordChangedAt close to now and leaves mustChangePassword false", async () => {
    const t = await open();
    const before = Date.now();
    const user = await t.signUp();
    const row = await t.getUser(user.id);
    expect(row.passwordChangedAt).toBeInstanceOf(Date);
    expect(row.passwordChangedAt!.getTime()).toBeGreaterThanOrEqual(before - 5000);
    expect(row.passwordChangedAt!.getTime()).toBeLessThanOrEqual(Date.now() + 5000);
    expect(row.mustChangePassword).toBe(false);
  });
});

describe("password expiration", () => {
  const policy = { expiration: { maxAge: 3600 } };

  it("blocks an authenticated route with PASSWORD_EXPIRED once the password is older than maxAge", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.backdatePassword(user.id, TWO_HOURS);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: user.headers }),
      "PASSWORD_EXPIRED",
    );
  });

  it("does not block while the password is younger than maxAge", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.backdatePassword(user.id, 1800);
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
  });

  it("does not block when expiration is not configured", async () => {
    const t = await open();
    const user = await t.signUp();
    await t.backdatePassword(user.id, TWO_HOURS * 24 * 365);
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
  });

  it("keeps getSession reachable for an expired password", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.backdatePassword(user.id, TWO_HOURS);
    const session = await t.auth.api.getSession({ headers: user.headers });
    expect(session?.user.id).toBe(user.id);
  });

  it("keeps sign-out reachable for an expired password", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.backdatePassword(user.id, TWO_HOURS);
    const result = await t.auth.api.signOut({ headers: user.headers });
    expect(result.success).toBe(true);
  });

  it("keeps sign-in reachable for an expired password", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.backdatePassword(user.id, TWO_HOURS);
    const result = await t.auth.api.signInEmail({
      body: { email: user.email, password: DEFAULT_PASSWORD },
    });
    expect(result.user.id).toBe(user.id);
  });

  it("lets change-password through and unblocks routes afterwards", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.backdatePassword(user.id, TWO_HOURS);
    await pause();
    await t.auth.api.changePassword({
      body: { currentPassword: DEFAULT_PASSWORD, newPassword: P1 },
      headers: user.headers,
    });
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
  });

  it("returns the core 401 for a request without a session instead of a policy error", async () => {
    const t = await open({ policy });
    const error = await captureApiError(() => t.auth.api.listSessions({ headers: new Headers() }));
    expect(error.status).toBe("UNAUTHORIZED");
    expect(error.statusCode).toBe(401);
  });
});

describe("forced password change", () => {
  it("exposes mustChangePassword on the session user", async () => {
    const t = await open();
    const user = await t.signUp();
    expect(await flag(t, user.id, true)).toEqual({ status: true });
    const session = await t.auth.api.getSession({ headers: user.headers });
    expect((session?.user as { mustChangePassword?: boolean } | undefined)?.mustChangePassword).toBe(
      true,
    );
  });

  it("blocks authenticated routes with PASSWORD_CHANGE_REQUIRED", async () => {
    const t = await open();
    const user = await t.signUp();
    await flag(t, user.id, true);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: user.headers }),
      "PASSWORD_CHANGE_REQUIRED",
    );
    await expectForbidden(
      () => t.auth.api.updateUser({ body: { name: "Renamed Person" }, headers: user.headers }),
      "PASSWORD_CHANGE_REQUIRED",
    );
  });

  it("keeps sign-out reachable", async () => {
    const t = await open();
    const user = await t.signUp();
    await flag(t, user.id, true);
    const result = await t.auth.api.signOut({ headers: user.headers });
    expect(result.success).toBe(true);
  });

  it("clears the flag when the user changes the password", async () => {
    const t = await open();
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

  it("keeps the flag when change-password is rejected by the policy", async () => {
    const t = await open();
    const user = await t.signUp();
    await flag(t, user.id, true);
    await expectBadRequest(
      () =>
        t.auth.api.changePassword({
          body: { currentPassword: DEFAULT_PASSWORD, newPassword: "weakpass1" },
          headers: user.headers,
        }),
      "PASSWORD_MISSING_UPPERCASE",
    );
    expect((await t.getUser(user.id)).mustChangePassword).toBe(true);
  });

  it("clears the flag on reset-password", async () => {
    const t = await open();
    const user = await t.signUp();
    await flag(t, user.id, true);
    const token = await t.requestResetToken(user.email);
    await t.auth.api.resetPassword({ body: { newPassword: P1, token } });
    expect((await t.getUser(user.id)).mustChangePassword).toBe(false);
  });

  it("clears the flag on email-otp reset-password", async () => {
    const t = await open();
    const user = await t.signUp();
    await flag(t, user.id, true);
    await t.auth.api.requestPasswordResetEmailOTP({ body: { email: user.email } });
    const otp = await t.lastEmailOtp(user.email, "forget-password");
    await t.auth.api.resetPasswordEmailOTP({ body: { email: user.email, otp, password: P1 } });
    expect((await t.getUser(user.id)).mustChangePassword).toBe(false);
  });

  it("clears the flag on phone-number reset-password", async () => {
    const t = await open();
    const user = await t.signUp();
    await t.markPhoneNumber(user.id, PHONE);
    await flag(t, user.id, true);
    await t.auth.api.requestPasswordResetPhoneNumber({ body: { phoneNumber: PHONE } });
    const otp = await t.lastPhoneCode(PHONE);
    await t.auth.api.resetPasswordPhoneNumber({
      body: { phoneNumber: PHONE, otp, newPassword: P1 },
    });
    expect((await t.getUser(user.id)).mustChangePassword).toBe(false);
  });

  it("does not clear the flag when an admin sets the password but still records passwordChangedAt", async () => {
    const t = await open();
    const user = await t.signUp();
    const admin = await t.createAdmin();
    await flag(t, user.id, true);
    await t.updateUserRow(user.id, { passwordChangedAt: null });
    await t.auth.api.setUserPassword({
      body: { userId: user.id, newPassword: P1 },
      headers: admin.headers,
    });
    const row = await t.getUser(user.id);
    expect(row.mustChangePassword).toBe(true);
    expect(row.passwordChangedAt).not.toBeNull();
  });

  it("clears the flag with required false", async () => {
    const t = await open();
    const user = await t.signUp();
    await flag(t, user.id, true);
    await flag(t, user.id, false);
    expect((await t.getUser(user.id)).mustChangePassword).toBe(false);
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
  });

  it("returns forced rather than expired when both apply", async () => {
    const t = await open({ policy: { expiration: { maxAge: 3600 } } });
    const user = await t.signUp();
    await flag(t, user.id, true);
    await t.backdatePassword(user.id, TWO_HOURS);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: user.headers }),
      "PASSWORD_CHANGE_REQUIRED",
    );
  });

  it("answers 404 USER_NOT_FOUND for an unknown user id", async () => {
    const t = await open();
    await expectNotFound(() => flag(t, "no-such-user", true), "USER_NOT_FOUND");
  });

  it("lets a flagged admin call setPasswordChangeRequired with their own headers", async () => {
    const t = await open();
    const target = await t.signUp({ email: "bob@example.com", name: "Bob Jones" });
    const admin = await t.createAdmin();
    await flag(t, admin.id, true);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: admin.headers }),
      "PASSWORD_CHANGE_REQUIRED",
    );
    const result = await t.auth.api.setPasswordChangeRequired({
      body: { userId: target.id, required: true },
      headers: admin.headers,
    });
    expect(result).toEqual({ status: true });
    expect((await t.getUser(target.id)).mustChangePassword).toBe(true);
  });

  it("does not trust a stale session cookie cache after the password was changed", async () => {
    const t = await open({ cookieCache: true });
    const user = await t.signUp();
    await flag(t, user.id, true);
    const staleHeaders = await t.signInHeaders(user.email, DEFAULT_PASSWORD);
    await t.auth.api.changePassword({
      body: { currentPassword: DEFAULT_PASSWORD, newPassword: P1 },
      headers: staleHeaders,
    });
    const sessions = await t.auth.api.listSessions({ headers: staleHeaders });
    expect(sessions.length).toBeGreaterThan(0);
  });
});

describe("getPasswordPolicyStatus", () => {
  it("reports a healthy password with an expiry date derived from maxAge", async () => {
    const t = await open({ policy: { expiration: { maxAge: 3600 } } });
    const user = await t.signUp();
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    const changedAt = (await t.getUser(user.id)).passwordChangedAt!;
    expect(status.mustChangePassword).toBe(false);
    expect(status.passwordChangedAt?.getTime()).toBe(changedAt.getTime());
    expect(status.passwordExpiresAt?.getTime()).toBe(changedAt.getTime() + 3600 * 1000);
    expect(status.passwordChangeRequirement).toBeNull();
    expect(status.lockedUntil).toBeNull();
    expect(status.failedSignInAttempts).toBe(0);
  });

  it("reports expired when the password is older than maxAge", async () => {
    const t = await open({ policy: { expiration: { maxAge: 3600 } } });
    const user = await t.signUp();
    await t.backdatePassword(user.id, TWO_HOURS);
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.passwordChangeRequirement).toBe("expired");
    expect(status.mustChangePassword).toBe(false);
  });

  it("reports forced when the flag is set", async () => {
    const t = await open();
    const user = await t.signUp();
    await flag(t, user.id, true);
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.mustChangePassword).toBe(true);
    expect(status.passwordChangeRequirement).toBe("forced");
  });

  it("reports a null expiry when expiration is not configured", async () => {
    const t = await open();
    const user = await t.signUp();
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.passwordExpiresAt).toBeNull();
    expect(status.passwordChangedAt).toBeInstanceOf(Date);
  });

  it("answers 404 USER_NOT_FOUND for an unknown user id", async () => {
    const t = await open();
    await expectNotFound(
      () => t.auth.api.getPasswordPolicyStatus({ query: { userId: "no-such-user" } }),
      "USER_NOT_FOUND",
    );
  });
});
