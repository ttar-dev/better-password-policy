import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthRegistry,
  expectBadRequest,
  expectUnauthorized,
  pause,
  DEFAULT_EMAIL,
  DEFAULT_PASSWORD,
  GOOD_PASSWORDS,
  WRONG_PASSWORD,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const PHONE = "+66812345678";
const [P0, P1, P2, P3] = GOOD_PASSWORDS;

const change = async (t: TestAuth, headers: Headers, currentPassword: string, newPassword: string) => {
  await pause();
  return t.auth.api.changePassword({ body: { currentPassword, newPassword }, headers });
};

const expectRecorded = async (t: TestAuth, userId: string) => {
  const account = await t.getCredentialAccount(userId);
  const rows = await t.historyRows(userId);
  expect(rows.some((row) => row.passwordHash === account.password)).toBe(true);
  expect((await t.getUser(userId)).passwordChangedAt).not.toBeNull();
};

describe("password history with count 2", () => {
  const policy = { history: { count: 2 } };

  it("rejects changing to the current password", async () => {
    const t = await open({ policy });
    const user = await t.signUp({ password: P0 });
    await expectBadRequest(() => change(t, user.headers, P0, P0), "PASSWORD_REUSED");
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${P0}`);
  });

  it("rejects a password within the last two previous ones and accepts it once it has aged out", async () => {
    const t = await open({ policy });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P1);
    await change(t, user.headers, P1, P2);
    await expectBadRequest(() => change(t, user.headers, P2, P0), "PASSWORD_REUSED");
    await change(t, user.headers, P2, P3);
    await change(t, user.headers, P3, P0);
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${P0}`);
  });

  it("keeps at most count plus one rows per user", async () => {
    const t = await open({ policy });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P1);
    await change(t, user.headers, P1, P2);
    await change(t, user.headers, P2, P3);
    const rows = await t.historyRows(user.id);
    expect(rows).toHaveLength(3);
    expect(rows.map((row) => row.passwordHash)).toEqual([`fast:${P3}`, `fast:${P2}`, `fast:${P1}`]);
  });

  it("rejects reset-password to the current password", async () => {
    const t = await open({ policy });
    const user = await t.signUp({ password: P0 });
    const token = await t.requestResetToken(user.email);
    await expectBadRequest(
      () => t.auth.api.resetPassword({ body: { newPassword: P0, token } }),
      "PASSWORD_REUSED",
    );
  });

  it("rejects reset-password to a previous password", async () => {
    const t = await open({ policy });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P1);
    const token = await t.requestResetToken(user.email);
    await expectBadRequest(
      () => t.auth.api.resetPassword({ body: { newPassword: P0, token } }),
      "PASSWORD_REUSED",
    );
  });

  it("rejects admin set-user-password to the current password", async () => {
    const t = await open({ policy });
    const user = await t.signUp({ password: P0 });
    const admin = await t.createAdmin();
    await expectBadRequest(
      () =>
        t.auth.api.setUserPassword({
          body: { userId: user.id, newPassword: P0 },
          headers: admin.headers,
        }),
      "PASSWORD_REUSED",
    );
  });

  it("does not reveal reuse to a caller who does not know the current password", async () => {
    const t = await open({ policy });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P1);
    await expectBadRequest(
      () => change(t, user.headers, "Not-the-password-1", P0),
      "INVALID_PASSWORD",
    );
  });
});

describe("password history with count 0", () => {
  it("rejects only the current password", async () => {
    const t = await open({ policy: { history: { count: 0 } } });
    const user = await t.signUp({ password: P0 });
    await expectBadRequest(() => change(t, user.headers, P0, P0), "PASSWORD_REUSED");
    await change(t, user.headers, P0, P1);
    await change(t, user.headers, P1, P0);
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${P0}`);
  });
});

describe("password history switched off", () => {
  it("accepts changing to the same password and writes no rows", async () => {
    const t = await open({ policy: { history: false } });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P0);
    expect(await t.allHistoryRows()).toHaveLength(0);
    expect((await t.getUser(user.id)).passwordChangedAt).not.toBeNull();
  });
});

describe("password history with the real scrypt hasher", () => {
  it("detects reuse of the current password", async () => {
    const t = await open({ realHasher: true, policy: { history: { count: 2 } } });
    const user = await t.signUp({ password: P0 });
    await expectBadRequest(() => change(t, user.headers, P0, P0), "PASSWORD_REUSED");
  });

  it("detects reuse of a previous password", async () => {
    const t = await open({ realHasher: true, policy: { history: { count: 2 } } });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P1);
    await expectBadRequest(() => change(t, user.headers, P1, P0), "PASSWORD_REUSED");
  });
});

describe("recording of every credential password write", () => {
  it("records sign-up", async () => {
    const t = await open();
    const user = await t.signUp();
    await expectRecorded(t, user.id);
  });

  it("records change-password", async () => {
    const t = await open();
    const user = await t.signUp();
    await t.updateUserRow(user.id, { passwordChangedAt: null });
    await change(t, user.headers, DEFAULT_PASSWORD, P1);
    await expectRecorded(t, user.id);
    expect((await t.historyRows(user.id)).map((row) => row.passwordHash)).toContain(`fast:${P1}`);
  });

  it("records reset-password", async () => {
    const t = await open();
    const user = await t.signUp();
    await t.updateUserRow(user.id, { passwordChangedAt: null });
    const token = await t.requestResetToken(user.email);
    await t.auth.api.resetPassword({ body: { newPassword: P1, token } });
    await expectRecorded(t, user.id);
    expect((await t.historyRows(user.id)).map((row) => row.passwordHash)).toContain(`fast:${P1}`);
  });

  it("records email-otp reset-password", async () => {
    const t = await open();
    const user = await t.signUp();
    await t.updateUserRow(user.id, { passwordChangedAt: null });
    await t.auth.api.requestPasswordResetEmailOTP({ body: { email: user.email } });
    const otp = await t.lastEmailOtp(user.email, "forget-password");
    await t.auth.api.resetPasswordEmailOTP({ body: { email: user.email, otp, password: P1 } });
    await expectRecorded(t, user.id);
    expect((await t.historyRows(user.id)).map((row) => row.passwordHash)).toContain(`fast:${P1}`);
  });

  it("records phone-number reset-password", async () => {
    const t = await open();
    const user = await t.signUp();
    await t.markPhoneNumber(user.id, PHONE);
    await t.updateUserRow(user.id, { passwordChangedAt: null });
    await t.auth.api.requestPasswordResetPhoneNumber({ body: { phoneNumber: PHONE } });
    const otp = await t.lastPhoneCode(PHONE);
    await t.auth.api.resetPasswordPhoneNumber({
      body: { phoneNumber: PHONE, otp, newPassword: P1 },
    });
    await expectRecorded(t, user.id);
    expect((await t.historyRows(user.id)).map((row) => row.passwordHash)).toContain(`fast:${P1}`);
  });

  it("records admin set-user-password", async () => {
    const t = await open();
    const user = await t.signUp();
    const admin = await t.createAdmin();
    await t.updateUserRow(user.id, { passwordChangedAt: null });
    await t.auth.api.setUserPassword({
      body: { userId: user.id, newPassword: P1 },
      headers: admin.headers,
    });
    await expectRecorded(t, user.id);
    expect((await t.historyRows(user.id)).map((row) => row.passwordHash)).toContain(`fast:${P1}`);
  });

  it("records setPassword for a user without a credential account", async () => {
    const t = await open();
    const user = await t.createSessionOnlyUser("sam@example.com", "Sam Setter");
    await t.auth.api.setPassword({ body: { newPassword: P1 }, headers: user.headers });
    await expectRecorded(t, user.id);
  });

  it("records admin create-user with a password", async () => {
    const t = await open();
    const created = await t.auth.api.createUser({
      body: { email: "made@example.com", password: P1, name: "Made Up", role: "user" },
    });
    await expectRecorded(t, created.user.id);
  });

  it("writes no row and leaves passwordChangedAt null for admin create-user without a password", async () => {
    const t = await open();
    const created = await t.auth.api.createUser({
      body: { email: "made@example.com", name: "Made Up", role: "user" },
    });
    expect(await t.historyRows(created.user.id)).toHaveLength(0);
    expect((await t.getUser(created.user.id)).passwordChangedAt).toBeNull();
  });
});

describe("account updates that are not credential password writes", () => {
  it("adds no row and keeps passwordChangedAt when a non-credential account is linked and updated", async () => {
    const t = await open();
    const user = await t.signUp();
    const before = await t.getUser(user.id);
    const rowsBefore = await t.historyRows(user.id);
    await pause();
    const linked = await t.context.internalAdapter.linkAccount({
      userId: user.id,
      providerId: "github",
      accountId: "gh-1",
      accessToken: "token-1",
    });
    await t.context.internalAdapter.updateAccount(linked.id, { accessToken: "token-2" });
    expect(await t.historyRows(user.id)).toHaveLength(rowsBefore.length);
    expect((await t.getUser(user.id)).passwordChangedAt).toEqual(before.passwordChangedAt);
  });

  it("adds no row when the credential account is updated without a password in the patch", async () => {
    const t = await open();
    const user = await t.signUp();
    const before = await t.getUser(user.id);
    const rowsBefore = await t.historyRows(user.id);
    const account = await t.getCredentialAccount(user.id);
    await pause();
    await t.context.internalAdapter.updateAccount(account.id, { accessToken: "token-3" });
    expect(await t.historyRows(user.id)).toHaveLength(rowsBefore.length);
    expect((await t.getUser(user.id)).passwordChangedAt).toEqual(before.passwordChangedAt);
  });
});

describe("credential password writes outside an endpoint", () => {
  const prepare = async () => {
    const t = await open();
    const user = await t.signUp({ password: P0 });
    await expectUnauthorized(
      () => t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD } }),
      "INVALID_EMAIL_OR_PASSWORD",
    );
    await t.updateUserRow(user.id, { mustChangePassword: true });
    await pause();
    return {
      t,
      user,
      historyBefore: await t.historyRows(user.id),
      userBefore: await t.getUser(user.id),
      lockoutBefore: await t.lockoutRows(),
    };
  };

  it("resolves internalAdapter.updatePassword, writes the account password and records nothing", async () => {
    const { t, user, historyBefore, userBefore, lockoutBefore } = await prepare();
    await t.context.internalAdapter.updatePassword(user.id, "fast:Other1Pass");
    expect((await t.getCredentialAccount(user.id)).password).toBe("fast:Other1Pass");
    expect(await t.historyRows(user.id)).toEqual(historyBefore);
    const userAfter = await t.getUser(user.id);
    expect(userAfter.passwordChangedAt).toEqual(userBefore.passwordChangedAt);
    expect(userAfter.mustChangePassword).toBe(true);
    expect(await t.lockoutRows()).toEqual(lockoutBefore);
  });

  it("resolves internalAdapter.updateAccount with a password, writes it and records nothing", async () => {
    const { t, user, historyBefore, userBefore, lockoutBefore } = await prepare();
    const account = await t.getCredentialAccount(user.id);
    await t.context.internalAdapter.updateAccount(account.id, { password: "fast:Another2Pass" });
    expect((await t.getCredentialAccount(user.id)).password).toBe("fast:Another2Pass");
    expect(await t.historyRows(user.id)).toEqual(historyBefore);
    const userAfter = await t.getUser(user.id);
    expect(userAfter.passwordChangedAt).toEqual(userBefore.passwordChangedAt);
    expect(userAfter.mustChangePassword).toBe(true);
    expect(await t.lockoutRows()).toEqual(lockoutBefore);
  });

  it("lets the user sign in with the password written outside an endpoint", async () => {
    const t = await open();
    const user = await t.signUp({ password: P0 });
    await t.context.internalAdapter.updatePassword(user.id, `fast:${P1}`);
    const result = await t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: P1 } });
    expect(result.user.id).toBe(user.id);
  });
});

describe("history cleanup on user deletion", () => {
  it("removes every history row when the user is deleted", async () => {
    const t = await open({ enableDeleteUser: true });
    const user = await t.signUp({ password: P0 });
    await change(t, user.headers, P0, P1);
    expect(await t.historyRows(user.id)).toHaveLength(2);
    await t.auth.api.deleteUser({ body: { password: P1 }, headers: user.headers });
    expect(await t.allHistoryRows()).toHaveLength(0);
  });
});
