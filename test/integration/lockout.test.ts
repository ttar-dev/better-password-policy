import { describe, it, expect, afterEach, vi } from "vitest";
import {
  createAuthRegistry,
  captureApiError,
  collectLoggedStrings,
  expectForbidden,
  expectNotFound,
  expectTooManyRequests,
  expectUnauthorized,
  DEFAULT_EMAIL,
  DEFAULT_PASSWORD,
  GOOD_PASSWORDS,
  WRONG_PASSWORD,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";
import { lockoutIdentifierKey } from "../../src/lockout-keys.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const policy = { lockout: { maxAttempts: 3 } };
const EMAIL_IDENTIFIER = `email:${DEFAULT_EMAIL}`;
const PHONE = "+66812345678";
const USERNAME = "alice_smith";
const [, P1] = GOOD_PASSWORDS;

const wrongEmailSignIn = (t: TestAuth, email = DEFAULT_EMAIL) =>
  expectUnauthorized(
    () => t.auth.api.signInEmail({ body: { email, password: WRONG_PASSWORD } }),
    "INVALID_EMAIL_OR_PASSWORD",
  );

const exhaustEmailAttempts = async (t: TestAuth, email = DEFAULT_EMAIL) => {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await wrongEmailSignIn(t, email);
  }
};

const correctEmailSignIn = (t: TestAuth, email = DEFAULT_EMAIL) =>
  t.auth.api.signInEmail({ body: { email, password: DEFAULT_PASSWORD } });

describe("lockout after repeated failures", () => {
  it("returns 401 for each of the first three wrong passwords and records the count", async () => {
    const t = await open({ policy });
    await t.signUp();
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    const row = await t.lockoutRow(EMAIL_IDENTIFIER);
    expect(row?.failedAttempts).toBe(2);
    expect(row?.lockedUntil).toBeNull();
  });

  it("rejects even the correct password with 429 SIGN_IN_LOCKED after three wrong ones, without verifying it", async () => {
    const t = await open({ policy });
    await t.signUp();
    await exhaustEmailAttempts(t);
    const verifyCallsBefore = t.verifyCalls();
    await expectTooManyRequests(() => correctEmailSignIn(t), "SIGN_IN_LOCKED");
    expect(t.verifyCalls()).toBe(verifyCallsBefore);
  });

  it("locks a non-existent email exactly like an existing one", async () => {
    const t = await open({ policy });
    await t.signUp();
    const ghost = "ghost@example.com";
    await exhaustEmailAttempts(t, ghost);
    const lockedGhost = await expectTooManyRequests(
      () => t.auth.api.signInEmail({ body: { email: ghost, password: WRONG_PASSWORD } }),
      "SIGN_IN_LOCKED",
    );
    await exhaustEmailAttempts(t);
    const lockedReal = await expectTooManyRequests(
      () => t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD } }),
      "SIGN_IN_LOCKED",
    );
    expect(lockedGhost.body?.message).toBe(lockedReal.body?.message);
    expect(lockedGhost.statusCode).toBe(lockedReal.statusCode);
  });

  it("counts attempts regardless of email case", async () => {
    const t = await open({ policy });
    await t.signUp();
    await wrongEmailSignIn(t, "ALICE@EXAMPLE.COM");
    await wrongEmailSignIn(t, "Alice@Example.com");
    await wrongEmailSignIn(t, DEFAULT_EMAIL);
    await expectTooManyRequests(() => correctEmailSignIn(t), "SIGN_IN_LOCKED");
  });

  it("sets lockedUntil about duration seconds ahead once the limit is reached", async () => {
    const t = await open({ policy: { lockout: { maxAttempts: 3, duration: 600 } } });
    const user = await t.signUp();
    const startedAt = Date.now();
    await exhaustEmailAttempts(t);
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.lockedUntil).toBeInstanceOf(Date);
    expect(status.lockedUntil!.getTime()).toBeGreaterThanOrEqual(startedAt + 590_000);
    expect(status.lockedUntil!.getTime()).toBeLessThanOrEqual(Date.now() + 605_000);
    expect(status.failedSignInAttempts).toBe(3);
  });
});

describe("lockout reset on success", () => {
  it("clears the counter row when a correct password follows two wrong ones", async () => {
    const t = await open({ policy });
    await t.signUp();
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    const result = await correctEmailSignIn(t);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
  });

  it.each([
    ["policy after two-factor", false],
    ["policy before two-factor", true],
  ])("clears the counter row on the two-factor redirect with %s", async (_label, policyBeforeTwoFactor) => {
    const t = await open({ policy, policyBeforeTwoFactor });
    const user = await t.signUp();
    await t.enableTwoFactor(user.id);
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    const result = (await correctEmailSignIn(t)) as unknown as { twoFactorRedirect?: boolean };
    expect(result.twoFactorRedirect).toBe(true);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
  });
});

describe("lockout expiry", () => {
  it("accepts the correct password once the lock has expired", async () => {
    const t = await open({ policy });
    await t.signUp();
    await exhaustEmailAttempts(t);
    await t.expireLock(EMAIL_IDENTIFIER);
    const result = await correctEmailSignIn(t);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
  });

  it("restarts the count at one and clears lockedUntil when a wrong password follows an expired lock", async () => {
    const t = await open({ policy });
    await t.signUp();
    await exhaustEmailAttempts(t);
    await t.expireLock(EMAIL_IDENTIFIER);
    await wrongEmailSignIn(t);
    const row = await t.lockoutRow(EMAIL_IDENTIFIER);
    expect(row?.failedAttempts).toBe(1);
    expect(row?.lockedUntil).toBeNull();
  });
});

describe("lockout under concurrency", () => {
  it("lets exactly maxAttempts of ten concurrent wrong passwords be verified and rejects the rest with 429", async () => {
    const t = await open({ policy });
    await t.signUp();
    const verifyCallsBefore = t.verifyCalls();
    const outcomes = await Promise.allSettled(
      Array.from({ length: 10 }, () =>
        t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD } }),
      ),
    );
    const statusCodes = outcomes.map((outcome) => {
      if (outcome.status === "fulfilled") return 200;
      return (outcome.reason as { statusCode: number }).statusCode;
    });
    expect(statusCodes.filter((code) => code === 401)).toHaveLength(3);
    expect(statusCodes.filter((code) => code === 429)).toHaveLength(7);
    expect(t.verifyCalls() - verifyCallsBefore).toBe(3);
  });
});

describe("lockout on other sign-in methods", () => {
  it("locks the username identifier after three wrong passwords while email sign-in still works", async () => {
    const t = await open({ policy });
    await t.signUp({ username: USERNAME });
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expectUnauthorized(
        () => t.auth.api.signInUsername({ body: { username: USERNAME, password: WRONG_PASSWORD } }),
        "INVALID_USERNAME_OR_PASSWORD",
      );
    }
    await expectTooManyRequests(
      () => t.auth.api.signInUsername({ body: { username: USERNAME, password: DEFAULT_PASSWORD } }),
      "SIGN_IN_LOCKED",
    );
    const emailResult = await correctEmailSignIn(t);
    expect(emailResult.user.email).toBe(DEFAULT_EMAIL);
  });

  it("locks the phone identifier after three wrong passwords", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.markPhoneNumber(user.id, PHONE);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expectUnauthorized(
        () =>
          t.auth.api.signInPhoneNumber({ body: { phoneNumber: PHONE, password: WRONG_PASSWORD } }),
        "INVALID_PHONE_NUMBER_OR_PASSWORD",
      );
    }
    await expectTooManyRequests(
      () =>
        t.auth.api.signInPhoneNumber({ body: { phoneNumber: PHONE, password: DEFAULT_PASSWORD } }),
      "SIGN_IN_LOCKED",
    );
  });
});

describe("unlocking", () => {
  it("unlocks every identifier of the user when the password is reset", async () => {
    const t = await open({ policy });
    await t.signUp({ username: USERNAME });
    await exhaustEmailAttempts(t);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expectUnauthorized(
        () => t.auth.api.signInUsername({ body: { username: USERNAME, password: WRONG_PASSWORD } }),
        "INVALID_USERNAME_OR_PASSWORD",
      );
    }
    expect((await t.lockoutRows()).length).toBe(2);
    const token = await t.requestResetToken(DEFAULT_EMAIL);
    await t.auth.api.resetPassword({ body: { newPassword: P1, token } });
    expect(await t.lockoutRows()).toHaveLength(0);
    const result = await t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: P1 } });
    expect(result.user.email).toBe(DEFAULT_EMAIL);
  });

  it("unlocks the user through unlockSignIn", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await exhaustEmailAttempts(t);
    await expectTooManyRequests(() => correctEmailSignIn(t), "SIGN_IN_LOCKED");
    const result = await t.auth.api.unlockSignIn({ body: { userId: user.id } });
    expect(result).toEqual({ status: true });
    const signedIn = await correctEmailSignIn(t);
    expect(signedIn.user.email).toBe(DEFAULT_EMAIL);
  });

  it("answers 404 USER_NOT_FOUND from unlockSignIn for an unknown user", async () => {
    const t = await open({ policy });
    await expectNotFound(
      () => t.auth.api.unlockSignIn({ body: { userId: "no-such-user" } }),
      "USER_NOT_FOUND",
    );
  });

  it("still deletes old rows through unlockSignIn when lockout is switched off", async () => {
    const t = await open({ policy: { lockout: false } });
    const user = await t.signUp();
    await t.adapter.create({
      model: "signInLockout",
      data: {
        identifier: await lockoutIdentifierKey(t.context.secret, EMAIL_IDENTIFIER),
        failedAttempts: 3,
        lockedUntil: new Date(Date.now() + 600_000),
        lastAttemptAt: new Date(),
      },
    });
    await t.auth.api.unlockSignIn({ body: { userId: user.id } });
    expect(await t.lockoutRows()).toHaveLength(0);
  });
});

describe("lockout rows written before keyed hashing", () => {
  it("ignores a legacy plaintext row that still carries an active lock", async () => {
    const t = await open({ policy });
    await t.signUp();
    await t.adapter.create({
      model: "signInLockout",
      data: {
        identifier: EMAIL_IDENTIFIER,
        failedAttempts: 3,
        lockedUntil: new Date(Date.now() + 600_000),
        lastAttemptAt: new Date(),
      },
    });
    const result = await correctEmailSignIn(t);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
  });
});

describe("failures that are not credential failures", () => {
  it("never locks a user with the correct password who has not verified their email", async () => {
    const t = await open({ policy, requireEmailVerification: true });
    const user = await t.signUp();
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await expectForbidden(() => correctEmailSignIn(t), "EMAIL_NOT_VERIFIED");
    }
    expect(await t.lockoutRows()).toHaveLength(0);
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.failedSignInAttempts).toBe(0);
    expect(status.lockedUntil).toBeNull();
  });

  it("does not count a banned user's correct sign-in as a failure", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.updateUserRow(user.id, { banned: true });
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await expectForbidden(() => correctEmailSignIn(t), "BANNED_USER");
    }
    expect(await t.lockoutRows()).toHaveLength(0);
  });
});

describe("lockout counts anything but the correct password", () => {
  const rewritten = { policy, rewriteSignInErrors: true };

  it("still answers 429 SIGN_IN_LOCKED after three wrong passwords when a user-level after hook rewrites the sign-in error code", async () => {
    const t = await open(rewritten);
    await t.signUp();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expectUnauthorized(
        () => t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD } }),
        "INVALID_CREDENTIALS",
      );
    }
    await expectTooManyRequests(() => correctEmailSignIn(t), "SIGN_IN_LOCKED");
  });

  it("counts attempts under a rewriting hook one by one", async () => {
    const t = await open(rewritten);
    await t.signUp();
    await expectUnauthorized(
      () => t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD } }),
      "INVALID_CREDENTIALS",
    );
    await expectUnauthorized(
      () => t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD } }),
      "INVALID_CREDENTIALS",
    );
    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(2);
  });

  it("clears the counter when the correct password is presented even though the response is rewritten to an error", async () => {
    const t = await open({ ...rewritten, requireEmailVerification: true });
    await t.signUp();
    await expectUnauthorized(
      () => t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD } }),
      "INVALID_CREDENTIALS",
    );
    await expectUnauthorized(
      () => t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD } }),
      "INVALID_CREDENTIALS",
    );
    await expectUnauthorized(() => correctEmailSignIn(t), "INVALID_CREDENTIALS");
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
  });

  it("clears the counter when the correct password meets EMAIL_NOT_VERIFIED after two wrong ones", async () => {
    const t = await open({ policy, requireEmailVerification: true });
    await t.signUp();
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    await expectForbidden(() => correctEmailSignIn(t), "EMAIL_NOT_VERIFIED");
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
  });

  it("clears the counter when the correct password meets BANNED_USER after two wrong ones", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.updateUserRow(user.id, { banned: true });
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    await expectForbidden(() => correctEmailSignIn(t), "BANNED_USER");
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
  });

  it("never answers 429 for a banned user with the correct password under a rewriting hook", async () => {
    const t = await open(rewritten);
    const user = await t.signUp();
    await t.updateUserRow(user.id, { banned: true });
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const error = await captureApiError(() => correctEmailSignIn(t));
      expect(error.statusCode).not.toBe(429);
    }
    const rows = await t.lockoutRows();
    expect(rows.every((row) => row.failedAttempts === 0)).toBe(true);
  });

  it("counts sign-ins with a known email and a missing password and locks after three of them", async () => {
    const t = await open({ policy });
    await t.signUp();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const error = await captureApiError(() =>
        t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL } as never }),
      );
      expect(error.statusCode).toBe(400);
    }
    await expectTooManyRequests(() => correctEmailSignIn(t), "SIGN_IN_LOCKED");
  });

  it("starts the lock right after the third counted attempt", async () => {
    const t = await open({ policy: { lockout: { maxAttempts: 3, duration: 600 } }, rewriteSignInErrors: true });
    await t.signUp();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expectUnauthorized(
        () => t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_PASSWORD } }),
        "INVALID_CREDENTIALS",
      );
    }
    const row = await t.lockoutRow(EMAIL_IDENTIFIER);
    expect(row?.failedAttempts).toBe(3);
    expect(row?.lockedUntil).toBeInstanceOf(Date);
  });
});

describe("lockout switched off", () => {
  it("never answers 429 and writes no rows", async () => {
    const t = await open({ policy: { lockout: false } });
    await t.signUp();
    for (let attempt = 0; attempt < 10; attempt += 1) {
      await wrongEmailSignIn(t);
    }
    const result = await correctEmailSignIn(t);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(await t.lockoutRows()).toHaveLength(0);
  });

  it("reports no lock and zero failed attempts in the status", async () => {
    const t = await open({ policy: { lockout: false } });
    const user = await t.signUp();
    for (let attempt = 0; attempt < 4; attempt += 1) {
      await wrongEmailSignIn(t);
    }
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.lockedUntil).toBeNull();
    expect(status.failedSignInAttempts).toBe(0);
  });
});

describe("lockout cleanup on user deletion", () => {
  it("removes the user's lockout rows when the user is deleted", async () => {
    const t = await open({ policy, enableDeleteUser: true });
    const user = await t.signUp();
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    expect(await t.lockoutRows()).toHaveLength(1);
    await t.auth.api.deleteUser({ body: { password: DEFAULT_PASSWORD }, headers: user.headers });
    expect(await t.lockoutRows()).toHaveLength(0);
  });

  it("logs the constant cleanup message and no identifier when the cleanup query fails", async () => {
    const t = await open({ policy, enableDeleteUser: true });
    const user = await t.signUp();
    await wrongEmailSignIn(t);
    const original = t.adapter.deleteMany.bind(t.adapter);
    vi.spyOn(t.adapter, "deleteMany").mockImplementation((async (input: { model: string }) => {
      if (input.model === "signInLockout") {
        throw new Error(`Failed query: delete from sign_in_lockout params: ${DEFAULT_EMAIL}`);
      }
      return original(input as never);
    }) as never);
    const logged = vi.spyOn(t.context.logger, "error").mockImplementation(() => undefined);

    await t.auth.api.deleteUser({ body: { password: DEFAULT_PASSWORD }, headers: user.headers });

    const cleanupCalls = logged.mock.calls.filter(
      (call) => call[0] === "password-policy: failed to clean up after user deletion",
    );
    expect(cleanupCalls).toHaveLength(1);
    const serialized = logged.mock.calls
      .flat()
      .map((arg) => (arg instanceof Error ? `${arg.message}\n${arg.stack ?? ""}` : `${String(arg)}\n${JSON.stringify(arg)}`))
      .join("\n");
    expect(serialized).not.toContain(DEFAULT_EMAIL);
  });
});

describe("lockout leaves requests it cannot identify to core", () => {
  it("answers a sign-in with a missing email through core validation, not 429", async () => {
    const t = await open({ policy });
    await t.signUp();
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const error = await captureApiError(() =>
        t.auth.api.signInEmail({ body: { password: WRONG_PASSWORD } as never }),
      );
      expect(error.statusCode).not.toBe(429);
    }
    expect(await t.lockoutRows()).toHaveLength(0);
  });
});

describe("lockout reset when the sign-in throws after the password verified", () => {
  const SESSION_FAILURE = "session store unavailable";

  it("clears the counter when the session cannot be created after the correct password", async () => {
    const t = await open({ policy });
    await t.signUp();
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    vi.spyOn(t.context.internalAdapter, "createSession").mockRejectedValueOnce(new Error(SESSION_FAILURE));

    await expect(correctEmailSignIn(t)).rejects.toThrow(SESSION_FAILURE);

    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
    const retried = await correctEmailSignIn(t);
    expect(retried.user.email).toBe(DEFAULT_EMAIL);
  });

  it("never locks a user whose correct sign-ins keep throwing", async () => {
    const t = await open({ policy });
    await t.signUp();
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    const createSession = vi
      .spyOn(t.context.internalAdapter, "createSession")
      .mockRejectedValue(new Error(SESSION_FAILURE));

    for (let round = 0; round < 5; round += 1) {
      await expect(correctEmailSignIn(t)).rejects.toThrow(SESSION_FAILURE);
    }

    createSession.mockRestore();
    const signedIn = await correctEmailSignIn(t);
    expect(signedIn.user.email).toBe(DEFAULT_EMAIL);
    expect(await t.lockoutRows()).toHaveLength(0);
  });

  it("still signs in and logs a summary when resetting the counter fails", async () => {
    const t = await open({ policy });
    await t.signUp();
    await wrongEmailSignIn(t);
    await wrongEmailSignIn(t);
    const original = t.adapter.deleteMany.bind(t.adapter);
    vi.spyOn(t.adapter, "deleteMany").mockImplementation((async (input: {
      model: string;
      where?: { field: string }[];
    }) => {
      if (input.model === "signInLockout" && input.where?.some((clause) => clause.field === "identifier")) {
        throw new Error(`Failed query: delete from sign_in_lockout\nparams: ${DEFAULT_EMAIL}`);
      }
      return original(input as never);
    }) as never);
    const logged = vi.spyOn(t.context.logger, "error").mockImplementation(() => undefined);

    const signedIn = await correctEmailSignIn(t);

    expect(signedIn.user.email).toBe(DEFAULT_EMAIL);
    const resetCalls = logged.mock.calls.filter(
      (call) => call[0] === "password-policy: failed to reset the sign-in lockout counter",
    );
    expect(resetCalls).toHaveLength(1);
    expect(resetCalls[0]?.[1]).toEqual({ name: "Error", code: null });
    const serialized = logged.mock.calls.flatMap((call) => call.flatMap((arg) => collectLoggedStrings(arg)));
    expect(serialized.join("\n")).not.toContain(DEFAULT_EMAIL);
    expect(serialized.join("\n")).not.toContain("Failed query");
    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(3);
  });
});
