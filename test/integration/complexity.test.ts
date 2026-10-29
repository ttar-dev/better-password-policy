import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthRegistry,
  expectBadRequest,
  expectUnauthorized,
  captureApiError,
  DEFAULT_EMAIL,
  DEFAULT_PASSWORD,
  GOOD_PASSWORDS,
  WEAK_NO_UPPERCASE,
  WEAK_NO_LOWERCASE,
  WEAK_NO_DIGIT,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const ORIGINAL_HASH = `fast:${DEFAULT_PASSWORD}`;
const PHONE = "+66812345678";
const THAI_PASSWORD = "\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19\u0e44\u0e17\u0e22123";
const THAI_PASSWORD_WITH_MARKS = "\u0e01\u0e48\u0e2d\u0e19\u0e19\u0e2d\u0e19123";
const THAI_NAME = "\u0e13\u0e31\u0e10\u0e27\u0e38\u0e12\u0e34";
const THAI_NAME_PASSWORD = `X${THAI_NAME}9a`;

describe("complexity on every password-setting path", () => {
  it("rejects a weak password on sign-up and creates no user", async () => {
    const t = await open();
    await expectBadRequest(
      () =>
        t.auth.api.signUpEmail({
          body: { email: "nina@example.com", name: "Nina Park", password: WEAK_NO_UPPERCASE },
        }),
      "PASSWORD_MISSING_UPPERCASE",
    );
    expect(await t.context.internalAdapter.findUserByEmail("nina@example.com")).toBeNull();
  });

  it("rejects each missing character class with its own code on sign-up", async () => {
    const t = await open();
    const attempt = (password: string) => () =>
      t.auth.api.signUpEmail({ body: { email: "nina@example.com", name: "Nina Park", password } });
    await expectBadRequest(attempt(WEAK_NO_LOWERCASE), "PASSWORD_MISSING_LOWERCASE");
    await expectBadRequest(attempt(WEAK_NO_DIGIT), "PASSWORD_MISSING_DIGIT");
  });

  it("rejects a weak password on change-password and leaves the stored hash unchanged", async () => {
    const t = await open();
    const user = await t.signUp();
    await expectBadRequest(
      () =>
        t.auth.api.changePassword({
          body: { currentPassword: DEFAULT_PASSWORD, newPassword: WEAK_NO_UPPERCASE },
          headers: user.headers,
        }),
      "PASSWORD_MISSING_UPPERCASE",
    );
    expect((await t.getCredentialAccount(user.id)).password).toBe(ORIGINAL_HASH);
  });

  it("rejects a weak password on reset-password and leaves the stored hash unchanged", async () => {
    const t = await open();
    const user = await t.signUp();
    const token = await t.requestResetToken(user.email);
    await expectBadRequest(
      () => t.auth.api.resetPassword({ body: { newPassword: WEAK_NO_DIGIT, token } }),
      "PASSWORD_MISSING_DIGIT",
    );
    expect((await t.getCredentialAccount(user.id)).password).toBe(ORIGINAL_HASH);
  });

  it("rejects a weak password on email-otp reset-password and leaves the stored hash unchanged", async () => {
    const t = await open();
    const user = await t.signUp();
    await t.auth.api.requestPasswordResetEmailOTP({ body: { email: user.email } });
    const otp = await t.lastEmailOtp(user.email, "forget-password");
    await expectBadRequest(
      () =>
        t.auth.api.resetPasswordEmailOTP({
          body: { email: user.email, otp, password: WEAK_NO_LOWERCASE },
        }),
      "PASSWORD_MISSING_LOWERCASE",
    );
    expect((await t.getCredentialAccount(user.id)).password).toBe(ORIGINAL_HASH);
  });

  it("rejects a weak password on phone-number reset-password and leaves the stored hash unchanged", async () => {
    const t = await open();
    const user = await t.signUp();
    await t.markPhoneNumber(user.id, PHONE);
    await t.auth.api.requestPasswordResetPhoneNumber({ body: { phoneNumber: PHONE } });
    const otp = await t.lastPhoneCode(PHONE);
    await expectBadRequest(
      () =>
        t.auth.api.resetPasswordPhoneNumber({
          body: { phoneNumber: PHONE, otp, newPassword: WEAK_NO_UPPERCASE },
        }),
      "PASSWORD_MISSING_UPPERCASE",
    );
    expect((await t.getCredentialAccount(user.id)).password).toBe(ORIGINAL_HASH);
  });

  it("rejects a weak password on admin set-user-password and leaves the stored hash unchanged", async () => {
    const t = await open();
    const user = await t.signUp();
    const admin = await t.createAdmin();
    await expectBadRequest(
      () =>
        t.auth.api.setUserPassword({
          body: { userId: user.id, newPassword: WEAK_NO_UPPERCASE },
          headers: admin.headers,
        }),
      "PASSWORD_MISSING_UPPERCASE",
    );
    expect((await t.getCredentialAccount(user.id)).password).toBe(ORIGINAL_HASH);
  });

  it("rejects a weak password on setPassword and creates no credential account", async () => {
    const t = await open();
    const user = await t.createSessionOnlyUser("sam@example.com", "Sam Setter");
    await expectBadRequest(
      () =>
        t.auth.api.setPassword({
          body: { newPassword: WEAK_NO_UPPERCASE },
          headers: user.headers,
        }),
      "PASSWORD_MISSING_UPPERCASE",
    );
    const accounts = await t.adapter.findMany({
      model: "account",
      where: [{ field: "userId", value: user.id }],
    });
    expect(accounts).toHaveLength(0);
  });

  it("accepts a strong password on setPassword", async () => {
    const t = await open();
    const user = await t.createSessionOnlyUser("sam@example.com", "Sam Setter");
    const result = await t.auth.api.setPassword({
      body: { newPassword: GOOD_PASSWORDS[1] },
      headers: user.headers,
    });
    expect(result.status).toBe(true);
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${GOOD_PASSWORDS[1]}`);
  });

  it("rejects a weak password on admin create-user and creates no user", async () => {
    const t = await open();
    await expectBadRequest(
      () =>
        t.auth.api.createUser({
          body: {
            email: "made@example.com",
            password: WEAK_NO_UPPERCASE,
            name: "Made Up",
            role: "user",
          },
        }),
      "PASSWORD_MISSING_UPPERCASE",
    );
    expect(await t.context.internalAdapter.findUserByEmail("made@example.com")).toBeNull();
  });

  it("accepts a strong password on admin create-user", async () => {
    const t = await open();
    const created = await t.auth.api.createUser({
      body: { email: "made@example.com", password: GOOD_PASSWORDS[2], name: "Made Up", role: "user" },
    });
    expect((await t.getCredentialAccount(created.user.id)).password).toBe(
      `fast:${GOOD_PASSWORDS[2]}`,
    );
  });
});

describe("personal info checks use the right user per path", () => {
  it("rejects a password containing the name or email local-part on sign-up", async () => {
    const t = await open();
    await expectBadRequest(
      () =>
        t.auth.api.signUpEmail({
          body: { email: "dana.lee@example.com", name: "Dana Lee", password: "Dana1Strong" },
        }),
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("rejects a password containing the session user's name on change-password", async () => {
    const t = await open();
    const user = await t.signUp();
    await expectBadRequest(
      () =>
        t.auth.api.changePassword({
          body: { currentPassword: DEFAULT_PASSWORD, newPassword: "Smith9Strong" },
          headers: user.headers,
        }),
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("rejects a password containing the token owner's email on reset-password", async () => {
    const t = await open();
    const user = await t.signUp();
    const token = await t.requestResetToken(user.email);
    await expectBadRequest(
      () => t.auth.api.resetPassword({ body: { newPassword: "Alice9Strong", token } }),
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("rejects a password containing the new user's name on admin create-user", async () => {
    const t = await open();
    await expectBadRequest(
      () =>
        t.auth.api.createUser({
          body: {
            email: "erin.cole@example.com",
            password: "Erin1Strong",
            name: "Erin Cole",
            role: "user",
          },
        }),
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
    expect(await t.context.internalAdapter.findUserByEmail("erin.cole@example.com")).toBeNull();
  });
});

describe("caseless letters and combining marks", () => {
  const signUpWith = (t: TestAuth, password: string, name = "Nina Park") =>
    t.auth.api.signUpEmail({ body: { email: "nina@example.com", name, password } });

  it("accepts a Thai-only password on sign-up when caselessLettersSatisfyCase is on", async () => {
    const t = await open({ policy: { complexity: { caselessLettersSatisfyCase: true } } });
    const result = await signUpWith(t, THAI_PASSWORD);
    expect(result.user.email).toBe("nina@example.com");
    expect((await t.getCredentialAccount(result.user.id)).password).toBe(`fast:${THAI_PASSWORD}`);
  });

  it.each([
    ["omitted", {}],
    ["false", { caselessLettersSatisfyCase: false }],
  ])("rejects a Thai-only password on sign-up when caselessLettersSatisfyCase is %s", async (_name, complexity) => {
    const t = await open({ policy: { complexity } });
    await expectBadRequest(() => signUpWith(t, THAI_PASSWORD), "PASSWORD_MISSING_UPPERCASE");
    expect(await t.context.internalAdapter.findUserByEmail("nina@example.com")).toBeNull();
  });

  it("accepts a Thai-only new password on change-password when caselessLettersSatisfyCase is on", async () => {
    const t = await open({ policy: { complexity: { caselessLettersSatisfyCase: true } } });
    const user = await t.signUp();
    await t.auth.api.changePassword({
      body: { currentPassword: DEFAULT_PASSWORD, newPassword: THAI_PASSWORD },
      headers: user.headers,
    });
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${THAI_PASSWORD}`);
  });

  it("still rejects a Latin password without uppercase when caselessLettersSatisfyCase is on", async () => {
    const t = await open({ policy: { complexity: { caselessLettersSatisfyCase: true } } });
    await expectBadRequest(() => signUpWith(t, WEAK_NO_UPPERCASE), "PASSWORD_MISSING_UPPERCASE");
  });

  it("does not count Thai vowel and tone marks as a symbol when requireSymbol is on", async () => {
    const t = await open({
      policy: { complexity: { requireSymbol: true, caselessLettersSatisfyCase: true } },
    });
    await expectBadRequest(() => signUpWith(t, THAI_PASSWORD_WITH_MARKS), "PASSWORD_MISSING_SYMBOL");
  });

  it("accepts a Thai password once it contains a real symbol when requireSymbol is on", async () => {
    const t = await open({
      policy: { complexity: { requireSymbol: true, caselessLettersSatisfyCase: true } },
    });
    const result = await signUpWith(t, `${THAI_PASSWORD_WITH_MARKS}!`);
    expect(result.user.email).toBe("nina@example.com");
  });

  it("rejects a password containing the whole Thai name on sign-up", async () => {
    const t = await open();
    await expectBadRequest(
      () => signUpWith(t, THAI_NAME_PASSWORD, THAI_NAME),
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
    expect(await t.context.internalAdapter.findUserByEmail("nina@example.com")).toBeNull();
  });

  it("rejects a password containing the whole Thai name on change-password", async () => {
    const t = await open();
    const user = await t.signUp({ name: THAI_NAME });
    await expectBadRequest(
      () =>
        t.auth.api.changePassword({
          body: { currentPassword: DEFAULT_PASSWORD, newPassword: THAI_NAME_PASSWORD },
          headers: user.headers,
        }),
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });
});

describe("complexity interaction with core checks", () => {
  it("reports INVALID_PASSWORD, not a policy error, when change-password gets a wrong current password and a weak new one", async () => {
    const t = await open();
    const user = await t.signUp();
    await expectBadRequest(
      () =>
        t.auth.api.changePassword({
          body: { currentPassword: "Not-the-password-1", newPassword: WEAK_NO_UPPERCASE },
          headers: user.headers,
        }),
      "INVALID_PASSWORD",
    );
    expect((await t.getCredentialAccount(user.id)).password).toBe(ORIGINAL_HASH);
  });

  it("keeps the reset token valid after a policy rejection so a strong password then succeeds", async () => {
    const t = await open();
    const user = await t.signUp();
    const token = await t.requestResetToken(user.email);
    await expectBadRequest(
      () => t.auth.api.resetPassword({ body: { newPassword: WEAK_NO_UPPERCASE, token } }),
      "PASSWORD_MISSING_UPPERCASE",
    );
    const result = await t.auth.api.resetPassword({
      body: { newPassword: GOOD_PASSWORDS[1], token },
    });
    expect(result.status).toBe(true);
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${GOOD_PASSWORDS[1]}`);
  });

  it("does not apply complexity to sign-in so a non-existent email with a weak password is a plain 401", async () => {
    const t = await open();
    await expectUnauthorized(
      () => t.auth.api.signInEmail({ body: { email: "ghost@example.com", password: "a" } }),
      "INVALID_EMAIL_OR_PASSWORD",
    );
  });

  it("returns the same policy error for an existing and a new email when email verification is required", async () => {
    const t = await open({ requireEmailVerification: true });
    await t.signUp();
    const existing = await captureApiError(() =>
      t.auth.api.signUpEmail({
        body: { email: DEFAULT_EMAIL, name: "Alice Smith", password: WEAK_NO_UPPERCASE },
      }),
    );
    const fresh = await captureApiError(() =>
      t.auth.api.signUpEmail({
        body: { email: "newcomer@example.com", name: "New Comer", password: WEAK_NO_UPPERCASE },
      }),
    );
    expect(existing.statusCode).toBe(400);
    expect(existing.body?.code).toBe("PASSWORD_MISSING_UPPERCASE");
    expect(fresh.statusCode).toBe(existing.statusCode);
    expect(fresh.body?.code).toBe(existing.body?.code);
    expect(fresh.body?.message).toBe(existing.body?.message);
  });

  it("rejects a sign-up body that tries to set passwordChangedAt", async () => {
    const t = await open();
    const body = {
      email: "sneaky@example.com",
      name: "Sneaky Pete",
      password: GOOD_PASSWORDS[0],
      passwordChangedAt: new Date().toISOString(),
    };
    await expectBadRequest(() => t.auth.api.signUpEmail({ body }), "FIELD_NOT_ALLOWED");
  });
});

describe("custom validate callback", () => {
  const BANNED = "Banned1Password";

  it("reports PASSWORD_REJECTED when validate returns false and passes id null on sign-up", async () => {
    const seen: { password: string; user: { id: string | null; email: string | null; name: string | null } }[] = [];
    const t = await open({
      policy: {
        complexity: {
          validate: async (input) => {
            seen.push(input);
            return input.password !== BANNED;
          },
        },
      },
    });
    await expectBadRequest(
      () =>
        t.auth.api.signUpEmail({
          body: { email: "vera@example.com", name: "Vera Hill", password: BANNED },
        }),
      "PASSWORD_REJECTED",
    );
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual({
      password: BANNED,
      user: { id: null, email: "vera@example.com", name: "Vera Hill" },
    });
  });

  it("passes the session user's id to validate on change-password", async () => {
    const seen: { password: string; user: { id: string | null; email: string | null; name: string | null } }[] = [];
    const t = await open({
      policy: {
        complexity: {
          validate: async (input) => {
            seen.push(input);
            return input.password !== BANNED;
          },
        },
      },
    });
    const user = await t.signUp();
    seen.length = 0;
    await expectBadRequest(
      () =>
        t.auth.api.changePassword({
          body: { currentPassword: DEFAULT_PASSWORD, newPassword: BANNED },
          headers: user.headers,
        }),
      "PASSWORD_REJECTED",
    );
    const last = seen[seen.length - 1];
    expect(last.password).toBe(BANNED);
    expect(last.user.id).toBe(user.id);
    expect(last.user.email).toBe(user.email);
  });

  it("accepts the password when validate returns true", async () => {
    const t = await open({ policy: { complexity: { validate: () => true } } });
    const user = await t.signUp();
    expect(user.id).toBeTruthy();
  });
});

describe("complexity switched off", () => {
  it("accepts a weak password on sign-up and change-password", async () => {
    const t = await open({ policy: { complexity: false } });
    const user = await t.signUp({ password: "weakpass1" });
    expect((await t.getCredentialAccount(user.id)).password).toBe("fast:weakpass1");
    await t.auth.api.changePassword({
      body: { currentPassword: "weakpass1", newPassword: "weakpass2" },
      headers: user.headers,
    });
    expect((await t.getCredentialAccount(user.id)).password).toBe("fast:weakpass2");
  });

  it("accepts a weak password on admin create-user", async () => {
    const t = await open({ policy: { complexity: false } });
    const created = await t.auth.api.createUser({
      body: { email: "made@example.com", password: "weakpass1", name: "Made Up", role: "user" },
    });
    expect(created.user.email).toBe("made@example.com");
  });
});
