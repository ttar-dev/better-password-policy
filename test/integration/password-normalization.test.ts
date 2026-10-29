import { describe, it, expect, afterEach } from "vitest";
import { verifyPassword } from "better-auth/crypto";
import {
  createAuthRegistry,
  deviceSetCookieFrom,
  expectBadRequest,
  expectTooManyRequests,
  expectUnauthorized,
  pause,
  DEFAULT_EMAIL,
  DEFAULT_PASSWORD,
  WRONG_PASSWORD,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const TYPED = "Water1น้ำ";
const NORMALIZED = "Water1น้ํา";
const MARKS_TYPED = "Pass1กู้";
const MARKS_OTHER = "Pass1กู้";
const MARKS_NORMALIZED = MARKS_TYPED.normalize("NFKC");
const WRONG_DIFFERING = "Wrong-Water1น้ำ";
const SUPERSCRIPT_DIGIT = "Abcdefgh²";
const SUPERSCRIPT_DIGIT_NORMALIZED = "Abcdefgh2";
const FULLWIDTH_SURNAME = "ＳＭＩＴＨhorse1";
const LONGER_AFTER_NFKC = "Abcdef1ﬁx";
const SHORTER_AFTER_NFKC = "Abcdefg1é";
const THAI_NAME = "\u0E2A\u0E33\u0E23\u0E32\u0E0D \u0E43\u0E08\u0E14\u0E35";
const THAI_NAME_PASSWORD = "Aa\u0E2A\u0E33\u0E23\u0E32\u0E0D1234";
const FULLWIDTH_NAME = "\uFF33\uFF4D\uFF49\uFF54\uFF48";
const FULLWIDTH_NAME_PASSWORD = "Xsmith12A";
const OTHER_EMAIL = "bob@example.com";
const GHOST_EMAIL = "ghost@example.com";
const POLICY = { passwordNormalization: "NFKC" } as const;

const signInWith = (t: TestAuth, password: string, email = DEFAULT_EMAIL) =>
  t.auth.api.signInEmail({ body: { email, password } });

const wrongSignIn = (t: TestAuth, password: string, email = DEFAULT_EMAIL) =>
  expectUnauthorized(
    () => t.auth.api.signInEmail({ body: { email, password } }),
    "INVALID_EMAIL_OR_PASSWORD",
  );

const setLegacyHash = async (t: TestAuth, userId: string, typed: string) => {
  await t.adapter.update({
    model: "account",
    where: [
      { field: "userId", value: userId },
      { field: "providerId", value: "credential" },
    ],
    update: { password: `fast:${typed}` },
  });
};

const verifiesDuring = async (t: TestAuth, run: () => Promise<unknown>) => {
  const before = t.verifyCalls();
  await run();
  return t.verifyCalls() - before;
};

const verifyInputsDuring = async (t: TestAuth, run: () => Promise<unknown>) => {
  const before = t.verifyInputs().length;
  await run();
  return t.verifyInputs().slice(before);
};

const hashInputsDuring = async (t: TestAuth, run: () => Promise<unknown>) => {
  const before = t.hashInputs().length;
  await run();
  return t.hashInputs().slice(before);
};

describe("code points of the fixtures", () => {
  it("normalizes the typed Thai password to the normalized one", () => {
    expect(TYPED.normalize("NFKC")).toBe(NORMALIZED);
    expect(TYPED).not.toBe(NORMALIZED);
    expect(MARKS_OTHER.normalize("NFKC")).toBe(MARKS_NORMALIZED);
    expect(MARKS_OTHER).not.toBe(MARKS_TYPED);
  });
});

describe("passwordNormalization off", () => {
  it("hashes the password as typed and rejects the normalized form of it", async () => {
    const t = await open();
    const user = await t.signUp({ password: TYPED });
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${TYPED}`);
    expect(t.hashInputs()).toEqual([TYPED]);
    const verifies = await verifiesDuring(t, () => wrongSignIn(t, NORMALIZED));
    expect(verifies).toBe(1);
    expect(t.verifyInputs()).toEqual([NORMALIZED]);
  });

  it("treats false like the default", async () => {
    const t = await open({ policy: { passwordNormalization: false } });
    const user = await t.signUp({ password: TYPED });
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${TYPED}`);
    await wrongSignIn(t, NORMALIZED);
  });

  it("verifies once for a wrong password whose forms would differ", async () => {
    const t = await open();
    await t.signUp();
    expect(await verifiesDuring(t, () => wrongSignIn(t, WRONG_DIFFERING))).toBe(1);
  });
});

describe("passwordNormalization NFKC", () => {
  it("stores the normalized hash on sign-up and hashes only the normalized password", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: TYPED });
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${NORMALIZED}`);
    expect(t.hashInputs()).toEqual([NORMALIZED]);
  });

  it("signs in with the normalized form using one verification", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: TYPED });
    let result: Awaited<ReturnType<typeof signInWith>> | undefined;
    const inputs = await verifyInputsDuring(t, async () => {
      result = await signInWith(t, NORMALIZED);
    });
    expect(result?.user.id).toBe(user.id);
    expect(inputs).toEqual([NORMALIZED]);
  });

  it("signs in with the form as originally typed using one verification", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: TYPED });
    let result: Awaited<ReturnType<typeof signInWith>> | undefined;
    const inputs = await verifyInputsDuring(t, async () => {
      result = await signInWith(t, TYPED);
    });
    expect(result?.user.id).toBe(user.id);
    expect(inputs).toEqual([NORMALIZED]);
  });

  it("lets a user who signed up with the normalized form sign in with the typed one", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: NORMALIZED });
    expect((await signInWith(t, TYPED)).user.id).toBe(user.id);
    expect((await signInWith(t, NORMALIZED)).user.id).toBe(user.id);
  });

  it("matches the same Thai password typed with the vowel and tone marks in the other order", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: MARKS_TYPED });
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${MARKS_NORMALIZED}`);
    expect((await signInWith(t, MARKS_OTHER)).user.id).toBe(user.id);
  });

  it("still rejects a wrong password", async () => {
    const t = await open({ policy: POLICY });
    await t.signUp({ password: TYPED });
    await wrongSignIn(t, WRONG_DIFFERING);
  });

});

describe("with Better Auth's default password hasher", () => {
  const recordedOptions = { policy: POLICY, realHasher: true, recordBaseHasherCalls: true } as const;
  const realOptions = { policy: POLICY, realHasher: true } as const;

  it("leaves Better Auth's own verify in place when nothing else wraps it", async () => {
    const t = await open({ policy: { ...POLICY, lockout: false }, realHasher: true });
    const context = await t.auth.$context;
    expect(context.password.verify).toBe(verifyPassword);
  });

  it("verifies the normalized form and then the typed form when a plugin before passwordPolicy wraps the hasher", async () => {
    const t = await open(recordedOptions);
    await t.signUp();
    const before = t.baseVerifyInputs().length;
    await wrongSignIn(t, WRONG_DIFFERING);
    expect(t.baseVerifyInputs().slice(before)).toEqual([WRONG_DIFFERING.normalize("NFKC"), WRONG_DIFFERING]);
  });

  it("hashes the normalized and then the typed password for an unknown email when a plugin before passwordPolicy wraps the hasher", async () => {
    const t = await open(recordedOptions);
    const before = t.baseHashInputs().length;
    await wrongSignIn(t, WRONG_DIFFERING, GHOST_EMAIL);
    expect(t.baseHashInputs().slice(before)).toEqual([WRONG_DIFFERING.normalize("NFKC"), WRONG_DIFFERING]);
  });

  it("signs in with the normalized form after signing up with the typed form", async () => {
    const t = await open(realOptions);
    const user = await t.signUp({ password: TYPED });
    expect((await signInWith(t, NORMALIZED)).user.id).toBe(user.id);
  });

  it("signs in with the typed form after signing up with the normalized form", async () => {
    const t = await open(realOptions);
    const user = await t.signUp({ password: NORMALIZED });
    expect((await signInWith(t, TYPED)).user.id).toBe(user.id);
  });

  it("still rejects a wrong password", async () => {
    const t = await open(realOptions);
    await t.signUp({ password: TYPED });
    await wrongSignIn(t, WRONG_PASSWORD);
  });

  it("accepts a superscript digit as the required digit with NFKC on", async () => {
    const t = await open(realOptions);
    const user = await t.signUp({ password: SUPERSCRIPT_DIGIT });
    expect((await signInWith(t, SUPERSCRIPT_DIGIT_NORMALIZED)).user.id).toBe(user.id);
  });

  it("rejects a superscript digit as missing the digit with NFKC off", async () => {
    const t = await open({ realHasher: true });
    await expectBadRequest(() => t.signUp({ password: SUPERSCRIPT_DIGIT }), "PASSWORD_MISSING_DIGIT");
  });
});

describe("a hash made before the option was turned on", () => {
  it("signs in with the password as it was typed, verifying the normalized form first", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp();
    await setLegacyHash(t, user.id, TYPED);
    let result: Awaited<ReturnType<typeof signInWith>> | undefined;
    const inputs = await verifyInputsDuring(t, async () => {
      result = await signInWith(t, TYPED);
    });
    expect(result?.user.id).toBe(user.id);
    expect(inputs).toEqual([NORMALIZED, TYPED]);
  });

  it("rejects the normalized form of it with one verification", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp();
    await setLegacyHash(t, user.id, TYPED);
    const verifies = await verifiesDuring(t, () => wrongSignIn(t, NORMALIZED));
    expect(verifies).toBe(1);
  });

  it("does not rewrite the stored hash after a successful sign-in", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp();
    await setLegacyHash(t, user.id, TYPED);
    await signInWith(t, TYPED);
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${TYPED}`);
  });
});

describe("ASCII passwords with NFKC on", () => {
  it("verifies once on success", async () => {
    const t = await open({ policy: POLICY });
    await t.signUp();
    expect(await verifiesDuring(t, () => signInWith(t, DEFAULT_PASSWORD))).toBe(1);
  });

  it("verifies once on failure", async () => {
    const t = await open({ policy: POLICY });
    await t.signUp();
    expect(await verifiesDuring(t, () => wrongSignIn(t, WRONG_PASSWORD))).toBe(1);
  });

  it("stores the hash of the password unchanged", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp();
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${DEFAULT_PASSWORD}`);
  });
});

describe("a wrong password whose forms differ", () => {
  it("verifies twice and counts one failed attempt", async () => {
    const t = await open({ policy: { ...POLICY, lockout: { maxAttempts: 3 } } });
    await t.signUp();
    const inputs = await verifyInputsDuring(t, () => wrongSignIn(t, WRONG_DIFFERING));
    expect(inputs).toEqual([WRONG_DIFFERING.normalize("NFKC"), WRONG_DIFFERING]);
    expect((await t.lockoutRow(`email:${DEFAULT_EMAIL}`))?.failedAttempts).toBe(1);
  });

  it("locks after maxAttempts wrong passwords, refuses the fourth without verifying and used six verifications", async () => {
    const t = await open({ policy: { ...POLICY, lockout: { maxAttempts: 3 } } });
    await t.signUp();
    const before = t.verifyCalls();
    await wrongSignIn(t, WRONG_DIFFERING);
    await wrongSignIn(t, WRONG_DIFFERING);
    await wrongSignIn(t, WRONG_DIFFERING);
    await expectTooManyRequests(
      () => t.auth.api.signInEmail({ body: { email: DEFAULT_EMAIL, password: WRONG_DIFFERING } }),
      "SIGN_IN_LOCKED",
    );
    expect(t.verifyCalls() - before).toBe(6);
    expect((await t.lockoutRow(`email:${DEFAULT_EMAIL}`))?.lockedUntil).toBeInstanceOf(Date);
  });

  it("resets the counter and issues the device cookie when the typed fallback form matches", async () => {
    const t = await open({ policy: { ...POLICY, lockout: { maxAttempts: 3 } } });
    const user = await t.signUp();
    await setLegacyHash(t, user.id, TYPED);
    await wrongSignIn(t, WRONG_PASSWORD);
    expect((await t.lockoutRow(`email:${DEFAULT_EMAIL}`))?.failedAttempts).toBe(1);
    const result = await t.auth.api.signInEmail({
      body: { email: DEFAULT_EMAIL, password: TYPED },
      returnHeaders: true,
    });
    expect(result.response.user.id).toBe(user.id);
    expect(await t.lockoutRow(`email:${DEFAULT_EMAIL}`)).toBeNull();
    expect(deviceSetCookieFrom(result.headers)).toBeDefined();
  });

  it("resets the counter when the normalized form matches", async () => {
    const t = await open({ policy: { ...POLICY, lockout: { maxAttempts: 3 } } });
    await t.signUp({ password: TYPED });
    await wrongSignIn(t, WRONG_PASSWORD);
    await signInWith(t, TYPED);
    expect(await t.lockoutRow(`email:${DEFAULT_EMAIL}`)).toBeNull();
  });
});

describe("complexity sees the normalized password", () => {
  it("accepts a superscript digit as the digit with NFKC on and hashes the normalized form", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: SUPERSCRIPT_DIGIT });
    expect((await t.getCredentialAccount(user.id)).password).toBe(
      `fast:${SUPERSCRIPT_DIGIT_NORMALIZED}`,
    );
  });

  it("reports PASSWORD_MISSING_DIGIT for the same password with NFKC off", async () => {
    const t = await open();
    await expectBadRequest(() => t.signUp({ password: SUPERSCRIPT_DIGIT }), "PASSWORD_MISSING_DIGIT");
  });

  it("reports the personal info check on a Thai name stored in the typed form with NFKC on", async () => {
    const t = await open({ policy: POLICY });
    await expectBadRequest(
      () => t.signUp({ name: THAI_NAME, password: THAI_NAME_PASSWORD }),
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("reports the personal info check on a Thai name with NFKC off", async () => {
    const t = await open();
    await expectBadRequest(
      () => t.signUp({ name: THAI_NAME, password: THAI_NAME_PASSWORD }),
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("reports the personal info check on a fullwidth stored name with NFKC on", async () => {
    const t = await open({ policy: POLICY });
    await expectBadRequest(
      () => t.signUp({ name: FULLWIDTH_NAME, password: FULLWIDTH_NAME_PASSWORD }),
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("does not report the personal info check on a fullwidth stored name with NFKC off", async () => {
    const t = await open();
    const user = await t.signUp({ name: FULLWIDTH_NAME, password: FULLWIDTH_NAME_PASSWORD });
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${FULLWIDTH_NAME_PASSWORD}`);
  });

  it("reports the personal info check on the fullwidth surname with NFKC on", async () => {
    const t = await open({ policy: POLICY });
    await expectBadRequest(
      () => t.signUp({ password: FULLWIDTH_SURNAME }),
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("does not report the personal info check on the fullwidth surname with NFKC off", async () => {
    const t = await open();
    const user = await t.signUp({ password: FULLWIDTH_SURNAME });
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${FULLWIDTH_SURNAME}`);
  });

  it("counts minLength on the normalized password when NFKC makes it longer", async () => {
    const policy = { complexity: { minLength: 10 } };
    const on = await open({ policy: { ...policy, ...POLICY } });
    const user = await on.signUp({ password: LONGER_AFTER_NFKC });
    expect((await on.getCredentialAccount(user.id)).password).toBe(
      `fast:${LONGER_AFTER_NFKC.normalize("NFKC")}`,
    );
    const off = await open({ policy });
    await expectBadRequest(() => off.signUp({ password: LONGER_AFTER_NFKC }), "PASSWORD_TOO_SHORT");
  });

  it("counts minLength on the normalized password when NFKC makes it shorter", async () => {
    const policy = { complexity: { minLength: 10 } };
    const on = await open({ policy: { ...policy, ...POLICY } });
    await expectBadRequest(() => on.signUp({ password: SHORTER_AFTER_NFKC }), "PASSWORD_TOO_SHORT");
    const off = await open({ policy });
    const user = await off.signUp({ password: SHORTER_AFTER_NFKC });
    expect((await off.getCredentialAccount(user.id)).password).toBe(`fast:${SHORTER_AFTER_NFKC}`);
  });

  it("passes the normalized password to validate", async () => {
    const seen: string[] = [];
    const t = await open({
      policy: {
        ...POLICY,
        complexity: {
          validate: (input) => {
            seen.push(input.password);
            return true;
          },
        },
      },
    });
    await t.signUp({ password: TYPED });
    expect(seen).toEqual([NORMALIZED]);
  });

  it("passes the typed password to validate with NFKC off", async () => {
    const seen: string[] = [];
    const t = await open({
      policy: {
        complexity: {
          validate: (input) => {
            seen.push(input.password);
            return true;
          },
        },
      },
    });
    await t.signUp({ password: TYPED });
    expect(seen).toEqual([TYPED]);
  });
});

describe("history sees both forms", () => {
  const change = async (t: TestAuth, headers: Headers, currentPassword: string, newPassword: string) => {
    await pause();
    return t.auth.api.changePassword({ body: { currentPassword, newPassword }, headers });
  };

  it("rejects changing from the typed form to its normalized form as reused", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: TYPED });
    await expectBadRequest(() => change(t, user.headers, TYPED, NORMALIZED), "PASSWORD_REUSED");
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${NORMALIZED}`);
  });

  it("rejects changing from the normalized form to the typed form as reused", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: NORMALIZED });
    await expectBadRequest(() => change(t, user.headers, NORMALIZED, TYPED), "PASSWORD_REUSED");
  });

  it("rejects a new password equal to a legacy current hash as reused", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp();
    await setLegacyHash(t, user.id, TYPED);
    await expectBadRequest(() => change(t, user.headers, TYPED, TYPED), "PASSWORD_REUSED");
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${TYPED}`);
  });

  it("records the normalized hash as the new history row", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp();
    await change(t, user.headers, DEFAULT_PASSWORD, TYPED);
    const [latest] = await t.historyRows(user.id);
    expect(latest?.passwordHash).toBe(`fast:${NORMALIZED}`);
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${NORMALIZED}`);
  });

  it("accepts a different password", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: TYPED });
    await change(t, user.headers, TYPED, "Battery2Staple");
    expect((await t.getCredentialAccount(user.id)).password).toBe("fast:Battery2Staple");
  });
});

describe("admin create-user", () => {
  it("accepts the superscript digit with NFKC on", async () => {
    const t = await open({ policy: POLICY });
    const created = await t.auth.api.createUser({
      body: { email: OTHER_EMAIL, password: SUPERSCRIPT_DIGIT, name: "Bob Jones", role: "user" },
    });
    expect((await t.getCredentialAccount(created.user.id)).password).toBe(
      `fast:${SUPERSCRIPT_DIGIT_NORMALIZED}`,
    );
  });

  it("rejects the superscript digit with NFKC off", async () => {
    const t = await open();
    await expectBadRequest(
      () =>
        t.auth.api.createUser({
          body: { email: OTHER_EMAIL, password: SUPERSCRIPT_DIGIT, name: "Bob Jones", role: "user" },
        }),
      "PASSWORD_MISSING_DIGIT",
    );
  });

  it("stores the normalized hash and lets the new user sign in with the normalized form", async () => {
    const t = await open({ policy: POLICY });
    const created = await t.auth.api.createUser({
      body: { email: OTHER_EMAIL, password: TYPED, name: "Bob Jones", role: "user" },
    });
    expect((await t.getCredentialAccount(created.user.id)).password).toBe(`fast:${NORMALIZED}`);
    expect((await signInWith(t, NORMALIZED, OTHER_EMAIL)).user.id).toBe(created.user.id);
    expect((await signInWith(t, TYPED, OTHER_EMAIL)).user.id).toBe(created.user.id);
  });
});

describe("other password checks accept the other form", () => {
  it("accepts the normalized form on /verify-password for a password set with the typed form", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: TYPED });
    const result = await t.auth.api.verifyPassword({
      body: { password: NORMALIZED },
      headers: user.headers,
    });
    expect(result.status).toBe(true);
  });

  it("rejects a wrong password on /verify-password", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: TYPED });
    await expectBadRequest(
      () => t.auth.api.verifyPassword({ body: { password: WRONG_PASSWORD }, headers: user.headers }),
      "INVALID_PASSWORD",
    );
  });

  it("enables two-factor with the normalized form of a password set with the typed form", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp({ password: TYPED });
    const result = await t.auth.api.enableTwoFactor({
      body: { password: NORMALIZED },
      headers: user.headers,
    });
    expect(result).toMatchObject({ totpURI: expect.any(String) });
  });

  it("deletes the user with the normalized form of a password set with the typed form", async () => {
    const t = await open({ policy: POLICY, enableDeleteUser: true });
    const user = await t.signUp({ password: TYPED });
    await t.auth.api.deleteUser({ body: { password: NORMALIZED }, headers: user.headers });
    expect(await t.context.internalAdapter.findUserById(user.id)).toBeNull();
  });
});

describe("sign-in for an account that does not exist", () => {
  it("hashes the normalized and then the typed password once each when NFKC changes the password", async () => {
    const t = await open({ policy: POLICY });
    const inputs = await hashInputsDuring(t, () => wrongSignIn(t, TYPED, GHOST_EMAIL));
    expect(inputs).toEqual([NORMALIZED, TYPED]);
  });

  it("hashes an ASCII password once", async () => {
    const t = await open({ policy: POLICY });
    const inputs = await hashInputsDuring(t, () => wrongSignIn(t, WRONG_PASSWORD, GHOST_EMAIL));
    expect(inputs).toEqual([WRONG_PASSWORD]);
  });

  it("hashes the password once with NFKC off", async () => {
    const t = await open();
    const inputs = await hashInputsDuring(t, () => wrongSignIn(t, TYPED, GHOST_EMAIL));
    expect(inputs).toEqual([TYPED]);
  });

  it("hashes twice for an unknown username when NFKC changes the password", async () => {
    const t = await open({ policy: POLICY });
    const inputs = await hashInputsDuring(t, () =>
      expectUnauthorized(
        () => t.auth.api.signInUsername({ body: { username: "ghost_user", password: TYPED } }),
        "INVALID_USERNAME_OR_PASSWORD",
      ),
    );
    expect(inputs).toEqual([NORMALIZED, TYPED]);
  });

  it("does not hash anything for an existing account", async () => {
    const t = await open({ policy: POLICY });
    await t.signUp({ password: TYPED });
    const inputs = await hashInputsDuring(t, () => wrongSignIn(t, WRONG_DIFFERING));
    expect(inputs).toEqual([]);
  });

  it("costs an unknown account and an existing account the same number of base calls for a password NFKC changes", async () => {
    const t = await open({ policy: POLICY });
    await t.signUp();
    const existingVerifies = await verifiesDuring(t, () => wrongSignIn(t, WRONG_DIFFERING));
    const ghostHashes = (await hashInputsDuring(t, () => wrongSignIn(t, WRONG_DIFFERING, GHOST_EMAIL))).length;
    expect(existingVerifies).toBe(2);
    expect(ghostHashes).toBe(2);
  });
});

describe("hash calls outside the sign-in paths hash only the normalized password", () => {
  it("hashes only the normalized form when change-password fails on a wrong current password", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp();
    await pause();
    const inputs = await hashInputsDuring(t, () =>
      expectBadRequest(
        () =>
          t.auth.api.changePassword({
            body: { currentPassword: WRONG_PASSWORD, newPassword: TYPED },
            headers: user.headers,
          }),
        "INVALID_PASSWORD",
      ),
    );
    expect(inputs).not.toContain(TYPED);
    expect(inputs.length).toBeGreaterThan(0);
    expect(inputs.every((input) => input === NORMALIZED)).toBe(true);
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${DEFAULT_PASSWORD}`);
  });

  it("hashes only the normalized form when set-password is rejected for a user who already has a password", async () => {
    const t = await open({ policy: POLICY });
    const user = await t.signUp();
    const inputs = await hashInputsDuring(t, () =>
      expectBadRequest(
        () => t.auth.api.setPassword({ body: { newPassword: TYPED }, headers: user.headers }),
        "PASSWORD_ALREADY_SET",
      ),
    );
    expect(inputs).not.toContain(TYPED);
    expect(inputs.length).toBeGreaterThan(0);
    expect(inputs.every((input) => input === NORMALIZED)).toBe(true);
  });

  it("hashes the normalized password exactly once on admin create-user", async () => {
    const t = await open({ policy: POLICY });
    const inputs = await hashInputsDuring(t, () =>
      t.auth.api.createUser({
        body: { email: OTHER_EMAIL, password: TYPED, name: "Bob Jones", role: "user" },
      }),
    );
    expect(inputs).toEqual([NORMALIZED]);
  });

  it("hashes the normalized password exactly once on sign-up", async () => {
    const t = await open({ policy: POLICY });
    const inputs = await hashInputsDuring(t, () => t.signUp({ password: TYPED }));
    expect(inputs).toEqual([NORMALIZED]);
  });
});

describe("a plugin before passwordPolicy replaces the hasher with one that does not normalize", () => {
  const replacedOptions = { policy: POLICY, replaceHasherBeforePolicy: true, realHasher: true } as const;
  const change = async (t: TestAuth, headers: Headers, currentPassword: string, newPassword: string) => {
    await pause();
    return t.auth.api.changePassword({ body: { currentPassword, newPassword }, headers });
  };

  it("signs in with the form as originally typed", async () => {
    const t = await open(replacedOptions);
    const user = await t.signUp({ password: TYPED });
    expect((await signInWith(t, TYPED)).user.id).toBe(user.id);
  });

  it("signs in with the normalized form", async () => {
    const t = await open(replacedOptions);
    const user = await t.signUp({ password: TYPED });
    expect((await signInWith(t, NORMALIZED)).user.id).toBe(user.id);
  });

  it("stores the hash of the normalized password", async () => {
    const t = await open(replacedOptions);
    const user = await t.signUp({ password: TYPED });
    expect((await t.getCredentialAccount(user.id)).password).toBe(`plain:${NORMALIZED}`);
  });

  it("rejects changing the password from the typed form to its normalized form as reused", async () => {
    const t = await open(replacedOptions);
    const user = await t.signUp({ password: TYPED });
    await expectBadRequest(() => change(t, user.headers, TYPED, NORMALIZED), "PASSWORD_REUSED");
  });

  it("still rejects a wrong password", async () => {
    const t = await open(replacedOptions);
    await t.signUp({ password: TYPED });
    await wrongSignIn(t, WRONG_DIFFERING);
  });
});
