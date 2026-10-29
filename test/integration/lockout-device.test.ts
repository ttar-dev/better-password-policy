import { createHmac } from "node:crypto";
import { describe, it, expect, afterEach, vi } from "vitest";
import {
  createAuthRegistry,
  deviceCookieHeadersFrom,
  deviceSetCookieFrom,
  expectTooManyRequests,
  expectUnauthorized,
  DEFAULT_EMAIL,
  DEFAULT_PASSWORD,
  GOOD_PASSWORDS,
  WRONG_PASSWORD,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  vi.useRealTimers();
  await registry.closeAll();
});

const SECRET = "x".repeat(40);
const policy = { lockout: { maxAttempts: 3 } };
const EMAIL_IDENTIFIER = `email:${DEFAULT_EMAIL}`;
const BOB_EMAIL = "bob@example.com";
const PHONE = "+66812345678";
const USERNAME = "alice_smith";
const [, P1] = GOOD_PASSWORDS;
const IDENTIFIER_KEY = /^i1:[0-9a-f]{64}$/;
const DEVICE_KEY = /^d1:[0-9a-f]{64}:[0-9a-f]{32}$/;
const DAY_SECONDS = 86_400;
const DEFAULT_COOKIE_MAX_AGE = 2_592_000;

const signInOk = (t: TestAuth, headers?: Headers, email = DEFAULT_EMAIL, password = DEFAULT_PASSWORD) =>
  t.auth.api.signInEmail({
    body: { email, password },
    returnHeaders: true,
    ...(headers ? { headers } : {}),
  });

const wrongEmail = (t: TestAuth, headers?: Headers, email = DEFAULT_EMAIL) =>
  expectUnauthorized(
    () =>
      t.auth.api.signInEmail({
        body: { email, password: WRONG_PASSWORD },
        ...(headers ? { headers } : {}),
      }),
    "INVALID_EMAIL_OR_PASSWORD",
  );

const lockedEmail = (t: TestAuth, headers?: Headers, password = WRONG_PASSWORD, email = DEFAULT_EMAIL) =>
  expectTooManyRequests(
    () =>
      t.auth.api.signInEmail({
        body: { email, password },
        ...(headers ? { headers } : {}),
      }),
    "SIGN_IN_LOCKED",
  );

const wrongTimes = async (count: number, run: () => Promise<unknown>) => {
  for (let attempt = 0; attempt < count; attempt += 1) {
    await run();
  }
};

const obtainDevice = async (t: TestAuth, email = DEFAULT_EMAIL, password = DEFAULT_PASSWORD) =>
  deviceCookieHeadersFrom((await signInOk(t, undefined, email, password)).headers);

const emailBody = (password: string) => ({ email: DEFAULT_EMAIL, password });

const deviceCookieAttributes = (setCookie: string) => setCookie.split(";").map((part) => part.trim());

const deviceCookieParts = (cookieHeaders: Headers) => {
  const pair = cookieHeaders.get("cookie") ?? "";
  const separator = pair.indexOf("=");
  const name = pair.slice(0, separator);
  const decoded = decodeURIComponent(pair.slice(separator + 1));
  const signatureStart = decoded.lastIndexOf(".");
  const unsigned = decoded.slice(0, signatureStart);
  const [version, deviceId, expiresAt, binding] = unsigned.split(":");
  return {
    name,
    decoded,
    signatureStart,
    unsigned,
    version,
    deviceId: deviceId ?? "",
    expiresAt: expiresAt ?? "",
    binding: binding ?? "",
  };
};

const signLikeBetterCall = (name: string, value: string): Headers => {
  const signature = createHmac("sha256", SECRET).update(value).digest("base64");
  return new Headers({ cookie: `${name}=${encodeURIComponent(`${value}.${signature}`)}` });
};

const tamperSignature = (cookieHeaders: Headers): Headers => {
  const parts = deviceCookieParts(cookieHeaders);
  const first = parts.decoded[parts.signatureStart + 1] === "A" ? "B" : "A";
  const tampered =
    parts.decoded.slice(0, parts.signatureStart + 1) +
    first +
    parts.decoded.slice(parts.signatureStart + 2);
  return new Headers({ cookie: `${parts.name}=${encodeURIComponent(tampered)}` });
};

const forgeWrongBinding = (cookieHeaders: Headers): Headers => {
  const parts = deviceCookieParts(cookieHeaders);
  return signLikeBetterCall(
    parts.name,
    `v1:${parts.deviceId}:${parts.expiresAt}:${"0".repeat(64)}`,
  );
};

const identifiersOf = async (t: TestAuth) => (await t.lockoutRows()).map((row) => row.identifier);

describe("stored lockout keys", () => {
  it("stores identifier and device counters as keyed hashes with no readable email, username or phone", async () => {
    const t = await open({ policy });
    const user = await t.signUp({ username: USERNAME });
    await t.markPhoneNumber(user.id, PHONE);
    const device = await obtainDevice(t);
    await wrongEmail(t);
    await expectUnauthorized(
      () => t.auth.api.signInUsername({ body: { username: USERNAME, password: WRONG_PASSWORD } }),
      "INVALID_USERNAME_OR_PASSWORD",
    );
    await expectUnauthorized(
      () => t.auth.api.signInPhoneNumber({ body: { phoneNumber: PHONE, password: WRONG_PASSWORD } }),
      "INVALID_PHONE_NUMBER_OR_PASSWORD",
    );
    await wrongEmail(t, device);

    const identifiers = await identifiersOf(t);
    expect(identifiers).toHaveLength(4);
    expect(identifiers.filter((value) => IDENTIFIER_KEY.test(value))).toHaveLength(3);
    expect(identifiers.filter((value) => DEVICE_KEY.test(value))).toHaveLength(1);
    for (const value of identifiers) {
      expect(value).not.toContain("alice");
      expect(value).not.toContain("example.com");
      expect(value).not.toContain("smith");
      expect(value).not.toContain("66812345678");
    }
  });
});

describe("device cookie issuance", () => {
  it("sets a signed HttpOnly SameSite=Lax cookie for 30 days on a successful sign-in without Secure on http", async () => {
    const t = await open({ policy });
    await t.signUp();
    const before = Math.floor(Date.now() / 1000);
    const result = await signInOk(t);
    const after = Math.floor(Date.now() / 1000);
    const setCookie = deviceSetCookieFrom(result.headers);
    expect(setCookie).toBeDefined();
    expect(setCookie).toMatch(/^better-auth\.password_policy_device=/);
    const attributes = deviceCookieAttributes(setCookie!);
    expect(attributes).toContain(`Max-Age=${DEFAULT_COOKIE_MAX_AGE}`);
    expect(attributes).toContain("Path=/");
    expect(attributes).toContain("HttpOnly");
    expect(attributes).toContain("SameSite=Lax");
    expect(attributes).not.toContain("Secure");

    const parts = deviceCookieParts(deviceCookieHeadersFrom(result.headers));
    expect(parts.version).toBe("v1");
    expect(parts.deviceId).toMatch(/^[0-9a-f]{32}$/);
    expect(parts.binding).toMatch(/^[0-9a-f]{64}$/);
    expect(Number(parts.expiresAt)).toBeGreaterThanOrEqual(before + DEFAULT_COOKIE_MAX_AGE);
    expect(Number(parts.expiresAt)).toBeLessThanOrEqual(after + DEFAULT_COOKIE_MAX_AGE);
  });

  it("uses the configured deviceCookie maxAge", async () => {
    const t = await open({ policy: { lockout: { maxAttempts: 3, deviceCookie: { maxAge: 600 } } } });
    await t.signUp();
    const setCookie = deviceSetCookieFrom((await signInOk(t)).headers);
    expect(deviceCookieAttributes(setCookie!)).toContain("Max-Age=600");
  });

  it("issues a different cookie value on every successful sign-in, including one made with the previous cookie", async () => {
    const t = await open({ policy });
    await t.signUp();
    const first = await obtainDevice(t);
    const second = await signInOk(t);
    const third = await signInOk(t, first);
    const values = [
      first.get("cookie"),
      deviceCookieHeadersFrom(second.headers).get("cookie"),
      deviceCookieHeadersFrom(third.headers).get("cookie"),
    ];
    expect(new Set(values).size).toBe(3);
    expect(deviceCookieParts(first).deviceId).not.toBe(
      deviceCookieParts(deviceCookieHeadersFrom(third.headers)).deviceId,
    );
  });

  it.each([
    ["policy after two-factor", false],
    ["policy before two-factor", true],
  ])("is issued on the two-factor redirect with %s", async (_label, policyBeforeTwoFactor) => {
    const t = await open({ policy, policyBeforeTwoFactor });
    const user = await t.signUp();
    await t.enableTwoFactor(user.id);
    const result = await signInOk(t);
    expect((result.response as unknown as { twoFactorRedirect?: boolean }).twoFactorRedirect).toBe(true);
    expect(deviceSetCookieFrom(result.headers)).toBeDefined();
  });

  it("is issued with 403 BANNED_USER when the correct password meets a banned user", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.updateUserRow(user.id, { banned: true });
    const response = await t.signInResponse("/sign-in/email", emailBody(DEFAULT_PASSWORD));
    expect(response.status).toBe(403);
    expect(deviceSetCookieFrom(response.headers)).toBeDefined();
  });

  it("is issued with 403 EMAIL_NOT_VERIFIED when the correct password meets an unverified user", async () => {
    const t = await open({ policy, requireEmailVerification: true });
    await t.signUp();
    const response = await t.signInResponse("/sign-in/email", emailBody(DEFAULT_PASSWORD));
    expect(response.status).toBe(403);
    expect(deviceSetCookieFrom(response.headers)).toBeDefined();
  });

  it("is not issued for a wrong password", async () => {
    const t = await open({ policy });
    await t.signUp();
    const response = await t.signInResponse("/sign-in/email", emailBody(WRONG_PASSWORD));
    expect(response.status).toBe(401);
    expect(deviceSetCookieFrom(response.headers)).toBeUndefined();
  });

  it("is not issued for an unknown email", async () => {
    const t = await open({ policy });
    await t.signUp();
    const response = await t.signInResponse("/sign-in/email", {
      email: "ghost@example.com",
      password: DEFAULT_PASSWORD,
    });
    expect(response.status).toBe(401);
    expect(deviceSetCookieFrom(response.headers)).toBeUndefined();
  });

  it("is not issued for a body without an email", async () => {
    const t = await open({ policy });
    await t.signUp();
    const response = await t.signInResponse("/sign-in/email", { password: DEFAULT_PASSWORD });
    expect(response.status).toBe(400);
    expect(deviceSetCookieFrom(response.headers)).toBeUndefined();
  });

  it("is not issued on 429 for an untrusted client or for one carrying a cookie that is itself locked out", async () => {
    const t = await open({ policy });
    await t.signUp();
    const device = await obtainDevice(t);
    await wrongTimes(3, () => wrongEmail(t));
    const untrusted = await t.signInResponse("/sign-in/email", emailBody(DEFAULT_PASSWORD));
    expect(untrusted.status).toBe(429);
    expect(deviceSetCookieFrom(untrusted.headers)).toBeUndefined();

    await wrongTimes(3, () => wrongEmail(t, device));
    const trusted = await t.signInResponse("/sign-in/email", emailBody(DEFAULT_PASSWORD), device);
    expect(trusted.status).toBe(429);
    expect(deviceSetCookieFrom(trusted.headers)).toBeUndefined();
  });

  it("is not issued and never trusted when deviceCookie is false", async () => {
    const t = await open({ policy: { lockout: { maxAttempts: 3, deviceCookie: false } } });
    await t.signUp();
    const response = await t.signInResponse("/sign-in/email", emailBody(DEFAULT_PASSWORD));
    expect(response.status).toBe(200);
    expect(deviceSetCookieFrom(response.headers)).toBeUndefined();
  });

  it("is not issued when lockout is switched off", async () => {
    const t = await open({ policy: { lockout: false } });
    await t.signUp();
    const response = await t.signInResponse("/sign-in/email", emailBody(DEFAULT_PASSWORD));
    expect(response.status).toBe(200);
    expect(deviceSetCookieFrom(response.headers)).toBeUndefined();
  });
});

describe("trusted device counting", () => {
  it("lets the trusted device sign in while the identifier is locked and leaves the identifier lock in place", async () => {
    const t = await open({ policy });
    await t.signUp();
    const device = await obtainDevice(t);
    await wrongTimes(3, () => wrongEmail(t));
    await lockedEmail(t, undefined, DEFAULT_PASSWORD);

    const result = await signInOk(t, device);
    expect(result.response.user.email).toBe(DEFAULT_EMAIL);

    const row = await t.lockoutRow(EMAIL_IDENTIFIER);
    expect(row?.failedAttempts).toBe(3);
    expect(row?.lockedUntil).toBeInstanceOf(Date);
    await lockedEmail(t, undefined, DEFAULT_PASSWORD);
  });

  it("counts a wrong password sent with the cookie in the device row and not in the identifier row", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    await wrongEmail(t);
    await wrongEmail(t, device);
    await wrongEmail(t, device);

    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(1);
    const deviceRows = await t.deviceLockoutRows(user.id);
    expect(deviceRows).toHaveLength(1);
    expect(deviceRows[0]?.failedAttempts).toBe(2);
  });

  it("locks the device after maxAttempts wrong passwords without verifying the next one, while an untrusted client can still sign in", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    await wrongTimes(3, () => wrongEmail(t, device));

    const verifyCallsBefore = t.verifyCalls();
    await lockedEmail(t, device, DEFAULT_PASSWORD);
    expect(t.verifyCalls()).toBe(verifyCallsBefore);

    const [deviceRow] = await t.deviceLockoutRows(user.id);
    expect(deviceRow?.lockedUntil).toBeInstanceOf(Date);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();

    const untrusted = await signInOk(t);
    expect(untrusted.response.user.email).toBe(DEFAULT_EMAIL);
  });

  it("lets exactly maxAttempts of ten concurrent wrong passwords with the cookie be verified and answers the rest with 429", async () => {
    const t = await open({ policy });
    await t.signUp();
    const device = await obtainDevice(t);
    const verifyCallsBefore = t.verifyCalls();
    const outcomes = await Promise.allSettled(
      Array.from({ length: 10 }, () =>
        t.auth.api.signInEmail({ body: emailBody(WRONG_PASSWORD), headers: device }),
      ),
    );
    const statusCodes = outcomes.map((outcome) =>
      outcome.status === "fulfilled" ? 200 : (outcome.reason as { statusCode: number }).statusCode,
    );
    expect(statusCodes.filter((code) => code === 401)).toHaveLength(3);
    expect(statusCodes.filter((code) => code === 429)).toHaveLength(7);
    expect(t.verifyCalls() - verifyCallsBefore).toBe(3);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
  });

  it("deletes only the device row on a trusted success and keeps the identifier row as it was", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    await wrongEmail(t);
    await wrongEmail(t, device);
    await signInOk(t, device);

    expect(await t.deviceLockoutRows(user.id)).toHaveLength(0);
    const row = await t.lockoutRow(EMAIL_IDENTIFIER);
    expect(row?.failedAttempts).toBe(1);
    expect(row?.lockedUntil).toBeNull();
  });

  it("deletes the identifier row on an untrusted success", async () => {
    const t = await open({ policy });
    await t.signUp();
    await wrongEmail(t);
    await signInOk(t);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
  });

  it("trusts a username sign-in with the cookie obtained from an email sign-in of the same user", async () => {
    const t = await open({ policy });
    await t.signUp({ username: USERNAME });
    const device = await obtainDevice(t);
    await wrongTimes(3, () =>
      expectUnauthorized(
        () => t.auth.api.signInUsername({ body: { username: USERNAME, password: WRONG_PASSWORD } }),
        "INVALID_USERNAME_OR_PASSWORD",
      ),
    );
    await expectTooManyRequests(
      () => t.auth.api.signInUsername({ body: { username: USERNAME, password: DEFAULT_PASSWORD } }),
      "SIGN_IN_LOCKED",
    );
    const trusted = await t.auth.api.signInUsername({
      body: { username: USERNAME, password: DEFAULT_PASSWORD },
      headers: device,
    });
    expect(trusted.user.email).toBe(DEFAULT_EMAIL);
  });

  it("counts a valid cookie used with an identifier that has no user in that identifier's row", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    const ghost = "ghost@example.com";
    await wrongEmail(t, device, ghost);

    expect((await t.lockoutRow(`email:${ghost}`))?.failedAttempts).toBe(1);
    expect(await t.deviceLockoutRows(user.id)).toHaveLength(0);
  });
});

describe("cookies that are not trusted", () => {
  it("counts a cookie with a tampered signature in the identifier row", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    await wrongEmail(t, tamperSignature(device));

    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(1);
    expect(await t.deviceLockoutRows(user.id)).toHaveLength(0);
  });

  it("counts a correctly signed cookie with the wrong binding in the identifier row", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    await wrongEmail(t, forgeWrongBinding(device));

    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(1);
    expect(await t.deviceLockoutRows(user.id)).toHaveLength(0);
  });

  it("does not let a forged cookie get past a locked identifier", async () => {
    const t = await open({ policy });
    await t.signUp();
    const device = await obtainDevice(t);
    await wrongTimes(3, () => wrongEmail(t));
    await lockedEmail(t, forgeWrongBinding(device), DEFAULT_PASSWORD);
    await lockedEmail(t, tamperSignature(device), DEFAULT_PASSWORD);
  });

  it("counts another user's cookie presented with this user's email in the identifier row", async () => {
    const t = await open({ policy });
    const alice = await t.signUp();
    const bob = await t.signUp({ email: BOB_EMAIL, name: "Bob Jones" });
    const bobDevice = await obtainDevice(t, BOB_EMAIL);
    await wrongEmail(t, bobDevice);

    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(1);
    expect(await t.deviceLockoutRows(alice.id)).toHaveLength(0);
    expect(await t.deviceLockoutRows(bob.id)).toHaveLength(0);

    await wrongTimes(2, () => wrongEmail(t, bobDevice));
    await lockedEmail(t, bobDevice, DEFAULT_PASSWORD);
  });

  it("stops trusting a cookie after the user's password was reset", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    const token = await t.requestResetToken(DEFAULT_EMAIL);
    await t.auth.api.resetPassword({ body: { newPassword: P1, token } });
    await wrongEmail(t, device);

    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(1);
    expect(await t.deviceLockoutRows(user.id)).toHaveLength(0);
  });

  it("stops trusting a cookie once its expiry has passed", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-06-01T00:00:00.000Z"));
    const t = await open({ policy: { lockout: { maxAttempts: 3, deviceCookie: { maxAge: 1 } } } });
    const user = await t.signUp();
    const device = await obtainDevice(t);

    await wrongEmail(t, device);
    expect((await t.deviceLockoutRows(user.id))[0]?.failedAttempts).toBe(1);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();

    vi.setSystemTime(new Date("2026-06-01T00:00:05.000Z"));
    await wrongEmail(t, device);
    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(1);
    expect((await t.deviceLockoutRows(user.id))[0]?.failedAttempts).toBe(1);
  });
});

const collectLoggedStrings = (value: unknown, depth = 0): string[] => {
  if (value === null || value === undefined || depth > 5) {
    return [];
  }
  if (typeof value !== "object") {
    return [String(value)];
  }
  const collected = [String(value)];
  try {
    collected.push(JSON.stringify(value));
  } catch {
    collected.push("");
  }
  if (value instanceof Error) {
    collected.push(value.name, value.message, value.stack ?? "");
    collected.push(...collectLoggedStrings(value.cause, depth + 1));
  }
  for (const nested of Object.values(value)) {
    collected.push(...collectLoggedStrings(nested, depth + 1));
  }
  return collected;
};

describe("log hygiene when the user lookup fails", () => {
  const LOOKUP_MESSAGE = "password-policy: failed to look up the user for the device cookie";

  it("logs the constant lookup message and no identifier, and counts the attempt in the identifier row", async () => {
    const t = await open({ policy });
    await t.signUp();
    const device = await obtainDevice(t);
    const original = t.adapter.findOne.bind(t.adapter);
    let failed = false;
    vi.spyOn(t.adapter, "findOne").mockImplementation((async (input: { model: string }) => {
      if (input.model === "user" && !failed) {
        failed = true;
        throw new Error(`Failed query: select from user where email = $1 params: ${DEFAULT_EMAIL}`);
      }
      return original(input as never);
    }) as never);
    const logged = vi.spyOn(t.context.logger, "error").mockImplementation(() => undefined);

    await wrongEmail(t, device);

    expect(failed).toBe(true);
    const lookupCalls = logged.mock.calls.filter((call) => String(call[0]).includes(LOOKUP_MESSAGE));
    expect(lookupCalls.length).toBeGreaterThan(0);
    expect(lookupCalls.every((call) => call[0] === LOOKUP_MESSAGE)).toBe(true);
    const serialized = logged.mock.calls.flatMap((args) => args.flatMap((arg) => collectLoggedStrings(arg)));
    expect(serialized.join("\n")).not.toContain(DEFAULT_EMAIL);
    expect((await t.lockoutRow(EMAIL_IDENTIFIER))?.failedAttempts).toBe(1);
  });
});

describe("clearing device rows", () => {
  const seedTwoKindsOfRows = async (t: TestAuth) => {
    const user = await t.signUp();
    const device = await obtainDevice(t);
    await wrongEmail(t);
    await wrongEmail(t, device);
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).not.toBeNull();
    expect(await t.deviceLockoutRows(user.id)).toHaveLength(1);
    return { user, device };
  };

  it("removes identifier and device rows through unlockSignIn and leaves other users' rows alone", async () => {
    const t = await open({ policy });
    const { user } = await seedTwoKindsOfRows(t);
    const bob = await t.signUp({ email: BOB_EMAIL, name: "Bob Jones" });
    const bobDevice = await obtainDevice(t, BOB_EMAIL);
    await wrongEmail(t, undefined, BOB_EMAIL);
    await wrongEmail(t, bobDevice, BOB_EMAIL);

    const result = await t.auth.api.unlockSignIn({ body: { userId: user.id } });
    expect(result).toEqual({ status: true });

    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();
    expect(await t.deviceLockoutRows(user.id)).toHaveLength(0);
    expect(await t.lockoutRow(`email:${BOB_EMAIL}`)).not.toBeNull();
    expect(await t.deviceLockoutRows(bob.id)).toHaveLength(1);
  });

  it("removes identifier and device rows when the password is reset", async () => {
    const t = await open({ policy });
    await seedTwoKindsOfRows(t);
    const token = await t.requestResetToken(DEFAULT_EMAIL);
    await t.auth.api.resetPassword({ body: { newPassword: P1, token } });
    expect(await t.lockoutRows()).toHaveLength(0);
  });

  it("removes identifier and device rows when the user is deleted", async () => {
    const t = await open({ policy, enableDeleteUser: true });
    const { user } = await seedTwoKindsOfRows(t);
    await t.auth.api.deleteUser({ body: { password: DEFAULT_PASSWORD }, headers: user.headers });
    expect(await t.lockoutRows()).toHaveLength(0);
  });
});

describe("sign-in status with device rows", () => {
  it("reports a lock and the failure count when only a device row is locked, and clears both after unlocking", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    await wrongTimes(3, () => wrongEmail(t, device));
    expect(await t.lockoutRow(EMAIL_IDENTIFIER)).toBeNull();

    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.lockedUntil).toBeInstanceOf(Date);
    expect(status.lockedUntil!.getTime()).toBeGreaterThan(Date.now());
    expect(status.failedSignInAttempts).toBe(3);

    await t.auth.api.unlockSignIn({ body: { userId: user.id } });
    const cleared = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(cleared.lockedUntil).toBeNull();
    expect(cleared.failedSignInAttempts).toBe(0);
  });

  it("reports the highest failure count across identifier and device rows", async () => {
    const t = await open({ policy: { lockout: { maxAttempts: 5 } } });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    await wrongTimes(2, () => wrongEmail(t));
    await wrongTimes(4, () => wrongEmail(t, device));

    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.failedSignInAttempts).toBe(4);
    expect(status.lockedUntil).toBeNull();
  });

  it("ignores a device row whose lock has expired", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    const device = await obtainDevice(t);
    await wrongTimes(3, () => wrongEmail(t, device));
    const [deviceRow] = await t.deviceLockoutRows(user.id);
    await t.adapter.update({
      model: "signInLockout",
      where: [{ field: "id", value: deviceRow!.id }],
      update: { lockedUntil: new Date(Date.now() - DAY_SECONDS * 1000) },
    });

    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.lockedUntil).toBeNull();
    expect(status.failedSignInAttempts).toBe(0);
  });
});
