import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { sql } from "drizzle-orm";
import { createRequire } from "node:module";
import { expect } from "vitest";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { admin, username, phoneNumber, emailOTP, twoFactor, testUtils, bearer } from "better-auth/plugins";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { passwordPolicy } from "../../src/index.ts";
import type { PasswordPolicyOptions } from "../../src/index.ts";
import * as schema from "../fixtures/auth-schema.ts";

interface DrizzleKitApi {
  generateDrizzleJson(schemaModule: Record<string, unknown>): unknown;
  generateMigration(previous: unknown, next: unknown): Promise<string[]>;
}

const nodeRequire = createRequire(import.meta.url);
const drizzleKit = nodeRequire("drizzle-kit/api") as DrizzleKitApi;

let migrationStatementsPromise: Promise<string[]> | undefined;

const loadMigrationStatements = (): Promise<string[]> => {
  migrationStatementsPromise ??= drizzleKit.generateMigration(
    drizzleKit.generateDrizzleJson({}),
    drizzleKit.generateDrizzleJson(schema),
  );
  return migrationStatementsPromise;
};

export const DEFAULT_EMAIL = "alice@example.com";
export const DEFAULT_NAME = "Alice Smith";
export const DEFAULT_PASSWORD = "Correct1Horse";
export const WRONG_PASSWORD = "Wrong-password-1";
export const GOOD_PASSWORDS = [
  "Correct1Horse",
  "Battery2Staple",
  "Zebra3Pencil",
  "Lantern4Orbit",
  "Quartz5Meadow",
  "Violet6Harbor",
] as const;
export const WEAK_NO_UPPERCASE = "weakpass1";
export const WEAK_NO_LOWERCASE = "WEAKPASS1";
export const WEAK_NO_DIGIT = "Weakpassx";

export interface TestAuthOptions {
  policy?: PasswordPolicyOptions;
  realHasher?: boolean;
  policyBeforeTwoFactor?: boolean;
  requireEmailVerification?: boolean;
  cookieCache?: boolean;
  enableDeleteUser?: boolean;
  bearerPosition?: "before-policy" | "after-policy";
  withoutPolicy?: boolean;
  sessionUpdateAge?: number;
  rewriteSignInErrors?: boolean;
  usernamePosition?: "before-policy" | "after-policy";
  userBeforeHook?: ReturnType<typeof createAuthMiddleware>;
}

export interface SignedUpUser {
  id: string;
  email: string;
  password: string;
  headers: Headers;
}

export interface SignUpInput {
  email?: string;
  name?: string;
  password?: string;
  username?: string;
}

export interface UserRow {
  id: string;
  email: string;
  name: string;
  role: string | null;
  banned: boolean | null;
  username: string | null;
  phoneNumber: string | null;
  twoFactorEnabled: boolean | null;
  mustChangePassword: boolean | null;
  passwordChangedAt: Date | null;
}

export interface AccountRow {
  id: string;
  userId: string;
  providerId: string;
  accountId: string;
  password: string | null;
}

export interface HistoryRow {
  id: string;
  userId: string;
  passwordHash: string;
  createdAt: Date;
}

export interface LockoutRow {
  id: string;
  identifier: string;
  failedAttempts: number;
  lockedUntil: Date | null;
  lastAttemptAt: Date;
}

interface TestUtilsContext {
  test: {
    createUser(overrides: { email: string; name: string }): unknown;
    saveUser(user: unknown): Promise<{ id: string }>;
    login(input: { userId: string }): Promise<{ headers: Headers }>;
  };
}

export interface ApiErrorShape {
  status: string;
  statusCode: number;
  body?: { code?: string; message?: string };
}

export const cookieHeadersFrom = (responseHeaders: Headers): Headers => {
  const cookie = responseHeaders
    .getSetCookie()
    .map((entry) => entry.split(";")[0])
    .join("; ");
  return new Headers({ cookie });
};

export const latestCookieHeadersFrom = (responseHeaders: Headers): Headers => {
  const latest = new Map<string, string>();
  for (const entry of responseHeaders.getSetCookie()) {
    const pair = entry.split(";")[0] ?? "";
    const separator = pair.indexOf("=");
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    if (value === "") latest.delete(name);
    else latest.set(name, value);
  }
  const cookie = [...latest].map(([name, value]) => `${name}=${value}`).join("; ");
  return new Headers({ cookie });
};

export const pause = (milliseconds = 3): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

export const captureApiError = async (run: () => Promise<unknown>): Promise<ApiErrorShape> => {
  try {
    await run();
  } catch (error) {
    return error as ApiErrorShape;
  }
  throw new Error("expected the call to reject but it resolved");
};

export const expectApiError = async (
  run: () => Promise<unknown>,
  expected: { status: string; statusCode: number; code: string },
): Promise<ApiErrorShape> => {
  const error = await captureApiError(run);
  expect(error.status).toBe(expected.status);
  expect(error.statusCode).toBe(expected.statusCode);
  expect(error.body?.code).toBe(expected.code);
  return error;
};

export const expectBadRequest = (run: () => Promise<unknown>, code: string) =>
  expectApiError(run, { status: "BAD_REQUEST", statusCode: 400, code });

export const expectUnauthorized = (run: () => Promise<unknown>, code: string) =>
  expectApiError(run, { status: "UNAUTHORIZED", statusCode: 401, code });

export const expectForbidden = (run: () => Promise<unknown>, code: string) =>
  expectApiError(run, { status: "FORBIDDEN", statusCode: 403, code });

export const expectNotFound = (run: () => Promise<unknown>, code: string) =>
  expectApiError(run, { status: "NOT_FOUND", statusCode: 404, code });

export const expectTooManyRequests = (run: () => Promise<unknown>, code: string) =>
  expectApiError(run, { status: "TOO_MANY_REQUESTS", statusCode: 429, code });

export const createTestAuth = async (options: TestAuthOptions = {}) => {
  const client = new PGlite();
  const db = drizzle({ client, schema });
  for (const statement of await loadMigrationStatements()) {
    await db.execute(sql.raw(statement));
  }

  let verifyCallCount = 0;
  const resetTokens: { email: string; token: string }[] = [];
  const phoneOtps: { phoneNumber: string; code: string }[] = [];
  const emailOtps: { email: string; otp: string; type: string }[] = [];

  const fastPassword = {
    hash: async (password: string) => `fast:${password}`,
    verify: async ({ hash, password }: { hash: string; password: string }) => {
      verifyCallCount += 1;
      return hash === `fast:${password}`;
    },
  };

  const policy = passwordPolicy(options.policy);
  const phonePlugin = phoneNumber({
    sendOTP: async ({ phoneNumber: target, code }) => {
      phoneOtps.push({ phoneNumber: target, code });
    },
    sendPasswordResetOTP: async ({ phoneNumber: target, code }) => {
      phoneOtps.push({ phoneNumber: target, code });
    },
  });
  const emailOtpPlugin = emailOTP({
    sendVerificationOTP: async ({ email, otp, type }) => {
      emailOtps.push({ email, otp, type });
    },
  });

  const policyPlugins = options.withoutPolicy ? [] : [policy];
  const usernameAfterPolicy = options.usernamePosition === "after-policy";
  const usernameBeforePolicy = usernameAfterPolicy ? [] : [username()];
  const usernameBehindPolicy = usernameAfterPolicy ? [username()] : [];
  const basePlugins = options.policyBeforeTwoFactor
    ? [
        admin(),
        ...usernameBeforePolicy,
        phonePlugin,
        emailOtpPlugin,
        ...policyPlugins,
        ...usernameBehindPolicy,
        twoFactor(),
        testUtils(),
      ]
    : [
        admin(),
        ...usernameBeforePolicy,
        phonePlugin,
        emailOtpPlugin,
        twoFactor(),
        ...policyPlugins,
        ...usernameBehindPolicy,
        testUtils(),
      ];
  const plugins =
    options.bearerPosition === "before-policy"
      ? [bearer(), ...basePlugins]
      : options.bearerPosition === "after-policy"
        ? [...basePlugins, bearer()]
        : basePlugins;

  const rewriteSignInErrors = createAuthMiddleware(async (hookContext) => {
    const returned = hookContext.context.returned;
    if (
      hookContext.path?.startsWith("/sign-in") &&
      returned instanceof APIError &&
      returned.statusCode !== 429
    ) {
      throw new APIError("UNAUTHORIZED", {
        code: "INVALID_CREDENTIALS",
        message: "Invalid credentials",
      });
    }
  });

  const auth = betterAuth({
    baseURL: "http://localhost:3000",
    secret: "x".repeat(40),
    database: drizzleAdapter(db, { provider: "pg", schema }),
    emailAndPassword: {
      enabled: true,
      requireEmailVerification: options.requireEmailVerification ?? false,
      sendResetPassword: async ({ user, token }) => {
        resetTokens.push({ email: user.email, token });
      },
      ...(options.realHasher ? {} : { password: fastPassword }),
    },
    emailVerification: { sendVerificationEmail: async () => {} },
    user: options.enableDeleteUser ? { deleteUser: { enabled: true } } : {},
    session: {
      ...(options.cookieCache ? { cookieCache: { enabled: true, maxAge: 300 } } : {}),
      ...(options.sessionUpdateAge === undefined ? {} : { updateAge: options.sessionUpdateAge }),
    },
    ...(options.rewriteSignInErrors || options.userBeforeHook
      ? {
          hooks: {
            ...(options.rewriteSignInErrors ? { after: rewriteSignInErrors } : {}),
            ...(options.userBeforeHook ? { before: options.userBeforeHook } : {}),
          },
        }
      : {}),
    plugins,
  });

  const context = await auth.$context;
  const adapter = context.adapter;
  const testUtilsContext = context as unknown as TestUtilsContext;

  const signUp = async (input: SignUpInput = {}): Promise<SignedUpUser> => {
    const email = input.email ?? DEFAULT_EMAIL;
    const password = input.password ?? DEFAULT_PASSWORD;
    const result = await auth.api.signUpEmail({
      body: {
        email,
        password,
        name: input.name ?? DEFAULT_NAME,
        ...(input.username ? { username: input.username } : {}),
      },
      returnHeaders: true,
    });
    return {
      id: result.response.user.id,
      email,
      password,
      headers: cookieHeadersFrom(result.headers),
    };
  };

  const signInHeaders = async (email: string, password: string): Promise<Headers> => {
    const result = await auth.api.signInEmail({ body: { email, password }, returnHeaders: true });
    return cookieHeadersFrom(result.headers);
  };

  const signInBearerHeaders = async (email: string, password: string): Promise<Headers> => {
    const result = await auth.api.signInEmail({ body: { email, password }, returnHeaders: true });
    const token = result.headers.get("set-auth-token");
    if (!token) throw new Error("bearer plugin did not return a set-auth-token header");
    return new Headers({ authorization: `Bearer ${token}` });
  };

  const getUser = async (userId: string): Promise<UserRow> => {
    const row = await adapter.findOne<UserRow>({
      model: "user",
      where: [{ field: "id", value: userId }],
    });
    if (!row) throw new Error(`user ${userId} not found`);
    return row;
  };

  const getCredentialAccount = async (userId: string): Promise<AccountRow> => {
    const row = await adapter.findOne<AccountRow>({
      model: "account",
      where: [
        { field: "userId", value: userId },
        { field: "providerId", value: "credential" },
      ],
    });
    if (!row) throw new Error(`credential account for ${userId} not found`);
    return row;
  };

  const historyRows = (userId: string): Promise<HistoryRow[]> =>
    adapter.findMany<HistoryRow>({
      model: "passwordHistory",
      where: [{ field: "userId", value: userId }],
      sortBy: { field: "createdAt", direction: "desc" },
    });

  const allHistoryRows = (): Promise<HistoryRow[]> =>
    adapter.findMany<HistoryRow>({ model: "passwordHistory" });

  const lockoutRows = (): Promise<LockoutRow[]> =>
    adapter.findMany<LockoutRow>({ model: "signInLockout" });

  const lockoutRow = (identifier: string): Promise<LockoutRow | null> =>
    adapter.findOne<LockoutRow>({
      model: "signInLockout",
      where: [{ field: "identifier", value: identifier }],
    });

  const updateUserRow = async (userId: string, update: Record<string, unknown>) => {
    await adapter.update({
      model: "user",
      where: [{ field: "id", value: userId }],
      update,
    });
  };

  const expireLock = async (identifier: string) => {
    await adapter.update({
      model: "signInLockout",
      where: [{ field: "identifier", value: identifier }],
      update: { lockedUntil: new Date(Date.now() - 60_000) },
    });
  };

  const backdatePassword = async (userId: string, secondsAgo: number) => {
    await updateUserRow(userId, { passwordChangedAt: new Date(Date.now() - secondsAgo * 1000) });
  };

  const markPhoneNumber = async (userId: string, phone: string) => {
    await updateUserRow(userId, { phoneNumber: phone, phoneNumberVerified: true });
  };

  const enableTwoFactor = async (userId: string) => {
    await context.internalAdapter.updateUser(userId, { twoFactorEnabled: true });
  };

  const createAdmin = async (): Promise<SignedUpUser> => {
    const created = await signUp({
      email: "root@example.org",
      name: "Root Operator",
      password: "Admin9Password",
    });
    await context.internalAdapter.updateUser(created.id, { role: "admin" });
    return { ...created, headers: await signInHeaders(created.email, created.password) };
  };

  const createSessionOnlyUser = async (email: string, name: string) => {
    const saved = await testUtilsContext.test.saveUser(
      testUtilsContext.test.createUser({ email, name }),
    );
    const login = await testUtilsContext.test.login({ userId: saved.id });
    return { id: saved.id, headers: login.headers };
  };

  const requestResetToken = async (email: string): Promise<string> => {
    await auth.api.requestPasswordReset({
      body: { email, redirectTo: "http://localhost:3000/reset" },
    });
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const found = [...resetTokens].reverse().find((entry) => entry.email === email);
      if (found) return found.token;
      await pause(10);
    }
    throw new Error(`no reset token captured for ${email}`);
  };

  const lastPhoneCode = async (target: string): Promise<string> => {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const found = [...phoneOtps].reverse().find((entry) => entry.phoneNumber === target);
      if (found) return found.code;
      await pause(10);
    }
    throw new Error(`no phone code captured for ${target}`);
  };

  const lastEmailOtp = async (email: string, type: string): Promise<string> => {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const found = [...emailOtps]
        .reverse()
        .find((entry) => entry.email === email && entry.type === type);
      if (found) return found.otp;
      await pause(10);
    }
    throw new Error(`no email otp captured for ${email}`);
  };

  const close = async () => {
    await client.close();
  };

  return {
    auth,
    context,
    adapter,
    db,
    signUp,
    signInHeaders,
    signInBearerHeaders,
    getUser,
    getCredentialAccount,
    historyRows,
    allHistoryRows,
    lockoutRows,
    lockoutRow,
    updateUserRow,
    expireLock,
    backdatePassword,
    markPhoneNumber,
    enableTwoFactor,
    createAdmin,
    createSessionOnlyUser,
    requestResetToken,
    lastPhoneCode,
    lastEmailOtp,
    verifyCalls: () => verifyCallCount,
    close,
  };
};

export type TestAuth = Awaited<ReturnType<typeof createTestAuth>>;

export const createAuthRegistry = () => {
  const opened: TestAuth[] = [];
  return {
    open: async (options?: TestAuthOptions): Promise<TestAuth> => {
      const instance = await createTestAuth(options);
      opened.push(instance);
      return instance;
    },
    closeAll: async () => {
      await Promise.all(opened.splice(0).map((instance) => instance.close()));
    },
  };
};
