import type { AuthContext } from "@better-auth/core";
import { tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import { APIError, createAuthMiddleware } from "better-auth/api";
import type { DBAdapter } from "better-auth/types";
import { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
import { issueDeviceCookie, passwordEpochOf, readDeviceCookie } from "./device-cookie.ts";
import type { SignInHookContext } from "./device-cookie.ts";
import {
  LOCKOUT_MODEL,
  deviceCookieBinding,
  lockoutDeviceKey,
  lockoutDeviceKeyPrefix,
  lockoutIdentifierKey,
} from "./lockout-keys.ts";
import { createLockoutRetentionPurge } from "./lockout-retention.ts";
import { summarizeError } from "./log-error.ts";
import type { ResolvedLockout, ResolvedLockoutPlatformSettings } from "./options.ts";
import type { PasswordVerifier } from "./password-normalization.ts";
import { readNonEmptyString, toRecord } from "./record.ts";
import { tenantPolicyUnavailable } from "./tenant-resolver.ts";
import type { EffectivePolicyResolver, PolicySubject } from "./tenant-resolver.ts";

export const SIGN_IN_PATHS: readonly string[] = ["/sign-in/email", "/sign-in/username", "/sign-in/phone-number"];

interface LockoutRow {
  id: string;
  identifier: string;
  failedAttempts: number;
  lockedUntil: Date | null;
  lastAttemptAt: Date;
}

export interface LockoutState {
  lockedUntil: Date | null;
  failedAttempts: number;
}

export interface SignInUserLookup {
  field: "email" | "username" | "phoneNumber";
  value: string;
}

export const usernameLookupValue = (username: string, usernameOptions: unknown): string => {
  const options = toRecord(usernameOptions);
  const configured = options.usernameNormalization;
  const normalize = (value: string): string => {
    if (configured === false) {
      return value;
    }
    if (typeof configured === "function") {
      const normalized: unknown = configured(value);
      return typeof normalized === "string" ? normalized : value;
    }
    return value.toLowerCase();
  };
  return toRecord(options.validationOrder).username === "pre-normalization"
    ? normalize(normalize(username))
    : normalize(username);
};

export const signInUserLookup = (
  path: string | undefined,
  body: unknown,
  usernameOptions?: unknown,
): SignInUserLookup | null => {
  const fields = toRecord(body);
  switch (path) {
    case "/sign-in/email": {
      const email = readNonEmptyString(fields, "email");
      return email === null ? null : { field: "email", value: email.toLowerCase() };
    }
    case "/sign-in/username": {
      const username = readNonEmptyString(fields, "username");
      if (username === null) {
        return null;
      }
      const value = usernameLookupValue(username, usernameOptions);
      return value === "" ? null : { field: "username", value };
    }
    case "/sign-in/phone-number": {
      const phoneNumber = readNonEmptyString(fields, "phoneNumber");
      return phoneNumber === null ? null : { field: "phoneNumber", value: phoneNumber };
    }
    default:
      return null;
  }
};

export const signInLockoutIdentifier = (
  path: string | undefined,
  body: unknown,
  usernameOptions?: unknown,
): string | null => {
  const lookup = signInUserLookup(path, body, usernameOptions);
  if (lookup === null) {
    return null;
  }
  switch (lookup.field) {
    case "email":
      return `email:${lookup.value}`;
    case "username":
      return `username:${lookup.value.toLowerCase()}`;
    case "phoneNumber":
      return `phone:${lookup.value}`;
  }
};

export const lockoutIdentifiersForUser = (user: {
  email: string;
  username?: string | null;
  phoneNumber?: string | null;
}): string[] => {
  const identifiers = [`email:${user.email.toLowerCase()}`];
  if (user.username) {
    identifiers.push(`username:${user.username.toLowerCase()}`);
  }
  if (user.phoneNumber) {
    identifiers.push(`phone:${user.phoneNumber}`);
  }
  return identifiers;
};

export const lockoutIdentifiersOfRecord = (user: unknown): string[] => {
  const fields = toRecord(user);
  const email = readNonEmptyString(fields, "email");
  if (email === null) {
    return [];
  }
  return lockoutIdentifiersForUser({
    email,
    username: readNonEmptyString(fields, "username"),
    phoneNumber: readNonEmptyString(fields, "phoneNumber"),
  });
};

type LockoutWhere = { field: string; operator: "in" | "starts_with"; value: string | string[] };

const userLockoutWheres = async (secret: string, user: unknown): Promise<LockoutWhere[][]> => {
  const wheres: LockoutWhere[][] = [];
  const identifiers = lockoutIdentifiersOfRecord(user);
  if (identifiers.length > 0) {
    const keys = await Promise.all(identifiers.map((identifier) => lockoutIdentifierKey(secret, identifier)));
    wheres.push([{ field: "identifier", operator: "in", value: keys }]);
  }
  const userId = readNonEmptyString(toRecord(user), "id");
  if (userId !== null) {
    wheres.push([{ field: "identifier", operator: "starts_with", value: await lockoutDeviceKeyPrefix(secret, userId) }]);
  }
  return wheres;
};

export const deleteUserLockoutRows = async (adapter: DBAdapter, secret: string, user: unknown): Promise<void> => {
  for (const where of await userLockoutWheres(secret, user)) {
    await adapter.deleteMany({ model: LOCKOUT_MODEL, where });
  }
};

const summarizeLockoutRows = (rows: LockoutRow[], now: Date): LockoutState => {
  let lockedUntil: Date | null = null;
  let failedAttempts = 0;
  for (const row of rows) {
    const rowLockedUntil = row.lockedUntil === null ? null : new Date(row.lockedUntil);
    const lockActive = rowLockedUntil !== null && rowLockedUntil.getTime() > now.getTime();
    const lockExpired = rowLockedUntil !== null && !lockActive;
    if (lockActive && (lockedUntil === null || rowLockedUntil.getTime() > lockedUntil.getTime())) {
      lockedUntil = rowLockedUntil;
    }
    if (!lockExpired) {
      failedAttempts = Math.max(failedAttempts, row.failedAttempts);
    }
  }
  return { lockedUntil, failedAttempts };
};

export const readUserLockoutState = async (
  adapter: DBAdapter,
  secret: string,
  user: unknown,
  now: Date,
): Promise<LockoutState> => {
  const rows: LockoutRow[] = [];
  for (const where of await userLockoutWheres(secret, user)) {
    rows.push(...(await adapter.findMany<LockoutRow>({ model: LOCKOUT_MODEL, where })));
  }
  return summarizeLockoutRows(rows, now);
};

const identifierWhere = (identifier: string) => ({ field: "identifier", value: identifier });

const lockUntil = (now: Date, lockout: ResolvedLockout): Date => new Date(now.getTime() + lockout.durationSeconds * 1000);

const resetVerifiedCounter = async (
  authContext: Pick<AuthContext, "adapter" | "logger">,
  key: string,
): Promise<void> => {
  try {
    await authContext.adapter.deleteMany({ model: LOCKOUT_MODEL, where: [identifierWhere(key)] });
  } catch (error) {
    authContext.logger.error("password-policy: failed to reset the sign-in lockout counter", summarizeError(error));
  }
};

export const createSignInLockoutHooks = (
  lockout: ResolvedLockout,
  platform: ResolvedLockoutPlatformSettings,
  effectivePolicy: EffectivePolicyResolver,
) => {
  const requestsWithCorrectPassword = new WeakSet<object>();
  const effectiveLockoutByRequest = new WeakMap<object, Promise<ResolvedLockout>>();
  const signInUserByRequest = new WeakMap<object, Promise<Record<string, unknown> | null>>();
  const counterKeyByRequest = new WeakMap<object, string>();
  const purgeStaleRows =
    platform.retentionSeconds === null ? null : createLockoutRetentionPurge(platform.retentionSeconds);

  const trackVerifiedPassword =
    (originalVerify: PasswordVerifier): PasswordVerifier =>
    async (input) => {
      const verified = await originalVerify(input);
      if (!verified) {
        return false;
      }
      const endpointContext = tryGetCurrentAuthEndpointContext();
      if (
        endpointContext === undefined ||
        endpointContext.path === undefined ||
        !SIGN_IN_PATHS.includes(endpointContext.path)
      ) {
        return true;
      }
      const requestContext = endpointContext.context;
      requestsWithCorrectPassword.add(requestContext);
      const key = counterKeyByRequest.get(requestContext);
      if (key !== undefined) {
        await resetVerifiedCounter(requestContext, key);
      }
      return true;
    };

  const usernameOptionsOf = (ctx: SignInHookContext): unknown => ctx.context.getPlugin("username")?.options;

  const userLookupOf = (ctx: SignInHookContext): SignInUserLookup | null =>
    signInUserLookup(ctx.path, ctx.body, usernameOptionsOf(ctx));

  const findSignInUser = (ctx: SignInHookContext): Promise<Record<string, unknown> | null> => {
    const cached = signInUserByRequest.get(ctx.context);
    if (cached !== undefined) {
      return cached;
    }
    const lookup = userLookupOf(ctx);
    const pending =
      lookup === null
        ? Promise.resolve(null)
        : ctx.context.adapter
            .findOne<Record<string, unknown>>({
              model: "user",
              where: [{ field: lookup.field, value: lookup.value }],
            })
            .then((found) => (found !== null && typeof found.id === "string" ? toRecord(found) : null));
    signInUserByRequest.set(ctx.context, pending);
    return pending;
  };

  const lookupEffectiveLockout = async (ctx: SignInHookContext): Promise<ResolvedLockout> => {
    const lookup = userLookupOf(ctx);
    let subject: PolicySubject = { kind: "anonymous", email: null };
    if (lookup !== null) {
      let found: Record<string, unknown> | null;
      try {
        found = await findSignInUser(ctx);
      } catch (error) {
        ctx.context.logger.error("password-policy: failed to look up the user for tenantPolicy", summarizeError(error));
        throw tenantPolicyUnavailable();
      }
      subject =
        found !== null
          ? { kind: "user", record: found }
          : { kind: "anonymous", email: lookup.field === "email" ? lookup.value : null };
    }
    const resolved = await effectivePolicy.resolve({ authContext: ctx.context, endpoint: ctx }, subject);
    if (resolved.lockout === null) {
      throw tenantPolicyUnavailable();
    }
    return resolved.lockout;
  };

  const effectiveLockout = (ctx: SignInHookContext): Promise<ResolvedLockout> => {
    if (!effectivePolicy.tenantAware) {
      return Promise.resolve(lockout);
    }
    const cached = effectiveLockoutByRequest.get(ctx.context);
    if (cached !== undefined) {
      return cached;
    }
    const pending = lookupEffectiveLockout(ctx);
    effectiveLockoutByRequest.set(ctx.context, pending);
    return pending;
  };

  const classifyAttempt = async (ctx: SignInHookContext, identifier: string): Promise<string> => {
    const secret = ctx.context.secret;
    if (platform.deviceCookieMaxAgeSeconds !== null) {
      const cookie = await readDeviceCookie(ctx);
      if (cookie !== null) {
        let user: Record<string, unknown> | null = null;
        try {
          user = await findSignInUser(ctx);
        } catch (error) {
          ctx.context.logger.error("password-policy: failed to look up the user for the device cookie", summarizeError(error));
        }
        const userId = user === null ? null : readNonEmptyString(user, "id");
        if (user !== null && userId !== null) {
          const binding = await deviceCookieBinding(
            secret,
            userId,
            cookie.deviceId,
            cookie.expiresAt,
            passwordEpochOf(user),
          );
          if (binding === cookie.binding) {
            return lockoutDeviceKey(secret, userId, cookie.deviceId);
          }
        }
      }
    }
    return lockoutIdentifierKey(secret, identifier);
  };

  const issueTrustedDevice = async (ctx: SignInHookContext, maxAgeSeconds: number): Promise<void> => {
    try {
      const user = await findSignInUser(ctx);
      if (user !== null) {
        await issueDeviceCookie(ctx, user, maxAgeSeconds);
      }
    } catch (error) {
      ctx.context.logger.error("password-policy: failed to issue the sign-in device cookie", summarizeError(error));
    }
  };

  const matcher = (context: { path?: string | undefined }): boolean =>
    typeof context.path === "string" && SIGN_IN_PATHS.includes(context.path);

  const before = {
    matcher,
    handler: createAuthMiddleware(async (ctx) => {
      if (purgeStaleRows !== null) {
        await purgeStaleRows(ctx.context);
      }
      const identifier = signInLockoutIdentifier(ctx.path, ctx.body, usernameOptionsOf(ctx));
      if (identifier === null) {
        return;
      }
      const key = await classifyAttempt(ctx, identifier);
      counterKeyByRequest.set(ctx.context, key);
      const adapter = ctx.context.adapter;
      const now = new Date();
      const lockedError = () => APIError.from("TOO_MANY_REQUESTS", PASSWORD_POLICY_ERROR_CODES.SIGN_IN_LOCKED);

      const existing = await adapter.findOne<LockoutRow>({
        model: LOCKOUT_MODEL,
        where: [identifierWhere(key)],
      });
      if (existing?.lockedUntil) {
        const previousLockedUntil = new Date(existing.lockedUntil);
        if (previousLockedUntil.getTime() > now.getTime()) {
          throw lockedError();
        }
        await adapter.incrementOne<LockoutRow>({
          model: LOCKOUT_MODEL,
          where: [identifierWhere(key), { field: "lockedUntil", value: previousLockedUntil }],
          increment: {},
          set: { failedAttempts: 0, lockedUntil: null },
        });
      }

      const effective = await effectiveLockout(ctx);

      const reserve = () =>
        adapter.incrementOne<LockoutRow>({
          model: LOCKOUT_MODEL,
          where: [identifierWhere(key)],
          increment: { failedAttempts: 1 },
          set: { lastAttemptAt: now },
        });

      let reserved = await reserve();
      if (reserved === null) {
        try {
          reserved = await adapter.create<Omit<LockoutRow, "id">, LockoutRow>({
            model: LOCKOUT_MODEL,
            data: { identifier: key, failedAttempts: 1, lockedUntil: null, lastAttemptAt: now },
          });
        } catch (error) {
          reserved = await reserve();
          if (reserved === null) {
            throw error;
          }
        }
      }

      if (reserved.failedAttempts > effective.maxAttempts) {
        await adapter.updateMany({
          model: LOCKOUT_MODEL,
          where: [identifierWhere(key)],
          update: { lockedUntil: lockUntil(now, effective) },
        });
        throw lockedError();
      }
    }),
  };

  const after = {
    matcher,
    handler: createAuthMiddleware(async (ctx) => {
      const key = counterKeyByRequest.get(ctx.context);
      if (key === undefined) {
        return;
      }

      if (requestsWithCorrectPassword.has(ctx.context)) {
        if (platform.deviceCookieMaxAgeSeconds !== null) {
          await issueTrustedDevice(ctx, platform.deviceCookieMaxAgeSeconds);
        }
        return;
      }

      const adapter = ctx.context.adapter;
      const effective = await effectiveLockout(ctx);

      const row = await adapter.findOne<LockoutRow>({
        model: LOCKOUT_MODEL,
        where: [identifierWhere(key)],
      });
      if (row !== null && row.failedAttempts >= effective.maxAttempts) {
        await adapter.updateMany({
          model: LOCKOUT_MODEL,
          where: [identifierWhere(key)],
          update: { lockedUntil: lockUntil(new Date(), effective) },
        });
      }
    }),
  };

  return { before, after, trackVerifiedPassword };
};
