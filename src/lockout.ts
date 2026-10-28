import { tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import { APIError, createAuthMiddleware } from "better-auth/api";
import type { DBAdapter } from "better-auth/types";
import { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
import type { ResolvedLockout } from "./options.ts";
import { readNonEmptyString, toRecord } from "./record.ts";

export const SIGN_IN_PATHS: readonly string[] = ["/sign-in/email", "/sign-in/username", "/sign-in/phone-number"];

const LOCKOUT_MODEL = "signInLockout";

export type UsernameNormalizer = (username: string) => string;

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

const isUsernameNormalizer = (value: unknown): value is UsernameNormalizer => typeof value === "function";

const normalizeUsername = (raw: string, normalizer: UsernameNormalizer | undefined): string => {
  if (normalizer === undefined) {
    return raw;
  }
  const normalized = normalizer(raw);
  return typeof normalized === "string" ? normalized : raw;
};

export const signInLockoutIdentifier = (
  path: string | undefined,
  body: unknown,
  normalizer?: UsernameNormalizer,
): string | null => {
  const fields = toRecord(body);
  switch (path) {
    case "/sign-in/email": {
      const email = readNonEmptyString(fields, "email");
      return email === null ? null : `email:${email.toLowerCase()}`;
    }
    case "/sign-in/username": {
      const username = readNonEmptyString(fields, "username");
      if (username === null) {
        return null;
      }
      const normalized = normalizeUsername(username, normalizer).toLowerCase();
      return normalized === "" ? null : `username:${normalized}`;
    }
    case "/sign-in/phone-number": {
      const phoneNumber = readNonEmptyString(fields, "phoneNumber");
      return phoneNumber === null ? null : `phone:${phoneNumber}`;
    }
    default:
      return null;
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

export const deleteLockoutRows = async (adapter: DBAdapter, identifiers: string[]): Promise<void> => {
  if (identifiers.length === 0) {
    return;
  }
  await adapter.deleteMany({
    model: LOCKOUT_MODEL,
    where: [{ field: "identifier", operator: "in", value: identifiers }],
  });
};

export const readLockoutState = async (
  adapter: DBAdapter,
  identifiers: string[],
  now: Date,
): Promise<LockoutState> => {
  if (identifiers.length === 0) {
    return { lockedUntil: null, failedAttempts: 0 };
  }
  const rows = await adapter.findMany<LockoutRow>({
    model: LOCKOUT_MODEL,
    where: [{ field: "identifier", operator: "in", value: identifiers }],
  });
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

const identifierWhere = (identifier: string) => ({ field: "identifier", value: identifier });

const lockUntil = (now: Date, lockout: ResolvedLockout): Date => new Date(now.getTime() + lockout.durationSeconds * 1000);

type PasswordVerifier = (input: { hash: string; password: string }) => Promise<boolean>;

export const createSignInLockoutHooks = (lockout: ResolvedLockout) => {
  const requestsWithCorrectPassword = new WeakSet<object>();

  const trackVerifiedPassword =
    (originalVerify: PasswordVerifier): PasswordVerifier =>
    async (input) => {
      const verified = await originalVerify(input);
      if (verified) {
        const endpointContext = tryGetCurrentAuthEndpointContext();
        if (endpointContext !== undefined && endpointContext.path !== undefined && SIGN_IN_PATHS.includes(endpointContext.path)) {
          requestsWithCorrectPassword.add(endpointContext.context);
        }
      }
      return verified;
    };

  const resolveIdentifier = (
    path: string | undefined,
    body: unknown,
    plugin: { options?: unknown } | null,
  ): string | null => {
    const normalization = toRecord(plugin?.options).usernameNormalization;
    return signInLockoutIdentifier(path, body, isUsernameNormalizer(normalization) ? normalization : undefined);
  };

  const matcher = (context: { path?: string | undefined }): boolean =>
    typeof context.path === "string" && SIGN_IN_PATHS.includes(context.path);

  const before = {
    matcher,
    handler: createAuthMiddleware(async (ctx) => {
      const identifier = resolveIdentifier(ctx.path, ctx.body, ctx.context.getPlugin("username"));
      if (identifier === null) {
        return;
      }
      const adapter = ctx.context.adapter;
      const now = new Date();
      const lockedError = () => APIError.from("TOO_MANY_REQUESTS", PASSWORD_POLICY_ERROR_CODES.SIGN_IN_LOCKED);

      const existing = await adapter.findOne<LockoutRow>({
        model: LOCKOUT_MODEL,
        where: [identifierWhere(identifier)],
      });
      if (existing?.lockedUntil) {
        const previousLockedUntil = new Date(existing.lockedUntil);
        if (previousLockedUntil.getTime() > now.getTime()) {
          throw lockedError();
        }
        await adapter.incrementOne<LockoutRow>({
          model: LOCKOUT_MODEL,
          where: [identifierWhere(identifier), { field: "lockedUntil", value: previousLockedUntil }],
          increment: {},
          set: { failedAttempts: 0, lockedUntil: null },
        });
      }

      const reserve = () =>
        adapter.incrementOne<LockoutRow>({
          model: LOCKOUT_MODEL,
          where: [identifierWhere(identifier)],
          increment: { failedAttempts: 1 },
          set: { lastAttemptAt: now },
        });

      let reserved = await reserve();
      if (reserved === null) {
        try {
          reserved = await adapter.create<Omit<LockoutRow, "id">, LockoutRow>({
            model: LOCKOUT_MODEL,
            data: { identifier, failedAttempts: 1, lockedUntil: null, lastAttemptAt: now },
          });
        } catch (error) {
          reserved = await reserve();
          if (reserved === null) {
            throw error;
          }
        }
      }

      if (reserved.failedAttempts > lockout.maxAttempts) {
        await adapter.updateMany({
          model: LOCKOUT_MODEL,
          where: [identifierWhere(identifier)],
          update: { lockedUntil: lockUntil(now, lockout) },
        });
        throw lockedError();
      }
    }),
  };

  const after = {
    matcher,
    handler: createAuthMiddleware(async (ctx) => {
      const identifier = resolveIdentifier(ctx.path, ctx.body, ctx.context.getPlugin("username"));
      if (identifier === null) {
        return;
      }
      const adapter = ctx.context.adapter;

      if (requestsWithCorrectPassword.has(ctx.context)) {
        await adapter.deleteMany({ model: LOCKOUT_MODEL, where: [identifierWhere(identifier)] });
        return;
      }

      const row = await adapter.findOne<LockoutRow>({
        model: LOCKOUT_MODEL,
        where: [identifierWhere(identifier)],
      });
      if (row !== null && row.failedAttempts >= lockout.maxAttempts) {
        await adapter.updateMany({
          model: LOCKOUT_MODEL,
          where: [identifierWhere(identifier)],
          update: { lockedUntil: lockUntil(new Date(), lockout) },
        });
      }
    }),
  };

  return { before, after, trackVerifiedPassword };
};
