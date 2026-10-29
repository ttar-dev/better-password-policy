import type { AuthContext } from "@better-auth/core";
import type { PasswordWriteTargets } from "./password-hash.ts";
import { deleteUserLockoutRows } from "./lockout.ts";
import { summarizeError } from "./log-error.ts";
import { ADMIN_PASSWORD_PATHS } from "./password-targets.ts";
import { readNonEmptyString, toRecord } from "./record.ts";
import type { EffectivePolicyResolver, PolicyEndpointContext } from "./tenant-resolver.ts";

const HISTORY_MODEL = "passwordHistory";

const selectStaleHistoryIds = async (
  authContext: AuthContext,
  effectivePolicy: EffectivePolicyResolver,
  endpoint: PolicyEndpointContext | null,
  userId: string,
  rows: { id: string }[],
): Promise<string[]> => {
  const { base } = effectivePolicy;
  if (base.historyCount === null || rows.length <= base.historyCount + 1) {
    return [];
  }
  let keep = base.historyCount + 1;
  if (effectivePolicy.tenantAware) {
    try {
      const effective = await effectivePolicy.resolve({ authContext, endpoint }, { kind: "user-id", userId });
      keep = (effective.historyCount ?? base.historyCount) + 1;
    } catch {
      return [];
    }
  }
  return rows.slice(keep).map((row) => row.id);
};

export const recordCredentialPasswordWrite = async (
  authContext: AuthContext,
  effectivePolicy: EffectivePolicyResolver,
  endpoint: PolicyEndpointContext | null,
  userId: string,
  passwordHash: string,
): Promise<void> => {
  const { base } = effectivePolicy;
  const endpointPath = endpoint?.path;
  try {
    const now = new Date();
    const adapter = authContext.adapter;

    if (base.historyCount !== null) {
      await adapter.create({
        model: HISTORY_MODEL,
        data: { userId, passwordHash, createdAt: now },
      });
      const rows = await adapter.findMany<{ id: string }>({
        model: HISTORY_MODEL,
        where: [{ field: "userId", value: userId }],
        sortBy: { field: "createdAt", direction: "desc" },
      });
      const staleIds = await selectStaleHistoryIds(authContext, effectivePolicy, endpoint, userId, rows);
      if (staleIds.length > 0) {
        await adapter.deleteMany({
          model: HISTORY_MODEL,
          where: [{ field: "id", operator: "in", value: staleIds }],
        });
      }
    }

    const clearsForcedChange =
      base.forcedChange && !(endpointPath !== undefined && ADMIN_PASSWORD_PATHS.includes(endpointPath));
    const updatedUser = await authContext.internalAdapter.updateUser(userId, {
      passwordChangedAt: now,
      ...(clearsForcedChange ? { mustChangePassword: false } : {}),
    });
    if (updatedUser) {
      await deleteUserLockoutRows(adapter, authContext.secret, toRecord(updatedUser));
    }
  } catch (error) {
    authContext.logger.error("password-policy: failed to record credential password write", summarizeError(error));
  }
};

export const createPasswordWriteHooks = (
  effectivePolicy: EffectivePolicyResolver,
  authContext: AuthContext,
  passwordWriteTargets: PasswordWriteTargets,
) => {
  const pendingPasswordHashes = new WeakMap<object, string>();

  return {
    account: {
      create: {
        after: async (
          account: { userId: string; providerId: string; password?: string | null },
          context: PolicyEndpointContext | null | undefined,
        ): Promise<void> => {
          if (account.providerId !== "credential" || !account.password) {
            return;
          }
          await recordCredentialPasswordWrite(
            authContext,
            effectivePolicy,
            context ?? null,
            account.userId,
            account.password,
          );
        },
      },
      update: {
        before: async (data: Record<string, unknown>, context: object | null | undefined): Promise<void> => {
          if (context === null || context === undefined) {
            return;
          }
          const password = readNonEmptyString(data, "password");
          if (password !== null) {
            pendingPasswordHashes.set(context, password);
          }
        },
        after: async (result: unknown, context: PolicyEndpointContext | null | undefined): Promise<void> => {
          if (context === null || context === undefined) {
            return;
          }
          const pendingHash = pendingPasswordHashes.get(context);
          if (pendingHash === undefined) {
            return;
          }
          pendingPasswordHashes.delete(context);

          if (typeof result === "number") {
            const target = passwordWriteTargets.get(context);
            if (result > 0 && target !== undefined) {
              await recordCredentialPasswordWrite(
                authContext,
                effectivePolicy,
                context,
                target.userId,
                target.passwordHash,
              );
            }
            return;
          }

          const row = toRecord(result);
          const userId = readNonEmptyString(row, "userId");
          if (row.providerId === "credential" && userId !== null) {
            await recordCredentialPasswordWrite(
              authContext,
              effectivePolicy,
              context,
              userId,
              readNonEmptyString(row, "password") ?? pendingHash,
            );
          }
        },
      },
    },
    user: {
      delete: {
        after: async (user: Record<string, unknown>): Promise<void> => {
          try {
            await deleteUserLockoutRows(authContext.adapter, authContext.secret, user);
            const userId = readNonEmptyString(user, "id");
            if (userId !== null) {
              await authContext.adapter.deleteMany({
                model: HISTORY_MODEL,
                where: [{ field: "userId", value: userId }],
              });
            }
          } catch (error) {
            authContext.logger.error("password-policy: failed to clean up after user deletion", summarizeError(error));
          }
        },
      },
    },
  };
};
