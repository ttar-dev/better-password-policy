import type { AuthContext } from "@better-auth/core";
import type { PasswordWriteTargets } from "./password-hash.ts";
import { deleteLockoutRows, lockoutIdentifiersOfRecord } from "./lockout.ts";
import type { ResolvedPasswordPolicy } from "./options.ts";
import { ADMIN_PASSWORD_PATHS } from "./password-targets.ts";
import { readNonEmptyString, toRecord } from "./record.ts";

const HISTORY_MODEL = "passwordHistory";

export const recordCredentialPasswordWrite = async (
  authContext: AuthContext,
  policy: ResolvedPasswordPolicy,
  userId: string,
  passwordHash: string,
  endpointPath: string | undefined,
): Promise<void> => {
  try {
    const now = new Date();
    const adapter = authContext.adapter;

    if (policy.historyCount !== null) {
      await adapter.create({
        model: HISTORY_MODEL,
        data: { userId, passwordHash, createdAt: now },
      });
      const rows = await adapter.findMany<{ id: string }>({
        model: HISTORY_MODEL,
        where: [{ field: "userId", value: userId }],
        sortBy: { field: "createdAt", direction: "desc" },
      });
      const staleIds = rows.slice(policy.historyCount + 1).map((row) => row.id);
      if (staleIds.length > 0) {
        await adapter.deleteMany({
          model: HISTORY_MODEL,
          where: [{ field: "id", operator: "in", value: staleIds }],
        });
      }
    }

    const keepsForcedChange = endpointPath !== undefined && ADMIN_PASSWORD_PATHS.includes(endpointPath);
    const updatedUser = await authContext.internalAdapter.updateUser(userId, {
      passwordChangedAt: now,
      ...(keepsForcedChange ? {} : { mustChangePassword: false }),
    });
    if (updatedUser) {
      await deleteLockoutRows(adapter, lockoutIdentifiersOfRecord(toRecord(updatedUser)));
    }
  } catch (error) {
    authContext.logger.error("password-policy: failed to record credential password write", error);
  }
};

export const createPasswordWriteHooks = (
  policy: ResolvedPasswordPolicy,
  authContext: AuthContext,
  passwordWriteTargets: PasswordWriteTargets,
) => {
  const pendingPasswordHashes = new WeakMap<object, string>();

  return {
    account: {
      create: {
        after: async (
          account: { userId: string; providerId: string; password?: string | null },
          context: { path?: string } | null,
        ): Promise<void> => {
          if (account.providerId !== "credential" || !account.password) {
            return;
          }
          await recordCredentialPasswordWrite(authContext, policy, account.userId, account.password, context?.path);
        },
      },
      update: {
        before: async (data: Record<string, unknown>, context: object | null): Promise<void> => {
          if (context === null) {
            return;
          }
          const password = readNonEmptyString(data, "password");
          if (password !== null) {
            pendingPasswordHashes.set(context, password);
          }
        },
        after: async (result: unknown, context: { path?: string } | null): Promise<void> => {
          if (context === null) {
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
                policy,
                target.userId,
                target.passwordHash,
                context.path,
              );
            }
            return;
          }

          const row = toRecord(result);
          const userId = readNonEmptyString(row, "userId");
          if (row.providerId === "credential" && userId !== null) {
            await recordCredentialPasswordWrite(
              authContext,
              policy,
              userId,
              readNonEmptyString(row, "password") ?? pendingHash,
              context.path,
            );
          }
        },
      },
    },
    user: {
      delete: {
        after: async (user: Record<string, unknown>): Promise<void> => {
          try {
            await deleteLockoutRows(authContext.adapter, lockoutIdentifiersOfRecord(user));
            const userId = readNonEmptyString(user, "id");
            if (userId !== null) {
              await authContext.adapter.deleteMany({
                model: HISTORY_MODEL,
                where: [{ field: "userId", value: userId }],
              });
            }
          } catch (error) {
            authContext.logger.error("password-policy: failed to clean up after user deletion", error);
          }
        },
      },
    },
  };
};
