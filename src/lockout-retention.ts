import type { AuthContext } from "@better-auth/core";
import type { DBAdapter } from "better-auth/types";
import { LOCKOUT_MODEL } from "./lockout-keys.ts";
import { summarizeError } from "./log-error.ts";

export const LOCKOUT_PURGE_INTERVAL_MS = 3_600_000;

export const purgeStaleLockoutRows = async (adapter: DBAdapter, now: Date, retentionSeconds: number): Promise<void> => {
  const cutoff = new Date(now.getTime() - retentionSeconds * 1000);
  await adapter.deleteMany({
    model: LOCKOUT_MODEL,
    where: [
      { field: "lastAttemptAt", operator: "lt", value: cutoff },
      { field: "lockedUntil", operator: "eq", value: null },
    ],
  });
  await adapter.deleteMany({
    model: LOCKOUT_MODEL,
    where: [
      { field: "lastAttemptAt", operator: "lt", value: cutoff },
      { field: "lockedUntil", operator: "lt", value: now },
    ],
  });
};

export const createLockoutRetentionPurge = (retentionSeconds: number) => {
  let nextPurgeAt = 0;

  return async (authContext: Pick<AuthContext, "adapter" | "logger" | "runInBackgroundOrAwait">): Promise<void> => {
    const now = new Date();
    if (now.getTime() < nextPurgeAt) {
      return;
    }
    nextPurgeAt = now.getTime() + LOCKOUT_PURGE_INTERVAL_MS;
    const task = purgeStaleLockoutRows(authContext.adapter, now, retentionSeconds).catch((error: unknown) => {
      authContext.logger.error("password-policy: failed to purge stale sign-in lockout rows", summarizeError(error));
    });
    await authContext.runInBackgroundOrAwait(task);
  };
};
