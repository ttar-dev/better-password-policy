import { BASE_ERROR_CODES } from "@better-auth/core/error";
import { APIError, createAuthEndpoint } from "better-auth/api";
import * as z from "zod";
import { deleteLockoutRows, lockoutIdentifiersOfRecord, readLockoutState } from "./lockout.ts";
import type { ResolvedPasswordPolicy } from "./options.ts";
import { toRecord } from "./record.ts";
import { getPasswordChangeRequirement, getPasswordExpiresAt } from "./requirement.ts";

const toDateOrNull = (value: unknown): Date | null => {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }
  return null;
};

export const createPasswordPolicyEndpoints = (policy: ResolvedPasswordPolicy) => ({
  setPasswordChangeRequired: createAuthEndpoint.serverOnly(
    {
      method: "POST",
      body: z.object({ userId: z.string(), required: z.boolean() }),
    },
    async (ctx) => {
      const user = await ctx.context.internalAdapter.findUserById(ctx.body.userId);
      if (!user) {
        throw APIError.from("NOT_FOUND", BASE_ERROR_CODES.USER_NOT_FOUND);
      }
      await ctx.context.internalAdapter.updateUser(user.id, { mustChangePassword: ctx.body.required });
      return ctx.json({ status: true });
    },
  ),
  unlockSignIn: createAuthEndpoint.serverOnly(
    {
      method: "POST",
      body: z.object({ userId: z.string() }),
    },
    async (ctx) => {
      const user = await ctx.context.internalAdapter.findUserById(ctx.body.userId);
      if (!user) {
        throw APIError.from("NOT_FOUND", BASE_ERROR_CODES.USER_NOT_FOUND);
      }
      await deleteLockoutRows(ctx.context.adapter, lockoutIdentifiersOfRecord(user));
      return ctx.json({ status: true });
    },
  ),
  getPasswordPolicyStatus: createAuthEndpoint.serverOnly(
    {
      method: "GET",
      query: z.object({ userId: z.string() }),
    },
    async (ctx) => {
      const user = await ctx.context.internalAdapter.findUserById(ctx.query.userId);
      if (!user) {
        throw APIError.from("NOT_FOUND", BASE_ERROR_CODES.USER_NOT_FOUND);
      }
      const fields = toRecord(user);
      const mustChangePassword = fields.mustChangePassword === true;
      const passwordChangedAt = toDateOrNull(fields.passwordChangedAt);
      const lockoutState =
        policy.lockout === null
          ? { lockedUntil: null, failedAttempts: 0 }
          : await readLockoutState(ctx.context.adapter, lockoutIdentifiersOfRecord(user), new Date());
      return ctx.json({
        mustChangePassword,
        passwordChangedAt,
        passwordExpiresAt: getPasswordExpiresAt(passwordChangedAt, policy.maxAgeSeconds),
        passwordChangeRequirement: getPasswordChangeRequirement(
          { mustChangePassword, passwordChangedAt },
          policy.maxAgeSeconds,
        ),
        lockedUntil: lockoutState.lockedUntil,
        failedSignInAttempts: lockoutState.failedAttempts,
      });
    },
  ),
});
