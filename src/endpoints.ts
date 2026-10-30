import { BASE_ERROR_CODES } from "@better-auth/core/error";
import { APIError, createAuthEndpoint } from "better-auth/api";
import * as z from "zod";
import { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
import { deleteUserLockoutRows, readUserLockoutState } from "./lockout.ts";
import { toRecord } from "./record.ts";
import { getPasswordChangeRequirement, getPasswordExpiresAt, parsePasswordChangedAt } from "./requirement.ts";
import { toEffectivePasswordPolicy } from "./tenant-policy.ts";
import type { EffectivePolicyResolver } from "./tenant-resolver.ts";

export const createPasswordPolicyEndpoints = (effectivePolicy: EffectivePolicyResolver) => ({
  setPasswordChangeRequired: createAuthEndpoint.serverOnly(
    {
      method: "POST",
      body: z.object({ userId: z.string(), required: z.boolean() }),
    },
    async (ctx) => {
      if (!effectivePolicy.base.forcedChange) {
        throw APIError.from("BAD_REQUEST", PASSWORD_POLICY_ERROR_CODES.FORCED_PASSWORD_CHANGE_DISABLED);
      }
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
      await deleteUserLockoutRows(ctx.context.adapter, ctx.context.secret, user);
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
      const effective = await effectivePolicy.resolve(
        { authContext: ctx.context, endpoint: { context: ctx.context, headers: ctx.headers, request: ctx.request } },
        { kind: "user", record: fields },
      );
      const mustChangePassword = effectivePolicy.base.forcedChange && fields.mustChangePassword === true;
      const passwordChangedAt = parsePasswordChangedAt(fields.passwordChangedAt);
      const lockoutState =
        effective.lockout === null
          ? { lockedUntil: null, failedAttempts: 0 }
          : await readUserLockoutState(ctx.context.adapter, ctx.context.secret, user, new Date());
      return ctx.json({
        mustChangePassword,
        passwordChangedAt,
        passwordExpiresAt: getPasswordExpiresAt(passwordChangedAt, effective.maxAgeSeconds),
        passwordChangeRequirement: getPasswordChangeRequirement(
          { mustChangePassword, passwordChangedAt },
          effective.maxAgeSeconds,
        ),
        lockedUntil: lockoutState.lockedUntil,
        failedSignInAttempts: lockoutState.failedAttempts,
        policy: toEffectivePasswordPolicy(effective, ctx.context.password.config),
      });
    },
  ),
});
