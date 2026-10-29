import type { BetterAuthPlugin } from "better-auth";
import { mergeSchema } from "better-auth/db";
import { createPasswordPolicyEndpoints } from "./endpoints.ts";
import { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
import { canRequirePasswordChange, createPasswordChangeGate } from "./gate.ts";
import { createSignInLockoutHooks } from "./lockout.ts";
import {
  resolveLockoutPlatformSettings,
  resolvePasswordNormalizationOption,
  resolvePasswordPolicyOptions,
  resolveTenantPolicyOption,
} from "./options.ts";
import type { PasswordPolicyOptions } from "./options.ts";
import { createAdminCreateUserPolicyHook, createPolicyEnforcingHash } from "./password-hash.ts";
import type { PasswordWriteTargets } from "./password-hash.ts";
import {
  createNormalizingVerify,
  createPasswordNormalizer,
  usesDefaultPasswordVerifier,
} from "./password-normalization.ts";
import { createPasswordWriteHooks } from "./password-writes.ts";
import { passwordPolicySchema } from "./schema.ts";
import { createEffectivePolicyResolver } from "./tenant-resolver.ts";

export const passwordPolicy = (options?: PasswordPolicyOptions) => {
  const policy = resolvePasswordPolicyOptions(options);
  const effectivePolicy = createEffectivePolicyResolver(policy, resolveTenantPolicyOption(options?.tenantPolicy));
  const passwordNormalization = resolvePasswordNormalizationOption(options?.passwordNormalization);
  const normalizePassword = createPasswordNormalizer(passwordNormalization);
  const passwordWriteTargets: PasswordWriteTargets = new WeakMap();
  const passwordChangeGate = canRequirePasswordChange(effectivePolicy) ? createPasswordChangeGate(effectivePolicy) : null;
  const lockoutPlatform = resolveLockoutPlatformSettings(options?.lockout, policy.lockout);
  const lockoutHooks =
    policy.lockout === null || lockoutPlatform === null
      ? null
      : createSignInLockoutHooks(policy.lockout, lockoutPlatform, effectivePolicy);

  return {
    id: "password-policy",
    init(authContext) {
      const verifierNormalizesItself = usesDefaultPasswordVerifier(authContext.password);
      const verifyPassword =
        passwordNormalization === null || verifierNormalizesItself
          ? authContext.password.verify
          : createNormalizingVerify(authContext.password.verify, normalizePassword);
      return {
        context: {
          password: {
            ...authContext.password,
            hash: createPolicyEnforcingHash(
              authContext.password.hash,
              effectivePolicy,
              passwordWriteTargets,
              normalizePassword,
              !verifierNormalizesItself,
            ),
            verify: lockoutHooks === null ? verifyPassword : lockoutHooks.trackVerifiedPassword(verifyPassword),
          },
        },
        options: {
          databaseHooks: createPasswordWriteHooks(effectivePolicy, authContext, passwordWriteTargets),
        },
      };
    },
    hooks: {
      before: [
        ...(passwordChangeGate === null ? [] : [passwordChangeGate]),
        ...(lockoutHooks === null ? [] : [lockoutHooks.before]),
        ...(policy.complexity === null ? [] : [createAdminCreateUserPolicyHook(effectivePolicy, normalizePassword)]),
      ],
      after: [...(lockoutHooks === null ? [] : [lockoutHooks.after])],
    },
    endpoints: createPasswordPolicyEndpoints(effectivePolicy),
    schema: mergeSchema(passwordPolicySchema, options?.schema),
    options,
    $ERROR_CODES: PASSWORD_POLICY_ERROR_CODES,
  } satisfies BetterAuthPlugin;
};

declare module "@better-auth/core" {
  interface BetterAuthPluginRegistry<AuthOptions, Options> {
    "password-policy": {
      creator: typeof passwordPolicy;
    };
  }
}

export { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
export type { PasswordPolicyErrorCode } from "./error-codes.ts";
export { PASSWORD_CHANGE_EXEMPT_PATHS } from "./gate.ts";
export { passwordPolicySchema } from "./schema.ts";
export type { PasswordPolicySchema } from "./schema.ts";
export { getPasswordChangeRequirement, getPasswordExpiresAt } from "./requirement.ts";
export type { PasswordChangeRequirement } from "./requirement.ts";
export { TENANT_PASSWORD_POLICY_LIMITS, validateTenantPasswordPolicyOverride } from "./tenant-policy.ts";
export type {
  EffectivePasswordPolicy,
  TenantPasswordPolicyIssue,
  TenantPasswordPolicyValidationResult,
} from "./tenant-policy.ts";
export type {
  PasswordComplexityOptions,
  PasswordExpirationOptions,
  PasswordHistoryOptions,
  PasswordNormalizationForm,
  PasswordPolicyOptions,
  PasswordValidationInput,
  SignInDeviceCookieOptions,
  SignInLockoutOptions,
  TenantPasswordPolicyContext,
  TenantPasswordPolicyOverride,
  TenantPasswordPolicyResolver,
  TenantPasswordPolicyUser,
} from "./options.ts";
