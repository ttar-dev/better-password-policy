import type { BetterAuthPlugin } from "better-auth";
import { mergeSchema } from "better-auth/db";
import { createPasswordPolicyEndpoints } from "./endpoints.ts";
import { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
import { createPasswordChangeGate } from "./gate.ts";
import { createSignInLockoutHooks } from "./lockout.ts";
import { resolvePasswordPolicyOptions } from "./options.ts";
import type { PasswordPolicyOptions } from "./options.ts";
import { createAdminCreateUserPolicyHook, createPolicyEnforcingHash } from "./password-hash.ts";
import type { PasswordWriteTargets } from "./password-hash.ts";
import { createPasswordWriteHooks } from "./password-writes.ts";
import { passwordPolicySchema } from "./schema.ts";

export const passwordPolicy = (options?: PasswordPolicyOptions) => {
  const policy = resolvePasswordPolicyOptions(options);
  const passwordWriteTargets: PasswordWriteTargets = new WeakMap();
  const lockoutHooks = policy.lockout === null ? null : createSignInLockoutHooks(policy.lockout);

  return {
    id: "password-policy",
    init(authContext) {
      return {
        context: {
          password: {
            ...authContext.password,
            hash: createPolicyEnforcingHash(authContext.password.hash, policy, passwordWriteTargets),
            verify:
              lockoutHooks === null
                ? authContext.password.verify
                : lockoutHooks.trackVerifiedPassword(authContext.password.verify),
          },
        },
        options: {
          databaseHooks: createPasswordWriteHooks(policy, authContext, passwordWriteTargets),
        },
      };
    },
    hooks: {
      before: [
        createPasswordChangeGate(policy.maxAgeSeconds),
        ...(lockoutHooks === null ? [] : [lockoutHooks.before]),
        ...(policy.complexity === null ? [] : [createAdminCreateUserPolicyHook(policy)]),
      ],
      after: [...(lockoutHooks === null ? [] : [lockoutHooks.after])],
    },
    endpoints: createPasswordPolicyEndpoints(policy),
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
export type {
  PasswordComplexityOptions,
  PasswordExpirationOptions,
  PasswordHistoryOptions,
  PasswordPolicyOptions,
  PasswordValidationInput,
  SignInLockoutOptions,
} from "./options.ts";
