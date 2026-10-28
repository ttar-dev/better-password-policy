import type { BetterAuthClientPlugin } from "better-auth/client";
import { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
import type { passwordPolicy } from "./index.ts";

export const passwordPolicyClient = () =>
  ({
    id: "password-policy",
    $InferServerPlugin: {} as ReturnType<typeof passwordPolicy>,
    $ERROR_CODES: PASSWORD_POLICY_ERROR_CODES,
  }) satisfies BetterAuthClientPlugin;

export { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
export { getPasswordChangeRequirement, getPasswordExpiresAt } from "./requirement.ts";
export type { PasswordChangeRequirement } from "./requirement.ts";
