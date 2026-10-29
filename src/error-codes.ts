import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

export const PASSWORD_POLICY_ERROR_CODES = defineErrorCodes({
  PASSWORD_MISSING_UPPERCASE: "Password must contain at least one uppercase letter",
  PASSWORD_MISSING_LOWERCASE: "Password must contain at least one lowercase letter",
  PASSWORD_MISSING_DIGIT: "Password must contain at least one digit",
  PASSWORD_MISSING_SYMBOL: "Password must contain at least one symbol",
  PASSWORD_CONTAINS_PERSONAL_INFO: "Password must not contain your name or email",
  PASSWORD_REJECTED: "Password does not meet the password policy",
  PASSWORD_REUSED: "Password was used recently, choose a different password",
  PASSWORD_CHANGE_REQUIRED: "Password change required",
  PASSWORD_EXPIRED: "Password expired, change it to continue",
  FORCED_PASSWORD_CHANGE_DISABLED: "Forced password change is disabled",
  SIGN_IN_LOCKED: "Too many failed sign-in attempts, try again later",
  PASSWORD_POLICY_UNAVAILABLE: "Password policy is unavailable, try again later",
});

export type PasswordPolicyErrorCode = keyof typeof PASSWORD_POLICY_ERROR_CODES;
