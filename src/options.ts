import type { InferOptionSchema } from "better-auth/types";
import type { PasswordPolicySchema } from "./schema.ts";

export interface PasswordValidationInput {
  password: string;
  user: { id: string | null; email: string | null; name: string | null };
}

export type PasswordValidator = (input: PasswordValidationInput) => boolean | Promise<boolean>;

export interface PasswordComplexityOptions {
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireDigit?: boolean;
  requireSymbol?: boolean;
  rejectPersonalInfo?: boolean;
  validate?: PasswordValidator;
}

export interface PasswordHistoryOptions {
  count?: number;
}

export interface PasswordExpirationOptions {
  maxAge: number;
}

export interface SignInLockoutOptions {
  maxAttempts?: number;
  duration?: number;
}

export interface PasswordPolicyOptions {
  complexity?: PasswordComplexityOptions | false;
  history?: PasswordHistoryOptions | false;
  expiration?: PasswordExpirationOptions | false;
  lockout?: SignInLockoutOptions | false;
  schema?: InferOptionSchema<PasswordPolicySchema>;
}

export interface ResolvedComplexity {
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
  rejectPersonalInfo: boolean;
  validate: PasswordValidator | null;
}

export interface ResolvedLockout {
  maxAttempts: number;
  durationSeconds: number;
}

export interface ResolvedPasswordPolicy {
  complexity: ResolvedComplexity | null;
  historyCount: number | null;
  maxAgeSeconds: number | null;
  lockout: ResolvedLockout | null;
}

const DEFAULT_HISTORY_COUNT = 5;
const DEFAULT_LOCKOUT_MAX_ATTEMPTS = 5;
const DEFAULT_LOCKOUT_DURATION_SECONDS = 900;

const invalid = (message: string) => new TypeError(`password-policy: ${message}`);

const resolveComplexity = (option: PasswordPolicyOptions["complexity"]): ResolvedComplexity | null => {
  if (option === false) {
    return null;
  }
  return {
    requireUppercase: option?.requireUppercase ?? true,
    requireLowercase: option?.requireLowercase ?? true,
    requireDigit: option?.requireDigit ?? true,
    requireSymbol: option?.requireSymbol ?? false,
    rejectPersonalInfo: option?.rejectPersonalInfo ?? true,
    validate: option?.validate ?? null,
  };
};

const resolveHistoryCount = (option: PasswordPolicyOptions["history"]): number | null => {
  if (option === false) {
    return null;
  }
  const count = option?.count ?? DEFAULT_HISTORY_COUNT;
  if (!Number.isInteger(count) || count < 0) {
    throw invalid("history.count must be an integer >= 0");
  }
  return count;
};

const resolveMaxAgeSeconds = (option: PasswordPolicyOptions["expiration"]): number | null => {
  if (option === undefined || option === false) {
    return null;
  }
  if (!Number.isFinite(option.maxAge) || option.maxAge <= 0) {
    throw invalid("expiration.maxAge must be a finite number > 0");
  }
  return option.maxAge;
};

const resolveLockout = (option: PasswordPolicyOptions["lockout"]): ResolvedLockout | null => {
  if (option === false) {
    return null;
  }
  const maxAttempts = option?.maxAttempts ?? DEFAULT_LOCKOUT_MAX_ATTEMPTS;
  const durationSeconds = option?.duration ?? DEFAULT_LOCKOUT_DURATION_SECONDS;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw invalid("lockout.maxAttempts must be an integer >= 1");
  }
  if (!Number.isFinite(durationSeconds) || durationSeconds <= 0) {
    throw invalid("lockout.duration must be a finite number > 0");
  }
  return { maxAttempts, durationSeconds };
};

export const resolvePasswordPolicyOptions = (options?: PasswordPolicyOptions): ResolvedPasswordPolicy => ({
  complexity: resolveComplexity(options?.complexity),
  historyCount: resolveHistoryCount(options?.history),
  maxAgeSeconds: resolveMaxAgeSeconds(options?.expiration),
  lockout: resolveLockout(options?.lockout),
});
