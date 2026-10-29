import type { InferOptionSchema } from "better-auth/types";
import type { PasswordPolicySchema } from "./schema.ts";
import { TENANT_PASSWORD_POLICY_LIMITS } from "./tenant-policy.ts";

export interface PasswordValidationInput {
  password: string;
  user: { id: string | null; email: string | null; name: string | null };
}

export type PasswordValidator = (input: PasswordValidationInput) => boolean | Promise<boolean>;

export interface PasswordComplexityOptions {
  minLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireDigit?: boolean;
  requireSymbol?: boolean;
  rejectPersonalInfo?: boolean;
  caselessLettersSatisfyCase?: boolean;
  validate?: PasswordValidator;
}

export interface PasswordHistoryOptions {
  count?: number;
}

export interface PasswordExpirationOptions {
  maxAge: number;
}

export interface SignInDeviceCookieOptions {
  maxAge?: number;
}

export interface SignInLockoutOptions {
  maxAttempts?: number;
  duration?: number;
  retention?: number | false;
  deviceCookie?: SignInDeviceCookieOptions | false;
}

export interface TenantPasswordPolicyOverride {
  complexity?: {
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireDigit?: boolean;
    requireSymbol?: boolean;
    rejectPersonalInfo?: boolean;
    caselessLettersSatisfyCase?: boolean;
  };
  history?: { count?: number };
  expiration?: { maxAge?: number };
  lockout?: { maxAttempts?: number; duration?: number };
}

export interface TenantPasswordPolicyUser {
  id: string;
  email: string;
  name: string;
  [field: string]: unknown;
}

export interface TenantPasswordPolicyContext {
  user: TenantPasswordPolicyUser | null;
  email: string | null;
  path: string | null;
  headers: Headers | null;
  request: Request | null;
}

export type TenantPasswordPolicyResolver = (
  context: TenantPasswordPolicyContext,
) => TenantPasswordPolicyOverride | null | undefined | Promise<TenantPasswordPolicyOverride | null | undefined>;

export interface PasswordPolicyOptions {
  complexity?: PasswordComplexityOptions | false;
  history?: PasswordHistoryOptions | false;
  expiration?: PasswordExpirationOptions | false;
  lockout?: SignInLockoutOptions | false;
  tenantPolicy?: TenantPasswordPolicyResolver;
  schema?: InferOptionSchema<PasswordPolicySchema>;
}

export interface ResolvedComplexity {
  minLength: number | null;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
  rejectPersonalInfo: boolean;
  caselessLettersSatisfyCase: boolean;
  validate: PasswordValidator | null;
}

export interface ResolvedLockout {
  maxAttempts: number;
  durationSeconds: number;
}

export interface ResolvedLockoutPlatformSettings {
  retentionSeconds: number | null;
  deviceCookieMaxAgeSeconds: number | null;
}

export interface ResolvedPasswordPolicy {
  complexity: ResolvedComplexity | null;
  historyCount: number | null;
  maxAgeSeconds: number | null;
  expirationDisabled: boolean;
  lockout: ResolvedLockout | null;
}

const DEFAULT_HISTORY_COUNT = 5;
const DEFAULT_LOCKOUT_MAX_ATTEMPTS = 5;
const DEFAULT_LOCKOUT_DURATION_SECONDS = 900;
const DEFAULT_LOCKOUT_RETENTION_SECONDS = 2592000;
const MIN_LOCKOUT_RETENTION_SECONDS = 86400;
const MAX_LOCKOUT_RETENTION_SECONDS = 315360000;
const DEFAULT_DEVICE_COOKIE_MAX_AGE_SECONDS = 2592000;
const MAX_DEVICE_COOKIE_MAX_AGE_SECONDS = 34560000;

const invalid = (message: string) => new TypeError(`password-policy: ${message}`);

const resolveComplexity = (option: PasswordPolicyOptions["complexity"]): ResolvedComplexity | null => {
  if (option === false) {
    return null;
  }
  const minLength = option?.minLength ?? null;
  const limits = TENANT_PASSWORD_POLICY_LIMITS.complexity.minLength;
  if (minLength !== null && (!Number.isInteger(minLength) || minLength < limits.min || minLength > limits.max)) {
    throw invalid(`complexity.minLength must be an integer between ${limits.min} and ${limits.max}`);
  }
  return {
    minLength,
    requireUppercase: option?.requireUppercase ?? true,
    requireLowercase: option?.requireLowercase ?? true,
    requireDigit: option?.requireDigit ?? true,
    requireSymbol: option?.requireSymbol ?? false,
    rejectPersonalInfo: option?.rejectPersonalInfo ?? true,
    caselessLettersSatisfyCase: option?.caselessLettersSatisfyCase ?? false,
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

const resolveRetentionSeconds = (option: SignInLockoutOptions | undefined): number | null => {
  if (option?.retention === false) {
    return null;
  }
  const retention = option?.retention ?? DEFAULT_LOCKOUT_RETENTION_SECONDS;
  if (
    !Number.isInteger(retention) ||
    retention < MIN_LOCKOUT_RETENTION_SECONDS ||
    retention > MAX_LOCKOUT_RETENTION_SECONDS
  ) {
    throw invalid(
      `lockout.retention must be false or an integer between ${MIN_LOCKOUT_RETENTION_SECONDS} and ${MAX_LOCKOUT_RETENTION_SECONDS}`,
    );
  }
  return retention;
};

const resolveDeviceCookieMaxAgeSeconds = (option: SignInLockoutOptions | undefined): number | null => {
  if (option?.deviceCookie === false) {
    return null;
  }
  const maxAge = option?.deviceCookie?.maxAge ?? DEFAULT_DEVICE_COOKIE_MAX_AGE_SECONDS;
  if (!Number.isInteger(maxAge) || maxAge < 1 || maxAge > MAX_DEVICE_COOKIE_MAX_AGE_SECONDS) {
    throw invalid(`lockout.deviceCookie.maxAge must be an integer between 1 and ${MAX_DEVICE_COOKIE_MAX_AGE_SECONDS}`);
  }
  return maxAge;
};

export const resolveLockoutPlatformSettings = (
  option: PasswordPolicyOptions["lockout"],
  lockout: ResolvedLockout | null,
): ResolvedLockoutPlatformSettings | null => {
  if (option === false || lockout === null) {
    return null;
  }
  return {
    retentionSeconds: resolveRetentionSeconds(option),
    deviceCookieMaxAgeSeconds: resolveDeviceCookieMaxAgeSeconds(option),
  };
};

export const resolvePasswordPolicyOptions = (options?: PasswordPolicyOptions): ResolvedPasswordPolicy => ({
  complexity: resolveComplexity(options?.complexity),
  historyCount: resolveHistoryCount(options?.history),
  maxAgeSeconds: resolveMaxAgeSeconds(options?.expiration),
  expirationDisabled: options?.expiration === false,
  lockout: resolveLockout(options?.lockout),
});

const isTenantPolicyResolver = (value: unknown): value is TenantPasswordPolicyResolver => typeof value === "function";

export const resolveTenantPolicyOption = (option: unknown): TenantPasswordPolicyResolver | null => {
  if (option === undefined) {
    return null;
  }
  if (!isTenantPolicyResolver(option)) {
    throw invalid("tenantPolicy must be a function");
  }
  return option;
};
