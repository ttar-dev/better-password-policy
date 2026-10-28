import * as z from "zod";
import type { ResolvedComplexity, ResolvedPasswordPolicy, TenantPasswordPolicyOverride } from "./options.ts";

export const TENANT_PASSWORD_POLICY_LIMITS = {
  complexity: { minLength: { min: 1, max: 128 } },
  history: { count: { min: 0, max: 24 } },
  expiration: { maxAge: { min: 86400, max: 315360000 } },
  lockout: { maxAttempts: { min: 1, max: 100 }, duration: { min: 1, max: 86400 } },
} as const;

export interface TenantPasswordPolicyIssue {
  path: string;
  message: string;
}

export type TenantPasswordPolicyValidationResult =
  | { success: true; data: TenantPasswordPolicyOverride }
  | { success: false; issues: TenantPasswordPolicyIssue[] };

export interface EffectivePasswordPolicy {
  minLength: number;
  maxLength: number;
  complexity: {
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireDigit: boolean;
    requireSymbol: boolean;
    rejectPersonalInfo: boolean;
    customValidation: boolean;
  } | null;
  history: { count: number } | null;
  expiration: { maxAge: number } | null;
  lockout: { maxAttempts: number; duration: number } | null;
}

const boundedInteger = ({ min, max }: { min: number; max: number }) => z.int().min(min).max(max);

const overrideSchema = z.strictObject({
  complexity: z
    .strictObject({
      minLength: boundedInteger(TENANT_PASSWORD_POLICY_LIMITS.complexity.minLength).optional(),
      requireUppercase: z.boolean().optional(),
      requireLowercase: z.boolean().optional(),
      requireDigit: z.boolean().optional(),
      requireSymbol: z.boolean().optional(),
      rejectPersonalInfo: z.boolean().optional(),
    })
    .optional(),
  history: z.strictObject({ count: boundedInteger(TENANT_PASSWORD_POLICY_LIMITS.history.count).optional() }).optional(),
  expiration: z
    .strictObject({ maxAge: boundedInteger(TENANT_PASSWORD_POLICY_LIMITS.expiration.maxAge).optional() })
    .optional(),
  lockout: z
    .strictObject({
      maxAttempts: boundedInteger(TENANT_PASSWORD_POLICY_LIMITS.lockout.maxAttempts).optional(),
      duration: boundedInteger(TENANT_PASSWORD_POLICY_LIMITS.lockout.duration).optional(),
    })
    .optional(),
}) satisfies z.ZodType<TenantPasswordPolicyOverride>;

const joinPath = (segments: readonly PropertyKey[]): string => segments.map((segment) => String(segment)).join(".");

const toIssues = (error: z.ZodError): TenantPasswordPolicyIssue[] =>
  error.issues.flatMap((issue) => {
    if (issue.code === "unrecognized_keys") {
      return issue.keys.map((key) => ({ path: joinPath([...issue.path, key]), message: issue.message }));
    }
    return [{ path: joinPath(issue.path), message: issue.message }];
  });

export const validateTenantPasswordPolicyOverride = (input: unknown): TenantPasswordPolicyValidationResult => {
  const parsed = overrideSchema.safeParse(input);
  return parsed.success ? { success: true, data: parsed.data } : { success: false, issues: toIssues(parsed.error) };
};

const largest = (first: number | null, second: number | null): number | null => {
  if (first === null) {
    return second;
  }
  if (second === null) {
    return first;
  }
  return Math.max(first, second);
};

const smallest = (first: number | null, second: number | null): number | null => {
  if (first === null) {
    return second;
  }
  if (second === null) {
    return first;
  }
  return Math.min(first, second);
};

const mergeComplexity = (
  base: ResolvedComplexity | null,
  override: TenantPasswordPolicyOverride["complexity"],
): ResolvedComplexity | null => {
  if (base === null) {
    return null;
  }
  return {
    minLength: largest(base.minLength, override?.minLength ?? null),
    requireUppercase: base.requireUppercase || override?.requireUppercase === true,
    requireLowercase: base.requireLowercase || override?.requireLowercase === true,
    requireDigit: base.requireDigit || override?.requireDigit === true,
    requireSymbol: base.requireSymbol || override?.requireSymbol === true,
    rejectPersonalInfo: base.rejectPersonalInfo || override?.rejectPersonalInfo === true,
    validate: base.validate,
  };
};

export const mergeTenantPasswordPolicy = (
  base: ResolvedPasswordPolicy,
  override: TenantPasswordPolicyOverride,
): ResolvedPasswordPolicy => ({
  complexity: mergeComplexity(base.complexity, override.complexity),
  historyCount:
    base.historyCount === null ? null : Math.max(base.historyCount, override.history?.count ?? base.historyCount),
  maxAgeSeconds: base.expirationDisabled ? null : smallest(base.maxAgeSeconds, override.expiration?.maxAge ?? null),
  expirationDisabled: base.expirationDisabled,
  lockout:
    base.lockout === null
      ? null
      : {
          maxAttempts: Math.min(base.lockout.maxAttempts, override.lockout?.maxAttempts ?? base.lockout.maxAttempts),
          durationSeconds: Math.max(
            base.lockout.durationSeconds,
            override.lockout?.duration ?? base.lockout.durationSeconds,
          ),
        },
});

export const toEffectivePasswordPolicy = (
  policy: ResolvedPasswordPolicy,
  lengths: { minPasswordLength: number; maxPasswordLength: number },
): EffectivePasswordPolicy => ({
  minLength: Math.max(lengths.minPasswordLength, policy.complexity?.minLength ?? 0),
  maxLength: lengths.maxPasswordLength,
  complexity:
    policy.complexity === null
      ? null
      : {
          requireUppercase: policy.complexity.requireUppercase,
          requireLowercase: policy.complexity.requireLowercase,
          requireDigit: policy.complexity.requireDigit,
          requireSymbol: policy.complexity.requireSymbol,
          rejectPersonalInfo: policy.complexity.rejectPersonalInfo,
          customValidation: policy.complexity.validate !== null,
        },
  history: policy.historyCount === null ? null : { count: policy.historyCount },
  expiration: policy.maxAgeSeconds === null ? null : { maxAge: policy.maxAgeSeconds },
  lockout:
    policy.lockout === null
      ? null
      : { maxAttempts: policy.lockout.maxAttempts, duration: policy.lockout.durationSeconds },
});
