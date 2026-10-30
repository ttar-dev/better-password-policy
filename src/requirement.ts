export type PasswordChangeRequirement = "forced" | "expired" | null;

export const parsePasswordChangedAt = (value: unknown): Date | null => {
  const parsed =
    value instanceof Date ? value : typeof value === "string" || typeof value === "number" ? new Date(value) : null;
  return parsed === null || Number.isNaN(parsed.getTime()) ? null : parsed;
};

export const getPasswordExpiresAt = (
  passwordChangedAt: Date | string | null | undefined,
  maxAgeSeconds: number | null | undefined,
): Date | null => {
  const changedAt = parsePasswordChangedAt(passwordChangedAt);
  if (changedAt === null || maxAgeSeconds === null || maxAgeSeconds === undefined) {
    return null;
  }
  return new Date(changedAt.getTime() + maxAgeSeconds * 1000);
};

export const getPasswordChangeRequirement = (
  user: { mustChangePassword?: boolean | null; passwordChangedAt?: Date | string | null },
  maxAgeSeconds: number | null | undefined,
  now: Date = new Date(),
): PasswordChangeRequirement => {
  if (user.mustChangePassword === true) {
    return "forced";
  }
  const expiresAt = getPasswordExpiresAt(user.passwordChangedAt, maxAgeSeconds);
  if (expiresAt !== null && now.getTime() >= expiresAt.getTime()) {
    return "expired";
  }
  return null;
};
