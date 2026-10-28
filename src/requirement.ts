export type PasswordChangeRequirement = "forced" | "expired" | null;

const toTime = (value: Date | string | null | undefined): number | null => {
  if (value === null || value === undefined) {
    return null;
  }
  const time = (value instanceof Date ? value : new Date(value)).getTime();
  return Number.isNaN(time) ? null : time;
};

export const getPasswordExpiresAt = (
  passwordChangedAt: Date | string | null | undefined,
  maxAgeSeconds: number | null | undefined,
): Date | null => {
  const changedAt = toTime(passwordChangedAt);
  if (changedAt === null || maxAgeSeconds === null || maxAgeSeconds === undefined) {
    return null;
  }
  return new Date(changedAt + maxAgeSeconds * 1000);
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
