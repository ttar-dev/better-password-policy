import type { createAuthMiddleware } from "better-auth/api";
import { createDeviceId, deviceCookieBinding } from "./lockout-keys.ts";
import { readNonEmptyString } from "./record.ts";

export const DEVICE_COOKIE_NAME = "password_policy_device";

const DEVICE_COOKIE_PATTERN = /^v1:([0-9a-f]{32}):([1-9][0-9]{0,11}):([0-9a-f]{64})$/;

export type SignInHookContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];

export interface DeviceCookieValue {
  deviceId: string;
  expiresAt: number;
  binding: string;
}

export const formatDeviceCookieValue = (value: DeviceCookieValue): string =>
  `v1:${value.deviceId}:${value.expiresAt}:${value.binding}`;

export const parseDeviceCookieValue = (raw: string): DeviceCookieValue | null => {
  const match = DEVICE_COOKIE_PATTERN.exec(raw);
  if (match === null) {
    return null;
  }
  const [, deviceId, expiresAt, binding] = match;
  if (deviceId === undefined || expiresAt === undefined || binding === undefined) {
    return null;
  }
  return { deviceId, expiresAt: Number(expiresAt), binding };
};

export const passwordEpochOf = (user: Record<string, unknown>): string => {
  const changedAt = user.passwordChangedAt;
  const parsed =
    changedAt instanceof Date
      ? changedAt
      : typeof changedAt === "string" || typeof changedAt === "number"
        ? new Date(changedAt)
        : null;
  return parsed === null || Number.isNaN(parsed.getTime()) ? "none" : String(parsed.getTime());
};

export const readDeviceCookie = async (ctx: SignInHookContext): Promise<DeviceCookieValue | null> => {
  try {
    const cookie = ctx.context.createAuthCookie(DEVICE_COOKIE_NAME);
    const raw = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
    if (typeof raw !== "string") {
      return null;
    }
    const value = parseDeviceCookieValue(raw);
    return value !== null && value.expiresAt * 1000 > Date.now() ? value : null;
  } catch {
    return null;
  }
};

export const issueDeviceCookie = async (
  ctx: SignInHookContext,
  user: Record<string, unknown>,
  maxAgeSeconds: number,
): Promise<void> => {
  const userId = readNonEmptyString(user, "id");
  if (userId === null) {
    return;
  }
  const secret = ctx.context.secret;
  const deviceId = createDeviceId();
  const expiresAt = Math.floor(Date.now() / 1000) + maxAgeSeconds;
  const binding = await deviceCookieBinding(secret, userId, deviceId, expiresAt, passwordEpochOf(user));
  const cookie = ctx.context.createAuthCookie(DEVICE_COOKIE_NAME, { maxAge: maxAgeSeconds });
  await ctx.setSignedCookie(cookie.name, formatDeviceCookieValue({ deviceId, expiresAt, binding }), secret, cookie.attributes);
};
