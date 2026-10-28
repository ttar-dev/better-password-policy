import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
import { toRecord } from "./record.ts";
import { getPasswordChangeRequirement, type PasswordChangeRequirement } from "./requirement.ts";

export const PASSWORD_CHANGE_EXEMPT_PATHS: readonly string[] = [
  "/change-password",
  "/sign-out",
  "/get-session",
  "/sign-in/email",
  "/sign-in/username",
  "/sign-in/phone-number",
  "/sign-in/social",
  "/sign-in/email-otp",
  "/callback/:id",
  "/sign-up/email",
  "/request-password-reset",
  "/reset-password",
  "/reset-password/:token",
  "/email-otp/send-verification-otp",
  "/email-otp/check-verification-otp",
  "/email-otp/verify-email",
  "/email-otp/request-password-reset",
  "/forget-password/email-otp",
  "/email-otp/reset-password",
  "/phone-number/request-password-reset",
  "/phone-number/reset-password",
  "/verify-email",
  "/send-verification-email",
  "/ok",
  "/error",
  "/admin/stop-impersonating",
];

const toRequirementInput = (user: unknown): { mustChangePassword: boolean; passwordChangedAt: Date | string | null } => {
  const fields = toRecord(user);
  const changedAt = fields.passwordChangedAt;
  return {
    mustChangePassword: fields.mustChangePassword === true,
    passwordChangedAt: changedAt instanceof Date || typeof changedAt === "string" ? changedAt : null,
  };
};

type GateContext = Parameters<typeof getSessionFromCtx>[0];

const deriveBearerHeaders = async (ctx: GateContext): Promise<Headers | null> => {
  const hooks = ctx.context.getPlugin("bearer")?.hooks?.before ?? [];
  for (const hook of hooks) {
    if (!hook.matcher(ctx)) {
      continue;
    }
    const outcome = await hook.handler({ ...ctx, returnHeaders: true });
    const derived = toRecord(toRecord(toRecord(outcome).response).context).headers;
    if (derived instanceof Headers) {
      return derived;
    }
  }
  return null;
};

type GateSession = NonNullable<Awaited<ReturnType<typeof getSessionFromCtx>>>;

const isGateSession = (candidate: unknown): candidate is GateSession =>
  typeof toRecord(toRecord(candidate).user).id === "string";

const lookupSessionIgnoringMemo = async (ctx: GateContext, headers: Headers | undefined): Promise<GateSession | null> => {
  ctx.context.session = null;
  return getSessionFromCtx({ ...ctx, headers, responseHeaders: new Headers() }, { disableRefresh: true });
};

const collectCandidateSessions = async (ctx: GateContext): Promise<GateSession[]> => {
  const memoizedSession = ctx.context.session;
  try {
    const bearerHeaders = await deriveBearerHeaders(ctx);
    const requestSession = await lookupSessionIgnoringMemo(ctx, ctx.headers);
    const bearerSession = bearerHeaders === null ? null : await lookupSessionIgnoringMemo(ctx, bearerHeaders);
    return [memoizedSession, requestSession, bearerSession].filter(isGateSession);
  } finally {
    ctx.context.session = memoizedSession;
  }
};

const strictestRequirement = async (ctx: GateContext, candidates: GateSession[], maxAgeSeconds: number | null) => {
  const checkedUserIds = new Set<string>();
  let strictest: PasswordChangeRequirement = null;
  for (const candidate of candidates) {
    if (getPasswordChangeRequirement(toRequirementInput(candidate.user), maxAgeSeconds) === null) {
      continue;
    }
    if (checkedUserIds.has(candidate.user.id)) {
      continue;
    }
    checkedUserIds.add(candidate.user.id);
    const freshUser = await ctx.context.internalAdapter.findUserById(candidate.user.id);
    const requirement = freshUser ? getPasswordChangeRequirement(toRequirementInput(freshUser), maxAgeSeconds) : null;
    if (requirement === "forced") {
      return "forced";
    }
    if (requirement === "expired") {
      strictest = "expired";
    }
  }
  return strictest;
};

export const createPasswordChangeGate = (maxAgeSeconds: number | null) => ({
  matcher: (context: { path?: string | undefined }): boolean =>
    typeof context.path === "string" && !PASSWORD_CHANGE_EXEMPT_PATHS.includes(context.path),
  handler: createAuthMiddleware(async (ctx) => {
    const requirement = await strictestRequirement(ctx, await collectCandidateSessions(ctx), maxAgeSeconds);
    if (requirement === "forced") {
      throw APIError.from("FORBIDDEN", PASSWORD_POLICY_ERROR_CODES.PASSWORD_CHANGE_REQUIRED);
    }
    if (requirement === "expired") {
      throw APIError.from("FORBIDDEN", PASSWORD_POLICY_ERROR_CODES.PASSWORD_EXPIRED);
    }
  }),
});
