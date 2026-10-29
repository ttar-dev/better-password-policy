import { tryGetCurrentAuthEndpointContext, type AuthEndpointContext } from "@better-auth/core/context";
import { BASE_ERROR_CODES } from "@better-auth/core/error";
import { APIError, createAuthMiddleware } from "better-auth/api";
import type { DBAdapter } from "better-auth/types";
import { findComplexityViolation, isPasswordTooShort } from "./complexity.ts";
import { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
import type { ResolvedPasswordPolicy } from "./options.ts";
import { SIGN_IN_PATHS } from "./lockout.ts";
import type { PasswordNormalizer, PasswordVerifier } from "./password-normalization.ts";
import { isPolicedPasswordContext, resolvePasswordTarget } from "./password-targets.ts";
import type { PasswordTarget } from "./password-targets.ts";
import { toRecord } from "./record.ts";
import type { EffectivePolicyResolver } from "./tenant-resolver.ts";

export interface PasswordWriteTarget {
  userId: string;
  passwordHash: string;
}

export type PasswordWriteTargets = WeakMap<object, PasswordWriteTarget>;

export interface PasswordCandidate {
  typed: string;
  normalized: string;
  normalize: PasswordNormalizer;
}

type PolicyTarget = Exclude<PasswordTarget, { kind: "unauthorized" }>;

const normalizePersonalInfo = (target: PolicyTarget, normalize: PasswordNormalizer) => ({
  email: target.email === null ? null : normalize(target.email),
  name: target.name === null ? null : normalize(target.name),
});

const rejectWith = (code: keyof typeof PASSWORD_POLICY_ERROR_CODES) =>
  APIError.from("BAD_REQUEST", PASSWORD_POLICY_ERROR_CODES[code]);

export const loadReuseCandidateHashes = async (
  adapter: DBAdapter,
  userId: string,
  currentPasswordHash: string | null,
  historyCount: number,
): Promise<string[]> => {
  const rows = await adapter.findMany<{ passwordHash: string }>({
    model: "passwordHistory",
    where: [{ field: "userId", value: userId }],
    sortBy: { field: "createdAt", direction: "desc" },
    limit: historyCount + 1,
  });
  const hashes = rows.map((row) => row.passwordHash);
  if (currentPasswordHash !== null) {
    hashes.push(currentPasswordHash);
  }
  return [...new Set(hashes)];
};

export const isPasswordReused = async (
  password: string,
  hashes: string[],
  verify: PasswordVerifier,
): Promise<boolean> => {
  for (const hash of hashes) {
    if (await verify({ hash, password })) {
      return true;
    }
  }
  return false;
};

export const assertPasswordAllowed = async (
  candidate: PasswordCandidate,
  target: PolicyTarget,
  policy: ResolvedPasswordPolicy,
  authContext: Pick<AuthEndpointContext["context"], "adapter" | "password">,
): Promise<void> => {
  if (policy.complexity !== null) {
    if (isPasswordTooShort(candidate.normalized, policy.complexity.minLength)) {
      throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.PASSWORD_TOO_SHORT);
    }
    const violation = findComplexityViolation(
      candidate.normalized,
      policy.complexity,
      normalizePersonalInfo(target, candidate.normalize),
    );
    if (violation !== null) {
      throw rejectWith(violation);
    }
    if (policy.complexity.validate !== null) {
      const accepted = await policy.complexity.validate({
        password: candidate.normalized,
        user: {
          id: target.kind === "existing-user" ? target.userId : null,
          email: target.email,
          name: target.name,
        },
      });
      if (!accepted) {
        throw rejectWith("PASSWORD_REJECTED");
      }
    }
  }
  if (policy.historyCount !== null && target.kind === "existing-user") {
    const hashes = await loadReuseCandidateHashes(
      authContext.adapter,
      target.userId,
      target.currentPasswordHash,
      policy.historyCount,
    );
    if (await isPasswordReused(candidate.typed, hashes, (input) => authContext.password.verify(input))) {
      throw rejectWith("PASSWORD_REUSED");
    }
  }
};

export const createPolicyEnforcingHash =
  (
    originalHash: (password: string) => Promise<string>,
    effectivePolicy: EffectivePolicyResolver,
    passwordWriteTargets: PasswordWriteTargets,
    normalizePassword: PasswordNormalizer,
    hashesAsTypedForSignInTiming: boolean,
  ) =>
  async (password: string): Promise<string> => {
    const normalized = normalizePassword(password);
    const c = tryGetCurrentAuthEndpointContext();
    const endpointPath = c?.path;
    if (!isPolicedPasswordContext(c)) {
      const passwordHash = await originalHash(normalized);
      if (
        hashesAsTypedForSignInTiming &&
        normalized !== password &&
        endpointPath !== undefined &&
        SIGN_IN_PATHS.includes(endpointPath)
      ) {
        await originalHash(password);
      }
      return passwordHash;
    }
    const target = await resolvePasswordTarget(c);
    if (target.kind === "unauthorized") {
      return originalHash(normalized);
    }
    const { base } = effectivePolicy;
    const policy =
      base.complexity !== null || (base.historyCount !== null && target.kind === "existing-user")
        ? await effectivePolicy.resolve(
            { authContext: c.context, endpoint: c },
            target.kind === "existing-user"
              ? { kind: "user", record: target.record }
              : { kind: "anonymous", email: target.email?.toLowerCase() ?? null },
          )
        : base;
    await assertPasswordAllowed({ typed: password, normalized, normalize: normalizePassword }, target, policy, c.context);
    const passwordHash = await originalHash(normalized);
    if (target.kind === "existing-user") {
      passwordWriteTargets.set(c, { userId: target.userId, passwordHash });
    }
    return passwordHash;
  };

export const createAdminCreateUserPolicyHook = (
  effectivePolicy: EffectivePolicyResolver,
  normalizePassword: PasswordNormalizer,
) => ({
  matcher: (context: { path?: string | undefined }): boolean => context.path === "/admin/create-user",
  handler: createAuthMiddleware(async (ctx) => {
    const body = toRecord(ctx.body);
    const password = body.password;
    if (typeof password !== "string" || password === "") {
      return;
    }
    const email = typeof body.email === "string" ? body.email : null;
    const policy = await effectivePolicy.resolve(
      { authContext: ctx.context, endpoint: ctx },
      { kind: "anonymous", email: email?.toLowerCase() ?? null },
    );
    await assertPasswordAllowed(
      { typed: password, normalized: normalizePassword(password), normalize: normalizePassword },
      {
        kind: "new-user",
        email,
        name: typeof body.name === "string" ? body.name : null,
      },
      policy,
      ctx.context,
    );
  }),
});
