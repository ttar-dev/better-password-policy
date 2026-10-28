import { tryGetCurrentAuthEndpointContext, type AuthEndpointContext } from "@better-auth/core/context";
import { APIError, createAuthMiddleware } from "better-auth/api";
import type { DBAdapter } from "better-auth/types";
import { findComplexityViolation } from "./complexity.ts";
import { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
import type { ResolvedPasswordPolicy } from "./options.ts";
import { isPolicedPasswordContext, resolvePasswordTarget } from "./password-targets.ts";
import type { PasswordTarget } from "./password-targets.ts";
import { toRecord } from "./record.ts";

export interface PasswordWriteTarget {
  userId: string;
  passwordHash: string;
}

export type PasswordWriteTargets = WeakMap<object, PasswordWriteTarget>;

type PasswordVerifier = (input: { hash: string; password: string }) => Promise<boolean>;

type PolicyTarget = Exclude<PasswordTarget, { kind: "unauthorized" }>;

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
  password: string,
  target: PolicyTarget,
  policy: ResolvedPasswordPolicy,
  authContext: Pick<AuthEndpointContext["context"], "adapter" | "password">,
): Promise<void> => {
  if (policy.complexity !== null) {
    const violation = findComplexityViolation(password, policy.complexity, target);
    if (violation !== null) {
      throw rejectWith(violation);
    }
    if (policy.complexity.validate !== null) {
      const accepted = await policy.complexity.validate({
        password,
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
    if (await isPasswordReused(password, hashes, (input) => authContext.password.verify(input))) {
      throw rejectWith("PASSWORD_REUSED");
    }
  }
};

export const createPolicyEnforcingHash =
  (
    originalHash: (password: string) => Promise<string>,
    policy: ResolvedPasswordPolicy,
    passwordWriteTargets: PasswordWriteTargets,
  ) =>
  async (password: string): Promise<string> => {
    const c = tryGetCurrentAuthEndpointContext();
    if (!isPolicedPasswordContext(c)) {
      return originalHash(password);
    }
    const target = await resolvePasswordTarget(c);
    if (target.kind === "unauthorized") {
      return originalHash(password);
    }
    await assertPasswordAllowed(password, target, policy, c.context);
    const passwordHash = await originalHash(password);
    if (target.kind === "existing-user") {
      passwordWriteTargets.set(c, { userId: target.userId, passwordHash });
    }
    return passwordHash;
  };

export const createAdminCreateUserPolicyHook = (policy: ResolvedPasswordPolicy) => ({
  matcher: (context: { path?: string | undefined }): boolean => context.path === "/admin/create-user",
  handler: createAuthMiddleware(async (ctx) => {
    const body = toRecord(ctx.body);
    const password = body.password;
    if (typeof password !== "string" || password === "") {
      return;
    }
    await assertPasswordAllowed(
      password,
      {
        kind: "new-user",
        email: typeof body.email === "string" ? body.email : null,
        name: typeof body.name === "string" ? body.name : null,
      },
      policy,
      ctx.context,
    );
  }),
});
