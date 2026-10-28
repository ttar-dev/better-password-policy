import type { AuthContext } from "@better-auth/core";
import { APIError } from "better-auth/api";
import { PASSWORD_POLICY_ERROR_CODES } from "./error-codes.ts";
import type {
  ResolvedPasswordPolicy,
  TenantPasswordPolicyContext,
  TenantPasswordPolicyResolver,
  TenantPasswordPolicyUser,
} from "./options.ts";
import { readString, toRecord } from "./record.ts";
import { mergeTenantPasswordPolicy, validateTenantPasswordPolicyOverride } from "./tenant-policy.ts";

export type PolicySubject =
  | { kind: "user"; record: Record<string, unknown> }
  | { kind: "user-id"; userId: string }
  | { kind: "anonymous"; email: string | null };

export interface PolicyEndpointContext {
  context: object;
  path?: string | undefined;
  headers?: Headers | undefined;
  request?: Request | undefined;
}

export interface PolicyResolutionScope {
  authContext: Pick<AuthContext, "logger" | "internalAdapter">;
  endpoint: PolicyEndpointContext | null;
}

export interface EffectivePolicyResolver {
  readonly base: ResolvedPasswordPolicy;
  readonly tenantAware: boolean;
  resolve(scope: PolicyResolutionScope, subject: PolicySubject): Promise<ResolvedPasswordPolicy>;
}

export const tenantPolicyUnavailable = () =>
  APIError.from("SERVICE_UNAVAILABLE", PASSWORD_POLICY_ERROR_CODES.PASSWORD_POLICY_UNAVAILABLE);

const memoKeyOf = (subject: PolicySubject): string | null => {
  switch (subject.kind) {
    case "anonymous":
      return `anonymous:${subject.email ?? ""}`;
    case "user-id":
      return `user:${subject.userId}`;
    case "user": {
      const id = readString(subject.record, "id");
      return id === null ? null : `user:${id}`;
    }
  }
};

const toPolicyUser = (record: Record<string, unknown>): TenantPasswordPolicyUser => ({
  ...record,
  id: readString(record, "id") ?? "",
  email: readString(record, "email") ?? "",
  name: readString(record, "name") ?? "",
});

const isTenantAware = (base: ResolvedPasswordPolicy, tenantPolicy: TenantPasswordPolicyResolver | null): boolean =>
  tenantPolicy !== null &&
  (base.complexity !== null || base.historyCount !== null || !base.expirationDisabled || base.lockout !== null);

export const createEffectivePolicyResolver = (
  base: ResolvedPasswordPolicy,
  tenantPolicy: TenantPasswordPolicyResolver | null,
): EffectivePolicyResolver => {
  const tenantAware = isTenantAware(base, tenantPolicy);
  const memo = new WeakMap<object, Map<string, Promise<ResolvedPasswordPolicy>>>();

  const failClosed = (scope: PolicyResolutionScope, message: string, detail: unknown) => {
    scope.authContext.logger.error(message, detail);
    return tenantPolicyUnavailable();
  };

  const loadUserRecord = async (
    scope: PolicyResolutionScope,
    subject: PolicySubject,
  ): Promise<Record<string, unknown> | null> => {
    if (subject.kind === "anonymous") {
      return null;
    }
    if (subject.kind === "user") {
      return subject.record;
    }
    let found: unknown;
    try {
      found = await scope.authContext.internalAdapter.findUserById(subject.userId);
    } catch (error) {
      throw failClosed(scope, "password-policy: failed to load the user for tenantPolicy", error);
    }
    if (!found) {
      throw failClosed(scope, "password-policy: user for tenantPolicy was not found", subject.userId);
    }
    return toRecord(found);
  };

  const compute = async (scope: PolicyResolutionScope, subject: PolicySubject): Promise<ResolvedPasswordPolicy> => {
    if (tenantPolicy === null) {
      return base;
    }
    const record = await loadUserRecord(scope, subject);
    const user = record === null ? null : toPolicyUser(record);
    const email =
      user !== null ? (user.email === "" ? null : user.email) : subject.kind === "anonymous" ? subject.email : null;
    const context: TenantPasswordPolicyContext = {
      user,
      email,
      path: scope.endpoint?.path ?? null,
      headers: scope.endpoint?.headers ? new Headers(scope.endpoint.headers) : null,
      request: scope.endpoint?.request ?? null,
    };
    let override: unknown;
    try {
      override = await tenantPolicy(context);
    } catch (error) {
      throw failClosed(scope, "password-policy: tenantPolicy failed", error);
    }
    if (override === null || override === undefined) {
      return base;
    }
    const validated = validateTenantPasswordPolicyOverride(override);
    if (!validated.success) {
      throw failClosed(scope, "password-policy: tenantPolicy returned an invalid override", validated.issues);
    }
    return mergeTenantPasswordPolicy(base, validated.data);
  };

  const resolve = (scope: PolicyResolutionScope, subject: PolicySubject): Promise<ResolvedPasswordPolicy> => {
    if (!tenantAware) {
      return Promise.resolve(base);
    }
    const key = memoKeyOf(subject);
    if (scope.endpoint === null || key === null) {
      return compute(scope, subject);
    }
    let perRequest = memo.get(scope.endpoint.context);
    if (perRequest === undefined) {
      perRequest = new Map();
      memo.set(scope.endpoint.context, perRequest);
    }
    const cached = perRequest.get(key);
    if (cached !== undefined) {
      return cached;
    }
    const pending = compute(scope, subject);
    perRequest.set(key, pending);
    return pending;
  };

  return { base, tenantAware, resolve };
};
