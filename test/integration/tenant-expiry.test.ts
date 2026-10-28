import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthRegistry,
  expectForbidden,
  expectServiceUnavailable,
  pause,
  DEFAULT_PASSWORD,
  GOOD_PASSWORDS,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";
import type { TenantPasswordPolicyContext, TenantPasswordPolicyResolver } from "../../src/index.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const [, P1] = GOOD_PASSWORDS;
const DAY = 86400;

type Decider = (context: TenantPasswordPolicyContext) => unknown;

const createProbe = (initial: Decider) => {
  const calls: TenantPasswordPolicyContext[] = [];
  let decide = initial;
  const tenantPolicy = ((context: TenantPasswordPolicyContext) => {
    calls.push(context);
    return decide(context);
  }) as TenantPasswordPolicyResolver;
  return {
    calls,
    tenantPolicy,
    decideWith: (next: Decider) => {
      decide = next;
    },
  };
};

const maxAgeForTenantUser = (userIds: () => string[], maxAge: number): Decider =>
  (context) => (context.user && userIds().includes(context.user.id) ? { expiration: { maxAge } } : null);

const everyone = (maxAge: number): Decider => () => ({ expiration: { maxAge } });

const flag = (t: TestAuth, userId: string, required: boolean) =>
  t.auth.api.setPasswordChangeRequired({ body: { userId, required } });

const expectExpired = (t: TestAuth, headers: Headers) =>
  expectForbidden(() => t.auth.api.listSessions({ headers }), "PASSWORD_EXPIRED");

describe("tenant expiration without a platform expiration", () => {
  it("blocks a tenant user whose password is older than the tenant maxAge", async () => {
    let tenantId = "";
    const probe = createProbe(maxAgeForTenantUser(() => [tenantId], DAY));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    tenantId = user.id;
    await t.backdatePassword(user.id, 2 * DAY);
    await expectExpired(t, user.headers);
  });

  it("does not block a user without a tenant override", async () => {
    let tenantId = "";
    const probe = createProbe(maxAgeForTenantUser(() => [tenantId], DAY));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const tenantUser = await t.signUp();
    tenantId = tenantUser.id;
    const other = await t.signUp({ email: "bob@example.com", name: "Bob Jones" });
    await t.backdatePassword(other.id, 2 * DAY);
    const sessions = await t.auth.api.listSessions({ headers: other.headers });
    expect(sessions.length).toBeGreaterThan(0);
  });

  it("unblocks the tenant user once the password is changed", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.decideWith(everyone(DAY));
    await t.backdatePassword(user.id, 2 * DAY);
    await expectExpired(t, user.headers);
    await pause();
    await t.auth.api.changePassword({
      body: { currentPassword: DEFAULT_PASSWORD, newPassword: P1 },
      headers: user.headers,
    });
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
  });
});

describe("tenant expiration with a platform expiration", () => {
  it("blocks a password older than the platform maxAge even when the tenant allows longer", async () => {
    const probe = createProbe(everyone(60 * DAY));
    const t = await open({
      policy: { tenantPolicy: probe.tenantPolicy, expiration: { maxAge: 30 * DAY } },
    });
    const user = await t.signUp();
    await t.backdatePassword(user.id, 31 * DAY);
    await expectExpired(t, user.headers);
  });

  it("blocks a password older than the tenant maxAge even when the platform allows longer", async () => {
    const probe = createProbe(everyone(DAY));
    const t = await open({
      policy: { tenantPolicy: probe.tenantPolicy, expiration: { maxAge: 30 * DAY } },
    });
    const user = await t.signUp();
    await t.backdatePassword(user.id, 2 * DAY);
    await expectExpired(t, user.headers);
  });
});

describe("tenant expiration with platform expiration switched off", () => {
  it("never blocks, reports no expiry and never calls the callback on gated routes", async () => {
    const probe = createProbe(everyone(DAY));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy, expiration: false } });
    const user = await t.signUp();
    await t.backdatePassword(user.id, 2 * DAY);
    probe.calls.length = 0;
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
    expect(probe.calls).toHaveLength(0);
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.passwordExpiresAt).toBeNull();
    expect(status.passwordChangeRequirement).toBeNull();
    expect(status.policy.expiration).toBeNull();
  });
});

describe("tenant expiration when the callback fails or is not needed", () => {
  it("keeps answering PASSWORD_CHANGE_REQUIRED for a forced user even when the callback throws", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    await flag(t, user.id, true);
    probe.decideWith(() => {
      throw new Error("tenant store down");
    });
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: user.headers }),
      "PASSWORD_CHANGE_REQUIRED",
    );
  });

  it("answers 503 PASSWORD_POLICY_UNAVAILABLE on a gated route when the callback throws", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.decideWith(() => {
      throw new Error("tenant store down");
    });
    await expectServiceUnavailable(
      () => t.auth.api.listSessions({ headers: user.headers }),
      "PASSWORD_POLICY_UNAVAILABLE",
    );
  });

  it("answers 503 on a gated route when the callback returns an invalid override", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.decideWith(() => ({ expiration: { maxAge: 60 } }));
    await expectServiceUnavailable(
      () => t.auth.api.listSessions({ headers: user.headers }),
      "PASSWORD_POLICY_UNAVAILABLE",
    );
  });

  it("keeps getSession reachable when the callback throws", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.decideWith(() => {
      throw new Error("tenant store down");
    });
    const session = await t.auth.api.getSession({ headers: user.headers });
    expect(session?.user.id).toBe(user.id);
  });

  it("does not block and does not call the callback when passwordChangedAt is null", async () => {
    const probe = createProbe(everyone(DAY));
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    await t.updateUserRow(user.id, { passwordChangedAt: null });
    probe.calls.length = 0;
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
    expect(probe.calls).toHaveLength(0);
  });
});

describe("tenant expiration callback context", () => {
  it("calls the callback once per gated request with the session user and the gated path", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.calls.length = 0;
    await t.auth.api.listSessions({ headers: user.headers });
    expect(probe.calls).toHaveLength(1);
    expect(probe.calls[0]?.user?.id).toBe(user.id);
    expect(probe.calls[0]?.email).toBe(user.email);
    expect(probe.calls[0]?.path).toBe("/list-sessions");
  });
});

describe("tenant expiration in the status", () => {
  it("derives passwordExpiresAt from the tenant maxAge and reports expired", async () => {
    const probe = createProbe(() => null);
    const t = await open({ policy: { tenantPolicy: probe.tenantPolicy } });
    const user = await t.signUp();
    probe.decideWith(everyone(DAY));
    await t.backdatePassword(user.id, 2 * DAY);
    const changedAt = (await t.getUser(user.id)).passwordChangedAt!;
    const status = await t.auth.api.getPasswordPolicyStatus({ query: { userId: user.id } });
    expect(status.passwordExpiresAt?.getTime()).toBe(changedAt.getTime() + DAY * 1000);
    expect(status.passwordChangeRequirement).toBe("expired");
    expect(status.policy.expiration).toEqual({ maxAge: DAY });
  });
});
