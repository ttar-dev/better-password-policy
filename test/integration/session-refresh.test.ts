import { describe, it, expect, afterEach } from "vitest";
import { createAuthRegistry } from "../harness/create-test-auth.ts";
import type { TestAuth, TestAuthOptions } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const SESSION_COOKIE_PREFIX = "better-auth.session_token=";
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

const dueSessionHeadersFor = async (options: TestAuthOptions) => {
  const t = await open(options);
  const user = await t.signUp();
  const nearExpiry = new Date(Date.now() + ONE_DAY_MS);
  const sessions = await t.adapter.findMany<{ id: string }>({ model: "session" });
  for (const session of sessions) {
    await t.adapter.update({
      model: "session",
      where: [{ field: "id", value: session.id }],
      update: { expiresAt: nearExpiry },
    });
  }
  return { t, user, nearExpiry };
};

const refreshedCookieOf = async (t: TestAuth, headers: Headers) => {
  const result = await t.auth.api.listSessions({ headers, returnHeaders: true });
  return result.headers.getSetCookie().find((entry) => entry.startsWith(SESSION_COOKIE_PREFIX));
};

describe("session refresh through a gated endpoint", () => {
  it("control: an instance without the plugin re-issues the session cookie when the session is due for refresh", async () => {
    const { t, user } = await dueSessionHeadersFor({ withoutPolicy: true });
    expect(await refreshedCookieOf(t, user.headers)).toBeDefined();
  });

  it("re-issues the session cookie on a non-exempt endpoint when the session is due for refresh", async () => {
    const { t, user } = await dueSessionHeadersFor({});
    const cookie = await refreshedCookieOf(t, user.headers);
    expect(cookie).toBeDefined();
  });

  it("extends the stored session expiry when the session is due for refresh", async () => {
    const { t, user, nearExpiry } = await dueSessionHeadersFor({});
    await refreshedCookieOf(t, user.headers);
    const [session] = await t.adapter.findMany<{ expiresAt: Date }>({ model: "session" });
    expect(session!.expiresAt.getTime()).toBeGreaterThan(nearExpiry.getTime() + ONE_DAY_MS);
  });

  it("does not re-issue the session cookie when the session is not due for refresh", async () => {
    const t = await open({});
    const user = await t.signUp();
    expect(await refreshedCookieOf(t, user.headers)).toBeUndefined();
  });
});

const MIXED_OWNER_EMAIL = "bob@example.com";
const MIXED_OWNER_NAME = "Bob Jones";

const sessionExpiries = async (t: TestAuth, userId: string) =>
  (
    await t.adapter.findMany<{ id: string; token: string; expiresAt: Date }>({
      model: "session",
      where: [{ field: "userId", value: userId }],
    })
  ).map((session) => ({ token: session.token, expiresAt: session.expiresAt.getTime() }));

const plainTokenOf = (signedValue: string) => decodeURIComponent(signedValue).split(".")[0];

describe.each([
  ["bearer before passwordPolicy", "before-policy"],
  ["bearer after passwordPolicy", "after-policy"],
] as const)("session refresh when another user's cookie accompanies a bearer token with %s", (_label, bearerPosition) => {
  it("guard: refreshes only the bearer session when another user's cookie is also sent", async () => {
    const t = await open({ bearerPosition });
    const cookieOwner = await t.signUp();
    const bearerOwner = await t.signUp({ email: MIXED_OWNER_EMAIL, name: MIXED_OWNER_NAME });
    const bearerHeaders = await t.signInBearerHeaders(bearerOwner.email, bearerOwner.password);
    const nearExpiry = new Date(Date.now() + ONE_DAY_MS);
    const sessions = await t.adapter.findMany<{ id: string }>({ model: "session" });
    for (const session of sessions) {
      await t.adapter.update({
        model: "session",
        where: [{ field: "id", value: session.id }],
        update: { expiresAt: nearExpiry },
      });
    }
    const bearerToken = plainTokenOf((bearerHeaders.get("authorization") ?? "").slice("Bearer ".length));

    const result = await t.auth.api.listSessions({
      headers: new Headers({
        cookie: cookieOwner.headers.get("cookie") ?? "",
        authorization: bearerHeaders.get("authorization") ?? "",
      }),
      returnHeaders: true,
    });

    const sessionCookies = result.headers
      .getSetCookie()
      .filter((entry) => entry.startsWith(SESSION_COOKIE_PREFIX));
    expect(sessionCookies).toHaveLength(1);
    const cookieValue = sessionCookies[0]!.slice(SESSION_COOKIE_PREFIX.length).split(";")[0]!;
    expect(plainTokenOf(cookieValue)).toBe(bearerToken);
    expect(result.headers.get("set-auth-token")).toBeTruthy();
    for (const session of await sessionExpiries(t, cookieOwner.id)) {
      expect(session.expiresAt).toBe(nearExpiry.getTime());
    }
    const refreshed = (await sessionExpiries(t, bearerOwner.id)).find(
      (session) => session.token === bearerToken,
    );
    expect(refreshed!.expiresAt).toBeGreaterThan(nearExpiry.getTime() + ONE_DAY_MS);
  });
});
