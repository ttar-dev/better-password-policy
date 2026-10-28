import { describe, it, expect, afterEach } from "vitest";
import { createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import {
  createAuthRegistry,
  expectForbidden,
  DEFAULT_EMAIL,
  DEFAULT_NAME,
  DEFAULT_PASSWORD,
  GOOD_PASSWORDS,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const [, P1] = GOOD_PASSWORDS;
const TWO_HOURS = 7200;
const RENAMED = "Renamed Person";
const LIST_SESSIONS_URL = "http://localhost:3000/api/auth/list-sessions";

const positions = [
  ["bearer before passwordPolicy", "before-policy"],
  ["bearer after passwordPolicy", "after-policy"],
] as const;

const flag = (t: TestAuth, userId: string) =>
  t.auth.api.setPasswordChangeRequired({ body: { userId, required: true } });

const listSessionsOverHttp = (t: TestAuth, bearerHeaders: Headers) =>
  t.auth.handler(
    new Request(LIST_SESSIONS_URL, {
      headers: {
        authorization: bearerHeaders.get("authorization") ?? "",
        origin: "http://localhost:3000",
      },
    }),
  );

describe.each(positions)("password gate with %s", (_label, bearerPosition) => {
  it("blocks listSessions and updateUser for a flagged user with a bearer token and leaves the name unchanged", async () => {
    const t = await open({ bearerPosition });
    const user = await t.signUp();
    const bearerHeaders = await t.signInBearerHeaders(user.email, user.password);
    await flag(t, user.id);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: bearerHeaders }),
      "PASSWORD_CHANGE_REQUIRED",
    );
    await expectForbidden(
      () => t.auth.api.updateUser({ body: { name: RENAMED }, headers: bearerHeaders }),
      "PASSWORD_CHANGE_REQUIRED",
    );
    expect((await t.getUser(user.id)).name).toBe(DEFAULT_NAME);
  });

  it("blocks listSessions and updateUser for an expired password with a bearer token and leaves the name unchanged", async () => {
    const t = await open({ bearerPosition, policy: { expiration: { maxAge: 3600 } } });
    const user = await t.signUp();
    const bearerHeaders = await t.signInBearerHeaders(user.email, user.password);
    await t.backdatePassword(user.id, TWO_HOURS);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: bearerHeaders }),
      "PASSWORD_EXPIRED",
    );
    await expectForbidden(
      () => t.auth.api.updateUser({ body: { name: RENAMED }, headers: bearerHeaders }),
      "PASSWORD_EXPIRED",
    );
    expect((await t.getUser(user.id)).name).toBe(DEFAULT_NAME);
  });

  it("still blocks the same flagged user when the session arrives by cookie", async () => {
    const t = await open({ bearerPosition });
    const user = await t.signUp();
    await flag(t, user.id);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: user.headers }),
      "PASSWORD_CHANGE_REQUIRED",
    );
  });

  it("answers 403 with the JSON code PASSWORD_CHANGE_REQUIRED over HTTP for a flagged user with a bearer token", async () => {
    const t = await open({ bearerPosition });
    const user = await t.signUp();
    const bearerHeaders = await t.signInBearerHeaders(user.email, user.password);
    await flag(t, user.id);
    const response = await listSessionsOverHttp(t, bearerHeaders);
    expect(response.status).toBe(403);
    const body = (await response.json()) as { code?: string };
    expect(body.code).toBe("PASSWORD_CHANGE_REQUIRED");
  });

  it("answers 403 with the JSON code PASSWORD_EXPIRED over HTTP for an expired password with a bearer token", async () => {
    const t = await open({ bearerPosition, policy: { expiration: { maxAge: 3600 } } });
    const user = await t.signUp();
    const bearerHeaders = await t.signInBearerHeaders(user.email, user.password);
    await t.backdatePassword(user.id, TWO_HOURS);
    const response = await listSessionsOverHttp(t, bearerHeaders);
    expect(response.status).toBe(403);
    const body = (await response.json()) as { code?: string };
    expect(body.code).toBe("PASSWORD_EXPIRED");
  });

  it("lets an unflagged user with a bearer token through listSessions, updateUser and over HTTP", async () => {
    const t = await open({ bearerPosition });
    const user = await t.signUp();
    const bearerHeaders = await t.signInBearerHeaders(user.email, user.password);
    const sessions = await t.auth.api.listSessions({ headers: bearerHeaders });
    expect(sessions.length).toBeGreaterThan(0);
    await t.auth.api.updateUser({ body: { name: RENAMED }, headers: bearerHeaders });
    expect((await t.getUser(user.id)).name).toBe(RENAMED);
    const response = await listSessionsOverHttp(t, bearerHeaders);
    expect(response.status).toBe(200);
  });

  it("keeps getSession reachable for a flagged user with a bearer token", async () => {
    const t = await open({ bearerPosition });
    const user = await t.signUp();
    const bearerHeaders = await t.signInBearerHeaders(user.email, user.password);
    await flag(t, user.id);
    const session = await t.auth.api.getSession({ headers: bearerHeaders });
    expect(session?.user.id).toBe(user.id);
  });

  it("keeps changePassword reachable for a flagged user with a bearer token and unblocks routes afterwards", async () => {
    const t = await open({ bearerPosition });
    const user = await t.signUp();
    const bearerHeaders = await t.signInBearerHeaders(user.email, user.password);
    await flag(t, user.id);
    await t.auth.api.changePassword({
      body: { currentPassword: DEFAULT_PASSWORD, newPassword: P1 },
      headers: bearerHeaders,
    });
    expect((await t.getUser(user.id)).mustChangePassword).toBe(false);
    const sessions = await t.auth.api.listSessions({ headers: user.headers });
    expect(sessions.length).toBeGreaterThan(0);
  });

  it("keeps signOut reachable for a flagged user with a bearer token", async () => {
    const t = await open({ bearerPosition });
    const user = await t.signUp();
    const bearerHeaders = await t.signInBearerHeaders(user.email, user.password);
    await flag(t, user.id);
    const result = await t.auth.api.signOut({ headers: bearerHeaders });
    expect(result.success).toBe(true);
  });
});

const OTHER_EMAIL = "bob@example.com";
const OTHER_NAME = "Bob Jones";

const mixedHeaders = (cookieOwner: Headers, bearerOwner: Headers) =>
  new Headers({
    cookie: cookieOwner.get("cookie") ?? "",
    authorization: bearerOwner.get("authorization") ?? "",
  });

const mixedOverHttp = (t: TestAuth, headers: Headers) =>
  t.auth.handler(
    new Request(LIST_SESSIONS_URL, {
      headers: {
        cookie: headers.get("cookie") ?? "",
        authorization: headers.get("authorization") ?? "",
        origin: "http://localhost:3000",
      },
    }),
  );

describe.each(positions)(
  "password gate evaluates the session the endpoint uses with %s",
  (_label, bearerPosition) => {
    const openMixed = async (policy?: { expiration: { maxAge: number } }) => {
      const t = await open({ bearerPosition, ...(policy ? { policy } : {}) });
      const unflagged = await t.signUp();
      const target = await t.signUp({ email: OTHER_EMAIL, name: OTHER_NAME });
      const targetBearer = await t.signInBearerHeaders(target.email, target.password);
      return { t, unflagged, target, headers: mixedHeaders(unflagged.headers, targetBearer) };
    };

    it("blocks listSessions and updateUser when an unflagged cookie accompanies the bearer token of a flagged user", async () => {
      const { t, target, headers } = await openMixed();
      await flag(t, target.id);
      await expectForbidden(
        () => t.auth.api.listSessions({ headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      await expectForbidden(
        () => t.auth.api.updateUser({ body: { name: RENAMED }, headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      expect((await t.getUser(target.id)).name).toBe(OTHER_NAME);
    });

    it("blocks the mixed request over HTTP with 403 and the JSON code PASSWORD_CHANGE_REQUIRED", async () => {
      const { t, target, headers } = await openMixed();
      await flag(t, target.id);
      const response = await mixedOverHttp(t, headers);
      expect(response.status).toBe(403);
      const body = (await response.json()) as { code?: string };
      expect(body.code).toBe("PASSWORD_CHANGE_REQUIRED");
    });

    it("blocks listSessions and updateUser when an unexpired cookie accompanies the bearer token of an expired-password user", async () => {
      const { t, target, headers } = await openMixed({ expiration: { maxAge: 3600 } });
      await t.backdatePassword(target.id, TWO_HOURS);
      await expectForbidden(() => t.auth.api.listSessions({ headers }), "PASSWORD_EXPIRED");
      await expectForbidden(
        () => t.auth.api.updateUser({ body: { name: RENAMED }, headers }),
        "PASSWORD_EXPIRED",
      );
      expect((await t.getUser(target.id)).name).toBe(OTHER_NAME);
    });

    it("blocks the mixed request over HTTP with 403 and the JSON code PASSWORD_EXPIRED", async () => {
      const { t, target, headers } = await openMixed({ expiration: { maxAge: 3600 } });
      await t.backdatePassword(target.id, TWO_HOURS);
      const response = await mixedOverHttp(t, headers);
      expect(response.status).toBe(403);
      const body = (await response.json()) as { code?: string };
      expect(body.code).toBe("PASSWORD_EXPIRED");
    });

    it("blocks when a flagged cookie accompanies the bearer token of an unflagged user", async () => {
      const t = await open({ bearerPosition });
      const flagged = await t.signUp({ email: OTHER_EMAIL, name: OTHER_NAME });
      const unflagged = await t.signUp();
      const unflaggedBearer = await t.signInBearerHeaders(unflagged.email, unflagged.password);
      await flag(t, flagged.id);
      const headers = mixedHeaders(flagged.headers, unflaggedBearer);
      await expectForbidden(
        () => t.auth.api.listSessions({ headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      await expectForbidden(
        () => t.auth.api.updateUser({ body: { name: RENAMED }, headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      const response = await mixedOverHttp(t, headers);
      expect(response.status).toBe(403);
      const body = (await response.json()) as { code?: string };
      expect(body.code).toBe("PASSWORD_CHANGE_REQUIRED");
      expect((await t.getUser(unflagged.id)).name).toBe(DEFAULT_NAME);
      expect((await t.getUser(flagged.id)).name).toBe(OTHER_NAME);
    });

    it("guard: lets the request through when the cookie and the bearer token belong to two unflagged users and acts as the bearer user", async () => {
      const t = await open({ bearerPosition });
      const cookieOwner = await t.signUp({ email: OTHER_EMAIL, name: OTHER_NAME });
      const bearerOwner = await t.signUp();
      const bearerHeaders = await t.signInBearerHeaders(bearerOwner.email, bearerOwner.password);
      const headers = mixedHeaders(cookieOwner.headers, bearerHeaders);
      const sessions = await t.auth.api.listSessions({ headers });
      expect(sessions.length).toBeGreaterThan(0);
      expect(sessions.every((session) => session.userId === bearerOwner.id)).toBe(true);
      await t.auth.api.updateUser({ body: { name: RENAMED }, headers });
      expect((await t.getUser(bearerOwner.id)).name).toBe(RENAMED);
      expect((await t.getUser(cookieOwner.id)).name).toBe(OTHER_NAME);
      const response = await mixedOverHttp(t, headers);
      expect(response.status).toBe(200);
    });
  },
);

describe("password gate leaves bearer requests without a valid session to core", () => {
  it("answers 401 for a garbage bearer token instead of a policy error", async () => {
    const t = await open({ bearerPosition: "before-policy" });
    await t.signUp({ email: DEFAULT_EMAIL });
    const error = await t.auth.api
      .listSessions({ headers: new Headers({ authorization: "Bearer not-a-real-token" }) })
      .then(
        () => null,
        (caught: { statusCode: number }) => caught,
      );
    expect(error?.statusCode).toBe(401);
  });
});

const UPDATE_USER_URL = "http://localhost:3000/api/auth/update-user";
const ALICE_USERNAME = "alice";
const BOB_USERNAME = "bobby";
const NEW_USERNAME = "mallory3";
const renameWithUsername = { name: RENAMED, username: NEW_USERNAME };

const updateUserOverHttp = (t: TestAuth, headers: Headers, body: Record<string, string>) =>
  t.auth.handler(
    new Request(UPDATE_USER_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: headers.get("cookie") ?? "",
        authorization: headers.get("authorization") ?? "",
        origin: "http://localhost:3000",
      },
      body: JSON.stringify(body),
    }),
  );

describe.each(positions)(
  "password gate with username after passwordPolicy and %s",
  (_label, bearerPosition) => {
    const openWithUsernames = async (policy?: { expiration: { maxAge: number } }) => {
      const t = await open({
        bearerPosition,
        usernamePosition: "after-policy",
        ...(policy ? { policy } : {}),
      });
      const cookieOwner = await t.signUp({ username: ALICE_USERNAME });
      const bearerOwner = await t.signUp({
        email: OTHER_EMAIL,
        name: OTHER_NAME,
        username: BOB_USERNAME,
      });
      const bearerHeaders = await t.signInBearerHeaders(bearerOwner.email, bearerOwner.password);
      return {
        t,
        cookieOwner,
        bearerOwner,
        headers: mixedHeaders(cookieOwner.headers, bearerHeaders),
      };
    };

    const expectNothingChanged = async (
      t: TestAuth,
      cookieOwner: { id: string },
      bearerOwner: { id: string },
    ) => {
      const cookieRow = await t.getUser(cookieOwner.id);
      const bearerRow = await t.getUser(bearerOwner.id);
      expect(cookieRow.name).toBe(DEFAULT_NAME);
      expect(cookieRow.username).toBe(ALICE_USERNAME);
      expect(bearerRow.name).toBe(OTHER_NAME);
      expect(bearerRow.username).toBe(BOB_USERNAME);
    };

    it("blocks updateUser with a username through the api when the cookie belongs to a flagged user and the bearer token to an unflagged one", async () => {
      const { t, cookieOwner, bearerOwner, headers } = await openWithUsernames();
      await flag(t, cookieOwner.id);
      await expectForbidden(
        () => t.auth.api.updateUser({ body: renameWithUsername, headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      await expectNothingChanged(t, cookieOwner, bearerOwner);
    });

    it("blocks updateUser with a username over HTTP when the cookie belongs to a flagged user and the bearer token to an unflagged one", async () => {
      const { t, cookieOwner, bearerOwner, headers } = await openWithUsernames();
      await flag(t, cookieOwner.id);
      const response = await updateUserOverHttp(t, headers, {
        name: RENAMED,
        username: NEW_USERNAME,
      });
      expect(response.status).toBe(403);
      const body = (await response.json()) as { code?: string };
      expect(body.code).toBe("PASSWORD_CHANGE_REQUIRED");
      await expectNothingChanged(t, cookieOwner, bearerOwner);
    });

    it("blocks updateUser with a username through the api when the cookie belongs to an expired-password user and the bearer token to a current one", async () => {
      const { t, cookieOwner, bearerOwner, headers } = await openWithUsernames({
        expiration: { maxAge: 3600 },
      });
      await t.backdatePassword(cookieOwner.id, TWO_HOURS);
      await expectForbidden(
        () => t.auth.api.updateUser({ body: renameWithUsername, headers }),
        "PASSWORD_EXPIRED",
      );
      await expectNothingChanged(t, cookieOwner, bearerOwner);
    });

    it("blocks updateUser with a username over HTTP when the cookie belongs to an expired-password user and the bearer token to a current one", async () => {
      const { t, cookieOwner, bearerOwner, headers } = await openWithUsernames({
        expiration: { maxAge: 3600 },
      });
      await t.backdatePassword(cookieOwner.id, TWO_HOURS);
      const response = await updateUserOverHttp(t, headers, {
        name: RENAMED,
        username: NEW_USERNAME,
      });
      expect(response.status).toBe(403);
      const body = (await response.json()) as { code?: string };
      expect(body.code).toBe("PASSWORD_EXPIRED");
      await expectNothingChanged(t, cookieOwner, bearerOwner);
    });

    it("blocks updateUser with a username through the api when the bearer token belongs to a flagged user and the cookie to an unflagged one", async () => {
      const { t, cookieOwner, bearerOwner, headers } = await openWithUsernames();
      await flag(t, bearerOwner.id);
      await expectForbidden(
        () => t.auth.api.updateUser({ body: renameWithUsername, headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      await expectNothingChanged(t, cookieOwner, bearerOwner);
    });

    it("blocks updateUser with a username over HTTP when the bearer token belongs to a flagged user and the cookie to an unflagged one", async () => {
      const { t, cookieOwner, bearerOwner, headers } = await openWithUsernames();
      await flag(t, bearerOwner.id);
      const response = await updateUserOverHttp(t, headers, {
        name: RENAMED,
        username: NEW_USERNAME,
      });
      expect(response.status).toBe(403);
      const body = (await response.json()) as { code?: string };
      expect(body.code).toBe("PASSWORD_CHANGE_REQUIRED");
      await expectNothingChanged(t, cookieOwner, bearerOwner);
    });
  },
);

const memoizeSessionHook = createAuthMiddleware(async (hookContext) => {
  await getSessionFromCtx(hookContext);
});

const countSessionsOf = async (t: TestAuth, userId: string) =>
  (
    await t.adapter.findMany<{ id: string }>({
      model: "session",
      where: [{ field: "userId", value: userId }],
    })
  ).length;

describe.each(positions)(
  "password gate with a user before-hook that loads the session and %s",
  (_label, bearerPosition) => {
    it("blocks revokeSessions when a cookie accompanies the bearer token of a flagged user and leaves that user's sessions in place", async () => {
      const t = await open({ bearerPosition, userBeforeHook: memoizeSessionHook });
      const cookieOwner = await t.signUp();
      const bearerOwner = await t.signUp({ email: OTHER_EMAIL, name: OTHER_NAME });
      const bearerHeaders = await t.signInBearerHeaders(bearerOwner.email, bearerOwner.password);
      await flag(t, bearerOwner.id);
      const sessionsBefore = await countSessionsOf(t, bearerOwner.id);
      expect(sessionsBefore).toBeGreaterThan(0);
      await expectForbidden(
        () =>
          t.auth.api.revokeSessions({
            headers: mixedHeaders(cookieOwner.headers, bearerHeaders),
          }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      expect(await countSessionsOf(t, bearerOwner.id)).toBe(sessionsBefore);
    });
  },
);

describe("password gate with a session memoized by an earlier user before-hook", () => {
  it("guard: blocks when the hook memoizes a flagged user's session and the request carries an unflagged user's cookie", async () => {
    let memoizedOwnerHeaders: Headers | undefined;
    const memoizeOtherUserHook = createAuthMiddleware(async (hookContext) => {
      if (hookContext.path !== "/list-sessions" || !memoizedOwnerHeaders) return;
      hookContext.context.session = await getSessionFromCtx({
        ...hookContext,
        headers: memoizedOwnerHeaders,
      });
    });
    const t = await open({ userBeforeHook: memoizeOtherUserHook });
    const flagged = await t.signUp();
    const unflagged = await t.signUp({ email: OTHER_EMAIL, name: OTHER_NAME });
    memoizedOwnerHeaders = flagged.headers;
    await flag(t, flagged.id);
    await expectForbidden(
      () => t.auth.api.listSessions({ headers: unflagged.headers }),
      "PASSWORD_CHANGE_REQUIRED",
    );
  });
});

describe.each(positions)(
  "password gate with cookieCache and two sessions of one user and %s",
  (_label, bearerPosition) => {
    const openCachedTwoSessions = async () => {
      const t = await open({ bearerPosition, cookieCache: true });
      const user = await t.signUp();
      const secondBearer = await t.signInBearerHeaders(user.email, user.password);
      return { t, user, headers: mixedHeaders(user.headers, secondBearer) };
    };

    it("blocks listSessions and updateUser when a primed cached cookie session accompanies a fresh bearer session of the same flagged user", async () => {
      const { t, user, headers } = await openCachedTwoSessions();
      await flag(t, user.id);
      await expectForbidden(
        () => t.auth.api.listSessions({ headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      await expectForbidden(
        () => t.auth.api.updateUser({ body: { name: RENAMED }, headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      expect((await t.getUser(user.id)).name).toBe(DEFAULT_NAME);
    });

    it("guard: lets a primed cached cookie session alone through listSessions after the user is flagged", async () => {
      const { t, user } = await openCachedTwoSessions();
      await flag(t, user.id);
      const sessions = await t.auth.api.listSessions({ headers: user.headers });
      expect(sessions.length).toBeGreaterThan(0);
    });
  },
);

describe.each(positions)(
  "password gate ranks forced change above expiry across candidates with %s",
  (_label, bearerPosition) => {
    const openForcedAndExpired = async () => {
      const t = await open({ bearerPosition, policy: { expiration: { maxAge: 3600 } } });
      const expired = await t.signUp();
      const forced = await t.signUp({ email: OTHER_EMAIL, name: OTHER_NAME });
      const expiredBearer = await t.signInBearerHeaders(expired.email, expired.password);
      const forcedBearer = await t.signInBearerHeaders(forced.email, forced.password);
      await flag(t, forced.id);
      await t.backdatePassword(expired.id, TWO_HOURS);
      return { t, expired, forced, expiredBearer, forcedBearer };
    };

    it("guard: answers PASSWORD_CHANGE_REQUIRED when the cookie belongs to the forced user and the bearer token to the expired-password user", async () => {
      const { t, expired, forced, expiredBearer } = await openForcedAndExpired();
      const headers = mixedHeaders(forced.headers, expiredBearer);
      await expectForbidden(
        () => t.auth.api.listSessions({ headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      await expectForbidden(
        () => t.auth.api.updateUser({ body: { name: RENAMED }, headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      expect((await t.getUser(expired.id)).name).toBe(DEFAULT_NAME);
      expect((await t.getUser(forced.id)).name).toBe(OTHER_NAME);
    });

    it("guard: answers PASSWORD_CHANGE_REQUIRED when the cookie belongs to the expired-password user and the bearer token to the forced user", async () => {
      const { t, expired, forced, forcedBearer } = await openForcedAndExpired();
      const headers = mixedHeaders(expired.headers, forcedBearer);
      await expectForbidden(
        () => t.auth.api.listSessions({ headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      await expectForbidden(
        () => t.auth.api.updateUser({ body: { name: RENAMED }, headers }),
        "PASSWORD_CHANGE_REQUIRED",
      );
      expect((await t.getUser(expired.id)).name).toBe(DEFAULT_NAME);
      expect((await t.getUser(forced.id)).name).toBe(OTHER_NAME);
    });
  },
);
