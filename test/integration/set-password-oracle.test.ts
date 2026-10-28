import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthRegistry,
  expectBadRequest,
  pause,
  GOOD_PASSWORDS,
  WEAK_NO_UPPERCASE,
} from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const [P0, P1, , P3] = GOOD_PASSWORDS;
const policy = { history: { count: 2 } };

const setPasswordAs = (t: TestAuth, headers: Headers, newPassword: string) =>
  t.auth.api.setPassword({ body: { newPassword }, headers });

describe("setPassword for a user who already has a password", () => {
  const openUserWithHistory = async () => {
    const t = await open({ policy });
    const user = await t.signUp({ password: P0 });
    await pause();
    await t.auth.api.changePassword({
      body: { currentPassword: P0, newPassword: P1 },
      headers: user.headers,
    });
    const historyBefore = await t.historyRows(user.id);
    return { t, user, historyBefore };
  };

  it.each([
    ["the current password", P1],
    ["a previous history password", P0],
    ["a weak password", WEAK_NO_UPPERCASE],
    ["a fresh strong password", P3],
  ])("answers 400 PASSWORD_ALREADY_SET for %s and records no history row", async (_label, candidate) => {
    const { t, user, historyBefore } = await openUserWithHistory();
    await expectBadRequest(() => setPasswordAs(t, user.headers, candidate), "PASSWORD_ALREADY_SET");
    expect(await t.historyRows(user.id)).toHaveLength(historyBefore.length);
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${P1}`);
  });

  it("answers identically for a guessed history password and for a fresh password", async () => {
    const { t, user } = await openUserWithHistory();
    const guessed = await expectBadRequest(
      () => setPasswordAs(t, user.headers, P0),
      "PASSWORD_ALREADY_SET",
    );
    const fresh = await expectBadRequest(
      () => setPasswordAs(t, user.headers, P3),
      "PASSWORD_ALREADY_SET",
    );
    expect(guessed.body?.message).toBe(fresh.body?.message);
  });
});

describe("setPassword for a user without a password", () => {
  it("rejects a weak password with the complexity code and records no history row", async () => {
    const t = await open({ policy });
    const user = await t.createSessionOnlyUser("sam@example.com", "Sam Setter");
    await expectBadRequest(
      () => setPasswordAs(t, user.headers, WEAK_NO_UPPERCASE),
      "PASSWORD_MISSING_UPPERCASE",
    );
    expect(await t.historyRows(user.id)).toHaveLength(0);
  });

  it("accepts a strong password and records a history row", async () => {
    const t = await open({ policy });
    const user = await t.createSessionOnlyUser("sam@example.com", "Sam Setter");
    const result = await setPasswordAs(t, user.headers, P3);
    expect(result.status).toBe(true);
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${P3}`);
    const rows = await t.historyRows(user.id);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.passwordHash).toBe(`fast:${P3}`);
  });
});
