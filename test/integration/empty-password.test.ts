import { describe, it, expect, afterEach } from "vitest";
import { createAuthRegistry, GOOD_PASSWORDS } from "../harness/create-test-auth.ts";
import type { TestAuth } from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const [, P1] = GOOD_PASSWORDS;
const policy = { history: { count: 2 } };

const blankCredentialPassword = async (t: TestAuth, userId: string) => {
  await t.adapter.update({
    model: "account",
    where: [
      { field: "userId", value: userId },
      { field: "providerId", value: "credential" },
    ],
    update: { password: "" },
  });
  expect((await t.getCredentialAccount(userId)).password).toBe("");
};

const expectStoredScryptHash = async (t: TestAuth, userId: string) => {
  const stored = (await t.getCredentialAccount(userId)).password;
  expect(stored).toBeTruthy();
  expect(stored).not.toBe("");
  expect(stored).toContain(":");
  return stored as string;
};

describe("empty-string credential password is treated like no password with history and the real hasher", () => {
  it("lets setPassword succeed and records a history row", async () => {
    const t = await open({ realHasher: true, policy });
    const user = await t.signUp();
    await blankCredentialPassword(t, user.id);
    const result = await t.auth.api.setPassword({ body: { newPassword: P1 }, headers: user.headers });
    expect(result.status).toBe(true);
    const stored = await expectStoredScryptHash(t, user.id);
    const rows = await t.historyRows(user.id);
    expect(rows.map((row) => row.passwordHash)).toContain(stored);
  });

  it("lets admin setUserPassword succeed", async () => {
    const t = await open({ realHasher: true, policy });
    const user = await t.signUp();
    const admin = await t.createAdmin();
    await blankCredentialPassword(t, user.id);
    const result = await t.auth.api.setUserPassword({
      body: { userId: user.id, newPassword: P1 },
      headers: admin.headers,
    });
    expect(result.status).toBe(true);
    await expectStoredScryptHash(t, user.id);
  });

  it("lets reset-password with a valid token succeed", async () => {
    const t = await open({ realHasher: true, policy });
    const user = await t.signUp();
    await blankCredentialPassword(t, user.id);
    const token = await t.requestResetToken(user.email);
    const result = await t.auth.api.resetPassword({ body: { newPassword: P1, token } });
    expect(result.status).toBe(true);
    await expectStoredScryptHash(t, user.id);
  });
});
