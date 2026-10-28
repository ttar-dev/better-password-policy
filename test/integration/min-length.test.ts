import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthRegistry,
  expectBadRequest,
  DEFAULT_PASSWORD,
} from "../harness/create-test-auth.ts";

const registry = createAuthRegistry();
const { open } = registry;
afterEach(async () => {
  await registry.closeAll();
});

const policy = { complexity: { minLength: 12 } };
const TOO_SHORT = "Abcdefgh12";
const EXACT = "Abcdefgh1234";
const SHORT_WITHOUT_UPPERCASE = "abcdefgh12";
const ORIGINAL_HASH = `fast:${DEFAULT_PASSWORD}`;
const NEW_EMAIL = "nina@example.com";

describe("platform complexity.minLength", () => {
  it("rejects a shorter password on sign-up with PASSWORD_TOO_SHORT and creates no user", async () => {
    const t = await open({ policy });
    await expectBadRequest(
      () =>
        t.auth.api.signUpEmail({
          body: { email: NEW_EMAIL, name: "Nina Park", password: TOO_SHORT },
        }),
      "PASSWORD_TOO_SHORT",
    );
    expect(await t.context.internalAdapter.findUserByEmail(NEW_EMAIL)).toBeNull();
  });

  it("accepts a password with exactly minLength characters on sign-up", async () => {
    const t = await open({ policy });
    const result = await t.auth.api.signUpEmail({
      body: { email: NEW_EMAIL, name: "Nina Park", password: EXACT },
    });
    expect(result.user.email).toBe(NEW_EMAIL);
  });

  it("rejects a shorter password on change-password and leaves the stored hash unchanged", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await expectBadRequest(
      () =>
        t.auth.api.changePassword({
          body: { currentPassword: DEFAULT_PASSWORD, newPassword: TOO_SHORT },
          headers: user.headers,
        }),
      "PASSWORD_TOO_SHORT",
    );
    expect((await t.getCredentialAccount(user.id)).password).toBe(ORIGINAL_HASH);
  });

  it("accepts a password with exactly minLength characters on change-password", async () => {
    const t = await open({ policy });
    const user = await t.signUp();
    await t.auth.api.changePassword({
      body: { currentPassword: DEFAULT_PASSWORD, newPassword: EXACT },
      headers: user.headers,
    });
    expect((await t.getCredentialAccount(user.id)).password).toBe(`fast:${EXACT}`);
  });

  it("rejects a shorter password on admin create-user and creates no user", async () => {
    const t = await open({ policy });
    await expectBadRequest(
      () =>
        t.auth.api.createUser({
          body: { email: "made@example.com", password: TOO_SHORT, name: "Made Up", role: "user" },
        }),
      "PASSWORD_TOO_SHORT",
    );
    expect(await t.context.internalAdapter.findUserByEmail("made@example.com")).toBeNull();
  });

  it("accepts a password with exactly minLength characters on admin create-user", async () => {
    const t = await open({ policy });
    const created = await t.auth.api.createUser({
      body: { email: "made@example.com", password: EXACT, name: "Made Up", role: "user" },
    });
    expect(created.user.email).toBe("made@example.com");
  });

  it("checks length before character classes so a short password without uppercase gets PASSWORD_TOO_SHORT", async () => {
    const t = await open({ policy });
    await expectBadRequest(
      () =>
        t.auth.api.signUpEmail({
          body: { email: NEW_EMAIL, name: "Nina Park", password: SHORT_WITHOUT_UPPERCASE },
        }),
      "PASSWORD_TOO_SHORT",
    );
  });

  it("does not apply minLength when complexity is switched off", async () => {
    const t = await open({ policy: { complexity: false } });
    const result = await t.auth.api.signUpEmail({
      body: { email: NEW_EMAIL, name: "Nina Park", password: "abcdefgh" },
    });
    expect(result.user.email).toBe(NEW_EMAIL);
  });
});
