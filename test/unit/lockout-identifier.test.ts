import { describe, it, expect } from "vitest";
import { signInLockoutIdentifier, lockoutIdentifiersForUser } from "../../src/lockout.ts";

describe("signInLockoutIdentifier", () => {
  it("lowercases the email for the email sign-in path", () => {
    expect(signInLockoutIdentifier("/sign-in/email", { email: "Alice@Example.COM" })).toBe(
      "email:alice@example.com",
    );
  });

  it("lowercases the username when no normalizer is given", () => {
    expect(signInLockoutIdentifier("/sign-in/username", { username: "Alice" })).toBe(
      "username:alice",
    );
  });

  it("applies the username normalizer and then lowercases the result", () => {
    const normalizer = (value: string) => value.replace(/[^a-z0-9]/gi, "");
    expect(
      signInLockoutIdentifier("/sign-in/username", { username: "Al.Ice" }, normalizer),
    ).toBe("username:alice");
  });

  it("keeps the phone number raw", () => {
    expect(
      signInLockoutIdentifier("/sign-in/phone-number", { phoneNumber: "+66812345678" }),
    ).toBe("phone:+66812345678");
  });

  it("returns null when the identifying field is missing", () => {
    expect(signInLockoutIdentifier("/sign-in/email", {})).toBeNull();
    expect(signInLockoutIdentifier("/sign-in/username", { email: "a@b.co" })).toBeNull();
    expect(signInLockoutIdentifier("/sign-in/phone-number", {})).toBeNull();
  });

  it("returns null when the identifying field is not a string", () => {
    expect(signInLockoutIdentifier("/sign-in/email", { email: 123 })).toBeNull();
    expect(signInLockoutIdentifier("/sign-in/username", { username: { value: "a" } })).toBeNull();
    expect(signInLockoutIdentifier("/sign-in/phone-number", { phoneNumber: null })).toBeNull();
  });

  it("returns null when the identifying field is an empty string", () => {
    expect(signInLockoutIdentifier("/sign-in/email", { email: "" })).toBeNull();
    expect(signInLockoutIdentifier("/sign-in/username", { username: "" })).toBeNull();
    expect(signInLockoutIdentifier("/sign-in/phone-number", { phoneNumber: "" })).toBeNull();
  });

  it("returns null for a path that is not a credential sign-in path", () => {
    expect(signInLockoutIdentifier("/sign-in/social", { email: "a@b.co" })).toBeNull();
    expect(signInLockoutIdentifier("/change-password", { email: "a@b.co" })).toBeNull();
  });
});

describe("lockoutIdentifiersForUser", () => {
  it("lists email, username and phone identifiers in that order", () => {
    expect(
      lockoutIdentifiersForUser({ email: "a@b.co", username: "Alice", phoneNumber: "+1" }),
    ).toEqual(["email:a@b.co", "username:alice", "phone:+1"]);
  });

  it("lowercases the email", () => {
    expect(lockoutIdentifiersForUser({ email: "A@B.Co" })).toEqual(["email:a@b.co"]);
  });

  it("omits identifiers the user does not have", () => {
    expect(lockoutIdentifiersForUser({ email: "a@b.co" })).toEqual(["email:a@b.co"]);
    expect(
      lockoutIdentifiersForUser({ email: "a@b.co", username: null, phoneNumber: null }),
    ).toEqual(["email:a@b.co"]);
    expect(lockoutIdentifiersForUser({ email: "a@b.co", phoneNumber: "+1" })).toEqual([
      "email:a@b.co",
      "phone:+1",
    ]);
  });
});
