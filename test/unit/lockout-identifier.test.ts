import { describe, it, expect } from "vitest";
import {
  signInLockoutIdentifier,
  lockoutIdentifiersForUser,
  signInUserLookup,
  usernameLookupValue,
} from "../../src/lockout.ts";

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
    const usernameNormalization = (value: string) => value.replace(/[^a-z0-9]/gi, "");
    expect(
      signInLockoutIdentifier("/sign-in/username", { username: "Al.Ice" }, { usernameNormalization }),
    ).toBe("username:alice");
  });

  it("lowercases the username when normalization is false", () => {
    expect(
      signInLockoutIdentifier("/sign-in/username", { username: "Alice" }, { usernameNormalization: false }),
    ).toBe("username:alice");
  });

  it("lowercases the doubly normalized value with pre-normalization validation order", () => {
    const usernameNormalization = (value: string) => value.replace(/^x/, "");
    expect(
      signInLockoutIdentifier(
        "/sign-in/username",
        { username: "xxAlice" },
        { usernameNormalization, validationOrder: { username: "pre-normalization" } },
      ),
    ).toBe("username:alice");
  });

  it("normalizes once with an explicit post-normalization validation order", () => {
    const usernameNormalization = (value: string) => value.replace(/^x/, "");
    expect(
      signInLockoutIdentifier(
        "/sign-in/username",
        { username: "xxAlice" },
        { usernameNormalization, validationOrder: { username: "post-normalization" } },
      ),
    ).toBe("username:xalice");
  });

  it("returns null when the normalizer empties the username", () => {
    expect(
      signInLockoutIdentifier(
        "/sign-in/username",
        { username: "..." },
        { usernameNormalization: (value: string) => value.replace(/\./g, "") },
      ),
    ).toBeNull();
  });

  it("keeps the email and phone identifiers when username options are given", () => {
    const usernameOptions = { usernameNormalization: false } as const;
    expect(signInLockoutIdentifier("/sign-in/email", { email: "Alice@Example.COM" }, usernameOptions)).toBe(
      "email:alice@example.com",
    );
    expect(
      signInLockoutIdentifier("/sign-in/phone-number", { phoneNumber: "+66812345678" }, usernameOptions),
    ).toBe("phone:+66812345678");
  });

  it.each([
    ["undefined options", undefined],
    ["empty options", {}],
    ["normalization false", { usernameNormalization: false }],
    ["normalization true", { usernameNormalization: true }],
    ["lowercasing normalizer", { usernameNormalization: (value: string) => value.toLowerCase() }],
    ["case keeping normalizer", { usernameNormalization: (value: string) => value.replace(/\./g, "") }],
    ["non-string normalizer result", { usernameNormalization: () => 7 }],
    [
      "pre-normalization with a non-idempotent normalizer",
      {
        usernameNormalization: (value: string) => value.replace(/^x/, ""),
        validationOrder: { username: "pre-normalization" },
      },
    ],
  ])("equals username: plus the lowercased lookup value for %s", (_name, usernameOptions) => {
    const body = { username: "xxAl.Ice" };
    const lookup = signInUserLookup("/sign-in/username", body, usernameOptions);
    expect(lookup).not.toBeNull();
    expect(signInLockoutIdentifier("/sign-in/username", body, usernameOptions)).toBe(
      `username:${lookup!.value.toLowerCase()}`,
    );
  });

  it("keeps the identifier of the default configuration", () => {
    expect(signInLockoutIdentifier("/sign-in/username", { username: "Alice_Smith" })).toBe(
      "username:alice_smith",
    );
    expect(signInLockoutIdentifier("/sign-in/username", { username: "Alice_Smith" }, {})).toBe(
      "username:alice_smith",
    );
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

describe("signInUserLookup", () => {
  it("lowercases the email for the email sign-in path", () => {
    expect(signInUserLookup("/sign-in/email", { email: "Alice@Example.COM" }, undefined)).toEqual({
      field: "email",
      value: "alice@example.com",
    });
  });

  it("lowercases the username when no normalization is configured", () => {
    expect(signInUserLookup("/sign-in/username", { username: "Alice" }, undefined)).toEqual({
      field: "username",
      value: "alice",
    });
  });

  it("keeps the raw username when normalization is false", () => {
    expect(signInUserLookup("/sign-in/username", { username: "Alice" }, { usernameNormalization: false })).toEqual({
      field: "username",
      value: "Alice",
    });
  });

  it("uses the normalization function result as is without lowercasing it", () => {
    const usernameNormalization = (value: string) => value.replace(".", "");
    expect(signInUserLookup("/sign-in/username", { username: "Al.Ice" }, { usernameNormalization })).toEqual({
      field: "username",
      value: "AlIce",
    });
  });

  it("lowercases the username for any other normalization value", () => {
    expect(signInUserLookup("/sign-in/username", { username: "Alice" }, { usernameNormalization: true })).toEqual({
      field: "username",
      value: "alice",
    });
  });

  it("keeps the phone number raw", () => {
    expect(signInUserLookup("/sign-in/phone-number", { phoneNumber: "+66812345678" }, undefined)).toEqual({
      field: "phoneNumber",
      value: "+66812345678",
    });
  });

  it("returns null when the identifying field is missing", () => {
    expect(signInUserLookup("/sign-in/email", {}, undefined)).toBeNull();
    expect(signInUserLookup("/sign-in/username", { email: "a@b.co" }, undefined)).toBeNull();
    expect(signInUserLookup("/sign-in/phone-number", {}, undefined)).toBeNull();
  });

  it("returns null when the identifying field is not a string", () => {
    expect(signInUserLookup("/sign-in/email", { email: 123 }, undefined)).toBeNull();
    expect(signInUserLookup("/sign-in/phone-number", { phoneNumber: null }, undefined)).toBeNull();
  });

  it("returns null when the identifying field is an empty string", () => {
    expect(signInUserLookup("/sign-in/email", { email: "" }, undefined)).toBeNull();
    expect(signInUserLookup("/sign-in/username", { username: "" }, undefined)).toBeNull();
    expect(signInUserLookup("/sign-in/phone-number", { phoneNumber: "" }, undefined)).toBeNull();
  });

  it("returns null for a path that is not a credential sign-in path", () => {
    expect(signInUserLookup("/sign-in/social", { email: "a@b.co" }, undefined)).toBeNull();
    expect(signInUserLookup("/change-password", { email: "a@b.co" }, undefined)).toBeNull();
    expect(signInUserLookup(undefined, { email: "a@b.co" }, undefined)).toBeNull();
  });
});

describe("usernameLookupValue", () => {
  it("lowercases with undefined, empty or non-object options", () => {
    expect(usernameLookupValue("Alice", undefined)).toBe("alice");
    expect(usernameLookupValue("Alice", {})).toBe("alice");
    expect(usernameLookupValue("Alice", null)).toBe("alice");
  });

  it("returns the username as typed when normalization is false", () => {
    expect(usernameLookupValue("Alice", { usernameNormalization: false })).toBe("Alice");
  });

  it("returns the result of a normalizer that keeps case", () => {
    expect(
      usernameLookupValue("Al.Ice", { usernameNormalization: (value: string) => value.replace(".", "") }),
    ).toBe("AlIce");
  });

  it("lowercases when normalization is true", () => {
    expect(usernameLookupValue("Alice", { usernameNormalization: true })).toBe("alice");
  });

  it("keeps the input when the normalizer returns something other than a string", () => {
    expect(usernameLookupValue("Alice", { usernameNormalization: () => 42 })).toBe("Alice");
    expect(usernameLookupValue("Alice", { usernameNormalization: () => undefined })).toBe("Alice");
  });

  it("applies the normalizer twice with pre-normalization validation order", () => {
    expect(
      usernameLookupValue("xxalice", {
        usernameNormalization: (value: string) => value.replace(/^x/, ""),
        validationOrder: { username: "pre-normalization" },
      }),
    ).toBe("alice");
  });

  it("applies the normalizer once with an explicit post-normalization validation order", () => {
    expect(
      usernameLookupValue("xxalice", {
        usernameNormalization: (value: string) => value.replace(/^x/, ""),
        validationOrder: { username: "post-normalization" },
      }),
    ).toBe("xalice");
  });

  it("applies the normalizer once when only the display username order is set", () => {
    expect(
      usernameLookupValue("xxalice", {
        usernameNormalization: (value: string) => value.replace(/^x/, ""),
        validationOrder: { displayUsername: "pre-normalization" },
      }),
    ).toBe("xalice");
  });

  it("lowercases twice with the default normalizer and pre-normalization", () => {
    expect(
      usernameLookupValue("ALICE", { validationOrder: { username: "pre-normalization" } }),
    ).toBe("alice");
  });

  it("does not normalize twice when normalization is false", () => {
    expect(
      usernameLookupValue("Alice", {
        usernameNormalization: false,
        validationOrder: { username: "pre-normalization" },
      }),
    ).toBe("Alice");
  });
});
