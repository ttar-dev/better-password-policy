import { describe, it, expect } from "vitest";
import { findComplexityViolation, personalInfoTokens, isPasswordTooShort } from "../../src/complexity.ts";
import { resolvePasswordPolicyOptions } from "../../src/options.ts";
import type { PasswordPolicyOptions } from "../../src/index.ts";

const rulesFrom = (complexity?: PasswordPolicyOptions["complexity"]) => {
  const resolved = resolvePasswordPolicyOptions({ complexity }).complexity;
  if (!resolved) throw new Error("complexity rules expected");
  return resolved;
};

const allRulesOff = () =>
  rulesFrom({
    requireUppercase: false,
    requireLowercase: false,
    requireDigit: false,
    requireSymbol: false,
    rejectPersonalInfo: false,
  });

describe("findComplexityViolation with default rules", () => {
  const rules = rulesFrom();

  it("accepts a password with uppercase, lowercase and a digit", async () => {
    expect(await findComplexityViolation("Abcdefg1", rules, {})).toBeNull();
  });

  it("reports PASSWORD_MISSING_UPPERCASE when there is no uppercase letter", async () => {
    expect(await findComplexityViolation("abcdefg1", rules, {})).toBe("PASSWORD_MISSING_UPPERCASE");
  });

  it("reports PASSWORD_MISSING_LOWERCASE when there is no lowercase letter", async () => {
    expect(await findComplexityViolation("ABCDEFG1", rules, {})).toBe("PASSWORD_MISSING_LOWERCASE");
  });

  it("reports PASSWORD_MISSING_DIGIT when there is no digit", async () => {
    expect(await findComplexityViolation("Abcdefgh", rules, {})).toBe("PASSWORD_MISSING_DIGIT");
  });

  it("does not require a symbol by default", async () => {
    expect(await findComplexityViolation("Abcdefg1", rules, {})).toBeNull();
  });

  it("treats a non-ASCII uppercase letter as an uppercase letter", async () => {
    expect(await findComplexityViolation("Ábcdefg1", rules, {})).toBeNull();
  });

  it("treats a non-ASCII decimal digit as a digit", async () => {
    expect(await findComplexityViolation("Abcdefg٣", rules, {})).toBeNull();
  });
});

describe("findComplexityViolation with requireSymbol", () => {
  const rules = rulesFrom({ requireSymbol: true });

  it("reports PASSWORD_MISSING_SYMBOL for letters and digits only", async () => {
    expect(await findComplexityViolation("Abcdefg1", rules, {})).toBe("PASSWORD_MISSING_SYMBOL");
  });

  it("counts a space as a symbol", async () => {
    expect(await findComplexityViolation("Abc defg1", rules, {})).toBeNull();
  });

  it("counts punctuation as a symbol", async () => {
    expect(await findComplexityViolation("Abcdefg1!", rules, {})).toBeNull();
  });
});

describe("findComplexityViolation personal info", () => {
  const rules = rulesFrom();
  const user = { email: "john.smith@example.com", name: "Alice Wonder" };

  it("rejects a password containing an email local-part token regardless of case", async () => {
    expect(await findComplexityViolation("Xjohn1abc", rules, user)).toBe(
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
    expect(await findComplexityViolation("SMITHy1zz", rules, user)).toBe(
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("rejects a password containing a name token", async () => {
    expect(await findComplexityViolation("Xwonder1a", rules, user)).toBe(
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("ignores the email domain", async () => {
    expect(await findComplexityViolation("Example1a", rules, user)).toBeNull();
  });

  it("ignores tokens shorter than three characters", async () => {
    expect(
      await findComplexityViolation("Xjo1abcal", rules, { email: "jo@example.com", name: "Al" }),
    ).toBeNull();
  });

  it("accepts any password when no personal info is provided", async () => {
    expect(await findComplexityViolation("Xjohn1abc", rules, {})).toBeNull();
  });

  it("does not check personal info when rejectPersonalInfo is false", async () => {
    const relaxed = rulesFrom({ rejectPersonalInfo: false });
    expect(await findComplexityViolation("Xjohn1abc", relaxed, user)).toBeNull();
  });

  it("reports the earlier character-class violation before personal info", async () => {
    expect(
      await findComplexityViolation("abc", rules, { email: "abc@example.com", name: "abc" }),
    ).toBe("PASSWORD_MISSING_UPPERCASE");
  });
});

describe("findComplexityViolation with every rule off", () => {
  it("accepts a password with no character classes and no length requirement", async () => {
    expect(await findComplexityViolation("aaaa", allRulesOff(), {})).toBeNull();
  });
});

describe("personalInfoTokens", () => {
  it("splits email local-part and name into lowercase unique tokens of length three or more", () => {
    expect(
      personalInfoTokens({ email: "John.Smith+tag@Example.com", name: "Alice de Wonder" }),
    ).toEqual(["john", "smith", "tag", "alice", "wonder"]);
  });

  it("keeps each token once in first-seen order", () => {
    expect(personalInfoTokens({ email: "alice@x.com", name: "Alice Alice Bob" })).toEqual([
      "alice",
      "bob",
    ]);
  });

  it("uses the part before the last at sign as the local-part", () => {
    expect(personalInfoTokens({ email: "dave.x@y@z.com" })).toEqual(["dave"]);
  });

  it("returns an empty list when nothing is provided", () => {
    expect(personalInfoTokens({})).toEqual([]);
  });
});

describe("isPasswordTooShort", () => {
  it("is false when no minimum length is set", () => {
    expect(isPasswordTooShort("a", null)).toBe(false);
    expect(isPasswordTooShort("", null)).toBe(false);
  });

  it("is true for a password shorter than the minimum", () => {
    expect(isPasswordTooShort("abcdefg", 8)).toBe(true);
  });

  it("is false for a password exactly as long as the minimum", () => {
    expect(isPasswordTooShort("abcdefgh", 8)).toBe(false);
  });

  it("is false for a password longer than the minimum", () => {
    expect(isPasswordTooShort("abcdefghi", 8)).toBe(false);
  });

  it("measures length in UTF-16 code units so one emoji counts as two", () => {
    expect(isPasswordTooShort("😀😀", 4)).toBe(false);
    expect(isPasswordTooShort("😀😀", 5)).toBe(true);
  });
});
