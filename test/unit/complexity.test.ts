import { describe, it, expect } from "vitest";
import { findComplexityViolation, personalInfoTokens, isPasswordTooShort } from "../../src/complexity.ts";
import { resolvePasswordPolicyOptions } from "../../src/options.ts";
import type { PasswordComplexityOptions, PasswordPolicyOptions } from "../../src/index.ts";

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

const THAI_PASSWORD = "\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19\u0e44\u0e17\u0e22123";
const THAI_WORD_WITH_MARKS = "\u0e01\u0e48\u0e2d\u0e19";
const THAI_NAME = "\u0e13\u0e31\u0e10\u0e27\u0e38\u0e12\u0e34";
const THAI_NAME_FIRST = "\u0e13\u0e31\u0e10";
const THAI_NAME_LAST = "\u0e27\u0e38\u0e12\u0e34";
const THAI_DIGITS = "\u0e51\u0e52\u0e53";
const HAN_PASSWORD = "\u5bc6\u7801\u5bc6\u7801\u5bc6\u78011";
const HEBREW_PASSWORD = "\u05e9\u05dc\u05d5\u05dd\u05e9\u05dc\u05d5\u05dd1";
const ARABIC_PASSWORD = "\u0645\u0631\u062d\u0628\u0627\u0645\u0631\u062d\u0628\u06271";
const THAI_MAI_YAMOK_PASSWORD = "\u0e46\u0e46\u0e46\u0e46\u0e46123";
const COMBINING_ACUTE = "\u0301";
const THAI_TONE_MARK = "\u0e48";
const DOTTED_CAPITAL_I = "\u0130";
const DOTLESS_SMALL_I = "\u0131";
const KEYCAP_SEQUENCE = "1\ufe0f\u20e3";

const rulesWithCaseless = (
  caselessLettersSatisfyCase: boolean,
  complexity: PasswordComplexityOptions = {},
) => rulesFrom({ ...complexity, caselessLettersSatisfyCase });

const symbolOnlyRules = () =>
  rulesFrom({
    requireUppercase: false,
    requireLowercase: false,
    requireDigit: false,
    requireSymbol: true,
    rejectPersonalInfo: false,
  });

const personalInfoOnlyRules = () =>
  rulesFrom({ requireUppercase: false, requireLowercase: false, requireDigit: false });

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

describe("findComplexityViolation requireSymbol with combining marks and non-Latin scripts", () => {
  const rules = symbolOnlyRules();

  it("does not count Thai vowel and tone marks as symbols", async () => {
    expect(await findComplexityViolation(THAI_WORD_WITH_MARKS, rules, {})).toBe(
      "PASSWORD_MISSING_SYMBOL",
    );
  });

  it("accepts the same Thai text once an ASCII symbol is added", async () => {
    expect(await findComplexityViolation(`${THAI_WORD_WITH_MARKS}!`, rules, {})).toBeNull();
  });

  it.each([
    ["a Thai baht sign", "\u0e3f"],
    ["a space", " "],
  ])("still counts %s as a symbol", async (_name, symbol) => {
    expect(await findComplexityViolation(`\u0e01${symbol}`, rules, {})).toBeNull();
  });

  it("does not count a precomposed accented letter as a symbol", async () => {
    expect(await findComplexityViolation("\u00e9", rules, {})).toBe("PASSWORD_MISSING_SYMBOL");
  });

  it("does not count a letter followed by a combining accent as a symbol", async () => {
    expect(await findComplexityViolation(`e${COMBINING_ACUTE}`, rules, {})).toBe(
      "PASSWORD_MISSING_SYMBOL",
    );
  });

  it("does not count Thai digits as symbols", async () => {
    expect(await findComplexityViolation(THAI_DIGITS, rules, {})).toBe("PASSWORD_MISSING_SYMBOL");
  });

  it("counts an enclosing keycap mark as a symbol", async () => {
    expect(await findComplexityViolation(`Pass${KEYCAP_SEQUENCE}word`, rules, {})).toBeNull();
  });

  it("counts a bare enclosing mark after a letter as a symbol", async () => {
    expect(await findComplexityViolation("a\u20e3", rules, {})).toBeNull();
  });
});

describe("findComplexityViolation with caselessLettersSatisfyCase", () => {
  it.each([
    [false, "PASSWORD_MISSING_UPPERCASE"],
    [true, null],
  ])("Thai-only password with option %s gives %s", async (option, expected) => {
    expect(await findComplexityViolation(THAI_PASSWORD, rulesWithCaseless(option), {})).toBe(expected);
  });

  it("treats an omitted option like false", async () => {
    expect(await findComplexityViolation(THAI_PASSWORD, rulesFrom(), {})).toBe(
      "PASSWORD_MISSING_UPPERCASE",
    );
  });

  it.each([
    [false, "PASSWORD_MISSING_LOWERCASE"],
    [true, null],
  ])("Thai-only password with only requireLowercase and option %s gives %s", async (option, expected) => {
    const rules = rulesWithCaseless(option, { requireUppercase: false });
    expect(await findComplexityViolation(THAI_PASSWORD, rules, {})).toBe(expected);
  });

  it.each([
    [false, "PASSWORD_MISSING_UPPERCASE"],
    [true, null],
  ])("lowercase Latin plus a Thai letter with option %s gives %s", async (option, expected) => {
    expect(
      await findComplexityViolation("abc\u0e44\u0e17\u0e221", rulesWithCaseless(option), {}),
    ).toBe(expected);
  });

  it("does not let a caseless letter replace the digit requirement", async () => {
    expect(
      await findComplexityViolation("\u0e44\u0e17\u0e22\u0e44\u0e17\u0e22", rulesWithCaseless(true), {}),
    ).toBe("PASSWORD_MISSING_DIGIT");
  });

  it("still reports a missing uppercase for lowercase Latin and digits only", async () => {
    expect(await findComplexityViolation("abcdef1", rulesWithCaseless(true), {})).toBe(
      "PASSWORD_MISSING_UPPERCASE",
    );
  });

  it("still reports a missing lowercase for uppercase Latin and digits only", async () => {
    expect(await findComplexityViolation("ABCDEF1", rulesWithCaseless(true), {})).toBe(
      "PASSWORD_MISSING_LOWERCASE",
    );
  });

  it("does not treat digits or symbols as caseless letters", async () => {
    expect(await findComplexityViolation("123456!?", rulesWithCaseless(true, { requireDigit: false }), {})).toBe(
      "PASSWORD_MISSING_UPPERCASE",
    );
  });

  it.each([
    ["a combining acute accent", `abc${COMBINING_ACUTE}def1`, "PASSWORD_MISSING_UPPERCASE"],
    ["a combining acute accent on uppercase", `ABC${COMBINING_ACUTE}DEF1`, "PASSWORD_MISSING_LOWERCASE"],
    ["a Thai tone mark", `abc${THAI_TONE_MARK}def1`, "PASSWORD_MISSING_UPPERCASE"],
    ["Thai digits", `abcdef${THAI_DIGITS}`, "PASSWORD_MISSING_UPPERCASE"],
  ])("does not let %s satisfy case", async (_name, password, expected) => {
    expect(await findComplexityViolation(password, rulesWithCaseless(true), {})).toBe(expected);
  });

  it.each([
    ["Han", HAN_PASSWORD],
    ["Hebrew", HEBREW_PASSWORD],
    ["Arabic", ARABIC_PASSWORD],
  ])("%s letters satisfy case only when the option is on", async (_name, password) => {
    expect(await findComplexityViolation(password, rulesWithCaseless(true), {})).toBeNull();
    expect(await findComplexityViolation(password, rulesWithCaseless(false), {})).toBe(
      "PASSWORD_MISSING_UPPERCASE",
    );
  });

  it("does not let U+0E46 THAI CHARACTER MAI YAMOK satisfy case because it is a modifier letter", async () => {
    expect(
      await findComplexityViolation(THAI_MAI_YAMOK_PASSWORD, rulesWithCaseless(true), {}),
    ).toBe("PASSWORD_MISSING_UPPERCASE");
  });

  it.each([
    ["a masculine ordinal indicator", "password1\u00ba", "PASSWORD_MISSING_UPPERCASE"],
    ["a feminine ordinal indicator", "PASSWORD1\u00aa", "PASSWORD_MISSING_LOWERCASE"],
    ["a Latin click letter", "password1\u01c3", "PASSWORD_MISSING_UPPERCASE"],
    ["a Common-script alef symbol", "password1\u2135", "PASSWORD_MISSING_UPPERCASE"],
  ])("does not let %s satisfy case", async (_name, password, expected) => {
    expect(await findComplexityViolation(password, rulesWithCaseless(true), {})).toBe(expected);
  });

  it("still lets a Thai letter satisfy lowercase next to uppercase Latin and a digit", async () => {
    expect(
      await findComplexityViolation("PASSWORD1\u0e44\u0e17\u0e22", rulesWithCaseless(true), {}),
    ).toBeNull();
  });

  it("accepts Thai digits as satisfying requireDigit", async () => {
    expect(await findComplexityViolation(`Abcdefg${THAI_DIGITS}`, rulesFrom(), {})).toBeNull();
  });

  it.each([false, true])(
    "changes nothing when requireUppercase is off and the option is %s",
    async (option) => {
      const rules = rulesWithCaseless(option, { requireUppercase: false });
      expect(await findComplexityViolation("abcdef1", rules, {})).toBeNull();
      expect(await findComplexityViolation("ABCDEF1", rules, {})).toBe("PASSWORD_MISSING_LOWERCASE");
    },
  );
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

describe("findComplexityViolation personal info in Thai", () => {
  const rules = rulesFrom();

  it("rejects a password containing the whole Thai name", async () => {
    expect(await findComplexityViolation(`X${THAI_NAME}9a`, rules, { name: THAI_NAME })).toBe(
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("rejects a password containing a Thai name part that sits before a space", async () => {
    expect(
      await findComplexityViolation(`X${THAI_NAME_FIRST}9a`, rules, {
        name: `${THAI_NAME_FIRST} ${THAI_NAME_LAST}`,
      }),
    ).toBe("PASSWORD_CONTAINS_PERSONAL_INFO");
  });

  it("accepts a password that does not contain the Thai name", async () => {
    expect(await findComplexityViolation("Xabcdef9a", rules, { name: THAI_NAME })).toBeNull();
  });

  it("matches uppercase personal info after lowercasing both sides", async () => {
    expect(
      await findComplexityViolation("xjohnx", personalInfoOnlyRules(), { name: "JOHN" }),
    ).toBe("PASSWORD_CONTAINS_PERSONAL_INFO");
  });
});

describe("findComplexityViolation personal info with Turkish dotted capital I", () => {
  const rules = rulesFrom();
  const user = { name: `${DOTTED_CAPITAL_I}brahim Y${DOTLESS_SMALL_I}lmaz` };

  it.each([
    ["a capital ASCII I", "Ibrahim2024x"],
    ["a lowercase ASCII i", "ibrahimK2024"],
    ["the dotted capital I itself", `${DOTTED_CAPITAL_I}brahim2024x`],
  ])("rejects a password containing the name with %s", async (_name, password) => {
    expect(await findComplexityViolation(password, rules, user)).toBe(
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });
});

describe("findComplexityViolation personal info across Unicode normalization forms", () => {
  const rules = rulesFrom();

  it("rejects a precomposed accented name in the password when the name is stored decomposed", async () => {
    expect(await findComplexityViolation("JoséAb2024", rules, { name: "José" })).toBe(
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("rejects a decomposed accented name in the password when the name is stored precomposed", async () => {
    expect(await findComplexityViolation("JoséAb2024", rules, { name: "José" })).toBe(
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
  });

  it("rejects a Thai name typed with the tone mark and lower vowel in the other order", async () => {
    expect(await findComplexityViolation("Xปู่Ab2024", rules, { name: "ปู่" })).toBe(
      "PASSWORD_CONTAINS_PERSONAL_INFO",
    );
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

  it("keeps a Thai name with combining marks as one whole token", () => {
    expect(personalInfoTokens({ name: THAI_NAME })).toEqual([THAI_NAME]);
    expect(Array.from(THAI_NAME)).toHaveLength(7);
  });

  it("counts combining marks toward the three code point minimum", () => {
    const threeCodePoints = "\u0e28\u0e23\u0e35";
    const twoCodePoints = "\u0e01\u0e35";
    expect(Array.from(threeCodePoints)).toHaveLength(3);
    expect(Array.from(twoCodePoints)).toHaveLength(2);
    expect(
      personalInfoTokens({
        name: `${threeCodePoints} ${twoCodePoints} ${THAI_WORD_WITH_MARKS}`,
      }),
    ).toEqual([threeCodePoints, THAI_WORD_WITH_MARKS]);
  });

  it("splits a Thai name on the space into its parts", () => {
    expect(personalInfoTokens({ name: `${THAI_NAME_FIRST} ${THAI_NAME_LAST}` })).toEqual([
      THAI_NAME_FIRST,
      THAI_NAME_LAST,
    ]);
  });

  it("splits an email local-part on punctuation", () => {
    expect(personalInfoTokens({ email: "jane.doe@x.com" })).toEqual(["jane", "doe"]);
  });

  it("splits a name on hyphens and apostrophes and drops short pieces", () => {
    expect(personalInfoTokens({ name: "Mary-Ann O'Neil" })).toEqual(["mary", "ann", "neil"]);
  });

  it("keeps a Latin letter with a combining accent inside its token, composed to NFC", () => {
    expect(personalInfoTokens({ name: `Jose${COMBINING_ACUTE}` })).toEqual(["jos\u00E9"]);
  });

  it("leaves no combining dot above in a token made from a dotted capital I", () => {
    expect(personalInfoTokens({ name: `${DOTTED_CAPITAL_I}brahim` })).toEqual(["ibrahim"]);
  });

  it("lowercases tokens", () => {
    expect(personalInfoTokens({ name: "JOHN" })).toEqual(["john"]);
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
