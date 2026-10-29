import type { PasswordPolicyErrorCode } from "./error-codes.ts";
import type { ResolvedComplexity } from "./options.ts";

export type ComplexityViolation = Extract<
  PasswordPolicyErrorCode,
  | "PASSWORD_MISSING_UPPERCASE"
  | "PASSWORD_MISSING_LOWERCASE"
  | "PASSWORD_MISSING_DIGIT"
  | "PASSWORD_MISSING_SYMBOL"
  | "PASSWORD_CONTAINS_PERSONAL_INFO"
>;

export type ComplexityRules = Partial<
  Pick<
    ResolvedComplexity,
    | "requireUppercase"
    | "requireLowercase"
    | "requireDigit"
    | "requireSymbol"
    | "rejectPersonalInfo"
    | "caselessLettersSatisfyCase"
  >
>;

export interface PersonalInfo {
  email?: string | null;
  name?: string | null;
}

const UPPERCASE = /\p{Lu}/u;
const LOWERCASE = /\p{Ll}/u;
const DIGIT = /\p{Nd}/u;
const CASELESS_LETTER = /(?![\p{Script=Latin}\p{Script=Common}])\p{Lo}/u;
const SYMBOL = /[^\p{L}\p{Mn}\p{Mc}\p{N}]/u;
const TOKEN_SEPARATOR = /[^\p{L}\p{Mn}\p{Mc}\p{N}]+/u;
const DOTTED_SMALL_I = /i\u0307/gu;
const MIN_TOKEN_LENGTH = 3;

const foldCase = (text: string): string => text.toLowerCase().normalize("NFC").replace(DOTTED_SMALL_I, "i");

export const personalInfoTokens = ({ email, name }: PersonalInfo): string[] => {
  const emailText = email ?? "";
  const atIndex = emailText.lastIndexOf("@");
  const localPart = atIndex === -1 ? emailText : emailText.slice(0, atIndex);
  const tokens = foldCase(`${localPart} ${name ?? ""}`)
    .split(TOKEN_SEPARATOR)
    .filter((token) => Array.from(token).length >= MIN_TOKEN_LENGTH);
  return [...new Set(tokens)];
};

export const isPasswordTooShort = (password: string, minLength: number | null): boolean =>
  minLength !== null && password.length < minLength;

export const findComplexityViolation = (
  password: string,
  rules: ComplexityRules,
  info: PersonalInfo,
): ComplexityViolation | null => {
  const caselessSatisfies = rules.caselessLettersSatisfyCase === true && CASELESS_LETTER.test(password);
  if (rules.requireUppercase && !UPPERCASE.test(password) && !caselessSatisfies) {
    return "PASSWORD_MISSING_UPPERCASE";
  }
  if (rules.requireLowercase && !LOWERCASE.test(password) && !caselessSatisfies) {
    return "PASSWORD_MISSING_LOWERCASE";
  }
  if (rules.requireDigit && !DIGIT.test(password)) {
    return "PASSWORD_MISSING_DIGIT";
  }
  if (rules.requireSymbol && !SYMBOL.test(password)) {
    return "PASSWORD_MISSING_SYMBOL";
  }
  if (rules.rejectPersonalInfo) {
    const lowered = foldCase(password);
    if (personalInfoTokens(info).some((token) => lowered.includes(token))) {
      return "PASSWORD_CONTAINS_PERSONAL_INFO";
    }
  }
  return null;
};
