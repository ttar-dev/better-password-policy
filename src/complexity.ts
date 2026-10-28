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
    "requireUppercase" | "requireLowercase" | "requireDigit" | "requireSymbol" | "rejectPersonalInfo"
  >
>;

export interface PersonalInfo {
  email?: string | null;
  name?: string | null;
}

const UPPERCASE = /\p{Lu}/u;
const LOWERCASE = /\p{Ll}/u;
const DIGIT = /\p{Nd}/u;
const SYMBOL = /[^\p{L}\p{N}]/u;
const TOKEN_SEPARATOR = /[^\p{L}\p{N}]+/u;
const MIN_TOKEN_LENGTH = 3;

export const personalInfoTokens = ({ email, name }: PersonalInfo): string[] => {
  const emailText = email ?? "";
  const atIndex = emailText.lastIndexOf("@");
  const localPart = atIndex === -1 ? emailText : emailText.slice(0, atIndex);
  const tokens = `${localPart} ${name ?? ""}`
    .toLowerCase()
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
  if (rules.requireUppercase && !UPPERCASE.test(password)) {
    return "PASSWORD_MISSING_UPPERCASE";
  }
  if (rules.requireLowercase && !LOWERCASE.test(password)) {
    return "PASSWORD_MISSING_LOWERCASE";
  }
  if (rules.requireDigit && !DIGIT.test(password)) {
    return "PASSWORD_MISSING_DIGIT";
  }
  if (rules.requireSymbol && !SYMBOL.test(password)) {
    return "PASSWORD_MISSING_SYMBOL";
  }
  if (rules.rejectPersonalInfo) {
    const lowered = password.toLowerCase();
    if (personalInfoTokens(info).some((token) => lowered.includes(token))) {
      return "PASSWORD_CONTAINS_PERSONAL_INFO";
    }
  }
  return null;
};
