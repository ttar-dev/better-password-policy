import { verifyPassword } from "better-auth/crypto";
import type { PasswordNormalizationForm } from "./options.ts";

export type PasswordNormalizer = (password: string) => string;

export type PasswordVerifier = (input: { hash: string; password: string }) => Promise<boolean>;

export const createPasswordNormalizer = (form: PasswordNormalizationForm | null): PasswordNormalizer =>
  form === null ? (password) => password : (password) => password.normalize(form);

export const createNormalizingVerify =
  (verify: PasswordVerifier, normalizePassword: PasswordNormalizer): PasswordVerifier =>
  async (input) => {
    const normalized = normalizePassword(input.password);
    if (await verify({ ...input, password: normalized })) {
      return true;
    }
    if (normalized === input.password) {
      return false;
    }
    return verify(input);
  };

export const usesDefaultPasswordVerifier = (password: { verify: unknown }): boolean =>
  password.verify === verifyPassword;
