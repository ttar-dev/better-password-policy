import { describe, it, expect, vi } from "vitest";
import { hashPassword, verifyPassword } from "better-auth/crypto";
import {
  createNormalizingVerify,
  createPasswordNormalizer,
  usesDefaultPasswordVerifier,
} from "../../src/password-normalization.ts";

const TYPED = "Water1น้ำ";
const NORMALIZED = "Water1น้ํา";
const TYPED_MARK_ORDER = "Pass1กู้";
const OTHER_MARK_ORDER = "Pass1กู้";

type VerifyInput = { hash: string; password: string };

const stubVerify = (results: boolean[]) => {
  const queue = [...results];
  return vi.fn(async (_input: VerifyInput) => queue.shift() ?? false);
};

describe("createPasswordNormalizer", () => {
  it("returns the same string unchanged when the form is null", () => {
    const normalize = createPasswordNormalizer(null);
    expect(normalize(TYPED)).toBe(TYPED);
    expect(normalize("Ａ１")).toBe("Ａ１");
    expect(normalize("")).toBe("");
  });

  it("normalizes the Thai sara am to nikhahit plus sara aa with NFKC", () => {
    expect(createPasswordNormalizer("NFKC")(TYPED)).toBe(NORMALIZED);
  });

  it("gives two orders of vowel and tone marks the same result with NFKC", () => {
    const normalize = createPasswordNormalizer("NFKC");
    expect(normalize(TYPED_MARK_ORDER)).toBe(normalize(OTHER_MARK_ORDER));
    expect(TYPED_MARK_ORDER).not.toBe(OTHER_MARK_ORDER);
  });

  it("folds compatibility characters with NFKC", () => {
    const normalize = createPasswordNormalizer("NFKC");
    expect(normalize("Ａ１")).toBe("A1");
    expect(normalize("ﬁ")).toBe("fi");
    expect(normalize("²")).toBe("2");
    expect(normalize("a b")).toBe("a b");
    expect(normalize("é")).toBe("é");
  });

  it("leaves ASCII untouched with NFKC", () => {
    const password = "Correct1Horse!~ ";
    expect(createPasswordNormalizer("NFKC")(password)).toBe(password);
  });
});

describe("createNormalizingVerify", () => {
  const normalize = createPasswordNormalizer("NFKC");

  it("calls the base verify once when the normalized and typed forms are equal", async () => {
    const base = stubVerify([false]);
    const result = await createNormalizingVerify(base, normalize)({ hash: "h", password: "Correct1Horse" });
    expect(result).toBe(false);
    expect(base).toHaveBeenCalledTimes(1);
    expect(base).toHaveBeenCalledWith({ hash: "h", password: "Correct1Horse" });
  });

  it("returns true after one call with the normalized form when it verifies", async () => {
    const base = stubVerify([true]);
    const result = await createNormalizingVerify(base, normalize)({ hash: "h", password: TYPED });
    expect(result).toBe(true);
    expect(base).toHaveBeenCalledTimes(1);
    expect(base).toHaveBeenCalledWith({ hash: "h", password: NORMALIZED });
  });

  it("falls back to the typed form after the normalized form fails and returns that result", async () => {
    const base = stubVerify([false, true]);
    const result = await createNormalizingVerify(base, normalize)({ hash: "h", password: TYPED });
    expect(result).toBe(true);
    expect(base.mock.calls.map(([input]) => input.password)).toEqual([NORMALIZED, TYPED]);
  });

  it("returns false after two calls when neither form verifies", async () => {
    const base = stubVerify([false, false]);
    const result = await createNormalizingVerify(base, normalize)({ hash: "h", password: TYPED });
    expect(result).toBe(false);
    expect(base.mock.calls.map(([input]) => input.password)).toEqual([NORMALIZED, TYPED]);
  });

  it("passes the hash through to both calls", async () => {
    const base = stubVerify([false, false]);
    await createNormalizingVerify(base, normalize)({ hash: "stored-hash", password: TYPED });
    expect(base.mock.calls.map(([input]) => input.hash)).toEqual(["stored-hash", "stored-hash"]);
  });

  it("does not fall back when the first call verifies even though the forms differ", async () => {
    const base = stubVerify([true, false]);
    await createNormalizingVerify(base, normalize)({ hash: "h", password: TYPED });
    expect(base).toHaveBeenCalledTimes(1);
  });

  it("calls the base verify once with the identity normalizer", async () => {
    const base = stubVerify([false, false]);
    const result = await createNormalizingVerify(base, createPasswordNormalizer(null))({
      hash: "h",
      password: TYPED,
    });
    expect(result).toBe(false);
    expect(base).toHaveBeenCalledTimes(1);
    expect(base).toHaveBeenCalledWith({ hash: "h", password: TYPED });
  });

  it("propagates a rejection from the base verify", async () => {
    const base = vi.fn(async (_input: VerifyInput): Promise<boolean> => {
      throw new Error("verify failed");
    });
    await expect(createNormalizingVerify(base, normalize)({ hash: "h", password: TYPED })).rejects.toThrow(
      "verify failed",
    );
  });
});

describe("usesDefaultPasswordVerifier", () => {
  const replacedHash = async (password: string) => password;
  const replacedVerify = async (_input: VerifyInput) => true;
  const wrappedHash = async (password: string) => hashPassword(password);
  const wrappedVerify = async (input: VerifyInput) => verifyPassword(input);

  it("is true when verify is Better Auth's own function", () => {
    expect(usesDefaultPasswordVerifier({ verify: verifyPassword })).toBe(true);
  });

  it("is true when only hash is wrapped, as haveIBeenPwned does", () => {
    expect(usesDefaultPasswordVerifier({ hash: wrappedHash, verify: verifyPassword } as { verify: unknown })).toBe(true);
  });

  it("is true when only hash is replaced", () => {
    expect(usesDefaultPasswordVerifier({ hash: replacedHash, verify: verifyPassword } as { verify: unknown })).toBe(true);
  });

  it("is false when verify is wrapped", () => {
    expect(usesDefaultPasswordVerifier({ verify: wrappedVerify })).toBe(false);
  });

  it("is false when verify is replaced", () => {
    expect(usesDefaultPasswordVerifier({ verify: replacedVerify })).toBe(false);
  });
});
