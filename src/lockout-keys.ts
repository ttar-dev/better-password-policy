export const LOCKOUT_MODEL = "signInLockout";

const KEY_DERIVATION_SALT = "@ttar-dev/better-password-policy";
const KEY_DERIVATION_INFO = "sign-in-lockout:v1";
const DEVICE_ID_BYTES = 16;

const encoder = new TextEncoder();
const hmacKeysBySecret = new Map<string, Promise<CryptoKey>>();

const toHex = (bytes: ArrayBuffer | Uint8Array): string =>
  Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

const deriveHmacKey = async (secret: string): Promise<CryptoKey> => {
  const material = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(KEY_DERIVATION_SALT),
      info: encoder.encode(KEY_DERIVATION_INFO),
    },
    material,
    256,
  );
  return crypto.subtle.importKey("raw", bits, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
};

const hmacKeyFor = (secret: string): Promise<CryptoKey> => {
  const cached = hmacKeysBySecret.get(secret);
  if (cached !== undefined) {
    return cached;
  }
  const pending = deriveHmacKey(secret);
  hmacKeysBySecret.set(secret, pending);
  pending.catch(() => {
    hmacKeysBySecret.delete(secret);
  });
  return pending;
};

const hmacHex = async (secret: string, message: string): Promise<string> => {
  const key = await hmacKeyFor(secret);
  return toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
};

export const lockoutIdentifierKey = async (secret: string, identifier: string): Promise<string> =>
  `i1:${await hmacHex(secret, `identifier:${identifier}`)}`;

export const lockoutDeviceKeyPrefix = async (secret: string, userId: string): Promise<string> =>
  `d1:${await hmacHex(secret, `user:${userId}`)}:`;

export const lockoutDeviceKey = async (secret: string, userId: string, deviceId: string): Promise<string> =>
  `${await lockoutDeviceKeyPrefix(secret, userId)}${deviceId}`;

export const deviceCookieBinding = (
  secret: string,
  userId: string,
  deviceId: string,
  expiresAt: number,
  passwordEpoch: string,
): Promise<string> => hmacHex(secret, `device:${deviceId}:${expiresAt}:${passwordEpoch}:${userId}`);

export const createDeviceId = (): string => toHex(crypto.getRandomValues(new Uint8Array(DEVICE_ID_BYTES)));
