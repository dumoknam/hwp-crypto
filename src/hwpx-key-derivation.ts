import { createHash, pbkdf2Sync } from "node:crypto";

/**
 * HWPX password → AES-256 key derivation.
 *
 * 1. SHA-256(UTF-8 password) → 32-byte start key
 * 2. PBKDF2-HMAC-SHA1(startKey, salt, iterations, keySize) → derived key
 */
export function deriveHwpxKey(
  password: string | Buffer,
  salt: Buffer,
  iterations: number,
  keySize: number,
): Buffer {
  const pw =
    typeof password === "string" ? Buffer.from(password, "utf-8") : password;
  const startKey = createHash("sha256").update(pw).digest();
  return pbkdf2Sync(startKey, salt, iterations, keySize, "sha1");
}
