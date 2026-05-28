import { createHash } from "node:crypto";

/**
 * HWP password → AES-128 key derivation.
 *
 * Ported from junorouse/hwp-password-recover password.py (genkey).
 *
 * 1. Interleave each password byte with a 1-bit left-rotated previous byte
 *    (first byte uses 0xEC as seed) into a 160-byte buffer.
 * 2. Strip zero bytes.
 * 3. SHA-1 hash → take first 16 bytes of hex digest as the AES key.
 */
export function deriveKey(password: string): Buffer {
  const buf = Buffer.alloc(160);
  const pw = Buffer.from(password, "binary");

  for (let i = 0; i < pw.length && i * 2 + 1 < 160; i++) {
    const prev = i ? pw[i - 1] : 0xec;
    const rotated = ((2 * prev) | (prev >> 7)) & 0xff;

    buf[i * 2] = rotated;
    buf[i * 2 + 1] = pw[i];
  }

  const filtered = Buffer.from(Array.from(buf).filter((b) => b !== 0));

  const hex = createHash("sha1").update(filtered).digest("hex");

  return Buffer.from(hex.slice(0, 32), "hex");
}
