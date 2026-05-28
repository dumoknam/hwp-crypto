import { createCipheriv } from "node:crypto";

/**
 * AES-128-ECB encrypt a single 16-byte block (no padding).
 */
function aesEcbEncryptBlock(key: Buffer, block: Uint8Array): Buffer {
  const cipher = createCipheriv("aes-128-ecb", key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

/**
 * Left-shift the 16-byte register by 1 bit.
 * Bytes 0..14 are shifted; byte 15's LSB is set to `feedbackBit`.
 *
 * Ported from the 3-iteration inner loop + final byte update in gogo().
 */
function shiftRegister(reg: Uint8Array, feedbackBit: number): void {
  let tmp = 1;
  for (let j = 0; j < 3; j++) {
    const v14 = reg[tmp];
    reg[tmp - 1] = ((2 * reg[tmp - 1]) & 0xff) | (reg[tmp] >> 7);

    const v15 = reg[tmp + 1];
    const v16 = ((2 * v14) & 0xff) | (reg[tmp + 1] >> 7);

    const v17 = reg[tmp + 2];
    reg[tmp] = v16;
    const v18 = ((2 * v15) & 0xff) | (v17 >> 7);

    const v19 = reg[tmp + 3];
    reg[tmp + 1] = v18;
    const v20 = ((2 * v17) & 0xff) | (v19 >> 7);

    const v21 = ((2 * v19) & 0xff) | (reg[tmp + 4] >> 7);

    reg[tmp + 2] = v20;
    reg[tmp + 3] = v21;

    tmp += 5;
  }

  reg[15] = ((2 * reg[15]) & 0xff) | (feedbackBit & 1);
}

/**
 * Custom 1-bit CFB stream cipher used by HWP password encryption.
 *
 * Ported from junorouse/hwp-password-recover utils.py (gogo).
 *
 * Each 16-byte block is processed bit-by-bit (128 iterations).
 * The shift register state carries across blocks.
 */
export function hwpCipher(
  key: Buffer,
  data: Uint8Array,
  encrypt: boolean,
): Buffer {
  const result = Buffer.alloc(data.length);
  const reg = new Uint8Array(16); // feedback register, IV = 0

  for (let blockOffset = 0; blockOffset < data.length; blockOffset += 16) {
    const blockEnd = Math.min(blockOffset + 16, data.length);
    const block = new Uint8Array(data.slice(blockOffset, blockEnd));

    // pad short final block with zeros
    const input = new Uint8Array(16);
    input.set(block);

    for (let i = 0; i < 128; i++) {
      const out = aesEcbEncryptBlock(key, reg);
      const outMsb = out[0]; // only first byte used

      const byteIdx = i >> 3;
      const bitPos = i & 7;

      if (encrypt) {
        input[byteIdx] ^= (outMsb & 0x80) >> bitPos;
      }

      // extract the feedback bit from the current byte
      const feedbackBit = (input[byteIdx] >> (7 - bitPos)) & 1;

      shiftRegister(reg, feedbackBit);

      if (!encrypt) {
        input[byteIdx] ^= (outMsb & 0x80) >> bitPos;
      }
    }

    if (encrypt) {
      result.set(reg.slice(0, blockEnd - blockOffset), blockOffset);
    } else {
      result.set(input.slice(0, blockEnd - blockOffset), blockOffset);
    }
  }

  return result;
}
