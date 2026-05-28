import { readFileSync, writeFileSync } from "node:fs";
import { detectFormat } from "./detect-format.js";
import { decryptHwp } from "./hwp-crypto.js";
import { decryptHwpx } from "./hwpx-crypto.js";

/**
 * Decrypt a password-protected HWP or HWPX file buffer.
 * Auto-detects the format from magic bytes.
 */
export function decrypt(input: Buffer, password: string): Buffer {
  const format = detectFormat(input);
  switch (format) {
    case "hwp":
      return decryptHwp(input, password);
    case "hwpx":
      return decryptHwpx(input, password);
    default:
      throw new Error("Unsupported file format. Expected HWP or HWPX.");
  }
}

/**
 * Decrypt a password-protected HWP or HWPX file and save to disk.
 * Auto-detects the format from magic bytes.
 */
export function decryptFile(
  inputPath: string,
  password: string,
  outputPath: string,
): void {
  const input = readFileSync(inputPath);
  const output = decrypt(input, password);
  writeFileSync(outputPath, output);
}
