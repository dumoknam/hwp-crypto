import { readFileSync, writeFileSync } from "node:fs";
import { createHash, createDecipheriv } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import AdmZip from "adm-zip";
import { deriveHwpxKey } from "./hwpx-key-derivation.js";
import {
  parseManifest,
  cleanManifest,
  type HwpxEncryptionEntry,
} from "./hwpx-manifest.js";

function verifyChecksum(plaintext: Buffer, expected: Buffer): boolean {
  const hash = createHash("sha256")
    .update(plaintext.subarray(0, 1024))
    .digest();
  return hash.equals(expected);
}

function decryptEntry(
  encrypted: Buffer,
  password: string | Buffer,
  entry: HwpxEncryptionEntry,
): Buffer {
  const key = deriveHwpxKey(password, entry.salt, entry.iterationCount, entry.keySize);
  const decipher = createDecipheriv("aes-256-cbc", key, entry.iv);
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  // deflate decompress; trailing zero-padding is ignored by zlib
  try {
    return inflateRawSync(decrypted);
  } catch {
    // Fallback for very small uncompressed entries
    return decrypted.subarray(0, entry.originalSize);
  }
}

function isEncryptedHwpx(zip: AdmZip): boolean {
  const manifestEntry = zip.getEntry("META-INF/manifest.xml");
  if (!manifestEntry) return false;
  const xml = manifestEntry.getData().toString("utf-8");
  return parseManifest(xml).length > 0;
}

/**
 * Decrypt a password-protected HWPX file buffer.
 *
 * Returns a new buffer containing the decrypted HWPX file
 * that can be opened without a password.
 */
export function decryptHwpx(input: Buffer, password: string): Buffer {
  const zip = new AdmZip(input);

  const manifestEntry = zip.getEntry("META-INF/manifest.xml");
  if (!manifestEntry) {
    throw new Error("Not a valid HWPX file: META-INF/manifest.xml not found.");
  }

  const manifestXml = manifestEntry.getData().toString("utf-8");
  const entries = parseManifest(manifestXml);

  if (entries.length === 0) {
    throw new Error("File is not password-protected.");
  }

  // Verify password on the first encrypted entry
  const firstEntry = entries[0];
  const firstData = zip.getEntry(firstEntry.fullPath)?.getData();
  if (!firstData) {
    throw new Error(`Encrypted entry not found: ${firstEntry.fullPath}`);
  }

  const firstPlaintext = decryptEntry(firstData, password, firstEntry);
  if (!verifyChecksum(firstPlaintext, firstEntry.checksum)) {
    throw new Error("Wrong password or unsupported encryption format.");
  }

  // Decrypt all encrypted entries
  zip.updateFile(firstEntry.fullPath, firstPlaintext);

  for (let i = 1; i < entries.length; i++) {
    const entry = entries[i];
    const data = zip.getEntry(entry.fullPath)?.getData();
    if (!data) continue;
    const plaintext = decryptEntry(data, password, entry);
    zip.updateFile(entry.fullPath, plaintext);
  }

  // Clean manifest: remove encryption metadata
  zip.updateFile(
    "META-INF/manifest.xml",
    Buffer.from(cleanManifest(manifestXml), "utf-8"),
  );

  return zip.toBuffer();
}

/**
 * Decrypt a password-protected HWPX file and save to disk.
 */
export function decryptHwpxFile(
  inputPath: string,
  password: string,
  outputPath: string,
): void {
  const input = readFileSync(inputPath);
  const output = decryptHwpx(input, password);
  writeFileSync(outputPath, output);
}

export { isEncryptedHwpx };
