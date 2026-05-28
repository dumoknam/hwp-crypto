import { readFileSync, writeFileSync } from "node:fs";
import { inflateRawSync } from "node:zlib";
import * as CFB from "cfb";
import { deriveKey } from "./key-derivation.js";
import { hwpCipher } from "./cipher.js";

const BLOCK_SIZE = 16;

function pkcs7Pad(data: Buffer): Buffer {
  const padLen = BLOCK_SIZE - (data.length % BLOCK_SIZE);
  return Buffer.concat([data, Buffer.alloc(padLen, padLen)]);
}

/** Standard HWP FileHeader with hasPassword flag cleared. */
const CLEAN_FILE_HEADER = Buffer.from(
  "48575020446f63756d656e742046696c65" +
    "0000000000000000000000000000000005020005010000000000000004000000" +
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" +
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" +
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" +
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000" +
    "00000000000000000000000000000000000000000000000000000000",
  "hex",
);

function isPasswordProtected(cfbFile: CFB.CFB$Container): boolean {
  const entry = CFB.find(cfbFile, "/FileHeader");
  if (!entry?.content) return false;
  const flags = entry.content[36];
  return (flags & 0x02) !== 0;
}

function listSectionStreams(cfbFile: CFB.CFB$Container): string[] {
  const sections: string[] = [];
  for (const entry of cfbFile.FileIndex) {
    if (entry.name.match(/^Section\d+$/)) {
      sections.push(entry.name);
    }
  }
  return sections.sort();
}

function decryptStream(key: Buffer, encrypted: Buffer): Buffer {
  const padded = pkcs7Pad(encrypted);
  const decrypted = hwpCipher(key, padded, false);
  return decrypted.subarray(0, encrypted.length);
}

function verifyPassword(key: Buffer, docInfoData: Buffer): void {
  const decrypted = decryptStream(key, docInfoData);
  try {
    inflateRawSync(decrypted);
  } catch {
    throw new Error("Wrong password or unsupported encryption format.");
  }
}

/**
 * Decrypt a password-protected HWP file buffer.
 *
 * Returns a new buffer containing the decrypted HWP file
 * that can be opened without a password.
 */
export function decryptHwp(input: Buffer, password: string): Buffer {
  const cfbFile = CFB.read(input, { type: "buffer" });

  if (!isPasswordProtected(cfbFile)) {
    throw new Error("File is not password-protected.");
  }

  const key = deriveKey(password);

  // Verify password by decrypting DocInfo and checking zlib integrity.
  const docInfoEntry = CFB.find(cfbFile, "/DocInfo");
  if (!docInfoEntry?.content) {
    throw new Error("DocInfo stream not found.");
  }
  const docInfoBuf = Buffer.from(docInfoEntry.content);
  verifyPassword(key, docInfoBuf);

  // Clear the password flag in FileHeader.
  const headerEntry = CFB.find(cfbFile, "/FileHeader");
  if (headerEntry) {
    headerEntry.content = CLEAN_FILE_HEADER;
  }

  // Decrypt DocInfo.
  docInfoEntry.content = decryptStream(key, docInfoBuf);

  // Decrypt all BodyText/SectionN streams.
  const sections = listSectionStreams(cfbFile);
  for (const name of sections) {
    const entry = CFB.find(cfbFile, `/BodyText/${name}`);
    if (entry?.content) {
      entry.content = decryptStream(key, Buffer.from(entry.content));
    }
  }

  // Decrypt ViewText/SectionN if present.
  for (const name of sections) {
    const entry = CFB.find(cfbFile, `/ViewText/${name}`);
    if (entry?.content) {
      entry.content = decryptStream(key, Buffer.from(entry.content));
    }
  }

  // Decrypt BinData entries.
  for (const entry of cfbFile.FileIndex) {
    const fullName = entry.name;
    if (
      cfbFile.FullPaths.some(
        (p) => p.includes("/BinData/") && p.endsWith(fullName),
      ) &&
      entry.content
    ) {
      entry.content = decryptStream(key, Buffer.from(entry.content));
    }
  }

  // Decrypt Scripts entries.
  for (const scriptName of ["DefaultJScript", "JScriptVersion"]) {
    const entry = CFB.find(cfbFile, `/Scripts/${scriptName}`);
    if (entry?.content) {
      entry.content = decryptStream(key, Buffer.from(entry.content));
    }
  }

  return Buffer.from(CFB.write(cfbFile, { type: "buffer" }));
}

/**
 * Decrypt a password-protected HWP file and save to disk.
 */
export function decryptHwpFile(
  inputPath: string,
  password: string,
  outputPath: string,
): void {
  const input = readFileSync(inputPath);
  const output = decryptHwp(input, password);
  writeFileSync(outputPath, output);
}
