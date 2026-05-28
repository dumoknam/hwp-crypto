const NS = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

export interface HwpxEncryptionEntry {
  fullPath: string;
  originalSize: number;
  checksum: Buffer;
  iv: Buffer;
  salt: Buffer;
  keySize: number;
  iterationCount: number;
}

function attr(xml: string, name: string): string {
  const re = new RegExp(`${name}\\s*=\\s*"([^"]*)"`, "s");
  return re.exec(xml)?.[1] ?? "";
}

/**
 * Parse META-INF/manifest.xml and return encryption metadata for each
 * encrypted entry. Non-encrypted entries are skipped.
 */
export function parseManifest(xml: string): HwpxEncryptionEntry[] {
  const entries: HwpxEncryptionEntry[] = [];

  const parts = xml.split("</manifest:file-entry>");
  for (const part of parts) {
    const startIdx = part.lastIndexOf("<manifest:file-entry");
    if (startIdx === -1) continue;

    const block = part.substring(startIdx);
    if (!block.includes("encryption-data")) continue;

    const fullPath = attr(block, "manifest:full-path");
    const originalSize = parseInt(attr(block, "manifest:size") || "0", 10);
    const checksum = attr(block, "manifest:checksum");
    const iv = attr(block, "manifest:initialisation-vector");
    const salt = attr(block, "manifest:salt");
    const keySize = parseInt(attr(block, "manifest:key-size") || "32", 10);
    const iterationCount = parseInt(
      attr(block, "manifest:iteration-count") || "1024",
      10,
    );

    entries.push({
      fullPath,
      originalSize,
      checksum: Buffer.from(checksum, "base64"),
      iv: Buffer.from(iv, "base64"),
      salt: Buffer.from(salt, "base64"),
      keySize,
      iterationCount,
    });
  }

  return entries;
}

/**
 * Remove encryption-data elements from manifest.xml so the
 * decrypted HWPX can be opened without confusion.
 */
export function cleanManifest(xml: string): string {
  let cleaned = xml.replace(
    /<manifest:encryption-data[\s\S]*?<\/manifest:encryption-data>/g,
    "",
  );
  cleaned = cleaned.replace(/\s*manifest:size\s*=\s*"[^"]*"/g, "");
  return cleaned;
}
