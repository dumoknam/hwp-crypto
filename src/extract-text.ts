import { inflateRawSync } from "node:zlib";
import * as CFB from "cfb";

const PARA_TEXT = 0x43;

function readRecords(data: Buffer): string[] {
  const texts: string[] = [];
  let offset = 0;

  while (offset + 4 <= data.length) {
    const val = data.readUInt32LE(offset);
    const tag = val & 0x3ff;
    let size = (val >> 20) & 0xfff;
    offset += 4;

    if (size === 4095) {
      if (offset + 4 > data.length) break;
      size = data.readUInt32LE(offset);
      offset += 4;
    }

    if (offset + size > data.length) break;

    if (tag === PARA_TEXT && size > 0) {
      const text = parseParaText(data.subarray(offset, offset + size));
      if (text) texts.push(text);
    }

    offset += size;
  }

  return texts;
}

function parseParaText(buf: Buffer): string {
  let str = "";
  let i = 0;

  while (i + 1 < buf.length) {
    const ch = buf.readUInt16LE(i);
    if (ch === 0) break;

    if (ch < 32) {
      if (ch === 10 || ch === 13) {
        str += "\n";
        i += 2;
      } else if (
        ch === 0 ||
        ch === 24 ||
        ch === 25 ||
        ch === 26 ||
        ch === 27 ||
        ch === 28 ||
        ch === 29 ||
        ch === 30 ||
        ch === 31
      ) {
        i += 2;
      } else {
        // extended control chars (1~8, 11, 12, 14~23): 8 chars = 16 bytes
        i += 16;
      }
      continue;
    }

    str += String.fromCodePoint(ch);
    i += 2;
  }

  return str.trim();
}

function isCompressed(cfbFile: CFB.CFB$Container): boolean {
  const entry = CFB.find(cfbFile, "/FileHeader");
  if (!entry?.content) return false;
  return (entry.content[36] & 0x01) !== 0;
}

function decompressStream(content: Buffer | Uint8Array, compressed: boolean): Buffer {
  const buf = Buffer.from(content);
  if (!compressed) return buf;
  try {
    return inflateRawSync(buf);
  } catch {
    return buf;
  }
}

/**
 * Extract all text from an HWP file buffer (encrypted or not).
 *
 * Reads all BodyText/SectionN streams, decompresses them,
 * and extracts paragraph text including text inside tables
 * and other nested controls.
 */
export function extractText(input: Buffer): string {
  const cfbFile = CFB.read(input, { type: "buffer" });
  const compressed = isCompressed(cfbFile);
  const allTexts: string[] = [];

  const sectionNames = cfbFile.FullPaths
    .filter((p) => /\/BodyText\/Section\d+$/.test(p))
    .sort();

  for (const path of sectionNames) {
    const entry = CFB.find(cfbFile, path);
    if (!entry?.content) continue;

    const data = decompressStream(Buffer.from(entry.content as Uint8Array), compressed);
    const texts = readRecords(data);
    allTexts.push(...texts);
  }

  return allTexts.join("\n");
}
