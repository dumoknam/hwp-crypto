export type HwpFormat = "hwp" | "hwpx" | "unknown";

/**
 * Detect file format from magic bytes.
 * - HWP 5.0 (OLE/CFB): D0 CF 11 E0
 * - HWPX (ZIP): 50 4B 03 04
 */
export function detectFormat(input: Buffer): HwpFormat {
  if (input.length < 4) return "unknown";

  if (
    input[0] === 0xd0 &&
    input[1] === 0xcf &&
    input[2] === 0x11 &&
    input[3] === 0xe0
  ) {
    return "hwp";
  }

  if (
    input[0] === 0x50 &&
    input[1] === 0x4b &&
    input[2] === 0x03 &&
    input[3] === 0x04
  ) {
    return "hwpx";
  }

  return "unknown";
}
