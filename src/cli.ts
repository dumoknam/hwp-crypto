#!/usr/bin/env node

import { decryptFile } from "./decrypt.js";

const [inputPath, password, outputPath] = process.argv.slice(2);

if (!inputPath || !password) {
  console.error("Usage: hwp-crypto <input.hwp|hwpx> <password> [output]");
  process.exit(1);
}

const out =
  outputPath ?? inputPath.replace(/\.(hwpx?)$/i, ".decrypted.$1");

try {
  decryptFile(inputPath, password, out);
  console.log(`Decrypted: ${out}`);
} catch (e) {
  console.error(`Error: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}
