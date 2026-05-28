#!/usr/bin/env node

import { decryptHwpFile } from "./hwp-crypto.js";

const [inputPath, password, outputPath] = process.argv.slice(2);

if (!inputPath || !password) {
  console.error("Usage: hwp-crypto <input.hwp> <password> [output.hwp]");
  process.exit(1);
}

const out = outputPath ?? inputPath.replace(/\.hwp$/i, ".decrypted.hwp");

try {
  decryptHwpFile(inputPath, password, out);
  console.log(`Decrypted: ${out}`);
} catch (e) {
  console.error(
    `Error: ${e instanceof Error ? e.message : String(e)}`,
  );
  process.exit(1);
}
