# hwp-crypto

Decrypt password-protected HWP (한글) files.

Supports HWP 5.0 files encrypted with EncryptVersion 4 (한글 7.0+).

## Install

```bash
npm install hwp-crypto
```

## Usage

### Library

```typescript
import { decryptHwp } from "hwp-crypto";
import { readFileSync, writeFileSync } from "fs";

const encrypted = readFileSync("secret.hwp");
const decrypted = decryptHwp(encrypted, "password");
writeFileSync("decrypted.hwp", decrypted);
```

### CLI

```bash
npx hwp-crypto input.hwp mypassword output.hwp
```

## API

### `decryptHwp(input: Buffer, password: string): Buffer`

Decrypts a password-protected HWP file buffer. Returns a new buffer that can be opened without a password.

Throws if the password is wrong or the file is not password-protected.

### `decryptHwpFile(inputPath: string, password: string, outputPath: string): void`

Reads, decrypts, and writes to disk.

### `deriveKey(password: string): Buffer`

Derives the AES-128 key from a password (exposed for advanced use).

## How it works

HWP password encryption uses a custom 1-bit CFB stream cipher built on AES-128-ECB. The password is converted to a 16-byte AES key via byte interleaving + SHA-1. Encrypted streams (DocInfo, BodyText/Section*, BinData, Scripts) are decrypted and the FileHeader password flag is cleared.

Based on the algorithm documented in [hwp-password-recover](https://github.com/junorouse/hwp-password-recover).

## License

MIT
