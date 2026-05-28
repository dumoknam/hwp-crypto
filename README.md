# hwp-crypto

Decrypt password-protected HWP/HWPX (한글) files and extract text.

- **HWP** — HWP 5.0 EncryptVersion 4 (한글 7.0+)
- **HWPX** — ODF-style AES-256-CBC encryption (한글 2010+)

## Install

```bash
npm install hwp-crypto
```

## Usage

### Auto-detect format and decrypt

```typescript
import { decrypt } from "hwp-crypto";
import { readFileSync } from "fs";

const encrypted = readFileSync("secret.hwp"); // or .hwpx
const decrypted = decrypt(encrypted, "password");
```

### Extract text from a password-protected file

```typescript
import { decrypt, extractText, extractTextHwpx, detectFormat } from "hwp-crypto";
import { readFileSync } from "fs";

const buf = readFileSync("secret.hwpx");
const decrypted = decrypt(buf, "password");

if (detectFormat(buf) === "hwpx") {
  console.log(extractTextHwpx(decrypted));
} else {
  console.log(extractText(decrypted));
}
```

### Format-specific APIs

```typescript
import { decryptHwp, decryptHwpx } from "hwp-crypto";

// HWP 5.0
const hwpResult = decryptHwp(hwpBuffer, "password");

// HWPX
const hwpxResult = decryptHwpx(hwpxBuffer, "password");
```

### Decrypt and save

```typescript
import { decryptFile } from "hwp-crypto";

decryptFile("secret.hwp", "password", "decrypted.hwp");
decryptFile("secret.hwpx", "password", "decrypted.hwpx");
```

### CLI

```bash
npx hwp-crypto input.hwp mypassword output.hwp
npx hwp-crypto input.hwpx mypassword output.hwpx
```

## API

### `decrypt(input: Buffer, password: string): Buffer`

Auto-detects HWP/HWPX format and decrypts. Returns a new buffer that can be opened without a password.

### `decryptFile(inputPath: string, password: string, outputPath: string): void`

Auto-detecting file-based version of `decrypt`.

### `decryptHwp(input: Buffer, password: string): Buffer`

Decrypts a password-protected HWP 5.0 file buffer.

### `decryptHwpx(input: Buffer, password: string): Buffer`

Decrypts a password-protected HWPX file buffer.

### `extractText(input: Buffer): string`

Extracts text from an HWP file buffer.

### `extractTextHwpx(input: Buffer): string`

Extracts text from an HWPX file buffer.

### `detectFormat(input: Buffer): "hwp" | "hwpx" | "unknown"`

Detects file format from magic bytes.

### `deriveKey(password: string): Buffer`

Derives the AES-128 key from a password (HWP 5.0, advanced use).

### `deriveHwpxKey(password: string | Buffer, salt: Buffer, iterations: number, keySize: number): Buffer`

Derives the AES-256 key from a password (HWPX, advanced use).

## How it works

### HWP 5.0

Custom 1-bit CFB stream cipher built on AES-128-ECB. Password → byte interleaving + SHA-1 → 16-byte AES key. Encrypted streams (DocInfo, BodyText/Section\*, BinData, Scripts) are decrypted and the FileHeader password flag is cleared.

### HWPX

ODF-style per-file encryption within a ZIP container. Password → SHA-256 → PBKDF2-HMAC-SHA1 → 32-byte AES key. Each encrypted XML entry is decrypted with AES-256-CBC, then deflate-decompressed. Checksum verification uses SHA-256 of the first 1024 bytes.

## Acknowledgements

본 제품은 한글과컴퓨터의 한글 문서 파일(.hwp) 공개 문서를 참고하여 개발하였습니다.

- [한컴 파일 형식 공개](https://store.hancom.com/etc/hwpDownload.do)
- [hwp-password-recover](https://github.com/junorouse/hwp-password-recover)

## License

MIT
