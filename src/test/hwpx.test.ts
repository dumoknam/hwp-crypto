import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash, createCipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import AdmZip from "adm-zip";
import { deriveHwpxKey } from "../hwpx-key-derivation.js";
import { parseManifest, cleanManifest } from "../hwpx-manifest.js";
import { decryptHwpx } from "../hwpx-crypto.js";
import { extractTextHwpx } from "../extract-text-hwpx.js";
import { detectFormat } from "../detect-format.js";

describe("deriveHwpxKey", () => {
  it("produces a 32-byte key by default", () => {
    const salt = Buffer.alloc(16, 0xab);
    const key = deriveHwpxKey("test", salt, 1024, 32);
    assert.equal(key.length, 32);
  });

  it("is deterministic", () => {
    const salt = Buffer.alloc(16, 0xcd);
    const k1 = deriveHwpxKey("hello", salt, 1024, 32);
    const k2 = deriveHwpxKey("hello", salt, 1024, 32);
    assert.deepEqual(k1, k2);
  });

  it("different passwords produce different keys", () => {
    const salt = Buffer.alloc(16, 0xef);
    const k1 = deriveHwpxKey("aaa", salt, 1024, 32);
    const k2 = deriveHwpxKey("bbb", salt, 1024, 32);
    assert.notDeepEqual(k1, k2);
  });

  it("uses SHA-256 start key then PBKDF2-HMAC-SHA1", () => {
    const password = "test123";
    const salt = Buffer.alloc(16, 0x01);
    const key = deriveHwpxKey(password, salt, 1024, 32);

    const startKey = createHash("sha256")
      .update(Buffer.from(password, "utf-8"))
      .digest();
    const expected = pbkdf2Sync(startKey, salt, 1024, 32, "sha1");
    assert.deepEqual(key, expected);
  });
});

describe("parseManifest", () => {
  const sampleManifest = `<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
  <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.hancom.hwpx"/>
  <manifest:file-entry manifest:full-path="Contents/section0.xml" manifest:size="500">
    <manifest:encryption-data manifest:checksum="${Buffer.alloc(32, 0xaa).toString("base64")}"
                              manifest:checksum-type="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k">
      <manifest:algorithm manifest:algorithm-name="http://www.w3.org/2001/04/xmlenc#aes256-cbc"
                          manifest:initialisation-vector="${Buffer.alloc(16, 0xbb).toString("base64")}"/>
      <manifest:key-derivation manifest:key-derivation-name="PBKDF2"
                               manifest:key-size="32"
                               manifest:iteration-count="1024"
                               manifest:salt="${Buffer.alloc(16, 0xcc).toString("base64")}"/>
      <manifest:start-key-generation manifest:start-key-generation-name="http://www.w3.org/2000/09/xmldsig#sha256"
                                     manifest:key-size="32"/>
    </manifest:encryption-data>
  </manifest:file-entry>
  <manifest:file-entry manifest:full-path="mimetype"/>
</manifest:manifest>`;

  it("parses encrypted entries", () => {
    const entries = parseManifest(sampleManifest);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].fullPath, "Contents/section0.xml");
    assert.equal(entries[0].originalSize, 500);
    assert.equal(entries[0].keySize, 32);
    assert.equal(entries[0].iterationCount, 1024);
  });

  it("decodes base64 fields", () => {
    const entries = parseManifest(sampleManifest);
    assert.equal(entries[0].checksum.length, 32);
    assert.equal(entries[0].iv.length, 16);
    assert.equal(entries[0].salt.length, 16);
  });

  it("skips non-encrypted entries", () => {
    const entries = parseManifest(sampleManifest);
    const paths = entries.map((e) => e.fullPath);
    assert.ok(!paths.includes("/"));
    assert.ok(!paths.includes("mimetype"));
  });
});

describe("cleanManifest", () => {
  it("removes encryption-data elements", () => {
    const xml = `<manifest:file-entry manifest:full-path="test.xml" manifest:size="100">
      <manifest:encryption-data manifest:checksum="abc">
        <manifest:algorithm/>
        <manifest:key-derivation/>
      </manifest:encryption-data>
    </manifest:file-entry>`;
    const cleaned = cleanManifest(xml);
    assert.ok(!cleaned.includes("encryption-data"));
    assert.ok(!cleaned.includes('manifest:size="100"'));
    assert.ok(cleaned.includes("test.xml"));
  });
});

describe("detectFormat", () => {
  it("detects HWP (CFB magic bytes)", () => {
    const buf = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0x00, 0x00]);
    assert.equal(detectFormat(buf), "hwp");
  });

  it("detects HWPX (ZIP magic bytes)", () => {
    const buf = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00]);
    assert.equal(detectFormat(buf), "hwpx");
  });

  it("returns unknown for other data", () => {
    const buf = Buffer.from([0x00, 0x01, 0x02, 0x03]);
    assert.equal(detectFormat(buf), "unknown");
  });

  it("returns unknown for short buffer", () => {
    assert.equal(detectFormat(Buffer.alloc(2)), "unknown");
  });
});

describe("decryptHwpx", () => {
  function createEncryptedHwpx(password: string): Buffer {
    const plaintext = `<?xml version="1.0"?>
<hp:p><hp:run><hp:t>Hello HWPX World</hp:t></hp:run></hp:p>`;
    const plaintextBuf = Buffer.from(plaintext, "utf-8");
    const compressed = deflateRawSync(plaintextBuf);

    const salt = randomBytes(16);
    const iv = Buffer.from(salt); // Hancom: salt == IV

    const startKey = createHash("sha256")
      .update(Buffer.from(password, "utf-8"))
      .digest();
    const derivedKey = pbkdf2Sync(startKey, salt, 1024, 32, "sha1");

    // Zero-pad to AES block size
    const padLen = 16 - (compressed.length % 16);
    const padded =
      padLen === 16
        ? compressed
        : Buffer.concat([compressed, Buffer.alloc(padLen)]);

    const cipher = createCipheriv("aes-256-cbc", derivedKey, iv);
    cipher.setAutoPadding(false);
    const encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);

    const checksum = createHash("sha256")
      .update(plaintextBuf.subarray(0, 1024))
      .digest();

    const manifest = `<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
  <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.hancom.hwpx"/>
  <manifest:file-entry manifest:full-path="Contents/section0.xml" manifest:size="${plaintextBuf.length}">
    <manifest:encryption-data manifest:checksum="${checksum.toString("base64")}"
                              manifest:checksum-type="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k">
      <manifest:algorithm manifest:algorithm-name="http://www.w3.org/2001/04/xmlenc#aes256-cbc"
                          manifest:initialisation-vector="${iv.toString("base64")}"/>
      <manifest:key-derivation manifest:key-derivation-name="PBKDF2"
                               manifest:key-size="32"
                               manifest:iteration-count="1024"
                               manifest:salt="${salt.toString("base64")}"/>
      <manifest:start-key-generation manifest:start-key-generation-name="http://www.w3.org/2000/09/xmldsig#sha256"
                                     manifest:key-size="32"/>
    </manifest:encryption-data>
  </manifest:file-entry>
</manifest:manifest>`;

    const zip = new AdmZip();
    zip.addFile("mimetype", Buffer.from("application/vnd.hancom.hwpx"));
    zip.addFile("META-INF/manifest.xml", Buffer.from(manifest, "utf-8"));
    zip.addFile("Contents/section0.xml", encrypted);
    return zip.toBuffer();
  }

  it("decrypts with correct password", () => {
    const hwpx = createEncryptedHwpx("mypass");
    const decrypted = decryptHwpx(hwpx, "mypass");

    const zip = new AdmZip(decrypted);
    const section = zip.getEntry("Contents/section0.xml");
    assert.ok(section);
    const xml = section.getData().toString("utf-8");
    assert.ok(xml.includes("Hello HWPX World"));
  });

  it("throws on wrong password", () => {
    const hwpx = createEncryptedHwpx("correct");
    assert.throws(() => decryptHwpx(hwpx, "wrong"), /Wrong password/);
  });

  it("throws on non-encrypted HWPX", () => {
    const zip = new AdmZip();
    zip.addFile("mimetype", Buffer.from("application/vnd.hancom.hwpx"));
    zip.addFile(
      "META-INF/manifest.xml",
      Buffer.from(
        `<?xml version="1.0"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
        <manifest:file-entry manifest:full-path="/"/></manifest:manifest>`,
      ),
    );
    assert.throws(() => decryptHwpx(zip.toBuffer(), "pass"), /not password/);
  });
});

describe("extractTextHwpx", () => {
  it("extracts text from section XML", () => {
    const xml = `<?xml version="1.0"?>
<sec xmlns:hp="http://www.hancom.co.kr/hwpml/2011/paragraph">
  <hp:p><hp:run><hp:t>첫 번째 문단</hp:t></hp:run></hp:p>
  <hp:p><hp:run><hp:t>두 번째 문단</hp:t></hp:run></hp:p>
</sec>`;

    const zip = new AdmZip();
    zip.addFile("Contents/section0.xml", Buffer.from(xml, "utf-8"));
    const text = extractTextHwpx(zip.toBuffer());
    assert.ok(text.includes("첫 번째 문단"));
    assert.ok(text.includes("두 번째 문단"));
  });

  it("handles XML entities", () => {
    const xml = `<sec xmlns:hp="http://www.hancom.co.kr/hwpml/2011/paragraph">
  <hp:p><hp:run><hp:t>A &amp; B &lt; C</hp:t></hp:run></hp:p>
</sec>`;

    const zip = new AdmZip();
    zip.addFile("Contents/section0.xml", Buffer.from(xml, "utf-8"));
    const text = extractTextHwpx(zip.toBuffer());
    assert.ok(text.includes("A & B < C"));
  });
});
