import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deriveKey } from "../key-derivation.js";
import { hwpCipher } from "../cipher.js";

describe("deriveKey", () => {
  it("produces a 16-byte AES key", () => {
    const key = deriveKey("test");
    assert.equal(key.length, 16);
  });

  it("is deterministic", () => {
    const a = deriveKey("hello");
    const b = deriveKey("hello");
    assert.deepEqual(a, b);
  });

  it("different passwords produce different keys", () => {
    const a = deriveKey("password1");
    const b = deriveKey("password2");
    assert.notDeepEqual(a, b);
  });
});

describe("hwpCipher", () => {
  it("encrypt then decrypt round-trips a single block", () => {
    const key = deriveKey("mypassword");
    const plaintext = Buffer.from("0123456789abcdef"); // exactly 16 bytes

    const encrypted = hwpCipher(key, plaintext, true);
    assert.equal(encrypted.length, 16);
    assert.notDeepEqual(encrypted, plaintext);

    const decrypted = hwpCipher(key, encrypted, false);
    assert.deepEqual(decrypted, plaintext);
  });

  it("round-trips multiple blocks", () => {
    const key = deriveKey("secret");
    const plaintext = Buffer.alloc(64);
    for (let i = 0; i < 64; i++) plaintext[i] = i;

    const encrypted = hwpCipher(key, plaintext, true);
    const decrypted = hwpCipher(key, encrypted, false);
    assert.deepEqual(decrypted, plaintext);
  });

  it("round-trips with various data patterns", () => {
    const key = deriveKey("한글비밀번호");

    // all zeros
    const zeros = Buffer.alloc(32, 0);
    assert.deepEqual(hwpCipher(key, hwpCipher(key, zeros, true), false), zeros);

    // all 0xff
    const ones = Buffer.alloc(32, 0xff);
    assert.deepEqual(hwpCipher(key, hwpCipher(key, ones, true), false), ones);
  });

  it("wrong key does not decrypt correctly", () => {
    const key1 = deriveKey("correct");
    const key2 = deriveKey("wrong");
    const plaintext = Buffer.from("sensitive data!!");

    const encrypted = hwpCipher(key1, plaintext, true);
    const badDecrypt = hwpCipher(key2, encrypted, false);
    assert.notDeepEqual(badDecrypt, plaintext);
  });
});
