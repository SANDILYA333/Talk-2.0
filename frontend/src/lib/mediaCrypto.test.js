import { describe, it, expect } from "vitest";
import { encryptBlob, decryptBlob } from "./mediaCrypto.js";

describe("mediaCrypto (AES-256-GCM + AAD)", () => {
  it("round trips at 1 B, 1 MB, and 5 MB", async () => {
    for (const size of [1, 1024 * 1024, 5 * 1024 * 1024]) {
      const plain = new Uint8Array(size);
      plain.fill(0x42);

      const { ciphertext, key, nonce } = await encryptBlob(plain);
      expect(ciphertext.byteLength).toBe(size + 16); // 16-byte auth tag
      expect(key.byteLength).toBe(32);
      expect(nonce.byteLength).toBe(12);

      const decrypted = await decryptBlob({
        ciphertext,
        key,
        nonce,
        declaredSize: size,
      });

      expect(decrypted.byteLength).toBe(size);
      expect(Buffer.from(decrypted).equals(Buffer.from(plain))).toBe(true);
    }
  });

  it("ciphertext does not start with plaintext magic bytes and IV is unique per call", async () => {
    const pngMagic = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const { ciphertext: c1, nonce: n1 } = await encryptBlob(pngMagic);
    const { ciphertext: c2, nonce: n2 } = await encryptBlob(pngMagic);

    expect(n1).not.toEqual(n2);
    expect(c1.slice(0, 8)).not.toEqual(pngMagic);
    expect(c1).not.toEqual(c2);
  });

  it("fails on tampered byte", async () => {
    const plain = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const { ciphertext, key, nonce } = await encryptBlob(plain);

    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 1;

    await expect(
      decryptBlob({ ciphertext: tampered, key, nonce, declaredSize: plain.length })
    ).rejects.toThrow();
  });

  it("fails on truncation", async () => {
    const plain = new Uint8Array(100);
    const { ciphertext, key, nonce } = await encryptBlob(plain);

    const truncated = ciphertext.slice(0, -1);
    await expect(
      decryptBlob({ ciphertext: truncated, key, nonce, declaredSize: plain.length })
    ).rejects.toThrow();
  });

  it("fails on appended bytes", async () => {
    const plain = new Uint8Array(100);
    const { ciphertext, key, nonce } = await encryptBlob(plain);

    const appended = new Uint8Array(ciphertext.length + 1);
    appended.set(ciphertext);
    appended[ciphertext.length] = 0x42;

    await expect(
      decryptBlob({ ciphertext: appended, key, nonce, declaredSize: plain.length })
    ).rejects.toThrow();
  });

  it("fails on wrong key", async () => {
    const plain = new Uint8Array([1, 2, 3, 4]);
    const { ciphertext, nonce } = await encryptBlob(plain);
    const wrongKey = new Uint8Array(32);
    wrongKey[0] = 0xff;

    await expect(
      decryptBlob({ ciphertext, key: wrongKey, nonce, declaredSize: plain.length })
    ).rejects.toThrow();
  });

  it("fails when decrypted length != declaredSize", async () => {
    const plain = new Uint8Array([1, 2, 3, 4]);
    const { ciphertext, key, nonce } = await encryptBlob(plain);

    await expect(
      decryptBlob({ ciphertext, key, nonce, declaredSize: plain.length + 1 })
    ).rejects.toThrow(/size mismatch/i);
  });
});
