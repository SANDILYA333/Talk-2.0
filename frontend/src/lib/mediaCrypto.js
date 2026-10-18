const AAD = new TextEncoder().encode("talk/blob/v1");

/**
 * Encrypt arbitrary media blob with AES-256-GCM using WebCrypto.
 * Fresh 32-byte key and 12-byte IV per call, tagged with AAD 'talk/blob/v1'.
 */
export async function encryptBlob(plainBytes) {
  const bytes = plainBytes instanceof Uint8Array ? plainBytes : new Uint8Array(plainBytes);
  const key = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: AAD,
      tagLength: 128,
    },
    cryptoKey,
    bytes
  );

  return {
    ciphertext: new Uint8Array(encryptedBuffer),
    key,
    nonce,
  };
}

/**
 * Decrypt media blob with AES-256-GCM using WebCrypto.
 * Verifies authentication tag + AAD and confirms decrypted length === declaredSize.
 */
export async function decryptBlob({ ciphertext, key, nonce, declaredSize }) {
  const ctBytes = ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext);
  const keyBytes = key instanceof Uint8Array ? key : new Uint8Array(key);
  const nonceBytes = nonce instanceof Uint8Array ? nonce : new Uint8Array(nonce);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonceBytes,
      additionalData: AAD,
      tagLength: 128,
    },
    cryptoKey,
    ctBytes
  );

  const decrypted = new Uint8Array(decryptedBuffer);

  if (typeof declaredSize === "number" && decrypted.byteLength !== declaredSize) {
    throw new Error(`Size mismatch: expected ${declaredSize} bytes but decrypted ${decrypted.byteLength}`);
  }

  return decrypted;
}
