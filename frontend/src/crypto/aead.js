import { concat, utf8, randomBytes } from "./bytes.js";
import { CryptoError } from "./errors.js";

export const TYPE = { text: 1, media: 2, secret: 3 };
const LABEL = utf8("talk/aad/v1");
const ID_RE = /^[0-9a-f]{24}$/;

export function buildAad({ v, type, senderId, receiverId, ikSender, ikReceiver }) {
  if (v !== 1 && v !== 2) throw new Error("bad-v");
  if (!TYPE[type]) throw new Error("bad-type");
  if (!ID_RE.test(senderId) || !ID_RE.test(receiverId)) throw new Error("bad-id");
  if (ikSender?.length !== 32 || ikReceiver?.length !== 32) throw new Error("bad-key");
  return concat(LABEL, Uint8Array.of(v, TYPE[type]), utf8(senderId), utf8(receiverId), ikSender, ikReceiver);
}

const importKey = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);

export async function aeadEncrypt(key32, plaintext, aad) {
  const nonce = randomBytes(12);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad },
    await importKey(key32),
    plaintext
  );
  return { nonce, ciphertext: new Uint8Array(ct) };
}

export async function aeadDecrypt(key32, nonce, ciphertext, aad) {
  if (nonce.length !== 12 || ciphertext.length < 16) throw new CryptoError("tampered");
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad },
      await importKey(key32),
      ciphertext
    );
    return new Uint8Array(pt);
  } catch {
    throw new CryptoError("tampered");
  }
}
