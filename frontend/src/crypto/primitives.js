import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes, equal, utf8 } from "./bytes.js";

const ZERO32 = new Uint8Array(32);

export function dh(priv, pub) {
  const out = x25519.getSharedSecret(priv, pub);
  if (equal(out, ZERO32)) throw new Error("bad-dh"); // low-order point
  return out;
}
export const xPub = (priv) => x25519.getPublicKey(priv);
export const edPub = (priv) => ed25519.getPublicKey(priv);
export const edSign = (msg, priv) => ed25519.sign(msg, priv);
export function edVerify(sig, msg, pub) {
  try {
    return ed25519.verify(sig, msg, pub);
  } catch {
    return false;
  }
}
export const kdf = (ikm, info, len = 32, salt = ZERO32) =>
  hkdf(sha256, ikm, salt, typeof info === "string" ? utf8(info) : info, len);

// any 32 random bytes are a valid X25519 scalar / Ed25519 seed
export const newSecret = () => randomBytes(32);
