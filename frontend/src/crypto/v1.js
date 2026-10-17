import { utf8, fromUtf8, toB64, fromB64 } from "./bytes.js";
import { newSecret, xPub, kdf } from "./primitives.js";
import { x3dhInitiate, x3dhRespond } from "./x3dh.js";
import { buildAad, aeadEncrypt, aeadDecrypt } from "./aead.js";
import { verifyBundle } from "./keys.js";
import { CryptoError } from "./errors.js";

export const MAX_TEXT_CHARS = 4000;
const BLOCK = 256;
const MAX_PADDED = 16384 - 16; // ciphertext cap minus GCM tag

export function pad(bytes) {
  const total = Math.ceil((bytes.length + 1) / BLOCK) * BLOCK;
  const out = new Uint8Array(total);
  out.set(bytes);
  out[bytes.length] = 0x80;
  return out;
}

export function unpad(bytes) {
  if (bytes.length === 0 || bytes.length % BLOCK !== 0) throw new CryptoError("tampered");
  let i = bytes.length - 1;
  while (i >= 0 && bytes[i] === 0) i--;
  if (i < 0 || bytes[i] !== 0x80) throw new CryptoError("tampered");
  return bytes.slice(0, i);
}

// myIk: { pub, priv }  bundle: see verifyBundle  pinned: { ik?, sik? }
export async function encryptV1({ envelope, type, senderId, receiverId, myIk, bundle, pinned }) {
  const check = verifyBundle(bundle, pinned);
  if (!check.ok) throw new CryptoError(check.reason);

  if (typeof envelope?.body === "string" && envelope.body.length > MAX_TEXT_CHARS) throw new CryptoError("too-long");
  const plain = pad(utf8(JSON.stringify(envelope)));
  if (plain.length > MAX_PADDED) throw new CryptoError("too-long");

  const ekPriv = newSecret();
  const ekPub = xPub(ekPriv);
  const sk = x3dhInitiate({ ikPriv: myIk.priv, ekPriv, ikPubB: bundle.ikPub, spkPubB: bundle.spk.pub });
  ekPriv.fill(0); // best effort

  const key = kdf(sk, "talk/v1/aead");
  const aad = buildAad({ v: 1, type, senderId, receiverId, ikSender: myIk.pub, ikReceiver: bundle.ikPub });
  const { nonce, ciphertext } = await aeadEncrypt(key, plain, aad);

  return {
    v: 1,
    type,
    nonce: toB64(nonce),
    ciphertext: toB64(ciphertext),
    header: { ek: toB64(ekPub), spkId: bundle.spk.id },
  };
}

// getSpkPriv(id) -> Uint8Array | null     senderIkPub comes from the pinned contact, never the message
export async function decryptV1({ msg, senderId, receiverId, myIk, getSpkPriv, senderIkPub }) {
  if (msg?.v !== 1) throw new CryptoError("unsupported-version");
  try {
    const spkPriv = getSpkPriv(msg.header?.spkId);
    if (!spkPriv) throw new CryptoError("undecryptable");

    const ekPub = fromB64(msg.header.ek);
    if (ekPub.length !== 32) throw new CryptoError("tampered");

    const sk = x3dhRespond({ ikPriv: myIk.priv, spkPriv, ikPubA: senderIkPub, ekPubA: ekPub });
    const key = kdf(sk, "talk/v1/aead");
    const aad = buildAad({ v: 1, type: msg.type, senderId, receiverId, ikSender: senderIkPub, ikReceiver: myIk.pub });

    const plain = unpad(await aeadDecrypt(key, fromB64(msg.nonce), fromB64(msg.ciphertext), aad));
    const envelope = JSON.parse(fromUtf8(plain));
    if (typeof envelope?.t !== "string" || typeof envelope?.ts !== "number") throw new CryptoError("tampered");
    return envelope;
  } catch (e) {
    throw e instanceof CryptoError ? e : new CryptoError("tampered");
  }
}
