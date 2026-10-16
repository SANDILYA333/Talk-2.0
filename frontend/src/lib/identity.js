import nacl from "tweetnacl";
import { get, set } from "idb-keyval";
import { axiosInstance } from "./axios";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const toB64 = (u8) => btoa(String.fromCharCode(...u8));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// Must match backend/src/lib/connectCode.js byte-for-byte
export async function deriveConnectCode(publicKeyB64) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64(publicKeyB64)));
  let out = "", acc = 0, nbits = 0;
  for (const byte of hash) {
    acc = (acc << 8) | byte;
    nbits += 8;
    while (nbits >= 5 && out.length < 10) {
      out += ALPHABET[(acc >> (nbits - 5)) & 31];
      nbits -= 5;
    }
    acc &= (1 << nbits) - 1;
    if (out.length === 10) break;
  }
  return `TALK-${out.slice(0, 5)}-${out.slice(5)}`;
}

export function normalizeConnectCode(input) {
  let s = String(input || "").toUpperCase().replace(/[^0-9A-Z]/g, "");
  if (s.length === 14 && s.startsWith("TALK")) s = s.slice(4);
  s = s.replace(/O/g, "0").replace(/[IL]/g, "1");
  if (!/^[0-9A-HJKMNP-TV-Z]{10}$/.test(s)) return null;
  return `TALK-${s.slice(0, 5)}-${s.slice(5)}`;
}

const keyName = (u) => `identity:${u._id}`;
let inflight = null; // stops double keypair creation under StrictMode

export function ensureIdentity(authUser) {
  if (!inflight) inflight = run(authUser).finally(() => { inflight = null; });
  return inflight;
}

async function run(u) {
  let kp = await get(keyName(u));

  if (!kp) {
    if (u.publicKey) return { status: "missing-local", connectCode: u.connectCode }; // new device / cleared storage
    const pair = nacl.box.keyPair();
    kp = { publicKey: toB64(pair.publicKey), secretKey: toB64(pair.secretKey) };
    await set(keyName(u), kp);
    navigator.storage?.persist?.();
  }

  if (u.publicKey && u.publicKey !== kp.publicKey) {
    return { status: "mismatch", connectCode: u.connectCode };
  }
  if (!u.publicKey) {
    const { data } = await axiosInstance.put("/identity", { publicKey: kp.publicKey });
    return { status: "ok", connectCode: data.connectCode };
  }
  return { status: "ok", connectCode: u.connectCode };
}

export async function resetIdentity(authUser) {
  const pair = nacl.box.keyPair();
  const kp = { publicKey: toB64(pair.publicKey), secretKey: toB64(pair.secretKey) };
  const { data } = await axiosInstance.put("/identity", { publicKey: kp.publicKey, replace: true });
  await set(keyName(authUser), kp);
  return { status: "ok", connectCode: data.connectCode };
}

export async function lookupContact(rawCode) {
  const code = normalizeConnectCode(rawCode);
  if (!code) throw new Error("That doesn't look like a TALK code");
  const { data } = await axiosInstance.get(`/identity/lookup/${code}`);
  const derived = await deriveConnectCode(data.publicKey);
  if (derived !== code || derived !== data.connectCode) {
    throw new Error("Server returned a key that doesn't match this code. Refusing.");
  }
  return data; // { _id, fullName, profilePic, publicKey, connectCode }
}
