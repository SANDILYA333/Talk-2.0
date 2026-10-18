import { axiosInstance } from "./axios";
import { fetchBundle } from "./keyApi";
import { checkContact, readPin } from "./safety";
import { loadIdentity, getSpkPriv, getPlain, putPlain } from "../storage/keystore";
import { encryptV1, decryptV1, fromB64, toB64, CryptoError } from "../crypto/index.js";

const BUNDLE_TTL_MS = 5 * 60_000;
const bundleCache = new Map(); // peerId -> { at, bundle }
const pinInflight = new Map(); // senderId -> Promise

export const clearBundleCache = (peerId) => (peerId ? bundleCache.delete(peerId) : bundleCache.clear());

export class SendError extends Error {
  constructor(code) { super(code); this.code = code; }
}

async function cachedBundle(peerId) {
  const hit = bundleCache.get(peerId);
  if (hit && Date.now() - hit.at < BUNDLE_TTL_MS) return hit.bundle;
  try {
    const bundle = await fetchBundle(peerId);
    bundleCache.set(peerId, { at: Date.now(), bundle });
    return bundle;
  } catch (e) {
    const status = e.response?.status;
    const msg = e.response?.data?.message;
    if (status === 404 || msg === "recipient-no-keys") throw new SendError("recipient-no-keys");
    if (msg === "recipient-keys-stale") throw new SendError("recipient-keys-stale");
    throw new SendError(e.message === "bad-bundle" ? "bad-bundle" : "network");
  }
}

export async function encryptText({ me, peerId, text }) {
  const idn = await loadIdentity(me);
  if (!idn) throw new SendError("no-identity");

  const bundle = await cachedBundle(peerId);
  const cur = { ik: toB64(bundle.ikPub), sik: toB64(bundle.sikPub) };
  const trust = await checkContact(me, peerId, cur);
  if (trust.status === "changed") {
    clearBundleCache(peerId);
    throw new SendError("key-changed");
  }
  // "new" and "ok": the stored pin now equals what the server just served
  const pinned = { ik: bundle.ikPub, sik: bundle.sikPub };

  const envelope = { t: "text", body: text, ts: Date.now() };
  try {
    const payload = await encryptV1({ envelope, type: "text", senderId: me, receiverId: peerId, myIk: idn.ik, bundle, pinned });
    return { payload, envelope };
  } catch (e) {
    if (e instanceof CryptoError) throw new SendError(e.code);
    throw e;
  }
}

async function currentKeys(peerId) {
  const { data } = await axiosInstance.get(`/identity/key/${peerId}`);
  return { ik: data.publicKey, sik: data.sik };
}

// first contact: fetch once per sender, pin, return the pin (null if the sender has no keys yet)
function fetchAndPin(me, senderId) {
  if (!pinInflight.has(senderId)) {
    const p = (async () => {
      const cur = await currentKeys(senderId);
      await checkContact(me, senderId, cur); // pins on first sight
      return readPin(me, senderId);
    })().finally(() => pinInflight.delete(senderId));
    pinInflight.set(senderId, p);
  }
  return pinInflight.get(senderId);
}

// -> { state, text?, ts? }
// state: ok | undecryptable | tampered | key-changed | unsupported-version | waiting-for-key
export async function readMessage({ me, msg }) {
  const hit = await getPlain(me, msg._id);
  if (hit) return { state: "ok", text: hit.body, ts: hit.ts };

  if (msg.senderId === me) return { state: "undecryptable" }; // sent from another device / cache cleared
  if (msg.v !== 1) return { state: "unsupported-version" };

  const idn = await loadIdentity(me);
  if (!idn) return { state: "undecryptable" };

  let pin = await readPin(me, msg.senderId);
  if (!pin) {
    try { pin = await fetchAndPin(me, msg.senderId); } catch { return { state: "waiting-for-key" }; }
    if (!pin) return { state: "waiting-for-key" };
  }

  try {
    const env = await decryptV1({
      msg, senderId: msg.senderId, receiverId: me, myIk: idn.ik,
      getSpkPriv: (id) => getSpkPriv(me, id),
      senderIkPub: fromB64(pin.ik), // the pin, never anything from the message
    });
    await putPlain(me, msg._id, { t: env.t, body: env.body, ts: env.ts });
    return { state: "ok", text: env.body, ts: env.ts };
  } catch (e) {
    const code = e instanceof CryptoError ? e.code : "tampered";
    if (code === "tampered") {
      const cur = await currentKeys(msg.senderId).catch(() => null);
      if (cur && (cur.ik !== pin.ik || (pin.sik && cur.sik && cur.sik !== pin.sik))) return { state: "key-changed" };
    }
    return { state: code };
  }
}

// message wire object -> store item
export async function toItem(me, msg) {
  const r = await readMessage({ me, msg });
  return {
    _id: msg._id, cid: msg.cid, senderId: msg.senderId, receiverId: msg.receiverId,
    createdAt: msg.createdAt, type: msg.type,
    state: r.state, text: r.text ?? "",
    raw: r.state === "ok" ? undefined : msg, // kept only so reprocess() can retry
  };
}

export async function snippetFor(me, lastMessage) {
  if (!lastMessage?._id) return "";
  const hit = await getPlain(me, lastMessage._id);
  if (!hit) return "Encrypted message";
  return hit.body.length > 80 ? hit.body.slice(0, 79) + "…" : hit.body;
}
