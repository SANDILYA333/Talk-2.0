import { axiosInstance } from "./axios";
import { fetchBundle } from "./keyApi";
import { checkContact, readPin } from "./safety";
import { loadIdentity, getSpkPriv, getPlain, putPlain } from "../storage/keystore";
import { encryptV1, decryptV1, fromB64, toB64, CryptoError } from "../crypto/index.js";
import { decryptBlob } from "./mediaCrypto.js";
import { blobStore } from "./blobStore.js";
import { validateAttachment } from "./mediaSecurity.js";

const BUNDLE_TTL_MS = 5 * 60_000;
const bundleCache = new Map(); // peerId -> { at, bundle }
const pinInflight = new Map(); // senderId -> Promise
const mediaObjectUrlCache = new Map(); // messageId -> objectUrl
const MAX_MEDIA_CACHE = 40;

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

export async function encryptEnvelope({ me, peerId, type = "text", envelope }) {
  const idn = await loadIdentity(me);
  if (!idn) throw new SendError("no-identity");

  const bundle = await cachedBundle(peerId);
  const cur = { ik: toB64(bundle.ikPub), sik: toB64(bundle.sikPub) };
  const trust = await checkContact(me, peerId, cur);
  if (trust.status === "changed") {
    clearBundleCache(peerId);
    throw new SendError("key-changed");
  }
  const pinned = { ik: bundle.ikPub, sik: bundle.sikPub };

  try {
    const payload = await encryptV1({ envelope, type, senderId: me, receiverId: peerId, myIk: idn.ik, bundle, pinned });
    return { payload, envelope };
  } catch (e) {
    if (e instanceof CryptoError) throw new SendError(e.code);
    throw e;
  }
}

export async function encryptText({ me, peerId, text }) {
  const envelope = { t: "text", body: text, ts: Date.now() };
  return encryptEnvelope({ me, peerId, type: "text", envelope });
}

export async function encryptMedia({ me, peerId, caption = "", att, blobId }) {
  const envelope = { t: "media", body: caption, ts: Date.now(), att };
  const res = await encryptEnvelope({ me, peerId, type: "media", envelope });
  if (blobId) {
    res.payload.blobId = blobId;
  }
  return res;
}

async function currentKeys(peerId) {
  const { data } = await axiosInstance.get(`/identity/key/${peerId}`);
  return { ik: data.publicKey, sik: data.sik };
}

function fetchAndPin(me, senderId) {
  if (!pinInflight.has(senderId)) {
    const p = (async () => {
      const cur = await currentKeys(senderId);
      await checkContact(me, senderId, cur);
      return readPin(me, senderId);
    })().finally(() => pinInflight.delete(senderId));
    pinInflight.set(senderId, p);
  }
  return pinInflight.get(senderId);
}

function toSafeAtt(att) {
  if (!att) return undefined;
  return {
    kind: att.kind,
    mime: att.mime,
    size: att.size,
    w: att.w,
    h: att.h,
    dur: att.dur,
    ph: att.ph,
  };
}

export async function readMessage({ me, msg }) {
  const hit = await getPlain(me, msg._id);
  if (hit) {
    return {
      state: "ok",
      text: hit.body ?? "",
      ts: hit.ts,
      type: hit.t || msg.type || "text",
      att: toSafeAtt(hit.att),
    };
  }

  if (msg.senderId === me) return { state: "undecryptable" };
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
      senderIkPub: fromB64(pin.ik),
    });

    if (env.t === "media") {
      if (!validateAttachment(env.att, blobStore.getEndpoint())) {
        return { state: "tampered" };
      }
    }

    await putPlain(me, msg._id, { t: env.t, body: env.body, ts: env.ts, att: env.att });
    return {
      state: "ok",
      text: env.body ?? "",
      ts: env.ts,
      type: env.t,
      att: toSafeAtt(env.att),
    };
  } catch (e) {
    const code = e instanceof CryptoError ? e.code : "tampered";
    if (code === "tampered") {
      const cur = await currentKeys(msg.senderId).catch(() => null);
      if (cur && (cur.ik !== pin.ik || (pin.sik && cur.sik && cur.sik !== pin.sik))) return { state: "key-changed" };
    }
    return { state: code };
  }
}

export async function loadMedia(me, messageId) {
  if (!me || !messageId) throw new Error("Missing parameters for loadMedia");

  if (mediaObjectUrlCache.has(messageId)) {
    return mediaObjectUrlCache.get(messageId);
  }

  const hit = await getPlain(me, messageId);
  if (!hit || !hit.att || !hit.att.key || !hit.att.nonce || !hit.att.url) {
    const err = new Error("Can't open this attachment on this device");
    err.code = "no-key";
    throw err;
  }

  const { att } = hit;
  const keyBytes = Uint8Array.from(atob(att.key), (c) => c.charCodeAt(0));
  const nonceBytes = Uint8Array.from(atob(att.nonce), (c) => c.charCodeAt(0));

  const ciphertext = await blobStore.fetch(att.url, { maxBytes: att.size + 16 });

  const plainBytes = await decryptBlob({
    ciphertext,
    key: keyBytes,
    nonce: nonceBytes,
    declaredSize: att.size,
  });

  const blob = new Blob([plainBytes], { type: att.mime });
  const objectUrl = URL.createObjectURL(blob);

  if (mediaObjectUrlCache.size >= MAX_MEDIA_CACHE) {
    const oldestKey = mediaObjectUrlCache.keys().next().value;
    const oldUrl = mediaObjectUrlCache.get(oldestKey);
    URL.revokeObjectURL(oldUrl);
    mediaObjectUrlCache.delete(oldestKey);
  }

  mediaObjectUrlCache.set(messageId, objectUrl);
  return objectUrl;
}

export function revokeMediaUrl(messageId) {
  if (mediaObjectUrlCache.has(messageId)) {
    URL.revokeObjectURL(mediaObjectUrlCache.get(messageId));
    mediaObjectUrlCache.delete(messageId);
  }
}

export async function toItem(me, msg) {
  const r = await readMessage({ me, msg });
  return {
    _id: msg._id, cid: msg.cid, senderId: msg.senderId, receiverId: msg.receiverId,
    createdAt: msg.createdAt, type: r.type || msg.type,
    state: r.state, text: r.text ?? "",
    att: r.att,
    raw: r.state === "ok" ? undefined : msg,
  };
}

export async function snippetFor(me, lastMessage) {
  if (!lastMessage?._id) return "";
  const hit = await getPlain(me, lastMessage._id);
  if (!hit) {
    if (lastMessage.type === "media") return "Photo";
    return "Encrypted message";
  }

  if (hit.t === "media" || (lastMessage.type === "media" && hit.att)) {
    const label = hit.att?.kind === "video" ? "Video" : "Photo";
    return hit.body ? `${label}: ${hit.body}` : label;
  }

  const text = hit.body ?? "";
  return text.length > 80 ? text.slice(0, 79) + "…" : text;
}

