import { axiosInstance } from "./axios";
import { fetchBundle } from "./keyApi";
import { checkContact, readPin } from "./safety";
import {
  loadIdentity,
  getSpkPriv,
  getOpkPriv,
  deleteOpkPriv,
  takeOpkPriv,
  getPlain,
  putPlain,
  withSessionLock,
  loadSession,
  saveSession,
  loadLoserSession,
  saveLoserSession,
} from "../storage/keystore";
import {
  encryptV1,
  decryptV1,
  initiateSession,
  encryptSessionMessage,
  decryptSessionMessage,
  resolveSimultaneousInitiation,
  initiateRatchetSession,
  respondRatchetSession,
  ratchetEncrypt,
  ratchetDecrypt,
  upgradeFromS8Session,
  fromB64,
  toB64,
  CryptoError,
  SendError,
  normalizeErrorCode,
  PEER_NO_KEYS,
  SESSION_SETUP_FAILED,
  PEER_KEY_CHANGED,
  DECRYPT_FAILED,
  DUPLICATE_MESSAGE,
  TOO_MANY_SKIPPED,
  SESSION_RESET_REQUIRED,
  HISTORY_UNAVAILABLE,
  LOCAL_KEYS_MISSING,
  STORAGE_UNAVAILABLE,
  UNSUPPORTED_VERSION,
  MEDIA_DECRYPT_FAILED,
  verifyBundle,
  equal,
} from "../crypto/index.js";
import { decryptBlob } from "./mediaCrypto.js";
import { blobStore } from "./blobStore.js";
import { validateAttachment } from "./mediaSecurity.js";

const BUNDLE_TTL_MS = 5 * 60_000;
const bundleCache = new Map(); // peerId -> { at, bundle }
const pinInflight = new Map(); // senderId -> Promise
const mediaObjectUrlCache = new Map(); // messageId -> objectUrl
const MAX_MEDIA_CACHE = 40;

export const clearBundleCache = (peerId) => (peerId ? bundleCache.delete(peerId) : bundleCache.clear());

export { SendError };

async function cachedBundle(peerId, { opk = false } = {}) {
  const hit = bundleCache.get(peerId);
  // When an OPK is needed, we do not use the cache because an OPK must be fetched freshly with ?opk=1
  if (!opk && hit && Date.now() - hit.at < BUNDLE_TTL_MS) return hit.bundle;
  try {
    const bundle = await fetchBundle(peerId, { opk });
    if (!opk) bundleCache.set(peerId, { at: Date.now(), bundle });
    return bundle;
  } catch (e) {
    const status = e.response?.status;
    const msg = e.response?.data?.message;
    if (status === 404 || msg === "recipient-no-keys") throw new SendError(PEER_NO_KEYS);
    if (msg === "recipient-keys-stale") throw new SendError(SESSION_SETUP_FAILED);
    throw new SendError(e.message === "bad-bundle" ? SESSION_SETUP_FAILED : "network");
  }
}

export async function encryptEnvelope({ me, peerId, type = "text", envelope }) {
  const idn = await loadIdentity(me);
  if (!idn) throw new SendError(LOCAL_KEYS_MISSING);

  return withSessionLock(me, peerId, async () => {
    let session = await loadSession(me, peerId);
    let initialHeader = null;

    if (!session) {
      // Fetch bundle requesting an OPK (?opk=1)
      const bundle = await cachedBundle(peerId, { opk: true });
      const cur = { ik: toB64(bundle.ikPub), sik: toB64(bundle.sikPub) };
      const trust = await checkContact(me, peerId, cur);
      if (trust.status === "changed") {
        clearBundleCache(peerId);
        throw new SendError(PEER_KEY_CHANGED);
      }
      const pinned = { ik: bundle.ikPub, sik: bundle.sikPub };

      try {
        const init = await initiateRatchetSession({
          senderId: me,
          receiverId: peerId,
          myIk: idn.ik,
          mySik: idn.sik,
          bundle,
          pinned,
        });
        session = init.session;
        initialHeader = init.initialHeader;
      } catch (e) {
        if (e instanceof CryptoError) throw new SendError(e.code);
        throw e;
      }
    } else {
      // Verify pinned identity has not changed
      const pin = await readPin(me, peerId);
      if (pin && session.peerIk && pin.ik !== session.peerIk) {
        throw new SendError(PEER_KEY_CHANGED);
      }
      if (pin && session.peerSik && pin.sik && pin.sik !== session.peerSik) {
        throw new SendError(PEER_KEY_CHANGED);
      }
      if (!session.rk || !session.dhs) {
        session = upgradeFromS8Session(session);
      }
    }

    try {
      const payload = await ratchetEncrypt({
        session,
        envelope,
        type,
        senderId: me,
        receiverId: peerId,
        myIk: idn.ik,
        initialHeader,
      });

      await saveSession(me, peerId, session);
      return { payload, envelope };
    } catch (e) {
      if (e instanceof CryptoError) throw new SendError(e.code);
      throw e;
    }
  });
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
      const bundle = await cachedBundle(senderId, { opk: false });
      const check = verifyBundle(bundle, {});
      if (!check.ok) {
        throw new CryptoError(SESSION_SETUP_FAILED, "bad-bundle-signature");
      }
      const cur = { ik: toB64(bundle.ikPub), sik: toB64(bundle.sikPub), protoMax: bundle.protoMax ?? 1 };
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

  if (msg.senderId === me) return { state: DECRYPT_FAILED };
  if (msg.v !== 1 && msg.v !== 2) return { state: UNSUPPORTED_VERSION };

  const idn = await loadIdentity(me);
  if (!idn) return { state: LOCAL_KEYS_MISSING };

  let pin = await readPin(me, msg.senderId);
  if (!pin) {
    try {
      pin = await fetchAndPin(me, msg.senderId);
    } catch (e) {
      if (e instanceof CryptoError) return { state: e.code };
      return { state: "waiting-for-key" };
    }
    if (!pin) return { state: "waiting-for-key" };
  }

  if (msg.v === 1) {
    const existingSession = await loadSession(me, msg.senderId);
    const isEstablished = existingSession && (existingSession.state === "established" || existingSession.rk);
    if (isEstablished || (pin?.protoMax && pin.protoMax >= 2)) {
      return { state: UNSUPPORTED_VERSION };
    }

    try {
      const env = await decryptV1({
        msg, senderId: msg.senderId, receiverId: me, myIk: idn.ik,
        getSpkPriv: (id) => getSpkPriv(me, id),
        senderIkPub: fromB64(pin.ik),
      });

      if (env.t === "media") {
        if (!validateAttachment(env.att, blobStore.getEndpoint())) {
          return { state: MEDIA_DECRYPT_FAILED };
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
      let code = e instanceof CryptoError ? e.code : DECRYPT_FAILED;
      code = normalizeErrorCode(code);
      if (code === DECRYPT_FAILED) {
        const cur = await currentKeys(msg.senderId).catch(() => null);
        if (cur && (cur.ik !== pin.ik || (pin.sik && cur.sik && cur.sik !== pin.sik))) return { state: PEER_KEY_CHANGED };
      }
      return { state: code };
    }
  }

  // msg.v === 2
  return withSessionLock(me, msg.senderId, async () => {
    let session = await loadSession(me, msg.senderId);
    let isLoserSession = false;

    if (pin) {
      if (msg.header?.ik && !equal(fromB64(pin.ik), fromB64(msg.header.ik))) return { state: PEER_KEY_CHANGED };
      if (msg.header?.sik && pin.sik && !equal(fromB64(pin.sik), fromB64(msg.header.sik))) return { state: PEER_KEY_CHANGED };
      if (session && session.sessionId === msg.header?.sessionId) {
        if (session.peerIk && pin.ik !== session.peerIk) return { state: PEER_KEY_CHANGED };
        if (session.peerSik && pin.sik && pin.sik !== session.peerSik) return { state: PEER_KEY_CHANGED };
      }
    }

    // Check simultaneous initiation tie-breaking if session is pending and an incoming initial message arrives
    if (session && session.state === "pending" && msg.header?.ek && msg.header?.sessionId !== session.sessionId) {
      const peerIkPub = fromB64(session.peerIk || pin.ik);
      const tie = resolveSimultaneousInitiation({
        localSession: session,
        incomingHeader: msg.header,
        myIk: idn.ik.pub,
        peerIk: peerIkPub,
      });

      if (!tie.winnerIsMe) {
        // Peer's session won: save local initiator session as loser session, allow new session creation
        await saveLoserSession(me, msg.senderId, session);
        session = null;
      }
    }

    // If incoming message belongs to a loser session, try decrypting with loser session
    if (!session || (msg.header?.sessionId && session.sessionId !== msg.header.sessionId)) {
      const loser = await loadLoserSession(me, msg.senderId);
      if (loser && loser.sessionId === msg.header?.sessionId) {
        session = loser;
        isLoserSession = true;
      }
    }

    try {
      let dec;
      if (msg.header?.dh) {
        dec = await ratchetDecrypt({
          session,
          receiverId: me,
          senderId: msg.senderId,
          myIk: idn.ik,
          msg,
          getSpkPriv: (id) => getSpkPriv(me, id),
          getOpkPriv: (id) => getOpkPriv(me, id),
          takeOpkPriv: (id) => takeOpkPriv(me, id),
          pinned: { ik: fromB64(pin.ik), sik: pin.sik ? fromB64(pin.sik) : null },
        });
      } else {
        dec = await decryptSessionMessage({
          session,
          receiverId: me,
          senderId: msg.senderId,
          myIk: idn.ik,
          msg,
          getSpkPriv: (id) => getSpkPriv(me, id),
          takeOpkPriv: (id) => takeOpkPriv(me, id),
          pinned: { ik: fromB64(pin.ik), sik: pin.sik ? fromB64(pin.sik) : null },
        });
      }

      const env = dec.envelope;
      if (env.t === "media") {
        if (!validateAttachment(env.att, blobStore.getEndpoint())) {
          return { state: MEDIA_DECRYPT_FAILED };
        }
      }

      // Commit session state first
      if (isLoserSession) {
        await saveLoserSession(me, msg.senderId, dec.session);
      } else {
        await saveSession(me, msg.senderId, dec.session);
      }

      // Then delete OPK private key
      if (dec.consumedOpkId !== null && dec.consumedOpkId !== undefined) {
        await deleteOpkPriv(me, dec.consumedOpkId);
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
      let code = e instanceof CryptoError ? e.code : DECRYPT_FAILED;
      code = normalizeErrorCode(code);
      if (code === DECRYPT_FAILED) {
        const cur = await currentKeys(msg.senderId).catch(() => null);
        if (cur && (cur.ik !== pin.ik || (pin.sik && cur.sik && cur.sik !== pin.sik))) return { state: PEER_KEY_CHANGED };
      }
      return { state: code };
    }
  });
}

export async function loadMedia(me, messageId) {
  if (!me || !messageId) throw new Error("Missing parameters for loadMedia");

  if (mediaObjectUrlCache.has(messageId)) {
    return mediaObjectUrlCache.get(messageId);
  }

  const hit = await getPlain(me, messageId);
  if (!hit || !hit.att || !hit.att.key || !hit.att.nonce || !hit.att.url) {
    const err = new CryptoError(MEDIA_DECRYPT_FAILED, "Can't open this attachment on this device");
    throw err;
  }

  const { att } = hit;
  const keyBytes = Uint8Array.from(atob(att.key), (c) => c.charCodeAt(0));
  const nonceBytes = Uint8Array.from(atob(att.nonce), (c) => c.charCodeAt(0));

  const ciphertext = await blobStore.fetch(att.url, { maxBytes: att.size + 16 });

  let plainBytes;
  try {
    plainBytes = await decryptBlob({
      ciphertext,
      key: keyBytes,
      nonce: nonceBytes,
      declaredSize: att.size,
    });
  } catch {
    throw new CryptoError(MEDIA_DECRYPT_FAILED, "Attachment decryption failed");
  }

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

