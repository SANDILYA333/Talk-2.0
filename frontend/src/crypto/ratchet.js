import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { concat, utf8, fromUtf8, toB64, fromB64, randomBytes } from "./bytes.js";
import { newSecret, xPub, dh } from "./primitives.js";
import { x3dhInitiate, x3dhRespond } from "./x3dh.js";
import { aeadEncrypt, aeadDecrypt, u32be, TYPE } from "./aead.js";
import { pad, unpad, MAX_TEXT_CHARS } from "./v1.js";
import { verifyBundle } from "./keys.js";
import {
  CryptoError,
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
} from "./errors.js";

export const INFO_SESSION = "talk/x3dh/v2/session";
export const INFO_ROOT = utf8("talk/v2/ratchet/root");
export const LABEL_V2R = utf8("talk/aad/v2r");
const ID_RE = /^[0-9a-f]{24}$/;

export const MAX_SKIP = 1000;
export const MAX_TOTAL_SKIPPED = 2000;
export const SKIPPED_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const MAX_PADDED = 16384 - 16;

/**
 * Root KDF: HKDF-SHA256(salt=RK, ikm=dhOut, info="talk/v2/ratchet/root", length=64)
 * -> (newRk, newCk)
 */
export function kdfRk(rk, dhOut) {
  const salt = rk instanceof Uint8Array ? rk : fromB64(rk);
  const ikm = dhOut instanceof Uint8Array ? dhOut : fromB64(dhOut);
  const derived = hkdf(sha256, ikm, salt, INFO_ROOT, 64);
  return {
    newRk: derived.slice(0, 32),
    newCk: derived.slice(32, 64),
  };
}

/**
 * Symmetric Chain KDF:
 * Mk = HMAC-SHA256(CK, 0x01)
 * nextCk = HMAC-SHA256(CK, 0x02)
 */
export function kdfCk(ck) {
  const key = ck instanceof Uint8Array ? ck : fromB64(ck);
  const mk = hmac(sha256, key, Uint8Array.of(0x01));
  const nextCk = hmac(sha256, key, Uint8Array.of(0x02));
  return { mk, nextCk };
}

/**
 * AAD for Double Ratchet message v2
 */
export function buildAadRatchet({ type, senderId, receiverId, ikSender, ikReceiver, sessionId, n, pn, dhPub }) {
  if (!TYPE[type]) throw new Error("bad-type");
  if (!ID_RE.test(senderId) || !ID_RE.test(receiverId)) throw new Error("bad-id");
  const ikS = ikSender instanceof Uint8Array ? ikSender : fromB64(ikSender);
  const ikR = ikReceiver instanceof Uint8Array ? ikReceiver : fromB64(ikReceiver);
  const dhP = dhPub instanceof Uint8Array ? dhPub : fromB64(dhPub);
  if (ikS.length !== 32 || ikR.length !== 32) throw new Error("bad-key");
  if (dhP.length !== 32) throw new Error("bad-dh-pub");
  if (typeof sessionId !== "string" || !sessionId) throw new Error("bad-session-id");
  if (!Number.isInteger(n) || n < 0) throw new Error("bad-counter");
  if (!Number.isInteger(pn) || pn < 0) throw new Error("bad-prev-counter");

  return concat(
    LABEL_V2R,
    Uint8Array.of(2, TYPE[type]),
    utf8(senderId),
    utf8(receiverId),
    ikS,
    ikR,
    utf8(sessionId),
    u32be(n),
    u32be(pn),
    dhP
  );
}

/**
 * Deep clone of ratchet session state for atomicity
 */
function cloneSession(s) {
  if (!s) return null;
  return {
    peerId: s.peerId,
    sessionId: s.sessionId,
    role: s.role,
    rk: s.rk instanceof Uint8Array ? new Uint8Array(s.rk) : (typeof s.rk === "string" ? fromB64(s.rk) : s.rk),
    dhs: s.dhs ? { pub: s.dhs.pub, priv: s.dhs.priv } : null,
    dhr: s.dhr || null,
    cks: s.cks instanceof Uint8Array ? new Uint8Array(s.cks) : (typeof s.cks === "string" ? fromB64(s.cks) : s.cks),
    ckr: s.ckr instanceof Uint8Array ? new Uint8Array(s.ckr) : (typeof s.ckr === "string" ? fromB64(s.ckr) : s.ckr),
    ns: s.ns ?? 0,
    nr: s.nr ?? 0,
    pn: s.pn ?? 0,
    skippedKeys: s.skippedKeys ? JSON.parse(JSON.stringify(s.skippedKeys)) : {},
    peerIk: s.peerIk,
    peerSik: s.peerSik,
    createdAt: s.createdAt,
    state: s.state,
  };
}

/**
 * Evict expired skipped keys (TTL 30 days) and enforce cap of 2000 oldest-first
 */
export function evictSkippedKeys(session, now = Date.now()) {
  if (!session?.skippedKeys) return;
  const entries = Object.entries(session.skippedKeys);

  // 1. Remove expired
  for (const [k, v] of entries) {
    if (now - v.createdAt >= SKIPPED_TTL_MS) {
      delete session.skippedKeys[k];
    }
  }

  // 2. Enforce cap
  const currentKeys = Object.entries(session.skippedKeys);
  if (currentKeys.length > MAX_TOTAL_SKIPPED) {
    currentKeys.sort((a, b) => a[1].createdAt - b[1].createdAt);
    const toRemove = currentKeys.length - MAX_TOTAL_SKIPPED;
    for (let i = 0; i < toRemove; i++) {
      delete session.skippedKeys[currentKeys[i][0]];
    }
  }
}

/**
 * Initiator creates a Double Ratchet session via X3DH with prekey bundle.
 */
export async function initiateRatchetSession({ senderId, receiverId, myIk, mySik, bundle, pinned }) {
  const check = verifyBundle(bundle, pinned);
  if (!check.ok) throw new CryptoError(check.reason === "key-changed" ? PEER_KEY_CHANGED : SESSION_SETUP_FAILED);

  const ekPriv = newSecret();
  const ekPub = xPub(ekPriv);

  const sk = x3dhInitiate({
    ikPriv: myIk.priv,
    ekPriv,
    ikPubB: bundle.ikPub,
    spkPubB: bundle.spk.pub,
    opkPubB: bundle.opk?.pub,
    info: INFO_SESSION,
  });
  ekPriv.fill(0);

  // Initial DH Ratchet step for initiator:
  // Alice generates DHs, sets DHr = Bob's SPK, and computes (RK, CKs) = KDF_RK(SK, DH(DHs, DHr))
  const dhsPriv = newSecret();
  const dhsPub = xPub(dhsPriv);
  const dhrPub = bundle.spk.pub;
  const dhOut = dh(dhsPriv, dhrPub);
  const { newRk, newCk: cks } = kdfRk(sk, dhOut);

  const sessionId = Array.from(randomBytes(16)).map((b) => b.toString(16).padStart(2, "0")).join("");

  const session = {
    peerId: receiverId,
    sessionId,
    role: "initiator",
    rk: newRk,
    dhs: { pub: toB64(dhsPub), priv: toB64(dhsPriv) },
    dhr: toB64(dhrPub),
    cks,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skippedKeys: {},
    peerIk: toB64(bundle.ikPub),
    peerSik: toB64(bundle.sikPub),
    createdAt: Date.now(),
    state: "pending",
  };

  const initialHeader = {
    sessionId,
    n: 0,
    pn: 0,
    dh: toB64(dhsPub),
    ek: toB64(ekPub),
    spkId: bundle.spk.id,
    opkId: bundle.opk ? bundle.opk.id : null,
    ik: toB64(myIk.pub),
    sik: toB64(mySik.pub),
  };

  return { session, initialHeader };
}

/**
 * Responder creates a Double Ratchet session from initial header and local prekeys.
 */
export async function respondRatchetSession({ receiverId, senderId, myIk, spkPriv, opkPriv, header, pinned }) {
  if (!spkPriv || spkPriv.length !== 32) throw new CryptoError(DECRYPT_FAILED);
  if (header.opkId !== null && header.opkId !== undefined) {
    if (!opkPriv || opkPriv.length !== 32) throw new CryptoError(DECRYPT_FAILED);
  }

  const ekPubA = fromB64(header.ek);
  if (ekPubA.length !== 32) throw new CryptoError(DECRYPT_FAILED);

  const ikPubA = header.ik ? fromB64(header.ik) : (pinned?.ik ? (typeof pinned.ik === "string" ? fromB64(pinned.ik) : pinned.ik) : null);
  if (!ikPubA || ikPubA.length !== 32) throw new CryptoError(DECRYPT_FAILED);

  if (pinned?.ik) {
    const pinnedIk = typeof pinned.ik === "string" ? fromB64(pinned.ik) : pinned.ik;
    let match = true;
    for (let i = 0; i < 32; i++) {
      if (pinnedIk[i] !== ikPubA[i]) { match = false; break; }
    }
    if (!match) throw new CryptoError(PEER_KEY_CHANGED);
  }

  const sk = x3dhRespond({
    ikPriv: myIk.priv,
    spkPriv,
    opkPriv: opkPriv ?? undefined,
    ikPubA,
    ekPubA,
    info: INFO_SESSION,
  });

  // Bob's initial ratchet keypair is his SPK keypair
  const spkPub = xPub(spkPriv);

  const session = {
    peerId: senderId,
    sessionId: header.sessionId,
    role: "responder",
    rk: sk,
    dhs: { pub: toB64(spkPub), priv: toB64(spkPriv) },
    dhr: null,
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skippedKeys: {},
    peerIk: toB64(ikPubA),
    peerSik: header.sik || (pinned?.sik ? (typeof pinned.sik === "string" ? pinned.sik : toB64(pinned.sik)) : ""),
    createdAt: Date.now(),
    state: "established",
  };

  return { session };
}

/**
 * Encrypt message with Double Ratchet.
 */
export async function ratchetEncrypt({ session, envelope, type = "text", senderId, receiverId, myIk, initialHeader }) {
  if (typeof envelope?.body === "string" && envelope.body.length > MAX_TEXT_CHARS) {
    throw new CryptoError("too-long");
  }
  const plain = pad(utf8(JSON.stringify(envelope)));
  if (plain.length > MAX_PADDED) throw new CryptoError("too-long");

  // If sending chain key is null, Bob or Alice needs to run DH ratchet step before sending
  if (!session.cks) {
    if (!session.dhr) {
      throw new CryptoError(SESSION_SETUP_FAILED);
    }
    const nextDhPriv = newSecret();
    const nextDhPub = xPub(nextDhPriv);
    const dhOut = dh(nextDhPriv, fromB64(session.dhr));
    const { newRk, newCk } = kdfRk(session.rk, dhOut);
    session.rk = newRk;
    session.cks = newCk;
    session.dhs = { pub: toB64(nextDhPub), priv: toB64(nextDhPriv) };
    session.ns = 0;
  }

  const { mk, nextCk } = kdfCk(session.cks);
  session.cks = nextCk;
  const n = session.ns++;

  const peerIk = typeof session.peerIk === "string" ? fromB64(session.peerIk) : session.peerIk;
  const dhPubBytes = fromB64(session.dhs.pub);

  const aad = buildAadRatchet({
    type,
    senderId,
    receiverId,
    ikSender: myIk.pub,
    ikReceiver: peerIk,
    sessionId: session.sessionId,
    n,
    pn: session.pn,
    dhPub: dhPubBytes,
  });

  const { nonce, ciphertext } = await aeadEncrypt(mk, plain, aad);
  mk.fill(0); // Zero message key

  const header = {
    sessionId: session.sessionId,
    n,
    pn: session.pn,
    dh: session.dhs.pub,
    ...(initialHeader ? initialHeader : {}),
  };

  return {
    v: 2,
    type,
    nonce: toB64(nonce),
    ciphertext: toB64(ciphertext),
    header,
  };
}

/**
 * Decrypt message with Double Ratchet.
 * Atomicity: Decrypts on a copy of the state and commits only after AEAD auth succeeds.
 */
export async function ratchetDecrypt({
  session,
  receiverId,
  senderId,
  myIk,
  msg,
  getSpkPriv,
  takeOpkPriv,
  pinned,
}) {
  if (msg?.v !== 2) throw new CryptoError(UNSUPPORTED_VERSION);
  const h = msg.header;
  if (!h || typeof h !== "object" || typeof h.sessionId !== "string") {
    throw new CryptoError(DECRYPT_FAILED);
  }

  let activeSession = session;

  // Initial handshake resolution
  if (!activeSession || (h.ek && h.sessionId !== activeSession.sessionId)) {
    if (!h.ek || !h.spkId) throw new CryptoError(DECRYPT_FAILED);
    const spkPriv = await getSpkPriv(h.spkId);
    if (!spkPriv) throw new CryptoError(DECRYPT_FAILED);

    let opkPriv = null;
    if (h.opkId !== null && h.opkId !== undefined) {
      opkPriv = await takeOpkPriv(h.opkId);
      if (!opkPriv) throw new CryptoError(DECRYPT_FAILED);
    }

    const res = await respondRatchetSession({
      receiverId,
      senderId,
      myIk,
      spkPriv,
      opkPriv,
      header: h,
      pinned,
    });
    activeSession = res.session;
  } else if (activeSession && h.sessionId !== activeSession.sessionId) {
    throw new CryptoError(DECRYPT_FAILED);
  }

  const n = h.n;
  const pn = h.pn ?? 0;
  const dhHeader = h.dh;
  if (!Number.isInteger(n) || n < 0 || typeof dhHeader !== "string") {
    throw new CryptoError(DECRYPT_FAILED);
  }

  // ATOMICITY: clone session
  const state = cloneSession(activeSession);
  let mk = null;

  // 1. Try skipped keys first
  const skippedKeyId = `${dhHeader}:${n}`;
  if (state.skippedKeys && state.skippedKeys[skippedKeyId]) {
    mk = fromB64(state.skippedKeys[skippedKeyId].key);
    delete state.skippedKeys[skippedKeyId];
  } else {
    // 2. If incoming ratchet key differs from dhr, perform DH Ratchet step
    if (dhHeader !== state.dhr) {
      // Skip unreceived messages in the previous receiving chain up to header.pn
      if (state.ckr !== null) {
        if (pn < state.nr) {
          throw new CryptoError(DECRYPT_FAILED);
        }
        if (pn - state.nr > MAX_SKIP) {
          throw new CryptoError(TOO_MANY_SKIPPED);
        }
        let curCk = state.ckr;
        for (let i = state.nr; i < pn; i++) {
          const step = kdfCk(curCk);
          state.skippedKeys[`${state.dhr}:${i}`] = {
            key: toB64(step.mk),
            createdAt: Date.now(),
          };
          curCk = step.nextCk;
        }
        state.ckr = curCk;
      }

      // DH Ratchet step
      const dhOut = dh(fromB64(state.dhs.priv), fromB64(dhHeader));
      const { newRk, newCk } = kdfRk(state.rk, dhOut);
      state.rk = newRk;
      state.ckr = newCk;
      state.dhr = dhHeader;
      state.pn = state.ns;
      state.nr = 0;

      // Generate our next DH ratchet keypair for subsequent sends
      const nextDhPriv = newSecret();
      const nextDhPub = xPub(nextDhPriv);
      const dhOut2 = dh(nextDhPriv, fromB64(state.dhr));
      const { newRk: rk2, newCk: cks2 } = kdfRk(state.rk, dhOut2);
      state.rk = rk2;
      state.cks = cks2;
      state.dhs = { pub: toB64(nextDhPub), priv: toB64(nextDhPriv) };
      state.ns = 0;
    }

    // 3. Skip unreceived messages in the current receiving chain up to header.n
    if (n < state.nr) {
      throw new CryptoError(DUPLICATE_MESSAGE);
    }
    if (n - state.nr > MAX_SKIP) {
      throw new CryptoError(TOO_MANY_SKIPPED);
    }

    let curCk = state.ckr;
    for (let i = state.nr; i < n; i++) {
      const step = kdfCk(curCk);
      state.skippedKeys[`${dhHeader}:${i}`] = {
        key: toB64(step.mk),
        createdAt: Date.now(),
      };
      curCk = step.nextCk;
    }

    const targetStep = kdfCk(curCk);
    mk = targetStep.mk;
    state.ckr = targetStep.nextCk;
    state.nr = n + 1;
  }

  // 4. Verify AEAD authentication
  const peerIk = typeof state.peerIk === "string" ? fromB64(state.peerIk) : state.peerIk;
  const dhPubBytes = fromB64(dhHeader);

  const aad = buildAadRatchet({
    type: msg.type,
    senderId,
    receiverId,
    ikSender: peerIk,
    ikReceiver: myIk.pub,
    sessionId: state.sessionId,
    n,
    pn,
    dhPub: dhPubBytes,
  });

  let plain;
  try {
    plain = unpad(await aeadDecrypt(mk, fromB64(msg.nonce), fromB64(msg.ciphertext), aad));
  } finally {
    mk.fill(0); // Zero out message key
  }

  const envelope = JSON.parse(fromUtf8(plain));
  if (typeof envelope?.t !== "string" || typeof envelope?.ts !== "number") {
    throw new CryptoError(DECRYPT_FAILED);
  }

  // 5. Evict skipped keys & commit state
  evictSkippedKeys(state);
  Object.assign(activeSession, state);

  return { session: activeSession, envelope };
}

/**
 * Migration helper: Upgrade an S8 session without ratchet fields
 */
export function upgradeFromS8Session(s8Session) {
  if (!s8Session) return null;
  if (s8Session.rk && s8Session.dhs) return s8Session;

  const dhsPriv = newSecret();
  const dhsPub = xPub(dhsPriv);

  return {
    ...s8Session,
    rk: s8Session.sk || newSecret(),
    dhs: { pub: toB64(dhsPub), priv: toB64(dhsPriv) },
    dhr: s8Session.peerIk || null,
    cks: s8Session.chainKeySend || null,
    ckr: s8Session.chainKeyRecv || null,
    ns: 0,
    nr: 0,
    pn: 0,
    skippedKeys: s8Session.skippedKeys || {},
  };
}
