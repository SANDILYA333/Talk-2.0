import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concat, utf8, fromUtf8, toB64, fromB64, randomBytes } from "./bytes.js";
import { newSecret, xPub, kdf } from "./primitives.js";
import { x3dhInitiate, x3dhRespond } from "./x3dh.js";
import { buildAadV2, aeadEncrypt, aeadDecrypt } from "./aead.js";
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
export const INFO_CHAIN_SEND = "talk/v2/chain/init-send";
export const INFO_CHAIN_RECV = "talk/v2/chain/init-recv";
export const MAX_SKIP = 100;
const MAX_PADDED = 16384 - 16;

/**
 * Signal-style symmetric KDF ratchet step:
 * Mk = HMAC-SHA256(CK, 0x01)
 * CK_next = HMAC-SHA256(CK, 0x02)
 */
export function kdfCk(ck) {
  const mk = hmac(sha256, ck, Uint8Array.of(0x01));
  const nextCk = hmac(sha256, ck, Uint8Array.of(0x02));
  return { mk, nextCk };
}

/**
 * Initiator creates a new v2 session via X3DH with prekey bundle.
 */
export async function initiateSession({ senderId, receiverId, myIk, mySik, bundle, pinned }) {
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
  ekPriv.fill(0); // Erase ephemeral private key

  const chainKeySend = kdf(sk, INFO_CHAIN_SEND);
  const chainKeyRecv = kdf(sk, INFO_CHAIN_RECV);
  const sessionId = Array.from(randomBytes(16)).map((b) => b.toString(16).padStart(2, "0")).join("");

  const session = {
    peerId: receiverId,
    sessionId,
    role: "initiator",
    sk,
    chainKeySend,
    chainKeyRecv,
    sendCounter: 0,
    recvCounter: 0,
    peerIk: toB64(bundle.ikPub),
    peerSik: toB64(bundle.sikPub),
    createdAt: Date.now(),
    state: "pending",
    skippedKeys: {},
  };

  const initialHeader = {
    sessionId,
    n: 0,
    ek: toB64(ekPub),
    spkId: bundle.spk.id,
    opkId: bundle.opk ? bundle.opk.id : null,
    ik: toB64(myIk.pub),
    sik: toB64(mySik.pub),
  };

  return { session, initialHeader };
}

/**
 * Responder creates a matching v2 session from initial header and local prekeys.
 */
export async function respondSession({ receiverId, senderId, myIk, spkPriv, opkPriv, header, pinned }) {
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

  // Responder's chain keys are inverted: receive on A's send chain, send on A's receive chain
  const chainKeySend = kdf(sk, INFO_CHAIN_RECV);
  const chainKeyRecv = kdf(sk, INFO_CHAIN_SEND);

  const session = {
    peerId: senderId,
    sessionId: header.sessionId,
    role: "responder",
    sk,
    chainKeySend,
    chainKeyRecv,
    sendCounter: 0,
    recvCounter: 0,
    peerIk: toB64(ikPubA),
    peerSik: header.sik || (pinned?.sik ? (typeof pinned.sik === "string" ? pinned.sik : toB64(pinned.sik)) : ""),
    createdAt: Date.now(),
    state: "established",
    skippedKeys: {},
  };

  return { session };
}

/**
 * Encrypt message under session sending chain.
 */
export async function encryptSessionMessage({ session, envelope, type = "text", senderId, receiverId, myIk, initialHeader }) {
  if (typeof envelope?.body === "string" && envelope.body.length > MAX_TEXT_CHARS) {
    throw new CryptoError("too-long");
  }
  const plain = pad(utf8(JSON.stringify(envelope)));
  if (plain.length > MAX_PADDED) throw new CryptoError("too-long");

  const n = session.sendCounter;
  const { mk, nextCk } = kdfCk(session.chainKeySend);
  session.chainKeySend = nextCk;
  session.sendCounter++;

  const peerIk = typeof session.peerIk === "string" ? fromB64(session.peerIk) : session.peerIk;
  const aad = buildAadV2({
    type,
    senderId,
    receiverId,
    ikSender: myIk.pub,
    ikReceiver: peerIk,
    sessionId: session.sessionId,
    n,
  });

  const { nonce, ciphertext } = await aeadEncrypt(mk, plain, aad);

  const header = {
    sessionId: session.sessionId,
    n,
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
 * Decrypt message under session receiving chain with out-of-order handling.
 */
export async function decryptSessionMessage({
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

  // If there is no active session, or if the incoming message has initial handshake fields
  // for a DIFFERENT session ID, establish the new session from the initial message
  if (!activeSession || (h.ek && h.sessionId !== activeSession.sessionId)) {
    if (!h.ek || !h.spkId) throw new CryptoError(DECRYPT_FAILED);
    const spkPriv = await getSpkPriv(h.spkId);
    if (!spkPriv) throw new CryptoError(DECRYPT_FAILED);

    let opkPriv = null;
    if (h.opkId !== null && h.opkId !== undefined) {
      opkPriv = await takeOpkPriv(h.opkId);
      if (!opkPriv) throw new CryptoError(DECRYPT_FAILED);
    }

    const res = await respondSession({
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
  if (!Number.isInteger(n) || n < 0) throw new CryptoError(DECRYPT_FAILED);

  let mk;
  let nextRecvCounter = activeSession.recvCounter;
  let nextChainKeyRecv = activeSession.chainKeyRecv;
  let nextSkippedKeys = null;
  let consumeSkipped = null;

  if (n === activeSession.recvCounter) {
    const step = kdfCk(activeSession.chainKeyRecv);
    mk = step.mk;
    nextChainKeyRecv = step.nextCk;
    nextRecvCounter = activeSession.recvCounter + 1;
  } else if (n > activeSession.recvCounter) {
    if (n - activeSession.recvCounter > MAX_SKIP) {
      throw new CryptoError(TOO_MANY_SKIPPED);
    }
    let curCk = activeSession.chainKeyRecv;
    const skipped = { ...(activeSession.skippedKeys || {}) };
    for (let s = activeSession.recvCounter; s < n; s++) {
      const step = kdfCk(curCk);
      skipped[s] = { key: toB64(step.mk), createdAt: Date.now() };
      curCk = step.nextCk;
    }
    const target = kdfCk(curCk);
    mk = target.mk;
    nextChainKeyRecv = target.nextCk;
    nextRecvCounter = n + 1;
    nextSkippedKeys = skipped;
  } else {
    // n < activeSession.recvCounter
    if (!activeSession.skippedKeys || !activeSession.skippedKeys[n]) {
      throw new CryptoError(DUPLICATE_MESSAGE);
    }
    mk = fromB64(activeSession.skippedKeys[n].key);
    consumeSkipped = n;
  }

  const peerIk = typeof activeSession.peerIk === "string" ? fromB64(activeSession.peerIk) : activeSession.peerIk;
  const aad = buildAadV2({
    type: msg.type,
    senderId,
    receiverId,
    ikSender: peerIk,
    ikReceiver: myIk.pub,
    sessionId: activeSession.sessionId,
    n,
  });

  const plain = unpad(await aeadDecrypt(mk, fromB64(msg.nonce), fromB64(msg.ciphertext), aad));
  const envelope = JSON.parse(fromUtf8(plain));
  if (typeof envelope?.t !== "string" || typeof envelope?.ts !== "number") {
    throw new CryptoError(DECRYPT_FAILED);
  }

  // Atomically advance state only AFTER successful AEAD decryption
  if (consumeSkipped !== null) {
    const nextSkipped = { ...activeSession.skippedKeys };
    delete nextSkipped[consumeSkipped];
    activeSession.skippedKeys = nextSkipped;
  } else {
    activeSession.recvCounter = nextRecvCounter;
    activeSession.chainKeyRecv = nextChainKeyRecv;
    if (nextSkippedKeys) activeSession.skippedKeys = nextSkippedKeys;
  }

  return { session: activeSession, envelope };
}

/**
 * Tie-breaker for simultaneous initiation:
 * Initiator with the lexicographically lower IK wins.
 */
export function resolveSimultaneousInitiation({ localSession, incomingHeader, myIk, peerIk }) {
  let cmp = 0;
  for (let i = 0; i < 32; i++) {
    if (myIk[i] < peerIk[i]) { cmp = -1; break; }
    if (myIk[i] > peerIk[i]) { cmp = 1; break; }
  }

  if (cmp < 0) {
    // Local initiator session wins
    return {
      winningSessionId: localSession.sessionId,
      winnerIsMe: true,
      loserSessionId: incomingHeader.sessionId,
    };
  } else {
    // Peer's incoming session wins
    return {
      winningSessionId: incomingHeader.sessionId,
      winnerIsMe: false,
      loserSessionId: localSession.sessionId,
    };
  }
}
