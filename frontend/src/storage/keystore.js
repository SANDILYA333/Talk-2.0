import { get, set, del, keys } from "idb-keyval";
import {
  toB64, fromB64, generateIdentity, generateSignedPrekey, generateOneTimePrekeys,
} from "../crypto/index.js";

const DAY = 86_400_000;
export const SPK_ROTATE_MS = 7 * DAY;
export const SPK_KEEP_MS = 30 * DAY;
export const OPK_BATCH = 50;

// ---------- locking: one lock per user for every mutating key op ----------
const chains = new Map();
function withLock(name, fn) {
  if (typeof navigator !== "undefined" && navigator.locks?.request) {
    return navigator.locks.request(name, fn);
  }
  const prev = chains.get(name) ?? Promise.resolve();
  const run = prev.then(() => fn());
  chains.set(name, run.catch(() => {}));
  return run;
}
const lockFor = (uid) => `talk:${uid}:keys`;

// ---------- key names ----------
const K = {
  identity: (u) => `identity:${u}`,
  spk: (u, id) => `spk:${u}:${id}`,
  spkCur: (u) => `spk-current:${u}`,
  spkNext: (u) => `spk-next:${u}`,
  opk: (u, id) => `opk:${u}:${id}`,
  opkNext: (u) => `opk-next:${u}`,
  plain: (u, id) => `plain:${u}:${id}`,
  session: (u, peer) => `session:${u}:${peer}`,
  loserSession: (u, peer) => `session-loser:${u}:${peer}`,
};

async function keysWithPrefix(prefix) {
  return (await keys()).filter((k) => typeof k === "string" && k.startsWith(prefix));
}

// ---------- identity ----------
export async function loadIdentity(uid) {
  const r = await get(K.identity(uid));
  if (!r) return null;
  return {
    ik: { pub: fromB64(r.publicKey), priv: fromB64(r.secretKey) },
    sik: r.sik ? { pub: fromB64(r.sik.pub), priv: fromB64(r.sik.priv) } : null,
  };
}

export function upgradeIdentity(uid) {
  return withLock(lockFor(uid), async () => {
    const r = await get(K.identity(uid));
    if (!r) return { status: "missing-local" };
    if (r.sik) return { status: "ok", sikPub: r.sik.pub };
    const { sik } = generateIdentity(); 
    const rec = { ...r, sik: { pub: toB64(sik.pub), priv: toB64(sik.priv) }, schema: 2 };
    await set(K.identity(uid), rec);
    return { status: "ok", sikPub: rec.sik.pub };
  });
}

// ---------- signed prekey ----------
export function ensureSpk(uid, now = Date.now()) {
  return withLock(lockFor(uid), async () => {
    const idn = await loadIdentity(uid);
    if (!idn?.sik) throw new Error("no-signing-key");

    const curId = await get(K.spkCur(uid));
    const cur = curId ? await get(K.spk(uid, curId)) : null;
    let current = cur;

    if (!cur || now - cur.createdAt >= SPK_ROTATE_MS) {
      const id = ((await get(K.spkNext(uid))) ?? 0) + 1;
      const s = generateSignedPrekey(idn.sik.priv, id);
      current = { id, pub: toB64(s.pub), priv: toB64(s.priv), sig: toB64(s.sig), createdAt: now };
      await set(K.spk(uid, id), current);
      await set(K.spkNext(uid), id);
      if (cur) await set(K.spk(uid, cur.id), { ...cur, retiredAt: now });
      await set(K.spkCur(uid), id); 
    }

    for (const k of await keysWithPrefix(`spk:${uid}:`)) {
      const r = await get(k);
      if (r?.retiredAt && now - r.retiredAt >= SPK_KEEP_MS) await del(k);
    }

    return {
      id: current.id,
      pub: fromB64(current.pub),
      sig: fromB64(current.sig),
      rotated: current !== cur,
    };
  });
}

export async function getSpkPriv(uid, id) {
  if (!Number.isInteger(id)) return null;
  const r = await get(K.spk(uid, id));
  return r ? fromB64(r.priv) : null;
}

// ---------- one-time prekeys ----------
export function generateOpks(uid, count = OPK_BATCH) {
  return withLock(lockFor(uid), async () => {
    const start = ((await get(K.opkNext(uid))) ?? 0) + 1;
    const batch = generateOneTimePrekeys(start, count);
    for (const o of batch) {
      await set(K.opk(uid, o.id), { id: o.id, pub: toB64(o.pub), priv: toB64(o.priv) });
    }
    await set(K.opkNext(uid), start + count - 1);
    return batch.map((o) => ({ id: o.id, pub: o.pub }));
  });
}

export async function getOpkPriv(uid, id) {
  if (!Number.isInteger(id)) return null;
  const r = await get(K.opk(uid, id));
  return r ? fromB64(r.priv) : null;
}

export function takeOpkPriv(uid, id) {
  return withLock(lockFor(uid), async () => {
    if (!Number.isInteger(id)) return null;
    const r = await get(K.opk(uid, id));
    if (!r) return null;
    await del(K.opk(uid, id));
    return fromB64(r.priv);
  });
}

export async function countOpks(uid) {
  return (await keysWithPrefix(`opk:${uid}:`)).length;
}

// ---------- decrypted-message cache ----------
export const putPlain = (uid, msgId, rec) => set(K.plain(uid, msgId), rec);
export const getPlain = async (uid, msgId) => (await get(K.plain(uid, msgId))) ?? null;
export const delPlain = (uid, msgId) => del(K.plain(uid, msgId));

// ---------- sessions (v2) ----------
export function withSessionLock(uid, peerId, fn) {
  const lockName = `talk:${uid}:session:${peerId}`;
  return withLock(lockName, fn);
}

export function saveSession(uid, peerId, session) {
  return set(K.session(uid, peerId), session);
}

export async function loadSession(uid, peerId) {
  return (await get(K.session(uid, peerId))) ?? null;
}

export function deleteSession(uid, peerId) {
  return del(K.session(uid, peerId));
}

export function saveLoserSession(uid, peerId, session) {
  return set(K.loserSession(uid, peerId), session);
}

export async function loadLoserSession(uid, peerId) {
  return (await get(K.loserSession(uid, peerId))) ?? null;
}

// ---------- identity reset ----------
export function wipeKeyMaterial(uid) {
  return withLock(lockFor(uid), async () => {
    const prefixes = [`spk:${uid}:`, `opk:${uid}:`, `session:${uid}:`, `session-loser:${uid}:`];
    for (const p of prefixes) for (const k of await keysWithPrefix(p)) await del(k);
    for (const k of [K.spkCur(uid), K.spkNext(uid), K.opkNext(uid)]) await del(k);
  });
}
