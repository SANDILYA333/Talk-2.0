import { axiosInstance } from "./axios";
import { loadIdentity, ensureSpk, generateOpks, OPK_BATCH } from "../storage/keystore";
import { toB64, fromB64, signIkBinding } from "../crypto/index.js";

const OPK_LOW = 10;

// idempotent: safe to run on every boot, and it self-heals if the server lost the bundle
export async function uploadBundle(uid) {
  const idn = await loadIdentity(uid);
  if (!idn?.sik) throw new Error("no-signing-key");
  const spk = await ensureSpk(uid);
  await axiosInstance.put("/keys/bundle", {
    sik: toB64(idn.sik.pub),
    ikBinding: toB64(signIkBinding(idn.sik.priv, idn.ik.pub)),
    spk: { id: spk.id, pub: toB64(spk.pub), sig: toB64(spk.sig) },
    protoMax: 1,
  });
}

export async function syncOpks(uid) {
  const { data } = await axiosInstance.get("/keys/opks/count");
  if (data.count >= OPK_LOW) return { added: 0 };
  const batch = await generateOpks(uid, OPK_BATCH); // publics only
  await axiosInstance.post("/keys/opks", { keys: batch.map((o) => ({ id: o.id, pub: toB64(o.pub) })) });
  return { added: batch.length };
}

// server JSON -> the Uint8Array shape verifyBundle() expects
export function parseBundle(d) {
  try {
    return {
      userId: d.userId,
      ikPub: fromB64(d.ikPub),
      sikPub: fromB64(d.sikPub),
      ikBinding: fromB64(d.ikBinding),
      spk: { id: d.spk.id, pub: fromB64(d.spk.pub), sig: fromB64(d.spk.sig) },
      opk: d.opk ? { id: d.opk.id, pub: fromB64(d.opk.pub) } : null,
      protoMax: d.protoMax,
    };
  } catch {
    throw new Error("bad-bundle");
  }
}

// the caller (S5) MUST run verifyBundle(parsed, pinned) before using it
export async function fetchBundle(peerId, { opk = false } = {}) {
  const { data } = await axiosInstance.get(`/keys/bundle/${peerId}`, { params: opk ? { opk: 1 } : {} });
  return parseBundle(data);
}
