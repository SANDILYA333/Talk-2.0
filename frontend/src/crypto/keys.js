import { concat, u32be, utf8, equal } from "./bytes.js";
import { newSecret, xPub, edPub, edSign, edVerify } from "./primitives.js";

const IK_LABEL = utf8("talk-ik-v1");
const SPK_LABEL = utf8("talk-spk-v1");

export function generateIdentity() {
  const ikPriv = newSecret();
  const sikPriv = newSecret();
  return {
    ik: { pub: xPub(ikPriv), priv: ikPriv },
    sik: { pub: edPub(sikPriv), priv: sikPriv },
  };
}

export const signIkBinding = (sikPriv, ikPub) => edSign(concat(IK_LABEL, ikPub), sikPriv);

export function generateSignedPrekey(sikPriv, id) {
  const priv = newSecret();
  const pub = xPub(priv);
  const sig = edSign(concat(SPK_LABEL, u32be(id), pub), sikPriv);
  return { id, pub, priv, sig };
}

export function generateOneTimePrekeys(startId, count) {
  return Array.from({ length: count }, (_, i) => {
    const priv = newSecret();
    return { id: startId + i, pub: xPub(priv), priv };
  });
}

// bundle: { ikPub, sikPub, ikBinding, spk: { id, pub, sig } }  (all Uint8Array, id integer)
// pinned: optional { ik, sik }
export function verifyBundle(b, pinned = {}) {
  const okLen =
    b?.ikPub?.length === 32 &&
    b?.sikPub?.length === 32 &&
    b?.ikBinding?.length === 64 &&
    b?.spk?.pub?.length === 32 &&
    b?.spk?.sig?.length === 64 &&
    Number.isInteger(b?.spk?.id);
  if (!okLen) return { ok: false, reason: "bad-length" };
  if (!edVerify(b.ikBinding, concat(IK_LABEL, b.ikPub), b.sikPub)) return { ok: false, reason: "bad-ik-binding" };
  if (!edVerify(b.spk.sig, concat(SPK_LABEL, u32be(b.spk.id), b.spk.pub), b.sikPub))
    return { ok: false, reason: "bad-spk-sig" };
  if (pinned.ik && !equal(pinned.ik, b.ikPub)) return { ok: false, reason: "ik-changed" };
  if (pinned.sik && !equal(pinned.sik, b.sikPub)) return { ok: false, reason: "sik-changed" };
  return { ok: true };
}
