import { get, set } from "idb-keyval";

const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const enc = new TextEncoder();

function cmp(x, y) {
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}
function cat(...a) {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) { out.set(x, o); o += x.length; }
  return out;
}

// mine / theirs: { ik, sik } base64. Symmetric: parties are sorted before hashing.
export async function safetyNumber(mine, theirs) {
  const parties = [cat(unb64(mine.ik), unb64(mine.sik)), cat(unb64(theirs.ik), unb64(theirs.sik))].sort(cmp);
  const h = new Uint8Array(await crypto.subtle.digest("SHA-512", cat(enc.encode("talk-safety-v2"), ...parties)));
  const groups = [];
  for (let i = 0; i < 60; i += 5) {
    let n = 0;
    for (let j = 0; j < 5; j++) n = n * 256 + h[i + j];
    groups.push(String(n % 100000).padStart(5, "0"));
  }
  return groups;
}

const k = (me, peer) => `contact:${me}:${peer}`;

// cur: { ik, sik } from the server. status: "new" | "ok" | "changed" | "no-keys"
export async function checkContact(me, peer, cur) {
  if (!cur?.sik) return { status: "no-keys", verified: false, peerKeys: cur };
  const rec = await get(k(me, peer));
  if (!rec) {
    await set(k(me, peer), { ik: cur.ik, sik: cur.sik, verified: false });
    return { status: "new", verified: false, peerKeys: cur };
  }
  const oldIk = rec.ik ?? rec.key; // legacy G0 shape
  if (oldIk !== cur.ik) return { status: "changed", verified: !!rec.verified, peerKeys: cur };
  if (!rec.sik) {
    await set(k(me, peer), { ik: cur.ik, sik: cur.sik, verified: false });
    return { status: "ok", verified: false, upgraded: rec.verified === true, peerKeys: cur };
  }
  if (rec.sik !== cur.sik) return { status: "changed", verified: !!rec.verified, peerKeys: cur };
  return { status: "ok", verified: !!rec.verified, peerKeys: cur };
}

export const markVerified = (me, peer, keys) =>
  set(k(me, peer), { ik: keys.ik, sik: keys.sik, verified: true, at: Date.now() });

export const acceptKeyChange = (me, peer, keys) =>
  set(k(me, peer), { ik: keys.ik, sik: keys.sik, verified: false });

// normalized pin, or null. Reads the G0 legacy shape too.
export async function readPin(me, peer) {
  const r = await get(k(me, peer));
  return r ? { ik: r.ik ?? r.key, sik: r.sik ?? null, verified: !!r.verified } : null;
}

