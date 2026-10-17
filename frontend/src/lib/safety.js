import { get, set } from "idb-keyval";

const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const enc = new TextEncoder();

function cmp(x, y) {
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

export async function safetyNumber(keyA, keyB) {
  const [a, b] = [unb64(keyA), unb64(keyB)].sort(cmp);
  const prefix = enc.encode("talk-safety-v1");
  const input = new Uint8Array(prefix.length + a.length + b.length);
  input.set(prefix);
  input.set(a, prefix.length);
  input.set(b, prefix.length + a.length);

  const h = new Uint8Array(await crypto.subtle.digest("SHA-512", input));
  const groups = [];
  for (let i = 0; i < 60; i += 5) {
    let n = 0;
    for (let j = 0; j < 5; j++) n = n * 256 + h[i + j];
    groups.push(String(n % 100000).padStart(5, "0"));
  }
  return groups;
}

const k = (me, peer) => `contact:${me}:${peer}`;

export async function checkContact(me, peer, currentKey) {
  const rec = await get(k(me, peer));
  if (!rec) {
    await set(k(me, peer), { key: currentKey, verified: false });
    return { status: "new", verified: false, peerKey: currentKey };
  }
  if (rec.key !== currentKey) {
    return { status: "changed", verified: rec.verified, peerKey: currentKey };
  }
  return { status: "ok", verified: rec.verified, peerKey: currentKey };
}

export const markVerified = (me, peer, key) =>
  set(k(me, peer), { key, verified: true, at: Date.now() });

export const acceptKeyChange = (me, peer, key) =>
  set(k(me, peer), { key, verified: false });
