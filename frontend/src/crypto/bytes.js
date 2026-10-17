export const utf8 = (s) => new TextEncoder().encode(s);
export const fromUtf8 = (u) => new TextDecoder("utf-8", { fatal: true }).decode(u);

export function concat(...arrs) {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}

export function u32be(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError("u32be");
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

export const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

export function toB64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
}

// strict: rejects whitespace, missing padding, non-canonical forms
export function fromB64(s) {
  if (typeof s !== "string") throw new TypeError("b64");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (toB64(out) !== s) throw new TypeError("b64-noncanonical");
  return out;
}

export function equal(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
