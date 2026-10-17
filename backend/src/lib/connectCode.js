import { createHash } from "node:crypto";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford Base32

export function deriveConnectCode(publicKeyB64) {
  const hash = createHash("sha256").update(Buffer.from(publicKeyB64, "base64")).digest();
  let out = "", acc = 0, nbits = 0;
  for (const byte of hash) {
    acc = (acc << 8) | byte;
    nbits += 8;
    while (nbits >= 5 && out.length < 10) {
      out += ALPHABET[(acc >> (nbits - 5)) & 31];
      nbits -= 5;
    }
    acc &= (1 << nbits) - 1;
    if (out.length === 10) break;
  }
  return `TALK-${out.slice(0, 5)}-${out.slice(5)}`;
}

export function normalizeConnectCode(input) {
  let s = String(input || "").toUpperCase().replace(/[^0-9A-Z]/g, "");
  if (s.length === 14 && s.startsWith("TALK")) s = s.slice(4);
  s = s.replace(/O/g, "0").replace(/[IL]/g, "1");
  if (!/^[0-9A-HJKMNP-TV-Z]{10}$/.test(s)) return null;
  return `TALK-${s.slice(0, 5)}-${s.slice(5)}`;
}
