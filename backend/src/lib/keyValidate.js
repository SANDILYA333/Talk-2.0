import { createPublicKey, verify } from "node:crypto";

const ED_SPKI = Buffer.from("302a300506032b6570032100", "hex");

// canonical base64 of exactly `len` bytes, else null
export function b64Bytes(s, len) {
  if (typeof s !== "string") return null;
  const b = Buffer.from(s, "base64");
  if (b.length !== len || b.toString("base64") !== s) return null;
  return b;
}

// canonical base64 of any length, else null
export function b64Decode(s) {
  if (typeof s !== "string") return null;
  const b = Buffer.from(s, "base64");
  return b.toString("base64") === s ? b : null;
}

export const isU32 = (n) => Number.isInteger(n) && n >= 1 && n <= 0xffffffff;

export function edVerify(sig, msg, pub) {
  try {
    const key = createPublicKey({ key: Buffer.concat([ED_SPKI, pub]), format: "der", type: "spki" });
    return verify(null, msg, key, sig);
  } catch {
    return false;
  }
}

export const ikBindingMsg = (ik) => Buffer.concat([Buffer.from("talk-ik-v1"), ik]);

export function spkMsg(id, pub) {
  const i = Buffer.alloc(4);
  i.writeUInt32BE(id);
  return Buffer.concat([Buffer.from("talk-spk-v1"), i, pub]);
}
