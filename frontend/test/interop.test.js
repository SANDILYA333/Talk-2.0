import { describe, it, expect } from "vitest";
import { createPublicKey, verify } from "node:crypto";
import { generateIdentity, generateSignedPrekey, signIkBinding } from "../src/crypto/index.js";

const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const nodeVerify = (sig, msg, pub) =>
  verify(null, Buffer.from(msg), createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(pub)]), format: "der", type: "spki" }), Buffer.from(sig));

describe("noble signatures verify under Node crypto (what the server does)", () => {
  it("IK binding", () => {
    const id = generateIdentity();
    const sig = signIkBinding(id.sik.priv, id.ik.pub);
    const msg = Buffer.concat([Buffer.from("talk-ik-v1"), Buffer.from(id.ik.pub)]);
    expect(nodeVerify(sig, msg, id.sik.pub)).toBe(true);
    expect(nodeVerify(sig, Buffer.concat([Buffer.from("talk-ik-v1"), Buffer.alloc(32)]), id.sik.pub)).toBe(false);
  });
  it("SPK signature, ids 1, 255, 256, 65536, 4294967295", () => {
    const id = generateIdentity();
    for (const n of [1, 255, 256, 65536, 4294967295]) {
      const s = generateSignedPrekey(id.sik.priv, n);
      const i = Buffer.alloc(4); i.writeUInt32BE(n);
      const msg = Buffer.concat([Buffer.from("talk-spk-v1"), i, Buffer.from(s.pub)]);
      expect(nodeVerify(s.sig, msg, id.sik.pub)).toBe(true);
    }
  });
});
