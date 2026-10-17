import { describe, it, expect } from "vitest";
import { dh, xPub, edPub, edSign, edVerify, kdf } from "./primitives.js";
import { u32be, toB64, fromB64 } from "./bytes.js";
import { buildAad } from "./aead.js";
import { x3dhInitiate, x3dhRespond } from "./x3dh.js";
import { generateIdentity, generateSignedPrekey, signIkBinding, verifyBundle } from "./keys.js";
import { encryptV1, decryptV1 } from "./v1.js";

const hex = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
const toHex = (u) => [...u].map((b) => b.toString(16).padStart(2, "0")).join("");

const ID_A = "a".repeat(24);
const ID_B = "b".repeat(24);

function world() {
  const A = generateIdentity();
  const B = generateIdentity();
  const spkB = generateSignedPrekey(B.sik.priv, 7);
  const bundleB = {
    ikPub: B.ik.pub,
    sikPub: B.sik.pub,
    ikBinding: signIkBinding(B.sik.priv, B.ik.pub),
    spk: { id: 7, pub: spkB.pub, sig: spkB.sig },
  };
  return { A, B, spkB, bundleB };
}
const env = (body) => ({ t: "text", body, ts: 1700000000000 });
const send = (w, body = "hi", over = {}) =>
  encryptV1({
    envelope: env(body), type: "text", senderId: ID_A, receiverId: ID_B,
    myIk: w.A.ik, bundle: w.bundleB, pinned: { ik: w.B.ik.pub, sik: w.B.sik.pub }, ...over,
  });
const recv = (w, msg, over = {}) =>
  decryptV1({
    msg, senderId: ID_A, receiverId: ID_B, myIk: w.B.ik,
    getSpkPriv: (id) => (id === 7 ? w.spkB.priv : null),
    senderIkPub: w.A.ik.pub, ...over,
  });
const flip = (b64) => { const u = fromB64(b64); u[0] ^= 1; return toB64(u); };

describe("known vectors", () => {
  it("X25519 RFC 7748 section 6.1", () => {
    const a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const b = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    expect(toHex(xPub(a))).toBe("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    expect(toHex(xPub(b))).toBe("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    expect(toHex(dh(a, xPub(b)))).toBe(shared);
    expect(toHex(dh(b, xPub(a)))).toBe(shared);
  });
  it("HKDF-SHA256 RFC 5869 case 1", () => {
    const okm = kdf(new Uint8Array(22).fill(0x0b), hex("f0f1f2f3f4f5f6f7f8f9"), 42, hex("000102030405060708090a0b0c"));
    expect(toHex(okm)).toBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
  });
  it("Ed25519 RFC 8032 test 1", () => {
    const sk = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    expect(toHex(edPub(sk))).toBe("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const sig = edSign(new Uint8Array(0), sk);
    expect(toHex(sig)).toBe("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    expect(edVerify(sig, new Uint8Array(0), edPub(sk))).toBe(true);
  });
  it("dh rejects an all-zero public key", () => {
    expect(() => dh(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), new Uint8Array(32))).toThrow();
  });
});

describe("encodings", () => {
  it("u32be", () => {
    expect([...u32be(1)]).toEqual([0, 0, 0, 1]);
    expect([...u32be(0x01020304)]).toEqual([1, 2, 3, 4]);
    expect(() => u32be(-1)).toThrow();
  });
  it("base64 is strict", () => {
    expect(() => fromB64("AAAA ")).toThrow();
    expect(() => fromB64("AAA")).toThrow();
    expect(toB64(fromB64("AQID"))).toBe("AQID");
  });
  it("AAD is fixed width (125 bytes) and starts with label", () => {
    const k = new Uint8Array(32).fill(1);
    const aad = buildAad({ v: 1, type: "text", senderId: ID_A, receiverId: ID_B, ikSender: k, ikReceiver: k });
    expect(aad.length).toBe(125);
    expect(new TextDecoder().decode(aad.slice(0, 11))).toBe("talk/aad/v1");
    expect(aad[11]).toBe(1);
    expect(aad[12]).toBe(1);
  });
  it("AAD rejects bad ids", () => {
    const k = new Uint8Array(32);
    expect(() => buildAad({ v: 1, type: "text", senderId: "XYZ", receiverId: ID_B, ikSender: k, ikReceiver: k })).toThrow();
  });
});

describe("X3DH", () => {
  it("initiator and responder derive the same key", () => {
    const { A, B, spkB } = world();
    const ek = generateIdentity().ik;
    const a = x3dhInitiate({ ikPriv: A.ik.priv, ekPriv: ek.priv, ikPubB: B.ik.pub, spkPubB: spkB.pub });
    const b = x3dhRespond({ ikPriv: B.ik.priv, spkPriv: spkB.priv, ikPubA: A.ik.pub, ekPubA: ek.pub });
    expect(toHex(a)).toBe(toHex(b));
  });
  it("matches with a one-time prekey, and differs without it", () => {
    const { A, B, spkB } = world();
    const ek = generateIdentity().ik;
    const opk = generateIdentity().ik;
    const withOpkA = x3dhInitiate({ ikPriv: A.ik.priv, ekPriv: ek.priv, ikPubB: B.ik.pub, spkPubB: spkB.pub, opkPubB: opk.pub });
    const withOpkB = x3dhRespond({ ikPriv: B.ik.priv, spkPriv: spkB.priv, opkPriv: opk.priv, ikPubA: A.ik.pub, ekPubA: ek.pub });
    const without = x3dhInitiate({ ikPriv: A.ik.priv, ekPriv: ek.priv, ikPubB: B.ik.pub, spkPubB: spkB.pub });
    expect(toHex(withOpkA)).toBe(toHex(withOpkB));
    expect(toHex(withOpkA)).not.toBe(toHex(without));
  });
});

describe("bundle verification", () => {
  it("accepts a good bundle", () => {
    const w = world();
    expect(verifyBundle(w.bundleB, { ik: w.B.ik.pub, sik: w.B.sik.pub })).toEqual({ ok: true });
  });
  it("rejects a bad SPK signature", () => {
    const w = world();
    const bad = { ...w.bundleB, spk: { ...w.bundleB.spk, sig: new Uint8Array(64) } };
    expect(verifyBundle(bad).reason).toBe("bad-spk-sig");
  });
  it("rejects an SPK id that was swapped after signing", () => {
    const w = world();
    const bad = { ...w.bundleB, spk: { ...w.bundleB.spk, id: 8 } };
    expect(verifyBundle(bad).reason).toBe("bad-spk-sig");
  });
  it("rejects a swapped IK (binding no longer matches)", () => {
    const w = world();
    const bad = { ...w.bundleB, ikPub: generateIdentity().ik.pub };
    expect(verifyBundle(bad).reason).toBe("bad-ik-binding");
  });
  it("flags a changed pinned IK or SIK", () => {
    const w = world();
    expect(verifyBundle(w.bundleB, { ik: generateIdentity().ik.pub }).reason).toBe("ik-changed");
    expect(verifyBundle(w.bundleB, { sik: generateIdentity().sik.pub }).reason).toBe("sik-changed");
  });
  it("rejects bad lengths", () => {
    const w = world();
    expect(verifyBundle({ ...w.bundleB, ikPub: new Uint8Array(31) }).reason).toBe("bad-length");
  });
});

describe("v1 encrypt / decrypt", () => {
  it("round trips", async () => {
    const w = world();
    const msg = await send(w, "hello bob");
    expect(msg.v).toBe(1);
    expect((await recv(w, msg)).body).toBe("hello bob");
  });
  it("round trips unicode", async () => {
    const w = world();
    const s = "नमस्ते 🌍 héllo";
    expect((await recv(w, await send(w, s))).body).toBe(s);
  });
  it("uses a fresh ek, nonce and ciphertext per message", async () => {
    const w = world();
    const m1 = await send(w, "same");
    const m2 = await send(w, "same");
    expect(m1.header.ek).not.toBe(m2.header.ek);
    expect(m1.nonce).not.toBe(m2.nonce);
    expect(m1.ciphertext).not.toBe(m2.ciphertext);
  });
  it("pads to 256-byte blocks, hiding short lengths", async () => {
    const w = world();
    const a = await send(w, "a");
    const b = await send(w, "b".repeat(100));
    expect(fromB64(a.ciphertext).length).toBe(fromB64(b.ciphertext).length);
    expect((fromB64(a.ciphertext).length - 16) % 256).toBe(0);
  });
  it("rejects text over 4000 chars", async () => {
    await expect(send(world(), "x".repeat(4001))).rejects.toMatchObject({ code: "too-long" });
  });
  it("refuses to encrypt to a bad bundle", async () => {
    const w = world();
    const bad = { ...w.bundleB, spk: { ...w.bundleB.spk, sig: new Uint8Array(64) } };
    await expect(send(w, "hi", { bundle: bad })).rejects.toMatchObject({ code: "bad-spk-sig" });
  });
  it("refuses a changed pinned key", async () => {
    const w = world();
    await expect(send(w, "hi", { pinned: { ik: generateIdentity().ik.pub } })).rejects.toMatchObject({ code: "ik-changed" });
  });

  describe("fails closed on tampering", () => {
    it("flipped ciphertext", async () => {
      const w = world(); const m = await send(w);
      await expect(recv(w, { ...m, ciphertext: flip(m.ciphertext) })).rejects.toMatchObject({ code: "tampered" });
    });
    it("flipped nonce", async () => {
      const w = world(); const m = await send(w);
      await expect(recv(w, { ...m, nonce: flip(m.nonce) })).rejects.toMatchObject({ code: "tampered" });
    });
    it("swapped ek", async () => {
      const w = world(); const m = await send(w);
      await expect(recv(w, { ...m, header: { ...m.header, ek: toB64(generateIdentity().ik.pub) } })).rejects.toMatchObject({ code: "tampered" });
    });
    it("re-aimed at a different receiver id", async () => {
      const w = world(); const m = await send(w);
      await expect(recv(w, m, { receiverId: "c".repeat(24) })).rejects.toMatchObject({ code: "tampered" });
    });
    it("re-labelled as a different sender id", async () => {
      const w = world(); const m = await send(w);
      await expect(recv(w, m, { senderId: "c".repeat(24) })).rejects.toMatchObject({ code: "tampered" });
    });
    it("type changed from text to media", async () => {
      const w = world(); const m = await send(w);
      await expect(recv(w, { ...m, type: "media" })).rejects.toMatchObject({ code: "tampered" });
    });
    it("wrong sender identity key", async () => {
      const w = world(); const m = await send(w);
      await expect(recv(w, m, { senderIkPub: generateIdentity().ik.pub })).rejects.toMatchObject({ code: "tampered" });
    });
    it("garbage header", async () => {
      const w = world(); const m = await send(w);
      await expect(recv(w, { ...m, header: { ek: "!!!", spkId: 7 } })).rejects.toMatchObject({ code: "tampered" });
    });
  });

  it("unknown spkId gives undecryptable", async () => {
    const w = world(); const m = await send(w);
    await expect(recv(w, m, { getSpkPriv: () => null })).rejects.toMatchObject({ code: "undecryptable" });
  });
  it("v2 gives unsupported-version", async () => {
    const w = world(); const m = await send(w);
    await expect(recv(w, { ...m, v: 2 })).rejects.toMatchObject({ code: "unsupported-version" });
  });
  it("a third party cannot decrypt", async () => {
    const w = world(); const m = await send(w);
    const eve = generateIdentity();
    await expect(recv(w, m, { myIk: eve.ik })).rejects.toBeTruthy();
  });
});
