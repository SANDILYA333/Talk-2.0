import "fake-indexeddb/auto";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { set } from "idb-keyval";
import nacl from "tweetnacl";

vi.mock("./axios", () => ({ axiosInstance: { get: vi.fn(), put: vi.fn(), post: vi.fn() } }));
import { axiosInstance as ax } from "./axios";
import { encryptText, readMessage, snippetFor, clearBundleCache } from "./chatCrypto.js";
import { readPin, acceptKeyChange } from "./safety.js";
import { upgradeIdentity, ensureSpk, loadIdentity, putPlain, getPlain, delPlain, wipeKeyMaterial, deleteSession } from "../storage/keystore.js";
import { signIkBinding, toB64, fromB64, encryptV1 } from "../crypto/index.js";
import { PEER_KEY_CHANGED, DECRYPT_FAILED, UNSUPPORTED_VERSION, PEER_NO_KEYS, SESSION_SETUP_FAILED } from "../crypto/errors.js";

let n = 0;
const uid = () => (++n).toString(16).padStart(24, "0");
const b64 = (u) => Buffer.from(u).toString("base64");

async function mkUser() {
  const id = uid();
  const kp = nacl.box.keyPair();
  await set(`identity:${id}`, { publicKey: b64(kp.publicKey), secretKey: b64(kp.secretKey) });
  await upgradeIdentity(id);
  await ensureSpk(id);
  return id;
}
// simulates an identity reset: brand-new IK + SIK + SPK
async function resetUser(id) {
  const kp = nacl.box.keyPair();
  await set(`identity:${id}`, { publicKey: b64(kp.publicKey), secretKey: b64(kp.secretKey) });
  await wipeKeyMaterial(id);
  await upgradeIdentity(id);
  await ensureSpk(id);
}
async function bundleOf(id) {
  const idn = await loadIdentity(id);
  const spk = await ensureSpk(id);
  return {
    userId: id, ikPub: toB64(idn.ik.pub), sikPub: toB64(idn.sik.pub),
    ikBinding: toB64(signIkBinding(idn.sik.priv, idn.ik.pub)),
    spk: { id: spk.id, pub: toB64(spk.pub), sig: toB64(spk.sig) },
    opk: null, protoMax: 1,
  };
}
const keysOf = async (id) => {
  const b = await bundleOf(id);
  return { publicKey: b.ikPub, sik: b.sikPub, connectCode: "TALK-XXXXX-XXXXX" };
};
const httpErr = (status, message) => Object.assign(new Error(String(status)), { response: { status, data: { message } } });
const calls = (prefix) => ax.get.mock.calls.filter((c) => c[0].startsWith(prefix)).length;

let down;
beforeEach(() => {
  ax.get.mockReset();
  clearBundleCache?.();
  down = { bundle: new Set(), keys: new Set() };
  ax.get.mockImplementation(async (url) => {
    const m = url.match(/^\/(keys\/bundle|identity\/key)\/(.+)$/);
    if (!m) throw new Error("unexpected " + url);
    const [, kind, id] = m;
    if (kind === "keys/bundle") {
      if (down.bundle.has(id)) throw httpErr(404, "recipient-no-keys");
      return { data: await bundleOf(id) };
    }
    if (down.keys.has(id)) throw new Error("network");
    return { data: await keysOf(id) };
  });
});

const wire = (from, to, payload, over = {}) => ({
  _id: uid(), senderId: from, receiverId: to, cid: `c-${++n}-padpadpad`,
  createdAt: "2026-10-18T00:00:00.000Z", ...payload, ...over,
});
async function flow(text = "hi bob") {
  const A = await mkUser(), B = await mkUser();
  const { payload } = await encryptText({ me: A, peerId: B, text });
  return { A, B, msg: wire(A, B, payload) };
}
const flip = (b) => { const u = fromB64(b); u[0] ^= 1; return toB64(u); };

describe("encryptText", () => {
  it("makes a v2 payload with no plaintext in it", async () => {
    const A = await mkUser(), B = await mkUser();
    const { payload, envelope } = await encryptText({ me: A, peerId: B, text: "secret-hello" });
    expect(payload.v).toBe(2);
    expect(payload.type).toBe("text");
    expect(Object.keys(payload).sort()).toEqual(["ciphertext", "header", "nonce", "type", "v"]);
    expect(JSON.stringify(payload)).not.toContain("secret-hello");
    expect(envelope).toMatchObject({ t: "text", body: "secret-hello" });
  });
  it("pins the peer on first send", async () => {
    const A = await mkUser(), B = await mkUser();
    await encryptText({ me: A, peerId: B, text: "x" });
    expect(await readPin(A, B)).toMatchObject({ verified: false });
  });
  it("caches the bundle, refetches after clearBundleCache and session reset", async () => {
    const A = await mkUser(), B = await mkUser();
    await encryptText({ me: A, peerId: B, text: "1" });
    await encryptText({ me: A, peerId: B, text: "2" });
    expect(calls("/keys/bundle")).toBe(1);
    clearBundleCache();
    await deleteSession(A, B);
    await encryptText({ me: A, peerId: B, text: "3" });
    expect(calls("/keys/bundle")).toBe(2);
  });
  it("recipient without keys", async () => {
    const A = await mkUser(), B = await mkUser();
    down.bundle.add(B);
    await expect(encryptText({ me: A, peerId: B, text: "x" })).rejects.toMatchObject({ code: PEER_NO_KEYS });
  });
  it("blocks sending when the peer's keys changed since pinning", async () => {
    const A = await mkUser(), B = await mkUser();
    await encryptText({ me: A, peerId: B, text: "x" });
    await resetUser(B);
    clearBundleCache();
    await deleteSession(A, B);
    await expect(encryptText({ me: A, peerId: B, text: "y" })).rejects.toMatchObject({ code: PEER_KEY_CHANGED });
  });
  it("refuses a bundle with a bad signature", async () => {
    const A = await mkUser(), B = await mkUser();
    ax.get.mockImplementationOnce(async () => {
      const b = await bundleOf(B);
      b.spk.sig = toB64(new Uint8Array(64));
      return { data: b };
    });
    await expect(encryptText({ me: A, peerId: B, text: "x" })).rejects.toMatchObject({ code: SESSION_SETUP_FAILED });
  });
  it("rejects over-long text", async () => {
    const A = await mkUser(), B = await mkUser();
    await expect(encryptText({ me: A, peerId: B, text: "x".repeat(4001) })).rejects.toMatchObject({ code: "too-long" });
  });
});

describe("readMessage", () => {
  it("decrypts, caches, and still works after the SPK is gone", async () => {
    const { B, msg } = await flow("hi bob");
    expect(await readMessage({ me: B, msg })).toMatchObject({ state: "ok", text: "hi bob" });
    expect(await getPlain(B, msg._id)).toMatchObject({ body: "hi bob" });
    await wipeKeyMaterial(B);
    expect((await readMessage({ me: B, msg })).state).toBe("ok"); // cache hit
  });
  it("re-decrypts when the cache entry is deleted (v1 message)", async () => {
    const A = await mkUser(), B = await mkUser();
    const idnA = await loadIdentity(A);
    const rawB = await bundleOf(B);
    const bundleB = {
      userId: B,
      ikPub: fromB64(rawB.ikPub),
      sikPub: fromB64(rawB.sikPub),
      ikBinding: fromB64(rawB.ikBinding),
      spk: { id: rawB.spk.id, pub: fromB64(rawB.spk.pub), sig: fromB64(rawB.spk.sig) },
    };
    const v1Payload = await encryptV1({
      bundle: bundleB,
      senderId: A,
      receiverId: B,
      myIk: idnA.ik,
      type: "text",
      envelope: { t: "text", body: "again", ts: Date.now() },
    });
    const msg = wire(A, B, v1Payload);
    await readMessage({ me: B, msg });
    await delPlain(B, msg._id);
    expect(await readMessage({ me: B, msg })).toMatchObject({ state: "ok", text: "again" });
  });
  it("round trips unicode", async () => {
    const { B, msg } = await flow("नमस्ते 🌍 héllo");
    expect((await readMessage({ me: B, msg })).text).toBe("नमस्ते 🌍 héllo");
  });
  it("own message: undecryptable without cache, ok with cache", async () => {
    const { A, B, msg } = await flow("mine");
    expect((await readMessage({ me: A, msg })).state).toBe(DECRYPT_FAILED);
    await putPlain(A, msg._id, { t: "text", body: "mine", ts: 1 });
    expect(await readMessage({ me: A, msg })).toMatchObject({ state: "ok", text: "mine" });
    void B;
  });
  it("tampered ciphertext: state tampered, nothing cached", async () => {
    const { B, msg } = await flow();
    const r = await readMessage({ me: B, msg: { ...msg, ciphertext: flip(msg.ciphertext) } });
    expect(r.state).toBe(DECRYPT_FAILED);
    expect(await getPlain(B, msg._id)).toBeNull();
  });
  it("first contact pins the sender (one fetch even for concurrent reads)", async () => {
    const A = await mkUser(), B = await mkUser();
    const msgs = [];
    for (const t of ["1", "2", "3"]) msgs.push(wire(A, B, (await encryptText({ me: A, peerId: B, text: t })).payload));
    const rs = await Promise.all(msgs.map((msg) => readMessage({ me: B, msg })));
    expect(rs.map((r) => r.text)).toEqual(["1", "2", "3"]);
    expect(calls("/identity/key")).toBe(1);
    expect(await readPin(B, A)).toMatchObject({ verified: false });
  });
  it("waiting-for-key when the sender's key cannot be fetched, then ok", async () => {
    const { A, B, msg } = await flow();
    down.keys.add(A);
    expect((await readMessage({ me: B, msg })).state).toBe("waiting-for-key");
    down.keys.delete(A);
    expect((await readMessage({ me: B, msg })).state).toBe("ok");
  });
  it("unsupported version never touches the network", async () => {
    const { B, msg } = await flow();
    ax.get.mockClear();
    expect((await readMessage({ me: B, msg: { ...msg, v: 3 } })).state).toBe(UNSUPPORTED_VERSION);
    expect(ax.get).not.toHaveBeenCalled();
  });
  it("undecryptable when the SPK is gone and nothing is cached", async () => {
    const { B, msg } = await flow();
    await wipeKeyMaterial(B);
    expect((await readMessage({ me: B, msg })).state).toBe(DECRYPT_FAILED);
  });
  it("sender reset: key-changed, then ok after the user accepts", async () => {
    const A = await mkUser(), B = await mkUser();
    const m1 = wire(A, B, (await encryptText({ me: A, peerId: B, text: "before" })).payload);
    expect((await readMessage({ me: B, msg: m1 })).state).toBe("ok"); // B pins A
    await resetUser(A);
    clearBundleCache();
    const m2 = wire(A, B, (await encryptText({ me: A, peerId: B, text: "after" })).payload);
    expect((await readMessage({ me: B, msg: m2 })).state).toBe(PEER_KEY_CHANGED);
    const cur = await keysOf(A);
    await acceptKeyChange(B, A, { ik: cur.publicKey, sik: cur.sik });
    expect(await readMessage({ me: B, msg: m2 })).toMatchObject({ state: "ok", text: "after" });
  });
});

describe("snippetFor", () => {
  it("cached body, truncated at 80, or a placeholder", async () => {
    const me = uid();
    await putPlain(me, "m1", { body: "short", ts: 1 });
    await putPlain(me, "m2", { body: "x".repeat(200), ts: 1 });
    expect(await snippetFor(me, { _id: "m1" })).toBe("short");
    const long = await snippetFor(me, { _id: "m2" });
    expect(long.length).toBe(80);
    expect(long.endsWith("…")).toBe(true);
    expect(await snippetFor(me, { _id: "nope" })).toBe("Encrypted message");
    expect(await snippetFor(me, null)).toBe("");
  });
});
