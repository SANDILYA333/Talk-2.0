import "dotenv/config";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import mongoose from "mongoose";
import { generateKeyPairSync, sign, randomBytes } from "node:crypto";
import User from "../src/models/user.model.js";
import KeyBundle from "../src/models/keyBundle.model.js";
import OneTimePrekey from "../src/models/oneTimePrekey.model.js";
import { putBundle, postOpks, getOpkCount, getBundle } from "../src/controllers/keys.controller.js";
import { setIdentity, getKeyById } from "../src/controllers/identity.controller.js";
import { deriveConnectCode } from "../src/lib/connectCode.js";
import { b64Bytes, edVerify } from "../src/lib/keyValidate.js";

const RUN = `t_s4_${Date.now()}`;
let n = 0;
const b64 = (u) => Buffer.from(u).toString("base64");

// encodings written out literally on purpose (spec S1.1), not imported
const ikMsg = (ik) => Buffer.concat([Buffer.from("talk-ik-v1"), ik]);
const spkMsg = (id, pub) => {
  const i = Buffer.alloc(4); i.writeUInt32BE(id);
  return Buffer.concat([Buffer.from("talk-spk-v1"), i, pub]);
};

function newSik() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pub: publicKey.export({ format: "der", type: "spki" }).subarray(-32), sign: (m) => sign(null, m, privateKey) };
}

async function mkUser(withIdentity = true) {
  const k = ++n;
  const ik = randomBytes(32);
  const doc = { clerkId: `${RUN}_${k}`, email: `${RUN}_${k}@test.local`, fullName: `T${k}`, profilePic: "" };
  if (withIdentity) { doc.publicKey = b64(ik); doc.connectCode = deriveConnectCode(b64(ik)); }
  return { user: await User.create(doc), ik };
}

function body(ik, sik, id = 1, over = {}) {
  const pub = randomBytes(32);
  return {
    sik: b64(sik.pub),
    ikBinding: b64(sik.sign(ikMsg(ik))),
    spk: { id, pub: b64(pub), sig: b64(sik.sign(spkMsg(id, pub))) },
    protoMax: 1,
    ...over,
  };
}

const opkBatch = (start, count) =>
  Array.from({ length: count }, (_, i) => ({ id: start + i, pub: b64(randomBytes(32)) }));

async function call(handler, { user, body, params, query } = {}) {
  const req = { user, body, params: params ?? {}, query: query ?? {} };
  let status = 200, json;
  const res = { status(c) { status = c; return this; }, json(j) { json = j; return this; } };
  await handler(req, res);
  return { status, json };
}

async function ready() {
  const u = await mkUser(); const sik = newSik();
  const r = await call(putBundle, { user: u.user, body: body(u.ik, sik) });
  expect(r.status).toBe(200);
  return { ...u, sik };
}

beforeAll(async () => {
  await mongoose.connect(process.env.MONGO_URI, { dbName: "talk_test" });
  await Promise.all([User.init(), KeyBundle.init(), OneTimePrekey.init()]);
});
afterAll(async () => {
  const users = await User.find({ clerkId: new RegExp(`^${RUN}`) }).select("_id");
  const ids = users.map((u) => u._id);
  await KeyBundle.deleteMany({ userId: { $in: ids } });
  await OneTimePrekey.deleteMany({ userId: { $in: ids } });
  await User.deleteMany({ _id: { $in: ids } });
  await mongoose.disconnect();
});

describe("keyValidate", () => {
  it("canonical base64 only, exact length", () => {
    expect(b64Bytes(b64(randomBytes(32)), 32)).not.toBeNull();
    expect(b64Bytes(b64(randomBytes(31)), 32)).toBeNull();
    expect(b64Bytes(b64(randomBytes(32)) + "\n", 32)).toBeNull();
    expect(b64Bytes(123, 32)).toBeNull();
    expect(b64Bytes("AAAA", 32)).toBeNull();
  });
  it("Ed25519 RFC 8032 test 1 verifies", () => {
    const hex = (h) => Buffer.from(h, "hex");
    const pub = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const sig = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    expect(edVerify(sig, Buffer.alloc(0), pub)).toBe(true);
    expect(edVerify(sig, Buffer.from("x"), pub)).toBe(false);
  });
});

describe("PUT /keys/bundle", () => {
  it("409 when the user has no identity", async () => {
    const { user, ik } = await mkUser(false);
    const r = await call(putBundle, { user, body: body(ik, newSik()) });
    expect(r.status).toBe(409);
  });
  it("accepts a valid bundle and stores it", async () => {
    const { user } = await ready();
    const kb = await KeyBundle.findOne({ userId: user._id });
    expect(kb.spk.id).toBe(1);
    expect(kb.protoMax).toBe(1);
  });
  it("rejects a binding signed over a different IK", async () => {
    const { user } = await mkUser(); const sik = newSik();
    const r = await call(putBundle, { user, body: body(randomBytes(32), sik) });
    expect(r.status).toBe(400);
    expect(r.json.message).toBe("bad-ik-binding");
  });
  it("rejects a bad SPK signature", async () => {
    const { user, ik } = await mkUser(); const sik = newSik();
    const b = body(ik, sik); b.spk.sig = b64(randomBytes(64));
    const r = await call(putBundle, { user, body: b });
    expect(r.json.message).toBe("bad-spk-sig");
  });
  it("rejects an SPK id changed after signing", async () => {
    const { user, ik } = await mkUser(); const sik = newSik();
    const b = body(ik, sik, 1); b.spk.id = 2;
    expect((await call(putBundle, { user, body: b })).json.message).toBe("bad-spk-sig");
  });
  it("rejects bad shapes", async () => {
    const { user, ik } = await mkUser(); const sik = newSik();
    for (const bad of [
      { ...body(ik, sik), sik: b64(randomBytes(31)) },
      { ...body(ik, sik), protoMax: 3 },
      { ...body(ik, sik), ikBinding: b64(randomBytes(64)) + " " },
      { ...body(ik, sik), spk: { id: 0, pub: b64(randomBytes(32)), sig: b64(randomBytes(64)) } },
      { ...body(ik, sik), spk: { id: 1.5, pub: b64(randomBytes(32)), sig: b64(randomBytes(64)) } },
      {}, undefined,
    ]) {
      expect((await call(putBundle, { user, body: bad })).status).toBe(400);
    }
  });
  it("is idempotent for the identical bundle", async () => {
    const { user, ik, sik } = await mkUser().then(async (u) => ({ ...u, sik: newSik() }));
    const b = body(ik, sik, 1);
    expect((await call(putBundle, { user, body: b })).status).toBe(200);
    expect((await call(putBundle, { user, body: b })).status).toBe(200);
  });
  it("rotates upward, refuses stale ids, refuses same id with a new key", async () => {
    const { user, ik, sik } = await ready();
    expect((await call(putBundle, { user, body: body(ik, sik, 2) })).status).toBe(200);
    expect((await call(putBundle, { user, body: body(ik, sik, 1) })).json.message).toBe("stale-spk");
    expect((await call(putBundle, { user, body: body(ik, sik, 2) })).json.message).toBe("stale-spk");
  });
  it("a new signing key is accepted and clears OPKs", async () => {
    const { user, ik } = await ready();
    await call(postOpks, { user, body: { keys: opkBatch(1, 5) } });
    expect(await OneTimePrekey.countDocuments({ userId: user._id })).toBe(5);
    expect((await call(putBundle, { user, body: body(ik, newSik(), 1) })).status).toBe(200);
    expect(await OneTimePrekey.countDocuments({ userId: user._id })).toBe(0);
  });
  it("concurrent identical uploads both succeed, one document", async () => {
    const { user, ik } = await mkUser(); const sik = newSik(); const b = body(ik, sik);
    const rs = await Promise.all([1, 2, 3].map(() => call(putBundle, { user, body: b })));
    expect(rs.every((r) => r.status === 200)).toBe(true);
    expect(await KeyBundle.countDocuments({ userId: user._id })).toBe(1);
  });
});

describe("POST /keys/opks and count", () => {
  it("409 without a bundle", async () => {
    const { user } = await mkUser();
    expect((await call(postOpks, { user, body: { keys: opkBatch(1, 3) } })).json.message).toBe("no-bundle");
  });
  it("adds, counts, and is idempotent on resend", async () => {
    const { user } = await ready();
    const keys = opkBatch(1, 50);
    expect((await call(postOpks, { user, body: { keys } })).json.count).toBe(50);
    expect((await call(postOpks, { user, body: { keys } })).json.count).toBe(50);
    expect((await call(getOpkCount, { user })).json.count).toBe(50);
  });
  it("same id with a different key is a conflict", async () => {
    const { user } = await ready();
    await call(postOpks, { user, body: { keys: opkBatch(1, 3) } });
    const r = await call(postOpks, { user, body: { keys: opkBatch(1, 1) } });
    expect(r.status).toBe(409);
    expect(r.json.message).toBe("opk-conflict");
  });
  it("caps at 100 stored", async () => {
    const { user } = await ready();
    expect((await call(postOpks, { user, body: { keys: opkBatch(1, 100) } })).json.count).toBe(100);
    const r = await call(postOpks, { user, body: { keys: opkBatch(101, 1) } });
    expect(r.status).toBe(409);
    expect(r.json.message).toBe("opk-cap");
  });
  it("rejects bad input", async () => {
    const { user } = await ready();
    const dup = opkBatch(1, 2); dup[1].id = 1;
    for (const bad of [
      { keys: [] }, { keys: opkBatch(1, 101) }, { keys: dup }, { keys: [{ id: 1, pub: "zzz" }] },
      { keys: [{ id: 0, pub: b64(randomBytes(32)) }] }, {}, undefined,
    ]) {
      expect((await call(postOpks, { user, body: bad })).status).toBe(400);
    }
  });
});

describe("GET /keys/bundle/:userId", () => {
  it("404 for a user without keys, 400 for own id and bad id", async () => {
    const me = await mkUser(); const other = await mkUser();
    expect((await call(getBundle, { user: me.user, params: { userId: String(other.user._id) } })).status).toBe(404);
    expect((await call(getBundle, { user: me.user, params: { userId: String(me.user._id) } })).status).toBe(400);
    expect((await call(getBundle, { user: me.user, params: { userId: "nope" } })).status).toBe(400);
  });
  it("returns the bundle, IK from User, no email, no OPK by default", async () => {
    const me = await mkUser(); const peer = await ready();
    const r = await call(getBundle, { user: me.user, params: { userId: String(peer.user._id) } });
    expect(r.status).toBe(200);
    expect(r.json.ikPub).toBe(b64(peer.ik));
    expect(r.json.sikPub).toBe(b64(peer.sik.pub));
    expect(r.json.opk).toBeNull();
    expect(r.json.spk.id).toBe(1);
    expect(JSON.stringify(r.json)).not.toMatch(/@test\.local/);
  });
  it("opk=1 hands out OPKs in order, each exactly once", async () => {
    const me = await mkUser(); const peer = await ready();
    await call(postOpks, { user: peer.user, body: { keys: opkBatch(1, 2) } });
    const p = { userId: String(peer.user._id) };
    const a = await call(getBundle, { user: me.user, params: p, query: { opk: "1" } });
    const b = await call(getBundle, { user: me.user, params: p, query: { opk: "1" } });
    const c = await call(getBundle, { user: me.user, params: p, query: { opk: "1" } });
    expect(a.json.opk.id).toBe(1);
    expect(b.json.opk.id).toBe(2);
    expect(c.json.opk).toBeNull();
    expect(await OneTimePrekey.countDocuments({ userId: peer.user._id })).toBe(0);
  });
  it("concurrent fetches never share an OPK", async () => {
    const me = await mkUser(); const peer = await ready();
    await call(postOpks, { user: peer.user, body: { keys: opkBatch(1, 10) } });
    const p = { userId: String(peer.user._id) };
    const rs = await Promise.all(Array.from({ length: 10 }, () =>
      call(getBundle, { user: me.user, params: p, query: { opk: "1" } })));
    const ids = rs.map((r) => r.json.opk?.id);
    expect(new Set(ids).size).toBe(10);
    expect(ids.every(Boolean)).toBe(true);
  });
  it("409 stale when the stored IK no longer matches the binding", async () => {
    const me = await mkUser(); const peer = await ready();
    const newIk = randomBytes(32);
    await User.updateOne({ _id: peer.user._id }, { publicKey: b64(newIk), connectCode: deriveConnectCode(b64(newIk)) });
    const r = await call(getBundle, { user: me.user, params: { userId: String(peer.user._id) } });
    expect(r.status).toBe(409);
    expect(r.json.message).toBe("recipient-keys-stale");
  });
});

describe("identity integration", () => {
  it("replace with a new key deletes bundle and OPKs", async () => {
    const { user } = await ready();
    await call(postOpks, { user, body: { keys: opkBatch(1, 3) } });
    const fresh = await User.findById(user._id);
    const r = await call(setIdentity, { user: fresh, body: { publicKey: b64(randomBytes(32)), replace: true } });
    expect(r.status).toBe(200);
    expect(await KeyBundle.countDocuments({ userId: user._id })).toBe(0);
    expect(await OneTimePrekey.countDocuments({ userId: user._id })).toBe(0);
  });
  it("getKeyById returns sik after a bundle, null before", async () => {
    const me = await mkUser(); const noKeys = await mkUser(); const peer = await ready();
    expect((await call(getKeyById, { user: me.user, params: { userId: String(noKeys.user._id) } })).json.sik).toBeNull();
    expect((await call(getKeyById, { user: me.user, params: { userId: String(peer.user._id) } })).json.sik).toBe(b64(peer.sik.pub));
  });
});
