import "dotenv/config";
import { vi, describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
vi.mock("../src/lib/socket.js", () => ({ emitToUser: vi.fn() }));
import mongoose from "mongoose";
import { randomBytes, randomUUID } from "node:crypto";
import User from "../src/models/user.model.js";
import KeyBundle from "../src/models/keyBundle.model.js";
import Message from "../src/models/message.model.js";
import { emitToUser } from "../src/lib/socket.js";
import { sendMessage, getMessages, getConversationsForSidebar } from "../src/controllers/message.controller.js";

const RUN = `t_s5_${Date.now()}`;
let n = 0;
const b64 = (u) => Buffer.from(u).toString("base64");

async function mkUser({ keys = true } = {}) {
  const k = ++n;
  const user = await User.create({ clerkId: `${RUN}_${k}`, email: `${RUN}_${k}@test.local`, fullName: `T${k}`, profilePic: "" });
  if (keys) {
    await KeyBundle.create({
      userId: user._id, sik: b64(randomBytes(32)), ikBinding: b64(randomBytes(64)),
      spk: { id: 1, pub: b64(randomBytes(32)), sig: b64(randomBytes(64)) },
    });
  }
  return user;
}

const good = (over = {}) => ({
  cid: randomUUID(), v: 1, type: "text",
  ciphertext: b64(randomBytes(16 + 256)), nonce: b64(randomBytes(12)),
  header: { ek: b64(randomBytes(32)), spkId: 1 },
  ...over,
});

async function call(handler, { user, body, params, query } = {}) {
  const req = { user, body, params: params ?? {}, query: query ?? {} };
  let status = 200, json;
  const res = { status(c) { status = c; return this; }, json(j) { json = j; return this; } };
  await handler(req, res);
  return { status, json };
}
const send = (from, to, body) => call(sendMessage, { user: from, params: { id: String(to._id ?? to) }, body });

beforeAll(async () => {
  await mongoose.connect(process.env.MONGO_URI, { dbName: "talk_test" });
  await Promise.all([User.init(), KeyBundle.init(), Message.init()]);
});
beforeEach(() => emitToUser.mockClear());
afterAll(async () => {
  const users = await User.find({ clerkId: new RegExp(`^${RUN}`) }).select("_id");
  const ids = users.map((u) => u._id);
  await Message.deleteMany({ $or: [{ senderId: { $in: ids } }, { receiverId: { $in: ids } }] });
  await KeyBundle.deleteMany({ userId: { $in: ids } });
  await User.deleteMany({ _id: { $in: ids } });
  await mongoose.disconnect();
});

describe("schema", () => {
  it("has no plaintext paths, has the new fields and indexes", () => {
    for (const p of ["text", "image", "video"]) expect(Message.schema.path(p)).toBeUndefined();
    for (const p of ["cid", "v", "type", "ciphertext", "nonce", "header", "expiresAt"]) expect(Message.schema.path(p)).toBeDefined();
    const idx = Message.schema.indexes();
    expect(idx.some(([k, o]) => k.senderId === 1 && k.cid === 1 && o.unique)).toBe(true);
    expect(idx.some(([k, o]) => k.expiresAt === 1 && o.expireAfterSeconds === 0 && o.sparse)).toBe(true);
    expect(idx.some(([k]) => k.senderId === 1 && k.receiverId === 1 && k._id === -1)).toBe(true);
  });
});

describe("sendMessage: happy path", () => {
  it("stores ciphertext only, returns 201, emits to the receiver once", async () => {
    const a = await mkUser(), b = await mkUser();
    const body = good();
    const r = await send(a, b, body);
    expect(r.status).toBe(201);
    expect(r.json).toMatchObject({ senderId: String(a._id), receiverId: String(b._id), cid: body.cid, v: 1, type: "text" });
    expect(JSON.stringify(r.json)).not.toMatch(/"(text|image|video)":/);
    const raw = await Message.collection.findOne({ cid: body.cid });
    expect(raw.ciphertext).toBe(body.ciphertext);
    expect(raw.text).toBeUndefined();
    expect(emitToUser).toHaveBeenCalledTimes(1);
    expect(emitToUser.mock.calls[0][0]).toBe(String(b._id));
    expect(emitToUser.mock.calls[0][1]).toBe("newMessage");
    expect(emitToUser.mock.calls[0][2]._id).toBe(r.json._id);
  });
});

describe("sendMessage: validation", () => {
  const bad = {
    "missing cid": { cid: undefined },
    "cid with spaces": { cid: "has space 1234" },
    "cid too short": { cid: "abc" },
    "v=2": { v: 2 }, "v=0": { v: 0 }, "v is a string": { v: "1" },
    "type media": { type: "media" }, "type secret": { type: "secret" }, "type bogus": { type: "x" },
    "ciphertext not base64": { ciphertext: "***" },
    "ciphertext non-canonical": { ciphertext: b64(randomBytes(272)) + "\n" },
    "ciphertext too short": { ciphertext: b64(randomBytes(16)) },
    "ciphertext bad padding": { ciphertext: b64(randomBytes(300)) },
    "ciphertext too long": { ciphertext: b64(randomBytes(16 + 256 * 70)) },
    "nonce 11 bytes": { nonce: b64(randomBytes(11)) },
    "nonce 13 bytes": { nonce: b64(randomBytes(13)) },
    "header missing": { header: undefined },
    "header ek 31 bytes": { header: { ek: b64(randomBytes(31)), spkId: 1 } },
    "header spkId 0": { header: { ek: b64(randomBytes(32)), spkId: 0 } },
    "header spkId 1.5": { header: { ek: b64(randomBytes(32)), spkId: 1.5 } },
    "header spkId string": { header: { ek: b64(randomBytes(32)), spkId: "1" } },
    "header extra key": { header: { ek: b64(randomBytes(32)), spkId: 1, x: 1 } },
    "plaintext text field": { text: "hello" },
    "plaintext image field": { image: "x" },
    "unknown field": { expiresIn: 5 },
  };
  for (const [name, over] of Object.entries(bad)) {
    it(`rejects: ${name}`, async () => {
      const a = await mkUser(), b = await mkUser();
      const r = await send(a, b, good(over));
      expect(r.status).toBe(400);
      expect(await Message.countDocuments({ senderId: a._id })).toBe(0);
      expect(emitToUser).not.toHaveBeenCalled();
    });
  }
  it("rejects a missing body", async () => {
    const a = await mkUser(), b = await mkUser();
    expect((await send(a, b, undefined)).status).toBe(400);
  });
  it("rejects a bad id, self, unknown user", async () => {
    const a = await mkUser();
    expect((await send(a, "nope", good())).status).toBe(400);
    expect((await send(a, a, good())).status).toBe(400);
    expect((await send(a, new mongoose.Types.ObjectId(), good())).status).toBe(404);
  });
  it("409 recipient-no-keys when the recipient has no bundle", async () => {
    const a = await mkUser(), c = await mkUser({ keys: false });
    const r = await send(a, c, good());
    expect(r.status).toBe(409);
    expect(r.json.message).toBe("recipient-no-keys");
    expect(emitToUser).not.toHaveBeenCalled();
  });
});

describe("sendMessage: dedupe", () => {
  it("same cid twice: one document, 200 with the same _id, one emit", async () => {
    const a = await mkUser(), b = await mkUser();
    const body = good();
    const r1 = await send(a, b, body);
    expect(r1.status).toBe(201);
    const r2 = await send(a, b, body);
    expect(r2.status).toBe(200);
    expect(r2.json._id).toBe(r1.json._id);
    expect(await Message.countDocuments({ senderId: a._id, cid: body.cid })).toBe(1);
    expect(emitToUser).toHaveBeenCalledTimes(1);
  });
  it("same cid from two different senders is fine", async () => {
    const a = await mkUser(), b = await mkUser(), c = await mkUser();
    const cid = randomUUID();
    expect((await send(a, c, good({ cid }))).status).toBe(201);
    expect((await send(b, c, good({ cid }))).status).toBe(201);
  });
  it("same cid reused for a different receiver is a conflict", async () => {
    const a = await mkUser(), b = await mkUser(), c = await mkUser();
    const cid = randomUUID();
    await send(a, b, good({ cid }));
    const r = await send(a, c, good({ cid }));
    expect(r.status).toBe(409);
    expect(r.json.message).toBe("cid-conflict");
  });
  it("5 concurrent identical sends: one 201, rest 200, one doc, one emit", async () => {
    const a = await mkUser(), b = await mkUser();
    const body = good();
    const rs = await Promise.all([1, 2, 3, 4, 5].map(() => send(a, b, body)));
    expect(rs.filter((r) => r.status === 201).length).toBe(1);
    expect(rs.filter((r) => r.status === 200).length).toBe(4);
    expect(new Set(rs.map((r) => r.json._id)).size).toBe(1);
    expect(await Message.countDocuments({ senderId: a._id, cid: body.cid })).toBe(1);
    expect(emitToUser).toHaveBeenCalledTimes(1);
  });
});

describe("getMessages", () => {
  it("returns ciphertext-only wire objects, paginated", async () => {
    const a = await mkUser(), b = await mkUser();
    for (let i = 0; i < 5; i++) await send(a, b, good());
    const r = await call(getMessages, { user: b, params: { id: String(a._id) }, query: { limit: "3" } });
    expect(r.json.messages.length).toBe(3);
    expect(r.json.hasMore).toBe(true);
    for (const m of r.json.messages) {
      expect(m.ciphertext).toBeTruthy();
      expect(m).not.toHaveProperty("text");
      expect(m).not.toHaveProperty("__v");
      expect(typeof m._id).toBe("string");
      expect(typeof m.senderId).toBe("string");
    }
    const older = await call(getMessages, { user: b, params: { id: String(a._id) }, query: { limit: "3", before: r.json.messages[0]._id } });
    expect(older.json.messages.length).toBe(2);
    expect(older.json.hasMore).toBe(false);
  });
});

describe("getConversationsForSidebar", () => {
  it("projects lastMessage metadata only and no ciphertext or plaintext", async () => {
    const a = await mkUser(), b = await mkUser(), c = await mkUser();
    await send(a, b, good());
    await send(c, a, good());
    const r = await call(getConversationsForSidebar, { user: a });
    expect(r.status).toBe(200);
    expect(r.json.length).toBe(2);
    for (const item of r.json) {
      expect(item.lastMessage).toBeDefined();
      expect(item.lastMessage).toHaveProperty("_id");
      expect(item.lastMessage).toHaveProperty("senderId");
      expect(item.lastMessage).toHaveProperty("createdAt");
      expect(item.lastMessage).toHaveProperty("type");
    }
    expect(JSON.stringify(r.json)).not.toMatch(/"(text|ciphertext|nonce|header)":/);
  });
});
