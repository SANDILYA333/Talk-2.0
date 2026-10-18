import "dotenv/config";
import { vi, describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
vi.mock("../src/lib/socket.js", () => ({ emitToUser: vi.fn() }));
import mongoose from "mongoose";
import { randomBytes, randomUUID } from "node:crypto";
import User from "../src/models/user.model.js";
import KeyBundle from "../src/models/keyBundle.model.js";
import Message from "../src/models/message.model.js";
import ReadState from "../src/models/readState.model.js";
import { emitToUser } from "../src/lib/socket.js";
import { sendMessage, getConversationsForSidebar, markRead } from "../src/controllers/message.controller.js";

const RUN = `t_s6_${Date.now()}`;
let n = 0;
const b64 = (u) => Buffer.from(u).toString("base64");

async function mkUser() {
  const k = ++n;
  const user = await User.create({
    clerkId: `${RUN}_${k}`,
    email: `${RUN}_${k}@test.local`,
    fullName: `User_${k}`,
    profilePic: "",
  });
  await KeyBundle.create({
    userId: user._id,
    sik: b64(randomBytes(32)),
    ikBinding: b64(randomBytes(64)),
    spk: { id: 1, pub: b64(randomBytes(32)), sig: b64(randomBytes(64)) },
  });
  return user;
}

const good = (over = {}) => ({
  cid: randomUUID(),
  v: 1,
  type: "text",
  ciphertext: b64(randomBytes(16 + 256)),
  nonce: b64(randomBytes(12)),
  header: { ek: b64(randomBytes(32)), spkId: 1 },
  ...over,
});

async function call(handler, { user, body, params, query } = {}) {
  const req = { user, body, params: params ?? {}, query: query ?? {} };
  let status = 200, json;
  const res = {
    status(c) {
      status = c;
      return this;
    },
    json(j) {
      json = j;
      return this;
    },
  };
  await handler(req, res);
  return { status, json };
}

const send = (from, to, body = good()) =>
  call(sendMessage, { user: from, params: { id: String(to._id ?? to) }, body });

const mark = (user, peer, upTo) =>
  call(markRead, { user, params: { peerId: String(peer._id ?? peer) }, body: { upTo } });

beforeAll(async () => {
  await mongoose.connect(process.env.MONGO_URI, { dbName: "talk_test" });
  await Promise.all([User.init(), KeyBundle.init(), Message.init(), ReadState.init()]);
});

beforeEach(() => emitToUser.mockClear());

afterAll(async () => {
  const users = await User.find({ clerkId: new RegExp(`^${RUN}`) }).select("_id");
  const ids = users.map((u) => u._id);
  await Message.deleteMany({ $or: [{ senderId: { $in: ids } }, { receiverId: { $in: ids } }] });
  await ReadState.deleteMany({ $or: [{ userId: { $in: ids } }, { peerId: { $in: ids } }] });
  await KeyBundle.deleteMany({ userId: { $in: ids } });
  await User.deleteMany({ _id: { $in: ids } });
  await mongoose.disconnect();
});

describe("ReadState model & indexes", () => {
  it("has userId, peerId, lastReadMessageId and unique index on {userId, peerId}", () => {
    expect(ReadState.schema.path("userId")).toBeDefined();
    expect(ReadState.schema.path("peerId")).toBeDefined();
    expect(ReadState.schema.path("lastReadMessageId")).toBeDefined();
    const idx = ReadState.schema.indexes();
    expect(idx.some(([k, o]) => k.userId === 1 && k.peerId === 1 && o.unique)).toBe(true);
  });
});

describe("POST /api/messages/read/:peerId (markRead)", () => {
  it("rejects bad peerId and missing/bad upTo", async () => {
    const a = await mkUser(), b = await mkUser();
    expect((await mark(a, "not-an-id", new mongoose.Types.ObjectId().toString())).status).toBe(400);
    expect((await mark(a, b, undefined)).status).toBe(400);
    expect((await mark(a, b, "not-an-id")).status).toBe(400);
  });

  it("rejects a message from another conversation or an own message", async () => {
    const a = await mkUser(), b = await mkUser(), c = await mkUser();
    const ownMsg = (await send(a, b)).json;
    const otherMsg = (await send(b, c)).json;

    // own message sent by a to b
    const rOwn = await mark(a, b, ownMsg._id);
    expect([400, 404]).toContain(rOwn.status);

    // message between b and c, not sent to a
    const rOther = await mark(a, b, otherMsg._id);
    expect([400, 404]).toContain(rOther.status);
  });

  it("advances forward only, same value is a no-op, emits readUpdated on change", async () => {
    const a = await mkUser(), b = await mkUser();
    const m1 = (await send(b, a)).json;
    const m2 = (await send(b, a)).json;
    emitToUser.mockClear();

    // advance to m2
    const r1 = await mark(a, b, m2._id);
    expect(r1.status).toBe(200);
    expect(emitToUser).toHaveBeenCalledTimes(1);
    expect(emitToUser).toHaveBeenCalledWith(String(a._id), "readUpdated", { peerId: String(b._id) });

    const state1 = await ReadState.findOne({ userId: a._id, peerId: b._id });
    expect(String(state1.lastReadMessageId)).toBe(m2._id);

    emitToUser.mockClear();

    // trying to move backwards to m1 should be 200 no-op
    const r2 = await mark(a, b, m1._id);
    expect(r2.status).toBe(200);
    expect(emitToUser).not.toHaveBeenCalled();

    const state2 = await ReadState.findOne({ userId: a._id, peerId: b._id });
    expect(String(state2.lastReadMessageId)).toBe(m2._id);

    // same value m2 is also a no-op
    const r3 = await mark(a, b, m2._id);
    expect(r3.status).toBe(200);
    expect(emitToUser).not.toHaveBeenCalled();
  });

  it("concurrent calls end at the highest value", async () => {
    const a = await mkUser(), b = await mkUser();
    const msgs = [];
    for (let i = 0; i < 4; i++) {
      msgs.push((await send(b, a)).json);
    }

    // shuffle and fire concurrently
    const shuffled = [...msgs].sort(() => Math.random() - 0.5);
    const results = await Promise.all(shuffled.map((m) => mark(a, b, m._id)));
    for (const r of results) expect(r.status).toBe(200);

    const highest = msgs[msgs.length - 1];
    const finalState = await ReadState.findOne({ userId: a._id, peerId: b._id });
    expect(String(finalState.lastReadMessageId)).toBe(highest._id);
  });

  it("users are isolated", async () => {
    const a = await mkUser(), b = await mkUser(), c = await mkUser();
    const m = (await send(b, a)).json;
    await mark(a, b, m._id);

    const cState = await ReadState.findOne({ userId: c._id, peerId: b._id });
    expect(cState).toBeNull();
  });
});

describe("getConversationsForSidebar unreadCount", () => {
  it("counts only peer messages after the marker, excludes own messages, zero after markRead", async () => {
    const a = await mkUser(), b = await mkUser();
    const m1 = (await send(b, a)).json;
    const m2 = (await send(b, a)).json;
    const m3 = (await send(b, a)).json;

    // Initially 3 unread from b to a
    let convs = (await call(getConversationsForSidebar, { user: a })).json;
    let bConv = convs.find((c) => String(c._id) === String(b._id));
    expect(bConv.unreadCount).toBe(3);

    // A sends an own message to B; own messages must not increment unreadCount
    await send(a, b);
    convs = (await call(getConversationsForSidebar, { user: a })).json;
    bConv = convs.find((c) => String(c._id) === String(b._id));
    expect(bConv.unreadCount).toBe(3);

    // Mark read up to m2 -> 1 unread left (m3)
    await mark(a, b, m2._id);
    convs = (await call(getConversationsForSidebar, { user: a })).json;
    bConv = convs.find((c) => String(c._id) === String(b._id));
    expect(bConv.unreadCount).toBe(1);

    // Mark read up to m3 -> 0 unread
    await mark(a, b, m3._id);
    convs = (await call(getConversationsForSidebar, { user: a })).json;
    bConv = convs.find((c) => String(c._id) === String(b._id));
    expect(bConv.unreadCount).toBe(0);

    // B sends a new message -> increments to 1
    await send(b, a);
    convs = (await call(getConversationsForSidebar, { user: a })).json;
    bConv = convs.find((c) => String(c._id) === String(b._id));
    expect(bConv.unreadCount).toBe(1);

    // Response must not contain plaintext or ciphertext fields
    expect(JSON.stringify(convs)).not.toMatch(/"(text|ciphertext|nonce|header)":/);
  });

  it("maintains per-conversation independence", async () => {
    const a = await mkUser(), b = await mkUser(), c = await mkUser();
    await send(b, a);
    await send(b, a);
    await send(c, a);

    const convs = (await call(getConversationsForSidebar, { user: a })).json;
    const bConv = convs.find((item) => String(item._id) === String(b._id));
    const cConv = convs.find((item) => String(item._id) === String(c._id));

    expect(bConv.unreadCount).toBe(2);
    expect(cConv.unreadCount).toBe(1);
  });
});
