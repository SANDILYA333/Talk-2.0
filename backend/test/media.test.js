import "dotenv/config";
import { vi, describe, it, expect, beforeAll, afterAll } from "vitest";
vi.mock("../src/lib/socket.js", () => ({ emitToUser: vi.fn() }));
import mongoose from "mongoose";
import { randomBytes, randomUUID } from "node:crypto";
import User from "../src/models/user.model.js";
import KeyBundle from "../src/models/keyBundle.model.js";
import Message from "../src/models/message.model.js";
import { emitToUser } from "../src/lib/socket.js";
import { sendMessage } from "../src/controllers/message.controller.js";
import { getUploadAuth } from "../src/controllers/media.controller.js";

const RUN = `t_s7_${Date.now()}`;
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

describe("S7 Backend: Encrypted media & upload-auth", () => {
  let sender, receiver;

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGO_URI, { dbName: "talk_test" });
    await Promise.all([User.init(), KeyBundle.init(), Message.init()]);
    sender = await mkUser();
    receiver = await mkUser();
  });

  afterAll(async () => {
    await Message.deleteMany({
      $or: [{ senderId: sender._id }, { receiverId: sender._id }],
    });
    await KeyBundle.deleteMany({ userId: { $in: [sender._id, receiver._id] } });
    await User.deleteMany({ _id: { $in: [sender._id, receiver._id] } });
    await mongoose.disconnect();
  });

  describe("upload-auth", () => {
    it("returns signed upload params with expiry <= 5 min and no private key", async () => {
      const { status, json } = await call(getUploadAuth, { user: sender });
      expect(status).toBe(200);
      expect(json).toBeDefined();
      expect(json.publicKey).toBe(process.env.IMAGEKIT_PUBLIC_KEY);
      expect(json.urlEndpoint).toBeDefined();
      expect(typeof json.token).toBe("string");
      expect(typeof json.signature).toBe("string");
      expect(typeof json.expire).toBe("number");

      // Expiry <= 5 minutes from now
      const nowSec = Math.floor(Date.now() / 1000);
      expect(json.expire).toBeGreaterThan(nowSec);
      expect(json.expire).toBeLessThanOrEqual(nowSec + 300);

      // Never contains the private key
      const dumped = JSON.stringify(json);
      expect(dumped.includes(process.env.IMAGEKIT_PRIVATE_KEY)).toBe(false);
      expect(json.privateKey).toBeUndefined();
    });
  });

  describe("sendMessage: media type & blobId rules", () => {
    it("accepts type media with valid blobId", async () => {
      const validBlobId = randomBytes(16).toString("hex");
      const body = good({
        type: "media",
        blobId: validBlobId,
      });

      const { status, json } = await call(sendMessage, {
        user: sender,
        params: { id: String(receiver._id) },
        body,
      });

      expect(status).toBe(201);
      expect(json.type).toBe("media");
      expect(json.blobId).toBe(validBlobId);

      // Verify DB storage
      const saved = await Message.findById(json._id);
      expect(saved.type).toBe("media");
      expect(saved.blobId).toBe(validBlobId);
    });

    it("rejects media without blobId", async () => {
      const body = good({ type: "media" });
      const { status, json } = await call(sendMessage, {
        user: sender,
        params: { id: String(receiver._id) },
        body,
      });
      expect(status).toBe(400);
      expect(json.message).toBe("bad-blob-id");
    });

    it("rejects text with blobId", async () => {
      const body = good({
        type: "text",
        blobId: randomBytes(16).toString("hex"),
      });
      const { status, json } = await call(sendMessage, {
        user: sender,
        params: { id: String(receiver._id) },
        body,
      });
      expect(status).toBe(400);
      expect(json.message).toBe("blob-forbidden-on-text");
    });

    it("rejects bad blobId formats", async () => {
      for (const badId of ["short", "with spaces 12345", "special!@#$%^&*()_+", 1234567890123456]) {
        const body = good({ type: "media", blobId: badId });
        const { status } = await call(sendMessage, {
          user: sender,
          params: { id: String(receiver._id) },
          body,
        });
        expect(status).toBe(400);
      }
    });

    it("rejects plaintext fields and unknown fields on media messages", async () => {
      const validBlobId = randomBytes(16).toString("hex");

      const withText = good({ type: "media", blobId: validBlobId, text: "plaintext" });
      expect((await call(sendMessage, { user: sender, params: { id: String(receiver._id) }, body: withText })).status).toBe(400);

      const withImage = good({ type: "media", blobId: validBlobId, image: "http://example.com" });
      expect((await call(sendMessage, { user: sender, params: { id: String(receiver._id) }, body: withImage })).status).toBe(400);

      const withUnknown = good({ type: "media", blobId: validBlobId, extra: "foo" });
      expect((await call(sendMessage, { user: sender, params: { id: String(receiver._id) }, body: withUnknown })).status).toBe(400);
    });
  });

  describe("Message schema", () => {
    it("has blobId with sparse index", () => {
      const blobPath = Message.schema.paths.blobId;
      expect(blobPath).toBeDefined();
      expect(blobPath.instance).toBe("String");

      // Verify sparse index
      const indexes = Message.schema.indexes();
      const hasBlobIndex = indexes.some(
        ([idx, opts]) => idx.blobId === 1 && opts?.sparse === true
      );
      expect(hasBlobIndex).toBe(true);
    });
  });
});
