import "fake-indexeddb/auto";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { set } from "idb-keyval";
import nacl from "tweetnacl";
import { PEER_KEY_CHANGED } from "../crypto/errors.js";

const mockSocket = {
  handlers: {},
  on(event, handler) { this.handlers[event] = handler; },
  off(event) { delete this.handlers[event]; },
  emit(event, ...args) { this.handlers[event]?.(...args); },
};

let currentAuthUserId = null;

vi.mock("./useAuthStore", () => ({
  useAuthStore: {
    getState: vi.fn(() => ({
      authUser: currentAuthUserId ? { _id: currentAuthUserId } : null,
      socket: mockSocket,
    })),
    setState: vi.fn(),
    subscribe: vi.fn(),
  },
}));

vi.mock("../lib/axios", () => ({
  axiosInstance: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
  },
}));

import { axiosInstance as ax } from "../lib/axios";
import { useChatStore } from "./useChatStore";
import { upgradeIdentity, ensureSpk, loadIdentity, generateOpks, loadSession } from "../storage/keystore";
import { signIkBinding, toB64 } from "../crypto/index.js";
import { syncOpks } from "../lib/keyApi.js";
import { readMessage } from "../lib/chatCrypto.js";

let n = 0;
const uid = () => (++n).toString(16).padStart(24, "0");
const b64 = (u) => Buffer.from(u).toString("base64");

async function waitFor(fn, timeout = 2000, interval = 15) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      if (fn()) return;
    } catch {}
    await new Promise((r) => setTimeout(r, interval));
  }
  fn();
}

const userOpkMap = {};

async function mkUser() {
  const id = uid();
  const kp = nacl.box.keyPair();
  await set(`identity:${id}`, { publicKey: b64(kp.publicKey), secretKey: b64(kp.secretKey) });
  await upgradeIdentity(id);
  await ensureSpk(id);
  const opks = await generateOpks(id, 5);
  userOpkMap[id] = opks[0];
  return id;
}

describe("S8 Integration & Store Sessions", () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    useChatStore.getState().reset();
  });

  it("syncOpks: low OPK count (< 20) triggers replenishment of 50 new OPKs", async () => {
    const userId = await mkUser();

    // Server returns count = 15 (< 20)
    ax.get.mockImplementation(async (url) => {
      if (url === "/keys/opks/count") return { data: { count: 15 } };
      throw new Error("unexpected: " + url);
    });

    let uploadedKeys = null;
    ax.post.mockImplementation(async (url, body) => {
      if (url === "/keys/opks") {
        uploadedKeys = body.keys;
        return { data: { added: body.keys.length, count: 65 } };
      }
      throw new Error("unexpected: " + url);
    });

    const res = await syncOpks(userId);
    expect(res.added).toBe(50);
    expect(uploadedKeys).toHaveLength(50);
  });

  it("syncOpks: count >= 20 does not trigger replenishment", async () => {
    const userId = await mkUser();

    ax.get.mockImplementation(async (url) => {
      if (url === "/keys/opks/count") return { data: { count: 35 } };
      throw new Error("unexpected: " + url);
    });

    const res = await syncOpks(userId);
    expect(res.added).toBe(0);
    expect(ax.post).not.toHaveBeenCalled();
  });

  it("two accounts: send, receive, reply, reload, send again over v2 sessions", async () => {
    const userA = await mkUser();
    const userB = await mkUser();

    // Bundle provider helper
    const getBundleOf = async (id, withOpk = false) => {
      const idn = await loadIdentity(id);
      const spk = await ensureSpk(id);
      return {
        userId: id,
        ikPub: toB64(idn.ik.pub),
        sikPub: toB64(idn.sik.pub),
        ikBinding: toB64(signIkBinding(idn.sik.priv, idn.ik.pub)),
        spk: { id: spk.id, pub: toB64(spk.pub), sig: toB64(spk.sig) },
        opk: withOpk && userOpkMap[id] ? { id: userOpkMap[id].id, pub: toB64(userOpkMap[id].pub) } : null,
        protoMax: 2,
      };
    };

    const getKeysOf = async (id) => {
      const b = await getBundleOf(id);
      return { publicKey: b.ikPub, sik: b.sikPub, connectCode: "TALK-12345" };
    };

    ax.get.mockImplementation(async (url, cfg) => {
      const mb = url.match(/^\/keys\/bundle\/(.+)$/);
      if (mb) return { data: await getBundleOf(mb[1], !!cfg?.params?.opk) };
      const mk = url.match(/^\/identity\/key\/(.+)$/);
      if (mk) return { data: await getKeysOf(mk[1]) };
      if (url === "/messages/conversations") return { data: [] };
      throw new Error("unexpected: " + url);
    });

    // 1. User A sends initial message to User B
    currentAuthUserId = userA;
    useChatStore.setState({
      messages: [],
      conversations: [],
      selectedUser: { _id: userB, fullName: "Bob" },
      activeConversationId: userB,
    });

    let sentMsgAtoB = null;
    ax.post.mockImplementation(async (url, body) => {
      sentMsgAtoB = {
        _id: uid(),
        senderId: userA,
        receiverId: userB,
        createdAt: new Date().toISOString(),
        ...body,
      };
      return { data: sentMsgAtoB };
    });

    await useChatStore.getState().sendMessage("Hello Bob from Alice");
    expect(sentMsgAtoB).toBeDefined();
    expect(sentMsgAtoB.v).toBe(2);
    expect(sentMsgAtoB.header.n).toBe(0);
    expect(sentMsgAtoB.header.sessionId).toBeDefined();
    expect(sentMsgAtoB.header.ek).toBeDefined();

    // 2. User B receives initial message from User A
    currentAuthUserId = userB;
    useChatStore.setState({
      messages: [],
      conversations: [],
      selectedUser: { _id: userA, fullName: "Alice" },
      activeConversationId: userA,
    });
    useChatStore.getState().listenForMessages();

    mockSocket.emit("newMessage", sentMsgAtoB);
    await waitFor(() => useChatStore.getState().messages.length === 1);

    const bobMsgs = useChatStore.getState().messages;
    expect(bobMsgs.length).toBe(1);
    expect(bobMsgs[0].state).toBe("ok");
    expect(bobMsgs[0].text).toBe("Hello Bob from Alice");

    // 3. User B replies to User A using established session
    let replyBtoA = null;
    ax.post.mockImplementation(async (url, body) => {
      replyBtoA = {
        _id: uid(),
        senderId: userB,
        receiverId: userA,
        createdAt: new Date().toISOString(),
        ...body,
      };
      return { data: replyBtoA };
    });

    await useChatStore.getState().sendMessage("Hello Alice, received loud and clear!");
    expect(replyBtoA).toBeDefined();
    expect(replyBtoA.v).toBe(2);
    expect(replyBtoA.header.sessionId).toBe(sentMsgAtoB.header.sessionId);

    // 4. Simulate reload (reset chat store in-memory state, session persists in IndexedDB)
    useChatStore.getState().reset();
    currentAuthUserId = userA;
    useChatStore.setState({
      messages: [],
      conversations: [],
      selectedUser: { _id: userB, fullName: "Bob" },
      activeConversationId: userB,
    });
    useChatStore.getState().listenForMessages();

    // 5. User A receives User B's reply after reload
    mockSocket.emit("newMessage", replyBtoA);
    await new Promise((r) => setTimeout(r, 60));

    const aliceMsgs = useChatStore.getState().messages;
    expect(aliceMsgs.length).toBe(1);
    expect(aliceMsgs[0].state).toBe("ok");
    expect(aliceMsgs[0].text).toBe("Hello Alice, received loud and clear!");

    // 6. User A sends another message on the existing session
    let sent2 = null;
    ax.post.mockImplementation(async (url, body) => {
      sent2 = {
        _id: uid(),
        senderId: userA,
        receiverId: userB,
        createdAt: new Date().toISOString(),
        ...body,
      };
      return { data: sent2 };
    });

    await useChatStore.getState().sendMessage("Great, persistent session confirmed!");
    expect(sent2).toBeDefined();
    expect(sent2.v).toBe(2);
    expect(sent2.header.sessionId).toBe(sentMsgAtoB.header.sessionId);
    // msg2 header has no ek/spkId since session is established
    expect(sent2.header.ek).toBeUndefined();
    // Under Double Ratchet, receiving a reply triggers a DH step, so n resets to 0 and pn records previous chain length 1
    expect(sent2.header.n).toBe(0);
    expect(sent2.header.pn).toBe(1);
  });

  it("media messages work through v2 sessions with the per-file key inside encrypted payload", async () => {
    const userA = await mkUser();
    const userB = await mkUser();

    const getBundleOf = async (id, withOpk = false) => {
      const idn = await loadIdentity(id);
      const spk = await ensureSpk(id);
      return {
        userId: id,
        ikPub: toB64(idn.ik.pub),
        sikPub: toB64(idn.sik.pub),
        ikBinding: toB64(signIkBinding(idn.sik.priv, idn.ik.pub)),
        spk: { id: spk.id, pub: toB64(spk.pub), sig: toB64(spk.sig) },
        opk: withOpk && userOpkMap[id] ? { id: userOpkMap[id].id, pub: toB64(userOpkMap[id].pub) } : null,
        protoMax: 2,
      };
    };

    ax.get.mockImplementation(async (url, cfg) => {
      if (url === "/media/upload-auth") {
        return {
          data: {
            endpoint: "https://upload.imagekit.io/api/v1/files/upload",
            token: "tok",
            expire: 123456,
            signature: "sig",
            publicKey: "pub",
          },
        };
      }
      const mb = url.match(/^\/keys\/bundle\/(.+)$/);
      if (mb) return { data: await getBundleOf(mb[1], !!cfg?.params?.opk) };
      const mk = url.match(/^\/identity\/key\/(.+)$/);
      if (mk) return { data: { publicKey: (await getBundleOf(mk[1])).ikPub, sik: (await getBundleOf(mk[1])).sikPub } };
      if (url === "/messages/conversations") return { data: [] };
      throw new Error("unexpected: " + url);
    });

    globalThis.XMLHttpRequest = vi.fn().mockImplementation(() => {
      const xhr = {
        open: vi.fn(),
        upload: {},
        send: vi.fn(() => {
          setTimeout(() => {
            xhr.status = 200;
            xhr.responseText = JSON.stringify({
              fileId: "fid_123",
              url: "https://ik.imagekit.io/answer/chat/file123",
            });
            xhr.onload();
          }, 10);
        }),
        abort: vi.fn(),
      };
      return xhr;
    });

    currentAuthUserId = userA;
    useChatStore.setState({
      messages: [],
      conversations: [],
      selectedUser: { _id: userB, fullName: "Bob" },
      activeConversationId: userB,
    });

    let sentMedia = null;
    ax.post.mockImplementation(async (url, body) => {
      sentMedia = {
        _id: uid(),
        senderId: userA,
        receiverId: userB,
        createdAt: new Date().toISOString(),
        ...body,
      };
      return { data: sentMedia };
    });

    const jpegBytes = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01]);
    const file = new File([jpegBytes], "pic.jpg", { type: "image/jpeg" });

    await useChatStore.getState().sendMedia({ file, caption: "v2 session media" });

    expect(sentMedia).toBeDefined();
    expect(sentMedia.v).toBe(2);
    expect(sentMedia.type).toBe("media");
    expect(sentMedia.blobId).toBeDefined();
    expect(sentMedia.header.sessionId).toBeDefined();

    // User B receives media message
    currentAuthUserId = userB;
    useChatStore.setState({
      messages: [],
      conversations: [],
      selectedUser: { _id: userA, fullName: "Alice" },
      activeConversationId: userA,
    });
    useChatStore.getState().listenForMessages();

    mockSocket.emit("newMessage", sentMedia);
    await waitFor(() => useChatStore.getState().messages.length === 1);

    const bMsgs = useChatStore.getState().messages;
    expect(bMsgs.length).toBe(1);
    expect(bMsgs[0].state).toBe("ok");
    expect(bMsgs[0].type).toBe("media");
    expect(bMsgs[0].text).toBe("v2 session media");
    expect(bMsgs[0].att).toBeDefined();
    expect(bMsgs[0].att.kind).toBe("image");
  });

  it("peer key changed: sending is blocked, message fails with key-changed, and UI failure reason matches", async () => {
    const userA = await mkUser();
    const userB = await mkUser();

    const getBundleOf = async (id, withOpk = false) => {
      const idn = await loadIdentity(id);
      const spk = await ensureSpk(id);
      return {
        userId: id,
        ikPub: toB64(idn.ik.pub),
        sikPub: toB64(idn.sik.pub),
        ikBinding: toB64(signIkBinding(idn.sik.priv, idn.ik.pub)),
        spk: { id: spk.id, pub: toB64(spk.pub), sig: toB64(spk.sig) },
        opk: withOpk && userOpkMap[id] ? { id: userOpkMap[id].id, pub: toB64(userOpkMap[id].pub) } : null,
        protoMax: 2,
      };
    };

    const getKeysOf = async (id) => {
      const b = await getBundleOf(id);
      return { publicKey: b.ikPub, sik: b.sikPub, connectCode: "TALK-12345" };
    };

    ax.get.mockImplementation(async (url, cfg) => {
      const mb = url.match(/^\/keys\/bundle\/(.+)$/);
      if (mb) return { data: await getBundleOf(mb[1], !!cfg?.params?.opk) };
      const mk = url.match(/^\/identity\/key\/(.+)$/);
      if (mk) return { data: await getKeysOf(mk[1]) };
      if (url === "/messages/conversations") return { data: [] };
      throw new Error("unexpected: " + url);
    });

    ax.post.mockImplementation(async (url, body) => ({
      data: {
        _id: uid(),
        senderId: userA,
        receiverId: userB,
        createdAt: new Date().toISOString(),
        ...body,
      },
    }));

    currentAuthUserId = userA;
    useChatStore.setState({
      messages: [],
      conversations: [],
      selectedUser: { _id: userB, fullName: "Bob" },
      activeConversationId: userB,
    });

    // Send first message: successfully creates session and pins B
    await useChatStore.getState().sendMessage("First message");
    expect(useChatStore.getState().messages[0].state).toBe("ok");

    // Simulate peer B key changing by modifying pinned identity
    const { set: idbSet } = await import("idb-keyval");
    await idbSet(`contact:${userA}:${userB}`, {
      ik: b64(nacl.randomBytes(32)),
      sik: b64(nacl.randomBytes(32)),
      verified: false,
    });

    // Send second message: should be blocked with key-changed
    await useChatStore.getState().sendMessage("Blocked message");
    const msgs = useChatStore.getState().messages;
    expect(msgs.length).toBe(2);
    expect(msgs[1].state).toBe("failed");
    expect(msgs[1].failReason).toBe(PEER_KEY_CHANGED);
  });

  it("R1.4: fail, then retry: advances ns exactly once, reuses wire payload, and receiver decrypts with zero skipped keys", async () => {
    const userA = await mkUser();
    const userB = await mkUser();

    const getBundleOf = async (id, withOpk = false) => {
      const idn = await loadIdentity(id);
      const spk = await ensureSpk(id);
      return {
        userId: id,
        ikPub: toB64(idn.ik.pub),
        sikPub: toB64(idn.sik.pub),
        ikBinding: toB64(signIkBinding(idn.sik.priv, idn.ik.pub)),
        spk: { id: spk.id, pub: toB64(spk.pub), sig: toB64(spk.sig) },
        opk: withOpk && userOpkMap[id] ? { id: userOpkMap[id].id, pub: toB64(userOpkMap[id].pub) } : null,
        protoMax: 2,
      };
    };

    ax.get.mockImplementation(async (url, cfg) => {
      const mb = url.match(/^\/keys\/bundle\/(.+)$/);
      if (mb) return { data: await getBundleOf(mb[1], !!cfg?.params?.opk) };
      const mk = url.match(/^\/identity\/key\/(.+)$/);
      if (mk) return { data: { publicKey: (await getBundleOf(mk[1])).ikPub, sik: (await getBundleOf(mk[1])).sikPub } };
      if (url === "/messages/conversations") return { data: [] };
      throw new Error("unexpected: " + url);
    });

    currentAuthUserId = userA;
    useChatStore.setState({
      messages: [],
      conversations: [],
      selectedUser: { _id: userB, fullName: "Bob" },
      activeConversationId: userB,
    });

    const postedBodies = [];
    let shouldFail = true;
    ax.post.mockImplementation(async (url, body) => {
      if (url.startsWith("/messages/send/")) {
        postedBodies.push(JSON.parse(JSON.stringify(body)));
        if (shouldFail) {
          throw new Error("Network error");
        }
        return {
          data: {
            _id: uid(),
            senderId: userA,
            receiverId: userB,
            createdAt: new Date().toISOString(),
            ...body,
          },
        };
      }
      throw new Error("unexpected: " + url);
    });

    // 1. Initial send fails on network
    await useChatStore.getState().sendMessage("hello retry");
    const msgs = useChatStore.getState().messages;
    expect(msgs).toHaveLength(1);
    expect(msgs[0].state).toBe("failed");
    expect(postedBodies).toHaveLength(1);

    const firstBody = postedBodies[0];
    const sessionAfterFail = await loadSession(userA, userB);
    const nsAfterFail = sessionAfterFail.ns;

    // 2. Retry send succeeds
    shouldFail = false;
    await useChatStore.getState().retrySend(msgs[0].cid);
    expect(useChatStore.getState().messages[0].state).toBe("ok");
    expect(postedBodies).toHaveLength(2);

    const secondBody = postedBodies[1];
    // Wire payload must be reused
    expect(secondBody.ciphertext).toBe(firstBody.ciphertext);
    expect(secondBody.nonce).toBe(firstBody.nonce);
    expect(secondBody.header.n).toBe(firstBody.header.n);

    // ns advanced exactly once, not twice
    const sessionAfterRetry = await loadSession(userA, userB);
    expect(sessionAfterRetry.ns).toBe(nsAfterFail);

    // 3. Receiver decrypts with zero skipped keys
    const serverMsg = {
      _id: uid(),
      senderId: userA,
      receiverId: userB,
      ...postedBodies[1],
    };
    const readResult = await readMessage({ me: userB, msg: serverMsg });
    expect(readResult.state).toBe("ok");
    expect(readResult.text).toBe("hello retry");
    const bSession = await loadSession(userB, userA);
    expect(Object.keys(bSession.skippedKeys)).toHaveLength(0);
  });

  it("R1.4: if session was reset between failure and retry, discards payload and sends as new message", async () => {
    const userA = await mkUser();
    const userB = await mkUser();

    const getBundleOf = async (id, withOpk = false) => {
      const idn = await loadIdentity(id);
      const spk = await ensureSpk(id);
      return {
        userId: id,
        ikPub: toB64(idn.ik.pub),
        sikPub: toB64(idn.sik.pub),
        ikBinding: toB64(signIkBinding(idn.sik.priv, idn.ik.pub)),
        spk: { id: spk.id, pub: toB64(spk.pub), sig: toB64(spk.sig) },
        opk: withOpk && userOpkMap[id] ? { id: userOpkMap[id].id, pub: toB64(userOpkMap[id].pub) } : null,
        protoMax: 2,
      };
    };

    ax.get.mockImplementation(async (url, cfg) => {
      const mb = url.match(/^\/keys\/bundle\/(.+)$/);
      if (mb) return { data: await getBundleOf(mb[1], !!cfg?.params?.opk) };
      const mk = url.match(/^\/identity\/key\/(.+)$/);
      if (mk) return { data: { publicKey: (await getBundleOf(mk[1])).ikPub, sik: (await getBundleOf(mk[1])).sikPub } };
      if (url === "/messages/conversations") return { data: [] };
      throw new Error("unexpected: " + url);
    });

    currentAuthUserId = userA;
    useChatStore.setState({
      messages: [],
      conversations: [],
      selectedUser: { _id: userB, fullName: "Bob" },
      activeConversationId: userB,
    });

    const postedBodies = [];
    let shouldFail = true;
    ax.post.mockImplementation(async (url, body) => {
      if (url.startsWith("/messages/send/")) {
        postedBodies.push(JSON.parse(JSON.stringify(body)));
        if (shouldFail) {
          throw new Error("Network error");
        }
        return {
          data: {
            _id: uid(),
            senderId: userA,
            receiverId: userB,
            createdAt: new Date().toISOString(),
            ...body,
          },
        };
      }
      throw new Error("unexpected: " + url);
    });

    // 1. Initial send fails on network
    await useChatStore.getState().sendMessage("hello reset retry");
    const msgs = useChatStore.getState().messages;
    expect(msgs).toHaveLength(1);
    expect(msgs[0].state).toBe("failed");
    expect(postedBodies).toHaveLength(1);

    const firstBody = postedBodies[0];

    // 2. Session is reset
    await useChatStore.getState().resetSession(userB);

    // 3. Retry send succeeds
    shouldFail = false;
    await useChatStore.getState().retrySend(msgs[0].cid);
    expect(useChatStore.getState().messages[0].state).toBe("ok");
    expect(postedBodies).toHaveLength(2);

    const secondBody = postedBodies[1];
    // Since session was reset, payload was discarded and re-encrypted with new session
    expect(secondBody.header.sessionId).not.toBe(firstBody.header.sessionId);
    expect(secondBody.ciphertext).not.toBe(firstBody.ciphertext);
  });
});


