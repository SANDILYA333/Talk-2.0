import "fake-indexeddb/auto";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { set } from "idb-keyval";
import nacl from "tweetnacl";
import { PEER_NO_KEYS, PEER_KEY_CHANGED } from "../crypto/errors.js";

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
import { upgradeIdentity, ensureSpk, loadIdentity, getPlain, wipeKeyMaterial } from "../storage/keystore";
import { signIkBinding, toB64 } from "../crypto/index.js";
import { acceptKeyChange } from "../lib/safety.js";
import { encryptText, clearBundleCache } from "../lib/chatCrypto.js";

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

async function mkUser() {
  const id = uid();
  const kp = nacl.box.keyPair();
  await set(`identity:${id}`, { publicKey: b64(kp.publicKey), secretKey: b64(kp.secretKey) });
  await upgradeIdentity(id);
  await ensureSpk(id);
  return id;
}

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

describe("useChatStore E2EE", () => {
  let meId, peerId;

  beforeEach(async () => {
    vi.clearAllMocks();
    clearBundleCache?.();
    meId = await mkUser();
    peerId = await mkUser();
    currentAuthUserId = meId;

    useChatStore.setState({
      messages: [],
      conversations: [],
      users: [],
      selectedUser: { _id: peerId, fullName: "Peer" },
      activeConversationId: peerId,
    });

    ax.get.mockImplementation(async (url) => {
      const mb = url.match(/^\/keys\/bundle\/(.+)$/);
      if (mb) return { data: await bundleOf(mb[1]) };
      const mk = url.match(/^\/identity\/key\/(.+)$/);
      if (mk) return { data: await keysOf(mk[1]) };
      if (url === "/messages/conversations") return { data: [] };
      throw new Error("unexpected GET: " + url);
    });

    useChatStore.getState().listenForMessages();
  });

  it("sendMessage: item goes pending -> ok, _id from server response, putPlain called, JSON.stringify(post body) does NOT contain the plaintext, body has exactly {cid,v,type,ciphertext,nonce,header}", async () => {
    let capturedBody;
    const srvMsgId = uid();
    ax.post.mockImplementation(async (url, body) => {
      capturedBody = body;
      return {
        data: {
          _id: srvMsgId,
          senderId: meId,
          receiverId: peerId,
          createdAt: new Date().toISOString(),
          ...body,
        },
      };
    });

    await useChatStore.getState().sendMessage("super secret message");

    expect(capturedBody).toBeDefined();
    expect(JSON.stringify(capturedBody)).not.toContain("super secret message");
    expect(Object.keys(capturedBody).sort()).toEqual(["cid", "ciphertext", "header", "nonce", "type", "v"]);
    expect(capturedBody.v).toBe(2);
    expect(capturedBody.type).toBe("text");

    const state = useChatStore.getState();
    const item = state.messages.find((m) => m._id === srvMsgId);
    expect(item).toBeDefined();
    expect(item.state).toBe("ok");
    expect(item.text).toBe("super secret message");

    const cached = await getPlain(meId, srvMsgId);
    expect(cached).toMatchObject({ body: "super secret message" });
  });

  it("network failure: item state 'failed'; retrySend reuses the SAME cid and ends 'ok'", async () => {
    ax.post.mockRejectedValueOnce(new Error("Network Error"));
    await useChatStore.getState().sendMessage("retry message");

    const failedItem = useChatStore.getState().messages[0];
    expect(failedItem.state).toBe("failed");
    expect(failedItem.failReason).toBe("Network Error");
    const originalCid = failedItem.cid;

    const srvId = uid();
    ax.post.mockImplementationOnce(async (url, body) => ({
      data: {
        _id: srvId,
        senderId: meId,
        receiverId: peerId,
        createdAt: new Date().toISOString(),
        ...body,
      },
    }));

    await useChatStore.getState().retrySend(originalCid);

    const postCall = ax.post.mock.calls[1];
    expect(postCall[1].cid).toBe(originalCid);

    const successItem = useChatStore.getState().messages.find((m) => m.cid === originalCid);
    expect(successItem.state).toBe("ok");
    expect(successItem._id).toBe(srvId);
  });

  it("recipient-no-keys (404 on bundle): item 'failed' with failReason 'recipient-no-keys', no POST made", async () => {
    ax.get.mockImplementation(async (url) => {
      if (url.startsWith("/keys/bundle/")) throw httpErr(404, "recipient-no-keys");
      return { data: {} };
    });

    await useChatStore.getState().sendMessage("cannot send");

    expect(ax.post).not.toHaveBeenCalled();
    const item = useChatStore.getState().messages[0];
    expect(item.state).toBe("failed");
    expect(item.failReason).toBe(PEER_NO_KEYS);
  });

  it("newMessage socket event: decrypted into messages when it is the active chat; the same _id delivered twice appears once", async () => {
    const { payload } = await encryptText({ me: peerId, peerId: meId, text: "incoming socket message" });
    const msgId = uid();
    const wireMsg = {
      _id: msgId,
      senderId: peerId,
      receiverId: meId,
      cid: `c-${uid()}`,
      createdAt: new Date().toISOString(),
      ...payload,
    };

    mockSocket.emit("newMessage", wireMsg);
    await waitFor(() => useChatStore.getState().messages.length === 1);

    expect(useChatStore.getState().messages.length).toBe(1);
    expect(useChatStore.getState().messages[0]).toMatchObject({
      _id: msgId,
      state: "ok",
      text: "incoming socket message",
    });

    mockSocket.emit("newMessage", wireMsg);
    await new Promise((r) => setTimeout(r, 50));

    expect(useChatStore.getState().messages.length).toBe(1);
  });

  it("newMessage for a non-active chat does not add to messages but refreshes conversations", async () => {
    const otherId = await mkUser();
    const { payload } = await encryptText({ me: otherId, peerId: meId, text: "other chat msg" });
    const wireMsg = {
      _id: uid(),
      senderId: otherId,
      receiverId: meId,
      cid: `c-${uid()}`,
      createdAt: new Date().toISOString(),
      ...payload,
    };

    mockSocket.emit("newMessage", wireMsg);
    await waitFor(() => ax.get.mock.calls.some((c) => c[0] === "/messages/conversations"));

    expect(useChatStore.getState().messages.length).toBe(0);
    expect(ax.get.mock.calls.some((c) => c[0] === "/messages/conversations")).toBe(true);
  });

  it("getMessages hydrates every item (state set, no raw ciphertext left on ok items)", async () => {
    const { payload: p1 } = await encryptText({ me: peerId, peerId: meId, text: "msg 1" });
    const { payload: p2 } = await encryptText({ me: peerId, peerId: meId, text: "msg 2" });
    const wireDocs = [
      { _id: uid(), senderId: peerId, receiverId: meId, cid: `c-${uid()}`, createdAt: new Date().toISOString(), ...p1 },
      { _id: uid(), senderId: peerId, receiverId: meId, cid: `c-${uid()}`, createdAt: new Date().toISOString(), ...p2 },
    ];

    ax.get.mockImplementation(async (url) => {
      const mb = url.match(/^\/keys\/bundle\/(.+)$/);
      if (mb) return { data: await bundleOf(mb[1]) };
      const mk = url.match(/^\/identity\/key\/(.+)$/);
      if (mk) return { data: await keysOf(mk[1]) };
      if (url.startsWith("/messages/")) return { data: { messages: wireDocs, hasMore: false } };
      throw new Error("unexpected: " + url);
    });

    await useChatStore.getState().getMessages(peerId);

    const msgs = useChatStore.getState().messages;
    expect(msgs.length).toBe(2);
    for (const m of msgs) {
      expect(m.state).toBe("ok");
      expect(m.raw).toBeUndefined();
      expect(m.ciphertext).toBeUndefined();
      expect(typeof m.text).toBe("string");
    }
    expect(msgs[0].text).toBe("msg 1");
    expect(msgs[1].text).toBe("msg 2");
  });

  it("reprocess(): a 'key-changed' item becomes 'ok' after acceptKeyChange", async () => {
    const { payload: p1 } = await encryptText({ me: peerId, peerId: meId, text: "first from peer" });
    const m1 = { _id: uid(), senderId: peerId, receiverId: meId, cid: `c-${uid()}`, createdAt: new Date().toISOString(), ...p1 };
    ax.get.mockImplementation(async (url) => {
      const mb = url.match(/^\/keys\/bundle\/(.+)$/);
      if (mb) return { data: await bundleOf(mb[1]) };
      const mk = url.match(/^\/identity\/key\/(.+)$/);
      if (mk) return { data: await keysOf(mk[1]) };
      if (url.startsWith("/messages/")) return { data: { messages: [m1], hasMore: false } };
      throw new Error("unexpected: " + url);
    });

    await useChatStore.getState().getMessages(peerId);
    expect(useChatStore.getState().messages[0].state).toBe("ok");

    await resetUser(peerId);
    clearBundleCache();

    const { payload: p2 } = await encryptText({ me: peerId, peerId: meId, text: "second from reset peer" });
    const m2 = { _id: uid(), senderId: peerId, receiverId: meId, cid: `c-${uid()}`, createdAt: new Date().toISOString(), ...p2 };

    mockSocket.emit("newMessage", m2);
    await new Promise((r) => setTimeout(r, 50));

    const item2 = useChatStore.getState().messages.find((m) => m._id === m2._id);
    expect(item2).toBeDefined();
    expect(item2.state).toBe(PEER_KEY_CHANGED);
    expect(item2.raw).toBeDefined();

    const cur = await keysOf(peerId);
    await acceptKeyChange(meId, peerId, { ik: cur.publicKey, sik: cur.sik });

    await useChatStore.getState().reprocess();

    const item2After = useChatStore.getState().messages.find((m) => m._id === m2._id);
    expect(item2After.state).toBe("ok");
    expect(item2After.text).toBe("second from reset peer");
  });
});
