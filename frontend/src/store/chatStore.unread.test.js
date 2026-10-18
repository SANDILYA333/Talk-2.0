import "fake-indexeddb/auto";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import { set } from "idb-keyval";
import nacl from "tweetnacl";

const mockSocket = {
  handlers: {},
  on(event, handler) {
    this.handlers[event] = handler;
  },
  off(event) {
    delete this.handlers[event];
  },
  emit(event, ...args) {
    this.handlers[event]?.(...args);
  },
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
import { upgradeIdentity, ensureSpk, loadIdentity } from "../storage/keystore";
import { signIkBinding, toB64 } from "../crypto/index.js";
import { encryptText, clearBundleCache } from "../lib/chatCrypto.js";

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

async function bundleOf(id) {
  const idn = await loadIdentity(id);
  const spk = await ensureSpk(id);
  return {
    userId: id,
    ikPub: toB64(idn.ik.pub),
    sikPub: toB64(idn.sik.pub),
    ikBinding: toB64(signIkBinding(idn.sik.priv, idn.ik.pub)),
    spk: { id: spk.id, pub: toB64(spk.pub), sig: toB64(spk.sig) },
    opk: null,
    protoMax: 1,
  };
}

const keysOf = async (id) => {
  const b = await bundleOf(id);
  return { publicKey: b.ikPub, sik: b.sikPub, connectCode: "TALK-XXXXX-XXXXX" };
};

describe("useChatStore unread counts & chat list (S6)", () => {
  let meId, peer1Id, peer2Id;

  beforeEach(async () => {
    vi.clearAllMocks();
    clearBundleCache?.();
    meId = await mkUser();
    peer1Id = await mkUser();
    peer2Id = await mkUser();
    currentAuthUserId = meId;

    if (typeof globalThis.document === "undefined") {
      const listeners = {};
      globalThis.document = {
        visibilityState: "visible",
        addEventListener: (e, fn) => { (listeners[e] ||= []).push(fn); },
        removeEventListener: (e, fn) => { listeners[e] = (listeners[e] || []).filter((f) => f !== fn); },
        dispatchEvent: (ev) => { (listeners[ev.type] || []).forEach((fn) => fn(ev)); return true; },
      };
      globalThis.window = {
        addEventListener: (e, fn) => { (listeners[e] ||= []).push(fn); },
        removeEventListener: (e, fn) => { listeners[e] = (listeners[e] || []).filter((f) => f !== fn); },
        dispatchEvent: (ev) => {
          (listeners[ev.type] || []).forEach((fn) => fn(ev));
          if (globalThis.document.onvisibilitychange) globalThis.document.onvisibilitychange(ev);
          return true;
        },
      };
      globalThis.Event = class Event {
        constructor(type) { this.type = type; }
      };
    }

    // Default document visibility to visible
    globalThis.document.visibilityState = "visible";

    useChatStore.setState({
      messages: [],
      conversations: [
        {
          _id: peer1Id,
          fullName: "Peer 1",
          unreadCount: 0,
          snippet: "Old 1",
          lastMessage: { _id: "m0", createdAt: "2026-10-18T10:00:00.000Z" },
        },
        {
          _id: peer2Id,
          fullName: "Peer 2",
          unreadCount: 0,
          snippet: "Old 2",
          lastMessage: { _id: "m02", createdAt: "2026-10-18T09:00:00.000Z" },
        },
      ],
      users: [],
      selectedUser: { _id: peer1Id, fullName: "Peer 1" },
      activeConversationId: peer1Id,
    });

    ax.get.mockImplementation(async (url) => {
      const mb = url.match(/^\/keys\/bundle\/(.+)$/);
      if (mb) return { data: await bundleOf(mb[1]) };
      const mk = url.match(/^\/identity\/key\/(.+)$/);
      if (mk) return { data: await keysOf(mk[1]) };
      if (url === "/messages/conversations") {
        return {
          data: [
            {
              _id: peer1Id,
              fullName: "Peer 1",
              unreadCount: 0,
              lastMessage: { _id: "m0", createdAt: "2026-10-18T10:00:00.000Z", type: "text" },
            },
          ],
        };
      }
      throw new Error("unexpected GET: " + url);
    });

    ax.post.mockResolvedValue({ data: { ok: true } });

    useChatStore.getState().listenForMessages();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("incoming message in a non-active chat: unread+1, snippet from cache, conversation moves to top, no message appended to open chat", async () => {
    const { payload } = await encryptText({ me: peer2Id, peerId: meId, text: "hey peer2" });
    const wireMsg = {
      _id: uid(),
      senderId: peer2Id,
      receiverId: meId,
      cid: `c-${uid()}`,
      createdAt: "2026-10-18T12:00:00.000Z",
      ...payload,
    };

    mockSocket.emit("newMessage", wireMsg);
    await new Promise((r) => setTimeout(r, 60));

    // Active chat is peer1, so messages must still be empty for peer1
    expect(useChatStore.getState().messages.length).toBe(0);

    const convs = useChatStore.getState().conversations;
    // Peer 2 moved to top!
    expect(convs[0]._id).toBe(peer2Id);
    expect(convs[0].unreadCount).toBe(1);
    expect(convs[0].snippet).toBe("hey peer2");
  });

  it("incoming message in the active visible chat: marked read, unread stays 0", async () => {
    const { payload } = await encryptText({ me: peer1Id, peerId: meId, text: "visible msg" });
    const msgId = uid();
    const wireMsg = {
      _id: msgId,
      senderId: peer1Id,
      receiverId: meId,
      cid: `c-${uid()}`,
      createdAt: "2026-10-18T12:00:00.000Z",
      ...payload,
    };

    mockSocket.emit("newMessage", wireMsg);
    await new Promise((r) => setTimeout(r, 60));

    // Decrypted in active chat
    expect(useChatStore.getState().messages.length).toBe(1);
    const conv1 = useChatStore.getState().conversations.find((c) => c._id === peer1Id);
    expect(conv1.unreadCount).toBe(0);

    // Debounced markRead was called for peer1Id with msgId
    await new Promise((r) => setTimeout(r, 350));
    const readCalls = ax.post.mock.calls.filter((c) => c[0] === `/messages/read/${peer1Id}`);
    expect(readCalls.length).toBeGreaterThanOrEqual(1);
    expect(readCalls[0][1]).toEqual({ upTo: msgId });
  });

  it("active chat but document hidden: not marked read, unread counts up; becoming visible marks it read", async () => {
    globalThis.document.visibilityState = "hidden";

    const { payload } = await encryptText({ me: peer1Id, peerId: meId, text: "hidden msg" });
    const msgId = uid();
    const wireMsg = {
      _id: msgId,
      senderId: peer1Id,
      receiverId: meId,
      cid: `c-${uid()}`,
      createdAt: "2026-10-18T12:00:00.000Z",
      ...payload,
    };

    mockSocket.emit("newMessage", wireMsg);
    await new Promise((r) => setTimeout(r, 60));

    // Message is decrypted in chat
    expect(useChatStore.getState().messages.length).toBe(1);
    // But since tab is hidden, unread count increases!
    let conv1 = useChatStore.getState().conversations.find((c) => c._id === peer1Id);
    expect(conv1.unreadCount).toBe(1);

    // markRead not called while hidden
    expect(ax.post.mock.calls.some((c) => c[0] === `/messages/read/${peer1Id}`)).toBe(false);

    // Becoming visible triggers markRead
    globalThis.document.visibilityState = "visible";
    globalThis.window.dispatchEvent(new Event("visibilitychange"));
    globalThis.document.dispatchEvent(new Event("visibilitychange"));

    await new Promise((r) => setTimeout(r, 350));
    const readCalls = ax.post.mock.calls.filter((c) => c[0] === `/messages/read/${peer1Id}`);
    expect(readCalls.length).toBeGreaterThanOrEqual(1);
    expect(readCalls[0][1]).toEqual({ upTo: msgId });

    conv1 = useChatStore.getState().conversations.find((c) => c._id === peer1Id);
    expect(conv1.unreadCount).toBe(0);
  });

  it("rapid events coalesce into a single refetch; a stale response never overwrites a newer one", async () => {
    vi.useFakeTimers();

    let callCount = 0;
    let resolveFirst;
    const firstPromise = new Promise((resolve) => {
      resolveFirst = resolve;
    });

    ax.get.mockImplementation(async (url) => {
      if (url === "/messages/conversations") {
        callCount++;
        if (callCount === 1) {
          // Slow first response
          return firstPromise;
        }
        return {
          data: [
            {
              _id: peer1Id,
              fullName: "Peer 1 Newer",
              unreadCount: 0,
              lastMessage: { _id: "m_new", createdAt: "2026-10-18T13:00:00.000Z" },
            },
          ],
        };
      }
      return { data: {} };
    });

    // Fire 3 rapid refetches
    useChatStore.getState().getConversations();
    useChatStore.getState().getConversations();
    useChatStore.getState().getConversations();

    // Advance debounce
    await vi.advanceTimersByTimeAsync(350);

    // Should only have initiated 1 network call due to debounce
    expect(callCount).toBe(1);

    // Fire another one later
    useChatStore.getState().getConversations();
    await vi.advanceTimersByTimeAsync(350);
    expect(callCount).toBe(2);

    // Now resolve the first (stale) one
    resolveFirst({
      data: [
        {
          _id: peer1Id,
          fullName: "Peer 1 STALE",
          unreadCount: 99,
          lastMessage: { _id: "m_stale", createdAt: "2026-10-18T05:00:00.000Z" },
        },
      ],
    });

    await vi.runAllTimersAsync();

    // Stale response must NOT overwrite newer one
    const conv = useChatStore.getState().conversations.find((c) => c._id === peer1Id);
    expect(conv.fullName).toBe("Peer 1 Newer");
    expect(conv.unreadCount).not.toBe(99);
  });

  it("markRead is debounced and never sends a lower marker than already sent", async () => {
    vi.useFakeTimers();

    const m1 = "000000000000000000000001";
    const m2 = "000000000000000000000002";

    useChatStore.getState().markRead(peer1Id, m2);
    useChatStore.getState().markRead(peer1Id, m1); // lower marker!

    await vi.advanceTimersByTimeAsync(350);

    const calls = ax.post.mock.calls.filter((c) => c[0] === `/messages/read/${peer1Id}`);
    expect(calls.length).toBe(1);
    expect(calls[0][1]).toEqual({ upTo: m2 });

    // Calling again with lower marker m1 does not make any POST
    useChatStore.getState().markRead(peer1Id, m1);
    await vi.advanceTimersByTimeAsync(350);
    expect(ax.post.mock.calls.filter((c) => c[0] === `/messages/read/${peer1Id}`).length).toBe(1);
  });

  it("logout resets conversations, messages, unread, and selection completely", () => {
    useChatStore.setState({
      messages: [{ _id: "1", text: "secret" }],
      conversations: [{ _id: peer1Id, unreadCount: 5 }],
      selectedUser: { _id: peer1Id },
      activeConversationId: peer1Id,
    });

    useChatStore.getState().reset();

    const s = useChatStore.getState();
    expect(s.messages).toEqual([]);
    expect(s.conversations).toEqual([]);
    expect(s.selectedUser).toBeNull();
    expect(s.activeConversationId).toBeNull();
  });
});
