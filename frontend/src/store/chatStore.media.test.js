import "fake-indexeddb/auto";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { set } from "idb-keyval";
import nacl from "tweetnacl";

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
import { upgradeIdentity, ensureSpk, loadIdentity, getPlain, putPlain } from "../storage/keystore";
import { signIkBinding, toB64 } from "../crypto/index.js";
import { clearBundleCache, readMessage, snippetFor } from "../lib/chatCrypto.js";

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

describe("S7 Frontend: chatStore sendMedia & media pipeline", () => {
  let meId, peerId;

  beforeEach(async () => {
    vi.clearAllMocks();
    clearBundleCache?.();
    meId = await mkUser();
    peerId = await mkUser();
    currentAuthUserId = meId;

    useChatStore.getState().reset();
    useChatStore.setState({
      selectedUser: { _id: peerId, fullName: "Peer" },
      activeConversationId: peerId,
      messages: [],
    });

    ax.get.mockImplementation(async (url) => {
      const mb = url.match(/^\/keys\/bundle\/(.+)$/);
      if (mb) return { data: await bundleOf(mb[1]) };
      const mk = url.match(/^\/identity\/key\/(.+)$/);
      if (mk) return { data: await keysOf(mk[1]) };
      if (url === "/messages/conversations") return { data: [] };
      if (url === "/media/upload-auth") {
        return {
          data: {
            publicKey: "public_test",
            urlEndpoint: "https://ik.imagekit.io/answer",
            token: "tok",
            expire: 1800,
            signature: "sig",
          },
        };
      }
      throw new Error("unexpected GET: " + url);
    });

    ax.post.mockResolvedValue({
      data: {
        _id: uid(),
        createdAt: new Date().toISOString(),
      },
    });
  });

  it("chatCrypto: S5 plaintext records without att still read cleanly", async () => {
    const msgId = uid();
    await putPlain(meId, msgId, { t: "text", body: "legacy text", ts: 12345 });
    const cached = await getPlain(meId, msgId);
    expect(cached.body).toBe("legacy text");
    expect(cached.att).toBeUndefined();

    const snippet = await snippetFor(meId, { _id: msgId, type: "text" });
    expect(snippet).toBe("legacy text");
  });

  it("snippetFor: formats photo and video snippets with optional caption", async () => {
    const photoId = uid();
    await putPlain(meId, photoId, {
      t: "media",
      body: "sunset view",
      ts: 123,
      att: { kind: "image", mime: "image/jpeg" },
    });
    expect(await snippetFor(meId, { _id: photoId, type: "media" })).toBe("Photo: sunset view");

    const photoNoCaptionId = uid();
    await putPlain(meId, photoNoCaptionId, {
      t: "media",
      body: "",
      ts: 124,
      att: { kind: "image", mime: "image/jpeg" },
    });
    expect(await snippetFor(meId, { _id: photoNoCaptionId, type: "media" })).toBe("Photo");

    const videoId = uid();
    await putPlain(meId, videoId, {
      t: "media",
      body: "dog running",
      ts: 125,
      att: { kind: "video", mime: "video/mp4" },
    });
    expect(await snippetFor(meId, { _id: videoId, type: "media" })).toBe("Video: dog running");
  });

  it("sendMedia: state machine, body has exact wire keys, upload receives ciphertext only", async () => {
    let uploadPayload = null;
    globalThis.XMLHttpRequest = vi.fn().mockImplementation(() => {
      let progressCb;
      const xhr = {
        open: vi.fn(),
        upload: {
          set onprogress(cb) { progressCb = cb; },
        },
        send: vi.fn((formData) => {
          uploadPayload = formData;
          if (progressCb) progressCb({ lengthComputable: true, loaded: 100, total: 100 });
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

    const jpegBytes = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01]);
    const file = new File([jpegBytes], "photo.jpg", { type: "image/jpeg" });

    const sentPromise = useChatStore.getState().sendMedia({ file, caption: "nice pic" });
    await sentPromise;

    const msgs = useChatStore.getState().messages;
    expect(msgs.length).toBe(1);
    const m = msgs[0];
    expect(m.state).toBe("ok");
    expect(m.type).toBe("media");
    expect(m.text).toBe("nice pic");

    // Check POST body to /messages/send/:peerId
    const postCalls = ax.post.mock.calls.filter((c) => c[0].startsWith("/messages/send/"));
    expect(postCalls.length).toBe(1);
    const postBody = postCalls[0][1];

    // POST body has EXACTLY {cid, v, type, ciphertext, nonce, header, blobId}
    const expectedKeys = ["cid", "v", "type", "ciphertext", "nonce", "header", "blobId"].sort();
    expect(Object.keys(postBody).sort()).toEqual(expectedKeys);
    expect(postBody.type).toBe("media");
    expect(typeof postBody.blobId).toBe("string");

    // The upload to ImageKit received CIPHERTEXT, not the original JPEG bytes
    expect(uploadPayload).toBeDefined();
    const uploadedBlob = uploadPayload.get("file");
    const uploadedBytes = new Uint8Array(await uploadedBlob.arrayBuffer());
    // Ciphertext does NOT start with JPEG magic bytes FF D8 FF
    expect(uploadedBytes[0] === 0xff && uploadedBytes[1] === 0xd8 && uploadedBytes[2] === 0xff).toBe(false);
  });

  it("sendMedia: cancel aborts upload and cleans up local preview", async () => {
    let abortCalled = false;
    globalThis.XMLHttpRequest = vi.fn().mockImplementation(() => {
      const xhr = {
        open: vi.fn(),
        upload: {},
        send: vi.fn(),
        abort: vi.fn(() => { abortCalled = true; }),
      };
      return xhr;
    });

    const jpegBytes = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01]);
    const file = new File([jpegBytes], "photo.jpg", { type: "image/jpeg" });

    const sendPromise = useChatStore.getState().sendMedia({ file, caption: "" });
    // Immediately cancel
    const cid = useChatStore.getState().messages[0]?.cid;
    expect(cid).toBeDefined();

    useChatStore.getState().cancelMediaUpload(cid);
    await sendPromise.catch(() => {});

    expect(abortCalled).toBe(true);
    // Message is cancelled or removed
    const msg = useChatStore.getState().messages.find((x) => x.cid === cid);
    expect(!msg || msg.state === "cancelled").toBe(true);
  });

  it("sendMedia: retry skips re-upload if blob was already uploaded", async () => {
    let uploadCount = 0;
    globalThis.XMLHttpRequest = vi.fn().mockImplementation(() => {
      const xhr = {
        open: vi.fn(),
        upload: {},
        send: vi.fn(() => {
          uploadCount++;
          setTimeout(() => {
            xhr.status = 200;
            xhr.responseText = JSON.stringify({
              fileId: "fid_retry",
              url: "https://ik.imagekit.io/answer/chat/fileretry",
            });
            xhr.onload();
          }, 10);
        }),
        abort: vi.fn(),
      };
      return xhr;
    });

    // Make network POST fail the first time
    ax.post.mockRejectedValueOnce(new Error("Network error during send"));

    const jpegBytes = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01]);
    const file = new File([jpegBytes], "retry.jpg", { type: "image/jpeg" });

    await useChatStore.getState().sendMedia({ file });
    const m = useChatStore.getState().messages[0];
    expect(m.state).toBe("failed");
    expect(uploadCount).toBe(1);

    // Now retry!
    ax.post.mockResolvedValueOnce({
      data: { _id: uid(), createdAt: new Date().toISOString() },
    });

    await useChatStore.getState().retrySend(m.cid);

    // Upload count must STILL be 1 (skips re-upload!)
    expect(uploadCount).toBe(1);
    const mAfter = useChatStore.getState().messages[0];
    expect(mAfter.state).toBe("ok");
    expect(mAfter.cid).toBe(m.cid); // same cid
  });
});

