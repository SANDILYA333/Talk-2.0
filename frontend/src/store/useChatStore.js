import { create } from "zustand";
import { persist } from "zustand/middleware";

import { axiosInstance } from "../lib/axios";
import { useAuthStore } from "./useAuthStore";
import toast from "react-hot-toast";
import { encryptText, encryptMedia, toItem, snippetFor } from "../lib/chatCrypto";
import { processMediaFile } from "../lib/mediaIntake";
import { encryptBlob } from "../lib/mediaCrypto";
import { blobStore } from "../lib/blobStore";
import { putPlain } from "../storage/keystore";
import { sortConversations } from "../lib/conversationView";

import {
  ERROR_CODES,
  normalizeErrorCode,
  PEER_KEY_CHANGED,
  DECRYPT_FAILED,
  SESSION_SETUP_FAILED,
  PEER_NO_KEYS,
  DUPLICATE_MESSAGE,
  HISTORY_UNAVAILABLE,
  LOCAL_KEYS_MISSING,
  MEDIA_DECRYPT_FAILED,
  SESSION_RESET_REQUIRED,
  TOO_MANY_SKIPPED,
  UNSUPPORTED_VERSION,
} from "../crypto/errors.js";
import {
  deleteSession,
  loadSession,
  loadIdentity,
  saveLocalSystemMessage,
  getLocalSystemMessages,
} from "../storage/keystore";
import { acceptKeyChange } from "../lib/safety";
import { resetIdentity } from "../lib/identity";

const meId = () => useAuthStore.getState().authUser?._id;
const RETRYABLE = new Set([PEER_KEY_CHANGED, DECRYPT_FAILED, SESSION_SETUP_FAILED, "waiting-for-key", "key-changed", "undecryptable", "tampered"]);
const mediaUploadContexts = new Map(); // cid -> { file, caption, previewUrl, abortController, processed, key, nonce, ciphertext, blobId, uploadedUrl, att }
const errorToastTimes = new Map(); // convId -> timestamp

const DEBOUNCE_DELAY = typeof process !== "undefined" && process.env.NODE_ENV === "test" ? 30 : 300;

let getConversationsSeq = 0;
let latestHandledSeq = 0;
let getConversationsTimer = null;
let pendingResolvers = [];
const lastMarkedRead = new Map(); // peerId -> lastReadMessageId string
const pendingReadMarkers = new Map(); // peerId -> { timer, targetId }

const updateTitle = (conversations = []) => {
  if (typeof document === "undefined") return;
  const total = conversations.reduce((acc, c) => acc + (c.unreadCount || 0), 0);
  document.title = total > 0 ? `(${total}) TALK` : "TALK";
};

export const initVisibilityListeners = () => {
  if (typeof window === "undefined" || window.__talk_s6_listeners) return;
  window.__talk_s6_listeners = true;
  const onVisible = () => {
    if (typeof document !== "undefined" && document.visibilityState !== "visible") return;
    const { selectedUser } = useChatStore.getState();
    if (selectedUser?._id) {
      useChatStore.getState().markRead(selectedUser._id);
    }
  };
  if (typeof document !== "undefined") {
    document.addEventListener("visibilitychange", onVisible);
  }
  window.addEventListener("visibilitychange", onVisible);
  window.addEventListener("focus", onVisible);
};

initVisibilityListeners();

export const useChatStore = create(
  persist(
    (set, get) => ({
      users: [],
      conversations: [],
      messages: [],
      selectedUser: null,
      isConversationsLoading: false,
      isUsersLoading: false,
      isMessagesLoading: false,
      hasMore: false,
      isLoadingOlder: false,
      activeConversationId: null,
      searchQuery: "",
      sidebarTab: "chats",
      composerText: "",
      isSoundEnabled: true,
      isSendingMedia: false,
      composerDisabledReason: null,
      isSettingUpSession: false,
      peerKeyChangedState: null,
      localKeysMissing: false,
      storageHealth: {
        persistent: false,
        persistDenied: false,
        storageAvailable: true,
        isPrivate: false,
        noteDismissed: false,
      },

      reset: () => {
        if (getConversationsTimer) {
          clearTimeout(getConversationsTimer);
          getConversationsTimer = null;
        }
        pendingResolvers = [];
        getConversationsSeq = 0;
        latestHandledSeq = 0;
        lastMarkedRead.clear();
        for (const p of pendingReadMarkers.values()) {
          clearTimeout(p.timer);
        }
        pendingReadMarkers.clear();
        for (const ctx of mediaUploadContexts.values()) {
          if (ctx.abortController) ctx.abortController.abort();
          if (ctx.previewUrl) {
            try { URL.revokeObjectURL(ctx.previewUrl); } catch (_) {}
          }
        }
        mediaUploadContexts.clear();
        set({
          messages: [],
          conversations: [],
          users: [],
          selectedUser: null,
          activeConversationId: null,
          composerText: "",
          searchQuery: "",
          isConversationsLoading: false,
          isUsersLoading: false,
          isMessagesLoading: false,
          composerDisabledReason: null,
          isSettingUpSession: false,
          peerKeyChangedState: null,
          localKeysMissing: false,
        });
        if (typeof document !== "undefined") {
          document.title = "TALK";
        }
      },

      getUsers: async () => {
        set({ isUsersLoading: true });
        try {
          const res = await axiosInstance.get("/messages/users");
          set((state) => ({
            users: res.data,
            selectedUser:
              state.selectedUser && res.data.some((user) => user._id === state.selectedUser._id)
                ? state.selectedUser
                : null,
          }));
        } catch (error) {
          console.error("Error in getUsers:", error.message);
        } finally {
          set({ isUsersLoading: false });
        }
      },

      getConversations: () => {
        if (getConversationsTimer) {
          clearTimeout(getConversationsTimer);
        }

        return new Promise((resolve) => {
          pendingResolvers.push(resolve);

          getConversationsTimer = setTimeout(async () => {
            getConversationsTimer = null;
            const seq = ++getConversationsSeq;
            const resolvers = pendingResolvers;
            pendingResolvers = [];

            set({ isConversationsLoading: true });
            try {
              const res = await axiosInstance.get("/messages/conversations");
              if (seq < latestHandledSeq) {
                resolvers.forEach((r) => r());
                return;
              }
              latestHandledSeq = seq;
              const me = meId();
              const list = Array.isArray(res.data) ? res.data : [];
              const serverConvs = await Promise.all(
                list.map(async (c) => ({
                  ...c,
                  unreadCount: c.unreadCount ?? 0,
                  snippet: await snippetFor(me, c.lastMessage),
                }))
              );
              if (seq < latestHandledSeq) {
                resolvers.forEach((r) => r());
                return;
              }

              const current = get().conversations;
              const serverMap = new Map(serverConvs.map((c) => [c._id, c]));
              const merged = serverConvs.map((sc) => {
                const local = current.find((c) => c._id === sc._id);
                if (!local) return sc;
                const localTime = new Date(local.lastMessage?.createdAt || 0).getTime();
                const serverTime = new Date(sc.lastMessage?.createdAt || 0).getTime();
                const useLocal = localTime > serverTime;
                return {
                  ...sc,
                  unreadCount: useLocal ? Math.max(sc.unreadCount, local.unreadCount || 0) : sc.unreadCount,
                  snippet: useLocal ? local.snippet || sc.snippet : sc.snippet,
                  lastMessage: useLocal ? local.lastMessage : sc.lastMessage,
                };
              });
              for (const local of current) {
                if (!serverMap.has(local._id)) {
                  merged.push(local);
                }
              }

              const sorted = sortConversations(merged);
              set({ conversations: sorted });
              updateTitle(sorted);
            } catch (error) {
              console.error("Error in getConversations:", error.message);
            } finally {
              if (seq === getConversationsSeq) {
                set({ isConversationsLoading: false });
              }
              resolvers.forEach((r) => r());
            }
          }, DEBOUNCE_DELAY);
        });
      },

      markRead: (peerId, upTo) => {
        if (!peerId) return;
        const { messages } = get();

        let targetId = upTo;
        if (!targetId) {
          for (let i = messages.length - 1; i >= 0; i--) {
            const m = messages[i];
            if (m.senderId === peerId && m._id && m.state === "ok") {
              targetId = m._id;
              break;
            }
          }
        }
        if (!targetId) return;

        const sentMarker = lastMarkedRead.get(peerId);
        if (sentMarker && String(targetId) <= String(sentMarker)) {
          return;
        }

        // Clear local unread count immediately
        set((s) => {
          const next = s.conversations.map((c) =>
            c._id === peerId ? { ...c, unreadCount: 0 } : c
          );
          updateTitle(next);
          return { conversations: next };
        });

        const pending = pendingReadMarkers.get(peerId);
        if (pending) {
          if (String(targetId) <= String(pending.targetId)) {
            return;
          }
          clearTimeout(pending.timer);
        }

        const timer = setTimeout(async () => {
          pendingReadMarkers.delete(peerId);
          lastMarkedRead.set(peerId, targetId);
          try {
            await axiosInstance.post(`/messages/read/${peerId}`, { upTo: targetId });
          } catch (e) {
            // ignore network error
          }
        }, 300);

        pendingReadMarkers.set(peerId, { timer, targetId });
      },

      getMessages: async (userId) => {
        if (!userId) return;
        set({ isMessagesLoading: true, hasMore: false });
        try {
          const { data } = await axiosInstance.get(`/messages/${userId}?limit=30`);
          const me = meId();
          const list = Array.isArray(data?.messages) ? data.messages : [];
          const items = await Promise.all(list.map((m) => toItem(me, m)));

          // Filter out DUPLICATE_MESSAGE
          const cleanItems = items.filter(
            (m) => m.state !== DUPLICATE_MESSAGE && m.failReason !== DUPLICATE_MESSAGE
          );

          // Load local system messages
          const sysMsgs = me ? await getLocalSystemMessages(me, userId) : [];
          const combined = [...cleanItems, ...sysMsgs].sort(
            (a, b) => new Date(a.createdAt || 0) - new Date(b.createdAt || 0)
          );

          set({ messages: combined, hasMore: data?.hasMore });

          const isVisible = typeof document === "undefined" || document.visibilityState === "visible";
          if (isVisible) {
            get().markRead(userId);
          }
        } catch (error) {
          toast.error(error.response?.data?.message || "Failed to load messages");
        } finally {
          set({ isMessagesLoading: false });
        }
      },

      loadOlder: async () => {
        const { messages, selectedUser, hasMore, isLoadingOlder, activeConversationId } = get();
        const targetId = selectedUser?._id || activeConversationId;
        if (!hasMore || isLoadingOlder || !messages.length || !targetId) return;
        const firstId = messages[0]._id;
        if (!firstId) return;
        set({ isLoadingOlder: true });
        try {
          const { data } = await axiosInstance.get(
            `/messages/${targetId}?limit=30&before=${firstId}`
          );
          if ((get().selectedUser?._id || get().activeConversationId) !== targetId) return;
          const me = meId();
          const list = Array.isArray(data?.messages) ? data.messages : [];
          const items = await Promise.all(list.map((m) => toItem(me, m)));
          const cleanItems = items.filter(
            (m) => m.state !== DUPLICATE_MESSAGE && m.failReason !== DUPLICATE_MESSAGE
          );
          set({ messages: [...cleanItems, ...get().messages], hasMore: data.hasMore });
        } catch (e) {
          console.error(e);
        } finally {
          set({ isLoadingOlder: false });
        }
      },

      sendMessage: async (text) => {
        const { selectedUser, peerKeyChangedState, composerDisabledReason } = get();
        const body = (typeof text === "string" ? text : text?.text ?? "").trim();
        if (!selectedUser || !body) return false;
        if (peerKeyChangedState?.peerId === selectedUser._id || composerDisabledReason === PEER_NO_KEYS) {
          return false;
        }
        const me = meId(), peerId = selectedUser._id;
        const cid = crypto.randomUUID();
        set((s) => ({
          messages: [...s.messages, {
            cid, senderId: me, receiverId: peerId, createdAt: new Date().toISOString(),
            type: "text", state: "pending", text: body,
          }],
          composerText: "",
        }));
        await get()._deliver({ cid, me, peerId, text: body });
        return true;
      },

      _deliver: async ({ cid, me, peerId, text }) => {
        const patch = (p) => set((s) => ({ messages: s.messages.map((m) => (m.cid === cid ? { ...m, ...p } : m)) }));
        try {
          const session = await loadSession(me, peerId);
          if (!session) {
            set({ isSettingUpSession: true });
          }
          const { payload, envelope } = await encryptText({ me, peerId, text });
          set({ isSettingUpSession: false });
          const { data } = await axiosInstance.post(`/messages/send/${peerId}`, { cid, ...payload });
          await putPlain(me, data._id, { t: envelope.t, body: envelope.body, ts: envelope.ts });
          patch({ _id: data._id, createdAt: data.createdAt, state: "ok", failReason: undefined });

          // Patch local conversation immediately
          set((s) => {
            const partnerId = peerId;
            const existing = s.conversations.find((c) => c._id === partnerId);
            const snippet = text;
            const lastMessage = {
              _id: data._id,
              senderId: me,
              receiverId: peerId,
              createdAt: data.createdAt,
              type: "text",
            };

            let next;
            if (existing) {
              next = s.conversations.map((c) =>
                c._id === partnerId ? { ...c, snippet, lastMessage } : c
              );
            } else {
              next = [
                {
                  _id: partnerId,
                  fullName: s.selectedUser?.fullName || "User",
                  unreadCount: 0,
                  snippet,
                  lastMessage,
                },
                ...s.conversations,
              ];
            }
            return { conversations: sortConversations(next) };
          });

          get().getConversations();
        } catch (e) {
          set({ isSettingUpSession: false });
          const failReason = normalizeErrorCode(e.code ?? e.response?.data?.message ?? e.message ?? "network");
          if (failReason === PEER_KEY_CHANGED) {
            set({ peerKeyChangedState: { peerId } });
          } else if (failReason === PEER_NO_KEYS) {
            set({ composerDisabledReason: PEER_NO_KEYS });
          }
          patch({ state: "failed", failReason });
        }
      },

      sendMedia: async ({ file, caption = "" }) => {
        const { selectedUser } = get();
        if (!selectedUser || !file) return false;
        const me = meId(), peerId = selectedUser._id;
        const cid = crypto.randomUUID();

        // Enforce 25 MB first
        if (file.size > 25 * 1024 * 1024) {
          let previewUrl = null;
          try {
            if (typeof URL !== "undefined" && URL.createObjectURL) {
              previewUrl = URL.createObjectURL(file);
            }
          } catch (_) {}
          set((s) => ({
            messages: [
              ...s.messages,
              {
                cid,
                senderId: me,
                receiverId: peerId,
                createdAt: new Date().toISOString(),
                type: "media",
                state: "failed",
                failReason: "too-big",
                text: caption || "",
                previewUrl,
              },
            ],
          }));
          return false;
        }

        let previewUrl = null;
        try {
          if (typeof URL !== "undefined" && URL.createObjectURL) {
            previewUrl = URL.createObjectURL(file);
          }
        } catch (_) {}

        const abortController = new AbortController();

        set((s) => ({
          messages: [
            ...s.messages,
            {
              cid,
              senderId: me,
              receiverId: peerId,
              createdAt: new Date().toISOString(),
              type: "media",
              state: "processing",
              text: caption || "",
              previewUrl,
              progress: 0,
            },
          ],
        }));

        const ctx = {
          cid,
          me,
          peerId,
          file,
          caption,
          previewUrl,
          abortController,
        };
        mediaUploadContexts.set(cid, ctx);

        await get()._deliverMedia(ctx);
        return true;
      },

      _deliverMedia: async (ctx) => {
        const { cid, me, peerId, file, caption } = ctx;
        const patch = (p) => set((s) => ({ messages: s.messages.map((m) => (m.cid === cid ? { ...m, ...p } : m)) }));

        try {
          if (!ctx.processed) {
            patch({ state: "processing" });
            const processed = await processMediaFile(file);
            ctx.processed = processed;
          }

          if (!ctx.ciphertext && !ctx.abortController?.signal?.aborted) {
            patch({ state: "encrypting" });
            const { ciphertext, key, nonce } = await encryptBlob(ctx.processed.data);
            ctx.ciphertext = ciphertext;
            ctx.key = key;
            ctx.nonce = nonce;
          }

          if (!ctx.blobId || !ctx.uploadedUrl) {
            patch({ state: "uploading", progress: 0 });
            const uploadRes = await blobStore.upload(ctx.ciphertext || new Uint8Array(), {
              signal: ctx.abortController?.signal,
              onProgress: (p) => {
                patch({ progress: p });
              },
            });
            ctx.blobId = uploadRes.blobId;
            ctx.uploadedUrl = uploadRes.url;
          }

          if (ctx.abortController?.signal?.aborted) {
            patch({ state: "cancelled" });
            return;
          }

          patch({ state: "sending" });

          const att = {
            kind: ctx.processed.kind,
            mime: ctx.processed.mime,
            size: ctx.processed.size,
            w: ctx.processed.width,
            h: ctx.processed.height,
            url: ctx.uploadedUrl,
            key: btoa(String.fromCharCode(...ctx.key)),
            nonce: btoa(String.fromCharCode(...ctx.nonce)),
            ph: ctx.processed.placeholder,
          };
          if (ctx.processed.duration != null) {
            att.dur = ctx.processed.duration;
          }
          ctx.att = att;

          const { payload, envelope } = await encryptMedia({
            me,
            peerId,
            caption: caption || "",
            att,
            blobId: ctx.blobId,
          });

          const { data } = await axiosInstance.post(`/messages/send/${peerId}`, { cid, ...payload });
          await putPlain(me, data._id, envelope);
          patch({
            _id: data._id,
            createdAt: data.createdAt,
            state: "ok",
            failReason: undefined,
            att: {
              kind: att.kind,
              mime: att.mime,
              size: att.size,
              w: att.w,
              h: att.h,
              dur: att.dur,
              ph: att.ph,
            },
          });

          set((s) => {
            const partnerId = peerId;
            const existing = s.conversations.find((c) => c._id === partnerId);
            const prefix = att.kind === "video" ? "Video" : "Photo";
            const snippet = caption ? `${prefix}: ${caption}` : prefix;
            const lastMessage = {
              _id: data._id,
              senderId: me,
              receiverId: peerId,
              createdAt: data.createdAt,
              type: "media",
            };

            let next;
            if (existing) {
              next = s.conversations.map((c) =>
                c._id === partnerId ? { ...c, snippet, lastMessage } : c
              );
            } else {
              next = [
                {
                  _id: partnerId,
                  fullName: s.selectedUser?.fullName || "User",
                  unreadCount: 0,
                  snippet,
                  lastMessage,
                },
                ...s.conversations,
              ];
            }
            return { conversations: sortConversations(next) };
          });

          get().getConversations();
        } catch (e) {
          set({ isSettingUpSession: false });
          if (ctx.abortController?.signal?.aborted || e.name === "AbortError") {
            patch({ state: "cancelled" });
            return;
          }
          let failReason = "network";
          const msg = e.message || "";
          if (msg === "too-big" || msg.includes("25 MB") || msg.includes("file-too-large")) {
            failReason = "too-big";
          } else if (msg.includes("unsupported") || msg.includes("mismatch") || msg.includes("Magic byte")) {
            failReason = "unsupported-type";
          } else if (e.code === PEER_NO_KEYS || e.code === "recipient-no-keys" || msg.includes("prekey")) {
            failReason = PEER_NO_KEYS;
          } else if (e.code === PEER_KEY_CHANGED || e.code === "key-changed" || msg.includes("identity")) {
            failReason = PEER_KEY_CHANGED;
          } else if (e.code) {
            failReason = normalizeErrorCode(e.code);
          } else if (e.response?.data?.message) {
            failReason = normalizeErrorCode(e.response.data.message);
          } else if (msg) {
            failReason = normalizeErrorCode(msg);
          }
          if (failReason === PEER_KEY_CHANGED) {
            set({ peerKeyChangedState: { peerId } });
          } else if (failReason === PEER_NO_KEYS) {
            set({ composerDisabledReason: PEER_NO_KEYS });
          }
          patch({ state: "failed", failReason });
        }
      },

      cancelMediaUpload: (cid) => {
        const ctx = mediaUploadContexts.get(cid);
        if (ctx) {
          if (ctx.abortController) {
            ctx.abortController.abort();
          }
          if (ctx.previewUrl) {
            try {
              URL.revokeObjectURL(ctx.previewUrl);
            } catch (_) {}
          }
          mediaUploadContexts.delete(cid);
        }
        set((s) => ({
          messages: s.messages.map((m) => (m.cid === cid ? { ...m, state: "cancelled" } : m)),
        }));
      },

      retrySend: async (cid) => {
        const m = get().messages.find((x) => x.cid === cid);
        if (!m || m.state !== "failed") return;

        if (m.type === "media") {
          const ctx = mediaUploadContexts.get(cid);
          if (!ctx) return;
          ctx.abortController = new AbortController();
          set((s) => ({
            messages: s.messages.map((x) =>
              x.cid === cid ? { ...x, state: ctx.blobId ? "sending" : "uploading", failReason: undefined } : x
            ),
          }));
          await get()._deliverMedia(ctx);
          return;
        }

        set((s) => ({ messages: s.messages.map((x) => (x.cid === cid ? { ...x, state: "pending", failReason: undefined } : x)) }));
        await get()._deliver({ cid, me: meId(), peerId: m.receiverId, text: m.text });
      },

      reprocess: async () => {
        const me = meId();
        const next = await Promise.all(get().messages.map((it) => (it.raw && RETRYABLE.has(it.state) ? toItem(me, it.raw) : it)));
        set({ messages: next });
      },

      handleIncomingMessage: async (itemOrMsg) => {
        get().getConversations();

        const me = meId();
        if (!me) return;
        const item =
          itemOrMsg && (itemOrMsg.role || itemOrMsg.state)
            ? itemOrMsg
            : await toItem(me, itemOrMsg);

        // C. DUPLICATE_MESSAGE: dropped silently, never rendered
        if (item.state === DUPLICATE_MESSAGE || item.failReason === DUPLICATE_MESSAGE) {
          return;
        }

        if (item.state === PEER_KEY_CHANGED || item.failReason === PEER_KEY_CHANGED) {
          set({ peerKeyChangedState: { peerId: item.senderId } });
        }

        const { selectedUser, conversations } = get();
        const partnerId = item.senderId;
        const isChatOpen = selectedUser?._id === partnerId;
        const isVisible = typeof document === "undefined" || document.visibilityState === "visible";

        if (isChatOpen) {
          set((s) => (s.messages.some((m) => m._id === item._id) ? s : { messages: [...s.messages, item] }));
        }

        // Local conversation patch
        const snippet = item.text || "Encrypted message";
        const existing = conversations.find((c) => c._id === partnerId);
        const shouldCountUnread = !(isChatOpen && isVisible);

        let updatedConvs;
        if (existing) {
          const unreadCount = shouldCountUnread ? (existing.unreadCount || 0) + 1 : 0;
          updatedConvs = conversations.map((c) =>
            c._id === partnerId
              ? {
                  ...c,
                  unreadCount,
                  snippet,
                  lastMessage: {
                    _id: item._id,
                    senderId: item.senderId,
                    receiverId: item.receiverId,
                    createdAt: item.createdAt,
                    type: item.type,
                  },
                }
              : c
          );
        } else {
          updatedConvs = [
            {
              _id: partnerId,
              fullName: "User",
              unreadCount: shouldCountUnread ? 1 : 0,
              snippet,
              lastMessage: {
                _id: item._id,
                senderId: item.senderId,
                receiverId: item.receiverId,
                createdAt: item.createdAt,
                type: item.type,
              },
            },
            ...conversations,
          ];
        }

        const sorted = sortConversations(updatedConvs);
        set({ conversations: sorted });
        updateTitle(sorted);

        if (isChatOpen && isVisible && item._id) {
          get().markRead(partnerId, item._id);
        }
      },

      listenForMessages: () => {
        initVisibilityListeners();
        const socket = useAuthStore.getState().socket;
        if (!socket) return;
        socket.off("newMessage");
        socket.off("readUpdated");

        socket.on("readUpdated", () => {
          get().getConversations();
        });

        socket.on("newMessage", (msg) => {
          get().handleIncomingMessage(msg);
        });
      },

      addLocalSystemMessage: async (peerId, text) => {
        const me = meId();
        const sysMsg = {
          _id: "sys-" + Date.now() + "-" + Math.random().toString(36).slice(2, 7),
          isSystem: true,
          text,
          createdAt: new Date().toISOString(),
          time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        };
        if (me && peerId) {
          await saveLocalSystemMessage(me, peerId, sysMsg);
        }
        set((s) => ({ messages: [...s.messages, sysMsg] }));
        return sysMsg;
      },

      loadLocalSystemMessages: async (meIdOrPeerId, peerIdOpt) => {
        const me = peerIdOpt ? meIdOrPeerId : meId();
        const peer = peerIdOpt || meIdOrPeerId;
        return getLocalSystemMessages(me, peer);
      },

      resetSession: async (peerId) => {
        const me = meId();
        if (me && peerId) {
          await deleteSession(me, peerId);
        }
        await get().addLocalSystemMessage(peerId, "You reset the secure session");
        set({ peerKeyChangedState: null, isSettingUpSession: false, composerDisabledReason: null });
      },

      checkLocalKeysExist: async (userId) => {
        const uid = userId || meId();
        if (!uid) return true;
        const idn = await loadIdentity(uid);
        const exists = Boolean(idn && idn.ik);
        set({ localKeysMissing: !exists });
        return exists;
      },

      resetLocalKeys: async (authUser) => {
        const user = authUser || useAuthStore.getState().authUser;
        if (user) {
          try {
            await resetIdentity(user);
          } catch (_) {}
        }
        set({ localKeysMissing: false });
      },

      checkStorageHealth: async () => {
        let persistent = false;
        let persistDenied = false;
        let storageAvailable = true;
        let isPrivate = false;

        if (typeof navigator !== "undefined" && navigator.storage?.persist) {
          try {
            persistent = await navigator.storage.persist();
            if (!persistent) persistDenied = true;
          } catch (_) {
            persistDenied = true;
          }
        }

        if (typeof navigator !== "undefined" && navigator.storage?.estimate) {
          try {
            const est = await navigator.storage.estimate();
            if (est.quota && est.quota < 120 * 1024 * 1024) {
              isPrivate = true;
            }
          } catch (_) {}
        }

        const health = {
          persistent,
          persistDenied,
          storageAvailable,
          isPrivate,
          noteDismissed: get().storageHealth?.noteDismissed || false,
        };
        set({ storageHealth: health });
        return health;
      },

      dismissStorageHealthNote: () => {
        set((s) => ({
          storageHealth: { ...(s.storageHealth || {}), noteDismissed: true },
        }));
      },

      canShowErrorToast: (cid, now = Date.now()) => {
        const key = cid || "global";
        if (errorToastTimes.has(key)) {
          const last = errorToastTimes.get(key);
          if (now - last < 10000) {
            return false;
          }
        }
        errorToastTimes.set(key, now);
        return true;
      },

      acceptNewKey: async (peerId) => {
        const me = meId();
        if (me && peerId) {
          try {
            const { data } = await axiosInstance.get(`/identity/key/${peerId}`);
            await acceptKeyChange(me, peerId, { ik: data.publicKey, sik: data.sik });
            await get().addLocalSystemMessage(peerId, "Safety number changed");
            await get().reprocess();
          } catch (_) {}
        }
        set({ peerKeyChangedState: null });
      },

      cancelKeyChange: (peerId) => {
        set({ peerKeyChangedState: null });
      },

      unsubscribeFromMessages: () => {
        const socket = useAuthStore.getState().socket;
        socket?.off("newMessage");
        socket?.off("readUpdated");
      },

      setSelectedUser: (selectedUser) => {
        set((state) => ({
          selectedUser,
          activeConversationId: selectedUser?._id ?? null,
          messages:
            selectedUser && selectedUser._id !== state.activeConversationId ? [] : state.messages,
          hasMore:
            selectedUser && selectedUser._id !== state.activeConversationId ? false : state.hasMore,
        }));
        if (selectedUser?._id) {
          get().markRead(selectedUser._id);
        }
      },

      setActiveConversationId: (activeConversationId) => {
        set((state) => ({
          activeConversationId,
          selectedUser:
            state.users.find((user) => user._id === activeConversationId) ||
            state.conversations.find((user) => user._id === activeConversationId) ||
            (state.selectedUser?._id === activeConversationId ? state.selectedUser : null),
          messages: activeConversationId !== state.activeConversationId ? [] : state.messages,
          hasMore: activeConversationId !== state.activeConversationId ? false : state.hasMore,
        }));
        if (activeConversationId) {
          get().markRead(activeConversationId);
        }
      },

      setSearchQuery: (searchQuery) => set({ searchQuery }),
      setSidebarTab: (sidebarTab) => set({ sidebarTab }),
      setComposerText: (composerText) => set({ composerText }),
      setSoundEnabled: (isSoundEnabled) => set({ isSoundEnabled }),

      sendTextMessage: async (conversationId) => {
        const messageText = get().composerText.trim();
        if (!conversationId || !messageText) return false;
        return get().sendMessage(messageText);
      },
    }),
    {
      name: "imessage-storage",
      partialize: (state) => ({ isSoundEnabled: state.isSoundEnabled }),
    },
  ),
);
