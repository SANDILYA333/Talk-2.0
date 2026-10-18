import { create } from "zustand";
import { persist } from "zustand/middleware";

import { axiosInstance } from "../lib/axios";
import { useAuthStore } from "./useAuthStore";
import toast from "react-hot-toast";
import { encryptText, toItem, snippetFor } from "../lib/chatCrypto";
import { putPlain } from "../storage/keystore";
import { sortConversations } from "../lib/conversationView";

const meId = () => useAuthStore.getState().authUser?._id;
const RETRYABLE = new Set(["key-changed", "waiting-for-key", "undecryptable", "tampered"]);

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
          set({ messages: items, hasMore: data?.hasMore });

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
          set({ messages: [...items, ...get().messages], hasMore: data.hasMore });
        } catch (e) {
          console.error(e);
        } finally {
          set({ isLoadingOlder: false });
        }
      },

      sendMessage: async (text) => {
        const { selectedUser } = get();
        const body = (typeof text === "string" ? text : text?.text ?? "").trim();
        if (!selectedUser || !body) return false;
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
          const { payload, envelope } = await encryptText({ me, peerId, text });
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
          patch({ state: "failed", failReason: e.code ?? e.response?.data?.message ?? e.message ?? "network" });
        }
      },

      retrySend: async (cid) => {
        const m = get().messages.find((x) => x.cid === cid);
        if (!m || m.state !== "failed") return;
        set((s) => ({ messages: s.messages.map((x) => (x.cid === cid ? { ...x, state: "pending", failReason: undefined } : x)) }));
        await get()._deliver({ cid, me: meId(), peerId: m.receiverId, text: m.text });
      },

      reprocess: async () => {
        const me = meId();
        const next = await Promise.all(get().messages.map((it) => (it.raw && RETRYABLE.has(it.state) ? toItem(me, it.raw) : it)));
        set({ messages: next });
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

        socket.on("newMessage", async (msg) => {
          get().getConversations();

          const me = meId();
          if (!me) return;
          const item = await toItem(me, msg);

          const { selectedUser, conversations } = get();
          const partnerId = msg.senderId;
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
                      _id: msg._id,
                      senderId: msg.senderId,
                      receiverId: msg.receiverId,
                      createdAt: msg.createdAt,
                      type: msg.type,
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
                  _id: msg._id,
                  senderId: msg.senderId,
                  receiverId: msg.receiverId,
                  createdAt: msg.createdAt,
                  type: msg.type,
                },
              },
              ...conversations,
            ];
          }

          const sorted = sortConversations(updatedConvs);
          set({ conversations: sorted });
          updateTitle(sorted);

          if (isChatOpen && isVisible) {
            get().markRead(partnerId, msg._id);
          }
        });
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
