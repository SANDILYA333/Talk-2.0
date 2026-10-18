import { create } from "zustand";
import { persist } from "zustand/middleware";

import { axiosInstance } from "../lib/axios";
import { useAuthStore } from "./useAuthStore";
import toast from "react-hot-toast";
import { encryptText, toItem, snippetFor } from "../lib/chatCrypto";
import { putPlain } from "../storage/keystore";

const meId = () => useAuthStore.getState().authUser?._id;
const RETRYABLE = new Set(["key-changed", "waiting-for-key", "undecryptable", "tampered"]);

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

      getConversations: async () => {
        set({ isConversationsLoading: true });
        try {
          const res = await axiosInstance.get("/messages/conversations");
          const me = meId();
          const list = Array.isArray(res.data) ? res.data : [];
          const conversations = await Promise.all(
            list.map(async (c) => ({ ...c, snippet: await snippetFor(me, c.lastMessage) }))
          );
          set({ conversations });
        } catch (error) {
          console.error("Error in getConversations:", error.message);
        } finally {
          set({ isConversationsLoading: false });
        }
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
          if ((get().selectedUser?._id || get().activeConversationId) !== targetId) return; // switched chat mid-request
          const me = meId();
          const items = await Promise.all((data.messages || []).map((m) => toItem(me, m)));
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
        const cid = crypto.randomUUID(); // needs https or localhost
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
          await putPlain(me, data._id, { t: envelope.t, body: envelope.body, ts: envelope.ts }); // cache even if the user left this chat
          patch({ _id: data._id, createdAt: data.createdAt, state: "ok", failReason: undefined });
          get().getConversations();
        } catch (e) {
          patch({ state: "failed", failReason: e.code ?? e.response?.data?.message ?? e.message ?? "network" });
        }
      },

      retrySend: async (cid) => {
        const m = get().messages.find((x) => x.cid === cid);
        if (!m || m.state !== "failed") return;
        set((s) => ({ messages: s.messages.map((x) => (x.cid === cid ? { ...x, state: "pending", failReason: undefined } : x)) }));
        await get()._deliver({ cid, me: meId(), peerId: m.receiverId, text: m.text }); // same cid: server dedupes
      },

      reprocess: async () => {
        const me = meId();
        const next = await Promise.all(get().messages.map((it) => (it.raw && RETRYABLE.has(it.state) ? toItem(me, it.raw) : it)));
        set({ messages: next });
      },

      listenForMessages: () => {
        const socket = useAuthStore.getState().socket;
        if (!socket) return;
        socket.off("newMessage");
        socket.on("newMessage", async (msg) => {
          const me = meId();
          if (!me) return;
          const item = await toItem(me, msg); // decrypts and caches BEFORE the sidebar refresh
          if (get().selectedUser?._id === msg.senderId) {
            set((s) => (s.messages.some((m) => m._id === item._id) ? s : { messages: [...s.messages, item] }));
          }
          get().getConversations();
        });
      },

      unsubscribeFromMessages: () => {
        const socket = useAuthStore.getState().socket;
        socket?.off("newMessage");
      },

      setSelectedUser: (selectedUser) =>
        set((state) => ({
          selectedUser,
          activeConversationId: selectedUser?._id ?? null,
          messages:
            selectedUser && selectedUser._id !== state.activeConversationId ? [] : state.messages,
          hasMore:
            selectedUser && selectedUser._id !== state.activeConversationId ? false : state.hasMore,
        })),

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
