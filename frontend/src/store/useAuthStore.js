import { create } from "zustand";
import { axiosInstance } from "../lib/axios";
import { io } from "socket.io-client";
import { useChatStore } from "./useChatStore";
import { ensureIdentity } from "../lib/identity";
import { bootKeys } from "../lib/keysBoot";

const BASE_URL = import.meta.env.MODE === "development" ? "http://localhost:3000" : "/";

export const useAuthStore = create((set, get) => ({
  authUser: null,
  identity: null,
  isCheckingAuth: true,
  onlineUsers: [],
  socket: null,

  checkAuth: async () => {
    set({ isCheckingAuth: true });

    try {
      const res = await axiosInstance.get("/auth/check");
      set({ authUser: res.data });

      try {
        const identity = await ensureIdentity(res.data);
        set({ identity });
        if (identity.status === "ok") {
          bootKeys(res.data._id).catch((e) => console.error("keys:", e));
        }
      } catch (e) {
        console.error("identity:", e);
      }

      get().connectSocket();
    } catch (error) {
      console.error("Error in checkAuth:", error);
      set({ authUser: null, identity: null });
    } finally {
      set({ isCheckingAuth: false });
    }
  },

  clearAuth: () => {
    useChatStore.getState().reset?.();
    set({ authUser: null, identity: null, isCheckingAuth: false, onlineUsers: [] });
    get().disconnectSocket();
  },

  connectSocket: () => {
    if (get().socket?.connected) return;

    const socket = io(BASE_URL, {
      auth: async (cb) => cb({ token: await window.Clerk?.session?.getToken() }),
    });

    set({ socket });

    useChatStore.getState().listenForMessages();

    socket.on("getOnlineUsers", (userIds) => {
      set({ onlineUsers: userIds });
    });
  },

  disconnectSocket: () => {
    const socket = get().socket;
    if (socket?.connected) socket.disconnect();
    set({ socket: null });
  },
}));
