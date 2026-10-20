import { useMediaQuery } from "./useMediaQuery";
import { formatMessageTime } from "../lib/utils";
import { useChatStore } from "../store/useChatStore";
import { useAuthStore } from "../store/useAuthStore";

// John Doe -> JD
export function getInitials(name) {
  if (!name || typeof name !== "string") return "?";
  return name
    .split(" ")
    .filter(Boolean)
    .map((namePart) => namePart[0])
    .join("") || "?";
}

// mapUserToConversation is an adapter — it converts the raw backend shapes (a user document + an array of message documents) into the clean view-model that the chat UI components expect to render.

// Two transformations happen:
// 1. Messages → UI messages
// 2. User → peer

function mapUserToConversation({ user, messages, authUser, onlineUsers }) {
  const mappedMessages = (messages || []).map((message) => ({
    id: message._id || message.cid,
    _id: message._id,
    cid: message.cid,
    senderId: message.senderId,
    receiverId: message.receiverId,
    type: message.type || "text",
    att: message.att,
    previewUrl: message.previewUrl,
    progress: message.progress,
    role: String(message.senderId) === String(authUser?._id) ? "me" : "them",
    text: message.text || "",
    state: message.state || "ok",
    failReason: message.failReason,
    time: formatMessageTime(message.createdAt),
  }));

  const fullName = user?.fullName || "User";
  return {
    id: user?._id,
    peer: {
      name: fullName,
      subtitle: user?.email || "",
      isOnline: Array.isArray(onlineUsers) && onlineUsers.includes(user?._id),
      avatarUrl: user?.profilePic || "",
      initials: getInitials(fullName),
    },
    messages: mappedMessages,
  };
}

export function useSelectedConversation() {
  const isSSR = typeof window === "undefined";
  const chatState = isSSR ? useChatStore.getState() : null;
  const authState = isSSR ? useAuthStore.getState() : null;

  const activeConversationId = isSSR
    ? chatState.activeConversationId
    : useChatStore((state) => state.activeConversationId);
  const conversations = isSSR ? chatState.conversations : useChatStore((state) => state.conversations);
  const users = isSSR ? chatState.users : useChatStore((state) => state.users);
  const messages = isSSR ? chatState.messages : useChatStore((state) => state.messages);

  const authUser = isSSR ? authState.authUser : useAuthStore((state) => state.authUser);
  const onlineUsers = isSSR ? authState.onlineUsers : useAuthStore((state) => state.onlineUsers);

  const isLargeScreen = useMediaQuery("(min-width: 1024px)");

  const storeSelectedUser = isSSR ? chatState.selectedUser : useChatStore((state) => state.selectedUser);

  const selectedUser = activeConversationId
    ? (storeSelectedUser?._id === activeConversationId ? storeSelectedUser : null) ||
      conversations.find((user) => user._id === activeConversationId) ||
      users.find((user) => user._id === activeConversationId)
    : null;

  const activeConversation = selectedUser
    ? mapUserToConversation({ user: selectedUser, messages, authUser, onlineUsers })
    : null;

  return {
    activeConversation,
    activeConversationId,
    selectedUser,
    isLargeScreen,
  };
}
