import { useWallpaper } from "../context/wallpaper";
import { useChatStore } from "../store/useChatStore";
import { useAuthStore } from "../store/useAuthStore";
import { useSelectedConversation } from "../hooks/useSelectedConversation";
import { useEffect } from "react";
import ChatSidebar from "../components/chat/ChatSidebar";
import { ChatHeader } from "../components/chat/ChatHeader";
import { MessageList } from "../components/chat/MessageList";
import { ChatComposer } from "../components/chat/ChatComposer";
import { StorageHealthBanner } from "../components/chat/StorageHealthBanner";
import { LocalKeysMissingModal } from "../components/chat/LocalKeysMissingModal";

function ChatPage() {
  const { frameStyle } = useWallpaper();

  const getConversations = useChatStore((state) => state.getConversations);
  const getMessages = useChatStore((state) => state.getMessages);
  const getUsers = useChatStore((state) => state.getUsers);
  const checkStorageHealth = useChatStore((state) => state.checkStorageHealth);
  const checkLocalKeysExist = useChatStore((state) => state.checkLocalKeysExist);
  const authUser = useAuthStore((state) => state.authUser);
  const { activeConversation, activeConversationId, isLargeScreen } = useSelectedConversation();

  useEffect(() => {
    checkStorageHealth();
  }, [checkStorageHealth]);

  useEffect(() => {
    if (authUser?._id) {
      checkLocalKeysExist(authUser._id);
    }
  }, [authUser?._id, checkLocalKeysExist]);

  useEffect(() => {
    getUsers();
    getConversations();
  }, [getConversations, getUsers]);

  useEffect(() => {
    if (!activeConversationId) return;

    getMessages(activeConversationId);
  }, [getMessages, activeConversationId]);

  return (
    <div className="flex h-dvh flex-col overflow-hidden p-2 sm:p-3 md:p-8" style={frameStyle}>
      <StorageHealthBanner />
      <div className="mx-auto flex w-full max-w-6xl flex-1 overflow-hidden rounded-2xl border border-border bg-background text-foreground">
        <ChatSidebar />

        <div
          className={`flex-1 flex-col overflow-hidden ${
            !isLargeScreen && !activeConversationId ? "hidden lg:flex" : "flex"
          }`}
        >
          <ChatHeader />
          <MessageList />

          {activeConversation ? <ChatComposer /> : null}
        </div>
      </div>
      <LocalKeysMissingModal />
    </div>
  );
}
export default ChatPage;
