import { useEffect, useState } from "react";
import { Avatar, Button } from "@heroui/react";
import { ChevronLeftIcon, Volume2Icon, VolumeXIcon, XIcon } from "lucide-react";
import { AppLogo } from "../AppLogo";
import { AvatarWithOnlineIndicator } from "./AvatarWithOnlineIndicator";

import { ThemePresetPicker } from "../ThemePresetPicker";
import { ThemeToggle } from "../ThemeToggle";
import { WallpaperPicker } from "../WallpaperPicker";

import { useChatStore } from "../../store/useChatStore";
import { useAuthStore } from "../../store/useAuthStore";
import { useSelectedConversation } from "../../hooks/useSelectedConversation";
import { axiosInstance } from "../../lib/axios";
import { checkContact, acceptKeyChange } from "../../lib/safety";
import SafetyNumberModal from "./SafetyNumberModal";

export function ChatHeader() {
  const isSoundEnabled = useChatStore((state) => state.isSoundEnabled);
  const setActiveConversationId = useChatStore((state) => state.setActiveConversationId);
  const setSoundEnabled = useChatStore((state) => state.setSoundEnabled);

  const authUser = useAuthStore((state) => state.authUser);
  const { activeConversation, selectedUser, isLargeScreen } = useSelectedConversation();

  const [trust, setTrust] = useState(null);
  const [showSafety, setShowSafety] = useState(false);

  useEffect(() => {
    if (!selectedUser || !authUser?._id) return;
    let off = false;
    setTrust(null);
    (async () => {
      const { data } = await axiosInstance.get(`/identity/key/${selectedUser._id}`);
      const t = await checkContact(authUser._id, selectedUser._id, { ik: data.publicKey, sik: data.sik });
      if (!off) setTrust(t);
    })().catch(() => {
      if (!off) setTrust(null);
    }); // 404 = peer has no identity yet
    return () => {
      off = true;
    };
  }, [selectedUser?._id, authUser?._id]);

  return (
    <>
      <header className="sticky top-0 z-10 flex shrink-0 flex-wrap items-center gap-1 border-b border-border px-1.5 py-1.5 sm:gap-2 sm:px-2 sm:py-2">
        {activeConversation && !isLargeScreen ? (
          <Button
            variant="ghost"
            size="sm"
            isIconOnly
            className="shrink-0"
            onPress={() => setActiveConversationId(null)}
          >
            <ChevronLeftIcon className="size-6" strokeWidth={2.25} />
          </Button>
        ) : null}

        {activeConversation ? (
          <>
            <AvatarWithOnlineIndicator isOnline={activeConversation.peer.isOnline ?? true}>
              <Avatar className="size-9 shrink-0">
                <Avatar.Image
                  alt={activeConversation.peer.name}
                  src={activeConversation.peer.avatarUrl}
                />
                <Avatar.Fallback className="text-sm font-medium">
                  {activeConversation.peer.initials}
                </Avatar.Fallback>
              </Avatar>
            </AvatarWithOnlineIndicator>

            <div className="flex-1 text-center sm:text-left">
              <div className="flex items-center gap-2 justify-center sm:justify-start">
                <p className="truncate text-[15px] font-semibold leading-tight">
                  {activeConversation.peer.name}
                </p>
                <button
                  type="button"
                  onClick={() => setShowSafety(true)}
                  disabled={!trust || trust.status === "no-keys"}
                  className="inline-flex items-center gap-1 rounded-full border border-border bg-surface px-2 py-0.5 text-xs font-medium cursor-pointer hover:bg-muted/10 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {trust?.status === "no-keys"
                    ? "⏳ No keys yet"
                    : trust?.verified
                    ? "🔒 Verified"
                    : "🔓 Verify"}
                </button>
              </div>
              <p className="truncate text-xs text-muted">
                {activeConversation.peer.isOnline ? (
                  <span className="font-medium text-success">Online</span>
                ) : (
                  "Offline"
                )}
              </p>
            </div>
          </>
        ) : (
          <div className="flex flex-1 items-center gap-2.5 sm:text-left">
            <AppLogo size={36} className="rounded-[9px]" />
            <div className="flex-1 text-center sm:text-left">
              <p className="truncate text-[13px] font-medium text-muted">Select a conversation</p>
            </div>
          </div>
        )}

        <div className="ml-auto flex max-w-full shrink-0 flex-wrap items-center justify-end gap-0.5 sm:gap-1">
          <div className="hidden min-[400px]:contents">
            <WallpaperPicker />
            <ThemePresetPicker />
          </div>

          <ThemeToggle />

          <Button
            variant="ghost"
            size="sm"
            isIconOnly
            className="shrink-0"
            aria-pressed={isSoundEnabled}
            onPress={() => setSoundEnabled(!isSoundEnabled)}
          >
            {isSoundEnabled ? (
              <Volume2Icon className="size-5.5" strokeWidth={2} aria-hidden />
            ) : (
              <VolumeXIcon className="size-5.5" strokeWidth={2} aria-hidden />
            )}
          </Button>

          {activeConversation ? (
            <Button
              variant="ghost"
              size="sm"
              isIconOnly
              className="shrink-0"
              aria-label="Close chat"
              onPress={() => setActiveConversationId(null)}
            >
              <XIcon className="size-5.5" strokeWidth={2} aria-hidden />
            </Button>
          ) : null}
        </div>
      </header>

      {trust?.upgraded && selectedUser && (
        <div className="flex items-center justify-between gap-2 border-b border-amber-300 bg-amber-100 px-3 py-2 text-sm text-amber-900 dark:border-amber-900/50 dark:bg-amber-950/70 dark:text-amber-200">
          <span>Safety number format updated. Verify again.</span>
        </div>
      )}

      {trust?.status === "changed" && selectedUser && (
        <div className="flex items-center justify-between gap-2 border-b border-red-300 bg-red-100 px-3 py-2 text-sm text-red-900 dark:border-red-900/50 dark:bg-red-950/70 dark:text-red-200">
          <span>
            {selectedUser.fullName}&apos;s security key changed. Verify before trusting this chat.
          </span>
          <button
            type="button"
            className="shrink-0 font-medium underline cursor-pointer hover:text-red-950 dark:hover:text-red-100"
            onClick={async () => {
              await acceptKeyChange(authUser._id, selectedUser._id, trust.peerKeys);
              setTrust({ ...trust, status: "ok", verified: false });
            }}
          >
            Accept new key
          </button>
        </div>
      )}

      {authUser && selectedUser && (
        <SafetyNumberModal
          open={showSafety}
          onClose={() => setShowSafety(false)}
          me={authUser}
          peer={selectedUser}
          trust={trust}
          onChange={setTrust}
        />
      )}
    </>
  );
}

