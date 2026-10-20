import { useRef, useState } from "react";
import { Button, TextArea } from "@heroui/react";
import { ImageIcon, SendHorizontalIcon, Loader2, AlertTriangle } from "lucide-react";
import toast from "react-hot-toast";
import useKeyboardSound from "../../hooks/useKeyboardSound";
import { useChatStore } from "../../store/useChatStore";
import { useAuthStore } from "../../store/useAuthStore";
import { PEER_NO_KEYS } from "../../crypto/errors.js";
import SafetyNumberModal from "./SafetyNumberModal";

const ALLOWED_MEDIA_TYPES = "image/jpeg,image/png,image/webp,image/gif,video/mp4,video/webm";

export function ChatComposer() {
  const fileInputRef = useRef(null);
  const composerText = useChatStore((state) => state.composerText);
  const isSoundEnabled = useChatStore((state) => state.isSoundEnabled);
  const sendMessage = useChatStore((state) => state.sendMessage);
  const sendMedia = useChatStore((state) => state.sendMedia);
  const setComposerText = useChatStore((state) => state.setComposerText);
  const isSSR = typeof window === "undefined";
  const storeState = isSSR ? useChatStore.getState() : null;
  const composerDisabledReason = isSSR ? storeState.composerDisabledReason : useChatStore((state) => state.composerDisabledReason);
  const isSettingUpSession = isSSR ? storeState.isSettingUpSession : useChatStore((state) => state.isSettingUpSession);
  const peerKeyChangedState = isSSR ? storeState.peerKeyChangedState : useChatStore((state) => state.peerKeyChangedState);
  const acceptNewKey = useChatStore((state) => state.acceptNewKey);
  const cancelKeyChange = useChatStore((state) => state.cancelKeyChange);
  const selectedUser = useChatStore((state) => state.selectedUser);
  const authUser = useAuthStore((state) => state.authUser);

  const [showSafetyModal, setShowSafetyModal] = useState(false);

  const { playRandomKeyStrokeSound } = useKeyboardSound();

  const isPeerNoKeys = composerDisabledReason === PEER_NO_KEYS;
  const isBlocked = Boolean(isPeerNoKeys || peerKeyChangedState);

  const playSoundIfEnabled = () => {
    if (isSoundEnabled) playRandomKeyStrokeSound();
  };

  const handleSend = async () => {
    if (isBlocked) return;
    const text = composerText.trim();
    if (!text) return;
    await sendMessage(text);
    playSoundIfEnabled();
  };

  const handleComposerTextChange = (event) => {
    if (isBlocked) return;
    setComposerText(event.target.value);
    playSoundIfEnabled();
  };

  const handleAttachClick = () => {
    if (isBlocked) return;
    fileInputRef.current?.click();
  };

  const handleFileSelect = async (event) => {
    if (isBlocked) return;
    const file = event.target.files?.[0];
    if (!file) return;

    if (file.size > 25 * 1024 * 1024) {
      toast.error("File exceeds 25 MB limit");
      event.target.value = "";
      return;
    }

    const caption = composerText.trim();
    setComposerText("");
    event.target.value = "";
    playSoundIfEnabled();
    await sendMedia({ file, caption });
  };

  return (
    <footer className="shrink-0 border-t border-border px-1.5 pb-2 pt-2 sm:px-2">
      {peerKeyChangedState && (
        <div className="mb-2 rounded-xl border border-amber-300 bg-amber-50 p-2.5 text-xs text-amber-900 dark:border-amber-800 dark:bg-amber-950/80 dark:text-amber-200">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
            <div className="flex items-center gap-1.5 font-medium">
              <AlertTriangle className="size-4 shrink-0 text-amber-600 dark:text-amber-400" />
              <span>Safety number changed</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowSafetyModal(true)}
                className="font-medium underline cursor-pointer hover:opacity-80"
              >
                View safety number
              </button>
              <button
                type="button"
                onClick={() => {
                  if (
                    typeof window !== "undefined" &&
                    window.confirm(
                      "Accept new security key for this contact? Verify their safety number first if possible."
                    )
                  ) {
                    acceptNewKey(peerKeyChangedState.peerId);
                  }
                }}
                className="rounded bg-amber-600 px-2 py-1 font-semibold text-white hover:bg-amber-700 cursor-pointer"
              >
                Accept new key
              </button>
              <button
                type="button"
                onClick={() => cancelKeyChange(peerKeyChangedState.peerId)}
                className="text-muted hover:text-foreground cursor-pointer"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {isPeerNoKeys && (
        <div className="mb-2 rounded-lg bg-surface/80 p-2 text-center text-xs text-muted">
          <span>This contact hasn&apos;t set up secure messaging yet. You can&apos;t send messages until they initialize their keys.</span>
        </div>
      )}

      {isSettingUpSession && (
        <div className="mb-1.5 flex items-center justify-center gap-1.5 text-xs text-muted">
          <Loader2 className="size-3 animate-spin text-muted" />
          <span>Setting up secure session…</span>
        </div>
      )}

      <div className="mx-auto flex w-full max-w-full items-end gap-1.5 px-0.5 sm:gap-2 sm:px-1">
        <input
          ref={fileInputRef}
          type="file"
          accept={ALLOWED_MEDIA_TYPES}
          onChange={handleFileSelect}
          disabled={isBlocked}
          className="hidden"
          aria-hidden="true"
        />
        <Button
          variant="ghost"
          isIconOnly
          onPress={handleAttachClick}
          isDisabled={isBlocked}
          title="Attach photo or video"
          aria-label="Attach photo or video"
          className="size-9 shrink-0 touch-manipulation self-end text-muted hover:text-foreground cursor-pointer disabled:opacity-50"
        >
          <ImageIcon className="size-5 sm:size-6" strokeWidth={2} />
        </Button>
        <TextArea
          fullWidth
          variant="secondary"
          placeholder={isPeerNoKeys ? "Messaging disabled" : "iMessage"}
          rows={1}
          value={composerText}
          disabled={isBlocked}
          onChange={handleComposerTextChange}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              handleSend();
            }
          }}
          className="flex-1 rounded-full"
        />

        <Button
          variant="primary"
          isIconOnly
          isDisabled={isBlocked || !composerText.trim()}
          onPress={handleSend}
        >
          <SendHorizontalIcon className="size-5" />
        </Button>
      </div>

      {showSafetyModal && authUser && selectedUser && (
        <SafetyNumberModal
          open={showSafetyModal}
          onClose={() => setShowSafetyModal(false)}
          me={authUser}
          peer={selectedUser}
          trust={{ status: "changed", verified: false }}
          onChange={() => {}}
        />
      )}
    </footer>
  );
}
