import { useRef } from "react";
import { Button, TextArea } from "@heroui/react";
import { ImageIcon, SendHorizontalIcon } from "lucide-react";
import toast from "react-hot-toast";
import useKeyboardSound from "../../hooks/useKeyboardSound";
import { useChatStore } from "../../store/useChatStore";

const ALLOWED_MEDIA_TYPES = "image/jpeg,image/png,image/webp,image/gif,video/mp4,video/webm";

export function ChatComposer() {
  const fileInputRef = useRef(null);
  const composerText = useChatStore((state) => state.composerText);
  const isSoundEnabled = useChatStore((state) => state.isSoundEnabled);
  const sendMessage = useChatStore((state) => state.sendMessage);
  const sendMedia = useChatStore((state) => state.sendMedia);
  const setComposerText = useChatStore((state) => state.setComposerText);
  const { playRandomKeyStrokeSound } = useKeyboardSound();

  const playSoundIfEnabled = () => {
    if (isSoundEnabled) playRandomKeyStrokeSound();
  };

  const handleSend = async () => {
    const text = composerText.trim();
    if (!text) return;
    await sendMessage(text);
    playSoundIfEnabled();
  };

  const handleComposerTextChange = (event) => {
    setComposerText(event.target.value);
    playSoundIfEnabled();
  };

  const handleAttachClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileSelect = async (event) => {
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
      <div className="mx-auto flex w-full max-w-full items-end gap-1.5 px-0.5 sm:gap-2 sm:px-1">
        <input
          ref={fileInputRef}
          type="file"
          accept={ALLOWED_MEDIA_TYPES}
          onChange={handleFileSelect}
          className="hidden"
          aria-hidden="true"
        />
        <Button
          variant="ghost"
          isIconOnly
          onPress={handleAttachClick}
          title="Attach photo or video"
          aria-label="Attach photo or video"
          className="size-9 shrink-0 touch-manipulation self-end text-muted hover:text-foreground cursor-pointer"
        >
          <ImageIcon className="size-5 sm:size-6" strokeWidth={2} />
        </Button>
        <TextArea
          fullWidth
          variant="secondary"
          placeholder="iMessage"
          rows={1}
          value={composerText}
          onChange={handleComposerTextChange}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              handleSend();
            }
          }}
          className="flex-1 rounded-full"
        />

        <Button variant="primary" isIconOnly isDisabled={!composerText.trim()} onPress={handleSend}>
          <SendHorizontalIcon className="size-5" />
        </Button>
      </div>
    </footer>
  );
}
