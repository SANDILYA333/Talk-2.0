import { Button, TextArea } from "@heroui/react";
import { ImageIcon, SendHorizontalIcon } from "lucide-react";
import useKeyboardSound from "../../hooks/useKeyboardSound";
import { useChatStore } from "../../store/useChatStore";

export function ChatComposer() {
  const composerText = useChatStore((state) => state.composerText);
  const isSoundEnabled = useChatStore((state) => state.isSoundEnabled);
  const sendMessage = useChatStore((state) => state.sendMessage);
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

  return (
    <footer className="shrink-0 border-t border-border px-1.5 pb-2 pt-2 sm:px-2">
      <div className="mx-auto flex w-full max-w-full items-end gap-1.5 px-0.5 sm:gap-2 sm:px-1">
        <Button
          variant="ghost"
          isIconOnly
          isDisabled
          title="Media coming soon"
          aria-label="Media coming soon"
          className="size-9 shrink-0 touch-manipulation self-end text-muted opacity-50 cursor-not-allowed"
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
