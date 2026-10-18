import { withTransform } from "../../lib/imagekit";
import { MessageVideo } from "./MessageVideo";
import { useChatStore } from "../../store/useChatStore";

const IMAGE_TRANSFORM = "q-auto,w-640,f-auto";

export function MessageBubble({ message }) {
  const retrySend = useChatStore((state) => state.retrySend);
  const selectedUser = useChatStore((state) => state.selectedUser);
  const isOwnMessage = message.role === "me";
  const state = message.state || "ok";
  const hasImage = Boolean(message.imageUrl);
  const hasVideo = Boolean(message.videoUrl);

  const getFailureReasonText = () => {
    if (message.failReason === "recipient-no-keys") {
      const name = selectedUser?.fullName || "They";
      return `${name} hasn't set up secure messaging yet`;
    }
    if (message.failReason === "key-changed") {
      return "Their security key changed. Verify in the header";
    }
    return "Check your connection";
  };

  const renderContent = () => {
    switch (state) {
      case "pending":
        return (
          <div className="opacity-75">
            {message.text ? (
              <p className="whitespace-pre-wrap wrap-break-word">{message.text}</p>
            ) : null}
            <p className="mt-1 text-[11px] font-medium text-accent-foreground/70 italic">Sending…</p>
          </div>
        );

      case "failed":
        return (
          <button
            type="button"
            onClick={() => message.cid && retrySend(message.cid)}
            className="text-left cursor-pointer group"
          >
            {message.text ? (
              <p className="whitespace-pre-wrap wrap-break-word opacity-60 mb-1">{message.text}</p>
            ) : null}
            <p className="text-xs font-semibold text-red-500 dark:text-red-400 group-hover:underline">
              Not sent · tap to retry
            </p>
            <p className="text-[11px] text-red-400/90 dark:text-red-300/80 mt-0.5">
              {getFailureReasonText()}
            </p>
          </button>
        );

      case "undecryptable":
        return (
          <p className="italic text-muted text-xs">
            Can&apos;t decrypt this message on this device
          </p>
        );

      case "tampered":
        return (
          <p className="font-medium text-red-500 dark:text-red-400 text-xs">
            This message failed verification
          </p>
        );

      case "key-changed":
        return (
          <p className="font-medium text-amber-600 dark:text-amber-400 text-xs">
            Security key changed. Verify to read
          </p>
        );

      case "waiting-for-key":
        return (
          <p className="italic text-muted text-xs">
            Waiting for their key…
          </p>
        );

      case "unsupported-version":
        return (
          <p className="font-medium text-amber-600 dark:text-amber-400 text-xs">
            Update the app to read this message
          </p>
        );

      case "ok":
      default:
        return (
          <>
            {hasImage ? (
              <img
                src={withTransform(message.imageUrl, IMAGE_TRANSFORM)}
                alt=""
                className="mb-1.5 max-h-40 max-w-full rounded-lg object-cover sm:max-h-52 sm:rounded-xl"
              />
            ) : null}
            {hasVideo ? <MessageVideo src={message.videoUrl} /> : null}
            {message.text ? (
              <p className="whitespace-pre-wrap wrap-break-word">{message.text}</p>
            ) : null}
          </>
        );
    }
  };

  return (
    <div className={`flex w-full ${isOwnMessage ? "justify-end" : "justify-start"}`}>
      <div
        className={`max-w-[min(90%,28rem)] rounded-2xl px-3 py-2 text-[15px] leading-snug sm:max-w-[min(75%,28rem)] sm:px-3.5 ${
          state === "failed"
            ? "rounded-br-md border border-red-500/30 bg-red-500/10 text-foreground"
            : isOwnMessage
            ? "rounded-br-md bg-accent text-accent-foreground"
            : "rounded-bl-md bg-surface"
        }`}
      >
        {renderContent()}
        {message.time && state !== "pending" && (
          <p
            className={`mt-1 text-[11px] tabular-nums ${
              state === "failed"
                ? "text-red-400/80"
                : isOwnMessage
                ? "text-accent-foreground/75"
                : "text-muted"
            }`}
          >
            {message.time}
          </p>
        )}
      </div>
    </div>
  );
}
