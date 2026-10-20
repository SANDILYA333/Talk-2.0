import { useState, useEffect } from "react";
import { X, RefreshCw, AlertCircle, Loader2 } from "lucide-react";
import { MessageVideo } from "./MessageVideo";
import { useChatStore } from "../../store/useChatStore";
import { useAuthStore } from "../../store/useAuthStore";
import { loadMedia } from "../../lib/chatCrypto";
import { safePlaceholderDataUrl } from "../../lib/mediaSecurity";
import {
  DECRYPT_FAILED,
  HISTORY_UNAVAILABLE,
  MEDIA_DECRYPT_FAILED,
  TOO_MANY_SKIPPED,
  SESSION_RESET_REQUIRED,
  UNSUPPORTED_VERSION,
  PEER_NO_KEYS,
  PEER_KEY_CHANGED,
  SESSION_SETUP_FAILED,
} from "../../crypto/errors.js";

export function MessageBubble({ message }) {
  const retrySend = useChatStore((state) => state.retrySend);
  const cancelMediaUpload = useChatStore((state) => state.cancelMediaUpload);
  const selectedUser = useChatStore((state) => state.selectedUser);
  const authUserId = useAuthStore((state) => state.authUser?._id);

  if (message.isSystem) {
    return (
      <div className="my-2 flex w-full justify-center select-none">
        <div className="rounded-full border border-border/50 bg-surface/80 px-3 py-1 text-center text-xs text-muted">
          <span>{message.text}</span>
          {message.time && <span className="ml-2 opacity-60 tabular-nums">{message.time}</span>}
        </div>
      </div>
    );
  }

  const isOwnMessage = message.role === "me";
  const state = message.state || "ok";
  const isMedia = message.type === "media";
  const att = message.att;

  const [mediaBlobUrl, setMediaBlobUrl] = useState(null);
  const [mediaError, setMediaError] = useState(null);
  const [isLoadingMedia, setIsLoadingMedia] = useState(false);

  // Auto-load images when message is OK
  useEffect(() => {
    let active = true;
    if (state === "ok" && isMedia && att?.kind === "image" && message._id && authUserId) {
      setIsLoadingMedia(true);
      loadMedia(authUserId, message._id)
        .then((url) => {
          if (active) setMediaBlobUrl(url);
        })
        .catch((err) => {
          if (active) setMediaError(err?.code || err?.message || "error");
        })
        .finally(() => {
          if (active) setIsLoadingMedia(false);
        });
    }
    return () => {
      active = false;
    };
  }, [state, isMedia, att?.kind, message._id, authUserId]);

  const handlePlayVideo = async () => {
    if (!message._id || !authUserId || isLoadingMedia) return;
    setIsLoadingMedia(true);
    try {
      const url = await loadMedia(authUserId, message._id);
      setMediaBlobUrl(url);
    } catch (err) {
      setMediaError(err?.code || err?.message || "error");
    } finally {
      setIsLoadingMedia(false);
    }
  };

  const getFailureReasonText = () => {
    switch (message.failReason) {
      case "too-big":
        return "Attachment exceeds 25 MB";
      case "unsupported-type":
      case UNSUPPORTED_VERSION:
        return "Unsupported file format";
      case PEER_NO_KEYS:
      case "recipient-no-keys": {
        const name = selectedUser?.fullName || "They";
        return `${name} hasn't set up secure messaging yet`;
      }
      case PEER_KEY_CHANGED:
      case "key-changed":
        return "Their security key changed. Verify in the header";
      case SESSION_SETUP_FAILED:
        return "Couldn't set up secure session";
      case DECRYPT_FAILED:
        return "Decryption failed";
      case HISTORY_UNAVAILABLE:
        return "Older message not available on this device";
      default:
        return "Check your connection";
    }
  };

  const placeholderUrl = safePlaceholderDataUrl(att?.ph);

  const renderMediaAttachment = () => {
    if (mediaError) {
      const isNoKey = mediaError === "no-key" || mediaError.includes("no-key");
      return (
        <div className="mb-1.5 flex items-center gap-2 rounded-lg bg-surface/60 p-3 text-xs italic text-muted">
          <AlertCircle className="size-4 shrink-0 text-muted" />
          <span>{isNoKey ? "Can't open this attachment on this device" : "Attachment unavailable"}</span>
        </div>
      );
    }

    if (att?.kind === "image") {
      if (mediaBlobUrl) {
        return (
          <img
            src={mediaBlobUrl}
            alt={message.text || "Photo attachment"}
            className="mb-1.5 max-h-60 max-w-full rounded-lg object-contain sm:max-h-80 sm:rounded-xl"
          />
        );
      }

      return (
        <div className="relative mb-1.5 flex min-h-[140px] min-w-[200px] max-w-full items-center justify-center overflow-hidden rounded-lg bg-black/10 sm:rounded-xl">
          {placeholderUrl ? (
            <img
              src={placeholderUrl}
              alt="Photo preview"
              className="h-full w-full object-cover blur-sm"
            />
          ) : (
            <div className="h-32 w-full bg-surface/50" />
          )}
          <div className="absolute inset-0 flex items-center justify-center bg-black/20">
            <Loader2 className="size-5 animate-spin text-white" />
          </div>
        </div>
      );
    }

    if (att?.kind === "video") {
      return (
        <MessageVideo
          src={mediaBlobUrl}
          poster={placeholderUrl}
          duration={att?.dur}
          isLoading={isLoadingMedia}
          onPlayRequested={handlePlayVideo}
        />
      );
    }

    return null;
  };

  const renderContent = () => {
    // Media upload in flight states: processing, encrypting, uploading, sending
    const isUploadingState =
      state === "processing" || state === "encrypting" || state === "uploading" || state === "sending";

    if (isUploadingState && isMedia) {
      const progress = message.progress || 0;
      return (
        <div className="space-y-1.5">
          {message.previewUrl ? (
            <div className="relative overflow-hidden rounded-lg sm:rounded-xl max-h-52 max-w-full">
              <img
                src={message.previewUrl}
                alt="Upload preview"
                className="max-h-52 w-full object-cover opacity-75"
              />
              <div className="absolute inset-0 flex items-center justify-center bg-black/40">
                {state === "uploading" ? (
                  <div className="flex flex-col items-center gap-1.5 text-white">
                    <div className="relative flex size-10 items-center justify-center rounded-full border-2 border-white/30 border-t-white animate-spin">
                      <span className="text-[10px] font-mono">{progress}%</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => message.cid && cancelMediaUpload(message.cid)}
                      className="mt-1 flex items-center gap-1 rounded bg-black/60 px-2 py-0.5 text-[11px] text-white hover:bg-black/80"
                    >
                      <X className="size-3" /> Cancel
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 rounded bg-black/60 px-2.5 py-1 text-xs text-white">
                    <Loader2 className="size-4 animate-spin" />
                    <span>{state === "encrypting" ? "Encrypting…" : state === "sending" ? "Sending…" : "Processing…"}</span>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-2 py-1 text-xs italic opacity-75">
              <Loader2 className="size-3.5 animate-spin" />
              <span>{state === "uploading" ? `Uploading ${progress}%…` : "Preparing media…"}</span>
              {state === "uploading" && (
                <button
                  type="button"
                  onClick={() => message.cid && cancelMediaUpload(message.cid)}
                  className="ml-2 text-red-300 underline"
                >
                  Cancel
                </button>
              )}
            </div>
          )}
          {message.text ? (
            <p className="whitespace-pre-wrap wrap-break-word">{message.text}</p>
          ) : null}
        </div>
      );
    }

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

      case "cancelled":
        return (
          <p className="italic text-muted text-xs">
            Upload cancelled
          </p>
        );

      case "failed":
        return (
          <button
            type="button"
            aria-label="Retry sending message"
            onClick={() => message.cid && retrySend(message.cid)}
            className="text-left cursor-pointer group"
          >
            {message.previewUrl && (
              <div className="relative mb-1.5 overflow-hidden rounded-lg sm:rounded-xl max-h-40 opacity-60">
                <img src={message.previewUrl} alt="" className="max-h-40 w-full object-cover" />
              </div>
            )}
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

      case HISTORY_UNAVAILABLE:
        return (
          <p className="italic text-muted text-xs">
            Older message not available on this device
          </p>
        );

      case MEDIA_DECRYPT_FAILED:
        return (
          <div className="flex items-center gap-2 rounded-lg bg-surface/60 p-2 text-xs italic text-muted">
            <AlertCircle className="size-4 shrink-0 text-muted" />
            <span>Attachment unavailable</span>
          </div>
        );

      case TOO_MANY_SKIPPED:
      case SESSION_RESET_REQUIRED:
        return (
          <div className="space-y-1">
            <p className="font-medium text-red-500 dark:text-red-400 text-xs">
              Secure session reset required
            </p>
            <button
              type="button"
              aria-label="Reset session"
              onClick={() => {
                const peerId = message.senderId || selectedUser?._id;
                if (
                  peerId &&
                  typeof window !== "undefined" &&
                  window.confirm(
                    "Reset secure session? Undelivered and in-flight messages will be lost."
                  )
                ) {
                  useChatStore.getState().resetSession(peerId);
                }
              }}
              className="text-xs font-semibold text-blue-500 underline cursor-pointer hover:text-blue-600"
            >
              Reset session
            </button>
          </div>
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

      case "session-failed":
        return (
          <p className="font-medium text-red-500 dark:text-red-400 text-xs">
            Secure session setup failed
          </p>
        );

      case DECRYPT_FAILED:
      case "decrypt-failed":
        return (
          <p className="font-medium text-red-500 dark:text-red-400 text-xs">
            Couldn&apos;t decrypt this message
          </p>
        );

      case "ok":
      default:
        return (
          <>
            {isMedia && renderMediaAttachment()}
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
        {message.time && state !== "pending" && !["processing", "encrypting", "uploading", "sending"].includes(state) && (
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

