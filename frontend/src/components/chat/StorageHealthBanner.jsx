import { AlertTriangle, Info, X } from "lucide-react";
import { useChatStore } from "../../store/useChatStore";

export function StorageHealthBanner() {
  const storageHealth = useChatStore((state) => state.storageHealth);
  const dismissStorageHealthNote = useChatStore((state) => state.dismissStorageHealthNote);

  if (!storageHealth) return null;

  const isPrivateOrUnavailable = storageHealth.isPrivate || !storageHealth.storageAvailable;
  const showPersistDeniedNote = storageHealth.persistDenied && !storageHealth.noteDismissed;

  if (!isPrivateOrUnavailable && !showPersistDeniedNote) return null;

  return (
    <div className="w-full shrink-0">
      {isPrivateOrUnavailable && (
        <div
          role="alert"
          aria-label="Storage warning"
          className="flex items-center gap-2 border-b border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs text-red-500 font-medium"
        >
          <AlertTriangle className="size-4 shrink-0" />
          <span className="flex-1">
            Private browsing or restricted storage detected. Messages and encryption keys will not be preserved across sessions.
          </span>
        </div>
      )}

      {showPersistDeniedNote && !isPrivateOrUnavailable && (
        <div
          role="status"
          aria-label="Storage persist notice"
          className="flex items-center justify-between gap-2 border-b border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-600 dark:text-amber-400"
        >
          <div className="flex items-center gap-2">
            <Info className="size-4 shrink-0" />
            <span>Persistent storage was denied by your browser. Storage may be cleared when disk space is low.</span>
          </div>
          <button
            type="button"
            onClick={dismissStorageHealthNote}
            aria-label="Dismiss storage notice"
            className="rounded p-0.5 hover:bg-amber-500/20 cursor-pointer"
          >
            <X className="size-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
