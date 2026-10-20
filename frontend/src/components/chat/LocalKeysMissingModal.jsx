import { useState } from "react";
import { ShieldAlert, KeyRound, Loader2 } from "lucide-react";
import { useChatStore } from "../../store/useChatStore";
import { useAuthStore } from "../../store/useAuthStore";

export function LocalKeysMissingModal() {
  const localKeysMissing = useChatStore((state) => state.localKeysMissing);
  const resetLocalKeys = useChatStore((state) => state.resetLocalKeys);
  const authUser = useAuthStore((state) => state.authUser);

  const [isResetting, setIsResetting] = useState(false);

  if (!localKeysMissing) return null;

  const handleSetupNewKeys = async () => {
    if (
      typeof window !== "undefined" &&
      !window.confirm(
        "Setting up new keys will start a new encryption identity. Past message history is not recoverable and will be lost. Continue?"
      )
    ) {
      return;
    }

    setIsResetting(true);
    try {
      await resetLocalKeys(authUser);
    } finally {
      setIsResetting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Security keys missing"
    >
      <div className="w-full max-w-md rounded-2xl border border-border bg-background p-6 text-foreground shadow-2xl">
        <div className="mb-4 flex size-12 items-center justify-center rounded-2xl bg-red-500/10 text-red-500">
          <KeyRound className="size-6" />
        </div>

        <h2 className="text-lg font-semibold tracking-tight">Security keys missing</h2>

        <p className="mt-2 text-sm text-muted leading-relaxed">
          Your account exists, but the encryption keys required to decrypt your messages are missing from this browser.
        </p>

        <p className="mt-2 text-xs text-muted/80 leading-relaxed">
          Talk uses end-to-end encryption with one device per account. History is stored only on your device and cannot be recovered from the server without your keys.
        </p>

        <div className="mt-6">
          <button
            type="button"
            onClick={handleSetupNewKeys}
            disabled={isResetting}
            aria-label="Set up new keys"
            className="w-full rounded-xl bg-primary py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50 cursor-pointer flex items-center justify-center gap-2"
          >
            {isResetting ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                <span>Initializing keys…</span>
              </>
            ) : (
              <span>Set up new keys</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
