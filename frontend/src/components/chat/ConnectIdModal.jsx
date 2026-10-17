import { useState } from "react";
import QRCode from "react-qr-code";
import { resetIdentity } from "../../lib/identity";

export default function ConnectIdModal({ open, onClose, authUser, identity, onIdentityChange }) {
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  if (!open) return null;

  const needsReset = identity?.status === "missing-local" || identity?.status === "mismatch";

  const copy = async () => {
    if (!identity?.connectCode) return;
    await navigator.clipboard.writeText(identity.connectCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const reset = async () => {
    if (!confirm("This creates a new Connect ID. Your old code will stop working. Continue?")) return;
    setBusy(true);
    try {
      const updated = await resetIdentity(authUser);
      onIdentityChange(updated);
    } catch (e) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div
        className="w-full max-w-sm rounded-2xl bg-white p-6 text-center text-black shadow-xl dark:bg-neutral-900 dark:text-white"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-lg font-semibold">Your Connect ID</h2>
        <p className="mb-4 text-sm opacity-60">Share this code so friends can add you.</p>

        {identity?.connectCode ? (
          <>
            <div className="mx-auto mb-4 inline-block rounded-xl bg-white p-3 shadow-inner">
              <QRCode value={identity.connectCode} size={176} />
            </div>
            <div className="mb-3 font-mono text-xl tracking-wider select-all">{identity.connectCode}</div>
            <button
              onClick={copy}
              className="mb-2 w-full rounded-xl bg-blue-500 py-2 font-medium text-white transition-colors hover:bg-blue-600"
            >
              {copied ? "Copied!" : "Copy code"}
            </button>
          </>
        ) : (
          <p className="mb-4 text-sm">
            {identity?.status === "error" ? "Could not set up identity. Reload and try again." : "Setting up your identity…"}
          </p>
        )}

        {needsReset && (
          <div className="mt-3 rounded-xl bg-amber-100 p-3 text-left text-sm text-amber-900 dark:bg-amber-950/60 dark:text-amber-200">
            This device doesn't have your private key (new device or cleared storage).
            <button
              onClick={reset}
              disabled={busy}
              className="mt-2 w-full rounded-lg bg-amber-500 py-2 font-medium text-white transition-colors hover:bg-amber-600"
            >
              {busy ? "Resetting…" : "Reset identity"}
            </button>
          </div>
        )}

        <button onClick={onClose} className="mt-3 w-full py-2 text-sm opacity-60 transition-opacity hover:opacity-100">
          Close
        </button>
      </div>
    </div>
  );
}
