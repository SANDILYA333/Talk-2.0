import { useState } from "react";
import { Scanner } from "@yudiel/react-qr-scanner";
import { lookupContact } from "../../lib/identity";

export default function AddByCodeModal({ open, onClose, onContactFound }) {
  const [code, setCode] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  if (!open) return null;

  const go = async (raw) => {
    setError("");
    setBusy(true);
    try {
      const contact = await lookupContact(raw);
      onContactFound(contact);
      setCode("");
      setScanning(false);
      onClose();
    } catch (e) {
      setError(e.response?.data?.message || e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div
        className="w-full max-w-sm rounded-2xl bg-white p-6 text-black shadow-xl dark:bg-neutral-900 dark:text-white"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-3 text-lg font-semibold">Add by code</h2>

        {scanning ? (
          <div className="mb-3 overflow-hidden rounded-xl">
            <Scanner onScan={(r) => r?.[0]?.rawValue && go(r[0].rawValue)} />
          </div>
        ) : (
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && go(code)}
            placeholder="TALK-XXXXX-XXXXX"
            className="mb-3 w-full rounded-xl border border-neutral-300 dark:border-neutral-700 bg-transparent p-3 font-mono text-center tracking-wider outline-none focus:border-blue-500"
            autoFocus
          />
        )}

        {error && <p className="mb-3 text-sm text-red-500">{error}</p>}

        {!scanning && (
          <button
            onClick={() => go(code)}
            disabled={busy || !code.trim()}
            className="mb-2 w-full rounded-xl bg-blue-500 py-2 font-medium text-white transition-colors hover:bg-blue-600 disabled:opacity-50"
          >
            {busy ? "Looking up…" : "Find"}
          </button>
        )}
        <button
          onClick={() => setScanning((s) => !s)}
          className="w-full py-2 text-sm font-medium text-blue-500 transition-colors hover:text-blue-600"
        >
          {scanning ? "Type code instead" : "Scan QR instead"}
        </button>
        <button onClick={onClose} className="w-full py-2 text-sm opacity-60 transition-opacity hover:opacity-100">
          Cancel
        </button>
      </div>
    </div>
  );
}
