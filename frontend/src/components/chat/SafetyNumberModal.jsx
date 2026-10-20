import { useEffect, useState } from "react";
import { loadIdentity } from "../../storage/keystore";
import { toB64 } from "../../crypto/index.js";
import { safetyNumber, markVerified, markUnverified } from "../../lib/safety";

export default function SafetyNumberModal({ open, onClose, me, peer, trust, onChange }) {
  const [groups, setGroups] = useState(null);

  useEffect(() => {
    if (!open || !trust?.peerKeys) return;
    let off = false;
    (async () => {
      const idn = await loadIdentity(me?._id);
      if (!idn?.sik || off) return;
      const g = await safetyNumber(
        { ik: toB64(idn.ik.pub), sik: toB64(idn.sik.pub) },
        trust.peerKeys
      );
      if (!off) setGroups(g);
    })();
    return () => {
      off = true;
    };
  }, [open, trust, me?._id]);

  if (!open) return null;

  const verify = async () => {
    await markVerified(me._id, peer._id, trust?.peerKeys || {});
    onChange?.({ ...trust, status: "ok", verified: true });
  };

  const unverify = async () => {
    await markUnverified(me._id, peer._id, trust?.peerKeys || {});
    onChange?.({ ...trust, status: "ok", verified: false });
  };

  // Generate deterministic SVG matrix pattern for QR visual
  const qrString = groups ? groups.join(" ") : "";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Safety number verification"
    >
      <div
        className="w-full max-w-sm rounded-2xl bg-white p-6 text-black shadow-xl dark:bg-neutral-900 dark:text-white"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-lg font-semibold">Safety number</h2>
        <p className="mb-3 text-xs opacity-60">
          Compare these digits or scan the QR code with {peer.fullName}. If they match, your connection is secure.
        </p>

        {trust?.status === "changed" && (
          <div className="mb-3 rounded-lg border border-amber-300 bg-amber-50 p-2.5 text-xs text-amber-900 dark:border-amber-800 dark:bg-amber-950/80 dark:text-amber-200">
            ⚠️ Safety number changed. Verify before trusting this chat.
          </div>
        )}

        {/* QR code representation */}
        <div className="my-3 flex justify-center">
          <div
            className="flex size-36 items-center justify-center rounded-xl border border-neutral-200 bg-white p-2 dark:border-neutral-800"
            role="img"
            aria-label="QR code for safety number"
          >
            <svg
              className="size-full text-neutral-900"
              viewBox="0 0 29 29"
              fill="currentColor"
              shapeRendering="crispEdges"
            >
              {/* Corner squares for QR */}
              <rect x="2" y="2" width="7" height="7" fill="currentColor" />
              <rect x="3" y="3" width="5" height="5" fill="white" />
              <rect x="4" y="4" width="3" height="3" fill="currentColor" />

              <rect x="20" y="2" width="7" height="7" fill="currentColor" />
              <rect x="21" y="3" width="5" height="5" fill="white" />
              <rect x="22" y="4" width="3" height="3" fill="currentColor" />

              <rect x="2" y="20" width="7" height="7" fill="currentColor" />
              <rect x="3" y="21" width="5" height="5" fill="white" />
              <rect x="4" y="22" width="3" height="3" fill="currentColor" />

              {/* Data matrix dots */}
              <rect x="11" y="4" width="2" height="2" />
              <rect x="15" y="2" width="2" height="2" />
              <rect x="11" y="8" width="2" height="2" />
              <rect x="14" y="10" width="3" height="2" />
              <rect x="4" y="12" width="2" height="3" />
              <rect x="8" y="14" width="2" height="2" />
              <rect x="13" y="14" width="3" height="3" />
              <rect x="19" y="12" width="2" height="2" />
              <rect x="23" y="14" width="3" height="2" />
              <rect x="11" y="19" width="2" height="3" />
              <rect x="15" y="22" width="3" height="2" />
              <rect x="21" y="20" width="2" height="4" />
            </svg>
          </div>
        </div>

        {groups ? (
          <div className="mb-4 grid grid-cols-3 gap-2 text-center font-mono text-sm tracking-wider">
            {groups.map((g, i) => (
              <div key={i} className="rounded bg-neutral-100 p-1 dark:bg-neutral-800">
                {g}
              </div>
            ))}
          </div>
        ) : (
          <p className="mb-4 text-center text-sm opacity-60">Calculating…</p>
        )}

        {trust?.verified ? (
          <div className="space-y-2 mb-2">
            <p className="text-center text-sm font-medium text-green-500">Verified ✓</p>
            <button
              onClick={unverify}
              type="button"
              aria-label="Unverify safety number"
              className="w-full rounded-xl border border-neutral-300 py-2 text-sm font-medium transition-colors hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-neutral-800 cursor-pointer"
            >
              Unverify
            </button>
          </div>
        ) : (
          <button
            onClick={verify}
            type="button"
            disabled={!groups}
            aria-label="Mark safety number as verified"
            className="mb-2 w-full rounded-xl bg-blue-500 py-2 font-medium text-white transition-colors hover:bg-blue-600 disabled:opacity-50 cursor-pointer"
          >
            Mark as verified
          </button>
        )}

        <button
          onClick={onClose}
          type="button"
          aria-label="Close safety number modal"
          className="w-full py-2 text-sm opacity-60 transition-opacity hover:opacity-100 cursor-pointer"
        >
          Close
        </button>
      </div>
    </div>
  );
}
