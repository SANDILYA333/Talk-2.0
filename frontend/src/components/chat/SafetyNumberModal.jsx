import { useEffect, useState } from "react";
import { loadIdentity } from "../../storage/keystore";
import { toB64 } from "../../crypto/index.js";
import { safetyNumber, markVerified } from "../../lib/safety";

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
    await markVerified(me._id, peer._id, trust.peerKeys);
    onChange({ ...trust, status: "ok", verified: true });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div
        className="w-full max-w-sm rounded-2xl bg-white p-6 text-black shadow-xl dark:bg-neutral-900 dark:text-white"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-lg font-semibold">Safety number</h2>
        <p className="mb-4 text-sm opacity-60">
          Compare these digits with {peer.fullName} in person or on a call. If they match, nobody is in the middle.
        </p>

        {groups ? (
          <div className="mb-4 grid grid-cols-3 gap-2 text-center font-mono text-lg">
            {groups.map((g, i) => (
              <div key={i}>{g}</div>
            ))}
          </div>
        ) : (
          <p className="mb-4 text-sm">Calculating…</p>
        )}

        {trust?.verified ? (
          <p className="mb-2 text-center text-sm font-medium text-green-500">Verified ✓</p>
        ) : (
          <button
            onClick={verify}
            disabled={!groups}
            className="mb-2 w-full rounded-xl bg-blue-500 py-2 font-medium text-white transition-colors hover:bg-blue-600 disabled:opacity-50 cursor-pointer"
          >
            Mark as verified
          </button>
        )}
        <button
          onClick={onClose}
          className="w-full py-2 text-sm opacity-60 transition-opacity hover:opacity-100 cursor-pointer"
        >
          Close
        </button>
      </div>
    </div>
  );
}
