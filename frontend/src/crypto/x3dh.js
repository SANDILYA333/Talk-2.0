import { concat } from "./bytes.js";
import { dh, kdf } from "./primitives.js";

const F = new Uint8Array(32).fill(0xff);
const INFO = "talk/x3dh/v1";

export function x3dhInitiate({ ikPriv, ekPriv, ikPubB, spkPubB, opkPubB, info = INFO }) {
  const parts = [F, dh(ikPriv, spkPubB), dh(ekPriv, ikPubB), dh(ekPriv, spkPubB)];
  if (opkPubB) parts.push(dh(ekPriv, opkPubB));
  return kdf(concat(...parts), info);
}

export function x3dhRespond({ ikPriv, spkPriv, opkPriv, ikPubA, ekPubA, info = INFO }) {
  const parts = [F, dh(spkPriv, ikPubA), dh(ikPriv, ekPubA), dh(spkPriv, ekPubA)];
  if (opkPriv) parts.push(dh(opkPriv, ekPubA));
  return kdf(concat(...parts), info);
}

