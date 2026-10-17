import { upgradeIdentity } from "../storage/keystore";
import { uploadBundle, syncOpks } from "./keyApi";

export async function bootKeys(uid) {
  const r = await upgradeIdentity(uid);
  if (r.status !== "ok") return r; // missing-local: the Connect ID reset flow handles it
  await uploadBundle(uid);
  await syncOpks(uid);
  return r;
}
