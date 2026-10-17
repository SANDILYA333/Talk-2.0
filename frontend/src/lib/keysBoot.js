import { upgradeIdentity, ensureSpk } from "../storage/keystore";

export async function bootKeys(uid) {
  const r = await upgradeIdentity(uid);
  if (r.status !== "ok") return r; // missing-local: the Connect ID reset flow handles it
  await ensureSpk(uid);
  return r;
}
