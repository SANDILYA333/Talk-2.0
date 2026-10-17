import "fake-indexeddb/auto";
import { describe, it, expect } from "vitest";
import { get, set } from "idb-keyval";
import nacl from "tweetnacl";
import { xPub } from "../crypto/primitives.js";
import { signIkBinding, verifyBundle } from "../crypto/index.js";
import {
  loadIdentity, upgradeIdentity, ensureSpk, getSpkPriv,
  generateOpks, getOpkPriv, takeOpkPriv, countOpks,
  putPlain, getPlain, delPlain, wipeKeyMaterial, SPK_ROTATE_MS, SPK_KEEP_MS,
} from "./keystore.js";

const DAY = 86_400_000;
const T0 = 1_700_000_000_000;
let n = 0;
const uid = () => (++n).toString(16).padStart(24, "0");
const b64 = (u) => Buffer.from(u).toString("base64");

async function seedLegacy(u) {
  const kp = nacl.box.keyPair(); 
  await set(`identity:${u}`, { publicKey: b64(kp.publicKey), secretKey: b64(kp.secretKey) });
  return kp;
}

describe("legacy compatibility", () => {
  it("tweetnacl X25519 keys are valid noble keys", () => {
    const kp = nacl.box.keyPair();
    expect(xPub(kp.secretKey)).toEqual(kp.publicKey);
  });
});

describe("identity upgrade", () => {
  it("adds SIK and leaves IK byte-identical", async () => {
    const u = uid();
    const kp = await seedLegacy(u);
    const r = await upgradeIdentity(u);
    expect(r.status).toBe("ok");
    const rec = await get(`identity:${u}`);
    expect(rec.publicKey).toBe(b64(kp.publicKey));
    expect(rec.secretKey).toBe(b64(kp.secretKey));
    expect(rec.sik.pub).toBeTruthy();
    const id = await loadIdentity(u);
    expect(id.ik.pub).toEqual(kp.publicKey);
    expect(id.sik.pub.length).toBe(32);
    expect(id.sik.priv.length).toBe(32);
  });
  it("is idempotent", async () => {
    const u = uid();
    await seedLegacy(u);
    const a = await upgradeIdentity(u);
    const b = await upgradeIdentity(u);
    expect(b.sikPub).toBe(a.sikPub);
  });
  it("concurrent calls produce ONE signing key", async () => {
    const u = uid();
    await seedLegacy(u);
    const rs = await Promise.all([1, 2, 3, 4, 5].map(() => upgradeIdentity(u)));
    expect(new Set(rs.map((r) => r.sikPub)).size).toBe(1);
  });
  it("missing identity: reports missing-local, creates nothing, SPK refuses", async () => {
    const u = uid();
    expect((await upgradeIdentity(u)).status).toBe("missing-local");
    expect(await get(`identity:${u}`)).toBeUndefined();
    await expect(ensureSpk(u, T0)).rejects.toThrow();
  });
  it("is isolated per user", async () => {
    const a = uid(), b = uid();
    await seedLegacy(a); await seedLegacy(b);
    const ra = await upgradeIdentity(a);
    expect((await loadIdentity(b)).sik).toBeNull();
    const rb = await upgradeIdentity(b);
    expect(rb.sikPub).not.toBe(ra.sikPub);
  });
});

describe("signed prekey", () => {
  it("first call creates id 1 with a valid signature", async () => {
    const u = uid();
    await seedLegacy(u); await upgradeIdentity(u);
    const spk = await ensureSpk(u, T0);
    expect(spk.id).toBe(1);
    expect(spk.rotated).toBe(true);
    const id = await loadIdentity(u);
    const bundle = {
      ikPub: id.ik.pub, sikPub: id.sik.pub,
      ikBinding: signIkBinding(id.sik.priv, id.ik.pub),
      spk: { id: spk.id, pub: spk.pub, sig: spk.sig },
    };
    expect(verifyBundle(bundle)).toEqual({ ok: true });
  });
  it("does not rotate early, rotates at 7 days, keeps the old key", async () => {
    const u = uid();
    await seedLegacy(u); await upgradeIdentity(u);
    await ensureSpk(u, T0);
    const early = await ensureSpk(u, T0 + SPK_ROTATE_MS - 1);
    expect(early.id).toBe(1);
    expect(early.rotated).toBe(false);
    const next = await ensureSpk(u, T0 + SPK_ROTATE_MS);
    expect(next.id).toBe(2);
    expect(next.rotated).toBe(true);
    expect(await getSpkPriv(u, 1)).not.toBeNull(); 
    expect(await getSpkPriv(u, 2)).not.toBeNull();
  });
  it("prunes a retired key 30 days after retirement; ids never repeat", async () => {
    const u = uid();
    await seedLegacy(u); await upgradeIdentity(u);
    await ensureSpk(u, T0);
    await ensureSpk(u, T0 + SPK_ROTATE_MS);               
    const later = await ensureSpk(u, T0 + SPK_ROTATE_MS + SPK_KEEP_MS);
    expect(later.id).toBe(3);
    expect(await getSpkPriv(u, 1)).toBeNull();
    expect(await getSpkPriv(u, 2)).not.toBeNull();
  });
  it("concurrent calls create ONE key", async () => {
    const u = uid();
    await seedLegacy(u); await upgradeIdentity(u);
    const rs = await Promise.all([1, 2, 3, 4, 5].map(() => ensureSpk(u, T0)));
    expect(new Set(rs.map((r) => r.id))).toEqual(new Set([1]));
    expect(await getSpkPriv(u, 2)).toBeNull();
  });
  it("unknown or invalid id gives null", async () => {
    const u = uid();
    expect(await getSpkPriv(u, 99)).toBeNull();
    expect(await getSpkPriv(u, undefined)).toBeNull();
    expect(await getSpkPriv(u, "1")).toBeNull();
  });
});

describe("one-time prekeys", () => {
  it("generates 50, then continues numbering", async () => {
    const u = uid();
    const a = await generateOpks(u);
    expect(a.length).toBe(50);
    expect(a[0].id).toBe(1);
    expect(a[49].id).toBe(50);
    expect(a[0].pub.length).toBe(32);
    expect("priv" in a[0]).toBe(false); 
    const b = await generateOpks(u);
    expect(b[0].id).toBe(51);
    expect(await countOpks(u)).toBe(100);
  });
  it("takeOpkPriv returns the key once, then null", async () => {
    const u = uid();
    await generateOpks(u);
    const k = await takeOpkPriv(u, 5);
    expect(k.length).toBe(32);
    expect(await takeOpkPriv(u, 5)).toBeNull();
    expect(await getOpkPriv(u, 5)).toBeNull();
    expect(await countOpks(u)).toBe(49);
  });
  it("concurrent takes: exactly one winner", async () => {
    const u = uid();
    await generateOpks(u);
    const rs = await Promise.all([1, 2, 3, 4, 5].map(() => takeOpkPriv(u, 7)));
    expect(rs.filter(Boolean).length).toBe(1);
  });
});

describe("plaintext cache", () => {
  it("round trips and is isolated per user", async () => {
    const a = uid(), b = uid();
    await putPlain(a, "m1", { body: "hi", ts: 1 });
    expect(await getPlain(a, "m1")).toEqual({ body: "hi", ts: 1 });
    expect(await getPlain(b, "m1")).toBeNull();
    await delPlain(a, "m1");
    expect(await getPlain(a, "m1")).toBeNull();
  });
});

describe("wipeKeyMaterial", () => {
  it("removes prekeys, keeps identity and plain cache, ids restart", async () => {
    const u = uid();
    await seedLegacy(u); await upgradeIdentity(u);
    await ensureSpk(u, T0); await generateOpks(u);
    await putPlain(u, "m1", { body: "keep", ts: 1 });
    await wipeKeyMaterial(u);
    expect(await getSpkPriv(u, 1)).toBeNull();
    expect(await countOpks(u)).toBe(0);
    expect(await get(`identity:${u}`)).toBeDefined();
    expect(await getPlain(u, "m1")).toEqual({ body: "keep", ts: 1 });
    expect((await ensureSpk(u, T0)).id).toBe(1);
  });
});
