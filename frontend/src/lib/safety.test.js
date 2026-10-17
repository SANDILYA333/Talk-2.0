import "fake-indexeddb/auto";
import { describe, it, expect } from "vitest";
import { set, get } from "idb-keyval";
import { safetyNumber, checkContact, markVerified, acceptKeyChange } from "./safety.js";

const b64 = (n) => Buffer.from(new Uint8Array(32).fill(n)).toString("base64");
const A = { ik: b64(1), sik: b64(2) };
const B = { ik: b64(3), sik: b64(4) };
let n = 0;
const ids = () => [`me${++n}`, `peer${n}`];

describe("safetyNumber v2", () => {
  it("is symmetric, 12 groups of 5 digits, deterministic", async () => {
    const x = await safetyNumber(A, B);
    expect(x).toEqual(await safetyNumber(B, A));
    expect(x).toEqual(await safetyNumber(A, B));
    expect(x.length).toBe(12);
    expect(x.every((g) => /^\d{5}$/.test(g))).toBe(true);
  });
  it("changes if any single key changes", async () => {
    const base = (await safetyNumber(A, B)).join();
    expect((await safetyNumber(A, { ...B, sik: b64(9) })).join()).not.toBe(base);
    expect((await safetyNumber(A, { ...B, ik: b64(9) })).join()).not.toBe(base);
    expect((await safetyNumber({ ...A, sik: b64(9) }, B)).join()).not.toBe(base);
  });
  it("swapping a party's ik and sik changes the number", async () => {
    expect((await safetyNumber(A, { ik: B.sik, sik: B.ik })).join()).not.toBe((await safetyNumber(A, B)).join());
  });
});

describe("checkContact", () => {
  it("pins on first sight", async () => {
    const [me, peer] = ids();
    const r = await checkContact(me, peer, B);
    expect(r).toMatchObject({ status: "new", verified: false });
    expect(await get(`contact:${me}:${peer}`)).toMatchObject({ ik: B.ik, sik: B.sik, verified: false });
  });
  it("no sik yet: status no-keys, nothing pinned", async () => {
    const [me, peer] = ids();
    expect((await checkContact(me, peer, { ik: B.ik, sik: null })).status).toBe("no-keys");
    expect(await get(`contact:${me}:${peer}`)).toBeUndefined();
  });
  it("same keys stay ok and verified persists", async () => {
    const [me, peer] = ids();
    await checkContact(me, peer, B);
    await markVerified(me, peer, B);
    expect(await checkContact(me, peer, B)).toMatchObject({ status: "ok", verified: true });
  });
  it("changed ik or changed sik is flagged", async () => {
    const [me, peer] = ids();
    await checkContact(me, peer, B);
    expect((await checkContact(me, peer, { ...B, ik: b64(9) })).status).toBe("changed");
    expect((await checkContact(me, peer, { ...B, sik: b64(9) })).status).toBe("changed");
  });
  it("acceptKeyChange re-pins unverified", async () => {
    const [me, peer] = ids();
    await checkContact(me, peer, B); await markVerified(me, peer, B);
    const next = { ik: b64(9), sik: b64(8) };
    await acceptKeyChange(me, peer, next);
    expect(await checkContact(me, peer, next)).toMatchObject({ status: "ok", verified: false });
  });
  it("legacy G0 record migrates once and resets verified", async () => {
    const [me, peer] = ids();
    await set(`contact:${me}:${peer}`, { key: B.ik, verified: true });
    const r = await checkContact(me, peer, B);
    expect(r).toMatchObject({ status: "ok", verified: false, upgraded: true });
    expect(await get(`contact:${me}:${peer}`)).toMatchObject({ ik: B.ik, sik: B.sik, verified: false });
    expect((await checkContact(me, peer, B)).upgraded).toBeFalsy();
  });
  it("legacy record with a different ik is flagged", async () => {
    const [me, peer] = ids();
    await set(`contact:${me}:${peer}`, { key: b64(7), verified: true });
    expect((await checkContact(me, peer, B)).status).toBe("changed");
  });
});
