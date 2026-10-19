import "fake-indexeddb/auto";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { set } from "idb-keyval";
import nacl from "tweetnacl";

vi.mock("./axios", () => ({ axiosInstance: { put: vi.fn(), post: vi.fn(), get: vi.fn() } }));
import { axiosInstance as ax } from "./axios";
import { uploadBundle, syncOpks, parseBundle } from "./keyApi.js";
import { bootKeys } from "./keysBoot.js";
import { upgradeIdentity, countOpks } from "../storage/keystore.js";
import { verifyBundle, fromB64 } from "../crypto/index.js";

let n = 0;
const uid = () => (++n).toString(16).padStart(24, "0");
const b64 = (u) => Buffer.from(u).toString("base64");

async function legacy(u) {
  const kp = nacl.box.keyPair();
  await set(`identity:${u}`, { publicKey: b64(kp.publicKey), secretKey: b64(kp.secretKey) });
  await upgradeIdentity(u);
  return kp;
}
beforeEach(() => { ax.put.mockReset(); ax.post.mockReset(); ax.get.mockReset(); });

describe("uploadBundle", () => {
  it("sends a bundle that passes verifyBundle after the server round trip", async () => {
    const u = uid(); const kp = await legacy(u);
    ax.put.mockResolvedValue({ data: { ok: true } });
    await uploadBundle(u);
    const [path, sent] = ax.put.mock.calls[0];
    expect(path).toBe("/keys/bundle");
    expect(sent.protoMax).toBe(2);
    const parsed = parseBundle({ userId: u, ikPub: b64(kp.publicKey), sikPub: sent.sik, ikBinding: sent.ikBinding, spk: sent.spk, opk: null, protoMax: 2 });
    expect(verifyBundle(parsed)).toEqual({ ok: true });
  });
  it("throws without a signing key", async () => {
    await expect(uploadBundle(uid())).rejects.toThrow();
  });
});

describe("syncOpks", () => {
  it("does nothing at 20 or more", async () => {
    const u = uid(); await legacy(u);
    ax.get.mockResolvedValue({ data: { count: 20 } });
    await syncOpks(u);
    expect(ax.post).not.toHaveBeenCalled();
    expect(await countOpks(u)).toBe(0);
  });
  it("uploads 50 public keys at 19", async () => {
    const u = uid(); await legacy(u);
    ax.get.mockResolvedValue({ data: { count: 19 } });
    ax.post.mockResolvedValue({ data: {} });
    await syncOpks(u);
    const [path, sent] = ax.post.mock.calls[0];
    expect(path).toBe("/keys/opks");
    expect(sent.keys.length).toBe(50);
    expect(sent.keys.every((k) => fromB64(k.pub).length === 32 && !("priv" in k))).toBe(true);
    expect(await countOpks(u)).toBe(50);
  });
});

describe("parseBundle", () => {
  it("rejects malformed server data", () => {
    expect(() => parseBundle({ ikPub: "zzz" })).toThrow();
  });
});

describe("bootKeys", () => {
  it("missing identity: no network calls", async () => {
    const r = await bootKeys(uid());
    expect(r.status).toBe("missing-local");
    expect(ax.put).not.toHaveBeenCalled();
    expect(ax.get).not.toHaveBeenCalled();
  });
  it("upgrades, uploads the bundle once, syncs OPKs once", async () => {
    const u = uid(); await legacy(u);
    ax.put.mockResolvedValue({ data: {} }); ax.post.mockResolvedValue({ data: {} });
    ax.get.mockResolvedValue({ data: { count: 0 } });
    await bootKeys(u);
    expect(ax.put).toHaveBeenCalledTimes(1);
    expect(ax.get).toHaveBeenCalledTimes(1);
    expect(ax.post).toHaveBeenCalledTimes(1);
  });
});
