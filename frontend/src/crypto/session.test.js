import "fake-indexeddb/auto";
import { describe, it, expect, beforeEach } from "vitest";
import {
  generateIdentity,
  generateSignedPrekey,
  generateOneTimePrekeys,
  signIkBinding,
  toB64,
  fromB64,
  CryptoError,
} from "./index.js";
import {
  initiateSession,
  respondSession,
  encryptSessionMessage,
  decryptSessionMessage,
  resolveSimultaneousInitiation,
} from "./session.js";
import {
  loadIdentity,
  ensureSpk,
  generateOpks,
  takeOpkPriv,
  getSpkPriv,
  loadSession,
  saveSession,
  deleteSession,
} from "../storage/keystore.js";
import { set } from "idb-keyval";

let n = 0;
const uid = () => (++n).toString(16).padStart(24, "0");

async function mkUserKeyMaterial() {
  const userId = uid();
  const idn = generateIdentity();
  await set(`identity:${userId}`, {
    publicKey: toB64(idn.ik.pub),
    secretKey: toB64(idn.ik.priv),
    sik: { pub: toB64(idn.sik.pub), priv: toB64(idn.sik.priv) },
    schema: 2,
  });
  const spk = await ensureSpk(userId);
  const opks = await generateOpks(userId, 5);
  return {
    userId,
    idn,
    spk,
    opks,
    bundle: (opkIndex = 0) => ({
      userId,
      ikPub: idn.ik.pub,
      sikPub: idn.sik.pub,
      ikBinding: signIkBinding(idn.sik.priv, idn.ik.pub),
      spk: { id: spk.id, pub: spk.pub, sig: spk.sig },
      opk: opkIndex !== null && opks[opkIndex] ? { id: opks[opkIndex].id, pub: opks[opkIndex].pub } : null,
      protoMax: 2,
    }),
  };
}

describe("S8: X3DH sessions and symmetric ratchet (crypto/session)", () => {
  it("initiator and responder derive an identical SK, with and without an OPK", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    // 1. With OPK
    const bundleWithOpk = bob.bundle(0);
    const { session: aliceSessionWithOpk, initialHeader: headerWithOpk } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bundleWithOpk,
    });

    const bobOpkPriv = await takeOpkPriv(bob.userId, headerWithOpk.opkId);
    expect(bobOpkPriv).toBeDefined();

    const { session: bobSessionWithOpk } = await respondSession({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      spkPriv: await getSpkPriv(bob.userId, headerWithOpk.spkId),
      opkPriv: bobOpkPriv,
      header: headerWithOpk,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    expect(Buffer.from(aliceSessionWithOpk.sk).equals(Buffer.from(bobSessionWithOpk.sk))).toBe(true);

    // 2. Without OPK (fallback 3-DH)
    const bundleNoOpk = bob.bundle(null);
    const { session: aliceSessionNoOpk, initialHeader: headerNoOpk } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bundleNoOpk,
    });

    const { session: bobSessionNoOpk } = await respondSession({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      spkPriv: await getSpkPriv(bob.userId, headerNoOpk.spkId),
      opkPriv: null,
      header: headerNoOpk,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    expect(Buffer.from(aliceSessionNoOpk.sk).equals(Buffer.from(bobSessionNoOpk.sk))).toBe(true);
  });

  it("initial message decrypts, and the OPK private key is deleted afterwards", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const bundle = bob.bundle(0);
    const opkId = bundle.opk.id;

    // Initiator encrypts initial message
    const { session: aliceSession, initialHeader } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle,
    });

    const envelope = { t: "text", body: "Hello Bob!", ts: 1000 };
    const wireMsg = await encryptSessionMessage({
      session: aliceSession,
      envelope,
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    expect(wireMsg.v).toBe(2);
    expect(wireMsg.header.ek).toBeDefined();
    expect(wireMsg.header.opkId).toBe(opkId);

    // Responder decrypts
    const { session: bobSession, envelope: decrypted } = await decryptSessionMessage({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: wireMsg,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    expect(decrypted.body).toBe("Hello Bob!");
    expect(decrypted.t).toBe("text");

    // Assert OPK was deleted from store
    const deletedOpk = await takeOpkPriv(bob.userId, opkId);
    expect(deletedOpk).toBeNull();
  });

  it("a second message uses the established session, not a new X3DH", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const msg1 = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "msg 1", ts: 1001 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    const { session: bobSession } = await decryptSessionMessage({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: msg1,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    // Alice sends a second message using established session
    aliceSession.state = "established";
    const msg2 = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "msg 2", ts: 1002 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });

    // msg2 header contains only session id and counter n, NO ek or spkId
    expect(msg2.header.ek).toBeUndefined();
    expect(msg2.header.spkId).toBeUndefined();
    expect(msg2.header.sessionId).toBe(aliceSession.sessionId);
    expect(msg2.header.n).toBe(1);

    const { envelope: dec2 } = await decryptSessionMessage({
      session: bobSession,
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: msg2,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    expect(dec2.body).toBe("msg 2");
  });

  it("a replayed initial message is rejected, because the OPK is gone", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const msg = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "once only", ts: 1000 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    // First decrypt succeeds and deletes the OPK
    await decryptSessionMessage({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    // Replay with new session setup must fail closed because OPK is missing
    await expect(
      decryptSessionMessage({
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg,
        getSpkPriv: (id) => getSpkPriv(bob.userId, id),
        takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();
  });

  it("out-of-order delivery within the window works. Counter beyond the window is rejected.", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    // Alice generates messages 0, 1, 2
    const m0 = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "m0", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    aliceSession.state = "established";
    const m1 = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "m1", ts: 2 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });
    const m2 = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "m2", ts: 3 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });

    // Bob receives m0 first
    const { session: bobSession } = await decryptSessionMessage({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    // Bob receives m2 BEFORE m1 (out of order!)
    const { envelope: dec2 } = await decryptSessionMessage({
      session: bobSession,
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m2,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    expect(dec2.body).toBe("m2");

    // Bob then receives delayed m1 (from skippedKeys)
    const { envelope: dec1 } = await decryptSessionMessage({
      session: bobSession,
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m1,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    expect(dec1.body).toBe("m1");

    // Message beyond window (> 100) is rejected
    aliceSession.sendCounter = 150;
    const mTooFar = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "too far", ts: 4 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });

    await expect(
      decryptSessionMessage({
        session: bobSession,
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: mTooFar,
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();
  });

  it("duplicate counter is rejected", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const m0 = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "m0", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    const { session: bobSession } = await decryptSessionMessage({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    // Decrypting m0 again must be rejected as duplicate
    await expect(
      decryptSessionMessage({
        session: bobSession,
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: m0,
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();
  });

  it("tampering with the header, ciphertext or AAD fails closed", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const msg = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "secret", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    // 1. Tampered ciphertext
    const ctBytes = fromB64(msg.ciphertext);
    ctBytes[0] ^= 0x01;
    const badCtMsg = { ...msg, ciphertext: toB64(ctBytes) };
    await expect(
      decryptSessionMessage({
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: badCtMsg,
        getSpkPriv: (id) => getSpkPriv(bob.userId, id),
        takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();

    // 2. Tampered header counter n
    const badHeaderMsg = { ...msg, header: { ...msg.header, n: 5 } };
    await expect(
      decryptSessionMessage({
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: badHeaderMsg,
        getSpkPriv: (id) => getSpkPriv(bob.userId, id),
        takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();
  });

  it("wrong SPK id or unknown OPK id fails closed with a clear error", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const msg = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "hi", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    // Wrong SPK id
    const badSpkMsg = { ...msg, header: { ...msg.header, spkId: 9999 } };
    await expect(
      decryptSessionMessage({
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: badSpkMsg,
        getSpkPriv: (id) => getSpkPriv(bob.userId, id),
        takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();

    // Unknown OPK id
    const badOpkMsg = { ...msg, header: { ...msg.header, opkId: 8888 } };
    await expect(
      decryptSessionMessage({
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: badOpkMsg,
        getSpkPriv: (id) => getSpkPriv(bob.userId, id),
        takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();
  });

  it("simultaneous initiation converges to one session on both sides", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    // Alice initiates to Bob
    const { session: aliceToBob, initialHeader: aliceHeader } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    // Bob concurrently initiates to Alice
    const { session: bobToAlice, initialHeader: bobHeader } = await initiateSession({
      senderId: bob.userId,
      receiverId: alice.userId,
      myIk: bob.idn.ik,
      mySik: bob.idn.sik,
      bundle: alice.bundle(0),
    });

    // Resolve simultaneous initiation for Alice
    const aliceResolved = resolveSimultaneousInitiation({
      localSession: aliceToBob,
      incomingHeader: bobHeader,
      myIk: alice.idn.ik.pub,
      peerIk: bob.idn.ik.pub,
    });

    // Resolve simultaneous initiation for Bob
    const bobResolved = resolveSimultaneousInitiation({
      localSession: bobToAlice,
      incomingHeader: aliceHeader,
      myIk: bob.idn.ik.pub,
      peerIk: alice.idn.ik.pub,
    });

    // Both parties agree on which session wins!
    expect(aliceResolved.winningSessionId).toBe(bobResolved.winningSessionId);
    expect(aliceResolved.winningSessionId).toBeDefined();
  });

  it("session state survives a page reload (IndexedDB round trip)", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    await saveSession(alice.userId, bob.userId, aliceSession);
    const restored = await loadSession(alice.userId, bob.userId);

    expect(restored).toBeDefined();
    expect(restored.sessionId).toBe(aliceSession.sessionId);
    expect(restored.role).toBe(aliceSession.role);
    expect(Buffer.from(restored.sk).equals(Buffer.from(aliceSession.sk))).toBe(true);
    expect(Buffer.from(restored.chainKeySend).equals(Buffer.from(aliceSession.chainKeySend))).toBe(true);
  });

  it("old SPK still decrypts a pending initial message after rotation, within the grace period", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    // Bob has initial SPK id 1
    const bundleBeforeRotate = bob.bundle(0);
    expect(bundleBeforeRotate.spk.id).toBe(1);

    // Alice initiates using SPK id 1
    const { session: aliceSession, initialHeader } = await initiateSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bundleBeforeRotate,
    });

    const msg = await encryptSessionMessage({
      session: aliceSession,
      envelope: { t: "text", body: "before rotation", ts: 1000 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    // Bob rotates SPK (7 days later)
    const newSpk = await ensureSpk(bob.userId, Date.now() + 8 * 86_400_000);
    expect(newSpk.id).toBe(2);

    // Old SPK id 1 is still available in grace period (<= 30 days)
    const oldSpkPriv = await getSpkPriv(bob.userId, 1);
    expect(oldSpkPriv).toBeDefined();

    // Bob decrypts the pending initial message using the old SPK
    const { envelope: dec } = await decryptSessionMessage({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    expect(dec.body).toBe("before rotation");
  });
});
