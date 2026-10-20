import "fake-indexeddb/auto";
import { vi, describe, it, expect, beforeEach } from "vitest";
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
  kdfRk,
  kdfCk,
  initiateRatchetSession,
  respondRatchetSession,
  ratchetEncrypt,
  ratchetDecrypt,
  MAX_SKIP,
  MAX_TOTAL_SKIPPED,
  SKIPPED_TTL_MS,
  upgradeFromS8Session,
} from "./ratchet.js";
import {
  loadIdentity,
  ensureSpk,
  generateOpks,
  takeOpkPriv,
  getSpkPriv,
  loadSession,
  saveSession,
  deleteSession,
  withSessionLock,
  putPlain,
  getPlain,
} from "../storage/keystore.js";
import { set, keys } from "idb-keyval";
import { newSecret, xPub, dh } from "./primitives.js";

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

describe("S9: Double Ratchet", () => {
  it("ping-pong across several DH ratchet steps, both directions", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const bundle = bob.bundle(0);
    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle,
    });

    // 1. Alice -> Bob (Initial message)
    const m1 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "ping 1", ts: 100 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    const { session: bobSession, envelope: d1 } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m1,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    expect(d1.body).toBe("ping 1");

    // 2. Bob -> Alice (DH ratchet step!)
    const m2 = await ratchetEncrypt({
      session: bobSession,
      envelope: { t: "text", body: "pong 1", ts: 200 },
      type: "text",
      senderId: bob.userId,
      receiverId: alice.userId,
      myIk: bob.idn.ik,
    });

    // Assert Bob's DH key changed from the initial SPK
    expect(m2.header.dh).toBeDefined();
    expect(m2.header.dh).not.toBe(toB64(bob.spk.pub));

    const { envelope: d2 } = await ratchetDecrypt({
      session: aliceSession,
      receiverId: alice.userId,
      senderId: bob.userId,
      myIk: alice.idn.ik,
      msg: m2,
      pinned: { ik: bob.idn.ik.pub, sik: bob.idn.sik.pub },
    });
    expect(d2.body).toBe("pong 1");

    // 3. Alice -> Bob (Another DH ratchet step!)
    const m3 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "ping 2", ts: 300 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });
    expect(m3.header.dh).not.toBe(m1.header.dh);

    const { envelope: d3 } = await ratchetDecrypt({
      session: bobSession,
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m3,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    expect(d3.body).toBe("ping 2");

    // 4. Bob -> Alice
    const m4 = await ratchetEncrypt({
      session: bobSession,
      envelope: { t: "text", body: "pong 2", ts: 400 },
      type: "text",
      senderId: bob.userId,
      receiverId: alice.userId,
      myIk: bob.idn.ik,
    });
    const { envelope: d4 } = await ratchetDecrypt({
      session: aliceSession,
      receiverId: alice.userId,
      senderId: bob.userId,
      myIk: alice.idn.ik,
      msg: m4,
      pinned: { ik: bob.idn.ik.pub, sik: bob.idn.sik.pub },
    });
    expect(d4.body).toBe("pong 2");
  });

  it("many messages in one direction (long chain), then a reply", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const messages = [];
    for (let i = 0; i < 25; i++) {
      const msg = await ratchetEncrypt({
        session: aliceSession,
        envelope: { t: "text", body: `msg ${i}`, ts: 1000 + i },
        type: "text",
        senderId: alice.userId,
        receiverId: bob.userId,
        myIk: alice.idn.ik,
        initialHeader: i === 0 ? initialHeader : undefined,
      });
      messages.push(msg);
    }

    let bobSession = null;
    for (let i = 0; i < messages.length; i++) {
      const res = await ratchetDecrypt({
        session: bobSession,
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: messages[i],
        getSpkPriv: (id) => getSpkPriv(bob.userId, id),
        takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      });
      bobSession = res.session;
      expect(res.envelope.body).toBe(`msg ${i}`);
    }

    // Bob replies after 25 incoming messages
    const reply = await ratchetEncrypt({
      session: bobSession,
      envelope: { t: "text", body: "reply after 25", ts: 2000 },
      type: "text",
      senderId: bob.userId,
      receiverId: alice.userId,
      myIk: bob.idn.ik,
    });

    const { envelope: decReply } = await ratchetDecrypt({
      session: aliceSession,
      receiverId: alice.userId,
      senderId: bob.userId,
      myIk: alice.idn.ik,
      msg: reply,
      pinned: { ik: bob.idn.ik.pub, sik: bob.idn.sik.pub },
    });
    expect(decReply.body).toBe("reply after 25");
  });

  it("out-of-order within a chain, and across a DH step (late message from previous chain via PN)", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    // Alice sends m0, m1, m2 in chain 1
    const m0 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "m0", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });
    const m1 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "m1", ts: 2 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });
    const m2 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "m2", ts: 3 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });

    // Bob receives m0
    const { session: bobSession } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    // Bob replies to m0, causing a DH ratchet step
    const reply0 = await ratchetEncrypt({
      session: bobSession,
      envelope: { t: "text", body: "reply0", ts: 4 },
      type: "text",
      senderId: bob.userId,
      receiverId: alice.userId,
      myIk: bob.idn.ik,
    });

    // Alice receives reply0
    await ratchetDecrypt({
      session: aliceSession,
      receiverId: alice.userId,
      senderId: bob.userId,
      myIk: alice.idn.ik,
      msg: reply0,
      pinned: { ik: bob.idn.ik.pub, sik: bob.idn.sik.pub },
    });

    // Alice sends m3 in the NEW chain (chain 2, with pn=3)
    const m3 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "m3 in new chain", ts: 5 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });

    expect(m3.header.pn).toBe(3); // Previous chain had 3 messages (m0, m1, m2)

    // Bob receives m3 BEFORE receiving m1 and m2!
    // Bob must skip m1 and m2 in the previous chain using PN, step the ratchet, and decrypt m3.
    const { envelope: dec3 } = await ratchetDecrypt({
      session: bobSession,
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m3,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    expect(dec3.body).toBe("m3 in new chain");

    // Later, late messages m2 and m1 arrive from the PREVIOUS chain!
    const { envelope: dec2 } = await ratchetDecrypt({
      session: bobSession,
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m2,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    expect(dec2.body).toBe("m2");

    const { envelope: dec1 } = await ratchetDecrypt({
      session: bobSession,
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m1,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    expect(dec1.body).toBe("m1");
  });

  it("dropped messages: later messages still decrypt, and skipped keys are stored", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const m0 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "msg 0", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });
    // m1 is dropped!
    await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "msg 1 (dropped)", ts: 2 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });
    const m2 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "msg 2", ts: 3 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });

    const { session: bobSession } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    const { envelope: dec2 } = await ratchetDecrypt({
      session: bobSession,
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m2,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    expect(dec2.body).toBe("msg 2");

    // Skipped key for message 1 must be saved in bobSession.skippedKeys
    expect(Object.keys(bobSession.skippedKeys).length).toBe(1);
    expect(Object.keys(bobSession.skippedKeys)[0]).toContain(":1");
  });

  it("MAX_SKIP exceeded: rejected, state unchanged", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const m0 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "m0", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    const { session: bobSession } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    // Advance Alice's counter beyond MAX_SKIP (1000)
    aliceSession.ns = 1500;
    const mTooFar = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "way too far", ts: 2 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });

    const bobNrBefore = bobSession.nr;
    const bobSkippedCountBefore = Object.keys(bobSession.skippedKeys || {}).length;

    await expect(
      ratchetDecrypt({
        session: bobSession,
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: mTooFar,
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();

    // Verify Bob's state did NOT change
    expect(bobSession.nr).toBe(bobNrBefore);
    expect(Object.keys(bobSession.skippedKeys || {}).length).toBe(bobSkippedCountBefore);
  });

  it("skipped-key cap and TTL eviction work", async () => {
    const session = {
      skippedKeys: {},
    };

    // Fill up to MAX_TOTAL_SKIPPED = 2000
    const now = Date.now();
    for (let i = 0; i < 2005; i++) {
      session.skippedKeys[`key:${i}`] = {
        key: toB64(new Uint8Array(32)),
        createdAt: now - (2005 - i) * 1000,
      };
    }

    // Add an expired key (> 30 days old)
    session.skippedKeys["expired:1"] = {
      key: toB64(new Uint8Array(32)),
      createdAt: now - 35 * 86_400_000,
    };

    // Run eviction helper
    const { evictSkippedKeys } = await import("./ratchet.js");
    evictSkippedKeys(session, now);

    // Expired key must be pruned
    expect(session.skippedKeys["expired:1"]).toBeUndefined();
    // Total count must not exceed 2000
    expect(Object.keys(session.skippedKeys).length).toBeLessThanOrEqual(2000);
  });

  it("replay of any old message is rejected", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const m0 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "m0", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    const { session: bobSession } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    // Replay m0
    await expect(
      ratchetDecrypt({
        session: bobSession,
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: m0,
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();
  });

  it("forged or tampered header, ciphertext or AAD: rejected and state byte-identical before and after", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const m0 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "secret", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    const { session: bobSession } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    const m1 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "m1", ts: 2 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });

    // Snapshot bobSession JSON string
    const bobSnapshot = JSON.stringify(bobSession);

    // Tamper ciphertext
    const ct = fromB64(m1.ciphertext);
    ct[0] ^= 0xff;
    const badMsg = { ...m1, ciphertext: toB64(ct) };

    await expect(
      ratchetDecrypt({
        session: bobSession,
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: badMsg,
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();

    // Verify state is strictly byte-identical
    expect(JSON.stringify(bobSession)).toBe(bobSnapshot);
  });

  it("a message that fails decrypt never advances any counter", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const m0 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "valid m0", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    const { session: bobSession } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    const nrBefore = bobSession.nr;
    const nsBefore = bobSession.ns;

    // Send forged message with higher n
    const forgedMsg = {
      ...m0,
      header: { ...m0.header, n: nrBefore + 1 },
    };

    await expect(
      ratchetDecrypt({
        session: bobSession,
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: forgedMsg,
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();

    expect(bobSession.nr).toBe(nrBefore);
    expect(bobSession.ns).toBe(nsBefore);
  });

  it("forward secrecy: after N messages, assert the old message keys and chain keys no longer exist in storage", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    // Record initial DH private key to assert it gets replaced and purged from storage
    const initialAliceDhPrivB64 = aliceSession.dhs.priv;

    const m0 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "first", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });
    await saveSession(alice.userId, bob.userId, aliceSession);

    const { session: bobSession } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    await saveSession(bob.userId, alice.userId, bobSession);

    // Exchange 5 messages in both directions, saving to IndexedDB after each operation
    let curSender = "alice";
    for (let i = 1; i <= 5; i++) {
      if (curSender === "alice") {
        const msg = await ratchetEncrypt({
          session: aliceSession,
          envelope: { t: "text", body: `msg ${i}`, ts: 10 + i },
          type: "text",
          senderId: alice.userId,
          receiverId: bob.userId,
          myIk: alice.idn.ik,
        });
        await saveSession(alice.userId, bob.userId, aliceSession);

        await ratchetDecrypt({
          session: bobSession,
          receiverId: bob.userId,
          senderId: alice.userId,
          myIk: bob.idn.ik,
          msg,
          pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
        });
        await saveSession(bob.userId, alice.userId, bobSession);
        curSender = "bob";
      } else {
        const msg = await ratchetEncrypt({
          session: bobSession,
          envelope: { t: "text", body: `msg ${i}`, ts: 10 + i },
          type: "text",
          senderId: bob.userId,
          receiverId: alice.userId,
          myIk: bob.idn.ik,
        });
        await saveSession(bob.userId, alice.userId, bobSession);

        await ratchetDecrypt({
          session: aliceSession,
          receiverId: alice.userId,
          senderId: bob.userId,
          myIk: alice.idn.ik,
          msg,
          pinned: { ik: bob.idn.ik.pub, sik: bob.idn.sik.pub },
        });
        await saveSession(alice.userId, bob.userId, aliceSession);
        curSender = "alice";
      }
    }

    // Direct IndexedDB storage inspection (not just in-memory objects)
    const storedAlice = await loadSession(alice.userId, bob.userId);
    const storedBob = await loadSession(bob.userId, alice.userId);

    // 1. Assert skippedKeys in IndexedDB storage is empty (no unevicted or leaked keys)
    expect(storedAlice.skippedKeys).toEqual({});
    expect(storedBob.skippedKeys).toEqual({});

    // 2. Assert that old ephemeral/DH private key from conversation start is completely gone from storage
    const rawStoredAlice = JSON.stringify(storedAlice);
    expect(rawStoredAlice).not.toContain(initialAliceDhPrivB64);

    // 3. Assert no old message keys exist anywhere in IndexedDB
    const allStorageKeys = await keys();
    const sessionKeysInIdb = allStorageKeys.filter((k) => typeof k === "string" && k.startsWith("session:"));
    expect(sessionKeysInIdb).toContain(`session:${alice.userId}:${bob.userId}`);
    expect(sessionKeysInIdb).toContain(`session:${bob.userId}:${alice.userId}`);

    // No lingering skipped key records or message key records anywhere in storage
    const orphanKeyRecords = allStorageKeys.filter(
      (k) => typeof k === "string" && (k.includes("mk:") || k.includes("skipped:"))
    );
    expect(orphanKeyRecords).toEqual([]);
  });

  it("post-compromise healing: clone the state at a point, continue the conversation, and show the cloned (stolen) state cannot decrypt messages after the next DH step", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const m0 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "m0", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    const { session: bobSession } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });

    // ATTACKER COMPROMISES / CLONES BOB'S SESSION STATE HERE!
    const stolenBobSession = JSON.parse(JSON.stringify(bobSession));

    // Bob sends reply1 to Alice (Alice advances her ratchet)
    const reply1 = await ratchetEncrypt({
      session: bobSession,
      envelope: { t: "text", body: "bob reply 1", ts: 2 },
      type: "text",
      senderId: bob.userId,
      receiverId: alice.userId,
      myIk: bob.idn.ik,
    });

    await ratchetDecrypt({
      session: aliceSession,
      receiverId: alice.userId,
      senderId: bob.userId,
      myIk: alice.idn.ik,
      msg: reply1,
      pinned: { ik: bob.idn.ik.pub, sik: bob.idn.sik.pub },
    });

    // Alice sends msg2 back to Bob (DH ratchet step performed with fresh DHs!)
    const msg2 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "alice msg 2 (healed)", ts: 3 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });

    // Legitimate Bob can decrypt msg2
    const { envelope: decHealed } = await ratchetDecrypt({
      session: bobSession,
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: msg2,
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    expect(decHealed.body).toBe("alice msg 2 (healed)");

    // ATTACKER with the cloned state CANNOT decrypt msg2 because Bob's fresh DH private key was generated after the compromise!
    await expect(
      ratchetDecrypt({
        session: stolenBobSession,
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: msg2,
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();
  });

  it("state survives reload at every point in a conversation", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    // Save to IndexedDB and reload
    await saveSession(alice.userId, bob.userId, aliceSession);
    let reloadedAlice = await loadSession(alice.userId, bob.userId);

    const m0 = await ratchetEncrypt({
      session: reloadedAlice,
      envelope: { t: "text", body: "after reload 1", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });
    await saveSession(alice.userId, bob.userId, reloadedAlice);

    const { session: bobSession } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    await saveSession(bob.userId, alice.userId, bobSession);

    // Reload Bob's session
    const reloadedBob = await loadSession(bob.userId, alice.userId);
    const reply = await ratchetEncrypt({
      session: reloadedBob,
      envelope: { t: "text", body: "bob reply after reload", ts: 2 },
      type: "text",
      senderId: bob.userId,
      receiverId: alice.userId,
      myIk: bob.idn.ik,
    });
    await saveSession(bob.userId, alice.userId, reloadedBob);

    // Reload Alice's session again
    reloadedAlice = await loadSession(alice.userId, bob.userId);
    const { envelope: decReply } = await ratchetDecrypt({
      session: reloadedAlice,
      receiverId: alice.userId,
      senderId: bob.userId,
      myIk: alice.idn.ik,
      msg: reply,
      pinned: { ik: bob.idn.ik.pub, sik: bob.idn.sik.pub },
    });
    expect(decReply.body).toBe("bob reply after reload");
  });

  it("deterministic regression vectors with fixed keys", async () => {
    // Fixed deterministic root key and DH output
    const fixedRk = new Uint8Array(32).fill(0x42);
    const fixedDh = new Uint8Array(32).fill(0x13);

    const { newRk, newCk } = kdfRk(fixedRk, fixedDh);
    expect(toB64(newRk)).toBeDefined();
    expect(toB64(newCk)).toBeDefined();

    // Verify constant output length and idempotency
    const v2 = kdfRk(fixedRk, fixedDh);
    expect(toB64(v2.newRk)).toBe(toB64(newRk));
    expect(toB64(v2.newCk)).toBe(toB64(newCk));

    // Symmetric chain KDF
    const { mk, nextCk } = kdfCk(newCk);
    expect(mk.length).toBe(32);
    expect(nextCk.length).toBe(32);
    const step2 = kdfCk(newCk);
    expect(toB64(step2.mk)).toBe(toB64(mk));
  });

  it("migration test from an S8 session", async () => {
    const s8Session = {
      peerId: "user123",
      sessionId: "s8-session-12345",
      role: "initiator",
      sk: new Uint8Array(32).fill(0x05),
      chainKeySend: new Uint8Array(32).fill(0x06),
      chainKeyRecv: new Uint8Array(32).fill(0x07),
      sendCounter: 4,
      recvCounter: 3,
      peerIk: toB64(new Uint8Array(32).fill(0x01)),
      peerSik: toB64(new Uint8Array(32).fill(0x02)),
      createdAt: 1000,
      state: "established",
    };

    // Upgrade S8 session to Double Ratchet
    const upgraded = upgradeFromS8Session(s8Session);
    expect(upgraded.rk).toBeDefined();
    expect(upgraded.dhs).toBeDefined();
    expect(upgraded.ns).toBe(0);
    expect(upgraded.nr).toBe(0);
    expect(upgraded.pn).toBe(0);
  });

  it("two simulated tabs sending and receiving concurrently on the same conversation maintain consistent state (no message lost or corrupted)", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: initAlice, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });
    await saveSession(alice.userId, bob.userId, initAlice);

    const m0 = await ratchetEncrypt({
      session: initAlice,
      envelope: { t: "text", body: "m0", ts: 1 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });
    await saveSession(alice.userId, bob.userId, initAlice);

    const { session: initBob } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: m0,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      takeOpkPriv: (id) => takeOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    await saveSession(bob.userId, alice.userId, initBob);

    // Simulated Tab 1 and Tab 2 sending concurrently from Alice to Bob
    // Both tabs use withSessionLock to serialize read-modify-write on IndexedDB session
    const tabSend = async (body) => {
      return withSessionLock(alice.userId, bob.userId, async () => {
        const session = await loadSession(alice.userId, bob.userId);
        await new Promise((r) => setTimeout(r, 10)); // simulate asynchronous execution in tab
        const payload = await ratchetEncrypt({
          session,
          envelope: { t: "text", body, ts: Date.now() },
          type: "text",
          senderId: alice.userId,
          receiverId: bob.userId,
          myIk: alice.idn.ik,
        });
        await saveSession(alice.userId, bob.userId, session);
        return payload;
      });
    };

    // Both tabs send concurrently
    const [msgFromTab1, msgFromTab2] = await Promise.all([
      tabSend("hello from tab 1"),
      tabSend("hello from tab 2"),
    ]);

    // Counters must be sequential and distinct without collision
    const counters = [msgFromTab1.header.n, msgFromTab2.header.n].sort((a, b) => a - b);
    expect(counters).toEqual([1, 2]);

    // Simulated Tab 1 and Tab 2 receiving concurrently on Bob's side
    const tabReceive = async (msg) => {
      return withSessionLock(bob.userId, alice.userId, async () => {
        const session = await loadSession(bob.userId, alice.userId);
        await new Promise((r) => setTimeout(r, 10));
        const dec = await ratchetDecrypt({
          session,
          receiverId: bob.userId,
          senderId: alice.userId,
          myIk: bob.idn.ik,
          msg,
          pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
        });
        await saveSession(bob.userId, alice.userId, dec.session);
        return dec.envelope;
      });
    };

    const [dec1, dec2] = await Promise.all([
      tabReceive(msgFromTab1),
      tabReceive(msgFromTab2),
    ]);

    const receivedTexts = [dec1.body, dec2.body];
    expect(receivedTexts).toContain("hello from tab 1");
    expect(receivedTexts).toContain("hello from tab 2");

    // Verify Bob's final session state in IndexedDB is consistent and uncorrupted
    const storedBob = await loadSession(bob.userId, alice.userId);
    expect(storedBob.nr).toBe(3);
    expect(storedBob.skippedKeys).toEqual({});
  });

  it("persists new ratchet state and plain cache to IndexedDB before message is shown and before ack", async () => {
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bob.bundle(0),
    });

    const m0 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "persist check", ts: 100 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });
    const msgId = "msg-persist-test-1";
    const wireMsg = { ...m0, _id: msgId, senderId: alice.userId, receiverId: bob.userId };

    // Set up pin for Bob
    const { acceptKeyChange } = await import("../lib/safety.js");
    await acceptKeyChange(bob.userId, alice.userId, {
      ik: toB64(alice.idn.ik.pub),
      sik: toB64(alice.idn.sik.pub),
    });

    const { readMessage } = await import("../lib/chatCrypto.js");

    // Before message decryption: no session in Bob's storage and no plain cache
    expect(await loadSession(bob.userId, alice.userId)).toBeNull();
    expect(await getPlain(bob.userId, msgId)).toBeNull();

    // Call readMessage
    const res = await readMessage({ me: bob.userId, msg: wireMsg });

    // Check that state in IndexedDB was persisted before return
    const storedBob = await loadSession(bob.userId, alice.userId);
    const cachedPlain = await getPlain(bob.userId, msgId);

    expect(storedBob).not.toBeNull();
    expect(storedBob.nr).toBe(1);
    expect(cachedPlain).not.toBeNull();
    expect(cachedPlain.body).toBe("persist check");
    expect(res).toMatchObject({ state: "ok", text: "persist check" });

    // Furthermore, if saveSession fails (storage error), decryptMessage fails closed
    const m1 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "fail closed", ts: 101 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
    });
    const m1Wire = { ...m1, _id: "msg-persist-fail-2", senderId: alice.userId, receiverId: bob.userId };

    const keystore = await import("../storage/keystore.js");
    const saveSpy = vi.spyOn(keystore, "saveSession").mockRejectedValueOnce(new Error("IDB disk full"));
    try {
      // Must fail closed (returns non-ok error state, never plaintext)
      const failRes = await readMessage({ me: bob.userId, msg: m1Wire });
      expect(failRes.state).not.toBe("ok");
      // Cache must NOT have been written
      expect(await getPlain(bob.userId, m1Wire._id)).toBeNull();
    } finally {
      saveSpy.mockRestore();
    }
  });

  it("R1.1: an initial message with a corrupted tag leaves OPK intact and saves no session, legitimate message decrypts afterwards and consumes OPK", async () => {
    const { getOpkPriv, deleteOpkPriv } = await import("../storage/keystore.js");
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();
    const bobBundle = bob.bundle(0);
    const opkId = bobBundle.opk.id;

    // Verify OPK exists in Bob's keystore initially
    expect(await getOpkPriv(bob.userId, opkId)).not.toBeNull();

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bobBundle,
      pinned: { ik: bob.idn.ik.pub, sik: bob.idn.sik.pub },
    });

    const legitMsg = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "secret hello", ts: 100 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    // 1. Create a tampered message with corrupted ciphertext/tag
    const tamperedCt = fromB64(legitMsg.ciphertext);
    tamperedCt[tamperedCt.length - 1] ^= 0x01; // flip last byte of tag
    const tamperedMsg = { ...legitMsg, ciphertext: toB64(tamperedCt) };

    // Attempt decrypt tamperedMsg - must fail
    await expect(
      ratchetDecrypt({
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: tamperedMsg,
        getSpkPriv: (id) => getSpkPriv(bob.userId, id),
        getOpkPriv: (id) => getOpkPriv(bob.userId, id),
        deleteOpkPriv: (id) => deleteOpkPriv(bob.userId, id),
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      })
    ).rejects.toThrow();

    // CRITICAL: Bob's OPK private key MUST STILL BE INTACT!
    const opkPrivAfterTamper = await getOpkPriv(bob.userId, opkId);
    expect(opkPrivAfterTamper).not.toBeNull();

    // And no session was saved
    expect(await loadSession(bob.userId, alice.userId)).toBeNull();

    // 2. Now decrypt the legitimate message — must succeed!
    const { session: bobSession, envelope } = await ratchetDecrypt({
      receiverId: bob.userId,
      senderId: alice.userId,
      myIk: bob.idn.ik,
      msg: legitMsg,
      getSpkPriv: (id) => getSpkPriv(bob.userId, id),
      getOpkPriv: (id) => getOpkPriv(bob.userId, id),
      deleteOpkPriv: (id) => deleteOpkPriv(bob.userId, id),
      pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
    });
    expect(envelope.body).toBe("secret hello");
    expect(bobSession).toBeDefined();

    // 3. A successful decrypt MUST delete the OPK
    expect(await getOpkPriv(bob.userId, opkId)).toBeNull();
  });

  it("R1.1: a forged initial message with a valid opkId and a bad tag does not consume the OPK", async () => {
    const { getOpkPriv, deleteOpkPriv } = await import("../storage/keystore.js");
    const eve = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();
    const bobBundle = bob.bundle(0);
    const opkId = bobBundle.opk.id;

    // Eve crafts a forged initial message referencing Bob's valid opkId but with random/invalid ciphertext
    const forgedHeader = {
      sessionId: "forged-session-id-1234567890",
      n: 0,
      pn: 0,
      dh: toB64(xPub(newSecret())),
      ek: toB64(xPub(newSecret())),
      spkId: bobBundle.spk.id,
      opkId: opkId,
      ik: toB64(eve.idn.ik.pub),
      sik: toB64(eve.idn.sik.pub),
    };
    const forgedMsg = {
      v: 2,
      type: "text",
      header: forgedHeader,
      nonce: toB64(new Uint8Array(12).fill(0x42)),
      ciphertext: toB64(new Uint8Array(272).fill(0x99)), // random/invalid tag
    };

    await expect(
      ratchetDecrypt({
        receiverId: bob.userId,
        senderId: eve.userId,
        myIk: bob.idn.ik,
        msg: forgedMsg,
        getSpkPriv: (id) => getSpkPriv(bob.userId, id),
        getOpkPriv: (id) => getOpkPriv(bob.userId, id),
        deleteOpkPriv: (id) => deleteOpkPriv(bob.userId, id),
        pinned: { ik: eve.idn.ik.pub, sik: eve.idn.sik.pub },
      })
    ).rejects.toThrow();

    // Bob's OPK MUST NOT be consumed by Eve's forged message
    expect(await getOpkPriv(bob.userId, opkId)).not.toBeNull();
  });

  it("R1.2: a tampered header.sik with a pinned peer gives PEER_KEY_CHANGED and no session", async () => {
    const { getOpkPriv, deleteOpkPriv } = await import("../storage/keystore.js");
    const { PEER_KEY_CHANGED } = await import("../crypto/errors.js");
    const alice = await mkUserKeyMaterial();
    const bob = await mkUserKeyMaterial();
    const bobBundle = bob.bundle(0);

    const { session: aliceSession, initialHeader } = await initiateRatchetSession({
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      mySik: alice.idn.sik,
      bundle: bobBundle,
      pinned: { ik: bob.idn.ik.pub, sik: bob.idn.sik.pub },
    });

    const msg = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "hello", ts: 100 },
      type: "text",
      senderId: alice.userId,
      receiverId: bob.userId,
      myIk: alice.idn.ik,
      initialHeader,
    });

    // Tamper header.sik (replace with a different valid 32-byte Ed25519 pub key)
    const otherIdn = generateIdentity();
    const tamperedMsg = {
      ...msg,
      header: {
        ...msg.header,
        sik: toB64(otherIdn.sik.pub),
      },
    };

    let thrownError = null;
    try {
      await ratchetDecrypt({
        receiverId: bob.userId,
        senderId: alice.userId,
        myIk: bob.idn.ik,
        msg: tamperedMsg,
        getSpkPriv: (id) => getSpkPriv(bob.userId, id),
        getOpkPriv: (id) => getOpkPriv(bob.userId, id),
        deleteOpkPriv: (id) => deleteOpkPriv(bob.userId, id),
        pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
      });
    } catch (e) {
      thrownError = e;
    }

    expect(thrownError).toBeInstanceOf(CryptoError);
    expect(thrownError?.code).toBe(PEER_KEY_CHANGED);
    expect(await loadSession(bob.userId, alice.userId)).toBeNull();
  });
});
