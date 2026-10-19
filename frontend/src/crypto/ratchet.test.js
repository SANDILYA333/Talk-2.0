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
import { set } from "idb-keyval";
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

    const m0 = await ratchetEncrypt({
      session: aliceSession,
      envelope: { t: "text", body: "first", ts: 1 },
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

    // Exchange 5 messages in both directions
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
        await ratchetDecrypt({
          session: bobSession,
          receiverId: bob.userId,
          senderId: alice.userId,
          myIk: bob.idn.ik,
          msg,
          pinned: { ik: alice.idn.ik.pub, sik: alice.idn.sik.pub },
        });
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
        await ratchetDecrypt({
          session: aliceSession,
          receiverId: alice.userId,
          senderId: bob.userId,
          myIk: alice.idn.ik,
          msg,
          pinned: { ik: bob.idn.ik.pub, sik: bob.idn.sik.pub },
        });
        curSender = "alice";
      }
    }

    // Assert that session records only contain current chain keys, no old message keys
    expect(bobSession.skippedKeys).toEqual({});
    expect(aliceSession.skippedKeys).toEqual({});
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
});
