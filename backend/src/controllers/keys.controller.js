import mongoose from "mongoose";
import User from "../models/user.model.js";
import KeyBundle from "../models/keyBundle.model.js";
import OneTimePrekey from "../models/oneTimePrekey.model.js";
import { b64Bytes, isU32, edVerify, ikBindingMsg, spkMsg } from "../lib/keyValidate.js";

const MAX_OPKS = 100;
const fail = (res, code, message, extra = {}) => res.status(code).json({ message, ...extra });
const oops = (res, name, err) => {
  console.error(`${name}:`, err.message); // never log bodies or keys
  return res.status(500).json({ message: "Internal server error" });
};

async function upsertBundle(userId, doc) {
  for (let i = 0; i < 2; i++) {
    try {
      return await KeyBundle.findOneAndUpdate({ userId }, { $set: doc }, { upsert: true });
    } catch (e) {
      if (e.code !== 11000 || i === 1) throw e; // two tabs raced the upsert: retry once
    }
  }
}

export const putBundle = async (req, res) => {
  try {
    const userId = req.user._id;
    const me = await User.findById(userId).select("publicKey");
    const ik = b64Bytes(me?.publicKey, 32);
    if (!ik) return fail(res, 409, "no-identity");

    const { sik, ikBinding, spk, protoMax = 1 } = req.body ?? {};
    const sikB = b64Bytes(sik, 32);
    const bindB = b64Bytes(ikBinding, 64);
    const spkPub = b64Bytes(spk?.pub, 32);
    const spkSig = b64Bytes(spk?.sig, 64);
    if (!sikB || !bindB || !spkPub || !spkSig || !isU32(spk?.id) || ![1, 2].includes(protoMax)) {
      return fail(res, 400, "bad-request");
    }
    if (!edVerify(bindB, ikBindingMsg(ik), sikB)) return fail(res, 400, "bad-ik-binding");
    if (!edVerify(spkSig, spkMsg(spk.id, spkPub), sikB)) return fail(res, 400, "bad-spk-sig");

    const existing = await KeyBundle.findOne({ userId });
    const sameSik = existing?.sik === sik;
    if (sameSik) {
      const old = existing.spk;
      if (spk.id < old.id || (spk.id === old.id && spk.pub !== old.pub)) return fail(res, 409, "stale-spk");
    }

    const unchanged = sameSik && existing.spk.id === spk.id;
    await upsertBundle(userId, {
      sik, ikBinding, protoMax,
      spk: { id: spk.id, pub: spk.pub, sig: spk.sig, createdAt: unchanged ? existing.spk.createdAt : new Date() },
    });
    if (existing && !sameSik) await OneTimePrekey.deleteMany({ userId });

    res.json({ ok: true, spkId: spk.id });
  } catch (err) {
    oops(res, "putBundle", err);
  }
};

export const postOpks = async (req, res) => {
  try {
    const userId = req.user._id;
    const list = req.body?.keys;
    if (!Array.isArray(list) || list.length < 1 || list.length > MAX_OPKS) return fail(res, 400, "bad-request");

    const seen = new Set();
    const clean = [];
    for (const k of list) {
      if (!isU32(k?.id) || !b64Bytes(k?.pub, 32) || seen.has(k.id)) return fail(res, 400, "bad-request");
      seen.add(k.id);
      clean.push({ id: k.id, pub: k.pub });
    }

    if (!(await KeyBundle.exists({ userId }))) return fail(res, 409, "no-bundle");

    const have = await OneTimePrekey.find({ userId, id: { $in: clean.map((k) => k.id) } }).select("id pub");
    const havePub = new Map(have.map((h) => [h.id, h.pub]));
    for (const k of clean) {
      if (havePub.has(k.id) && havePub.get(k.id) !== k.pub) return fail(res, 409, "opk-conflict");
    }

    const fresh = clean.filter((k) => !havePub.has(k.id));
    const count = await OneTimePrekey.countDocuments({ userId });
    if (count + fresh.length > MAX_OPKS) return fail(res, 409, "opk-cap", { count });

    if (fresh.length) {
      try {
        await OneTimePrekey.insertMany(fresh.map((k) => ({ userId, ...k })), { ordered: false });
      } catch (e) {
        if (e.code === 11000 || e.writeErrors) return fail(res, 409, "opk-conflict");
        throw e;
      }
    }
    res.json({ added: fresh.length, count: count + fresh.length });
  } catch (err) {
    oops(res, "postOpks", err);
  }
};

export const getOpkCount = async (req, res) => {
  try {
    res.json({ count: await OneTimePrekey.countDocuments({ userId: req.user._id }) });
  } catch (err) {
    oops(res, "getOpkCount", err);
  }
};

export const getBundle = async (req, res) => {
  try {
    const targetId = req.params.userId;
    if (!mongoose.isValidObjectId(targetId)) return fail(res, 400, "bad-id");
    if (String(req.user._id) === targetId) return fail(res, 400, "own-bundle");

    const [user, kb] = await Promise.all([
      User.findById(targetId).select("publicKey"),
      KeyBundle.findOne({ userId: targetId }),
    ]);
    if (!user?.publicKey || !kb) return fail(res, 404, "recipient-no-keys");

    // defense in depth: the stored binding must still match the current IK
    const ik = b64Bytes(user.publicKey, 32);
    const sik = b64Bytes(kb.sik, 32);
    const bind = b64Bytes(kb.ikBinding, 64);
    if (!ik || !sik || !bind || !edVerify(bind, ikBindingMsg(ik), sik)) return fail(res, 409, "recipient-keys-stale");

    // atomic: one OPK goes to exactly one requester. Only when asked (v2).
    const opk = req.query.opk === "1"
      ? await OneTimePrekey.findOneAndDelete({ userId: targetId }, { sort: { id: 1 } })
      : null;

    res.json({
      userId: targetId,
      ikPub: user.publicKey,
      sikPub: kb.sik,
      ikBinding: kb.ikBinding,
      spk: { id: kb.spk.id, pub: kb.spk.pub, sig: kb.spk.sig },
      opk: opk ? { id: opk.id, pub: opk.pub } : null,
      protoMax: kb.protoMax,
    });
  } catch (err) {
    oops(res, "getBundle", err);
  }
};
