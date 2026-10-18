import mongoose from "mongoose";
import Message from "../models/message.model.js";
import User from "../models/user.model.js";
import KeyBundle from "../models/keyBundle.model.js";
import { emitToUser } from "../lib/socket.js";
import { b64Bytes, b64Decode, isU32 } from "../lib/keyValidate.js";

const CID_RE = /^[A-Za-z0-9-]{8,64}$/;
const ALLOWED = new Set(["cid", "v", "type", "ciphertext", "nonce", "header"]);
const PLAINTEXT_FIELDS = ["text", "image", "video"];

export const toWire = (d) => {
  const o = d.toObject ? d.toObject() : d;
  return {
    _id: String(o._id),
    senderId: String(o.senderId),
    receiverId: String(o.receiverId),
    cid: o.cid, v: o.v, type: o.type,
    ciphertext: o.ciphertext, nonce: o.nonce, header: o.header,
    expiresAt: o.expiresAt ?? null,
    createdAt: o.createdAt,
  };
};

function parseSendBody(b) {
  if (!b || typeof b !== "object" || Array.isArray(b)) return { message: "bad-request" };
  for (const k of Object.keys(b)) {
    if (PLAINTEXT_FIELDS.includes(k)) return { message: "plaintext-field" };
    if (!ALLOWED.has(k)) return { message: "unknown-field" };
  }
  if (typeof b.cid !== "string" || !CID_RE.test(b.cid)) return { message: "bad-cid" };
  if (b.v !== 1) return { message: "unsupported-version" };
  if (b.type !== "text") return { message: "unsupported-type" };

  const ct = b64Decode(b.ciphertext);
  if (!ct || ct.length < 272 || ct.length > 16384 || (ct.length - 16) % 256 !== 0) return { message: "bad-ciphertext" };
  if (!b64Bytes(b.nonce, 12)) return { message: "bad-nonce" };

  const h = b.header;
  if (!h || typeof h !== "object" || Array.isArray(h)) return { message: "bad-header" };
  const keys = Object.keys(h);
  if (keys.length !== 2 || !keys.includes("ek") || !keys.includes("spkId")) return { message: "bad-header" };
  if (!b64Bytes(h.ek, 32) || !isU32(h.spkId)) return { message: "bad-header" };

  return { doc: { cid: b.cid, v: 1, type: "text", ciphertext: b.ciphertext, nonce: b.nonce, header: { ek: h.ek, spkId: h.spkId } } };
}

import ReadState from "../models/readState.model.js";

export async function getUsersForSidebar(req, res) {
  try {
    const loggedInUserId = req.user._id;
    const filteredUsers = await User.find({ _id: { $ne: loggedInUserId } }).select("-clerkId -email");
    res.status(200).json(filteredUsers);
  } catch (error) {
    console.error("Error in getUsersForSidebar:", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function getConversationsForSidebar(req, res) {
  try {
    const loggedInUserId = req.user._id;

    const conversations = await Message.aggregate([
      // 1. Keep only messages sent or received by me
      { $match: { $or: [{ senderId: loggedInUserId }, { receiverId: loggedInUserId }] } },
      // 2. Sort latest first
      { $sort: { createdAt: -1 } },
      // 3. Group by partner
      {
        $group: {
          _id: { $cond: [{ $eq: ["$senderId", loggedInUserId] }, "$receiverId", "$senderId"] },
          last: { $first: "$$ROOT" },
          lastMessageAt: { $first: "$createdAt" },
        },
      },
      // 4. Sort conversations by most recent message
      { $sort: { lastMessageAt: -1 } },
      // 5. Lookup user details
      { $lookup: { from: "users", localField: "_id", foreignField: "_id", as: "user" } },
      // 6. Lookup read state for this conversation
      {
        $lookup: {
          from: "readstates",
          let: { peerId: "$_id" },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ["$userId", loggedInUserId] },
                    { $eq: ["$peerId", "$$peerId"] },
                  ],
                },
              },
            },
          ],
          as: "readState",
        },
      },
      // 7. Count unread messages from this peer to me after lastReadMessageId
      {
        $lookup: {
          from: "messages",
          let: {
            peerId: "$_id",
            lastRead: {
              $ifNull: [
                { $first: "$readState.lastReadMessageId" },
                new mongoose.Types.ObjectId("000000000000000000000000"),
              ],
            },
          },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ["$receiverId", loggedInUserId] },
                    { $eq: ["$senderId", "$$peerId"] },
                    { $gt: ["$_id", "$$lastRead"] },
                  ],
                },
              },
            },
            { $count: "count" },
          ],
          as: "unread",
        },
      },
      // 8. Project user profile, unreadCount, and lastMessage metadata only
      {
        $replaceRoot: {
          newRoot: {
            $mergeObjects: [
              { $first: "$user" },
              {
                unreadCount: { $ifNull: [{ $first: "$unread.count" }, 0] },
                lastMessage: {
                  _id: "$last._id",
                  senderId: "$last.senderId",
                  receiverId: "$last.receiverId",
                  createdAt: "$last.createdAt",
                  type: "$last.type",
                },
              },
            ],
          },
        },
      },
      // 9. Strip sensitive fields
      { $project: { clerkId: 0, email: 0 } },
    ]);

    res.status(200).json(conversations);
  } catch (error) {
    console.error("Error in getConversationsForSidebar:", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
}

export const markRead = async (req, res) => {
  try {
    const { peerId } = req.params;
    const { upTo } = req.body || {};
    const userId = req.user._id;

    if (!mongoose.isValidObjectId(peerId) || String(userId) === String(peerId)) {
      return res.status(400).json({ message: "bad-id" });
    }
    if (!upTo || !mongoose.isValidObjectId(upTo)) {
      return res.status(400).json({ message: "bad-request" });
    }

    const targetMsg = await Message.findOne({
      _id: upTo,
      senderId: peerId,
      receiverId: userId,
    });
    if (!targetMsg) {
      return res.status(404).json({ message: "message-not-found" });
    }

    let changed = false;
    let state = await ReadState.findOne({ userId, peerId });
    if (!state) {
      try {
        state = await ReadState.create({ userId, peerId, lastReadMessageId: targetMsg._id });
        changed = true;
      } catch (err) {
        if (err.code !== 11000) throw err;
        state = await ReadState.findOne({ userId, peerId });
      }
    }

    if (state && String(targetMsg._id) > String(state.lastReadMessageId)) {
      const updated = await ReadState.findOneAndUpdate(
        { userId, peerId, lastReadMessageId: { $lt: targetMsg._id } },
        { $set: { lastReadMessageId: targetMsg._id } },
        { new: true }
      );
      if (updated) {
        changed = true;
        state = updated;
      }
    }

    if (changed) {
      emitToUser(String(userId), "readUpdated", { peerId: String(peerId) });
    }

    return res.status(200).json({
      ok: true,
      lastReadMessageId: String(state?.lastReadMessageId ?? targetMsg._id),
    });
  } catch (err) {
    console.error("markRead:", err.message);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const getMessages = async (req, res) => {
  try {
    const otherId = req.params.id;
    if (!mongoose.isValidObjectId(otherId)) return res.status(400).json({ message: "Bad id" });

    const myId = req.user._id;
    const limit = Math.min(parseInt(req.query.limit, 10) || 30, 100);

    const query = {
      $or: [
        { senderId: myId, receiverId: otherId },
        { senderId: otherId, receiverId: myId },
      ],
    };
    if (req.query.before) {
      if (!mongoose.isValidObjectId(req.query.before)) return res.status(400).json({ message: "Bad cursor" });
      query._id = { $lt: req.query.before };
    }

    const docs = await Message.find(query).sort({ _id: -1 }).limit(limit + 1);
    const hasMore = docs.length > limit;
    res.json({ messages: docs.slice(0, limit).reverse().map(toWire), hasMore });
  } catch (err) {
    console.error("getMessages:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const sendMessage = async (req, res) => {
  try {
    const receiverId = req.params.id;
    const senderId = req.user._id;
    if (!mongoose.isValidObjectId(receiverId)) return res.status(400).json({ message: "bad-id" });
    if (String(senderId) === receiverId) return res.status(400).json({ message: "self-message" });

    const parsed = parseSendBody(req.body);
    if (!parsed.doc) return res.status(400).json({ message: parsed.message });

    const [recipient, bundle] = await Promise.all([
      User.exists({ _id: receiverId }),
      KeyBundle.exists({ userId: receiverId }),
    ]);
    if (!recipient) return res.status(404).json({ message: "user-not-found" });
    if (!bundle) return res.status(409).json({ message: "recipient-no-keys" });

    let doc, created = true;
    try {
      doc = await Message.create({ senderId, receiverId, ...parsed.doc });
    } catch (e) {
      if (e.code !== 11000) throw e;
      doc = await Message.findOne({ senderId, cid: parsed.doc.cid });
      if (!doc) throw e;
      if (String(doc.receiverId) !== receiverId) return res.status(409).json({ message: "cid-conflict" });
      created = false;
    }

    const out = toWire(doc);
    if (created) emitToUser(receiverId, "newMessage", out);
    res.status(created ? 201 : 200).json(out);
  } catch (err) {
    console.error("sendMessage:", err.message); // never log the body
    res.status(500).json({ message: "Internal server error" });
  }
};
