import User from "../models/user.model.js";
import { deriveConnectCode, normalizeConnectCode } from "../lib/connectCode.js";

const isValidKey = (k) =>
  typeof k === "string" &&
  Buffer.from(k, "base64").length === 32 &&
  Buffer.from(k, "base64").toString("base64") === k;

export const setIdentity = async (req, res) => {
  try {
    const { publicKey, replace } = req.body;
    if (!isValidKey(publicKey)) return res.status(400).json({ message: "Invalid public key" });

    const existing = await User.findById(req.user._id).select("publicKey connectCode");
    if (existing.publicKey && existing.publicKey !== publicKey && !replace) {
      return res.status(409).json({ message: "Identity already set", connectCode: existing.connectCode });
    }

    const connectCode = deriveConnectCode(publicKey);
    await User.findByIdAndUpdate(req.user._id, { publicKey, connectCode });
    res.json({ connectCode, publicKey });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: "Key already registered" });
    console.error("setIdentity:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const lookupByCode = async (req, res) => {
  try {
    const code = normalizeConnectCode(req.params.code);
    if (!code) return res.status(400).json({ message: "Invalid code format" });

    const user = await User.findOne({ connectCode: code }).select("fullName profilePic publicKey connectCode");
    if (!user) return res.status(404).json({ message: "No user with that code" });
    if (user._id.equals(req.user._id)) return res.status(400).json({ message: "That's your own code" });

    res.json(user);
  } catch (err) {
    console.error("lookupByCode:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
};
