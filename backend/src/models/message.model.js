import mongoose from "mongoose";

const messageSchema = new mongoose.Schema(
  {
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    receiverId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    cid: { type: String, required: true },
    v: { type: Number, required: true, enum: [1, 2] },
    type: { type: String, required: true, enum: ["text", "media", "secret"] },
    ciphertext: { type: String, required: true },
    nonce: { type: String, required: true },
    header: { type: mongoose.Schema.Types.Mixed, required: true },
    expiresAt: { type: Date },
  },
  { timestamps: true }
);

messageSchema.index({ senderId: 1, receiverId: 1, _id: -1 });
messageSchema.index({ receiverId: 1, senderId: 1, _id: -1 });
messageSchema.index({ senderId: 1, cid: 1 }, { unique: true });
messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, sparse: true });

export default mongoose.models.Message || mongoose.model("Message", messageSchema);
