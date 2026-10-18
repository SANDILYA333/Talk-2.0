import mongoose from "mongoose";

const readStateSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    peerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    lastReadMessageId: { type: mongoose.Schema.Types.ObjectId, ref: "Message", required: true },
  },
  { timestamps: true }
);

readStateSchema.index({ userId: 1, peerId: 1 }, { unique: true });

export default mongoose.models.ReadState || mongoose.model("ReadState", readStateSchema);
