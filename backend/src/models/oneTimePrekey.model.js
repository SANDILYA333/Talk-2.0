import mongoose from "mongoose";

const opkSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  id: { type: Number, required: true },
  pub: { type: String, required: true },
});
opkSchema.index({ userId: 1, id: 1 }, { unique: true });

export default mongoose.models.OneTimePrekey || mongoose.model("OneTimePrekey", opkSchema);
