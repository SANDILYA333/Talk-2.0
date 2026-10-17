import mongoose from "mongoose";

const keyBundleSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, unique: true },
    sik: { type: String, required: true },
    ikBinding: { type: String, required: true },
    spk: {
      id: { type: Number, required: true },
      pub: { type: String, required: true },
      sig: { type: String, required: true },
      createdAt: { type: Date, default: Date.now },
    },
    protoMax: { type: Number, enum: [1, 2], default: 1 },
  },
  { timestamps: true }
);

export default mongoose.models.KeyBundle || mongoose.model("KeyBundle", keyBundleSchema);
