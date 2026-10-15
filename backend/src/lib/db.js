import mongoose from "mongoose";

export async function connectDB() {
  if (mongoose.connection.readyState >= 1) return;

  try {
    const mongoUri = process.env.MONGO_URI;

    if (!mongoUri) {
      throw new Error("MONGO_URI is required");
    }

    const conn = await mongoose.connect(mongoUri);

    console.log("MongoDB connected", conn.connection.host);
  } catch (error) {
    console.error("MongoDB connection error:", error.message);
  }
}
