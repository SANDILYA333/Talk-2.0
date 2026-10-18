import "dotenv/config";
import mongoose from "mongoose";

const apply = process.argv.includes("--yes");
await mongoose.connect(process.env.MONGO_URI);
const col = mongoose.connection.collection("messages");
const filter = { v: { $exists: false } };
console.log(`legacy plaintext messages (no "v"): ${await col.countDocuments(filter)}`);
if (!apply) console.log("dry run only. add --yes to delete.");
else console.log("deleted:", (await col.deleteMany(filter)).deletedCount);
await mongoose.disconnect();
