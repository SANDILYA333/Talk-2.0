import { clerkClient, getAuth } from "@clerk/express";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
  try {
    const { userId } = getAuth(req);
    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    let user = await User.findOne({ clerkId: userId });

    if (!user) {
      const c = await clerkClient.users.getUser(userId);
      const email =
        c.emailAddresses.find((e) => e.id === c.primaryEmailAddressId)?.emailAddress ??
        c.emailAddresses[0]?.emailAddress;

      try {
        user = await User.create({
          clerkId: userId,
          email,
          fullName: [c.firstName, c.lastName].filter(Boolean).join(" ") || email?.split("@")[0] || "User",
          profilePic: c.imageUrl,
        });
      } catch (err) {
        if (err.code !== 11000) throw err; // webhook won the race, just refetch
        user = await User.findOne({ clerkId: userId });
      }
    }

    req.user = user;
    next();
  } catch (err) {
    console.error("protectRoute:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
};