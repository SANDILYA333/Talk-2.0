import express from "express";
import rateLimit from "express-rate-limit";
import {
  getConversationsForSidebar,
  getMessages,
  getUsersForSidebar,
  sendMessage,
  markRead,
} from "../controllers/message.controller.js";
import { protectRoute } from "../middleware/auth.middleware.js";

const perUser = (limit, message) =>
  rateLimit({
    windowMs: 60_000,
    limit,
    keyGenerator: (req) => String(req.user._id),
    standardHeaders: true,
    legacyHeaders: false,
    message: { message },
  });

const router = express.Router();

router.use(protectRoute);

router.get("/users", getUsersForSidebar);
router.get("/conversations", getConversationsForSidebar);
router.get("/:id", getMessages);
router.post("/send/:id", protectRoute, sendMessage);
router.post("/read/:peerId", perUser(60, "Too many read updates"), markRead);

export default router;
