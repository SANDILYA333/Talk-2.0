import { Router } from "express";
import rateLimit from "express-rate-limit";
import { protectRoute } from "../middleware/auth.middleware.js";
import { putBundle, postOpks, getOpkCount, getBundle } from "../controllers/keys.controller.js";

const perUser = (limit, message) =>
  rateLimit({
    windowMs: 60_000,
    limit,
    keyGenerator: (req) => String(req.user._id),
    standardHeaders: true,
    legacyHeaders: false,
    message: { message },
  });

const router = Router();
router.put("/bundle", protectRoute, perUser(30, "Too many uploads"), putBundle);
router.post("/opks", protectRoute, perUser(30, "Too many uploads"), postOpks);
router.get("/opks/count", protectRoute, getOpkCount);
router.get("/bundle/:userId", protectRoute, perUser(20, "Too many key fetches"), getBundle);
export default router;
