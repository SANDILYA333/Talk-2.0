import express from "express";
import rateLimit from "express-rate-limit";
import { protectRoute } from "../middleware/auth.middleware.js";
import { getUploadAuth } from "../controllers/media.controller.js";

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
router.get("/upload-auth", perUser(30, "Too many upload auth requests"), getUploadAuth);

export default router;
