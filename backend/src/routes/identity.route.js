import { Router } from "express";
import rateLimit from "express-rate-limit";
import { protectRoute } from "../middleware/auth.middleware.js";
import { setIdentity, lookupByCode, getKeyById } from "../controllers/identity.controller.js";

const lookupLimiter = rateLimit({
  windowMs: 60_000,
  limit: 10,
  keyGenerator: (req) => String(req.user._id),
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many lookups, slow down" },
});

const router = Router();
router.put("/", protectRoute, setIdentity);
router.get("/lookup/:code", protectRoute, lookupLimiter, lookupByCode);
router.get("/key/:userId", protectRoute, getKeyById);
export default router;
