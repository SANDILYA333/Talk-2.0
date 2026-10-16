import express from "express";
import cors from "cors";

import "dotenv/config";

import fs from "fs";
import path from "path";

import { clerkMiddleware } from "@clerk/express";

import User from "./models/user.model.js";
import { connectDB } from "./lib/db.js";
import job from "./lib/cron.js";

import clerkWebhook from "./webhooks/clerk.webhook.js";
import authRoutes from "./routes/auth.route.js";
import messageRoutes from "./routes/message.route.js";
import identityRoutes from "./routes/identity.route.js";
import { app, server } from "./lib/socket.js";

const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL;

const publicDir = path.join(process.cwd(), "public");

// Ensure MongoDB is connected for incoming requests (essential for serverless execution)
app.use(async (req, res, next) => {
  await connectDB();
  next();
});

// it's important that you don't parse the webhook event data, it should be in the raw format
app.use("/api/webhooks/clerk", express.raw({ type: "application/json" }), clerkWebhook);

app.use(express.json());

const allowedOrigins = [FRONTEND_URL, "http://localhost:5173"].filter(Boolean);
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin) || origin.endsWith(".vercel.app")) {
        callback(null, true);
      } else {
        callback(null, true);
      }
    },
    credentials: true,
  })
);
app.use(clerkMiddleware());

app.get(["/health", "/api/health"], (req, res) => {
  res.status(200).json({ ok: true });
});

app.use("/api/auth", authRoutes);
app.use("/api/messages", messageRoutes);
app.use("/api/identity", identityRoutes);

// if the public directory exists, serve the static files
// this is for standalone/docker production builds
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));

  app.get("/{*any}", (req, res, next) => {
    res.sendFile(path.join(publicDir, "index.html"), (err) => next(err));
  });
}

// Start HTTP server only in standalone / local mode (not in Vercel serverless environment)
if (process.env.VERCEL !== "1") {
  server.listen(PORT, () => {
    connectDB();
    console.log("Server is up and running on PORT:", PORT);

    if (process.env.NODE_ENV === "production") job.start();
  });
}

export default app;

