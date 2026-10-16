import express from "express";
import http from "http";
import { Server } from "socket.io";
import { verifyToken } from "@clerk/backend";
import User from "../models/user.model.js";

const app = express();
const server = http.createServer(app);

const allowedOrigin = process.env.FRONTEND_URL || "http://localhost:5173";

const io = new Server(server, { cors: { origin: [allowedOrigin] } });

const online = new Map(); // userId -> number of open sockets (fixes multi-tab BUG-004)

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error("unauthorized"));

    const res = await verifyToken(token, { secretKey: process.env.CLERK_SECRET_KEY });
    if (res?.errors?.length) return next(new Error("unauthorized"));
    const payload = res?.data ?? res; // works across @clerk/backend versions

    const user = await User.findOne({ clerkId: payload.sub }).select("_id");
    if (!user) return next(new Error("user-not-found"));

    socket.data.userId = user._id.toString();
    next();
  } catch {
    next(new Error("unauthorized"));
  }
});

io.on("connection", (socket) => {
  const userId = socket.data.userId;
  socket.join(`user:${userId}`); // every tab/device joins the same room
  online.set(userId, (online.get(userId) || 0) + 1);
  io.emit("getOnlineUsers", [...online.keys()]);

  socket.on("disconnect", () => {
    const n = (online.get(userId) || 1) - 1;
    if (n <= 0) online.delete(userId);
    else online.set(userId, n);
    io.emit("getOnlineUsers", [...online.keys()]);
  });
});

export const emitToUser = (userId, event, payload) =>
  io.to(`user:${userId}`).emit(event, payload);

export { app, server, io };
