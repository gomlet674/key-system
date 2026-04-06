// server.js - Replit Ready Key System
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(cors());

// ====== ENV VARIABLES ======
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI; // isi di Replit Secrets
const ADMIN_TOKEN = process.env.ADMIN_TOKEN; // isi token admin di Replit Secrets

// ====== MONGOOSE SETUP ======
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => {
  console.error("❌ MongoDB Error:", err);
  process.exit(1); // stop server kalau gagal connect
});

// ====== SCHEMA ======
const keySchema = new mongoose.Schema({
  key: String,
  createdAt: { type: Date, default: Date.now },
  duration: Number, // detik
  usedBy: { type: [String], default: [] }, // userIds
  expired: { type: Boolean, default: false },
});

const Key = mongoose.model("Key", keySchema);

// ====== ROUTES ======

// Admin route: create key
app.post("/create", async (req, res) => {
  const { token, duration } = req.body;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: "Unauthorized" });

  const newKey = new Key({
    key: crypto.randomBytes(8).toString("hex").toUpperCase(),
    duration: duration || 3600,
  });

  await newKey.save();
  res.json({ key: newKey.key, expiresIn: newKey.duration });
});

// User route: verify key
app.post("/verify", async (req, res) => {
  const { key, userId } = req.body;
  if (!key || !userId) return res.status(400).json({ error: "Missing key or userId" });

  const keyData = await Key.findOne({ key });
  if (!keyData) return res.status(404).json({ valid: false, message: "Key not found" });

  // Check expiration
  const elapsed = (Date.now() - keyData.createdAt.getTime()) / 1000;
  if (elapsed > keyData.duration) {
    keyData.expired = true;
    await keyData.save();
    return res.json({ valid: false, message: "Key expired" });
  }

  // Mark user as used
  if (!keyData.usedBy.includes(userId.toString())) {
    keyData.usedBy.push(userId.toString());
    await keyData.save();
  }

  res.json({ valid: true, message: "Key valid" });
});

// Get all keys (Admin)
app.get("/keys", async (req, res) => {
  const token = req.query.token;
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: "Unauthorized" });
  const keys = await Key.find();
  res.json(keys);
});

// ====== START SERVER ======
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Public URL: https://${process.env.REPL_SLUG}.${process.env.REPL_OWNER}.repl.co`);
});