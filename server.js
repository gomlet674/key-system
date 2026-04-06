// server.js - Key System Roblox Railway-ready
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");

// =====================
// ENV Variables
// =====================
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;       // MongoDB URI dari Railway Variables
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;   // Token admin untuk create key

// =====================
// Init Express
// =====================
const app = express();
app.use(bodyParser.json());

// =====================
// MongoDB Connect
// =====================
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => {
  console.error("❌ MongoDB Error:", err);
  process.exit(1); // Stop server kalau gagal connect
});

// =====================
// Schema
// =====================
const keySchema = new mongoose.Schema({
  key: { type: String, required: true },
  createdBy: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  used: { type: Boolean, default: false }
});

const KeyModel = mongoose.model("Key", keySchema);

// =====================
// Routes
// =====================

// Test route
app.get("/", (req, res) => {
  res.send("🗝 Key System Server Online");
});

// Create key (admin only)
app.post("/create", async (req, res) => {
  const { token, key } = req.body;
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });

  try {
    const newKey = new KeyModel({ key, createdBy: "admin" });
    await newKey.save();
    res.json({ success: true, key: newKey.key });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create key" });
  }
});

// Verify key
app.post("/verify", async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: "Key is required" });

  try {
    const foundKey = await KeyModel.findOne({ key });
    if (!foundKey) return res.json({ valid: false, message: "Key not found" });
    if (foundKey.used) return res.json({ valid: false, message: "Key already used" });

    // Mark key as used
    foundKey.used = true;
    await foundKey.save();

    res.json({ valid: true, message: "Key valid!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// List all keys (admin only)
app.get("/keys", async (req, res) => {
  const token = req.headers["x-admin-token"];
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });

  try {
    const keys = await KeyModel.find().sort({ createdAt: -1 });
    res.json(keys);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch keys" });
  }
});

// =====================
// Start Server
// =====================
app.listen(PORT, () => {
  console.log(`🚀 Key System Server running on port ${PORT}`);
});
