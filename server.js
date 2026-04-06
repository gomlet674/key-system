// server.js
const express = require("express");
const mongoose = require("mongoose");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const app = express();

// ------------------- CONFIG -------------------
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI; // isi di Railway Variables
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "changeme";

// ------------------- TRUST PROXY -------------------
app.set("trust proxy", 1); // penting untuk X-Forwarded-For

// ------------------- MIDDLEWARE -------------------
app.use(express.json());
app.use(cors());

// ------------------- RATE LIMIT -------------------
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 menit
  max: 100, // 100 request per IP per menit
  message: { error: "Too many requests, slow down!" },
});
app.use(limiter);

// ------------------- MONGODB -------------------
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB connected"))
.catch(err => console.log("❌ MongoDB connection error:", err));

// ------------------- SCHEMA -------------------
const keySchema = new mongoose.Schema({
  key: String,
  ip: String,
  expiresAt: Date,
});
const Key = mongoose.model("Key", keySchema);

// ------------------- HELPERS -------------------
function generateKey(length = 8) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "";
  for(let i=0;i<length;i++){
    result += chars.charAt(Math.floor(Math.random()*chars.length));
  }
  return result;
}

// ------------------- ROUTES -------------------

// Admin generate key (manual)
app.post("/generate", async (req,res)=>{
  const auth = req.headers["authorization"];
  if(auth !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });

  const { tier, duration } = req.body;
  const key = generateKey(12);
  const expiresAt = new Date(Date.now() + (duration || 1) * 24*60*60*1000);

  const newKey = new Key({
    key, ip: null, expiresAt
  });

  await newKey.save();
  res.json({ key, expiresAt });
});

// Public get key (IP-based, 1x per day)
app.get("/getkey", async (req,res)=>{
  const userIP = req.ip;

  let existing = await Key.findOne({ ip: userIP });
  const now = new Date();

  if(existing && existing.expiresAt > now){
    return res.json({ key: existing.key, expiresAt: existing.expiresAt });
  }

  const key = generateKey(12);
  const expiresAt = new Date(Date.now() + 24*60*60*1000);

  const newKey = new Key({ key, ip: userIP, expiresAt });
  await newKey.save();

  res.json({ key, expiresAt });
});

// Verify key
app.post("/verify", async (req,res)=>{
  const { key } = req.body;
  if(!key) return res.status(400).json({ valid:false, error:"Missing key" });

  const existing = await Key.findOne({ key });
  const now = new Date();

  if(existing && existing.expiresAt > now){
    return res.json({ valid:true, key });
  }

  return res.json({ valid:false });
});

// ------------------- ROOT -------------------
app.get("/", (req,res)=>{
  res.send("🔐 Key System Server Running ✅");
});

// ------------------- START SERVER -------------------
app.listen(PORT, ()=>{
  console.log(`🚀 Server running on port ${PORT}`);
});
