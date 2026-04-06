const express = require("express");
const mongoose = require("mongoose");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());

// ===== CONFIG =====
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

// ===== DB =====
mongoose.connect(MONGO_URI)
.then(()=>console.log("✅ MongoDB Connected"))
.catch(err=>console.log(err));

// ===== SCHEMA =====
const Key = mongoose.model("Key", new mongoose.Schema({
  keyHash: String,
  tier: String,
  createdAt: { type: Date, default: Date.now },
  expiresAt: Date,
  ip: String,
  usageCount: { type: Number, default: 0 }
}));

const Log = mongoose.model("Log", new mongoose.Schema({
  action: String,
  ip: String,
  timestamp: { type: Date, default: Date.now }
}));

// ===== SECURITY =====
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20
});
app.use(limiter);

// ===== UTILS =====
function genKey(){
  return crypto.randomBytes(16).toString("hex");
}

function hash(key){
  return crypto.createHash("sha256").update(key).digest("hex");
}

// ===== ADMIN: GENERATE =====
app.post("/generate", async (req,res)=>{
  if(req.headers.authorization !== ADMIN_TOKEN)
    return res.status(401).json({error:"Unauthorized"});

  const rawKey = genKey();
  const keyHash = hash(rawKey);

  const { tier = "FREE", duration = 1 } = req.body;

  const expiresAt = new Date(Date.now() + duration * 24*60*60*1000);

  await Key.create({ keyHash, tier, expiresAt });

  res.json({ key: rawKey, tier, expiresAt });
});

// ===== VERIFY =====
app.post("/verify", async (req,res)=>{
  const { key } = req.body;
  const ip = req.ip;

  const found = await Key.findOne({ keyHash: hash(key) });

  if(!found){
    await Log.create({ action:"INVALID_KEY", ip });
    return res.json({ valid:false });
  }

  if(found.expiresAt < new Date()){
    await Log.create({ action:"EXPIRED", ip });
    return res.json({ valid:false, message:"Expired" });
  }

  // Bind IP (optional)
  if(!found.ip) found.ip = ip;
  if(found.ip !== ip){
    return res.json({ valid:false, message:"Different device" });
  }

  found.usageCount++;
  await found.save();

  await Log.create({ action:"VALID", ip });

  res.json({
    valid:true,
    tier: found.tier,
    usage: found.usageCount
  });
});

// ===== REVOKE =====
app.post("/revoke", async (req,res)=>{
  if(req.headers.authorization !== ADMIN_TOKEN)
    return res.status(401).json({error:"Unauthorized"});

  const { key } = req.body;
  await Key.deleteOne({ keyHash: hash(key) });

  res.json({ success:true });
});

// ===== LIST KEYS =====
app.get("/keys", async (req,res)=>{
  if(req.headers.authorization !== ADMIN_TOKEN)
    return res.status(401).json({error:"Unauthorized"});

  const keys = await Key.find().sort({ createdAt: -1 });
  res.json(keys);
});

// ===== LOGS =====
app.get("/logs", async (req,res)=>{
  if(req.headers.authorization !== ADMIN_TOKEN)
    return res.status(401).json({error:"Unauthorized"});

  const logs = await Log.find().sort({ timestamp: -1 }).limit(100);
  res.json(logs);
});

// ===== AUTO CLEAN EXPIRED =====
setInterval(async ()=>{
  await Key.deleteMany({ expiresAt: { $lt: new Date() } });
  console.log("🧹 Cleaned expired keys");
}, 60 * 60 * 1000);

// ===== START =====
app.listen(PORT, ()=>console.log("🚀 PRO++ Server Running"));
