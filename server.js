// server.js
const express = require("express");
const mongoose = require("mongoose");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const app = express();

const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "Faiq_X7p9L2qZ_83AbK";

// Trust proxy untuk Railway
app.set("trust proxy", 1);

app.use(express.json());
app.use(cors());

// Rate limit umum
app.use(rateLimit({
  windowMs: 1*60*1000, max:100, message:{error:"Too many requests"}
}));

// Rate limit khusus getkey
app.use("/getkey", rateLimit({
  windowMs: 10*60*1000, max:5, message:{error:"Request key too fast!"}
}));

// MongoDB
mongoose.connect(MONGO_URI,{useNewUrlParser:true,useUnifiedTopology:true})
  .then(()=>console.log("✅ MongoDB connected"))
  .catch(err=>console.log("❌ MongoDB error:",err));

const keySchema = new mongoose.Schema({
  key: String,
  ip: String,
  hardwareId: String,
  expiresAt: Date
});
const Key = mongoose.model("Key", keySchema);

function generateKey(length=12){
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "";
  for(let i=0;i<length;i++) result+=chars.charAt(Math.floor(Math.random()*chars.length));
  return result;
}

// Admin generate
app.post("/generate", async (req,res)=>{
  const auth = req.headers["authorization"];
  if(auth!==ADMIN_TOKEN) return res.status(401).json({error:"Unauthorized"});
  const {duration=1} = req.body;
  const key = generateKey();
  const expiresAt = new Date(Date.now() + duration*24*60*60*1000);
  await Key.create({key, ip:null, hardwareId:null, expiresAt});
  res.json({key, expiresAt});
});

// Public getkey
app.post("/getkey", async (req,res)=>{
  const {hardwareId} = req.body;
  if(!hardwareId) return res.status(400).json({error:"Missing hardwareId"});
  const ip = req.ip;
  const now = new Date();

  let existing = await Key.findOne({ ip, hardwareId, expiresAt:{$gt:now} });
  if(existing) return res.json({key:existing.key, expiresAt:existing.expiresAt});

  // generate new key unique
  let key = generateKey();
  while(await Key.findOne({key})) key = generateKey();

  const expiresAt = new Date(Date.now()+24*60*60*1000);
  await Key.create({key, ip, hardwareId, expiresAt});

  res.json({key, expiresAt});
});

// Verify key
app.post("/verify", async (req,res)=>{
  const {key, hardwareId} = req.body;
  const now = new Date();
  const doc = await Key.findOne({key, hardwareId, expiresAt:{$gt:now}});
  if(doc) return res.json({valid:true, key});
  res.json({valid:false});
});

app.get("/", (req,res)=>res.send("🔐 Key System PRO Running ✅"));

app.listen(PORT, ()=>console.log(`🚀 Server running on port ${PORT}`));
