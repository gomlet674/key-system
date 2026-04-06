const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI; // isi MongoDB Atlas URI di Railway Variables
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "Faiq_X7p9L2qZ_83AbK";

mongoose.connect(MONGO_URI)
  .then(()=>console.log("✅ MongoDB Connected"))
  .catch(err=>console.log("❌ MongoDB Error:",err));

const KeySchema = new mongoose.Schema({
  key: String,
  createdAt: { type: Date, default: Date.now },
  expiresAt: Date
});

const Key = mongoose.model("Key", KeySchema);

// Generate random key
function generateKey(length=16){
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = "";
  for(let i=0;i<length;i++){
    key += chars.charAt(Math.floor(Math.random()*chars.length));
  }
  return key;
}

// Request key (call setelah user selesai monetisasi)
app.post("/request-key", async (req,res)=>{
  // Optional: auth header untuk keamanan
  const newKey = generateKey(16);
  const expiresAt = new Date(Date.now() + 24*60*60*1000); // 1 hari
  try{
    await Key.create({key:newKey, expiresAt});
    res.json({key:newKey});
  }catch(err){
    res.status(500).json({error:err.message});
  }
});

// Verify key
app.post("/verify-key", async (req,res)=>{
  const {key} = req.body;
  const found = await Key.findOne({key});
  if(!found) return res.json({valid:false,message:"Key not found"});
  if(found.expiresAt < new Date()) return res.json({valid:false,message:"Key expired"});
  res.json({valid:true,message:"Key valid"});
});

app.listen(PORT,()=>console.log(`🚀 Key System Server running on port ${PORT}`));
