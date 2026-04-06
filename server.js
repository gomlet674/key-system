const express = require("express");
const mongoose = require("mongoose");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");

const app = express();

app.set("trust proxy", 1);
app.use(express.json());
app.use(cors());
app.use(helmet());

// ===== CONFIG =====
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI;

// ===== DATABASE =====
mongoose.connect(MONGO_URI)
.then(()=>console.log("✅ Mongo Connected"))
.catch(err=>console.log(err));

const keySchema = new mongoose.Schema({
  key: String,
  ip: String,
  device: String,
  session: String,
  expiresAt: Date
});

const Key = mongoose.model("Key", keySchema);

// ===== RATE LIMIT =====
app.use(rateLimit({ windowMs: 60000, max: 100 }));

app.use("/getkey", rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 3
}));

// ===== UTIL =====
function generateKey(){
  return uuidv4().replace(/-/g,"").substring(0,16).toUpperCase();
}

function getDevice(req){
  return (req.headers["user-agent"] || "") +
         (req.headers["accept-language"] || "");
}

// ===== ROOT =====
app.get("/", (req,res)=>{
  res.send("🔐 FINAL BOSS SYSTEM RUNNING");
});

// ===== GET KEY =====
app.get("/getkey", async (req,res)=>{
  const ip = req.ip;
  const device = getDevice(req);
  const now = new Date();

  let existing = await Key.findOne({
    ip,
    device,
    expiresAt: { $gt: now }
  });

  if(existing){
    return sendUI(res, existing.key, existing.expiresAt);
  }

  const key = generateKey();
  const session = uuidv4();
  const expiresAt = new Date(Date.now() + 24*60*60*1000);

  await Key.create({
    key,
    ip,
    device,
    session,
    expiresAt
  });

  sendUI(res, key, expiresAt);
});

// ===== VERIFY =====
app.post("/verify", async (req,res)=>{
  const { key } = req.body;
  const now = new Date();

  const found = await Key.findOne({
    key,
    expiresAt: { $gt: now }
  });

  if(found){
    return res.json({ valid:true });
  }

  res.json({ valid:false });
});

// ===== ADMIN (OPTIONAL) =====
app.get("/admin/stats", async (req,res)=>{
  const total = await Key.countDocuments();
  const active = await Key.countDocuments({ expiresAt: { $gt: new Date() } });

  res.json({
    total_keys: total,
    active_keys: active
  });
});

// ===== UI =====
function sendUI(res, key, expiresAt){
  res.send(`
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>

body{
  margin:0;
  height:100vh;
  display:flex;
  justify-content:center;
  align-items:center;
  background: linear-gradient(135deg,#141e30,#243b55);
  font-family:sans-serif;
  color:white;
}

.card{
  width:520px;
  padding:30px;
  border-radius:20px;
  background:rgba(0,0,0,0.65);
  backdrop-filter:blur(20px);
  text-align:center;
  box-shadow:0 0 40px rgba(0,0,0,0.6);
}

.key{
  font-size:28px;
  letter-spacing:3px;
  background:#111;
  padding:20px;
  border-radius:10px;
  margin:20px 0;
}

button{
  padding:12px 30px;
  border:none;
  border-radius:10px;
  background:linear-gradient(45deg,#00c6ff,#0072ff);
  color:white;
  cursor:pointer;
}

.timer{
  margin-top:10px;
  font-size:14px;
}

</style>
</head>

<body>

<div class="card">
  <h2>🔐 ACCESS KEY</h2>

  <div class="key" id="k">${key}</div>

  <button onclick="copy()">COPY</button>

  <div class="timer" id="t"></div>
</div>

<script>
function copy(){
  navigator.clipboard.writeText("${key}");
  alert("Copied!");
}

const exp = new Date("${expiresAt}").getTime();

setInterval(()=>{
  const now = new Date().getTime();
  const diff = exp - now;

  if(diff <= 0){
    document.getElementById("t").innerText = "Expired";
    return;
  }

  const h = Math.floor(diff/(1000*60*60));
  const m = Math.floor((diff%(1000*60*60))/(1000*60));
  const s = Math.floor((diff%(1000*60))/1000);

  document.getElementById("t").innerText =
    "Expires in: " + h+"h "+m+"m "+s+"s";
},1000);
</script>

</body>
</html>
  `);
}

// ===== START =====
app.listen(PORT, ()=>{
  console.log("🚀 Server running on port " + PORT);
});
