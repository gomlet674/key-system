const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();

app.set("trust proxy", 1);
app.use(express.json());
app.use(cors());
app.use(helmet());

// ===== CONFIG =====
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "admin123";

// ===== DB =====
mongoose.connect(MONGO_URI)
.then(()=>console.log("✅ Mongo Connected"))
.catch(err=>console.log(err));

const keySchema = new mongoose.Schema({
  key: String,
  ip: String,
  device: String,
  isVPN: Boolean,
  createdAt: Date,
  expiresAt: Date
});

const Key = mongoose.model("Key", keySchema);

// ===== UTIL =====
function generateKey(){
  return crypto.randomBytes(8).toString("hex").toUpperCase();
}

function getDevice(req){
  return (req.headers["user-agent"] || "") +
         (req.headers["accept-language"] || "");
}

// ===== VPN DETECTION =====
async function checkVPN(ip){
  try{
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=proxy,hosting`);
    const data = await res.json();

    return data.proxy || data.hosting;
  }catch{
    return false;
  }
}

// ===== ROOT =====
app.get("/", (req,res)=>{
  res.send("🔐 GOD MODE ACTIVE");
});

// ===== KEY ROUTE =====
app.get("/:slug", async (req,res)=>{
  const slug = req.params.slug;

  if(slug.length < 6){
    return res.status(404).send("Not Found");
  }

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

  // ===== DETEKSI VPN =====
  const isVPN = await checkVPN(ip);

  if(isVPN){
    return res.send("❌ VPN / Proxy terdeteksi! Matikan terlebih dahulu.");
  }

  const key = generateKey();
  const expiresAt = new Date(Date.now() + 24*60*60*1000);

  await Key.create({
    key,
    ip,
    device,
    isVPN,
    createdAt: now,
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

  res.json({ valid: !!found });
});

// ===== ADMIN AUTH =====
function adminAuth(req,res,next){
  const token = req.headers["authorization"];
  if(token !== ADMIN_TOKEN){
    return res.status(403).send("Forbidden");
  }
  next();
}

// ===== ADMIN DASHBOARD API =====
app.get("/admin/data", adminAuth, async (req,res)=>{
  const total = await Key.countDocuments();
  const active = await Key.countDocuments({
    expiresAt: { $gt: new Date() }
  });
  const vpn = await Key.countDocuments({ isVPN: true });

  res.json({ total, active, vpn });
});

// ===== ADMIN PANEL UI =====
app.get("/admin", (req,res)=>{
  res.send(`
<!DOCTYPE html>
<html>
<body style="background:#111;color:white;font-family:sans-serif">

<h2>Admin Dashboard</h2>

<input id="token" placeholder="Admin Token">
<button onclick="load()">Load</button>

<pre id="out"></pre>

<script>
async function load(){
  const token = document.getElementById("token").value;

  const res = await fetch("/admin/data",{
    headers:{ "Authorization": token }
  });

  const text = await res.text();
  document.getElementById("out").innerText = text;
}
</script>

</body>
</html>
  `);
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
  background:url('https://images.unsplash.com/photo-1501785888041-af3ef285b470') center/cover;
  font-family:sans-serif;
}

.card{
  background:rgba(0,0,0,0.7);
  padding:30px;
  border-radius:20px;
  color:white;
  width:90%;
  max-width:600px;
}

.keybox{
  display:flex;
  justify-content:space-between;
  background:#111;
  padding:20px;
  border-radius:10px;
}

button{
  background:#4facfe;
  border:none;
  padding:10px;
  border-radius:10px;
  color:white;
}
</style>
</head>

<body>

<div class="card">
<h3>KEY:</h3>

<div class="keybox">
<div id="k">${key}</div>
<button onclick="copy()">COPY</button>
</div>

<div id="t"></div>
</div>

<script>
function copy(){
navigator.clipboard.writeText("${key}");
alert("Copied!");
}
</script>

</body>
</html>
  `);
}

// ===== START =====
app.listen(PORT, ()=>{
  console.log("🚀 Running on " + PORT);
});
