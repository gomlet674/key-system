const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

// ===== BASIC MIDDLEWARE =====
app.set("trust proxy", 1); // WAJIB di Railway
app.use(express.json());
app.use(cors());
app.use(helmet());

// ===== CONFIG =====
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "CHANGE_ME_STRONG_TOKEN";

// ===== DATABASE =====
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ Mongo Connected"))
  .catch(err => console.error("❌ Mongo Error:", err));

const keySchema = new mongoose.Schema({
  key: String,
  ip: String,
  device: String,
  riskScore: Number,
  riskLevel: String, // low / medium / high
  createdAt: Date,
  expiresAt: Date
});

const Key = mongoose.model("Key", keySchema);

// ===== UTILS =====
function generateKey() {
  return crypto.randomBytes(8).toString("hex").toUpperCase();
}

function randomSlug(len = 10) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function getIP(req) {
  // ambil IP asli dari proxy (Railway)
  const xf = req.headers["x-forwarded-for"];
  if (xf) return xf.split(",")[0].trim();
  return req.ip;
}

function getDevice(req) {
  return (req.headers["user-agent"] || "") + "|" +
         (req.headers["accept-language"] || "");
}

// ===== SMART DETECTION (TANPA BLOCK KERAS) =====
function computeRisk(req) {
  let score = 0;
  const ua = (req.headers["user-agent"] || "").toLowerCase();

  // indikasi headless / bot sederhana
  if (!ua) score += 40;
  if (ua.includes("curl") || ua.includes("wget")) score += 40;
  if (ua.includes("bot") || ua.includes("spider")) score += 30;
  if (ua.includes("headless")) score += 30;

  // header aneh / minim
  if (!req.headers["accept-language"]) score += 10;

  // burst sederhana (tanpa block keras)
  // (catatan: ini hanya indikasi, bukan limit keras)
  const now = Date.now();
  const key = getIP(req) + "|" + getDevice(req);
  if (!app.locals.reqMap) app.locals.reqMap = new Map();
  const last = app.locals.reqMap.get(key) || 0;
  if (now - last < 1500) score += 15; // request terlalu cepat
  app.locals.reqMap.set(key, now);

  let level = "low";
  if (score >= 60) level = "high";
  else if (score >= 30) level = "medium";

  return { score, level };
}

// ===== ROOT =====
app.get("/", (req, res) => {
  res.send("🔐 Smart Detection Key System Active");
});

// ===== START (redirect ke slug acak) =====
app.get("/start", (req, res) => {
  const slug = randomSlug(10);
  res.redirect("/" + slug);
});

// ===== MAIN (SEMUA SLUG) =====
app.get("/:slug", async (req, res) => {
  const slug = req.params.slug;

  // validasi slug minimal
  if (slug.length < 6) {
    return res.status(404).send("Not Found");
  }

  const ip = getIP(req);
  const device = getDevice(req);
  const now = new Date();

  // ===== CARI KEY EXISTING =====
  const existing = await Key.findOne({
    ip,
    device,
    expiresAt: { $gt: now }
  });

  if (existing) {
    return sendUI(res, existing.key, existing.expiresAt);
  }

  // ===== SMART DETECTION =====
  const risk = computeRisk(req);
  console.log(`IP: ${ip} | Risk: ${risk.level} (${risk.score})`);

  // ===== GENERATE KEY =====
  const key = generateKey();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await Key.create({
    key,
    ip,
    device,
    riskScore: risk.score,
    riskLevel: risk.level,
    createdAt: now,
    expiresAt
  });

  sendUI(res, key, expiresAt);
});

// ===== VERIFY =====
app.post("/verify", async (req, res) => {
  const { key } = req.body;
  const now = new Date();

  const found = await Key.findOne({
    key,
    expiresAt: { $gt: now }
  });

  res.json({ valid: !!found });
});

// ===== ADMIN AUTH =====
function adminAuth(req, res, next) {
  const token = req.headers["authorization"];
  if (token !== ADMIN_TOKEN) {
    return res.status(403).send("Forbidden");
  }
  next();
}

// ===== ADMIN DATA =====
app.get("/admin/data", adminAuth, async (req, res) => {
  const total = await Key.countDocuments();
  const active = await Key.countDocuments({ expiresAt: { $gt: new Date() } });
  const highRisk = await Key.countDocuments({ riskLevel: "high" });

  res.json({
    total,
    active,
    highRisk
  });
});

// ===== ADMIN UI =====
app.get("/admin", (req, res) => {
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
  const txt = await res.text();
  document.getElementById("out").innerText = txt;
}
</script>

</body>
</html>
  `);
});

// ===== UI =====
function sendUI(res, key, expiresAt) {
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
  font-family:sans-serif;
  background:url('https://images.unsplash.com/photo-1501785888041-af3ef285b470') center/cover;
}
.card{
  width:90%;
  max-width:600px;
  background:rgba(0,0,0,0.7);
  padding:30px;
  border-radius:20px;
  color:white;
}
.box{
  display:flex;
  justify-content:space-between;
  background:#111;
  padding:20px;
  border-radius:10px;
}
.key{
  font-size:22px;
  word-break:break-all;
}
button{
  background:#4facfe;
  border:none;
  padding:10px;
  border-radius:10px;
  color:white;
}
.timer{margin-top:10px;}
</style>
</head>
<body>
<div class="card">
<h3>KEY:</h3>
<div class="box">
<div class="key" id="k">${key}</div>
<button onclick="copy()">COPY</button>
</div>
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
  const d = exp - now;
  if(d <= 0){
    document.getElementById("t").innerText = "Expired";
    return;
  }
  const h = Math.floor(d/3600000);
  const m = Math.floor((d%3600000)/60000);
  const s = Math.floor((d%60000)/1000);
  document.getElementById("t").innerText =
    "Expires in: "+h+"h "+m+"m "+s+"s";
},1000);
</script>

</body>
</html>
  `);
}

// ===== CLEANUP (opsional) =====
setInterval(async () => {
  await Key.deleteMany({ expiresAt: { $lt: new Date() } });
}, 60 * 60 * 1000);

// ===== START =====
app.listen(PORT, () => {
  console.log("🚀 Running on port " + PORT);
});
