const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));

// ===== CONFIG =====
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI; 
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "Faiq_X7p9L2qZ_83AbK"; 
const JWT_SECRET = process.env.JWT_SECRET || "gmon-ultra-secret-key";

// ===== ANTI DDOS & SPAM LIMITER =====
const globalLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, 
  max: 150, 
  message: "IP Anda diblokir sementara karena terlalu banyak request."
});
app.use(globalLimiter);

// ===== DB CONNECTION =====
mongoose.connect(MONGO_URI)
.then(()=>console.log("✅ Database MongoDB Terhubung (Modern Mode)"))
.catch(err => console.error("❌ Error DB:", err));

// ===== SCHEMA =====
const Key = mongoose.model("Key", new mongoose.Schema({
  keyValue: String,
  ip: String,
  hwid: { type: String, default: "Belum Verifikasi" },
  device: String,
  risk: Number,
  createdAt: Date,
  expiresAt: Date
}));

const Ban = mongoose.model("Ban", new mongoose.Schema({
  ip: String,
  hwid: String,
  reason: String,
  date: { type: Date, default: Date.now }
}));

// ===== UTILS =====
function genKey(){
  return "GMON-" + crypto.randomBytes(6).toString("hex").toUpperCase();
}

function getIP(req){
  return req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
}

function fingerprint(req){
  return (req.headers["user-agent"]||"") + (req.headers["accept-language"]||"");
}

function getExecutorHWID(req) {
  return req.headers["syn-fingerprint"] || 
         req.headers["krnl-hwid"] || 
         req.headers["flux-fingerprint"] || 
         req.headers["delta-hwid"] ||
         req.headers["identifier"] || 
         "UNKNOWN_HWID";
}

let reqLog = new Map();
setInterval(() => reqLog.clear(), 1800000); 

function detectBot(req){
  const ip = getIP(req);
  const now = Date.now();
  let data = reqLog.get(ip) || {count:0, last:0};
  data.count++;
  if(now - data.last < 500) data.count += 10;
  data.last = now;
  reqLog.set(ip, data);

  let risk = 0;
  const ua = (req.headers["user-agent"]||"").toLowerCase();
  if(!ua || ua === "") risk += 100;
  if(ua.includes("bot") || ua.includes("curl") || ua.includes("python")) risk += 80;
  if(data.count > 15) risk += 50;

  return risk;
}

// ===== CAPTCHA =====
let captcha = {};
app.get("/captcha", (req, res) => {
  const id = crypto.randomBytes(5).toString("hex");
  const code = Math.floor(1000 + Math.random() * 9000);
  captcha[id] = code;
  res.json({id, code});
});

function checkCaptcha(id, val){
  return captcha[id] && captcha[id] == val;
}

// ===== UI RENDERERS (MODERN DELTA/FLUXUS STYLE) =====
function renderKeyPage(key) {
  return `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>G-MON Hub | Key</title>
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
      body { background-color: #09090b; color: #ffffff; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
      .card { background: #18181b; padding: 40px; border-radius: 16px; box-shadow: 0 10px 40px rgba(0,0,0,0.5); text-align: center; width: 90%; max-width: 400px; border: 1px solid #27272a; }
      .logo { font-size: 26px; font-weight: 800; margin-bottom: 8px; background: linear-gradient(90deg, #8b5cf6, #3b82f6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
      .subtitle { color: #a1a1aa; font-size: 14px; margin-bottom: 30px; }
      .key-box { background: #000000; padding: 18px; border-radius: 10px; border: 1px solid #3f3f46; margin-bottom: 25px; }
      .key-text { font-family: 'Courier New', monospace; font-size: 18px; color: #e4e4e7; font-weight: 600; letter-spacing: 1px; }
      .btn { background: #6366f1; color: white; border: none; padding: 14px 24px; border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer; width: 100%; transition: 0.3s; }
      .btn:hover { background: #4f46e5; transform: translateY(-2px); box-shadow: 0 8px 20px rgba(99, 102, 241, 0.4); }
    </style>
  </head>
  <body>
    <div class="card">
      <div class="logo">G-MON HUB</div>
      <div class="subtitle">Your whitelist key has been generated. Valid for 24 hours.</div>
      <div class="key-box"><div class="key-text" id="keyText">${key}</div></div>
      <button class="btn" onclick="copyKey()">Copy Key</button>
    </div>
    <script>
      function copyKey() {
        navigator.clipboard.writeText(document.getElementById('keyText').innerText).then(() => {
          const btn = document.querySelector('.btn');
          btn.innerText = 'Copied Successfully!';
          btn.style.background = '#10b981';
          setTimeout(() => { btn.innerText = 'Copy Key'; btn.style.background = '#6366f1'; }, 2000);
        });
      }
    </script>
  </body>
  </html>`;
}

function renderErrorPage(msg) {
  return `<html lang="en"><body style="background:#09090b; color:#fff; font-family:'Inter',sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; text-align:center;">
    <div><h2 style="color:#ef4444;">Access Denied</h2><p style="color:#a1a1aa;">${msg}</p></div>
  </body></html>`;
}

// ===== WEB ROUTES =====
app.get("/start", (req, res) => {
  res.redirect("/checkpoint-" + crypto.randomBytes(4).toString("hex"));
});

app.get("/checkpoint-:id", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>G-MON Checkpoint</title>
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
        body { background: #09090b; color: #fff; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: #18181b; padding: 40px; border-radius: 16px; border: 1px solid #27272a; text-align: center; width: 90%; max-width: 350px; }
        h2 { margin:0 0 10px 0; color: #e4e4e7; }
        .pin-display { font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #8b5cf6; margin: 25px 0; }
        input { width: 85%; padding: 12px; background: #000; border: 1px solid #3f3f46; border-radius: 8px; color: #fff; text-align: center; font-size: 16px; outline: none; margin-bottom: 20px; transition: 0.3s; }
        input:focus { border-color: #8b5cf6; }
        button { background: #6366f1; color: white; padding: 12px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; width: 100%; transition: 0.3s; }
        button:hover { background: #4f46e5; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Security Check</h2>
        <p style="color:#a1a1aa; font-size:14px; margin:0;">Complete this step to continue.</p>
        <div class="pin-display" id="c">----</div>
        <input type="number" id="i" placeholder="Enter PIN from above">
        <button onclick="go()">Continue</button>
      </div>
      <script>
        let cid;
        fetch("/captcha").then(r=>r.json()).then(d=>{ cid=d.id; document.getElementById("c").innerText=d.code; });
        function go(){ location.href="/getkey?cid="+cid+"&val="+document.getElementById("i").value; }
      </script>
    </body>
    </html>
  `);
});

// ===== GET KEY CORE (LOGIKA DIPERBAIKI) =====
app.get("/getkey", async(req, res) => {
  const ip = getIP(req);
  const device = fingerprint(req);

  // 1. CEK KEY YANG SUDAH ADA (AGAR TETAP SAMA JIKA DI REFRESH)
  const existingKey = await Key.findOne({ ip, expiresAt: { $gt: new Date() } });
  if (existingKey) {
    // Jika key masih aktif, langsung tampilkan tanpa perlu verifikasi ulang
    return res.send(renderKeyPage(existingKey.keyValue));
  }

  // 2. JIKA BELUM PUNYA KEY, CEK CAPTCHA DARI HALAMAN SEBELUMNYA
  const {cid, val} = req.query;
  if(!checkCaptcha(cid, val)) {
    return res.status(400).send(renderErrorPage("Invalid or Expired Captcha. Please go back to /start"));
  }

  const risk = detectBot(req);
  if(risk >= 100) return res.status(403).send(renderErrorPage("Anomaly detected. Request blocked."));

  const banned = await Ban.findOne({ip});
  if(banned) return res.status(403).send(renderErrorPage("Your IP has been banned from using this service."));

  // Hapus key lama yang sudah expire (bersihkan DB)
  await Key.deleteMany({ ip }); 

  // Buat Key Baru
  const newKey = genKey();
  const exp = new Date(Date.now() + 86400000); // 24 Jam

  await Key.create({
    keyValue: newKey, 
    ip, device, risk,
    createdAt: new Date(),
    expiresAt: exp
  });

  // Tampilkan UI
  res.send(renderKeyPage(newKey));
});

// ===== ROBLOX API VERIFICATION =====
app.post("/verify", async(req, res) => {
  try {
    const { key } = req.body;
    if(!key) return res.json({valid: false, msg: "No Key Provided"});

    const ip = getIP(req);
    const executorHWID = getExecutorHWID(req);

    const isBanned = await Ban.findOne({ $or: [{ip}, {hwid: executorHWID}] });
    if(isBanned) return res.json({valid: false, msg: "Your device is BANNED."});

    const found = await Key.findOne({ keyValue: key, expiresAt: {$gt: new Date()} });
    if(!found) return res.json({valid: false, msg: "Invalid or Expired Key"});

    // HWID Lock System
    if(found.hwid === "Belum Verifikasi") {
      found.hwid = executorHWID;
      await found.save();
      return res.json({valid: true, msg: "Verified & Locked"});
    } else {
      if(found.hwid !== executorHWID) {
        return res.json({valid: false, msg: "Key used on another device."});
      }
    }

    res.json({valid: true, msg: "Verified"});
  } catch(e) {
    res.json({valid: false, msg: "Server Error"});
  }
});

// ===== ADMIN PANEL API & DASHBOARD (TETAP SAMA SEPERTI SEBELUMNYA) =====
// (Sengaja saya singkat kode dashboard admin di jawaban ini agar tidak kepanjangan, 
//  Anda bisa menggunakan kode app.post("/admin/...") dan app.get("/admin") 
//  dari jawaban saya sebelumnya, letakkan di bagian sini persis.)
app.listen(PORT, () => console.log("✨ G-MON SERVER RUNNING ON " + PORT));
