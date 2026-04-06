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
  windowMs: 10 * 60 * 1000, // 10 menit
  max: 150, // Maksimal 150 request per IP
  message: "IP Anda diblokir sementara karena terdeteksi spam/serangan DDOS."
});
app.use(globalLimiter);

// ===== DB CONNECTION =====
mongoose.connect(MONGO_URI)
.then(()=>console.log("✅ Database MongoDB Terhubung (Ultra Mode)"))
.catch(err => console.error("❌ Error DB:", err));

// ===== SCHEMA (Diperbarui untuk Pengintaian) =====
const Key = mongoose.model("Key", new mongoose.Schema({
  keyValue: String, // Key asli disimpan (tidak di-hash agar Admin bisa lihat)
  ip: String,
  hwid: { type: String, default: "Belum Verifikasi" }, // Lock ke 1 Device Executor
  device: String,
  risk: Number,
  createdAt: Date,
  expiresAt: Date
}));

const Ban = mongoose.model("Ban", new mongoose.Schema({
  ip: String,
  hwid: String, // Ban berdasarkan Device Roblox juga
  reason: String,
  date: { type: Date, default: Date.now }
}));

// ===== UTILS & SECURITY TRACKING =====
function genKey(){
  return "GMON-" + crypto.randomBytes(6).toString("hex").toUpperCase();
}

function getIP(req){
  return req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
}

// Deteksi Device Browser
function fingerprint(req){
  return (req.headers["user-agent"]||"") + (req.headers["accept-language"]||"");
}

// Deteksi HWID dari Executor Roblox
function getExecutorHWID(req) {
  return req.headers["syn-fingerprint"] || 
         req.headers["krnl-hwid"] || 
         req.headers["flux-fingerprint"] || 
         req.headers["delta-hwid"] ||
         req.headers["identifier"] || 
         "UNKNOWN_HWID";
}

// Pengintaian Ekstra (Bot & Bypasser Detection)
let reqLog = new Map();
setInterval(() => reqLog.clear(), 1800000); // Bersihkan memori per 30 menit

function detectBot(req){
  const ip = getIP(req);
  const now = Date.now();
  let data = reqLog.get(ip) || {count:0, last:0};
  data.count++;
  if(now - data.last < 500) data.count += 10; // Spam klik sangat cepat = BOT
  data.last = now;
  reqLog.set(ip, data);

  let risk = 0;
  const ua = (req.headers["user-agent"]||"").toLowerCase();

  if(!ua || ua === "") risk += 100; // Kosong = Bypasser script
  if(ua.includes("bot") || ua.includes("curl") || ua.includes("python") || ua.includes("postman")) risk += 80;
  if(ua.includes("bypass") || ua.includes("adblock")) risk += 60;
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

// ===== WEB ROUTES =====
app.get("/start", (req, res) => {
  res.redirect("/secure-" + crypto.randomBytes(4).toString("hex"));
});

app.get("/secure-:id", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>G-MON Security Check</title>
      <style>
        body { background: #0b0b0e; color: #fff; font-family: 'Courier New', Courier, monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .box { background: rgba(20,20,25,0.9); padding: 30px; border: 1px solid #ff003c; border-radius: 10px; box-shadow: 0 0 20px rgba(255,0,60,0.3); text-align: center; width: 320px; }
        h3 { color: #ff003c; text-transform: uppercase; letter-spacing: 2px; }
        .c-box { font-size: 30px; font-weight: bold; letter-spacing: 10px; margin: 20px 0; color: #0f0; text-shadow: 0 0 10px #0f0; user-select: none; }
        input { width: 90%; padding: 10px; background: #000; border: 1px solid #555; color: #0f0; text-align: center; font-size: 18px; outline: none; margin-bottom: 20px; }
        input:focus { border-color: #ff003c; }
        button { background: #ff003c; color: white; padding: 10px 20px; border: none; font-weight: bold; cursor: pointer; text-transform: uppercase; width: 100%; transition: 0.3s; }
        button:hover { background: #cc0030; box-shadow: 0 0 10px #ff003c; }
      </style>
    </head>
    <body>
      <div class="box">
        <h3>System Firewall</h3>
        <p style="font-size:12px; color:#aaa;">Verifikasi untuk mendapatkan akses key.</p>
        <div class="c-box" id="c">----</div>
        <input type="number" id="i" placeholder="INPUT PIN CODE">
        <button onclick="go()">Verify Identity</button>
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

// ===== GET KEY CORE =====
app.get("/getkey", async(req, res) => {
  const {cid, val} = req.query;
  if(!checkCaptcha(cid, val)) return res.status(400).send("<h3 style='color:red; text-align:center; margin-top:50px;'>Akses Ditolak: Captcha Salah. Kembali dan coba lagi.</h3>");

  const ip = getIP(req);
  const device = fingerprint(req);
  const risk = detectBot(req);

  if(risk >= 100) return res.status(403).send("<h3 style='color:red; text-align:center; margin-top:50px;'>Akses Diblokir: Terdeteksi Anomali Bypasser.</h3>");

  const banned = await Ban.findOne({ip});
  if(banned) return res.status(403).send("<h3 style='color:red; text-align:center; margin-top:50px;'>IP Anda telah di-BAN dari sistem.</h3>");

  // HAPUS KEY LAMA AGAR TIDAK BENTROK (FIX INVALID ERROR)
  await Key.deleteMany({ ip }); 

  const newKey = genKey();
  const exp = new Date(Date.now() + 86400000); // 24 Jam

  await Key.create({
    keyValue: newKey, // Disimpan mentah agar admin bisa memantau
    ip, device, risk,
    createdAt: new Date(),
    expiresAt: exp
  });

  res.send(`
    <html><body style="background:#0b0b0e; color:#fff; text-align:center; padding-top:15vh; font-family:monospace;">
      <h1 style="color:#0f0; text-shadow:0 0 10px #0f0;">ACCESS GRANTED</h1>
      <p style="color:#aaa;">Sistem mencatat IP Anda. Key berlaku 24 jam.</p>
      <div style="background:#111; padding:20px; border:1px solid #ff003c; display:inline-block; margin-top:20px;">
        <h2 style="margin:0; letter-spacing:2px;">${newKey}</h2>
      </div>
      <br><br>
      <button onclick="navigator.clipboard.writeText('${newKey}'); alert('Key Tersalin!');" style="background:#ff003c; color:#fff; padding:10px 20px; border:none; cursor:pointer; font-weight:bold;">COPY KEY</button>
    </body></html>
  `);
});

// ===== ROBLOX API VERIFICATION (WITH HWID LOCK) =====
app.post("/verify", async(req, res) => {
  try {
    const { key } = req.body;
    if(!key) return res.json({valid: false, msg: "No Key"});

    const ip = getIP(req);
    const executorHWID = getExecutorHWID(req);

    // Cek Ban berdasarkan HWID atau IP
    const isBanned = await Ban.findOne({ $or: [{ip}, {hwid: executorHWID}] });
    if(isBanned) return res.json({valid: false, msg: "BANNED"});

    const found = await Key.findOne({ keyValue: key, expiresAt: {$gt: new Date()} });

    if(!found) return res.json({valid: false, msg: "Key Invalid / Expired"});

    // SYSTEM HWID LOCK:
    if(found.hwid === "Belum Verifikasi") {
      // Pertama kali diverifikasi, kunci ke HWID ini
      found.hwid = executorHWID;
      await found.save();
      return res.json({valid: true, msg: "Verified & Locked to Device"});
    } else {
      // Jika sudah pernah diverifikasi, cek apakah HWID nya sama
      if(found.hwid !== executorHWID) {
        return res.json({valid: false, msg: "Key is Locked to another Device (Anti-Share)"});
      }
    }

    res.json({valid: true, msg: "Verified"});
  } catch(e) {
    res.json({valid: false, msg: "Server Error"});
  }
});

// ===== ADMIN PANEL API =====
app.post("/admin/login", (req, res) => {
  const {user, pass} = req.body;
  if(user !== ADMIN_USER || pass !== ADMIN_PASS) return res.status(401).json({msg: "Akses Ditolak"});
  const token = jwt.sign({user}, JWT_SECRET, {expiresIn: "12h"});
  res.json({token});
});

function auth(req, res, next){
  try{ jwt.verify(req.headers.authorization, JWT_SECRET); next(); } 
  catch(e){ res.status(403).json({msg: "Unauthorized"}); }
}

app.get("/admin/data", auth, async(req, res) => {
  const keys = await Key.find().sort({createdAt: -1}).limit(100);
  const bans = await Ban.find().sort({_id: -1});
  res.json({keys, bans});
});

app.post("/admin/ban", auth, async(req, res) => {
  const {ip, hwid, reason} = req.body;
  await Ban.create({ip, hwid, reason});
  await Key.deleteMany({ip}); // Hapus semua key miliknya
  res.json({ok: true});
});

app.post("/admin/deletekey", auth, async(req, res) => {
  const {id} = req.body;
  await Key.findByIdAndDelete(id);
  res.json({ok: true});
});

app.post("/admin/unban", auth, async(req, res) => {
  await Ban.findByIdAndDelete(req.body.id);
  res.json({ok: true});
});

// ===== ADMIN DASHBOARD FRONTEND =====
app.get("/admin", (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html>
  <head>
    <title>G-MON Security Dashboard</title>
    <style>
      body { background: #0a0a0c; color: #eee; font-family: 'Segoe UI', sans-serif; margin:0; }
      .nav { background: #111; padding: 15px 20px; border-bottom: 2px solid #ff003c; display:flex; justify-content:space-between; align-items:center; }
      .container { padding: 20px; max-width: 1300px; margin: auto; display:none; }
      .card { background: #15151a; border: 1px solid #333; padding: 20px; margin-bottom: 20px; border-radius: 8px; }
      table { width: 100%; border-collapse: collapse; text-align: left; font-size:14px; }
      th, td { padding: 10px; border-bottom: 1px solid #222; }
      th { color: #ff003c; text-transform: uppercase; font-size: 12px; }
      .key-text { color: #0f0; font-family: monospace; letter-spacing: 1px; }
      .btn { padding: 5px 10px; border:none; cursor:pointer; font-weight:bold; border-radius:3px; }
      .btn-danger { background: #ff003c; color: white; }
      .btn-warning { background: #ffaa00; color: #000; }
      #login { display:flex; justify-content:center; align-items:center; height:100vh; }
      .login-box { background:#111; padding:40px; border:1px solid #ff003c; text-align:center; }
      input { width:100%; padding:10px; margin-bottom:15px; background:#000; color:#fff; border:1px solid #333; }
    </style>
  </head>
  <body>
    <div id="login">
      <div class="login-box">
        <h2 style="color:#ff003c;">ADMIN LOGIN</h2>
        <input id="u" type="text" placeholder="Username">
        <input id="p" type="password" placeholder="Password">
        <button class="btn btn-danger" style="width:100%; padding:10px;" onclick="login()">ENTER SYSTEM</button>
      </div>
    </div>

    <div class="container" id="dash">
      <div class="nav">
        <h2 style="margin:0; color:#ff003c;">SURVEILLANCE PANEL</h2>
        <button class="btn btn-danger" onclick="logout()">LOGOUT</button>
      </div>
      <div class="card">
        <h3>Live Keys Monitoring</h3>
        <table id="kt"></table>
      </div>
      <div class="card">
        <h3>Banned Entities</h3>
        <table id="bt"></table>
      </div>
    </div>

    <script>
      const token = localStorage.getItem("adm_tk");
      if(token){ document.getElementById("login").style.display="none"; document.getElementById("dash").style.display="block"; loadData(); }

      async function login(){
        const res = await fetch("/admin/login", {
          method: "POST", headers: {"Content-Type":"application/json"},
          body: JSON.stringify({user: document.getElementById('u').value, pass: document.getElementById('p').value})
        });
        const data = await res.json();
        if(data.token){ localStorage.setItem("adm_tk", data.token); location.reload(); } else alert("GAGAL");
      }
      function logout(){ localStorage.removeItem("adm_tk"); location.reload(); }

      async function loadData(){
        const res = await fetch("/admin/data", {headers: {"Authorization": token}});
        if(res.status===403) return logout();
        const data = await res.json();
        
        document.getElementById("kt").innerHTML = \`<tr><th>Key (Raw)</th><th>IP Asal</th><th>HWID (Device Roblox)</th><th>Risk</th><th>Aksi</th></tr>\` + 
        data.keys.map(k => \`<tr>
          <td class="key-text">\${k.keyValue}</td>
          <td>\${k.ip}</td>
          <td style="color:#aaa; font-size:11px;">\${k.hwid}</td>
          <td style="color:\${k.risk>50?'red':'lime'}">\${k.risk}</td>
          <td>
            <button class="btn btn-warning" onclick="delKey('\${k._id}')">Hapus Key</button>
            <button class="btn btn-danger" onclick="ban('\${k.ip}', '\${k.hwid}')">Ban IP & HWID</button>
          </td>
        </tr>\`).join('');

        document.getElementById("bt").innerHTML = \`<tr><th>IP</th><th>HWID</th><th>Alasan</th><th>Aksi</th></tr>\` + 
        data.bans.map(b => \`<tr>
          <td>\${b.ip}</td>
          <td style="color:#aaa; font-size:11px;">\${b.hwid}</td>
          <td>\${b.reason}</td>
          <td><button class="btn btn-warning" onclick="unban('\${b._id}')">Unban</button></td>
        </tr>\`).join('');
      }

      async function delKey(id){
        if(confirm("Hapus Key ini? User akan terputus.")){
          await fetch("/admin/deletekey", {method:"POST", headers:{"Content-Type":"application/json", "Authorization": token}, body: JSON.stringify({id})});
          loadData();
        }
      }
      async function ban(ip, hwid){
        let reason = prompt("Alasan Ban:");
        if(reason !== null){
          await fetch("/admin/ban", {method:"POST", headers:{"Content-Type":"application/json", "Authorization": token}, body: JSON.stringify({ip, hwid, reason: reason||"Bypasser"})});
          loadData();
        }
      }
      async function unban(id){
        await fetch("/admin/unban", {method:"POST", headers:{"Content-Type":"application/json", "Authorization": token}, body: JSON.stringify({id})});
        loadData();
      }
    </script>
  </body>
  </html>
  `);
});

app.listen(PORT, () => console.log("🔥 SERVER SECURE RUNNING ON " + PORT));
