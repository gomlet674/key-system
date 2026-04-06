const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const app = express();
app.set("trust proxy", 1); // Wajib untuk Railway / Reverse Proxy
app.use(express.json());
app.use(cors());
app.use(helmet({
  contentSecurityPolicy: false // Dimatikan agar script/CSS inline untuk UI dapat berjalan
}));

// ===== CONFIG =====
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI; 
const ADMIN_USER = process.env.ADMIN_USER || "admin";
// Default password sesuai permintaan Anda
const ADMIN_PASS = process.env.ADMIN_PASS || "Faiq_X7p9L2qZ_83AbK"; 
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key-system-faiq";

// ===== ANTI DDOS / RATE LIMIT (TAMBAHAN) =====
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100, // Limit 100 request per IP
  message: "Terlalu banyak request, coba lagi nanti."
});
app.use(limiter);

// ===== DB =====
mongoose.connect(MONGO_URI)
.then(()=>console.log("Mongo Connected Successfully!"))
.catch(err => console.error("Mongo Connection Error:", err));

// ===== SCHEMA =====
const Key = mongoose.model("Key", new mongoose.Schema({
  key: String,
  ip: String,
  device: String,
  risk: Number,
  createdAt: Date,
  expiresAt: Date
}));

const Ban = mongoose.model("Ban", new mongoose.Schema({
  ip: String,
  device: String,
  reason: String // Tambahan
}));

// ===== UTIL =====
function hashKey(key){
  return crypto.createHash("sha256").update(key).digest("hex");
}

function genKey(){
  return crypto.randomBytes(16).toString("hex");
}

function getIP(req){
  return req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
}

function fingerprint(req){
  return (req.headers["user-agent"]||"") + (req.headers["accept-language"]||"");
}

// ===== AI-LIKE BOT DETECTION (DIPERKETAT) =====
let reqLog = new Map();

// Pembersihan memori Map tiap 1 jam agar server tidak lag
setInterval(() => reqLog.clear(), 3600000);

function detectBot(req){
  const ip = getIP(req);
  const now = Date.now();

  let data = reqLog.get(ip) || {count:0, last:0};
  data.count++;

  if(now - data.last < 1000) data.count += 5; // Deteksi spam klik
  data.last = now;
  reqLog.set(ip, data);

  let risk = 0;
  const ua = (req.headers["user-agent"]||"").toLowerCase();

  // Logika asli
  if(!ua) risk += 50;
  if(ua.includes("bot")) risk += 50;
  if(ua.includes("curl")) risk += 50;
  if(data.count > 10) risk += 40;

  // Tambahan anti-bot ketat
  if(ua.includes("postman") || ua.includes("insomnia")) risk += 30;
  if(!req.headers["accept-language"]) risk += 20;

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

// ===== START =====
app.get("/start", (req, res) => {
  res.redirect("/secure-" + crypto.randomBytes(4).toString("hex"));
});

// ===== HUMAN CHECK (UI EXECUTOR DELTA STYLE) =====
app.get("/secure-:id", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Key System | Verification</title>
      <style>
        * { box-sizing: border-box; }
        body { margin: 0; padding: 0; background: #0f0f13; color: #fff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; overflow: hidden; }
        .bg-glow { position: absolute; width: 400px; height: 400px; background: radial-gradient(circle, rgba(138,43,226,0.3) 0%, rgba(0,0,0,0) 70%); top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: -1; }
        .container { background: rgba(25, 25, 30, 0.6); backdrop-filter: blur(15px); -webkit-backdrop-filter: blur(15px); padding: 40px; border-radius: 20px; border: 1px solid rgba(255,255,255,0.05); text-align: center; width: 90%; max-width: 400px; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }
        h3 { margin-top: 0; font-weight: 600; font-size: 24px; color: #f0f0f0; margin-bottom: 5px; }
        p { color: #888; font-size: 14px; margin-bottom: 25px; }
        .captcha-box { background: rgba(0,0,0,0.5); padding: 15px; font-size: 28px; letter-spacing: 8px; font-weight: bold; border-radius: 10px; margin-bottom: 20px; color: #8a2be2; text-shadow: 0 0 10px rgba(138,43,226,0.5); user-select: none; border: 1px solid rgba(138,43,226,0.2); }
        input { width: 100%; padding: 15px; margin-bottom: 20px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.1); background: rgba(0,0,0,0.4); color: white; font-size: 16px; outline: none; transition: 0.3s; text-align: center; }
        input:focus { border-color: #8a2be2; box-shadow: 0 0 15px rgba(138,43,226,0.3); }
        button { background: linear-gradient(135deg, #8a2be2, #4b0082); color: white; border: none; padding: 15px; width: 100%; border-radius: 10px; font-size: 16px; cursor: pointer; transition: 0.3s; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }
        button:hover { opacity: 0.9; transform: translateY(-2px); box-shadow: 0 5px 15px rgba(138,43,226,0.4); }
        .loader { display: none; margin: 0 auto 20px; border: 4px solid rgba(255,255,255,0.1); border-top: 4px solid #8a2be2; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
      </style>
    </head>
    <body>
      <div class="bg-glow"></div>
      <div class="container">
        <h3>Verify you are human</h3>
        <p>Complete the captcha to get your key.</p>
        <div class="loader" id="loader"></div>
        <div class="captcha-box" id="c">----</div>
        <input type="number" id="i" placeholder="Enter PIN code here" autocomplete="off">
        <button onclick="go()">Continue</button>
      </div>

      <script>
        let cid, code;
        fetch("/captcha").then(r=>r.json()).then(d=>{
          cid = d.id; 
          code = d.code;
          document.getElementById("c").innerText = code;
        });

        function go(){
          const val = document.getElementById("i").value;
          if(!val) return alert("Please enter the code!");
          
          document.getElementById("loader").style.display = "block";
          document.getElementById("c").style.display = "none";
          
          setTimeout(() => {
            location.href = "/getkey?cid=" + cid + "&val=" + val;
          }, 800);
        }
      </script>
    </body>
    </html>
  `);
});

// ===== GET KEY =====
app.get("/getkey", async(req, res) => {
  const {cid, val} = req.query;

  if(!checkCaptcha(cid, val)) {
    return res.status(400).send("<h3>Captcha salah atau kadaluarsa. Silakan refresh.</h3>");
  }

  const ip = getIP(req);
  const device = fingerprint(req);

  const risk = detectBot(req);
  if(risk > 80) return res.status(403).send("<h3>Akses Ditolak (Sistem mendeteksi aktivitas Bot/Abnormal)</h3>");

  const banned = await Ban.findOne({ip}); // Cek Ban by IP
  if(banned) return res.status(403).send("<h3>Anda telah di Ban dari sistem ini.</h3>");

  const now = new Date();

  // Cek apakah sudah punya key aktif
  let exist = await Key.findOne({
    ip, device,
    expiresAt: {$gt: now}
  });

  if(exist){
    return res.send(renderKeyPage(exist.key));
  }

  const rawKey = genKey();
  const hashed = hashKey(rawKey);
  const exp = new Date(Date.now() + 86400000); // 24 Jam

  await Key.create({
    key: hashed,
    ip, device,
    risk,
    createdAt: now,
    expiresAt: exp
  });

  res.send(renderKeyPage(rawKey));
});

// Halaman Sukses Dapat Key
function renderKeyPage(key) {
  return `
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
      body{ background:#0f0f13; color:#fff; font-family:sans-serif; text-align:center; padding-top:20vh; }
      .box{ background:rgba(25,25,30,0.8); border: 1px solid #8a2be2; padding:30px; border-radius:15px; display:inline-block; max-width:90%; }
      input{ background:#000; color:#0f0; border:none; padding:10px; width:250px; text-align:center; margin-top:10px; border-radius:5px; outline:none; }
      button{ background:#8a2be2; color:#fff; padding:10px 20px; border:none; border-radius:5px; margin-top:15px; cursor:pointer; }
    </style></head><body>
      <div class="box">
        <h2>🎉 Success!</h2>
        <p>Your generated key is valid for 24 hours.</p>
        <input type="text" id="k" value="${key}" readonly><br>
        <button onclick="navigator.clipboard.writeText(document.getElementById('k').value); alert('Copied!')">Copy Key</button>
      </div>
    </body></html>
  `;
}

// ===== VERIFY UNTUK ROBLOX =====
// Endpoint ini dipakai oleh script Roblox (HTTPService)
app.post("/verify", async(req, res) => {
  const {key} = req.body;
  if(!key) return res.json({valid: false, msg:"No key provided"});

  const hashed = hashKey(key);

  const found = await Key.findOne({
    key: hashed,
    expiresAt: {$gt: new Date()}
  });

  res.json({valid: !!found});
});

// ===== JWT LOGIN =====
app.post("/admin/login", (req, res) => {
  const {user, pass} = req.body;

  if(user !== ADMIN_USER || pass !== ADMIN_PASS){
    return res.status(401).json({msg: "Kredensial Salah!"});
  }

  const token = jwt.sign({user}, JWT_SECRET, {expiresIn: "12h"});
  res.json({token});
});

// ===== AUTH MIDDLEWARE =====
function auth(req, res, next){
  try{
    const token = req.headers.authorization;
    jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    res.status(403).json({msg: "Forbidden / Token Invalid"});
  }
}

// ===== ADMIN API =====
app.get("/admin/data", auth, async(req, res) => {
  const keys = await Key.find().sort({createdAt: -1}).limit(100);
  const bans = await Ban.find().sort({_id: -1});
  res.json({keys, bans});
});

app.post("/admin/ban", auth, async(req, res) => {
  const {ip, device, reason} = req.body;
  await Ban.create({ip, device, reason: reason || "Banned by Admin"});
  res.json({ok: true});
});

app.post("/admin/unban", auth, async(req, res) => {
  const {ip} = req.body;
  await Ban.deleteOne({ip});
  res.json({ok: true});
});

// ===== ADMIN FRONTEND PANEL (LENGKAP & MEWAH) =====
app.get("/admin", (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - Dashboard</title>
    <style>
      :root { --bg: #0f0f13; --panel: #1a1a20; --primary: #8a2be2; --text: #fff; --text-dim: #aaa; }
      body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; }
      .login-container { display:flex; justify-content:center; align-items:center; height: 100vh; }
      .box { background: var(--panel); padding: 40px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); width: 100%; max-width: 350px; text-align:center; border: 1px solid rgba(255,255,255,0.05); }
      input { width: 100%; padding: 12px; margin-bottom: 15px; border-radius: 6px; border: 1px solid #333; background: #000; color: white; outline: none; box-sizing:border-box;}
      button { background: var(--primary); color: white; border: none; padding: 12px; width: 100%; border-radius: 6px; cursor: pointer; font-weight: bold; }
      button:hover { opacity: 0.8; }
      
      /* Dashboard Styles */
      #dashboard { display: none; padding: 20px; max-width: 1200px; margin: auto; }
      header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; padding-bottom: 20px; margin-bottom: 20px; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
      .card { background: var(--panel); padding: 20px; border-radius: 10px; border: 1px solid #333; }
      table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size:14px; }
      th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
      th { color: var(--primary); }
      .badge { background: #28a745; color: white; padding: 3px 8px; border-radius: 12px; font-size: 12px; }
      .badge.high { background: #dc3545; }
      .btn-sm { padding: 5px 10px; font-size:12px; background:#dc3545; border-radius:4px; border:none; color:#fff; cursor:pointer;}
      .btn-sm.map { background:#007bff; }
    </style>
  </head>
  <body>

    <div id="login-screen" class="login-container">
      <div class="box">
        <h2>Admin Login</h2>
        <p style="color:var(--text-dim);font-size:14px;">Masukkan kredensial JWT</p>
        <input type="text" id="user" placeholder="Username (admin)">
        <input type="password" id="pass" placeholder="Password (Faiq_...)">
        <button onclick="login()">Login</button>
      </div>
    </div>

    <div id="dashboard">
      <header>
        <h2>Control Panel <span style="color:var(--primary);">Key System</span></h2>
        <button onclick="logout()" style="width:auto; background:#dc3545;">Logout</button>
      </header>

      <div class="grid">
        <div class="card">
          <h3>Active Keys (Recent)</h3>
          <div style="overflow-x:auto;">
            <table>
              <thead><tr><th>IP Address</th><th>Risk</th><th>Exp</th><th>Action</th></tr></thead>
              <tbody id="key-table"></tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <h3>Banned Users</h3>
          <div style="overflow-x:auto;">
            <table>
              <thead><tr><th>IP Address</th><th>Reason</th><th>Action</th></tr></thead>
              <tbody id="ban-table"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <script>
      const token = localStorage.getItem("jwt_token");
      if(token) {
        document.getElementById("login-screen").style.display = "none";
        document.getElementById("dashboard").style.display = "block";
        loadData();
      }

      async function login() {
        const user = document.getElementById("user").value;
        const pass = document.getElementById("pass").value;
        const res = await fetch("/admin/login", {
          method: "POST", headers: {"Content-Type":"application/json"},
          body: JSON.stringify({user, pass})
        });
        const data = await res.json();
        if(data.token) {
          localStorage.setItem("jwt_token", data.token);
          location.reload();
        } else {
          alert("Login gagal: " + data.msg);
        }
      }

      function logout() {
        localStorage.removeItem("jwt_token");
        location.reload();
      }

      async function loadData() {
        const res = await fetch("/admin/data", {
          headers: { "Authorization": localStorage.getItem("jwt_token") }
        });
        if(res.status === 403) return logout();
        const data = await res.json();
        
        let keyHTML = '';
        data.keys.forEach(k => {
          const isExp = new Date(k.expiresAt) < new Date();
          const riskCls = k.risk > 50 ? 'high' : '';
          keyHTML += \`<tr>
            <td>\${k.ip}</td>
            <td><span class="badge \${riskCls}">\${k.risk}</span></td>
            <td>\${isExp ? 'Expired' : 'Active'}</td>
            <td>
              <button class="btn-sm" onclick="ban('\${k.ip}')">Ban IP</button>
              <button class="btn-sm map" onclick="trackIP('\${k.ip}')">Track</button>
            </td>
          </tr>\`;
        });
        document.getElementById("key-table").innerHTML = keyHTML;

        let banHTML = '';
        data.bans.forEach(b => {
          banHTML += \`<tr>
            <td>\${b.ip}</td>
            <td>\${b.reason || '-'}</td>
            <td><button class="btn-sm map" onclick="unban('\${b.ip}')">Unban</button></td>
          </tr>\`;
        });
        document.getElementById("ban-table").innerHTML = banHTML;
      }

      async function ban(ip) {
        if(!confirm("Ban IP: " + ip + "?")) return;
        await fetch("/admin/ban", {
          method:"POST", headers:{"Content-Type":"application/json", "Authorization": localStorage.getItem("jwt_token")},
          body: JSON.stringify({ip})
        });
        loadData();
      }

      async function unban(ip) {
        await fetch("/admin/unban", {
          method:"POST", headers:{"Content-Type":"application/json", "Authorization": localStorage.getItem("jwt_token")},
          body: JSON.stringify({ip})
        });
        loadData();
      }

      // Fitur Lacak Lokasi via API Gratis
      async function trackIP(ip) {
        try {
          // Jika IP localhost/private, lewati
          if(ip === "::1" || ip === "127.0.0.1") return alert("IP Localhost");
          const res = await fetch("http://ip-api.com/json/" + ip);
          const data = await res.json();
          if(data.status === "success") {
            alert(\`IP: \${data.query}\\nLokasi: \${data.city}, \${data.country}\\nISP: \${data.isp}\\nVPN/Proxy Check manual diperlukan.\`);
          } else {
            alert("Gagal melacak IP");
          }
        } catch(e) { alert("Error API Map"); }
      }
    </script>
  </body>
  </html>
  `);
});

// ===== START =====
app.listen(PORT, () => console.log("✅ SERVER RUNNING ON PORT " + PORT));
