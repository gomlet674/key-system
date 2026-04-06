const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const app = express();

// ===== CONFIG =====
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI; 
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "Faiq_X7p9L2qZ_83AbK"; 
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key-system-faiq";

// Middlewares
app.set("trust proxy", 1);
app.use(express.json());
app.use(cors());
app.use(helmet({
  contentSecurityPolicy: false 
}));

// ===== DATABASE CONNECTION =====
mongoose.connect(MONGO_URI)
  .then(() => console.log("🚀 Database Connected Successfully!"))
  .catch(err => {
    console.error("❌ Database Connection Error:", err);
    process.exit(1); // Stop server jika DB gagal
  });

// ===== SCHEMAS =====
const KeySchema = new mongoose.Schema({
  key: { type: String, required: true },
  ip: { type: String, index: true },
  device: String,
  risk: Number,
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, index: { expires: '24h' } } // Auto-delete dari MongoDB setelah 24 jam
});

const BanSchema = new mongoose.Schema({
  ip: { type: String, unique: true },
  device: String,
  reason: String,
  bannedAt: { type: Date, default: Date.now }
});

const Key = mongoose.model("Key", KeySchema);
const Ban = mongoose.model("Ban", BanSchema);

// ===== UTILITIES =====
function genKey() {
  return "FAIQ-" + crypto.randomBytes(6).toString("hex").toUpperCase();
}

function getIP(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
}

function fingerprint(req) {
  return (req.headers["user-agent"] || "unknown") + (req.headers["accept-language"] || "");
}

// ===== ANTI-BOT & SPAM LOGIC =====
let reqLog = new Map();
setInterval(() => reqLog.clear(), 600000); // Bersihkan log setiap 10 menit

function detectBot(req) {
  const ip = getIP(req);
  const now = Date.now();
  const ua = (req.headers["user-agent"] || "").toLowerCase();

  let data = reqLog.get(ip) || { count: 0, last: 0 };
  data.count++;
  
  if (now - data.last < 500) data.count += 5; // Deteksi klik terlalu cepat
  data.last = now;
  reqLog.set(ip, data);

  let risk = 0;
  if (!ua || ua.length < 10) risk += 60;
  if (ua.includes("bot") || ua.includes("python") || ua.includes("curl") || ua.includes("postman")) risk += 100;
  if (data.count > 20) risk += 50;

  return risk;
}

// ===== CAPTCHA SYSTEM (FIXED MEMORY LEAK) =====
let captchaStore = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [id, data] of captchaStore) {
        if (now - data.time > 300000) captchaStore.delete(id); // Hapus captcha > 5 menit
    }
}, 60000);

app.get("/captcha", (req, res) => {
  const id = crypto.randomBytes(4).toString("hex");
  const code = Math.floor(1000 + Math.random() * 9000);
  captchaStore.set(id, { code, time: Date.now() });
  res.json({ id, code });
});

// ===== RATE LIMITER =====
const globalLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Terlalu banyak permintaan. Silakan coba lagi nanti."
});
app.use("/getkey", globalLimit);

// ===== ROUTES =====

app.get("/", (req, res) => {
  res.redirect("/start");
});

app.get("/start", (req, res) => {
  res.redirect("/secure-" + crypto.randomBytes(4).toString("hex"));
});

// Human Verification UI
app.get("/secure-:id", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Verification System</title>
      <style>
        body { margin: 0; background: #0b0b0f; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .card { background: #15151a; padding: 30px; border-radius: 15px; text-align: center; border: 1px solid #333; width: 350px; }
        .captcha { font-size: 32px; font-weight: bold; color: #a855f7; letter-spacing: 5px; background: #000; padding: 10px; border-radius: 8px; margin: 20px 0; }
        input { width: 100%; padding: 12px; margin: 10px 0; border-radius: 8px; border: 1px solid #333; background: #000; color: #fff; box-sizing: border-box; text-align: center; font-size: 18px; }
        button { width: 100%; padding: 12px; border-radius: 8px; border: none; background: #a855f7; color: #fff; font-weight: bold; cursor: pointer; transition: 0.3s; }
        button:hover { background: #9333ea; }
      </style>
    </head>
    <body>
      <div class="card">
        <h3>Verify You Are Human</h3>
        <p style="color:#777">Enter the code shown below</p>
        <div class="captcha" id="code-display">....</div>
        <input type="number" id="user-input" placeholder="Enter PIN">
        <button onclick="verify()">Continue</button>
      </div>
      <script>
        let cid = "";
        async function loadCaptcha() {
          const r = await fetch('/captcha');
          const d = await r.json();
          cid = d.id;
          document.getElementById('code-display').innerText = d.code;
        }
        function verify() {
          const val = document.getElementById('user-input').value;
          if(!val) return alert("Fill the captcha!");
          window.location.href = \`/getkey?cid=\${cid}&val=\${val}\`;
        }
        loadCaptcha();
      </script>
    </body>
    </html>
  `);
});

// GET KEY LOGIC
app.get("/getkey", async (req, res) => {
  const { cid, val } = req.query;
  const ip = getIP(req);
  const dev = fingerprint(req);

  // 1. Check Ban
  const isBanned = await Ban.findOne({ ip });
  if (isBanned) return res.status(403).send("<h1>Access Denied: Your IP is banned.</h1>");

  // 2. Check Bot Risk
  if (detectBot(req) > 90) return res.status(403).send("<h1>Bot Detected! Access blocked.</h1>");

  // 3. Verify Captcha
  const captcha = captchaStore.get(cid);
  if (!captcha || captcha.code != val) {
    return res.status(400).send("<h1>Invalid Captcha. Please <a href='/start'>Try Again</a></h1>");
  }
  captchaStore.delete(cid); // Hapus setelah dipakai

  // 4. Check Existing Key
  let existing = await Key.findOne({ ip, device: dev, expiresAt: { $gt: new Date() } });
  
  if (existing) {
    return res.send(renderKeyPage(existing.key));
  }

  // 5. Create New Key
  const newKey = genKey();
  await Key.create({
    key: newKey,
    ip,
    device: dev,
    risk: detectBot(req),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
  });

  res.send(renderKeyPage(newKey));
});

function renderKeyPage(key) {
  return `
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>
    body{ background:#0b0b0f; color:#fff; font-family:sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }
    .box{ background:#15151a; padding:40px; border-radius:20px; border:1px solid #a855f7; text-align:center; box-shadow: 0 0 20px rgba(168,85,247,0.2); }
    input{ background:#000; color:#22c55e; border:1px solid #333; padding:12px; width:250px; text-align:center; border-radius:8px; font-family:monospace; font-size:18px; outline:none; }
    button{ background:#a855f7; color:#fff; padding:12px 25px; border:none; border-radius:8px; margin-top:20px; cursor:pointer; font-weight:bold; }
    </style></head><body>
      <div class="box">
        <h2 style="margin-top:0">Key Generated!</h2>
        <p style="color:#777">Valid for 24 Hours</p>
        <input type="text" id="k" value="${key}" readonly><br>
        <button onclick="navigator.clipboard.writeText('${key}'); alert('Key Copied!')">Copy to Clipboard</button>
      </div>
    </body></html>
  `;
}

// ===== VERIFY FOR ROBLOX =====
app.post("/verify", async (req, res) => {
  const { key } = req.body;
  if (!key) return res.json({ valid: false, msg: "Key is required" });

  const found = await Key.findOne({ key, expiresAt: { $gt: new Date() } });

  if (found) {
    res.json({ valid: true, msg: "Key valid" });
  } else {
    res.json({ valid: false, msg: "Key invalid or expired" });
  }
});

// ===== ADMIN SYSTEM =====
app.post("/admin/login", (req, res) => {
  const { user, pass } = req.body;
  if (user === ADMIN_USER && pass === ADMIN_PASS) {
    const token = jwt.sign({ user }, JWT_SECRET, { expiresIn: "12h" });
    return res.json({ token });
  }
  res.status(401).json({ msg: "Wrong Credentials" });
});

const auth = (req, res, next) => {
  try {
    const token = req.headers.authorization;
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ msg: "Unauthorized" });
  }
};

app.get("/admin/data", auth, async (req, res) => {
  const keys = await Key.find().sort({ createdAt: -1 }).limit(50);
  const bans = await Ban.find().sort({ _id: -1 });
  res.json({ keys, bans });
});

app.post("/admin/ban", auth, async (req, res) => {
  const { ip, reason } = req.body;
  await Ban.updateOne({ ip }, { ip, reason: reason || "Admin Decision" }, { upsert: true });
  res.json({ ok: true });
});

app.post("/admin/unban", auth, async (req, res) => {
  await Ban.deleteOne({ ip: req.body.ip });
  res.json({ ok: true });
});

// Admin Panel UI (Sederhana & Fungsional)
app.get("/admin", (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html>
  <head>
    <title>Admin Dashboard</title>
    <style>
      body { background: #000; color: #fff; font-family: sans-serif; padding: 20px; }
      .container { max-width: 1000px; margin: auto; }
      table { width: 100%; border-collapse: collapse; margin-top: 20px; }
      th, td { border: 1px solid #333; padding: 10px; text-align: left; }
      th { background: #a855f7; }
      .btn { padding: 5px 10px; cursor: pointer; border: none; border-radius: 4px; }
      .ban { background: #ef4444; color: #fff; }
      .login-box { text-align:center; margin-top: 100px; }
      input { padding: 10px; margin: 5px; border-radius: 5px; border: none; }
    </style>
  </head>
  <body>
    <div class="container" id="app">
      <div id="login-form" class="login-box">
        <h2>Admin Login</h2>
        <input type="text" id="u" placeholder="Username"><br>
        <input type="password" id="p" placeholder="Password"><br>
        <button class="btn" style="background:#a855f7; color:#fff" onclick="login()">Login</button>
      </div>

      <div id="dashboard" style="display:none">
        <h2>Admin Panel</h2>
        <button class="btn ban" onclick="localStorage.clear(); location.reload()">Logout</button>
        <h3>Recent Keys</h3>
        <table id="kt"></table>
        <h3>Banned IPs</h3>
        <table id="bt"></table>
      </div>
    </div>

    <script>
      const token = localStorage.getItem('token');
      if(token) showDash();

      async function login() {
        const res = await fetch('/admin/login', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({user: u.value, pass: p.value})
        });
        const data = await res.json();
        if(data.token) {
          localStorage.setItem('token', data.token);
          showDash();
        } else alert("Failed");
      }

      async function showDash() {
        document.getElementById('login-form').style.display = 'none';
        document.getElementById('dashboard').style.display = 'block';
        const res = await fetch('/admin/data', { headers: {'Authorization': localStorage.getItem('token')}});
        const data = await res.json();
        
        let kh = '<tr><th>IP</th><th>Key</th><th>Action</th></tr>';
        data.keys.forEach(k => {
          kh += \`<tr><td>\${k.ip}</td><td>\${k.key}</td><td><button class="btn ban" onclick="ban('\${k.ip}')">Ban</button></td></tr>\`;
        });
        kt.innerHTML = kh;

        let bh = '<tr><th>IP</th><th>Reason</th><th>Action</th></tr>';
        data.bans.forEach(b => {
          bh += \`<tr><td>\${b.ip}</td><td>\${b.reason}</td><td><button class="btn" style="background:#22c55e" onclick="unban('\${b.ip}')">Unban</button></td></tr>\`;
        });
        bt.innerHTML = bh;
      }

      async function ban(ip) {
        await fetch('/admin/ban', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'Authorization': localStorage.getItem('token')},
          body: JSON.stringify({ip, reason: "Manual Ban"})
        });
        showDash();
      }

      async function unban(ip) {
        await fetch('/admin/unban', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'Authorization': localStorage.getItem('token')},
          body: JSON.stringify({ip})
        });
        showDash();
      }
    </script>
  </body>
  </html>
  `);
});

// Start Server
app.listen(PORT, () => {
  console.log(`✅ SERVER RUNNING ON PORT ${PORT}`);
});
