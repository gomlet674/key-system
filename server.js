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

// ===== DB CONNECTION =====
mongoose.connect(MONGO_URI).then(()=>console.log("✅ Database Connected")).catch(err => console.error(err));

// ===== SCHEMA =====
const Key = mongoose.model("Key", new mongoose.Schema({
  keyValue: String,
  ip: String,
  hwid: { type: String, default: "Not Verified" },
  risk: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  expiresAt: Date
}));

const Ban = mongoose.model("Ban", new mongoose.Schema({
  ip: String,
  reason: { type: String, default: "Banned by Admin" },
  date: { type: Date, default: Date.now }
}));

// ===== UTILS =====
function genKey(){ return "GMON-" + crypto.randomBytes(8).toString("hex").toUpperCase(); }
function getIP(req){ return req.headers["x-forwarded-for"]?.split(",")[0] || req.ip; }

// ===== UI RENDERER (FLUXUS STYLE) =====
const UI_TEMPLATE = (content) => `
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
        body { background: #09090b; color: #fff; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: #18181b; padding: 40px; border-radius: 16px; border: 1px solid #27272a; text-align: center; width: 90%; max-width: 380px; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }
        .logo { font-size: 26px; font-weight: 800; background: linear-gradient(90deg, #818cf8, #c084fc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 10px; }
        .btn { background: #6366f1; color: #fff; border: none; padding: 12px; border-radius: 8px; font-weight: 600; cursor: pointer; width: 100%; transition: 0.3s; margin-top:15px; }
        .btn:hover { background: #4f46e5; transform: translateY(-2px); }
        .box { background: #000; padding: 15px; border-radius: 10px; border: 1px solid #3f3f46; margin: 20px 0; font-family: monospace; color: #a5b4fc; }
    </style>
</head>
<body><div class="card">${content}</div></body>
</html>`;

// ===== ROUTES =====
app.get("/start", (req, res) => res.redirect("/secure-" + crypto.randomBytes(4).toString("hex")));

app.get("/secure-:id", (req, res) => {
    const code = Math.floor(1000 + Math.random() * 9000);
    res.send(UI_TEMPLATE(`
        <div class="logo">Verification</div>
        <p style="color:#a1a1aa; font-size:14px;">Please enter the PIN below to continue.</p>
        <div style="font-size:32px; font-weight:800; color:#818cf8; letter-spacing:8px; margin:20px;">${code}</div>
        <input type="number" id="v" placeholder="Enter PIN" style="width:100%; padding:10px; background:#000; border:1px solid #3f3f46; color:#fff; border-radius:8px; text-align:center;">
        <button class="btn" onclick="go()">Continue</button>
        <script>function go(){ if(document.getElementById('v').value == '${code}') location.href='/getkey'; else alert('Wrong PIN'); }</script>
    `));
});

app.get("/getkey", async(req, res) => {
    const ip = getIP(req);
    // ANTI-REFRESH LOGIC: Cek key aktif
    let keyData = await Key.findOne({ ip, expiresAt: { $gt: new Date() } });
    
    if(!keyData) {
        const newKey = genKey();
        keyData = await Key.create({ keyValue: newKey, ip, expiresAt: new Date(Date.now() + 86400000) });
    }

    res.send(UI_TEMPLATE(`
        <div class="logo">G-MON HUB</div>
        <p style="color:#a1a1aa; font-size:14px;">Key valid for 24 hours. Don't share it!</p>
        <div class="box" id="key">${keyData.keyValue}</div>
        <button class="btn" onclick="navigator.clipboard.writeText('${keyData.keyValue}'); alert('Copied!')">Copy Key</button>
    `));
});

// ===== API VERIFY =====
app.post("/verify", async(req, res) => {
    const { key } = req.body;
    const ip = getIP(req);
    const hwid = req.headers["identifier"] || "UNKNOWN";

    const isBanned = await Ban.findOne({ ip });
    if(isBanned) return res.json({ valid: false, msg: "BANNED" });

    const found = await Key.findOne({ keyValue: key, expiresAt: { $gt: new Date() } });
    if(!found) return res.json({ valid: false, msg: "Invalid Key" });

    if(found.hwid === "Not Verified") {
        found.hwid = hwid;
        await found.save();
    } else if(found.hwid !== hwid) {
        return res.json({ valid: false, msg: "HWID Mismatch" });
    }

    res.json({ valid: true });
});

// ===== ADMIN PANEL =====
app.post("/admin/login", (req, res) => {
    if(req.body.user === ADMIN_USER && req.body.pass === ADMIN_PASS) {
        return res.json({ token: jwt.sign({user: ADMIN_USER}, JWT_SECRET, {expiresIn: "12h"}) });
    }
    res.status(401).json({msg: "Failed"});
});

const auth = (req, res, next) => {
    try { jwt.verify(req.headers.authorization, JWT_SECRET); next(); } catch(e) { res.status(403).send("No"); }
};

app.get("/admin/data", auth, async(req, res) => {
    const keys = await Key.find().sort({createdAt: -1}).limit(50);
    const bans = await Ban.find();
    res.json({keys, bans});
});

app.post("/admin/ban", auth, async(req, res) => {
    await Ban.create({ ip: req.body.ip });
    res.json({ok:true});
});

app.post("/admin/unban", auth, async(req, res) => {
    await Ban.deleteOne({ ip: req.body.ip });
    res.json({ok:true});
});

app.get("/admin", (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>G-MON | Dashboard</title>
        <style>
            body { background:#09090b; color:#eee; font-family:sans-serif; padding:20px; }
            .card { background:#18181b; padding:20px; border-radius:8px; border:1px solid #27272a; margin-bottom:20px; }
            table { width:100%; border-collapse:collapse; }
            th, td { text-align:left; padding:12px; border-bottom:1px solid #27272a; font-size:13px; }
            .btn { padding:5px 10px; border-radius:4px; border:none; cursor:pointer; font-weight:600; }
            .btn-red { background:#ef4444; color:#fff; }
            .btn-blue { background:#3b82f6; color:#fff; }
        </style>
    </head>
    <body>
        <div id="login">
            <input id="u" placeholder="Admin"><input id="p" type="password" placeholder="Pass">
            <button onclick="login()">Login</button>
        </div>
        <div id="main" style="display:none">
            <div class="card">
                <h3>System Monitor</h3>
                <table>
                    <thead><tr><th>Key</th><th>IP</th><th>HWID</th><th>Actions</th></tr></thead>
                    <tbody id="list"></tbody>
                </table>
            </div>
            <div class="card">
                <h3>Banned IPs</h3>
                <tbody id="blist"></tbody>
            </div>
        </div>
        <script>
            async function login(){
                const r = await fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:document.getElementById('u').value,pass:document.getElementById('p').value})});
                const d = await r.json(); if(d.token){ localStorage.setItem('tk',d.token); location.reload(); }
            }
            if(localStorage.getItem('tk')){
                document.getElementById('login').style.display='none';
                document.getElementById('main').style.display='block';
                load();
            }
            async function load(){
                const tk = localStorage.getItem('tk');
                const r = await fetch('/admin/data',{headers:{'Authorization':tk}});
                const d = await r.json();
                document.getElementById('list').innerHTML = d.keys.map(k => \`
                    <tr>
                        <td style="color:#818cf8">\${k.keyValue}</td>
                        <td>\${k.ip}</td>
                        <td>\${k.hwid}</td>
                        <td>
                            <button class="btn btn-red" onclick="act('/admin/ban','\${k.ip}')">Ban</button>
                            <button class="btn btn-blue" onclick="track('\${k.ip}')">Track</button>
                        </td>
                    </tr>\`).join('');
            }
            async function act(path, ip){ await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','Authorization':localStorage.getItem('tk')},body:JSON.stringify({ip})}); load(); }
            async function track(ip){
                const r = await fetch('http://ip-api.com/json/'+ip);
                const d = await r.json();
                alert(\`Lokasi: \${d.city}, \${d.country}\\nISP: \${d.isp}\`);
            }
        </script>
    </body></html>
    `);
});

app.listen(PORT, () => console.log("🚀 Server Running"));
