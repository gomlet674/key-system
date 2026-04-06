const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

app.set("trust proxy", 1);
app.use(express.json());
app.use(cors());
app.use(helmet());

// ===== CONFIG =====
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "12345";

// ===== DB =====
mongoose.connect(MONGO_URI)
.then(()=>console.log("✅ Mongo Connected"))
.catch(err=>console.log(err));

const Key = mongoose.model("Key", new mongoose.Schema({
  key:String,
  ip:String,
  device:String,
  risk:Number,
  createdAt:Date,
  expiresAt:Date
}));

// ===== UTIL =====
function genKey(){
  return crypto.randomBytes(8).toString("hex").toUpperCase();
}

function getIP(req){
  return req.headers["x-forwarded-for"]?.split(",")[0] || req.ip;
}

function getDevice(req){
  return (req.headers["user-agent"]||"");
}

function randomSlug(){
  return crypto.randomBytes(5).toString("hex");
}

// ===== SMART DETECTION =====
function riskCheck(req){
  let r = 0;
  const ua = (req.headers["user-agent"]||"").toLowerCase();

  if(!ua) r+=40;
  if(ua.includes("bot")) r+=30;
  if(ua.includes("curl")) r+=50;

  return r;
}

// ===== START =====
app.get("/start",(req,res)=>{
  res.redirect("/"+randomSlug());
});

// ===== MAIN =====
app.get("/:slug", async(req,res)=>{
  const slug = req.params.slug;
  if(slug.length < 6) return res.send("Not Found");

  const ip = getIP(req);
  const device = getDevice(req);
  const now = new Date();

  let exist = await Key.findOne({
    ip, device,
    expiresAt:{$gt:now}
  });

  if(exist){
    return sendUI(res, exist.key, exist.expiresAt);
  }

  const risk = riskCheck(req);

  const key = genKey();
  const expiresAt = new Date(Date.now()+86400000);

  await Key.create({
    key, ip, device, risk,
    createdAt:now,
    expiresAt
  });

  sendUI(res,key,expiresAt);
});

// ===== VERIFY =====
app.post("/verify", async(req,res)=>{
  const {key} = req.body;

  const found = await Key.findOne({
    key,
    expiresAt:{$gt:new Date()}
  });

  res.json({valid:!!found});
});

// ===== ADMIN LOGIN PAGE =====
app.get("/admin",(req,res)=>{
res.send(`
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
  background:#0f172a;
  color:white;
  font-family:sans-serif;
  display:flex;
  justify-content:center;
  align-items:center;
  height:100vh;
}
.box{
  background:#1e293b;
  padding:30px;
  border-radius:15px;
  text-align:center;
}
input{
  padding:10px;
  width:200px;
  border-radius:10px;
  border:none;
}
button{
  margin-top:10px;
  padding:10px 20px;
  border:none;
  border-radius:10px;
  background:#3b82f6;
  color:white;
}
</style>
</head>
<body>

<div class="box">
<h2>Admin Login</h2>
<input id="t" placeholder="Token"><br>
<button onclick="login()">Login</button>
<p id="msg"></p>
</div>

<script>
async function login(){
  const token=document.getElementById("t").value;

  const res=await fetch("/admin/data",{
    headers:{Authorization:token}
  });

  if(res.status!==200){
    document.getElementById("msg").innerText="❌ Wrong Token";
    return;
  }

  location.href="/admin/panel?token="+token;
}
</script>

</body>
</html>
`);
});

// ===== ADMIN PANEL =====
app.get("/admin/panel",(req,res)=>{
res.send(`
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{background:#0f172a;color:white;font-family:sans-serif;padding:20px;}
.card{background:#1e293b;padding:20px;border-radius:15px;margin:10px;}
</style>
</head>
<body>

<h2>Dashboard</h2>

<div class="card" id="data">Loading...</div>

<script>
const token=new URLSearchParams(location.search).get("token");

async function load(){
  const res=await fetch("/admin/data",{headers:{Authorization:token}});
  const d=await res.json();

  document.getElementById("data").innerHTML=
  "Total: "+d.total+"<br>"+
  "Active: "+d.active+"<br>"+
  "High Risk: "+d.high;
}

setInterval(load,2000);
load();
</script>

</body>
</html>
`);
});

// ===== ADMIN DATA =====
app.get("/admin/data", async(req,res)=>{
  if(req.headers.authorization !== ADMIN_TOKEN){
    return res.status(403).send("Forbidden");
  }

  const total = await Key.countDocuments();
  const active = await Key.countDocuments({expiresAt:{$gt:new Date()}});
  const high = await Key.countDocuments({risk:{$gte:30}});

  res.json({total,active,high});
});

// ===== UI KEY (BAGUS) =====
function sendUI(res,key,exp){
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
  background:rgba(0,0,0,0.6);
  backdrop-filter:blur(15px);
  padding:30px;
  border-radius:20px;
  color:white;
  width:90%;
  max-width:600px;
}
.box{
  display:flex;
  justify-content:space-between;
  background:#111;
  padding:20px;
  border-radius:10px;
}
.key{font-size:22px;}
button{
  background:#3b82f6;
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
<div class="box">
<div class="key">${key}</div>
<button onclick="copy()">COPY</button>
</div>
<p id="t"></p>
</div>

<script>
function copy(){
navigator.clipboard.writeText("${key}");
alert("Copied");
}
const exp=new Date("${exp}").getTime();
setInterval(()=>{
let d=exp-new Date().getTime();
if(d<=0)return document.getElementById("t").innerText="Expired";
let h=Math.floor(d/3600000);
let m=Math.floor(d%3600000/60000);
let s=Math.floor(d%60000/1000);
document.getElementById("t").innerText="Expires "+h+"h "+m+"m "+s+"s";
},1000);
</script>

</body>
</html>
`);
}

// ===== START =====
app.listen(PORT,()=>console.log("🚀 Running "+PORT));
