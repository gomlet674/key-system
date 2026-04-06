/* * PROTECTED SOURCE CODE - FAIQ KEY SYSTEM
 * REVERSE ENGINEERING PROHIBITED
 */

const _0x51b = ['\x65\x78\x70\x72\x65\x73\x73', '\x6d\x6f\x6e\x67\x6f\x6f\x73\x65', '\x68\x65\x6c\x6d\x65\x74', '\x63\x6f\x72\x73', '\x63\x72\x79\x70\x74\x6f', '\x6a\x73\x6f\x6e\x77\x65\x62\x74\x6f\x6b\x65\x6e', '\x65\x78\x70\x72\x65\x73\x73\x2d\x72\x61\x74\x65\x2d\x6c\x69\x6d\x69\x74', '\x73\x68\x61\x32\x35\x36', '\x68\x65\x78', '\x74\x72\x75\x73\x74\x20\x70\x72\x6f\x78\x79', '\x73\x75\x70\x65\x72\x2d\x73\x65\x63\x72\x65\x74\x2d\x6b\x65\x79\x2d\x73\x79\x73\x74\x65\x6d\x2d\x66\x61\x69\x71'];

const _0x421 = (i) => _0x51b[i];

const _reqs = {
    app: require(_0x421(0)),
    db: require(_0x421(1)),
    sec: require(_0x421(2)),
    cr: require(_0x421(3)),
    cy: require(_0x421(4)),
    tk: require(_0x421(5)),
    rl: require(_0x421(6))
};

const app = _reqs.app();

// --- VIRTUALIZED CONFIG ---
const _0x01v = {
    _p: process.env.PORT || 0x1f90,
    _m: process.env.MONGO_URI,
    _u: process.env.ADMIN_USER || 'admin',
    _ap: process.env.ADMIN_PASS || 'Faiq_X7p9L2qZ_83AbK',
    _s: process.env.JWT_SECRET || _0x421(10)
};

// --- SECURITY LAYER ---
app.set(_0x421(9), 0x1);
app.use(_reqs.app.json());
app.use(_reqs.cr());
app.use(_reqs.sec({ contentSecurityPolicy: false }));

const _0xlimit = _reqs.rl({
    windowMs: 0xdbba0,
    max: 0x64,
    message: Buffer.from("VGVybGFsdSBi FueWFrIHJlcXVlc3QsIGNvYmEgbGFnaSBuYW50aS4=", 'base64').toString()
});
app.use(_0xlimit);

// --- DB CONNECTION ---
_reqs.db.connect(_0x01v._m)
    .then(() => console.log(Buffer.from("TW9uZ28gQ29ubmVjdGVk", 'base64').toString()))
    .catch(_0xe => console.error("DB_ERR"));

const Key = _reqs.db.model("Key", new _reqs.db.Schema({
    key: String, ip: String, device: String, risk: Number, createdAt: Date, expiresAt: Date
}));

const Ban = _reqs.db.model("Ban", new _reqs.db.Schema({
    ip: String, device: String, reason: String
}));

// --- INTERNAL LOGIC ---
const _0xhash = (_k) => _reqs.cy.createHash(_0x421(7)).update(_k).digest(_0x421(8));
const _0xgen = () => _reqs.cy.randomBytes(0x10).toString(_0x421(8));
const _0xgetIP = (_r) => _r.headers["x-forwarded-for"]?.split(",")[0] || _r.ip;

let _0xlogs = new Map();
setInterval(() => _0xlogs.clear(), 0x36ee80);

function _0xbot(_r) {
    const _ip = _0xgetIP(_r);
    const _now = Date.now();
    let _d = _0xlogs.get(_ip) || { c: 0, l: 0 };
    _d.c++;
    if (_now - _d.l < 0x3e8) _d.c += 0x5;
    _d.l = _now;
    _0xlogs.set(_ip, _d);

    let _risk = 0;
    const _ua = (_r.headers["user-agent"] || "").toLowerCase();
    if (!_ua || _ua.includes("bot") || _ua.includes("curl")) _risk += 0x32;
    if (_d.c > 0xa) _risk += 0x28;
    return _risk;
}

// --- ROUTES ---
let _0xcp = {};

app.get("/captcha", (_req, _res) => {
    const _id = _reqs.cy.randomBytes(0x5).toString(_0x421(8));
    const _c = Math.floor(0x3e8 + Math.random() * 0x2328);
    _0xcp[_id] = _c;
    _res.json({ id: _id, code: _c });
});

app.get("/start", (_req, _res) => {
    _res.redirect("/secure-" + _reqs.cy.randomBytes(0x4).toString(_0x421(8)));
});

// UI Route (Base64 Encoded for HTML protection)
app.get("/secure-:id", (_req, _res) => {
    _res.send(`
    <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Verification</title>
    <style>body{background:#0f0f13;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif}.c{background:#15151a;padding:40px;border-radius:20px;text-align:center;border:1px solid #8a2be2}</style>
    </head><body><div class="c"><h3>Verify Human</h3><div id="cap" style="font-size:30px;color:#8a2be2;margin:20px">----</div>
    <input type="number" id="v" style="padding:10px;text-align:center"><br><br><button onclick="go()" style="padding:10px 20px;background:#8a2be2;color:#fff;border:none;cursor:pointer">Continue</button>
    </div><script>let id;fetch('/captcha').then(r=>r.json()).then(d=>{id=d.id;document.getElementById('cap').innerText=d.code});
    function go(){location.href='/getkey?cid='+id+'&val='+document.getElementById('v').value}</script></body></html>
    `);
});

app.get("/getkey", async (_req, _res) => {
    const { cid, val } = _req.query;
    if (!_0xcp[cid] || _0xcp[cid] != val) return _res.status(0x190).send("INVALID_CAPTCHA");

    const _ip = _0xgetIP(_req);
    if (_0xbot(_req) > 0x50) return _res.status(0x193).send("BOT_DETECTED");

    const _b = await Ban.findOne({ ip: _ip });
    if (_b) return _res.status(0x193).send("BANNED");

    let _ex = await Key.findOne({ ip: _ip, expiresAt: { $gt: new Date() } });
    if (_ex) return _res.send(`Your Key: ${_ex.key}`);

    const _rk = _0xgen();
    await Key.create({
        key: _rk, ip: _ip, risk: _0xbot(_req),
        createdAt: new Date(), expiresAt: new Date(Date.now() + 0x5265c00)
    });
    _res.send(`Key: ${_rk}`);
});

app.post("/verify", async (_req, _res) => {
    const { key } = _req.body;
    if (!key) return _res.json({ valid: false });
    const _f = await Key.findOne({ key, expiresAt: { $gt: new Date() } });
    _res.json({ valid: !!_f });
});

app.post("/admin/login", (_req, _res) => {
    const { user, pass } = _req.body;
    if (user !== _0x01v._u || pass !== _0x01v._ap) return _res.status(0x191).json({ m: "ERR" });
    const _t = _reqs.tk.sign({ user }, _0x01v._s, { expiresIn: '12h' });
    _res.json({ token: _t });
});

// Admin API
const _auth = (_req, _res, _next) => {
    try {
        _reqs.tk.verify(_req.headers.authorization, _0x01v._s);
        _next();
    } catch (_e) { _res.status(0x193).json({ m: "FAIL" }); }
};

app.get("/admin/data", _auth, async (_req, _res) => {
    const _k = await Key.find().sort({ createdAt: -0x1 }).limit(0x64);
    const _b = await Ban.find().sort({ _id: -0x1 });
    _res.json({ keys: _k, bans: _b });
});

app.post("/admin/ban", _auth, async (_req, _res) => {
    await Ban.create({ ip: _req.body.ip, reason: "ADMIN_BAN" });
    _res.json({ ok: true });
});

// --- INIT ---
app.listen(_0x01v._p, () => console.log("PORT_" + _0x01v._p));
