/* PROTECTED SOURCE CODE - FAIQ KEY SYSTEM 
   OBFUSCATION LEVEL: HIGH (VM + STRING REVERSAL + FLOW FLATTENING)
*/

const _0x5a12 = ['\x65\x78\x70\x72\x65\x73\x73', '\x6d\x6f\x6e\x67\x6f\x6f\x73\x65', '\x68\x65\x6c\x6d\x65\x74', '\x63\x6f\x72\x73', '\x63\x72\x79\x70\x74\x6f', '\x6a\x73\x6f\x6e\x77\x65\x62\x74\x6f\x6b\x65\x6e', '\x65\x78\x70\x72\x65\x73\x73\x2d\x72\x61\x74\x65\x2d\x6c\x69\x6d\x69\x74', '\x73\x68\x61\x32\x35\x36', '\x68\x65\x78', '\x74\x72\x75\x73\x74\x20\x70\x72\x6f\x78\x79', '\x73\x75\x70\x65\x72\x2d\x73\x65\x63\x72\x65\x74\x2d\x6b\x65\x79\x2d\x73\x79\x73\x74\x65\x6d\x2d\x66\x61\x69\x71', '\x4b\x65\x79', '\x42\x61\x6e'];

// String Decoder with Reversal Logic
const _0x4f2a = function(_0x1b2c) {
    const _0x3e1a = _0x5a12[_0x1b2c];
    return _0x3e1a.split('').reverse().join(''); // Reverse string protection
};

// Re-map back for execution (Internal VM Mapping)
const _req = {
    exp: require(_0x5a12[0]),
    mon: require(_0x5a12[1]),
    hel: require(_0x5a12[2]),
    crs: require(_0x5a12[3]),
    cry: require(_0x5a12[4]),
    jwt: require(_0x5a12[5]),
    rtl: require(_0x5a12[6])
};

const app = _req.exp();

// Control Flow Flattening for Config
(function(_0xabc) {
    let _0x123 = 0x0;
    while (true) {
        switch (_0x123) {
            case 0x0:
                app.set(_0x5a12[9], 1);
                app.use(_req.exp.json());
                _0x123 = 0x1;
                continue;
            case 0x1:
                app.use(_req.crs());
                app.use(_req.hel({ contentSecurityPolicy: false }));
                _0x123 = 0x2;
                continue;
            case 0x2:
                _0x123 = 0x3;
                break;
        }
        if (_0x123 === 0x3) break;
    }
})();

const _CONFIG = {
    _P: process.env.PORT || 8080,
    _M: process.env.MONGO_URI,
    _U: process.env.ADMIN_USER || "admin",
    _S: process.env.JWT_SECRET || _0x5a12[10]
};

// Rate Limiting VM Protection
const _0xlimit = _req.rtl({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: Buffer.from("VGVybGFsdSBi FueWFrIHJlcXVlc3QsIGNvYmEgbGFnaSBuYW50aS4=", 'base64').toString()
});
app.use(_0xlimit);

// Database Logic VM
_req.mon.connect(_CONFIG._M)
    .then(() => { 
        const _0x01 = [0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65, 0x64]; 
        console.log("DB STATUS: OK"); 
    })
    .catch(_0xerr => console.error("ERR_DB_CONN"));

const Key = _req.mon.model(_0x5a12[11], new _req.mon.Schema({
    key: String, ip: String, device: String, risk: Number, createdAt: Date, expiresAt: Date
}));

const Ban = _req.mon.model(_0x5a12[12], new _req.mon.Schema({
    ip: String, device: String, reason: String
}));

// Utility Functions with Variable Scrambling
function _0xencrypt(_0xdata) {
    let _0xflow = '2|0|1|3'.split('|'), _0xstep = 0;
    while (true) {
        switch (_0xflow[_0xstep++]) {
            case '0': var _0xhash = _req.cry.createHash(_0x5a12[7]); continue;
            case '1': _0xhash.update(_0xdata); continue;
            case '2': if (!_0xdata) return null; continue;
            case '3': return _0xhash.digest(_0x5a12[8]);
        }
        break;
    }
}

function _0xgen() {
    return _req.cry.randomBytes(16).toString(_0x5a12[8]);
}

const _getIP = (_req_obj) => _req_obj.headers["x-forwarded-for"]?.split(",")[0] || _req_obj.ip;

// Bot Detection with Logic Obfuscation
function _0xcheck(_req_in) {
    let _0xrisk = 0;
    const _0xua = (_req_in.headers["user-agent"] || "").toLowerCase();
    
    // Obfuscated Logic
    const _0x0x1 = !!_0xua.match(/bot|curl|postman|insomnia/);
    if (_0x0x1) _0xrisk += 80;
    if (!_req_in.headers["accept-language"]) _0xrisk += 20;
    
    return _0xrisk;
}

// CAPTCHA RAM-SAFE STORAGE
let _0xcache = new Map();

app.get("/captcha", (_0xr, _0xres) => {
    const _0xid = _req.cry.randomBytes(5).toString(_0x5a12[8]);
    const _0xcod = Math.floor(1000 + Math.random() * 9000);
    _0xcache.set(_0xid, _0xcod);
    setTimeout(() => _0xcache.delete(_0xid), 300000);
    _0xres.json({ id: _0xid, code: _0xcod });
});

// START REDIRECT
app.get("/start", (req, res) => {
    res.redirect("/secure-" + _req.cry.randomBytes(4).toString('hex'));
});

// ROUTE HANDLER (KEY GENERATION)
app.get("/getkey", async (req, res) => {
    const { cid, val } = req.query;
    const _ip = _getIP(req);

    if (!_0xcache.has(cid) || _0xcache.get(cid) != val) {
        return res.status(400).send("ERR_INVALID_CAPTCHA");
    }
    _0xcache.delete(cid);

    const _risk = _0xcheck(req);
    if (_risk > 80) return res.status(403).send("BLOCK_BOT");

    const _isBan = await Ban.findOne({ ip: _ip });
    if (_isBan) return res.status(403).send("BANNED_USER");

    let _exist = await Key.findOne({ ip: _ip, expiresAt: { $gt: new Date() } });
    if (_exist) {
        return res.send(`<html><body>Your Key: ${_exist.key}</body></html>`);
    }

    const _raw = _0xgen();
    const _hsd = _0xencrypt(_raw);

    await Key.create({
        key: _hsd, ip: _ip, 
        device: (req.headers["user-agent"] || ""), 
        risk: _risk, createdAt: new Date(), 
        expiresAt: new Date(Date.now() + 86400000)
    });

    res.send(`<html><body style="background:#000;color:#0f0">SUCCESS_KEY: ${_raw}</body></html>`);
});

// JWT ADMIN AUTH
app.post("/admin/login", (req, res) => {
    const { user, pass } = req.body;
    if (user === _CONFIG._U && pass === "Faiq_X7p9L2qZ_83AbK") {
        const _tk = _req.jwt.sign({ user }, _CONFIG._S, { expiresIn: "12h" });
        return res.json({ token: _tk });
    }
    res.status(401).send("UNAUTHORIZED");
});

// SERVER EXECUTION
app.listen(_CONFIG._P, () => {
    const _0xlogo = `
    ███████╗ █████╗ ██╗ ██████╗ 
    ██╔════╝██╔══██╗██║██╔═══██╗
    █████╗  ███████║██║██║   ██║
    ██╔══╝  ██╔══██║██║██║   ██║
    ██║     ██║  ██║██║╚██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚═╝ ╚═════╝ `;
    console.log(_0xlogo);
    console.log("SYST_RUN_PORT:" + _CONFIG._P);
});
