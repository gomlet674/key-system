const express = require("express");
const app = express();

app.use(express.json());

const ADMIN_TOKEN = "SECRET_ADMIN_123";

let keys = {};
let logs = [];

// Generate key
function genKey() {
    return "KEY-" + Math.random().toString(36).substring(2,10).toUpperCase();
}

// CREATE KEY
app.post("/create", (req, res) => {
    if (req.body.token !== ADMIN_TOKEN) {
        return res.json({ error: "UNAUTHORIZED" });
    }

    const duration = req.body.duration || 3600;
    const key = genKey();

    keys[key] = {
        userId: null,
        expire: Date.now() + duration * 1000
    };

    logs.push({ type: "CREATE", key, time: Date.now() });

    res.json({ key });
});

// VERIFY
app.post("/verify", (req, res) => {
    const { key, userId } = req.body;

    const data = keys[key];

    if (!data) {
        logs.push({ type: "FAIL", key });
        return res.json({ valid:false, msg:"INVALID" });
    }

    if (Date.now() > data.expire) {
        delete keys[key];
        logs.push({ type: "EXPIRED", key });
        return res.json({ valid:false, msg:"EXPIRED" });
    }

    if (!data.userId) {
        data.userId = userId;
        logs.push({ type:"BIND", key, userId });
        return res.json({ valid:true, msg:"BOUND" });
    }

    if (data.userId === userId) {
        logs.push({ type:"LOGIN", key, userId });
        return res.json({ valid:true, msg:"WELCOME" });
    }

    logs.push({ type:"DENY", key, userId });
    res.json({ valid:false, msg:"USED" });
});

// LOG VIEW
app.get("/logs", (req, res) => {
    res.json(logs);
});

app.listen(3000, () => console.log("Server ON"));