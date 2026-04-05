// server.js - Railway ready
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// --------------------
// ENV
// --------------------
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "Faiq_X7p9L2qZ_83AbK";

// --------------------
// MongoDB Connection
// --------------------
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error:", err));

// --------------------
// Key Schema
// --------------------
const keySchema = new mongoose.Schema({
    key: String,
    createdAt: { type: Date, default: Date.now },
    duration: Number, // in seconds
    expired: { type: Boolean, default: false },
    usedBy: { type: Number, default: null },
});

const Key = mongoose.model("Key", keySchema);

// --------------------
// Routes
// --------------------

// Generate Key (Admin only)
app.post("/create", async (req, res) => {
    const { token, duration } = req.body;

    if (!token || token !== ADMIN_TOKEN) {
        return res.status(403).json({ msg: "Invalid admin token" });
    }

    const newKey = crypto.randomBytes(8).toString("hex").toUpperCase();
    const keyDoc = new Key({ key: newKey, duration: duration || 3600 });
    await keyDoc.save();

    return res.json({ key: newKey });
});

// Verify Key (User)
app.post("/verify", async (req, res) => {
    const { key, userId } = req.body;

    if (!key || !userId) return res.status(400).json({ msg: "Missing key or userId" });

    const keyDoc = await Key.findOne({ key: key.toUpperCase() });

    if (!keyDoc) return res.json({ valid: false, msg: "Key not found" });

    if (keyDoc.expired) return res.json({ valid: false, msg: "Key expired" });

    const now = new Date();
    const expireTime = new Date(keyDoc.createdAt.getTime() + (keyDoc.duration * 1000));

    if (now > expireTime) {
        keyDoc.expired = true;
        await keyDoc.save();
        return res.json({ valid: false, msg: "Key expired" });
    }

    // Bind key to userId (optional)
    keyDoc.usedBy = userId;
    await keyDoc.save();

    return res.json({ valid: true, msg: "Key valid" });
});

// Default route
app.get("/", (req, res) => {
    res.send("Key-System Server is running ✅");
});

// --------------------
// Start server
// --------------------
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Your project is live at https://<your-railway-domain>.up.railway.app`);
});