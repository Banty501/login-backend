const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors({ origin: "*" }));
app.use(express.json());

let users = [];

app.get("/", (req,res)=>{
    res.send("Backend is running");
});

// SIGNUP
app.post("/signup", async (req,res)=>{
    const { username, password } = req.body;

    const exists = users.find(u => u.username === username);
    if (exists) {
        return res.json({ message: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    users.push({ username, password: hashed });

    res.json({ message: "User created successfully" });
});

// LOGIN
app.post("/login", async (req,res)=>{
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);

    if (!user) {
        return res.json({ message: "User not found" });
    }

    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
        return res.json({ message: "Wrong password" });
    }

    const token = jwt.sign(
        { username },
        "secret123",
        { expiresIn: "1h" }
    );

    res.json({
        message: "Login successful",
        token
    });
});

// DASHBOARD
app.get("/dashboard", (req,res)=>{
    const auth = req.headers.authorization;

    if (!auth) {
        return res.json({ message: "No token" });
    }

    try {
        const token = auth.split(" ")[1];
        const data = jwt.verify(token, "secret123");

        res.json({
            message: "Welcome " + data.username
        });

    } catch {
        res.json({ message: "Invalid token" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running"));
