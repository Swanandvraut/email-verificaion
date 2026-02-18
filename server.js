const express = require("express");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const cors = require("cors");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

// ---------------- Middleware ----------------
app.use(express.json());
app.use(cors());
app.use(express.static("public")); // Serve frontend files

// ---------------- Database ----------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

// ---------------- Gmail Transport ----------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ---------------- Helper: Generate OTP ----------------
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ---------------- Root Route ----------------
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

// ---------------- SEND EMAIL OTP ----------------
app.post("/send-email-otp", async (req, res) => {
  const { name, email } = req.body;

  if (!name || !email) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    const otp = generateOTP();
    const expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    const hashedOTP = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    await pool.query(
      `INSERT INTO users (name, email, email_otp, email_otp_expires)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (email)
       DO UPDATE SET
         email_otp=$3,
         email_otp_expires=$4`,
      [name, email, hashedOTP, expiry]
    );

    await transporter.sendMail({
      from: `"Fixofix Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your Fixofix Verification Code",
      html: `
        <div style="font-family:Arial; padding:20px;">
          <h2>Email Verification</h2>
          <p>Your verification code is:</p>
          <h1 style="letter-spacing:5px;">${otp}</h1>
          <p>This code expires in 5 minutes.</p>
        </div>
      `
    });

    res.json({ success: true });

  } catch (error) {
    console.error("SEND OTP ERROR:", error);
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// ---------------- VERIFY EMAIL OTP ----------------
app.post("/verify-email-otp", async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.json({ success: false, message: "User not found" });
    }

    const user = result.rows[0];

    if (!user.email_otp_expires || user.email_otp_expires < new Date()) {
      return res.json({ success: false, message: "OTP expired" });
    }

    const hashedOTP = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    if (hashedOTP !== user.email_otp) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    await pool.query(
      `UPDATE users
       SET email_verified=true,
           email_otp=NULL,
           email_otp_expires=NULL
       WHERE email=$1`,
      [email]
    );

    res.json({ success: true });

  } catch (error) {
    console.error("VERIFY OTP ERROR:", error);
    res.status(500).json({ success: false });
  }
});

// ---------------- Start Server ----------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
