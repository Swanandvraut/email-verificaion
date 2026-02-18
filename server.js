const express = require("express");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const cors = require("cors");
require("dotenv").config();

const pool = require("./config/db");

const app = express();
app.use(express.json());
app.use(cors({
  origin: "*"
}));


// ---------------- Gmail Transport ----------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}


// ---------------- SEND OTP ----------------
app.post("/send-email-otp", async (req, res) => {
  const { name, email } = req.body;

  try {
    const otp = generateOTP();
    const expiry = new Date(Date.now() + 5 * 60 * 1000);

    const hashedOTP = crypto.createHash("sha256").update(otp).digest("hex");

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
      from: `"Fixofix" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Fixofix Email Verification OTP",
      html: `
        <div style="font-family:Arial;padding:20px">
          <h2>Email Verification</h2>
          <p>Your OTP is:</p>
          <h1 style="letter-spacing:4px">${otp}</h1>
          <p>This OTP is valid for 5 minutes.</p>
        </div>
      `
    });

    res.json({ success: true });

  } catch (err) {
    console.log(err);
    res.status(500).json({ success: false });
  }
});


// ---------------- VERIFY OTP ----------------
app.post("/verify-email-otp", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (userResult.rows.length === 0)
      return res.json({ success: false, message: "User not found" });

    const user = userResult.rows[0];

    if (!user.email_otp_expires || user.email_otp_expires < new Date())
      return res.json({ success: false, message: "OTP expired" });

    const hashedOTP = crypto.createHash("sha256").update(otp).digest("hex");

    if (hashedOTP !== user.email_otp)
      return res.json({ success: false, message: "Invalid OTP" });

    await pool.query(
      `UPDATE users
       SET email_verified=true,
           email_otp=NULL,
           email_otp_expires=NULL
       WHERE email=$1`,
      [email]
    );

    res.json({ success: true });

  } catch (err) {
    res.status(500).json({ success: false });
  }
});

app.listen(process.env.PORT, () => {
  console.log("Server running on port " + process.env.PORT);
});
