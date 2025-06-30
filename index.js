// 1. Impor Modul yang Diperlukan
const express = require("express");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg"); // Impor Pool dari pg
import cors from "cors"; // Impor CORS untuk mengatasi masalah CORS
require("dotenv").config();

// 2. Inisialisasi Aplikasi Express
const app = express();
app.use(cors());
app.use(bodyParser.json());

// 3. Konfigurasi Koneksi Database (Neon)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // kadang perlu di Railway/Heroku
  },
});

// 4. Konfigurasi Rate Limiter
// Membatasi setiap IP untuk hanya membuat 5 permintaan per 15 menit
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 5, // Maksimal 5 permintaan
  message:
    "Terlalu banyak permintaan OTP dari IP ini, silakan coba lagi setelah 15 menit",
  standardHeaders: true, // Return rate limit info di header `RateLimit-*`
  legacyHeaders: false, // Disable header `X-RateLimit-*`
});

// 5. Konfigurasi Nodemailer Transporter (Tetap sama)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Fungsi untuk menghasilkan OTP 6 digit (Tetap sama)
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ----------------------------------------------------
//  ROUTES API
// ----------------------------------------------------

/**
 * @route   POST /request-otp
 * @desc    Mengirim OTP ke email pengguna dan menyimpannya di DB
 * @access  Public (dengan Rate Limiting)
 */
// Terapkan rate limiter ke route ini
app.post("/request-otp", otpLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "Email diperlukan" });
  }

  const otp = generateOtp();
  const expires_at = new Date(Date.now() + 5 * 60 * 1000); // OTP berlaku 5 menit

  try {
    // Gunakan UPSERT: Update jika ada, Insert jika tidak ada.
    const query = `
            INSERT INTO otps (email, otp, expires_at) 
            VALUES ($1, $2, $3)
            ON CONFLICT (email) 
            DO UPDATE SET otp = EXCLUDED.otp, expires_at = EXCLUDED.expires_at;
        `;
    await pool.query(query, [email, otp, expires_at]);

    const mailOptions = {
      // ... (gunakan template email HTML yang sudah Anda buat)
      from: `"OTP Auth" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Kode OTP untuk Autentikasi",
      html: `
      <!DOCTYPE html>
      <html>
      <head>
          <meta charset="utf-8">
          <style type="text/css">
              /* Gaya dasar untuk klien yang mendukung <style> */
              body { font-family: Arial, sans-serif; }
          </style>
      </head>
      <body style="margin: 0; padding: 0; background-color: #f4f4f4;">
          <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; margin: 20px auto; border: 1px solid #cccccc;">
              <tr>
                  <td align="center" bgcolor="#007bff" style="padding: 40px 0; color: #ffffff; font-size: 28px; font-weight: bold; font-family: Arial, sans-serif;">
                      Verifikasi Akun Anda
                  </td>
              </tr>
              <tr>
                  <td bgcolor="#ffffff" style="padding: 40px 30px;">
                      <h1 style="font-size: 24px; margin: 0; font-family: Arial, sans-serif;">Kode OTP Anda</h1>
                      <p style="margin: 20px 0; font-size: 16px; line-height: 1.5; font-family: Arial, sans-serif;">
                          Halo,
                          <br><br>
                          Gunakan kode berikut untuk menyelesaikan proses login Anda. Jangan bagikan kode ini kepada siapa pun.
                      </p>
                      <table align="center" border="0" cellpadding="0" cellspacing="0" style="margin: 20px auto;">
                          <tr>
                              <td align="center" bgcolor="#e9ecef" style="padding: 15px 25px; font-size: 32px; font-weight: bold; letter-spacing: 5px; font-family: 'Courier New', Courier, monospace; border-radius: 5px;">
                                  ${otp}
                              </td>
                          </tr>
                      </table>
                      <p style="margin-top: 20px; font-size: 16px; font-family: Arial, sans-serif;">
                          Kode ini akan kedaluwarsa dalam 5 menit.
                      </p>
                  </td>
              </tr>
              <tr>
                  <td bgcolor="#343a40" style="padding: 30px; text-align: center; color: #888888; font-size: 12px; font-family: Arial, sans-serif;">
                      &copy; 2025 OTP Auth. Semua Hak Dilindungi.
                      <br>
                      Jika Anda tidak meminta kode ini, mohon abaikan email ini.
                  </td>
              </tr>
          </table>
      </body>
      </html>
  `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error mengirim email:", error);
        return res.status(500).json({ message: "Gagal mengirim OTP" });
      }
      res.status(200).json({ message: "OTP berhasil dikirim ke email Anda" });
    });
  } catch (dbError) {
    console.error("Database error:", dbError);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

/**
 * @route   POST /verify-otp
 * @desc    Memverifikasi OTP dari DB dan memberikan JWT
 * @access  Public
 */
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ message: "Email dan OTP diperlukan" });
  }

  try {
    const result = await pool.query("SELECT * FROM otps WHERE email = $1", [
      email,
    ]);

    // Cek apakah ada data OTP untuk email ini
    if (result.rows.length === 0) {
      return res
        .status(400)
        .json({ message: "OTP tidak valid atau sudah kedaluwarsa" });
    }

    const otpData = result.rows[0];

    // Cek apakah OTP sudah kedaluwarsa
    if (new Date() > new Date(otpData.expires_at)) {
      await pool.query("DELETE FROM otps WHERE email = $1", [email]); // Hapus OTP kedaluwarsa
      return res.status(400).json({ message: "OTP sudah kedaluwarsa" });
    }

    // Cek apakah OTP cocok
    if (otpData.otp !== otp) {
      return res.status(400).json({ message: "OTP tidak valid" });
    }

    // Jika berhasil, hapus OTP dari database agar tidak bisa digunakan lagi
    await pool.query("DELETE FROM otps WHERE email = $1", [email]);

    // Buat token JWT
    const token = jwt.sign({ email: email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({
      message: "Login berhasil",
      token: token,
    });
  } catch (dbError) {
    console.error("Database error:", dbError);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Middleware dan route /profile (Tetap sama)
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}
app.get("/profile", authenticateToken, (req, res) => {
  res.json({ message: `Selamat datang, ${req.user.email}`, user: req.user });
});

// Jalankan Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server berjalan di port ${PORT}`);
});
