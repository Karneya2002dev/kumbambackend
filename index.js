const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();


const app = express();
app.use(cors());
app.use(express.json());

// DB Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  connectTimeout: 10000
});
db.connect(err => {
  if (err) throw err;
  console.log('✅ MySQL connected');
});

app.use('/uploads', express.static('uploads'));
// Nodemailer Setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,  // e.g. your_email@gmail.com
    pass: process.env.EMAIL_PASS   // App password
  }
});

// ✅ Signup Route
app.post('/api/signup', async (req, res) => {
  const { fullName, phone, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (results.length > 0) {
      return res.json({ success: false, message: 'User already exists' });
    }

    db.query(
      'INSERT INTO users (full_name, phone, email, password) VALUES (?, ?, ?, ?)',
      [fullName, phone, email, hashedPassword],
      err => {
        if (err) {
          console.error('Insert Error:', err); // Add this line
          return res.json({ success: false, message: 'Signup failed' });
        }
        res.json({ success: true });
      }
    );
  });
});


// ✅ Login + Send OTP via Email
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    if (results.length === 0) {
      return res.json({ success: false, message: 'User not found' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ success: false, message: 'Incorrect password' });
    }

    // ✅ Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60000); // 5 mins

    db.query(
      'INSERT INTO otp_verification (email, otp, expires_at) VALUES (?, ?, ?)',
      [email, otp, expiresAt],
      (insertErr) => {
        if (insertErr) {
          console.error('❌ OTP insert failed:', insertErr);
          return res.json({ success: false, message: 'OTP generation failed' });
        }

        // ✅ Send OTP email
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Your OTP - KUMBAM',
          text: `Your OTP is ${otp}. It will expire in 5 minutes.`,
        };

        transporter.sendMail(mailOptions, (mailErr, info) => {
          if (mailErr) {
            console.error('❌ Mail error:', mailErr);
            return res.json({ success: false, message: 'Failed to send OTP email' });
          }

          console.log('✅ OTP sent to email:', info.response);

          // ✅ ✅ UPDATED RESPONSE
          res.json({
            success: true,
            token: otp,
            phone: user.phone,
            username: user.full_name, // ✅ Send username to frontend
            message: 'OTP sent successfully'
          });
        });
      }
    );
  });
});

// ✅ OTP Verification Route
app.post('/api/verify-email-otp', (req, res) => {
  const { email, otp } = req.body;

  db.query(
    'SELECT * FROM otp_verification WHERE email = ? ORDER BY id DESC LIMIT 1',
    [email],
    (err, results) => {
      if (err) {
        console.error('❌ DB error during OTP verification:', err);
        return res.status(500).json({ success: false, message: 'Server error' });
      }

      if (results.length === 0) {
        return res.json({ success: false, message: 'No OTP found' });
      }

      const record = results[0];
      const now = new Date();

      if (record.otp !== otp) {
        return res.json({ success: false, message: 'Incorrect OTP' });
      }

      if (now > record.expires_at) {
        return res.json({ success: false, message: 'OTP expired' });
      }

      return res.json({ success: true, message: 'OTP verified successfully' });
    }
  );
});

// ✅ Reset Password Route
app.post('/api/reset-password', async (req, res) => {
  const { email, otp, password } = req.body;

  if (!email || !otp || !password) {
    return res.json({ success: false, message: 'All fields are required' });
  }

  try {
    // 1. Get latest OTP for this email
    db.query(
      'SELECT * FROM otp_verification WHERE email = ? ORDER BY id DESC LIMIT 1',
      [email],
      async (err, results) => {
        if (err) {
          console.error('❌ OTP check error:', err);
          return res.status(500).json({ success: false, message: 'Server error' });
        }

        if (results.length === 0) {
          return res.json({ success: false, message: 'No OTP found' });
        }

        const record = results[0];
        const now = new Date();

        // 2. Validate OTP and expiration
        if (record.otp !== otp) {
          return res.json({ success: false, message: 'Invalid OTP' });
        }

        if (now > record.expires_at) {
          return res.json({ success: false, message: 'OTP expired' });
        }

        // 3. Hash new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 4. Update user's password in DB
        db.query(
          'UPDATE users SET password = ? WHERE email = ?',
          [hashedPassword, email],
          (updateErr) => {
            if (updateErr) {
              console.error('❌ Password update failed:', updateErr);
              return res.json({ success: false, message: 'Password reset failed' });
            }

            return res.json({ success: true, message: 'Password reset successful' });
          }
        );
      }
    );
  } catch (error) {
    console.error('❌ Reset Error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});
// ✅ Forgot Password - Send OTP
app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.json({ success: false, message: 'Email is required' });
  }

  // Check if user exists
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error('❌ DB error:', err);
      return res.status(500).json({ success: false, message: 'Server error' });
    }

    if (results.length === 0) {
      return res.json({ success: false, message: 'User not found' });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60000); // 5 mins

    db.query(
      'INSERT INTO otp_verification (email, otp, expires_at) VALUES (?, ?, ?)',
      [email, otp, expiresAt],
      (insertErr) => {
        if (insertErr) {
          console.error('❌ OTP insert failed:', insertErr);
          return res.json({ success: false, message: 'OTP generation failed' });
        }

        // Send OTP Email
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Your KUMBAM Password Reset OTP',
          text: `Your OTP for password reset is ${otp}. It will expire in 5 minutes.`,
        };

        transporter.sendMail(mailOptions, (mailErr, info) => {
          if (mailErr) {
            console.error('❌ Mail send failed:', mailErr);
            return res.json({ success: false, message: 'Failed to send OTP email' });
          }

          console.log('✅ Forgot OTP sent:', info.response);
          return res.json({ success: true, message: 'OTP sent to your email' });
        });
      }
    );
  });
});

app.get('/api/banquets', (req, res) => {
  db.query('SELECT * FROM banquet_halls', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

app.get('/api/categories', (req, res) => {
  db.query('SELECT DISTINCT category FROM banquet_halls', (err, results) => {
    if (err) return res.status(500).send(err);
    const categories = results.map(r => r.category);
    res.json(categories);
  });
});

// POST /resend-otp
app.post('/api/resend-email-otp', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    // Check if user exists
    const [user] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (user.length === 0) {
      return res.status(404).json({ message: 'Email not found' });
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000);

    // Save OTP to DB
    await db.promise().query('UPDATE otp_verification SET otp = ? WHERE email = ?', [otp, email]);

    // Send OTP via email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is: ${otp}`,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error('Email error:', err);
        return res.status(500).json({ message: 'Error sending OTP email' });
      }
      return res.status(200).json({ message: 'OTP resent successfully' });
    });

  } catch (err) {
    console.error('Resend OTP Error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});



// ✅ Start Server
app.listen(5000, '0.0.0.0', () => {
  console.log('Server running on port 5000');
});
