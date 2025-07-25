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
app.use('/uploads', express.static('uploads'));



// ✅ Use MySQL Connection Pool
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

db.getConnection((err, connection) => {
  if (err) {
    console.error('❌ DB pool connection error:', err);
  } else {
    console.log('✅ Connected to Railway DB via pool!');
    connection.release();
  }
});

const availabilityRoute = require('./routes/availablity');
app.use('/api/availability', availabilityRoute);


// ✅ Nodemailer Setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ✅ Signup
app.post('/api/signup', async (req, res) => {
  const { fullName, phone, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Server error' });
    if (results.length > 0) return res.json({ success: false, message: 'User already exists' });

    db.query(
      'INSERT INTO users (full_name, phone, email, password) VALUES (?, ?, ?, ?)',
      [fullName, phone, email, hashedPassword],
      err => {
        if (err) {
          console.error('Insert Error:', err);
          return res.json({ success: false, message: 'Signup failed' });
        }
        res.json({ success: true });
      }
    );
  });
});

// ✅ Login + Send OTP
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error' });
    if (results.length === 0) return res.json({ success: false, message: 'User not found' });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.json({ success: false, message: 'Incorrect password' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60000);

    db.query(
      'INSERT INTO otp_verification (email, otp, expires_at) VALUES (?, ?, ?)',
      [email, otp, expiresAt],
      (insertErr) => {
        if (insertErr) return res.json({ success: false, message: 'OTP generation failed' });

        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Your OTP - KUMBAM',
          text: `Your OTP is ${otp}. It will expire in 5 minutes.`,
        };

        transporter.sendMail(mailOptions, (mailErr, info) => {
          if (mailErr) return res.json({ success: false, message: 'Failed to send OTP email' });

          res.json({
            success: true,
            token: otp,
            phone: user.phone,
            username: user.full_name,
            message: 'OTP sent successfully',
          });
        });
      }
    );
  });
});

// ✅ Verify OTP
app.post('/api/verify-email-otp', (req, res) => {
  const { email, otp } = req.body;

  db.query(
    'SELECT * FROM otp_verification WHERE email = ? ORDER BY id DESC LIMIT 1',
    [email],
    (err, results) => {
      if (err) return res.status(500).json({ success: false, message: 'Server error' });
      if (results.length === 0) return res.json({ success: false, message: 'No OTP found' });

      const record = results[0];
      const now = new Date();

      if (record.otp !== otp) return res.json({ success: false, message: 'Incorrect OTP' });
      if (now > record.expires_at) return res.json({ success: false, message: 'OTP expired' });

      res.json({ success: true, message: 'OTP verified successfully' });
    }
  );
});

// ✅ Forgot Password - Send OTP
app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Server error' });
    if (results.length === 0) return res.json({ success: false, message: 'User not found' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60000);

    db.query(
      'INSERT INTO otp_verification (email, otp, expires_at) VALUES (?, ?, ?)',
      [email, otp, expiresAt],
      (insertErr) => {
        if (insertErr) return res.json({ success: false, message: 'OTP generation failed' });

        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Your KUMBAM Password Reset OTP',
          text: `Your OTP is ${otp}. It will expire in 5 minutes.`,
        };

        transporter.sendMail(mailOptions, (mailErr, info) => {
          if (mailErr) return res.json({ success: false, message: 'Failed to send OTP email' });

          res.json({ success: true, message: 'OTP sent to your email' });
        });
      }
    );
  });
});

// ✅ Reset Password
app.post('/api/reset-password', async (req, res) => {
  const { email, otp, password } = req.body;

  db.query(
    'SELECT * FROM otp_verification WHERE email = ? ORDER BY id DESC LIMIT 1',
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ success: false, message: 'Server error' });
      if (results.length === 0) return res.json({ success: false, message: 'No OTP found' });

      const record = results[0];
      const now = new Date();

      if (record.otp !== otp) return res.json({ success: false, message: 'Invalid OTP' });
      if (now > record.expires_at) return res.json({ success: false, message: 'OTP expired' });

      const hashedPassword = await bcrypt.hash(password, 10);
      db.query(
        'UPDATE users SET password = ? WHERE email = ?',
        [hashedPassword, email],
        (updateErr) => {
          if (updateErr) return res.json({ success: false, message: 'Password reset failed' });

          res.json({ success: true, message: 'Password reset successful' });
        }
      );
    }
  );
});

// ✅ Resend OTP
app.post('/api/resend-email-otp', async (req, res) => {
  const { email } = req.body;

  try {
    const [rows] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (!Array.isArray(rows) || rows.length === 0) return res.status(404).json({ message: 'Email not found' });

    const otp = Math.floor(100000 + Math.random() * 900000);
    await db.promise().query(
      'INSERT INTO otp_verification (email, otp, expires_at) VALUES (?, ?, ?)',
      [email, otp, new Date(Date.now() + 5 * 60000)]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is: ${otp}`,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) return res.status(500).json({ message: 'Error sending OTP email' });
      res.status(200).json({ message: 'OTP resent successfully' });
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ✅ Get Banquets
app.get('/api/banquets', (req, res) => {
  db.query('SELECT * FROM banquet_halls', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

// ✅ Get Categories
app.get('/api/categories', (req, res) => {
  db.query('SELECT DISTINCT category FROM banquet_halls', (err, results) => {
    if (err) return res.status(500).send(err);
    const categories = results.map(r => r.category);
    res.json(categories);
  });
});

// ✅ Availability with Mahal Name & Price
app.get('/api/availability/:mahalId/:month/:year', (req, res) => {
  const { mahalId, month, year } = req.params;
  const sql = `
    SELECT bh.name AS mahal_name, bh.price AS mahal_price, b.booking_date, b.status
    FROM bookings b
    JOIN banquet_halls bh ON b.mahal_id = bh.id
    WHERE MONTH(b.booking_date) = ? AND YEAR(b.booking_date) = ? AND b.mahal_id = ?
  `;
  db.query(sql, [month, year, mahalId], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json(result);
  });
});


app.post('/api/bookings', (req, res) => {
  const { name, phone, event_type, address, mahal_name, location, price, dates } = req.body;

  const query = `
    INSERT INTO bookings (name, phone, event_type, address, mahal_name, location, price, dates)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;
  const values = [name, phone, event_type, address, mahal_name, location, price, dates];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Booking Error:', err);
      return res.status(500).json({ message: 'Server Error' });
    }
    res.status(200).json({ message: 'Booking saved successfully' });
  });
});


// ✅ Start Server
app.listen(5000, '0.0.0.0', () => {
  console.log('✅ Server running on port 5000');
});
