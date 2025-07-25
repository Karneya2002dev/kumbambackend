// const express = require('express');
// const router = express.Router();
// const db = require('../index');

// // Fetch availability and banquet info
// router.get('/:id/:month/:year', async (req, res) => {
//   const { id, month, year } = req.params;

//   try {
//     const [bookings] = await db.query(
//       'SELECT booking_date, status FROM bookings WHERE banquet_id = ? AND MONTH(booking_date) = ? AND YEAR(booking_date) = ?',
//       [id, month, year]
//     );

//     const [hallData] = await db.query('SELECT name, price FROM banquet_halls WHERE id = ?', [id]);

//     if (hallData.length === 0) {
//       return res.status(404).json({ error: 'Banquet hall not found' });
//     }

//     res.json({
//       hall: hallData[0],   // { name, price }
//       bookings             // [ { booking_date, status }, ... ]
//     });

//   } catch (err) {
//     console.error('❌ Server Error:', err);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// });

// module.exports = router;
