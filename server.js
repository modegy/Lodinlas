// server.js - فقط أضف هذا الكود في الأعلى بعد express()
const express = require('express');
const app = express();

// ═══════════════════════════════════════════
// 🔧 CORS FIX - فقط أضف هذا الجزء هنا
// ═══════════════════════════════════════════
app.use((req, res, next) => {
  // السماح بجميع الأصول في التطوير
  const allowedOrigins = [
    'https://lodinlas.onrender.com',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173'
  ];
  
  const origin = req.headers.origin;
  
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  } else {
    // في حالة عدم وجود أصل أو أصل غير معروف، اسمح للجميع (للتطوير)
    res.header('Access-Control-Allow-Origin', '*');
  }
  
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Session-Token, X-Device-Fingerprint, X-API-Signature, X-Timestamp, X-Nonce, X-Client-ID');
  
  // التعامل مع طلبات OPTIONS (preflight)
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

// ═══════════════════════════════════════════
// باقي الكود كما هو - لا تغيره!
// ═══════════════════════════════════════════
// ... باقي كود server.js الحالي
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

// ... بقية الإعدادات
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ... routes
const adminRoutes = require('./routes/admin');
app.use('/api/admin', adminRoutes);

// ... start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
