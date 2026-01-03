// server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || 'production';

// ==================== إعدادات CORS الديناميكية ====================
const getCorsOrigins = () => {
  // تحليل origins من متغير البيئة أو استخدام القيم الافتراضية
  if (process.env.CORS_ORIGINS) {
    return process.env.CORS_ORIGINS.split(',').map(origin => origin.trim());
  }
  
  // القيم الافتراضية بناءً على البيئة
  if (NODE_ENV === 'production') {
    return [
      'https://lodinlas.onrender.com',
      'https://lodinlas.com',
      'https://www.lodinlas.com'
    ];
  }
  
  // في التطوير
  return [
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:8080',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:8080'
  ];
};

const allowedOrigins = getCorsOrigins();
console.log('🔐 CORS Allowed Origins:', allowedOrigins);

// Middleware للتعامل مع CORS يدويًا
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // السماح بـ OPTIONS requests (preflight)
  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Session-Token, X-Device-Fingerprint, X-API-Signature, X-Timestamp, X-Nonce, X-Client-ID');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    return res.status(200).end();
  }
  
  // التحقق من الأصل
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  } else if (!origin) {
    // السماح بالطلبات بدون origin (مثل curl, postman)
    res.header('Access-Control-Allow-Origin', '*');
  } else {
    console.warn(`🚫 CORS Blocked: ${origin}`);
  }
  
  next();
});

// ==================== Middleware الأساسي ====================
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests, please try again later.'
  }
});
app.use('/api', limiter);

// Health Check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    corsOrigins: allowedOrigins
  });
});

// CORS Test Endpoint
app.get('/cors-test', (req, res) => {
  res.json({
    success: true,
    message: 'CORS is working!',
    yourOrigin: req.headers.origin,
    allowedOrigins: allowedOrigins,
    environment: NODE_ENV
  });
});

// ==================== Routes ====================
// Admin Routes
app.use('/api/admin', require('./routes/admin'));

// Sub Routes
app.use('/api/sub', require('./routes/sub'));

// API Routes
app.use('/api', require('./routes/api'));

// ==================== Error Handling ====================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

// ==================== Start Server ====================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
  🚀 Server started successfully!
  ╔══════════════════════════════════════════════════════════╗
  ║  🏢 Environment: ${NODE_ENV.padEnd(35)} ║
  ║  📡 Port: ${PORT.toString().padEnd(39)} ║
  ║  🔗 URL: https://lodinlas.onrender.com                   ║
  ║  🔐 CORS: ${allowedOrigins.length.toString().padEnd(36)} origins ║
  ║  ✅ Status: RUNNING                                       ║
  ╚══════════════════════════════════════════════════════════╝
  `);
});
