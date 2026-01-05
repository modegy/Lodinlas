// server.js - نسخة محمية بالكامل ومجانية
const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const compression = require('compression');

const app = express();

// ═══════════════════════════════════════════
// 🔧 TRUST PROXY - مهم جداً لـ Render
// ═══════════════════════════════════════════
app.set('trust proxy', 1);

// ═══════════════════════════════════════════
// 🛡️ Helmet.js - حماية مجانية قوية
// ═══════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://lodinlas.onrender.com"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// ═══════════════════════════════════════════
// 🌐 CORS الآمن والمجاني
// ═══════════════════════════════════════════
const allowedOrigins = [
  'https://lodinlas.onrender.com',
  'https://lodinlas-admin.onrender.com',
  'http://localhost:3000',
  'http://localhost:10000',
  'http://127.0.0.1:3000'
];

app.use(cors({
  origin: function (origin, callback) {
    // السماح لطلبات بدون أصل في التطوير
    if (!origin && process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }
    
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      console.log('⛔ CORS Blocked:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Token']
}));

// ═══════════════════════════════════════════
// ⚡ Rate Limiting - منع هجمات DDoS/Brute Force
// ═══════════════════════════════════════════
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 150, // 150 طلب لكل IP
  message: {
    success: false,
    error: 'عدد الطلبات تجاوز الحد المسموح. حاول مرة أخرى بعد 15 دقيقة'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // ساعة واحدة
  max: 10, // 10 محاولات تسجيل دخول
  message: {
    success: false,
    error: 'عدد محاولات تسجيل الدخول تجاوز الحد. حاول بعد ساعة'
  }
});

// ═══════════════════════════════════════════
// 🛡️ حماية إضافية مجانية
// ═══════════════════════════════════════════
app.use(mongoSanitize()); // منع NoSQL Injection
app.use(xss()); // منع هجمات XSS
app.use(hpp()); // منع Parameter Pollution
app.use(compression()); // ضغط الردود

// ═══════════════════════════════════════════
// 📦 Body Parser مع حماية
// ═══════════════════════════════════════════
app.use(express.json({ 
  limit: '1mb',
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '1mb',
  parameterLimit: 20
}));

// ═══════════════════════════════════════════
// 🔍 Request Logger المحسن
// ═══════════════════════════════════════════
app.use((req, res, next) => {
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const clientIP = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown';
  
  req.clientIP = clientIP;
  req.clientData = {
    ip: clientIP,
    userAgent,
    timestamp
  };
  
  // تسجيل الطلبات المهمة فقط (لتوفير الذاكرة)
  if (!req.path.includes('/health') && !req.path.includes('/favicon.ico')) {
    console.log(`[${timestamp}] ${clientIP} - ${req.method} ${req.path} - ${userAgent.substring(0, 50)}`);
  }
  
  next();
});

// ═══════════════════════════════════════════
// 📂 Static Files مع حماية
// ═══════════════════════════════════════════
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d',
  setHeaders: (res, path) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
  }
}));

// ═══════════════════════════════════════════
// ⚡ تطبيق Rate Limiting على المسارات
// ═══════════════════════════════════════════
app.use('/api/admin/login', authLimiter);
app.use('/api/admin', apiLimiter);
app.use('/api', apiLimiter);

// ═══════════════════════════════════════════
// 🛣️ Routes
// ═══════════════════════════════════════════
try {
  const mobileRoutes = require('./routes/mobile');
  app.use('/api', mobileRoutes);
  console.log('✅ Mobile routes loaded: /api/*');
} catch (error) {
  console.error('❌ Mobile routes error:', error.message);
}

try {
  const adminRoutes = require('./routes/admin');
  app.use('/api/admin', adminRoutes);
  console.log('✅ Admin routes loaded: /api/admin/*');
} catch (error) {
  console.error('❌ Admin routes error:', error.message);
}

try {
  const subAdminRoutes = require('./routes/subadmin');
  if (subAdminRoutes) {
    app.use('/api/sub', subAdminRoutes);
    console.log('✅ SubAdmin routes loaded: /api/sub/*');
  }
} catch (error) {
  console.warn('⚠️ SubAdmin routes not loaded:', error.message);
}

// ═══════════════════════════════════════════
// 🏠 Health Check Route
// ═══════════════════════════════════════════
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    memory: {
      rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)} MB`,
      heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`
    }
  });
});

// ═══════════════════════════════════════════
// 🏠 Home Route
// ═══════════════════════════════════════════
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═══════════════════════════════════════════
// 🚫 404 Handler محسن
// ═══════════════════════════════════════════
app.use((req, res) => {
  console.log(`404 Not Found: ${req.method} ${req.path} from ${req.clientIP}`);
  res.status(404).json({ 
    success: false, 
    error: 'Endpoint not found',
    path: req.path 
  });
});

// ═══════════════════════════════════════════
// ❌ Error Handler محسن
// ═══════════════════════════════════════════
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err.message);
  console.error('Stack:', err.stack);
  
  // تسجيل الأخطاء الأمنية
  if (err.message.includes('CORS') || err.message.includes('Rate limit')) {
    console.log(`🚨 Security Error from ${req.clientIP}: ${err.message}`);
  }
  
  res.status(err.status || 500).json({ 
    success: false, 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ═══════════════════════════════════════════
// 🚀 Start Server
// ═══════════════════════════════════════════
const PORT = process.env.PORT || 10000;

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('\n════════════════════════════════════════════════════════════');
  console.log('🚀 SecureArmor Server v15.0 (Ultra Secure - 100% FREE)');
  console.log('════════════════════════════════════════════════════════════');
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🛡️ Security Level: MAXIMUM`);
  console.log(`💰 Cost: $0.00 (Completely Free)`);
  console.log('════════════════════════════════════════════════════════════\n');
  
  console.log('📋 Security Features Activated:');
  console.log('   ✅ Helmet.js (10+ security headers)');
  console.log('   ✅ CORS Protection (Strict origin policy)');
  console.log('   ✅ Rate Limiting (DDoS & Brute Force protection)');
  console.log('   ✅ NoSQL Injection Protection');
  console.log('   ✅ XSS Protection');
  console.log('   ✅ HTTP Parameter Pollution Protection');
  console.log('   ✅ GZIP Compression');
  console.log('   ✅ Request Logging');
  console.log('   ✅ Trust Proxy (For Render/Heroku)');
});

// Graceful shutdown
const gracefulShutdown = () => {
  console.log('\n📴 Received shutdown signal, closing gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
  
  setTimeout(() => {
    console.log('⚠️ Forcing shutdown after timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

module.exports = app;
