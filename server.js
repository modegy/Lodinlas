// server.js - إعدادات الإنتاج
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || 'production';

// ==================== CORS للإنتاج ====================
const cors = require('cors');

// القائمة البيضاء للنطاقات المسموح بها في الإنتاج
const productionWhitelist = [
  'https://lodinlas.onrender.com',
  'https://lodinlas.com',
  'https://www.lodinlas.com',
  'https://admin.lodinlas.com'
];

// قائمة للنطاقات المسموح بها في التطوير
const developmentWhitelist = [
  'http://localhost:3000',
  'http://localhost:8080',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080'
];

const corsOptions = {
  origin: function (origin, callback) {
    // السماح بالطلبات بدون أصل (مثل تطبيقات الهاتف أو curl)
    if (!origin && NODE_ENV === 'production') {
      // في الإنتاج، نرفض الطلبات بدون origin
      return callback(new Error('Not allowed by CORS'), false);
    }
    
    if (!origin && NODE_ENV === 'development') {
      // في التطوير، نسمح بالطلبات بدون origin
      return callback(null, true);
    }
    
    // التحقق من القائمة البيضاء
    const whitelist = NODE_ENV === 'production' 
      ? productionWhitelist 
      : [...productionWhitelist, ...developmentWhitelist];
    
    if (whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.error(`🚫 CORS blocked: ${origin} in ${NODE_ENV} environment`);
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-API-Key',
    'X-Session-Token',
    'X-Device-Fingerprint',
    'X-API-Signature',
    'X-Timestamp',
    'X-Nonce',
    'X-Client-ID'
  ],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining'],
  maxAge: 600 // 10 دقائق للـ preflight cache
};

// ==================== Middleware الأساسي ====================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://lodinlas.firebaseio.com"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "same-site" },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));

// CORS - يجب أن يكون أول middleware بعد security
app.use(cors(corsOptions));

// التعامل مع طلبات OPTIONS (preflight)
app.options('*', cors(corsOptions));

// Compression لتقليل حجم البيانات
app.use(compression());

// Logging للإنتاج
if (NODE_ENV === 'production') {
  app.use(morgan('combined', {
    skip: (req, res) => req.url === '/health' || res.statusCode < 400
  }));
} else {
  app.use(morgan('dev'));
}

// Rate Limiting للإنتاج
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: NODE_ENV === 'production' ? 100 : 1000, // 100 طلب في الإنتاج، 1000 في التطوير
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests from this IP, please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  skip: (req) => {
    // تخطي rate limiting لـ health checks والطلبات الداخلية
    return req.path === '/health' || req.ip === '::1' || req.ip === '127.0.0.1';
  }
});

app.use('/api/', limiter);

// ==================== معالجة البيانات ====================
app.use(express.json({ 
  limit: '1mb',
  verify: (req, res, buf, encoding) => {
    if (buf && buf.length) {
      req.rawBody = buf.toString(encoding || 'utf8');
    }
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '1mb' 
}));

// ==================== Security Headers إضافية ====================
app.use((req, res, next) => {
  // X-Content-Type-Options
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // X-Frame-Options
  res.setHeader('X-Frame-Options', 'DENY');
  
  // X-XSS-Protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Referrer-Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Permissions-Policy
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  // Content-Security-Policy ديناميكي
  const cspHeader = `
    default-src 'self';
    script-src 'self' 'unsafe-inline';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    font-src 'self';
    connect-src 'self' https://lodinlas.firebaseio.com;
    frame-src 'none';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    block-all-mixed-content;
    upgrade-insecure-requests;
  `.replace(/\s+/g, ' ').trim();
  
  res.setHeader('Content-Security-Policy', cspHeader);
  
  next();
});

// ==================== Routes ====================
const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin');
const subRoutes = require('./routes/sub');

// Health check - بدون auth
app.get('/health', (req, res) => {
  const healthData = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.version
  };
  
  res.status(200).json(healthData);
});

// Route للتحقق من CORS
app.get('/cors-test', (req, res) => {
  res.json({
    success: true,
    message: 'CORS is working correctly',
    origin: req.headers.origin,
    environment: NODE_ENV
  });
});

// Routes مع auth
app.use('/api/admin', adminRoutes);
app.use('/api/sub', subRoutes);
app.use('/api', apiRoutes);

// ==================== Error Handling ====================
// 404 handler
app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.path,
    code: 'ENDPOINT_NOT_FOUND'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🚨 Server Error:', {
    message: err.message,
    stack: NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });

  // CORS errors
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      success: false,
      error: 'Cross-Origin Request Blocked',
      code: 'CORS_BLOCKED',
      allowedOrigins: NODE_ENV === 'production' ? productionWhitelist : [...productionWhitelist, ...developmentWhitelist]
    });
  }

  // Rate limit errors
  if (err.status === 429) {
    return res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      code: 'RATE_LIMIT_EXCEEDED'
    });
  }

  // Default error
  res.status(err.status || 500).json({
    success: false,
    error: NODE_ENV === 'production' ? 'Internal Server Error' : err.message,
    code: 'INTERNAL_SERVER_ERROR',
    ...(NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ==================== بدء الخادم ====================
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
  🚀 Server started successfully!
  ╔══════════════════════════════════════════════════════════╗
  ║  🏢 Environment: ${NODE_ENV.padEnd(35)} ║
  ║  📡 Port: ${PORT.toString().padEnd(39)} ║
  ║  🔗 URL: https://lodinlas.onrender.com                   ║
  ║  🔐 CORS: ${(productionWhitelist.length + ' domains').padEnd(36)} ║
  ║  ✅ Status: RUNNING                                       ║
  ╚══════════════════════════════════════════════════════════╝
  `);
  
  console.log('🔐 CORS Whitelist for Production:');
  productionWhitelist.forEach(domain => {
    console.log(`   ✓ ${domain}`);
  });
});

// ==================== Graceful Shutdown ====================
const gracefulShutdown = () => {
  console.log('\n⚠️  Received shutdown signal, closing server gracefully...');
  
  server.close(() => {
    console.log('✅ HTTP server closed');
    process.exit(0);
  });

  setTimeout(() => {
    console.error('❌ Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('🚨 Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
});

module.exports = app;
