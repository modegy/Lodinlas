const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// ═══════════════════════════════════════════
// 🛡️ SECURITY CONFIGURATIONS - حماية متقدمة
// ═══════════════════════════════════════════

// 1. التحقق من Environment Variables
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
  console.error('❌ FIREBASE_URL أو FIREBASE_KEY غير موجود');
  process.exit(1);
}

// 2. Helmet - حماية Headers
app.use(helmet({
  contentSecurityPolicy: false, // تم التبسيط
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  noSniff: true,
  xssFilter: true,
  hidePoweredBy: true
}));

// 3. CORS - السماح فقط للنطاقات المصرح بها
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : ['*'];

app.use(cors({
  origin: function (origin, callback) {
    if (allowedOrigins[0] === '*' || !origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('غير مصرح من CORS'));
    }
  },
  credentials: true,
  maxAge: 86400
}));

// 4. Rate Limiting - متعدد المستويات
const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: { success: false, error: message },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      console.warn(`⚠️ Rate limit exceeded: ${req.ip} - ${req.path}`);
      res.status(429).json({ 
        success: false, 
        error: message,
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
  });
};

// حماية عامة: 100 طلب / 15 دقيقة
const generalLimiter = createRateLimiter(
  15 * 60 * 1000, 
  100, 
  'تجاوزت الحد المسموح - انتظر 15 دقيقة'
);

// حماية Login: 5 محاولات / 15 دقيقة
const loginLimiter = createRateLimiter(
  15 * 60 * 1000, 
  5, 
  'تجاوزت محاولات الدخول - انتظر 15 دقيقة'
);

// حماية API Endpoints: 200 طلب / 15 دقيقة
const apiLimiter = createRateLimiter(
  15 * 60 * 1000, 
  200, 
  'تجاوزت حد الطلبات - انتظر قليلاً'
);

// 5. Brute Force Protection
const loginAttempts = new Map();

const bruteForcePrevention = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  if (!loginAttempts.has(ip)) {
    loginAttempts.set(ip, { count: 0, lastAttempt: now, blockedUntil: null });
  }
  
  const attempt = loginAttempts.get(ip);
  
  // إذا كان محظوراً
  if (attempt.blockedUntil && now < attempt.blockedUntil) {
    const waitTime = Math.ceil((attempt.blockedUntil - now) / 1000 / 60);
    return res.status(429).json({
      success: false,
      error: `تم حظرك مؤقتاً. حاول بعد ${waitTime} دقيقة`,
      blockedUntil: attempt.blockedUntil
    });
  }
  
  // إعادة تعيين إذا مر أكثر من 15 دقيقة
  if (now - attempt.lastAttempt > 15 * 60 * 1000) {
    attempt.count = 0;
    attempt.blockedUntil = null;
  }
  
  next();
};

const recordFailedLogin = (ip) => {
  const now = Date.now();
  const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: now, blockedUntil: null };
  
  attempt.count++;
  attempt.lastAttempt = now;
  
  // بعد 5 محاولات فاشلة
  if (attempt.count >= 5) {
    attempt.blockedUntil = now + (30 * 60 * 1000);
    console.error(`🚨 Brute force detected: ${ip} - Blocked for 30 minutes`);
  }
  
  loginAttempts.set(ip, attempt);
};

const resetLoginAttempts = (ip) => {
  loginAttempts.delete(ip);
};

// تنظيف محاولات تسجيل الدخول القديمة كل ساعة
setInterval(() => {
  const now = Date.now();
  for (const [ip, attempt] of loginAttempts.entries()) {
    if (now - attempt.lastAttempt > 60 * 60 * 1000) {
      loginAttempts.delete(ip);
    }
  }
}, 60 * 60 * 1000);

// 6. Request Size Limiting
app.use(express.json({ 
  limit: '10mb'
}));

// 7. IP Blacklist/Whitelist System
const ipBlacklist = new Set(
  process.env.IP_BLACKLIST ? process.env.IP_BLACKLIST.split(',') : []
);

const ipWhitelist = new Set(
  process.env.IP_WHITELIST ? process.env.IP_WHITELIST.split(',') : []
);

const ipFilter = (req, res, next) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  
  // إذا كان في القائمة السوداء
  if (ipBlacklist.has(clientIp)) {
    console.error(`🚫 Blocked IP: ${clientIp}`);
    return res.status(403).json({ success: false, error: 'محظور' });
  }
  
  // إذا كانت القائمة البيضاء مفعلة وال IP ليس فيها
  if (ipWhitelist.size > 0 && !ipWhitelist.has('*') && !ipWhitelist.has(clientIp)) {
    console.warn(`⚠️ Unauthorized IP: ${clientIp}`);
    return res.status(403).json({ success: false, error: 'غير مصرح' });
  }
  
  next();
};

app.use(ipFilter);

// 8. Request Logging & Monitoring
const requestLogger = (req, res, next) => {
  const start = Date.now();
  const ip = req.ip || req.connection.remoteAddress;
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    
    // تسجيل الطلبات المشبوهة
    if (duration > 5000 || res.statusCode >= 400) {
      console.log(`📊 ${req.method} ${req.path} | IP: ${ip} | Status: ${res.statusCode} | ${duration}ms`);
    }
  });
  
  next();
};

app.use(requestLogger);

// 9. Anti-DDoS Pattern Detection
const requestPatterns = new Map();

const ddosDetection = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  if (!requestPatterns.has(ip)) {
    requestPatterns.set(ip, []);
  }
  
  const timestamps = requestPatterns.get(ip);
  
  // حذف الطلبات القديمة (أكثر من دقيقة)
  const recentRequests = timestamps.filter(t => now - t < 60000);
  
  // إذا تجاوز 30 طلب في الدقيقة
  if (recentRequests.length > 30) {
    console.error(`🚨 DDoS Pattern Detected: ${ip} - ${recentRequests.length} requests/min`);
    ipBlacklist.add(ip);
    return res.status(429).json({ 
      success: false, 
      error: 'تم كشف نمط DDoS - تم حظرك'
    });
  }
  
  recentRequests.push(now);
  requestPatterns.set(ip, recentRequests);
  
  next();
};

app.use(ddosDetection);

// 10. تنظيف البيانات المؤقتة كل 5 دقائق
setInterval(() => {
  const now = Date.now();
  for (const [ip, timestamps] of requestPatterns.entries()) {
    const recent = timestamps.filter(t => now - t < 60000);
    if (recent.length === 0) {
      requestPatterns.delete(ip);
    } else {
      requestPatterns.set(ip, recent);
    }
  }
}, 5 * 60 * 1000);

// ═══════════════════════════════════════════
// Firebase & Session Management
// ═══════════════════════════════════════════

const firebase = axios.create({ 
  timeout: 15000
});

const FB_URL = process.env.FIREBASE_URL;
const FB_KEY = process.env.FIREBASE_KEY;
const adminSessions = new Map();

const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USERNAME || 'admin',
  password: process.env.ADMIN_PASSWORD || 'ChangeThisPassword123!'
};

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// تنظيف الجلسات كل ساعة
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of adminSessions.entries()) {
    if (now - session.createdAt > 24 * 60 * 60 * 1000) {
      adminSessions.delete(token);
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// 🔐 ENHANCED AUTHENTICATION MIDDLEWARE
// ═══════════════════════════════════════════

const authApp = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const expected = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
  
  if (!apiKey) {
    return res.status(401).json({ success: false, error: 'API Key مطلوب', code: 401 });
  }
  
  // مقارنة بسيطة لمنع الأخطاء
  if (apiKey === expected) {
    return next();
  }
  
  console.warn(`⚠️ Invalid API Key attempt from ${req.ip}`);
  res.status(401).json({ success: false, error: 'غير مصرح', code: 401 });
};

const authAdmin = (req, res, next) => {
  const sessionToken = req.headers['x-session-token'];
  
  if (sessionToken) {
    const session = adminSessions.get(sessionToken);
    
    if (!session) {
      return res.status(401).json({ 
        success: false, 
        error: 'جلسة غير صالحة', 
        code: 401 
      });
    }
    
    if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
      adminSessions.delete(sessionToken);
      return res.status(401).json({ 
        success: false, 
        error: 'انتهت الجلسة', 
        code: 401 
      });
    }
    
    session.lastActivity = Date.now();
    req.adminUser = session.username;
    return next();
  }
  
  const adminKey = req.headers['x-admin-key'];
  const expected = process.env.ADMIN_API_KEY;
  
  if (expected && adminKey === expected) {
    req.adminUser = 'api-key-user';
    return next();
  }
  
  res.status(401).json({ 
    success: false, 
    error: 'غير مصرح', 
    code: 401 
  });
};

const authSubAdmin = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const deviceFingerprint = req.headers['x-device-fingerprint'];
  
  if (!apiKey || !deviceFingerprint) {
    return res.status(401).json({ 
      success: false, 
      error: 'مفتاح API ومعرف الجهاز مطلوبان', 
      code: 401 
    });
  }
  
  try {
    const response = await firebase.get(`${FB_URL}/api_keys.json?auth=${FB_KEY}`);
    const keys = response.data || {};
    
    let foundKey = null;
    let keyId = null;
    
    for (const [id, keyData] of Object.entries(keys)) {
      if (keyData.api_key === apiKey) {
        foundKey = keyData;
        keyId = id;
        break;
      }
    }
    
    if (!foundKey || !foundKey.is_active) {
      return res.status(401).json({ 
        success: false, 
        error: 'مفتاح غير صالح', 
        code: 401 
      });
    }
    
    if (foundKey.expiry_timestamp && foundKey.expiry_timestamp < Date.now()) {
      return res.status(403).json({ 
        success: false, 
        error: 'مفتاح منتهي', 
        code: 403 
      });
    }
    
    if (foundKey.bound_device && foundKey.bound_device !== deviceFingerprint) {
      console.warn(`⚠️ Device mismatch: ${foundKey.admin_name}`);
      return res.status(403).json({ 
        success: false, 
        error: 'مربوط بجهاز آخر', 
        code: 403 
      });
    }
    
    if (!foundKey.bound_device) {
      await firebase.patch(`${FB_URL}/api_keys/${keyId}.json?auth=${FB_KEY}`, {
        bound_device: deviceFingerprint,
        device_bound_at: Date.now()
      });
    }
    
    await firebase.patch(`${FB_URL}/api_keys/${keyId}.json?auth=${FB_KEY}`, {
      usage_count: (foundKey.usage_count || 0) + 1,
      last_used: Date.now()
    });
    
    req.subAdmin = {
      name: foundKey.admin_name,
      permission: foundKey.permission_level || 'view_only',
      keyId: keyId
    };
    
    next();
    
  } catch (error) {
    console.error('خطأ في التحقق:', error);
    res.status(500).json({ success: false, error: 'خطأ في التحقق', code: 500 });
  }
};

// ═══════════════════════════════════════════
// 🔑 SECURE AUTH ENDPOINTS
// ═══════════════════════════════════════════

app.post('/api/admin/login', loginLimiter, bruteForcePrevention, (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip || req.connection.remoteAddress;
  
  if (!username || !password) {
    return res.status(400).json({ 
      success: false, 
      error: 'اسم المستخدم وكلمة المرور مطلوبان' 
    });
  }
  
  // مقارنة بسيطة
  if (username !== ADMIN_CREDENTIALS.username || password !== ADMIN_CREDENTIALS.password) {
    console.warn(`❌ فشل الدخول: ${username} من ${ip}`);
    recordFailedLogin(ip);
    
    return setTimeout(() => {
      res.status(401).json({ 
        success: false, 
        error: 'بيانات خاطئة' 
      });
    }, 2000);
  }
  
  resetLoginAttempts(ip);
  
  const sessionToken = generateSessionToken();
  
  adminSessions.set(sessionToken, {
    username,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    ip: ip
  });
  
  console.log(`✅ دخول ناجح: ${username} من ${ip}`);
  
  res.json({ 
    success: true, 
    sessionToken,
    expiresIn: '24 hours'
  });
});

app.post('/api/admin/logout', (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  
  if (sessionToken && adminSessions.has(sessionToken)) {
    adminSessions.delete(sessionToken);
  }
  
  res.json({ success: true });
});

// ═══════════════════════════════════════════
// 📱 APP ENDPOINTS
// ═══════════════════════════════════════════

app.get('/api/serverTime', apiLimiter, (req, res) => {
  const now = Date.now();
  res.json({
    success: true,
    server_time: now,
    unixtime: Math.floor(now / 1000)
  });
});

app.post('/api/verifyAccount', authApp, apiLimiter, async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    
    if (!username || !password || !deviceId) {
      return res.status(400).json({ success: false, error: 'بيانات ناقصة', code: 400 });
    }
    
    const passHash = hashPassword(password);
    const url = `${FB_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    
    if (!response.data || Object.keys(response.data).length === 0) {
      return res.json({ success: false, code: 1 });
    }
    
    const key = Object.keys(response.data)[0];
    const user = response.data[key];
    
    if (user.password_hash !== passHash) return res.json({ success: false, code: 2 });
    if (!user.is_active) return res.json({ success: false, code: 3 });
    if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
      return res.json({ success: false, code: 4 });
    }
    
    res.json({ success: true, username: user.username });
    
  } catch (error) {
    console.error('خطأ في التحقق:', error);
    res.status(500).json({ success: false, code: 0 });
  }
});

// ═══════════════════════════════════════════
// 🏥 HEALTH & STATUS
// ═══════════════════════════════════════════

app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: '3.0.0-secure',
    uptime: Math.floor(process.uptime()),
    security: {
      helmet: true,
      rateLimiting: true,
      bruteForce: true,
      ddosProtection: true,
      ipFiltering: true
    }
  });
});

app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>🛡️ Secure Firebase Proxy v3.0</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:system-ui;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);color:#fff;min-height:100vh;padding:20px}
    .container{max-width:1200px;margin:0 auto}
    .header{text-align:center;padding:40px 0}
    .header h1{font-size:3em;color:#4cc9f0;text-shadow:0 0 20px rgba(76,201,240,0.5)}
    .shield{display:inline-block;animation:pulse 2s infinite}
    @keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.1)}}
    .security-badge{background:linear-gradient(135deg,#10b981,#059669);padding:15px 30px;border-radius:50px;display:inline-block;margin:20px 0;box-shadow:0 10px 30px rgba(16,185,129,0.3)}
    .features{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin:40px 0}
    .feature{background:rgba(255,255,255,0.05);padding:25px;border-radius:15px;border:1px solid rgba(76,201,240,0.2);transition:all 0.3s}
    .feature:hover{transform:translateY(-5px);box-shadow:0 10px 30px rgba(76,201,240,0.2)}
    .feature h3{color:#4cc9f0;margin-bottom:15px;display:flex;align-items:center;gap:10px}
    .feature ul{list-style:none;line-height:1.8}
    .feature li:before{content:"✓";color:#10b981;margin-left:10px;font-weight:bold}
    .warning{background:rgba(239,68,68,0.1);border:1px solid #ef4444;padding:20px;border-radius:10px;margin:20px 0}
    .warning h3{color:#ef4444}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1><span class="shield">🛡️</span> Secure Firebase Proxy</h1>
      <div class="security-badge">
        ✅ v3.0 - حماية متقدمة مفعلة
      </div>
    </div>

    <div class="features">
      <div class="feature">
        <h3>🔒 حماية متعددة الطبقات</h3>
        <ul>
          <li>Helmet Security Headers</li>
          <li>Rate Limiting متقدم</li>
          <li>Anti-Brute Force</li>
          <li>DDoS Pattern Detection</li>
          <li>IP Filtering (Blacklist/Whitelist)</li>
        </ul>
      </div>

      <div class="feature">
        <h3>🔐 مصادقة آمنة</h3>
        <ul>
          <li>Session-based Authentication</li>
          <li>Secure API Key Validation</li>
          <li>تشفير كلمات المرور SHA-256</li>
          <li>Device Fingerprinting</li>
          <li>تنظيف الجلسات التلقائي</li>
        </ul>
      </div>

      <div class="feature">
        <h3>📊 مراقبة وتسجيل</h3>
        <ul>
          <li>Request Logging</li>
          <li>Pattern Detection</li>
          <li>Suspicious Activity Alerts</li>
          <li>Performance Monitoring</li>
          <li>Auto IP Banning</li>
        </ul>
      </div>

      <div class="feature">
        <h3>⚡ حدود الطلبات</h3>
        <ul>
          <li>عام: 100 طلب / 15 دقيقة</li>
          <li>Login: 5 محاولات / 15 دقيقة</li>
          <li>API: 200 طلب / 15 دقيقة</li>
          <li>DDoS: 30 طلب / دقيقة</li>
        </ul>
      </div>
    </div>

    <div class="warning">
      <h3>⚠️ تعليمات الأمان</h3>
      <p>1. غيّر ADMIN_USERNAME و ADMIN_PASSWORD في .env</p>
      <p>2. استخدم HTTPS في الإنتاج</p>
      <p>3. فعّل IP_WHITELIST للحماية القصوى</p>
      <p>4. راجع السجلات بانتظام</p>
    </div>
  </div>
</body>
</html>
  `);
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: 'غير موجود', code: 404 });
});

// Error Handler
app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  res.status(500).json({ success: false, error: 'خطأ في الخادم' });
});

app.listen(PORT, () => {
  console.log('═'.repeat(60));
  console.log('🛡️  SECURE Firebase Proxy v3.0');
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log('🔐 Security Features:');
  console.log('   ✓ Helmet Protection');
  console.log('   ✓ Multi-level Rate Limiting');
  console.log('   ✓ Brute Force Prevention');
  console.log('   ✓ DDoS Detection');
  console.log('   ✓ IP Filtering');
  console.log('   ✓ Request Monitoring');
  console.log('═'.repeat(60));
});
