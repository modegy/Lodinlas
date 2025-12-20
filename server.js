const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', 'loopback, linklocal, uniquelocal');

// ═══════════════════════════════════════════
// 🔐 SECURITY SYSTEM INITIALIZATION
// ═══════════════════════════════════════════
if (!global.requestCache) {
  global.requestCache = new Map();
}

// تنظيف الـ cache كل ساعة
setInterval(() => {
  if (global.requestCache && global.requestCache.size > 1000) {
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    for (const [key, timestamp] of global.requestCache.entries()) {
      if (timestamp < oneHourAgo) {
        global.requestCache.delete(key);
      }
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// التحقق من المتغيرات البيئية
// ═══════════════════════════════════════════
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
  console.error('❌ FIREBASE_URL أو FIREBASE_KEY غير موجود');
  process.exit(1);
}

// تحقق من وجود مفاتيح الأمان
if (!process.env.APP_SECRET_KEY || !process.env.APP_API_KEY) {
  console.warn('⚠️  APP_SECRET_KEY أو APP_API_KEY غير موجود - بعض الحماية قد لا تعمل');
}

// ═══════════════════════════════════════════
// الأمان والحماية
// ═══════════════════════════════════════════
app.use(helmet({ 
  contentSecurityPolicy: false, 
  crossOriginEmbedderPolicy: false 
}));

app.use(cors({
  origin: function(origin, callback) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',') 
      : ['*'];
    
    if (allowedOrigins[0] === '*' || !origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
}));

// ═══════════════════════════════════════════
// Rate Limiting
// ═══════════════════════════════════════════
const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs, 
    max,
    message: { success: false, error: message },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      return req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
        || req.headers['x-real-ip'] 
        || req.ip 
        || req.connection.remoteAddress;
    }
  });
};

const globalLimiter = createRateLimiter(60 * 1000, 100, 'Too many requests');
const loginLimiter = createRateLimiter(15 * 60 * 1000, 5, 'Too many login attempts');
const apiLimiter = createRateLimiter(60 * 1000, 50, 'API rate limit exceeded');

app.use('/', globalLimiter);
app.use(express.json({ limit: '2mb' }));

// ═══════════════════════════════════════════
// 🔐 VERIFY APP SIGNATURE MIDDLEWARE
// ═══════════════════════════════════════════
const verifyAppSignature = async (req, res, next) => {
  try {
    // استثناء لبعض الـ endpoints
    const excludedPaths = [
      '/api/health',
      '/api/serverTime',
      '/api/admin/login',
      '/api/admin/verify-session',
      '/api/sub/verify-key',
      '/'
    ];
    
    // استثناء الـ admin و sub routes
    if (req.path.startsWith('/api/admin/') || req.path.startsWith('/api/sub/')) {
      // استثناء login و verify فقط، الباقي يخضع للتحقق
      if (req.path === '/api/admin/login' || req.path === '/api/admin/verify-session' || req.path === '/api/sub/verify-key') {
        return next();
      }
    }
    
    if (excludedPaths.includes(req.path)) {
      return next();
    }
    
    // جلب الهيدرات
    const clientSignature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    const apiKey = req.headers['x-api-key'];
    const nonce = req.headers['x-nonce'];
    
    // التحقق من وجود جميع الهيدرات
    if (!clientSignature || !timestamp || !apiKey) {
      console.log(`🚨 Missing headers for: ${req.path}`);
      return res.status(401).json({ 
        success: false, 
        error: 'Missing authentication headers',
        code: 'AUTH_001'
      });
    }
    
    // التحقق من API Key
    const validApiKey = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
    if (apiKey !== validApiKey) {
      console.log(`🚨 Invalid API Key for: ${req.path}`);
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid API Key',
        code: 'AUTH_002'
      });
    }
    
    // التحقق من صلاحية الطلب (عدم تكرار الطلب)
    const requestKey = `${apiKey}_${nonce || 'none'}_${timestamp}`;
    if (global.requestCache?.has(requestKey)) {
      console.log(`🚨 Replay attack detected: ${requestKey}`);
      return res.status(401).json({ 
        success: false, 
        error: 'Duplicate request detected',
        code: 'AUTH_003'
      });
    }
    
    // التحقق من التوقيت (منع الطلبات القديمة)
    const currentTime = Math.floor(Date.now() / 1000);
    const requestTime = parseInt(timestamp);
    const expiryTime = parseInt(process.env.SIGNATURE_EXPIRY) || 300;
    
    if (Math.abs(currentTime - requestTime) > expiryTime) {
      console.log(`🚨 Expired request: ${requestTime} vs ${currentTime}`);
      return res.status(401).json({ 
        success: false, 
        error: 'Request expired',
        code: 'AUTH_004'
      });
    }
    
    // بناء البيانات للتوقيع
    let dataToSign = '';
    
    // حسب نوع الطلب
    if (req.method === 'GET') {
      dataToSign = req.originalUrl;
    } else {
      // للطلبات التي فيها body
      if (req.body && Object.keys(req.body).length > 0) {
        // ترتيب البيانات أبجديًا لتجنب اختلاف الترتيب
        const sortedBody = JSON.stringify(req.body, Object.keys(req.body).sort());
        dataToSign = req.originalUrl + '|' + sortedBody;
      } else {
        dataToSign = req.originalUrl;
      }
    }
    
    // إضافة التوقيت والمفتاح السري
    const secretKey = process.env.APP_SECRET_KEY || 'Ma7moud55##@2024SecureSigningKey!';
    const fullData = `${dataToSign}|${timestamp}|${secretKey}`;
    
    // إنشاء التوقيع المتوقع
    const expectedSignature = crypto
      .createHmac('sha256', secretKey)
      .update(fullData)
      .digest('base64')
      .trim();
    
    // مقارنة التوقيعات
    if (clientSignature !== expectedSignature) {
      console.log('🚨 Signature mismatch!');
      console.log('Expected:', expectedSignature);
      console.log('Received:', clientSignature);
      console.log('Data signed:', dataToSign);
      
      // تسجيل محاولة الهجوم
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
      console.log(`⚠️ Potential attack from IP: ${ip}`);
      
      return res.status(403).json({ 
        success: false, 
        error: 'Invalid signature',
        code: 'AUTH_005'
      });
    }
    
    // تخزين الطلب في الـ cache لمنع التكرار
    if (nonce) {
      global.requestCache.set(requestKey, Date.now());
      
      // تنظيف الـ cache بعد وقت الصلاحية
      setTimeout(() => {
        if (global.requestCache?.has(requestKey)) {
          global.requestCache.delete(requestKey);
        }
      }, expiryTime * 1000);
    }
    
    console.log(`✅ Signature verified for: ${req.path}`);
    next();
    
  } catch (error) {
    console.error('❌ Signature verification error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Signature verification failed',
      code: 'AUTH_006'
    });
  }
};

// ═══════════════════════════════════════════
// 🔐 APPLY SIGNATURE VERIFICATION
// ═══════════════════════════════════════════
app.use((req, res, next) => {
  // استثناء بعض الـ endpoints
  const publicPaths = [
    '/api/health',
    '/api/serverTime',
    '/api/admin/login',
    '/api/admin/verify-session',
    '/api/sub/verify-key',
    '/'
  ];
  
  if (publicPaths.includes(req.path)) {
    return next();
  }
  
  // التحقق من التوقيع للباقي
  return verifyAppSignature(req, res, next);
});

// ═══════════════════════════════════════════
// Brute Force Protection
// ═══════════════════════════════════════════
const loginAttempts = new Map();

const bruteForceProtection = (req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  
  if (!loginAttempts.has(ip)) {
    loginAttempts.set(ip, { count: 0, lastAttempt: Date.now() });
  }
  
  const attempt = loginAttempts.get(ip);
  
  // إعادة تعيين بعد 15 دقيقة
  if (Date.now() - attempt.lastAttempt > 15 * 60 * 1000) {
    attempt.count = 0;
  }
  
  if (attempt.count >= 5) {
    const remainingTime = Math.ceil((15 * 60 * 1000 - (Date.now() - attempt.lastAttempt)) / 1000 / 60);
    return res.status(429).json({ 
      success: false, 
      error: `Too many attempts. Try again in ${remainingTime} minutes` 
    });
  }
  
  next();
};

// تنظيف دوري للمحاولات القديمة
setInterval(() => {
  const now = Date.now();
  for (const [ip, attempt] of loginAttempts.entries()) {
    if (now - attempt.lastAttempt > 60 * 60 * 1000) {
      loginAttempts.delete(ip);
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// Firebase Setup
// ═══════════════════════════════════════════
const firebase = axios.create({ 
  baseURL: process.env.FIREBASE_URL, 
  timeout: 10000, 
  headers: { 'Content-Type': 'application/json' } 
});

const FB_KEY = process.env.FIREBASE_KEY;
const FB_URL = process.env.FIREBASE_URL;

// ═══════════════════════════════════════════
// دوال مساعدة
// ═══════════════════════════════════════════
const adminSessions = new Map();
const subAdminKeys = new Map();

const APP_API_KEY = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USERNAME || 'admin',
  password: process.env.ADMIN_PASSWORD || 'Admin@123456'
};

function generateToken() { 
  return crypto.randomBytes(32).toString('hex'); 
}

function hashPassword(password) { 
  return crypto.createHash('sha256').update(password).digest('hex'); 
}

function formatDate(timestamp) {
  if (!timestamp) return null;
  const d = new Date(timestamp);
  const day = String(d.getDate()).padStart(2, '0');
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const year = d.getFullYear();
  const hours = String(d.getHours()).padStart(2, '0');
  const mins = String(d.getMinutes()).padStart(2, '0');
  return `${day}/${month}/${year} ${hours}:${mins}`;
}

// تنظيف الجلسات المنتهية
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of adminSessions.entries()) {
    if (now - session.createdAt > 24 * 60 * 60 * 1000) {
      adminSessions.delete(token);
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// المصادقة - Middlewares
// ═══════════════════════════════════════════

// مصادقة Master Admin
const authAdmin = (req, res, next) => {
  const sessionToken = req.headers['x-session-token'];
  
  if (!sessionToken) {
    return res.status(401).json({ 
      success: false, 
      error: 'Session token required', 
      code: 401 
    });
  }
  
  const session = adminSessions.get(sessionToken);
  
  if (!session) {
    return res.status(401).json({ 
      success: false, 
      error: 'Invalid or expired session', 
      code: 401 
    });
  }
  
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    adminSessions.delete(sessionToken);
    return res.status(401).json({ 
      success: false, 
      error: 'Session expired', 
      code: 401 
    });
  }
  
  req.adminUser = session.username;
  next();
};

// مصادقة Sub Admin
const authSubAdmin = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    const deviceFingerprint = req.headers['x-device-fingerprint'];
    
    if (!apiKey) {
      return res.status(401).json({ 
        success: false, 
        error: 'API key required' 
      });
    }
    
    // التحقق من Cache أولاً
    const cached = subAdminKeys.get(apiKey);
    if (cached && cached.device === deviceFingerprint) {
      if (cached.expiry_timestamp > Date.now() && cached.is_active) {
        req.subAdminKey = cached;
        req.subAdminKeyId = cached.keyId;
        return next();
      }
    }
    
    // البحث في Firebase
    const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
    const keys = response.data || {};
    
    let foundKey = null;
    let keyId = null;
    
    for (const [id, key] of Object.entries(keys)) {
      if (key.api_key === apiKey) {
        foundKey = key;
        keyId = id;
        break;
      }
    }
    
    if (!foundKey) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid API key' 
      });
    }
    
    // التحقق من الصلاحيات
    if (!foundKey.is_active) {
      return res.status(403).json({ 
        success: false, 
        error: 'Key is inactive' 
      });
    }
    
    if (foundKey.expiry_timestamp && Date.now() > foundKey.expiry_timestamp) {
      return res.status(403).json({ 
        success: false, 
        error: 'Key expired' 
      });
    }
    
    if (foundKey.bound_device && foundKey.bound_device !== deviceFingerprint) {
      return res.status(403).json({ 
        success: false, 
        error: 'Key is bound to another device' 
      });
    }
    
    // تحديث Cache
    subAdminKeys.set(apiKey, {
      ...foundKey,
      keyId,
      device: deviceFingerprint,
      last_used: Date.now()
    });
    
    req.subAdminKey = foundKey;
    req.subAdminKeyId = keyId;
    next();
    
  } catch (error) {
    console.error('Auth Sub Admin error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Authentication error' 
    });
  }
};

// التحقق من صلاحيات Sub Admin
const checkSubAdminPermission = (requiredPermission) => {
  return (req, res, next) => {
    const keyData = req.subAdminKey;
    
    const permissions = {
      'full': ['view', 'add', 'extend', 'edit', 'delete'],
      'add_only': ['view', 'add'],
      'extend_only': ['view', 'extend'],
      'view_only': ['view']
    };
    
    const allowedPermissions = permissions[keyData.permission_level] || permissions.view_only;
    
    if (!allowedPermissions.includes(requiredPermission)) {
      return res.status(403).json({ 
        success: false, 
        error: 'Permission denied' 
      });
    }
    
    next();
  };
};

// ✅ التحقق من ملكية المستخدم (Sub Admin يمكنه التعديل فقط على مستخدميه)
const checkUserOwnership = async (req, res, next) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    
    // جلب بيانات المستخدم
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    // ✅ التحقق الصارم: يجب أن يكون created_by_key موجود ومطابق تماماً
    if (!user.created_by_key || user.created_by_key !== currentKeyId) {
      console.log(`🚫 Ownership denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
      return res.status(403).json({ 
        success: false, 
        error: 'You can only manage users you created' 
      });
    }
    
    req.targetUser = user;
    next();
    
  } catch (error) {
    console.error('Ownership check error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to verify ownership' 
    });
  }
};

// ═══════════════════════════════════════════
// Logger Middleware
// ═══════════════════════════════════════════
app.use((req, res, next) => {
  const startTime = Date.now();
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    if (duration > 1000 || res.statusCode >= 400) {
      console.log(`📊 ${req.method} ${req.path} | IP: ${ip} | Status: ${res.statusCode} | Time: ${duration}ms`);
    }
  });
  
  next();
});

// ═══════════════════════════════════════════
// PUBLIC ENDPOINTS
// ═══════════════════════════════════════════
app.get('/api/health', (req, res) => {
  const health = {
    status: 'healthy',
    version: '4.0.0',
    security: {
      signature_verification: true,
      replay_protection: true,
      timestamp_validation: true,
      request_cache_size: global.requestCache?.size || 0
    },
    uptime: Math.floor(process.uptime()),
    timestamp: Date.now(),
    environment: process.env.NODE_ENV || 'production'
  };
  
  res.json(health);
});

app.get('/api/serverTime', apiLimiter, (req, res) => {
  res.json({ 
    success: true, 
    server_time: Date.now(), 
    formatted: new Date().toISOString() 
  });
});

// ═══════════════════════════════════════════
// 📱 MOBILE APP ENDPOINTS
// ═══════════════════════════════════════════
app.post('/api/getUser', apiLimiter, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json(null);
    }
    
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) {
      return res.json(null);
    }
    
    const userId = Object.keys(users)[0];
    const user = users[userId];
    
    res.json({
      username: user.username,
      password_hash: user.password_hash,
      is_active: user.is_active !== false,
      device_id: user.device_id || '',
      expiry_date: formatDate(user.subscription_end),
      subscription_end: user.subscription_end
    });
    
  } catch (error) {
    console.error('Get user error:', error.message);
    res.status(500).json(null);
  }
});

app.post('/api/verifyAccount', apiLimiter, async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing fields', 
        code: 400 
      });
    }
    
    const passHash = hashPassword(password);
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) {
      return res.json({ success: false, code: 1 });
    }
    
    const userId = Object.keys(users)[0];
    const user = users[userId];
    
    if (user.password_hash !== passHash) {
      return res.json({ success: false, code: 2 });
    }
    
    if (!user.is_active) {
      return res.json({ success: false, code: 3 });
    }
    
    if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
      return res.json({ success: false, code: 4 });
    }
    
    res.json({ 
      success: true, 
      username: user.username, 
      code: 200 
    });
    
  } catch (error) {
    console.error('Verify account error:', error.message);
    res.status(500).json({ 
      success: false, 
      code: 0, 
      error: 'Server error' 
    });
  }
});

app.post('/api/updateDevice', apiLimiter, async (req, res) => {
  try {
    const { username, deviceId } = req.body;
    
    if (!username || !deviceId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing data' 
      });
    }
    
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const userId = Object.keys(users)[0];
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
      device_id: deviceId, 
      last_login: Date.now() 
    });
    
    res.json({ 
      success: true, 
      message: 'Device updated' 
    });
    
  } catch (error) {
    console.error('Update device error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Server error' 
    });
  }
});

// ═══════════════════════════════════════════
// 👑 MASTER ADMIN - AUTH
// ═══════════════════════════════════════════
app.post('/api/admin/login', loginLimiter, bruteForceProtection, async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
        
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Username and password required' 
            });
        }
        
        // ✅ **إضافة تأخير بسيط لحماية إضافية**
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        if (username !== ADMIN_CREDENTIALS.username || password !== ADMIN_CREDENTIALS.password) {
            const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
            attempt.count++;
            attempt.lastAttempt = Date.now();
            loginAttempts.set(ip, attempt);
            
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid credentials' 
            });
        }
        
        loginAttempts.delete(ip);
        const sessionToken = generateToken();
        
        adminSessions.set(sessionToken, { 
            username, 
            ip, 
            createdAt: Date.now(), 
            userAgent: req.headers['user-agent'] 
        });
        
        console.log(`✅ Admin login: ${username} from ${ip}`);
        
        res.json({ 
            success: true, 
            sessionToken, 
            expiresIn: '24 hours' 
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Server error' 
        });
    }
});

app.post('/api/admin/logout', authAdmin, (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  if (sessionToken) {
    adminSessions.delete(sessionToken);
  }
  res.json({ 
    success: true, 
    message: 'Logged out' 
  });
});

app.get('/api/admin/verify-session', authAdmin, (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  const session = adminSessions.get(sessionToken);
  const expiresIn = 24 * 60 * 60 * 1000 - (Date.now() - session.createdAt);
  
  res.json({
    success: true,
    session: { 
      username: session.username, 
      expires_in: Math.floor(expiresIn / 1000 / 60) + ' minutes' 
    },
    server_info: { 
      active_sessions: adminSessions.size, 
      uptime: Math.floor(process.uptime()) 
    }
  });
});

// ═══════════════════════════════════════════
// 🔧 SECURITY UTILITY ENDPOINTS
// ═══════════════════════════════════════════
app.post('/api/test/signature', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Signature verified successfully!',
    data: req.body 
  });
});

app.post('/api/admin/reset-security-cache', authAdmin, (req, res) => {
  if (global.requestCache) {
    const oldSize = global.requestCache.size;
    global.requestCache.clear();
    console.log(`🔄 Security cache cleared: ${oldSize} entries removed`);
    res.json({ 
      success: true, 
      message: `Security cache cleared (${oldSize} entries)` 
    });
  } else {
    res.json({ 
      success: false, 
      error: 'Cache not initialized' 
    });
  }
});

app.get('/api/admin/security-status', authAdmin, (req, res) => {
  res.json({
    success: true,
    security: {
      request_cache_size: global.requestCache?.size || 0,
      signature_enabled: true,
      replay_protection: true,
      timestamp_validation: true,
      login_attempts: loginAttempts.size,
      admin_sessions: adminSessions.size,
      subadmin_keys: subAdminKeys.size,
      signature_expiry: process.env.SIGNATURE_EXPIRY || 300
    }
  });
});

// ═══════════════════════════════════════════
// 👑 MASTER ADMIN - USER MANAGEMENT
// ═══════════════════════════════════════════
app.get('/api/admin/users', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const formattedUsers = {};
    for (const [id, user] of Object.entries(users)) {
      const subEnd = user.subscription_end || 0;
      formattedUsers[id] = {
        username: user.username || '',
        is_active: user.is_active !== false,
        expiry_timestamp: subEnd,
        expiry_date: formatDate(subEnd),
        created_at: user.created_at || null,
        last_login: user.last_login || null,
        device_id: user.device_id || '',
        max_devices: user.max_devices || 1,
        notes: user.notes || '',
        created_by_key: user.created_by_key || 'master'
      };
    }
    
    res.json({ 
      success: true, 
      data: formattedUsers, 
      count: Object.keys(formattedUsers).length 
    });
    
  } catch (error) {
    console.error('Get users error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch users' 
    });
  }
});

app.get('/api/admin/users/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);
    
    if (!response.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = response.data;
    res.json({
      success: true,
      data: {
        id: req.params.id,
        username: user.username,
        is_active: user.is_active !== false,
        expiry_timestamp: user.subscription_end || 0,
        expiry_date: formatDate(user.subscription_end),
        device_id: user.device_id || '',
        max_devices: user.max_devices || 1,
        created_by_key: user.created_by_key || 'master'
      }
    });
    
  } catch (error) {
    console.error('Get user error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch user' 
    });
  }
});

app.post('/api/admin/users', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username and password required' 
      });
    }
    
    // التحقق من عدم وجود نفس الاسم
    const checkUrl = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const checkRes = await firebase.get(checkUrl);
    
    if (checkRes.data && Object.keys(checkRes.data).length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username already exists' 
      });
    }
    
    // حساب تاريخ الانتهاء
    let expiryTimestamp;
    if (customExpiryDate) {
      expiryTimestamp = new Date(customExpiryDate).getTime();
    } else if (expiryMinutes) {
      expiryTimestamp = Date.now() + (expiryMinutes * 60 * 1000);
    } else {
      return res.status(400).json({ 
        success: false, 
        error: 'Expiry time required' 
      });
    }
    
    const userData = {
      username,
      password_hash: hashPassword(password),
      is_active: status !== 'inactive',
      subscription_end: expiryTimestamp,
      max_devices: maxDevices || 1,
      device_id: '',
      created_at: Date.now(),
      last_login: null,
      created_by_key: 'master'
    };
    
    const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
    
    console.log(`✅ User created by Master Admin: ${username}`);
    
    res.json({ 
      success: true, 
      message: 'User created', 
      userId: createRes.data.name 
    });
    
  } catch (error) {
    console.error('Create user error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create user' 
    });
  }
});

app.patch('/api/admin/users/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { is_active, max_devices, notes } = req.body;
    const updateData = {};
    
    if (typeof is_active === 'boolean') updateData.is_active = is_active;
    if (max_devices) updateData.max_devices = max_devices;
    if (notes !== undefined) updateData.notes = notes;
    
    await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, updateData);
    
    res.json({ 
      success: true, 
      message: 'User updated' 
    });
    
  } catch (error) {
    console.error('Update user error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update user' 
    });
  }
});

app.delete('/api/admin/users/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.delete(`users/${req.params.id}.json?auth=${FB_KEY}`);
    
    console.log(`🗑️ User deleted: ${req.params.id}`);
    
    res.json({ 
      success: true, 
      message: 'User deleted' 
    });
    
  } catch (error) {
    console.error('Delete user error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete user' 
    });
  }
});

// ✅ حذف جميع المنتهيين دفعة واحدة
app.post('/api/admin/users/delete-expired', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    const now = Date.now();
    
    const deletePromises = [];
    let expiredIds = [];
    
    for (const [id, user] of Object.entries(users)) {
      if (user.subscription_end && user.subscription_end <= now) {
        expiredIds.push(id);
        deletePromises.push(
          firebase.delete(`users/${id}.json?auth=${FB_KEY}`)
        );
      }
    }
    
    if (deletePromises.length === 0) {
      return res.json({ 
        success: true, 
        message: 'No expired users found', 
        count: 0 
      });
    }
    
    await Promise.all(deletePromises);
    
    console.log(`🗑️ Bulk deleted ${expiredIds.length} expired users`);
    
    res.json({ 
      success: true, 
      message: `Deleted ${expiredIds.length} expired users`, 
      count: expiredIds.length 
    });
    
  } catch (error) {
    console.error('Delete expired error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete expired users' 
    });
  }
});

app.post('/api/admin/users/:id/extend', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { minutes, days, hours } = req.body;
    
    const userRes = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    const now = Date.now();
    const currentEnd = user.subscription_end || now;
    
    let extensionMs = 0;
    if (minutes) {
      extensionMs = minutes * 60 * 1000;
    } else if (days || hours) {
      extensionMs = ((days || 0) * 24 * 60 * 60 * 1000) + ((hours || 0) * 60 * 60 * 1000);
    }
    
    if (!extensionMs) {
      return res.status(400).json({ 
        success: false, 
        error: 'Extension time required' 
      });
    }
    
    const newEndDate = (currentEnd > now ? currentEnd : now) + extensionMs;
    
    await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, {
      subscription_end: newEndDate,
      is_active: true
    });
    
    res.json({ 
      success: true, 
      message: 'Subscription extended', 
      new_end_date: newEndDate 
    });
    
  } catch (error) {
    console.error('Extend subscription error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to extend subscription' 
    });
  }
});

app.post('/api/admin/users/:id/reset-device', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, { 
      device_id: '' 
    });
    
    console.log(`🔄 Device reset for user: ${req.params.id}`);
    
    res.json({ 
      success: true, 
      message: 'Device reset' 
    });
    
  } catch (error) {
    console.error('Reset device error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to reset device' 
    });
  }
});

// ═══════════════════════════════════════════
// 👑 MASTER ADMIN - API KEYS MANAGEMENT
// ═══════════════════════════════════════════
app.get('/api/admin/api-keys', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
    const keys = response.data || {};
    
    const formattedKeys = {};
    for (const [id, key] of Object.entries(keys)) {
      formattedKeys[id] = {
        api_key: key.api_key || '',
        admin_name: key.admin_name || '',
        permission_level: key.permission_level || 'view_only',
        is_active: key.is_active !== false,
        expiry_timestamp: key.expiry_timestamp || null,
        usage_count: key.usage_count || 0,
        bound_device: key.bound_device || null,
        created_at: key.created_at || null
      };
    }
    
    res.json({ 
      success: true, 
      data: formattedKeys, 
      count: Object.keys(formattedKeys).length 
    });
    
  } catch (error) {
    console.error('Get API keys error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch API keys' 
    });
  }
});

app.post('/api/admin/api-keys', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { adminName, permissionLevel, expiryDays } = req.body;
    
    if (!adminName) {
      return res.status(400).json({ 
        success: false, 
        error: 'Admin name required' 
      });
    }
    
    const apiKey = `AK_${crypto.randomBytes(16).toString('hex')}`;
    
    const keyData = {
      api_key: apiKey,
      admin_name: adminName,
      permission_level: permissionLevel || 'view_only',
      is_active: true,
      expiry_timestamp: Date.now() + ((expiryDays || 30) * 24 * 60 * 60 * 1000),
      usage_count: 0,
      bound_device: null,
      created_at: Date.now()
    };
    
    await firebase.post(`api_keys.json?auth=${FB_KEY}`, keyData);
    
    console.log(`🔑 API Key created for: ${adminName}`);
    
    res.json({ 
      success: true, 
      message: 'API Key created', 
      apiKey 
    });
    
  } catch (error) {
    console.error('Create API key error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create API key' 
    });
  }
});

app.patch('/api/admin/api-keys/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { is_active } = req.body;
    
    await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, { 
      is_active 
    });
    
    res.json({ 
      success: true, 
      message: 'API Key updated' 
    });
    
  } catch (error) {
    console.error('Update API key error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update API key' 
    });
  }
});

app.delete('/api/admin/api-keys/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.delete(`api_keys/${req.params.id}.json?auth=${FB_KEY}`);
    
    console.log(`🗑️ API Key deleted: ${req.params.id}`);
    
    res.json({ 
      success: true, 
      message: 'API Key deleted' 
    });
    
  } catch (error) {
    console.error('Delete API key error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete API key' 
    });
  }
});

app.post('/api/admin/api-keys/:id/unbind-device', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, { 
      bound_device: null 
    });
    
    console.log(`🔓 Device unbound from API key: ${req.params.id}`);
    
    res.json({ 
      success: true, 
      message: 'Device unbound' 
    });
    
  } catch (error) {
    console.error('Unbind device error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to unbind device' 
    });
  }
});

// ═══════════════════════════════════════════
// 🔑 SUB ADMIN API
// ═══════════════════════════════════════════
app.post('/api/sub/verify-key', apiLimiter, async (req, res) => {
  try {
    const { apiKey, deviceFingerprint } = req.body;
    
    console.log('🔍 Sub Admin verify key request');
    
    if (!apiKey) {
      return res.status(400).json({ 
        success: false, 
        error: 'API key required' 
      });
    }
    
    // البحث في Firebase
    const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
    const keys = response.data || {};
    
    let foundKey = null;
    let keyId = null;
    
    for (const [id, key] of Object.entries(keys)) {
      if (key.api_key === apiKey) {
        foundKey = key;
        keyId = id;
        break;
      }
    }
    
    if (!foundKey) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid API key' 
      });
    }
    
    // التحقق من صلاحية المفتاح
    if (!foundKey.is_active) {
      return res.status(403).json({ 
        success: false, 
        error: 'Key is inactive' 
      });
    }
    
    if (foundKey.expiry_timestamp && Date.now() > foundKey.expiry_timestamp) {
      return res.status(403).json({ 
        success: false, 
        error: 'Key expired' 
      });
    }
    
    // ربط الجهاز
    if (!foundKey.bound_device) {
      await firebase.patch(`api_keys/${keyId}.json?auth=${FB_KEY}`, { 
        bound_device: deviceFingerprint 
      });
      console.log(`🔗 Device bound to key: ${keyId}`);
    } else if (foundKey.bound_device !== deviceFingerprint) {
      return res.status(403).json({ 
        success: false, 
        error: 'Key is bound to another device' 
      });
    }
    
    // تحديث عداد الاستخدام
    await firebase.patch(`api_keys/${keyId}.json?auth=${FB_KEY}`, {
      usage_count: (foundKey.usage_count || 0) + 1,
      last_used: Date.now()
    });
    
    // تحديث Cache
    subAdminKeys.set(apiKey, {
      ...foundKey,
      keyId,
      device: deviceFingerprint,
      last_used: Date.now()
    });
    
    console.log(`✅ Sub Admin verified: ${foundKey.admin_name} (ID: ${keyId})`);
    
    res.json({
      success: true,
      name: foundKey.admin_name,
      permission: foundKey.permission_level || 'view_only',
      key_id: keyId
    });
    
  } catch (error) {
    console.error('Verify key error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Server error' 
    });
  }
});

app.get('/api/sub/users', authSubAdmin, checkSubAdminPermission('view'), apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const currentKeyId = req.subAdminKeyId;
    const formattedUsers = {};
    
    for (const [id, user] of Object.entries(users)) {
      if (user.created_by_key === currentKeyId) {
        const subEnd = user.subscription_end || 0;
        formattedUsers[id] = {
          username: user.username || '',
          is_active: user.is_active !== false,
          expiry_timestamp: subEnd,
          expiry_date: formatDate(subEnd),
          device_id: user.device_id || '',
          max_devices: user.max_devices || 1,
          last_login: user.last_login || 0,
          created_at: user.created_at || 0,
          created_by: user.created_by || 'sub_admin',
          created_by_key: user.created_by_key || null
        };
      }
    }
    
    console.log(`👥 Sub Admin [${currentKeyId}] sees ${Object.keys(formattedUsers).length} users`);
    
    res.json({ 
      success: true, 
      data: formattedUsers, 
      count: Object.keys(formattedUsers).length 
    });
    
  } catch (error) {
    console.error('Sub Admin get users error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch users' 
    });
  }
});

app.get('/api/sub/users/:id/details', authSubAdmin, checkSubAdminPermission('view'), apiLimiter, async (req, res) => {
    try {
        const userId = req.params.id;
        const currentKeyId = req.subAdminKeyId;
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        
        if (!userRes.data) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found' 
            });
        }
        
        const user = userRes.data;
        
        if (user.created_by_key !== currentKeyId) {
            return res.status(403).json({ 
                success: false, 
                error: 'You can only view users you created' 
            });
        }
        
        res.json({
            success: true,
            user: {
                username: user.username || '',
                is_active: user.is_active !== false,
                device_id: user.device_id || '',
                max_devices: user.max_devices || 1,
                last_login: user.last_login || 0,
                created_at: user.created_at || 0,
                subscription_end: user.subscription_end || 0,
                created_by: user.created_by || 'sub_admin',
                notes: user.notes || ''
            }
        });
        
    } catch (error) {
        console.error('Get user details error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get user details' 
        });
    }
});

app.get('/api/sub/stats', authSubAdmin, checkSubAdminPermission('view'), apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const currentKeyId = req.subAdminKeyId;
    const now = Date.now();
    
    let totalUsers = 0;
    let activeUsers = 0;
    let expiredUsers = 0;
    
    for (const user of Object.values(users)) {
      if (user.created_by_key === currentKeyId) {
        totalUsers++;
        if (user.is_active !== false) {
          activeUsers++;
        }
        if (user.subscription_end && user.subscription_end <= now) {
          expiredUsers++;
        }
      }
    }
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        activeUsers,
        expiredUsers
      }
    });
    
  } catch (error) {
    console.error('Sub Admin stats error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to get stats' 
    });
  }
});

app.post('/api/sub/users', authSubAdmin, checkSubAdminPermission('add'), apiLimiter, async (req, res) => {
  try {
    const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username and password required' 
      });
    }
    
    const checkUrl = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const checkRes = await firebase.get(checkUrl);
    
    if (checkRes.data && Object.keys(checkRes.data).length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username already exists' 
      });
    }
    
    let expiryTimestamp;
    if (customExpiryDate) {
      expiryTimestamp = new Date(customExpiryDate).getTime();
    } else if (expiryMinutes) {
      expiryTimestamp = Date.now() + (expiryMinutes * 60 * 1000);
    } else {
      return res.status(400).json({ 
        success: false, 
        error: 'Expiry time required' 
      });
    }
    
    const userData = {
      username,
      password_hash: hashPassword(password),
      is_active: status !== 'inactive',
      subscription_end: expiryTimestamp,
      max_devices: maxDevices || 1,
      device_id: '',
      created_at: Date.now(),
      last_login: null,
      created_by_key: req.subAdminKeyId,
      created_by: req.subAdminKey.admin_name || 'sub_admin'
    };
    
    const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
    
    console.log(`✅ User created by Sub Admin [${req.subAdminKeyId}]: ${username}`);
    
    res.json({ 
      success: true, 
      message: 'User created', 
      userId: createRes.data.name,
      expiry_date: formatDate(expiryTimestamp)
    });
    
  } catch (error) {
    console.error('Sub Admin create user error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create user' 
    });
  }
});

app.post('/api/sub/users/:id/extend', authSubAdmin, checkSubAdminPermission('extend'), apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    const { minutes, days, hours } = req.body;
    
    if (!minutes && !days && !hours) {
      return res.status(400).json({ 
        success: false, 
        error: 'Extension time required' 
      });
    }
    
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    if (user.created_by_key !== currentKeyId) {
      console.log(`🚫 Extend denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
      return res.status(403).json({ 
        success: false, 
        error: 'You can only extend users you created' 
      });
    }
    
    const now = Date.now();
    const currentEnd = user.subscription_end || now;
    
    let extensionMs = 0;
    if (minutes) {
      extensionMs = minutes * 60 * 1000;
    } else if (days || hours) {
      extensionMs = ((days || 0) * 24 * 60 * 60 * 1000) + ((hours || 0) * 60 * 60 * 1000);
    }
    
    const newEndDate = (currentEnd > now ? currentEnd : now) + extensionMs;
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, {
      subscription_end: newEndDate,
      is_active: true
    });
    
    console.log(`⏰ Sub Admin [${currentKeyId}] extended user: ${user.username}`);
    
    res.json({ 
      success: true, 
      message: 'Subscription extended', 
      new_end_date: newEndDate,
      formatted_date: formatDate(newEndDate)
    });
    
  } catch (error) {
    console.error('Sub Admin extend error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to extend subscription' 
    });
  }
});

app.patch('/api/sub/users/:id', authSubAdmin, checkSubAdminPermission('edit'), apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    const { is_active } = req.body;
    
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    if (user.created_by_key !== currentKeyId) {
      console.log(`🚫 Edit denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
      return res.status(403).json({ 
        success: false, 
        error: 'You can only edit users you created' 
      });
    }
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
      is_active 
    });
    
    console.log(`✏️ Sub Admin [${currentKeyId}] updated user: ${user.username}`);
    
    res.json({ 
      success: true, 
      message: 'User updated' 
    });
    
  } catch (error) {
    console.error('Sub Admin update user error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update user' 
    });
  }
});

app.post('/api/sub/users/:id/reset-device', authSubAdmin, checkSubAdminPermission('edit'), apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    if (user.created_by_key !== currentKeyId) {
      console.log(`🚫 Reset device denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
      return res.status(403).json({ 
        success: false, 
        error: 'You can only reset device for users you created' 
      });
    }
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
      device_id: '' 
    });
    
    console.log(`🔄 Sub Admin [${currentKeyId}] reset device for user: ${user.username}`);
    
    res.json({ 
      success: true, 
      message: 'Device reset' 
    });
    
  } catch (error) {
    console.error('Sub Admin reset device error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to reset device' 
    });
  }
});

app.delete('/api/sub/users/:id', authSubAdmin, checkSubAdminPermission('delete'), apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    if (user.created_by_key !== currentKeyId) {
      console.log(`🚫 Delete denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
      return res.status(403).json({ 
        success: false, 
        error: 'You can only delete users you created' 
      });
    }
    
    await firebase.delete(`users/${userId}.json?auth=${FB_KEY}`);
    
    console.log(`🗑️ User deleted by Sub Admin [${currentKeyId}]: ${user.username}`);
    
    res.json({ 
      success: true, 
      message: 'User deleted' 
    });
    
  } catch (error) {
    console.error('Sub Admin delete user error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete user' 
    });
  }
});

// ═══════════════════════════════════════════
// تنظيف دوري للـ Cache
// ═══════════════════════════════════════════
setInterval(() => {
  const now = Date.now();
  for (const [apiKey, keyData] of subAdminKeys.entries()) {
    if (now - keyData.last_used > 30 * 60 * 1000) {
      subAdminKeys.delete(apiKey);
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// 🛠️ MAINTENANCE ENDPOINTS
// ═══════════════════════════════════════════
app.post('/api/admin/fix-old-users', authAdmin, async (req, res) => {
  try {
    console.log('🔧 Starting fix-old-users process...');
    
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    let fixed = 0;
    let alreadyFixed = 0;
    const fixedUsers = [];
    
    for (const [id, user] of Object.entries(users)) {
      if (!user.created_by_key) {
        await firebase.patch(`users/${id}.json?auth=${FB_KEY}`, {
          created_by_key: 'master'
        });
        console.log(`   ✅ Fixed: ${user.username} → created_by_key: "master"`);
        fixedUsers.push(user.username);
        fixed++;
      } else {
        alreadyFixed++;
      }
    }
    
    console.log(`🎉 Fix completed: ${fixed} fixed, ${alreadyFixed} already had key`);
    
    res.json({ 
      success: true, 
      message: `Fixed ${fixed} old users. ${alreadyFixed} already had created_by_key`,
      fixed: fixed,
      alreadyFixed: alreadyFixed,
      fixedUsers: fixedUsers
    });
  } catch (error) {
    console.error('❌ Fix-old-users error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

app.get('/api/admin/debug-users', authAdmin, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const debugInfo = [];
    let withKey = 0;
    let withoutKey = 0;
    let masterUsers = 0;
    let subAdminUsers = 0;
    
    for (const [id, user] of Object.entries(users)) {
      const keyStatus = user.created_by_key || 'MISSING';
      
      debugInfo.push({
        id: id.substring(0, 10) + '...',
        username: user.username,
        created_by_key: keyStatus,
        created_at: formatDate(user.created_at)
      });
      
      if (user.created_by_key) {
        withKey++;
        if (user.created_by_key === 'master') {
          masterUsers++;
        } else {
          subAdminUsers++;
        }
      } else {
        withoutKey++;
      }
    }
    
    res.json({
      success: true,
      summary: {
        total: Object.keys(users).length,
        withKey,
        withoutKey,
        masterUsers,
        subAdminUsers
      },
      users: debugInfo
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// ═══════════════════════════════════════════
// HOME PAGE
// ═══════════════════════════════════════════
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🛡️ Secure API v4.0</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #1a1a2e, #16213e);
      color: #fff;
      min-height: 100vh;
      padding: 40px 20px;
      text-align: center;
    }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { 
      color: #4cc9f0; 
      margin-bottom: 10px; 
      font-size: 2.8rem;
      text-shadow: 0 2px 10px rgba(76, 201, 240, 0.3);
    }
    .subtitle {
      color: #94a3b8;
      margin-bottom: 30px;
      font-size: 1.1rem;
    }
    .security-badge {
      background: linear-gradient(135deg, #10b981, #059669);
      padding: 15px 30px;
      border-radius: 25px;
      display: inline-block;
      margin: 20px 0;
      font-weight: bold;
      font-size: 1.1rem;
      box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
    }
    .security-features {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 15px;
      margin: 30px 0;
    }
    .feature {
      background: rgba(255, 255, 255, 0.05);
      padding: 20px;
      border-radius: 12px;
      border: 1px solid rgba(76, 201, 240, 0.2);
      text-align: left;
      position: relative;
      padding-left: 50px;
    }
    .feature:before {
      content: "✅";
      position: absolute;
      left: 15px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 1.2rem;
    }
    .endpoints {
      background: rgba(255, 255, 255, 0.05);
      padding: 30px;
      border-radius: 15px;
      text-align: left;
      margin-top: 30px;
      border: 2px solid rgba(76, 201, 240, 0.3);
    }
    .endpoints h3 {
      color: #4cc9f0;
      margin-bottom: 20px;
      font-size: 1.5rem;
      border-bottom: 2px solid rgba(76, 201, 240, 0.3);
      padding-bottom: 10px;
    }
    .ep {
      margin: 12px 0;
      padding: 15px;
      background: rgba(255, 255, 255, 0.02);
      border-radius: 10px;
      border-left: 4px solid #4cc9f0;
      font-size: 0.95rem;
      transition: all 0.3s;
    }
    .ep:hover {
      background: rgba(255, 255, 255, 0.05);
      transform: translateX(5px);
    }
    .m {
      display: inline-block;
      padding: 5px 15px;
      border-radius: 6px;
      margin-left: 10px;
      font-weight: bold;
      font-size: 12px;
      text-transform: uppercase;
      min-width: 60px;
      text-align: center;
    }
    .get { background: #10b981; }
    .post { background: #f59e0b; }
    .delete { background: #ef4444; }
    .patch { background: #8b5cf6; }
    .status {
      margin-top: 30px;
      padding: 15px;
      background: rgba(255, 255, 255, 0.03);
      border-radius: 10px;
      border: 1px solid rgba(76, 201, 240, 0.1);
    }
    .status-item {
      display: flex;
      justify-content: space-between;
      margin: 8px 0;
      padding: 8px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .status-value {
      color: #4cc9f0;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Secure Firebase Proxy</h1>
    <div class="subtitle">v4.0 • HMAC-SHA256 Signature Protection</div>
    
    <div class="security-badge">🔐 SIGNATURE VERIFICATION: ACTIVE</div>
    
    <div class="security-features">
      <div class="feature">HMAC-SHA256 Signature</div>
      <div class="feature">Replay Attack Protection</div>
      <div class="feature">Timestamp Validation (5 min)</div>
      <div class="feature">Request Caching System</div>
      <div class="feature">API Key Verification</div>
      <div class="feature">Brute Force Protection</div>
    </div>
    
    <div class="status">
      <div class="status-item">
        <span>🔄 Request Cache:</span>
        <span class="status-value">${global.requestCache?.size || 0} entries</span>
      </div>
      <div class="status-item">
        <span>⏱️ Uptime:</span>
        <span class="status-value">${Math.floor(process.uptime())}s</span>
      </div>
      <div class="status-item">
        <span>🔑 Security Level:</span>
        <span class="status-value">MAXIMUM</span>
      </div>
    </div>
    
    <div class="endpoints">
      <h3>📋 API Endpoints</h3>
      
      <div class="ep">
        <span class="m get">GET</span>
        <strong>/api/health</strong> - Health check & security status
      </div>
      
      <div class="ep">
        <span class="m post">POST</span>
        <strong>/api/getUser</strong> - Mobile app (HMAC-SHA256 required)
      </div>
      
      <div class="ep">
        <span class="m post">POST</span>
        <strong>/api/admin/login</strong> - Master Admin login
      </div>
      
      <div class="ep">
        <span class="m get">GET</span>
        <strong>/api/admin/users</strong> - Get all users (Admin only)
      </div>
      
      <div class="ep">
        <span class="m post">POST</span>
        <strong>/api/admin/users/delete-expired</strong> - Bulk delete expired users
      </div>
      
      <div class="ep">
        <span class="m post">POST</span>
        <strong>/api/sub/verify-key</strong> - Sub Admin verification
      </div>
      
      <div class="ep">
        <span class="m get">GET</span>
        <strong>/api/sub/users</strong> - Sub Admin get users (only his users)
      </div>
      
      <div class="ep">
        <span class="m get">GET</span>
        <strong>/api/admin/security-status</strong> - Security system status
      </div>
    </div>
    
    <p style="margin-top: 30px; color: #64748b; font-size: 0.9rem;">
      🔒 Protected by HMAC-SHA256 • 🔐 Sub Admin isolation • 🛡️ Replay attack protection
    </p>
  </div>
</body>
</html>`);
});

// ═══════════════════════════════════════════
// ERROR HANDLERS
// ═══════════════════════════════════════════
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    error: 'Endpoint not found', 
    code: 404 
  });
});

app.use((err, req, res, next) => {
  console.error('Server error:', err.message);
  res.status(500).json({ 
    success: false, 
    error: 'Internal server error', 
    code: 500 
  });
});

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════
app.listen(PORT, () => {
  console.log('═'.repeat(60));
  console.log('🛡️  Secure Firebase Proxy v4.0');
  console.log('🔐 SECURITY SYSTEM INITIALIZED:');
  console.log('   ✓ HMAC-SHA256 Signature Verification');
  console.log('   ✓ Replay Attack Protection');
  console.log('   ✓ Timestamp Validation (300s)');
  console.log('   ✓ Request Caching System');
  console.log('');
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'production'}`);
  console.log(`🔑 Security Level: MAXIMUM`);
  console.log('');
  console.log('✓ Mobile App endpoints protected with HMAC-SHA256');
  console.log('✓ Master Admin endpoints secured');
  console.log('✓ Sub Admin endpoints isolated');
  console.log('✓ Rate limiting active');
  console.log('');
  console.log('⚠️  IMPORTANT: Verify APP_SECRET_KEY matches APK');
  console.log('⚠️  IMPORTANT: For old users, run /api/admin/fix-old-users');
  console.log('');
  console.log('═'.repeat(60));
});
