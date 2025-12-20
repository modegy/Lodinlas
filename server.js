const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const csurf = require('csurf');
const cookieParser = require('cookie-parser');

// 1. إدارة الأسرار: تحميل متغيرات البيئة من server.env
require('dotenv').config({ path: './server.env' });

// 2. استيراد دوال الأمان المتقدمة
const { 
  hmacVerificationMiddleware, 
  decryptBodyMiddleware, 
  encryptResponseMiddleware,
  generateHMAC, // تم الاحتفاظ بها للاستخدام الداخلي إذا لزم الأمر
  decryptData,
  encryptData
} = require('./security');

const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', 'loopback, linklocal, uniquelocal');

// ═══════════════════════════════════════════
// التحقق من المتغيرات البيئية الأساسية
// ═══════════════════════════════════════════
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY || !process.env.HMAC_SECRET_KEY || !process.env.ENCRYPTION_KEY || !process.env.SESSION_SECRET) {
  console.error('❌ متغيرات البيئة الأساسية (FIREBASE_URL, FIREBASE_KEY, HMAC_SECRET_KEY, ENCRYPTION_KEY, SESSION_SECRET) غير موجودة. يرجى التحقق من ملف server.env');
  process.exit(1);
}

// ═══════════════════════════════════════════
// 3. الأمان والحماية المتقدمة (Helmet & CSP)
// ═══════════════════════════════════════════
app.use(helmet({ 
  // تفعيل CSP بشكل صارم
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com"], // مثال: إذا كنت تستخدم CDN
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://*"],
      connectSrc: ["'self'", process.env.FIREBASE_URL.replace(/\/$/, '')], // السماح بالاتصال بـ Firebase
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false, // تم تعطيله للسماح بالموارد الخارجية
}));

// ═══════════════════════════════════════════
// CORS
// ═══════════════════════════════════════════
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

// ═══════════════════════════════════════════
// Middlewares الأساسية
// ═══════════════════════════════════════════
// يجب أن يأتي هذا قبل csurf لأنه يحتاج إلى قراءة الكوكيز
app.use(cookieParser(process.env.SESSION_SECRET)); 

// يجب أن يأتي هذا قبل csurf لأنه يقرأ جسم الطلب
app.use(express.json({ limit: '2mb' }));

// ═══════════════════════════════════════════
// 4. حماية CSRF (لواجهة الأدمن فقط)
// ═══════════════════════════════════════════
const csrfProtection = csurf({ 
  cookie: { 
    key: '_csrf_token',
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production', // يجب أن يكون true في الإنتاج
    sameSite: 'strict' 
  } 
});

// ═══════════════════════════════════════════
// Brute Force Protection (كما هو في الكود الأصلي)
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
// دوال مساعدة (كما هي في الكود الأصلي)
// ═══════════════════════════════════════════
const adminSessions = new Map();
const subAdminKeys = new Map();

const APP_API_KEY = process.env.APP_API_KEY;
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USERNAME,
  password: process.env.ADMIN_PASSWORD
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
// المصادقة - Middlewares (تم تحديثها)
// ═══════════════════════════════════════════

// مصادقة التطبيق (تم تحديثها لتشمل HMAC)
const authApp = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ 
      success: false, 
      error: 'API Key required', 
      code: 401 
    });
  }
  
  if (apiKey === APP_API_KEY) {
    // إذا كان مفتاح API صحيحاً، ننتقل إلى التحقق من HMAC
    return hmacVerificationMiddleware(req, res, next);
  }
  
  res.status(401).json({ 
    success: false, 
    error: 'Invalid API Key', 
    code: 401 
  });
};

// مصادقة Master Admin (كما هي في الكود الأصلي)
const authAdmin = (req, res, next) => {
  const sessionToken = req.headers['x-session-token'];
  const masterToken = process.env.MASTER_ADMIN_TOKEN;
  
  if (!sessionToken) {
    return res.status(401).json({ 
      success: false, 
      error: 'Session token required', 
      code: 401 
    });
  }
  
  // ✅ تحقق من Master Token المباشر
  if (masterToken && sessionToken === masterToken) {
    req.adminUser = 'master_owner';
    return next();
  }
  
  // التحقق من Session عادية
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

// مصادقة Sub Admin (كما هي في الكود الأصلي)
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

// التحقق من صلاحيات Sub Admin (كما هي في الكود الأصلي)
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

// ✅ التحقق من ملكية المستخدم (كما هي في الكود الأصلي)
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
    if (user.created_by_key !== currentKeyId) {
      return res.status(403).json({ 
        success: false, 
        error: 'Access denied: User not created by this key' 
      });
    }
    
    next();
    
  } catch (error) {
    console.error('Check user ownership error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error during ownership check' 
    });
  }
};

// ═══════════════════════════════════════════
// 5. نقاط النهاية (Endpoints)
// ═══════════════════════════════════════════

// نقطة نهاية للحصول على CSRF Token (لواجهة الأدمن)
app.get('/api/admin/csrf-token', csrfProtection, (req, res) => {
  res.json({ 
    success: true, 
    csrfToken: req.csrfToken() 
  });
});

// ═══════════════════════════════════════════
// 📱 مسارات التطبيق (تم تطبيق التشفير وفك التشفير)
// ═══════════════════════════════════════════

// ✅ يجب تطبيق decryptBodyMiddleware قبل authApp إذا كان authApp يعتمد على جسم الطلب
// ✅ يجب تطبيق encryptResponseMiddleware بعد كل شيء لتشفير الردود

app.post('/api/getUser', authApp, decryptBodyMiddleware, encryptResponseMiddleware, apiLimiter, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({ 
        success: false, 
        code: 0, 
        error: 'Missing username' 
      });
    }
    
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) {
      return res.status(404).json({ 
        success: false, 
        code: 0, 
        error: 'User not found' 
      });
    }
    
    const userId = Object.keys(users)[0];
    const user = users[userId];
    
    // ✅ التحقق من حالة المستخدم وتاريخ الانتهاء
    if (user.is_active === false) {
      return res.status(403).json({ 
        success: false, 
        code: 1, 
        error: 'Account is inactive' 
      });
    }
    
    if (user.subscription_end && Date.now() > user.subscription_end) {
      return res.status(403).json({ 
        success: false, 
        code: 2, 
        error: 'Subscription expired' 
      });
    }
    
    // ✅ التحقق من تطابق كلمة المرور (إذا كانت مطلوبة)
    // الكود الأصلي لم يكن يتحقق من كلمة المرور هنا، لذا سنحافظ على نفس المنطق
    
    res.json({
      success: true,
      user_id: userId,
      username: user.username,
      is_active: user.is_active !== false,
      expiry_timestamp: user.subscription_end || 0,
      device_id: user.device_id || '',
      max_devices: user.max_devices || 1,
      // لا نرسل كلمة المرور أو أي بيانات حساسة أخرى
    });
    
  } catch (error) {
    console.error('Get user error:', error.message);
    res.status(500).json({ 
      success: false, 
      code: 0, 
      error: 'Server error' 
    });
  }
});

app.post('/api/verifyAccount', authApp, decryptBodyMiddleware, encryptResponseMiddleware, apiLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        code: 0, 
        error: 'Missing data' 
      });
    }
    
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) {
      return res.status(404).json({ 
        success: false, 
        code: 0, 
        error: 'User not found' 
      });
    }
    
    const userId = Object.keys(users)[0];
    const user = users[userId];
    
    // ✅ التحقق من كلمة المرور
    if (hashPassword(password) !== user.password_hash) {
      // ✅ تسجيل محاولة فاشلة
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
      loginAttempts.get(ip).count++;
      loginAttempts.get(ip).lastAttempt = Date.now();
      console.warn(`🚨 Failed login attempt for user: ${username} from IP: ${ip}`);
      
      return res.status(401).json({ 
        success: false, 
        code: 3, 
        error: 'Invalid password' 
      });
    }
    
    // إعادة تعيين عداد محاولات القوة الغاشمة
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    if (loginAttempts.has(ip)) {
      loginAttempts.get(ip).count = 0;
    }
    
    // ✅ التحقق من حالة المستخدم وتاريخ الانتهاء
    if (user.is_active === false) {
      return res.status(403).json({ 
        success: false, 
        code: 1, 
        error: 'Account is inactive' 
      });
    }
    
    if (user.subscription_end && Date.now() > user.subscription_end) {
      return res.status(403).json({ 
        success: false, 
        code: 2, 
        error: 'Subscription expired' 
      });
    }
    
    res.json({
      success: true,
      user_id: userId,
      username: user.username,
      is_active: user.is_active !== false,
      expiry_timestamp: user.subscription_end || 0,
      device_id: user.device_id || '',
      max_devices: user.max_devices || 1,
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


app.post('/api/updateDevice', authApp, decryptBodyMiddleware, encryptResponseMiddleware, apiLimiter, async (req, res) => {
  try {
    const { username, deviceId, deviceInfo } = req.body;
    
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
    const user = users[userId];
    
    // ✅ Get IP and User Agent
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const userAgent = req.headers['user-agent'] || '';
    
    // ✅ إعداد بيانات التحديث الأساسية
    const updateData = {
      device_id: deviceId,
      last_login: Date.now(),
      login_count: (user.login_count || 0) + 1,
      ip_address: ip,
      user_agent: userAgent
    };
    
    // ✅ إضافة معلومات الجهاز إذا كانت موجودة
    if (deviceInfo) {
      // Device Info
      updateData.device_model = deviceInfo.device_model || 'Unknown';
      updateData.device_brand = deviceInfo.device_brand || 'Unknown';
      updateData.device_manufacturer = deviceInfo.device_manufacturer || 'Unknown';
      updateData.device_product = deviceInfo.device_product || 'Unknown';
      updateData.device_type = deviceInfo.device_type || 'Phone';
      
      // OS Info
      updateData.android_version = deviceInfo.android_version || 'Unknown';
      updateData.sdk_version = deviceInfo.sdk_version || 0;
      
      // Security Info
      updateData.is_rooted = deviceInfo.is_rooted || false;
      updateData.has_screen_lock = deviceInfo.has_screen_lock || false;
      updateData.fingerprint_enabled = deviceInfo.fingerprint_enabled || false;
      
      // Hardware Info
      updateData.total_ram = deviceInfo.total_ram || 'Unknown';
      updateData.screen_size = deviceInfo.screen_size || 'Unknown';
      updateData.screen_density = deviceInfo.screen_density || 0;
      
      // Network Info
      updateData.network_type = deviceInfo.network_type || 'Unknown';
      updateData.carrier_name = deviceInfo.carrier_name || 'Unknown';
      
      // Battery Info
      updateData.battery_level = deviceInfo.battery_level || 0;
      updateData.is_charging = deviceInfo.is_charging || false;
      
      // Location (optional)
      if (deviceInfo.location) {
        updateData.location = deviceInfo.location;
      }
    }
    
    // ✅ إضافة إلى سجل تسجيل الدخول (Login History)
    const loginEntry = {
      timestamp: Date.now(),
      ip: ip,
      device: deviceInfo?.device_model || 'Unknown',
      os_version: deviceInfo?.android_version || 'Unknown',
      network: deviceInfo?.network_type || 'Unknown',
      carrier: deviceInfo?.carrier_name || 'Unknown',
      battery: deviceInfo?.battery_level || 0,
      is_rooted: deviceInfo?.is_rooted || false
    };
    
    // الاحتفاظ بآخر 10 عمليات دخول فقط
    const existingHistory = user.login_history || [];
    updateData.login_history = [
      ...existingHistory.slice(-9), // آخر 9
      loginEntry // الجديد
    ];
    
    // ✅ تحديث البيانات في Firebase
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, updateData);
    
    // ✅ تسجيل في Console للمراقبة
    console.log(`📱 Login: ${username} | Device: ${deviceInfo?.device_brand || 'Unknown'} ${deviceInfo?.device_model || 'Unknown'} | Android: ${deviceInfo?.android_version || '?'} | Root: ${deviceInfo?.is_rooted ? '⚠️ YES' : '✅ NO'} | Network: ${deviceInfo?.network_type || '?'} | IP: ${ip}`);
    
    // ✅ تنبيه إذا كان الجهاز مروت
    if (deviceInfo?.is_rooted) {
      console.warn(`🚨 WARNING: User "${username}" is using a ROOTED device!`);
    }
    
    res.json({ 
      success: true, 
      message: 'Device updated successfully',
      user_info: {
        username: user.username,
        login_count: updateData.login_count,
        is_rooted: updateData.is_rooted,
        last_login: updateData.last_login
      }
    });
    
  } catch (error) {
    console.error('❌ Update device error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Server error' 
    });
  }
});

// ═══════════════════════════════════════════
// 📊 مسارات الأدمن (تم تطبيق حماية CSRF)
// ═══════════════════════════════════════════

// مسار تسجيل الدخول لا يحتاج إلى CSRF
app.post('/api/admin/login', loginLimiter, bruteForceProtection, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (username === ADMIN_CREDENTIALS.username && password === ADMIN_CREDENTIALS.password) {
      const token = generateToken();
      adminSessions.set(token, { username, createdAt: Date.now() });
      
      // إعادة تعيين عداد محاولات القوة الغاشمة
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
      if (loginAttempts.has(ip)) {
        loginAttempts.get(ip).count = 0;
      }
      
      res.json({ 
        success: true, 
        message: 'Login successful', 
        session_token: token 
      });
    } else {
      // ✅ تسجيل محاولة فاشلة
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
      if (loginAttempts.has(ip)) {
        loginAttempts.get(ip).count++;
        loginAttempts.get(ip).lastAttempt = Date.now();
      }
      console.warn(`🚨 Failed admin login attempt for user: ${username} from IP: ${ip}`);
      
      res.status(401).json({ 
        success: false, 
        error: 'Invalid credentials' 
      });
    }
  } catch (error) {
    console.error('Admin login error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Server error' 
    });
  }
});

// مسارات الأدمن الأخرى تحتاج إلى authAdmin و csrfProtection
app.get('/api/admin/device-stats', authAdmin, apiLimiter, async (req, res) => {
  // ... (الكود الأصلي)
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const stats = {
      total_users: Object.keys(users).length,
      total_devices: 0,
      rooted_devices: 0,
      rooted_percentage: 0,
      
      // Device Brands
      device_brands: {},
      top_brands: [],
      
      // Android Versions
      android_versions: {},
      top_android_versions: [],
      
      // Device Types
      device_types: { Phone: 0, Tablet: 0, Unknown: 0 },
      
      // Network Types
      network_types: {},
      top_networks: [],
      
      // Carriers
      carriers: {},
      top_carriers: [],
      
      // Battery Stats
      average_battery: 0,
      charging_devices: 0,
      low_battery_devices: 0,
      
      // Security Stats
      screen_lock_enabled: 0,
      fingerprint_enabled: 0,
      
      // Active Users
      active_last_hour: 0,
      active_last_day: 0,
      active_last_week: 0
    };
    
    let batterySum = 0;
    let batteryCount = 0;
    const now = Date.now();
    const oneHour = 60 * 60 * 1000;
    const oneDay = 24 * oneHour;
    const oneWeek = 7 * oneDay;
    
    for (const user of Object.values(users)) {
      // Total Devices
      if (user.device_id) {
        stats.total_devices++;
        
        // Rooted
        if (user.is_rooted) stats.rooted_devices++;
        
        // Device Brands
        const brand = user.device_brand || 'Unknown';
        stats.device_brands[brand] = (stats.device_brands[brand] || 0) + 1;
        
        // Android Versions
        const version = user.android_version || 'Unknown';
        stats.android_versions[version] = (stats.android_versions[version] || 0) + 1;
        
        // Device Types
        const type = user.device_type || 'Unknown';
        stats.device_types[type]++;
        
        // Network Types
        const network = user.network_type || 'Unknown';
        stats.network_types[network] = (stats.network_types[network] || 0) + 1;
        
        // Carriers
        const carrier = user.carrier_name || 'Unknown';
        stats.carriers[carrier] = (stats.carriers[carrier] || 0) + 1;
        
        // Battery
        if (user.battery_level) {
          batterySum += user.battery_level;
          batteryCount++;
          if (user.battery_level <= 20) stats.low_battery_devices++;
        }
        if (user.is_charging) stats.charging_devices++;
        
        // Security
        if (user.has_screen_lock) stats.screen_lock_enabled++;
        if (user.fingerprint_enabled) stats.fingerprint_enabled++;
      }
      
      // Active Users
      if (user.last_login) {
        const timeSince = now - user.last_login;
        if (timeSince < oneHour) stats.active_last_hour++;
        if (timeSince < oneDay) stats.active_last_day++;
        if (timeSince < oneWeek) stats.active_last_week++;
      }
    }
    
    // Calculations
    stats.average_battery = batteryCount > 0 ? Math.round(batterySum / batteryCount) : 0;
    stats.rooted_percentage = stats.total_devices > 0 ? Math.round((stats.rooted_devices / stats.total_devices) * 100) : 0;
    
    // Top Brands (أكثر 5 علامات تجارية)
    stats.top_brands = Object.entries(stats.device_brands)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([brand, count]) => ({ brand, count }));
    
    // Top Android Versions
    stats.top_android_versions = Object.entries(stats.android_versions)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([version, count]) => ({ version, count }));
    
    // Top Networks
    stats.top_networks = Object.entries(stats.network_types)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([network, count]) => ({ network, count }));
    
    // Top Carriers
    stats.top_carriers = Object.entries(stats.carriers)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([carrier, count]) => ({ carrier, count }));
    
    res.json({ 
      success: true, 
      data: stats 
    });
    
  } catch (error) {
    console.error('Device stats error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch device stats' 
    });
  }
});

app.get('/api/admin/rooted-devices', authAdmin, apiLimiter, async (req, res) => {
  // ... (الكود الأصلي)
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const rootedDevices = [];
    
    for (const [userId, user] of Object.entries(users)) {
      if (user.is_rooted) {
        rootedDevices.push({
          user_id: userId,
          username: user.username,
          device_model: user.device_model || 'Unknown',
          device_brand: user.device_brand || 'Unknown',
          android_version: user.android_version || 'Unknown',
          last_login: user.last_login,
          ip_address: user.ip_address || 'Unknown',
          network_type: user.network_type || 'Unknown'
        });
      }
    }
    
    res.json({ 
      success: true, 
      data: rootedDevices 
    });
    
  } catch (error) {
    console.error('Rooted devices error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch rooted devices' 
    });
  }
});

app.get('/api/admin/users', authAdmin, apiLimiter, async (req, res) => {
  // ... (الكود الأصلي)
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const usersList = Object.entries(users).map(([id, user]) => ({
      id,
      username: user.username,
      is_active: user.is_active !== false,
      expiry_timestamp: user.subscription_end || 0,
      expiry_date: formatDate(user.subscription_end),
      device_id: user.device_id || '',
      max_devices: user.max_devices || 1,
      created_by_key: user.created_by_key || 'master'
    }));
    
    res.json({ 
      success: true, 
      data: usersList 
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
  // ... (الكود الأصلي)
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
        created_by_key: user.created_by_key || 'master' // ✅ إضافة هذا الحقل
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

app.post('/api/admin/users', authAdmin, csrfProtection, apiLimiter, async (req, res) => {
  // ... (الكود الأصلي)
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
      created_by_key: 'master'  // ✅ مهم جداً! تعيين master للمستخدمين من Master Admin
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

app.patch('/api/admin/users/:id', authAdmin, csrfProtection, apiLimiter, async (req, res) => {
  // ... (الكود الأصلي)
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

app.delete('/api/admin/users/:id', authAdmin, csrfProtection, apiLimiter, async (req, res) => {
  // ... (الكود الأصلي)
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

app.post('/api/admin/users/delete-expired', authAdmin, csrfProtection, apiLimiter, async (req, res) => {
  // ... (الكود الأصلي)
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
    
    // حذف دفعة واحدة
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

app.post('/api/admin/users/:id/extend', authAdmin, csrfProtection, apiLimiter, async (req, res) => {
  // ... (الكود الأصلي)
  try {
    const { minutes, days, hours } = req.body;
    
    if (!minutes && !days && !hours) {
      return res.status(400).json({ 
        success: false, 
        error: 'Extension duration required' 
      });
    }
    
    const userRes = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);
    const user = userRes.data;
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    let currentExpiry = user.subscription_end || Date.now();
    
    // إذا كان الاشتراك منتهيًا، نبدأ من الآن، وإلا نبدأ من تاريخ الانتهاء الحالي
    if (currentExpiry < Date.now()) {
      currentExpiry = Date.now();
    }
    
    let extensionTime = 0;
    if (minutes) extensionTime += minutes * 60 * 1000;
    if (hours) extensionTime += hours * 60 * 60 * 1000;
    if (days) extensionTime += days * 24 * 60 * 60 * 1000;
    
    const newExpiry = currentExpiry + extensionTime;
    
    await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, {
      subscription_end: newExpiry,
      is_active: true // تفعيل المستخدم عند التمديد
    });
    
    console.log(`✅ User ${user.username} extended until: ${formatDate(newExpiry)}`);
    
    res.json({ 
      success: true, 
      message: `Subscription extended until ${formatDate(newExpiry)}`,
      new_expiry: newExpiry
    });
    
  } catch (error) {
    console.error('Extend subscription error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to extend subscription' 
    });
  }
});

// ═══════════════════════════════════════════
// 6. إدارة الأخطاء الأمنية (Security Error Handling)
// ═══════════════════════════════════════════

// معالجة أخطاء CSRF
app.use((err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);
  
  console.warn(`🚨 CSRF Token Error: ${req.ip} tried to access ${req.path}`);
  res.status(403).json({ 
    success: false, 
    error: 'Invalid CSRF token. Request blocked for security.', 
    code: 403 
  });
});

// معالجة الأخطاء العامة
app.use((err, req, res, next) => {
  console.error('❌ General Error:', err.stack);
  res.status(500).json({ 
    success: false, 
    error: 'Internal Server Error', 
    details: process.env.NODE_ENV === 'development' ? err.message : undefined 
  });
});

// ═══════════════════════════════════════════
// بدء الخادم
// ═══════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`API Key: ${APP_API_KEY}`);
  console.log(`HMAC Key: ${process.env.HMAC_SECRET_KEY}`);
});
