/**
 * Firebase Proxy Server
 * خادم وسيط آمن لحماية مفاتيح Firebase
 * إصدار: 2.1.0 (محسّن)
 */

// ============================================
// استيراد المكتبات
// ============================================
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

// ============================================
// إعدادات التطبيق
// ============================================
const app = express();
const PORT = process.env.PORT || 10000;
const isProduction = process.env.NODE_ENV === 'production';

// تحقق من وجود المتغيرات البيئية الأساسية
const requiredEnvVars = ['FIREBASE_URL', 'FIREBASE_KEY'];
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    console.error(`❌ خطأ: المتغير البيئي ${varName} غير موجود`);
    console.log('⚙️  رجاءً أضفه في Render Dashboard → Environment');
    process.exit(1);
  }
});

// تحذير إذا لم يكن APP_API_KEY موجوداً
if (!process.env.APP_API_KEY) {
  console.warn('⚠️  تحذير: APP_API_KEY غير محدد، سيتم استخدام المفتاح الافتراضي');
}

// ============================================
// وظائف مساعدة
// ============================================

/**
 * مقارنة إصدارات التطبيق
 * @param {string} v1 - الإصدار الأول
 * @param {string} v2 - الإصدار الثاني
 * @returns {number} - 1 إذا v1 > v2، -1 إذا v1 < v2، 0 إذا متساويين
 */
function compareVersions(v1, v2) {
  try {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const num1 = parts1[i] || 0;
      const num2 = parts2[i] || 0;
      
      if (num1 > num2) return 1;
      if (num1 < num2) return -1;
    }
    return 0;
  } catch (error) {
    console.error('❌ خطأ في مقارنة الإصدارات:', error);
    return 0;
  }
}

/**
 * حساب الأيام المتبقية حتى انتهاء الصلاحية
 * @param {string} expiryDate - تاريخ الانتهاء بتنسيق dd/MM/yyyy HH:mm
 * @returns {number} - عدد الأيام المتبقية
 */
function calculateRemainingDays(expiryDate) {
  try {
    if (!expiryDate || typeof expiryDate !== 'string' || expiryDate.trim() === '') {
      return -1;
    }
    
    // تنسيق التاريخ: dd/MM/yyyy HH:mm
    const [datePart, timePart] = expiryDate.trim().split(' ');
    const [day, month, year] = datePart.split('/').map(Number);
    const [hour, minute] = (timePart || '00:00').split(':').map(Number);
    
    // التحقق من صحة القيم
    if (isNaN(day) || isNaN(month) || isNaN(year)) {
      return -1;
    }
    
    const expiryTime = new Date(year, month - 1, day, hour || 0, minute || 0);
    const now = new Date();
    
    if (isNaN(expiryTime.getTime())) {
      return -1;
    }
    
    const diffMs = expiryTime - now;
    const daysRemaining = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
    
    return Math.max(0, daysRemaining);
  } catch (error) {
    console.error('❌ خطأ في حساب الأيام المتبقية:', error);
    return -1;
  }
}

/**
 * تجزئة كلمة المرور (SHA-256 مع Salt)
 * @param {string} password - كلمة المرور
 * @param {string} salt - Salt اختياري
 * @returns {string} - التجزئة
 */
function calculatePasswordHash(password, salt = '') {
  try {
    if (!password || typeof password !== 'string') {
      return null;
    }
    
    const hash = crypto.createHash('sha256');
    hash.update(password + salt, 'utf8');
    return hash.digest('hex');
  } catch (error) {
    console.error('❌ خطأ في تجزئة كلمة المرور:', error);
    return null;
  }
}

/**
 * تنظيف وتحقق من المدخلات
 * @param {string} input - المدخل
 * @param {number} maxLength - الحد الأقصى للطول
 * @returns {string} - المدخل المنظف
 */
function sanitizeInput(input, maxLength = 100) {
  if (!input || typeof input !== 'string') {
    return '';
  }
  
  return input
    .trim()
    .slice(0, maxLength)
    .replace(/[<>\"\'&]/g, ''); // إزالة الأحرف الخطرة
}

/**
 * التحقق من صحة معرف الجهاز
 * @param {string} deviceId - معرف الجهاز
 * @returns {boolean} - صحيح أم لا
 */
function isValidDeviceId(deviceId) {
  if (!deviceId || typeof deviceId !== 'string') {
    return false;
  }
  
  // معرف الجهاز يجب أن يكون بين 16-128 حرف ويحتوي فقط على أحرف وأرقام وشرطات
  const deviceIdRegex = /^[a-zA-Z0-9\-_]{16,128}$/;
  return deviceIdRegex.test(deviceId);
}

/**
 * التحقق من صحة اسم المستخدم
 * @param {string} username - اسم المستخدم
 * @returns {boolean} - صحيح أم لا
 */
function isValidUsername(username) {
  if (!username || typeof username !== 'string') {
    return false;
  }
  
  // اسم المستخدم يجب أن يكون بين 3-50 حرف
  const usernameRegex = /^[a-zA-Z0-9_\-\.@]{3,50}$/;
  return usernameRegex.test(username.trim());
}

/**
 * استخراج بيانات من Firebase Response
 * @param {Object} firebaseResponse - استجابة Firebase
 * @returns {Object|null} - بيانات المستخدم
 */
function extractUserData(firebaseResponse) {
  try {
    if (!firebaseResponse || typeof firebaseResponse !== 'object') {
      return null;
    }
    
    const keys = Object.keys(firebaseResponse);
    if (keys.length === 0) {
      return null;
    }
    
    const userKey = keys[0];
    const userData = firebaseResponse[userKey];
    
    if (!userData) {
      return null;
    }
    
    return {
      key: userKey,
      ...userData,
      remainingDays: calculateRemainingDays(userData.expiry_date || '')
    };
  } catch (error) {
    console.error('❌ خطأ في استخراج بيانات المستخدم:', error);
    return null;
  }
}

/**
 * تسجيل الطلبات
 * @param {Object} req - كائن الطلب
 * @param {string} action - الإجراء
 */
function logRequest(req, action) {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const path = req.path;
  const ip = req.ip || req.connection.remoteAddress;
  const appVersion = req.headers['x-app-version'] || 'Unknown';
  const deviceId = req.headers['x-device-id'];
  
  console.log(`📥 ${timestamp} | ${method} ${path} | IP: ${ip} | App: ${appVersion} | Device: ${deviceId?.substring(0, 8) || 'N/A'} | ${action}`);
}

// ============================================
// Middleware
// ============================================

// 1. حماية Headers
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  hidePoweredBy: true,
}));

// 2. CORS - السماح بتطبيقات محددة فقط
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['https://play.google.com'];

app.use(cors({
  origin: (origin, callback) => {
    // السماح بطلبات بدون origin (مثل mobile apps)
    if (!origin) {
      return callback(null, true);
    }
    
    // السماح بـ localhost في بيئة التطوير فقط
    if (!isProduction && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    console.warn(`⚠️  محاولة وصول من مصدر غير مسموح: ${origin}`);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-api-key', 'x-app-version', 'x-device-id']
}));

// 3. Rate Limiting لمنع الهجمات
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: {
    success: false,
    error: 'تم تجاوز الحد المسموح للطلبات. حاول مرة أخرى لاحقاً.',
    code: 429,
    retryAfter: '15 دقيقة'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || 'unknown';
  }
});

app.use('/api/', limiter);

// 4. تحليل JSON
app.use(express.json({ 
  limit: '10mb',
  strict: true
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb' 
}));

// 5. منع التخزين المؤقت للـ API
app.use('/api/', (req, res, next) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });
  next();
});

// ============================================
// Middleware للتحقق من الطلبات
// ============================================
const authenticateRequest = (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    const appVersion = req.headers['x-app-version'] || '1.0.0';
    
    logRequest(req, 'Authenticating...');
    
    // التحقق من API Key
    const expectedApiKey = process.env.APP_API_KEY || 'default-key';
    
    if (!apiKey) {
      console.warn('🚫 طلب بدون API Key');
      return res.status(401).json({
        success: false,
        error: 'مفتاح API مطلوب',
        code: 401
      });
    }
    
    if (apiKey !== expectedApiKey) {
      console.warn(`🚫 محاولة وصول برمز API غير صحيح: ${apiKey.substring(0, 10)}...`);
      return res.status(401).json({
        success: false,
        error: 'غير مصرح',
        code: 401,
        message: 'رمز API غير صحيح'
      });
    }
    
    // التحقق من نسخة التطبيق
    const minVersion = process.env.MIN_APP_VERSION || '1.0.0';
    if (appVersion && compareVersions(appVersion, minVersion) < 0) {
      return res.status(426).json({
        success: false,
        error: 'يرجى تحديث التطبيق',
        code: 426,
        currentVersion: appVersion,
        minVersion: minVersion,
        updateUrl: process.env.APP_UPDATE_URL || 'https://play.google.com/store/apps/details?id=com.your.app'
      });
    }
    
    next();
  } catch (error) {
    console.error('❌ خطأ في مصادقة الطلب:', error);
    res.status(500).json({
      success: false,
      error: 'خطأ في المصادقة',
      code: 500
    });
  }
};

// ============================================
// إعدادات Axios لـ Firebase
// ============================================
const firebaseAxios = axios.create({
  timeout: 15000,
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'User-Agent': 'Firebase-Proxy-Server/2.1.0'
  }
});

// ============================================
// Endpoints
// ============================================

/**
 * 🔍 1. جلب بيانات المستخدم من Firebase
 * Endpoint: POST /api/getUser
 */
app.post('/api/getUser', authenticateRequest, async (req, res) => {
  try {
    const username = sanitizeInput(req.body.username, 50);
    
    // التحقق من البيانات
    if (!username) {
      return res.status(400).json({
        success: false,
        error: 'اسم المستخدم مطلوب',
        code: 400
      });
    }
    
    if (!isValidUsername(username)) {
      return res.status(400).json({
        success: false,
        error: 'اسم المستخدم غير صالح',
        code: 400,
        message: 'يجب أن يكون اسم المستخدم بين 3-50 حرف'
      });
    }
    
    logRequest(req, `جلب بيانات: ${username}`);
    
    // بناء رابط Firebase
    const encodedUsername = encodeURIComponent(username);
    const firebaseUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodedUsername}"&auth=${process.env.FIREBASE_KEY}`;
    
    // إرسال الطلب إلى Firebase
    const response = await firebaseAxios.get(firebaseUrl);
    
    // تحقق من وجود المستخدم
    if (!response.data || Object.keys(response.data).length === 0) {
      return res.json({
        success: false,
        error: 'اسم المستخدم غير موجود',
        code: 1,
        message: 'تأكد من صحة اسم المستخدم'
      });
    }
    
    // استخراج وتنسيق البيانات
    const userData = extractUserData(response.data);
    
    if (!userData) {
      return res.status(500).json({
        success: false,
        error: 'خطأ في معالجة البيانات',
        code: 500
      });
    }
    
    // إرجاع البيانات (مع إخفاء الحقول الحساسة)
    const safeUserData = {
      username: userData.username,
      is_active: userData.is_active || false,
      expiry_date: userData.expiry_date || '',
      device_id: userData.device_id || '',
      remaining_days: userData.remainingDays,
      created_at: userData.created_at || ''
    };
    
    console.log(`✅ تم جلب بيانات: ${username} (${safeUserData.remaining_days} يوم متبقي)`);
    
    res.json({
      success: true,
      data: safeUserData,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ خطأ في /api/getUser:', error.message);
    
    let errorCode = 0;
    let errorMessage = 'خطأ في الاتصال بالخادم';
    
    if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      errorCode = 13;
      errorMessage = 'انتهت مهلة الاتصال';
    } else if (error.response) {
      errorCode = error.response.status;
      errorMessage = 'خطأ في استجابة Firebase';
    } else if (error.code === 'ENOTFOUND') {
      errorCode = 12;
      errorMessage = 'لا يمكن الوصول إلى الخادم';
    }
    
    res.status(500).json({
      success: false,
      error: errorMessage,
      code: errorCode,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * 📱 2. تحديث معرف الجهاز
 * Endpoint: POST /api/updateDevice
 */
app.post('/api/updateDevice', authenticateRequest, async (req, res) => {
  try {
    const username = sanitizeInput(req.body.username, 50);
    const deviceId = sanitizeInput(req.body.deviceId, 128);
    
    // التحقق من البيانات
    if (!username || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'بيانات ناقصة',
        code: 400,
        required: ['username', 'deviceId']
      });
    }
    
    if (!isValidUsername(username)) {
      return res.status(400).json({
        success: false,
        error: 'اسم المستخدم غير صالح',
        code: 400
      });
    }
    
    if (!isValidDeviceId(deviceId)) {
      return res.status(400).json({
        success: false,
        error: 'معرف الجهاز غير صالح',
        code: 400,
        message: 'يجب أن يكون معرف الجهاز بين 16-128 حرف'
      });
    }
    
    logRequest(req, `تحديث جهاز: ${username}`);
    
    // 1. البحث عن المستخدم للحصول على المفتاح
    const searchUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const searchResponse = await firebaseAxios.get(searchUrl);
    
    if (!searchResponse.data || Object.keys(searchResponse.data).length === 0) {
      return res.json({
        success: false,
        error: 'المستخدم غير موجود',
        code: 1
      });
    }
    
    const userKey = Object.keys(searchResponse.data)[0];
    
    // 2. تحديث معرف الجهاز
    const updateUrl = `${process.env.FIREBASE_URL}/users/${userKey}.json?auth=${process.env.FIREBASE_KEY}`;
    const updateData = {
      device_id: deviceId,
      last_device_update: new Date().toISOString()
    };
    
    await firebaseAxios.patch(updateUrl, updateData);
    
    console.log(`✅ تم تحديث الجهاز: ${username} -> ${deviceId.substring(0, 10)}...`);
    
    res.json({
      success: true,
      message: 'تم تحديث معرف الجهاز بنجاح',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ خطأ في /api/updateDevice:', error.message);
    
    res.status(500).json({
      success: false,
      error: 'فشل في تحديث البيانات',
      code: 11,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * ✅ 3. التحقق الكامل من الحساب
 * Endpoint: POST /api/verifyAccount
 */
app.post('/api/verifyAccount', authenticateRequest, async (req, res) => {
  try {
    const username = sanitizeInput(req.body.username, 50);
    const password = req.body.password; // لا نقوم بتنظيف كلمة المرور
    const deviceId = sanitizeInput(req.body.deviceId, 128);
    
    // التحقق من البيانات
    if (!username || !password || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'بيانات الاعتماد ناقصة',
        code: 400,
        required: ['username', 'password', 'deviceId']
      });
    }
    
    if (!isValidUsername(username)) {
      return res.status(400).json({
        success: false,
        error: 'اسم المستخدم غير صالح',
        code: 400
      });
    }
    
    if (!isValidDeviceId(deviceId)) {
      return res.status(400).json({
        success: false,
        error: 'معرف الجهاز غير صالح',
        code: 400
      });
    }
    
    if (password.length < 4 || password.length > 100) {
      return res.status(400).json({
        success: false,
        error: 'كلمة المرور غير صالحة',
        code: 400
      });
    }
    
    logRequest(req, `التحقق من: ${username}`);
    
    // 1. حساب تجزئة كلمة المرور
    const passwordHash = calculatePasswordHash(password);
    if (!passwordHash) {
      return res.json({
        success: false,
        error: 'خطأ في معالجة كلمة المرور',
        code: 15
      });
    }
    
    // 2. جلب بيانات المستخدم من Firebase
    const userUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const userResponse = await firebaseAxios.get(userUrl);
    
    const userData = userResponse.data;
    
    if (!userData || Object.keys(userData).length === 0) {
      return res.json({
        success: false,
        error: 'اسم المستخدم غير موجود',
        code: 1,
        errorMessage: 'تأكد من صحة اسم المستخدم'
      });
    }
    
    const userKey = Object.keys(userData)[0];
    const user = userData[userKey];
    
    // 3. التحقق من كلمة المرور
    if (user.password_hash !== passwordHash) {
      console.warn(`🚫 محاولة دخول فاشلة: ${username} - كلمة مرور خاطئة`);
      return res.json({
        success: false,
        error: 'كلمة المرور خاطئة',
        code: 2,
        errorMessage: 'تأكد من صحة كلمة المرور'
      });
    }
    
    // 4. التحقق من حالة الحساب
    if (!user.is_active) {
      return res.json({
        success: false,
        error: 'الحساب غير نشط',
        code: 3,
        errorMessage: 'يرجى التواصل مع الدعم الفني'
      });
    }
    
    // 5. التحقق من الجهاز (إذا كان الحساب مربوط بجهاز)
    if (user.device_id && user.device_id.trim() !== '' && user.device_id !== deviceId) {
      return res.json({
        success: false,
        error: 'الحساب مربوط بجهاز آخر',
        code: 4,
        errorMessage: 'يمكنك تسجيل الدخول من جهاز واحد فقط'
      });
    }
    
    // 6. التحقق من تاريخ الانتهاء
    if (!user.expiry_date || user.expiry_date.trim() === '') {
      return res.json({
        success: false,
        error: 'لا يوجد تاريخ انتهاء للحساب',
        code: 5
      });
    }
    
    const remainingDays = calculateRemainingDays(user.expiry_date);
    
    if (remainingDays < 0) {
      return res.json({
        success: false,
        error: 'خطأ في تاريخ الانتهاء',
        code: 6
      });
    }
    
    if (remainingDays === 0) {
      return res.json({
        success: false,
        error: 'انتهت صلاحية الاشتراك',
        code: 7,
        errorMessage: 'يرجى تجديد الاشتراك'
      });
    }
    
    // 7. تحديث معرف الجهاز وآخر تسجيل دخول
    const updateUrl = `${process.env.FIREBASE_URL}/users/${userKey}.json?auth=${process.env.FIREBASE_KEY}`;
    await firebaseAxios.patch(updateUrl, {
      device_id: deviceId,
      last_login: new Date().toISOString(),
      login_count: (user.login_count || 0) + 1
    });
    
    console.log(`✅ تحقق ناجح: ${username} | متبقي: ${remainingDays} يوم`);
    
    // 8. إرجاع النتيجة الناجحة
    res.json({
      success: true,
      data: {
        username: user.username,
        expiry_date: user.expiry_date,
        remaining_days: remainingDays,
        is_active: user.is_active,
        last_login: new Date().toISOString()
      },
      message: 'تم التحقق بنجاح',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ خطأ في /api/verifyAccount:', error.message);
    
    let errorCode = 0;
    let errorMessage = 'حدث خطأ غير متوقع';
    
    if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      errorCode = 13;
      errorMessage = 'انتهت مهلة الاتصال';
    } else if (error.response && error.response.status === 401) {
      errorCode = 14;
      errorMessage = 'خطأ في مصادقة الخادم';
    }
    
    res.status(500).json({
      success: false,
      error: errorMessage,
      code: errorCode,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * 🔄 4. إعادة تعيين معرف الجهاز (للمدير)
 * Endpoint: POST /api/resetDevice
 */
app.post('/api/resetDevice', authenticateRequest, async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    const username = sanitizeInput(req.body.username, 50);
    
    // التحقق من صلاحيات المدير
    const expectedAdminKey = process.env.ADMIN_API_KEY;
    if (!expectedAdminKey || adminKey !== expectedAdminKey) {
      return res.status(403).json({
        success: false,
        error: 'غير مصرح لك بهذا الإجراء',
        code: 403
      });
    }
    
    if (!username || !isValidUsername(username)) {
      return res.status(400).json({
        success: false,
        error: 'اسم المستخدم غير صالح',
        code: 400
      });
    }
    
    logRequest(req, `إعادة تعيين جهاز: ${username}`);
    
    // البحث عن المستخدم
    const searchUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const searchResponse = await firebaseAxios.get(searchUrl);
    
    if (!searchResponse.data || Object.keys(searchResponse.data).length === 0) {
      return res.json({
        success: false,
        error: 'المستخدم غير موجود',
        code: 1
      });
    }
    
    const userKey = Object.keys(searchResponse.data)[0];
    
    // إعادة تعيين معرف الجهاز
    const updateUrl = `${process.env.FIREBASE_URL}/users/${userKey}.json?auth=${process.env.FIREBASE_KEY}`;
    await firebaseAxios.patch(updateUrl, {
      device_id: '',
      device_reset_at: new Date().toISOString()
    });
    
    console.log(`✅ تم إعادة تعيين الجهاز: ${username}`);
    
    res.json({
      success: true,
      message: 'تم إعادة تعيين معرف الجهاز بنجاح',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ خطأ في /api/resetDevice:', error.message);
    
    res.status(500).json({
      success: false,
      error: 'فشل في إعادة تعيين الجهاز',
      code: 500,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * ⏰ 5. الحصول على وقت السيرفر
 * Endpoint: GET /api/serverTime
 */
app.get('/api/serverTime', (req, res) => {
  const serverTime = Date.now();
  
  res.json({
    success: true,
    server_time: serverTime,
    server_time_formatted: new Date(serverTime).toISOString(),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    timestamp: new Date().toISOString()
  });
});

/**
 * 🩺 6. فحص صحة الخادم
 * Endpoint: GET /api/health
 */
app.get('/api/health', async (req, res) => {
  let firebaseStatus = 'unknown';
  
  // اختبار اتصال Firebase
  try {
    const testUrl = `${process.env.FIREBASE_URL}/.json?shallow=true&auth=${process.env.FIREBASE_KEY}`;
    await firebaseAxios.get(testUrl, { timeout: 5000 });
    firebaseStatus = 'connected';
  } catch (error) {
    firebaseStatus = 'disconnected';
  }
  
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    server: {
      uptime: Math.floor(process.uptime()),
      uptime_formatted: `${Math.floor(process.uptime() / 3600)} ساعة`,
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB'
      },
      node_version: process.version,
      platform: process.platform
    },
    firebase: {
      status: firebaseStatus,
      url_configured: !!process.env.FIREBASE_URL,
      key_configured: !!process.env.FIREBASE_KEY
    },
    security: {
      api_key_configured: !!process.env.APP_API_KEY,
      admin_key_configured: !!process.env.ADMIN_API_KEY,
      rate_limit: process.env.RATE_LIMIT_MAX || 100
    },
    environment: process.env.NODE_ENV || 'development',
    version: '2.1.0'
  };
  
  const statusCode = firebaseStatus === 'connected' ? 200 : 503;
  res.status(statusCode).json(health);
});

/**
 * 📊 7. إحصائيات بسيطة (للمدير)
 * Endpoint: GET /api/stats
 */
app.get('/api/stats', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    
    // التحقق من صلاحيات المدير
    const expectedAdminKey = process.env.ADMIN_API_KEY;
    if (!expectedAdminKey || adminKey !== expectedAdminKey) {
      return res.status(403).json({
        success: false,
        error: 'غير مصرح',
        code: 403
      });
    }
    
    // جلب عدد المستخدمين
    const usersUrl = `${process.env.FIREBASE_URL}/users.json?shallow=true&auth=${process.env.FIREBASE_KEY}`;
    const usersResponse = await firebaseAxios.get(usersUrl);
    
    const totalUsers = usersResponse.data ? Object.keys(usersResponse.data).length : 0;
    
    res.json({
      success: true,
      stats: {
        total_users: totalUsers,
        server_uptime: Math.floor(process.uptime()),
        memory_usage: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB'
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ خطأ في /api/stats:', error.message);
    
    res.status(500).json({
      success: false,
      error: 'فشل في جلب الإحصائيات',
      code: 500
    });
  }
});

/**
 * 🏠 8. الصفحة الرئيسية
 * Endpoint: GET /
 */
app.get('/', (req, res) => {
  const uptimeHours = Math.floor(process.uptime() / 3600);
  const uptimeMinutes = Math.floor((process.uptime() % 3600) / 60);
  
  const html = `
  <!DOCTYPE html>
  <html lang="ar" dir="rtl">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firebase Proxy Server - V2.1.0</title>
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body {
        font-family: 'Segoe UI', system-ui, sans-serif;
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
        color: #fff;
        min-height: 100vh;
        padding: 20px;
      }
      .container { max-width: 1000px; margin: 0 auto; }
      header {
        text-align: center;
        padding: 40px 20px;
        background: rgba(255,255,255,0.05);
        border-radius: 20px;
        margin-bottom: 30px;
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255,255,255,0.1);
      }
      .logo { font-size: 60px; margin-bottom: 20px; }
      h1 {
        font-size: 32px;
        background: linear-gradient(90deg, #667eea, #764ba2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 10px;
      }
      .version { color: #a0aec0; margin-bottom: 20px; }
      .status {
        display: inline-block;
        background: linear-gradient(90deg, #10b981, #059669);
        padding: 10px 30px;
        border-radius: 50px;
        font-weight: bold;
        animation: pulse 2s infinite;
      }
      @keyframes pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
        50% { box-shadow: 0 0 0 15px rgba(16, 185, 129, 0); }
      }
      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 20px;
        margin-bottom: 30px;
      }
      .card {
        background: rgba(255,255,255,0.05);
        border-radius: 15px;
        padding: 25px;
        border: 1px solid rgba(255,255,255,0.1);
        transition: all 0.3s ease;
      }
      .card:hover {
        transform: translateY(-5px);
        border-color: #667eea;
        box-shadow: 0 10px 40px rgba(102, 126, 234, 0.2);
      }
      .card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 15px;
      }
      .method {
        padding: 5px 12px;
        border-radius: 5px;
        font-size: 12px;
        font-weight: bold;
      }
      .method.get { background: #10b981; }
      .method.post { background: #f59e0b; }
      .path {
        font-family: 'Courier New', monospace;
        color: #a78bfa;
        font-size: 14px;
        word-break: break-all;
      }
      .desc { color: #cbd5e1; line-height: 1.6; font-size: 14px; }
      .protected { color: #fbbf24; font-size: 12px; margin-top: 10px; }
      .info-box {
        background: rgba(255,255,255,0.05);
        border-radius: 15px;
        padding: 25px;
        border: 1px solid rgba(255,255,255,0.1);
      }
      .info-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 20px;
        margin-top: 20px;
      }
      .info-item { text-align: center; }
      .info-label { color: #9ca3af; font-size: 12px; margin-bottom: 5px; }
      .info-value { color: #a78bfa; font-size: 18px; font-weight: bold; }
      footer {
        text-align: center;
        margin-top: 40px;
        padding-top: 20px;
        border-top: 1px solid rgba(255,255,255,0.1);
        color: #9ca3af;
        font-size: 14px;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <header>
        <div class="logo">🛡️</div>
        <h1>Firebase Proxy Server</h1>
        <div class="version">الإصدار 2.1.0 - خادم وسيط آمن</div>
        <div class="status">✅ الخادم يعمل</div>
      </header>
      
      <h2 style="margin-bottom:20px; color:#a78bfa;">📡 نقاط الوصول</h2>
      <div class="grid">
        <div class="card">
          <div class="card-header">
            <span class="method post">POST</span>
          </div>
          <div class="path">/api/getUser</div>
          <div class="desc">جلب بيانات مستخدم من Firebase</div>
          <div class="protected">🔒 محمي بـ API Key</div>
        </div>
        
        <div class="card">
          <div class="card-header">
            <span class="method post">POST</span>
          </div>
          <div class="path">/api/verifyAccount</div>
          <div class="desc">التحقق الكامل من الحساب</div>
          <div class="protected">🔒 محمي بـ API Key</div>
        </div>
        
        <div class="card">
          <div class="card-header">
            <span class="method post">POST</span>
          </div>
          <div class="path">/api/updateDevice</div>
          <div class="desc">تحديث معرف الجهاز</div>
          <div class="protected">🔒 محمي بـ API Key</div>
        </div>
        
        <div class="card">
          <div class="card-header">
            <span class="method post">POST</span>
          </div>
          <div class="path">/api/resetDevice</div>
          <div class="desc">إعادة تعيين الجهاز (للمدير)</div>
          <div class="protected">🔒 محمي بـ Admin Key</div>
        </div>
        
        <div class="card">
          <div class="card-header">
            <span class="method get">GET</span>
          </div>
          <div class="path">/api/serverTime</div>
          <div class="desc">الحصول على وقت السيرفر</div>
          <div class="protected">🔓 عام</div>
        </div>
        
        <div class="card">
          <div class="card-header">
            <span class="method get">GET</span>
          </div>
          <div class="path">/api/health</div>
          <div class="desc">فحص صحة الخادم</div>
          <div class="protected">🔓 عام</div>
        </div>
      </div>
      
      <div class="info-box">
        <h2 style="color:#a78bfa; margin-bottom:10px;">📊 معلومات النظام</h2>
        <div class="info-grid">
          <div class="info-item">
            <div class="info-label">وقت التشغيل</div>
            <div class="info-value">${uptimeHours}س ${uptimeMinutes}د</div>
          </div>
          <div class="info-item">
            <div class="info-label">Node.js</div>
            <div class="info-value">${process.version}</div>
          </div>
          <div class="info-item">
            <div class="info-label">البيئة</div>
            <div class="info-value">${isProduction ? 'إنتاج' : 'تطوير'}</div>
          </div>
          <div class="info-item">
            <div class="info-label">Firebase</div>
            <div class="info-value">${process.env.FIREBASE_URL ? '✅' : '❌'}</div>
          </div>
        </div>
      </div>
      
      <footer>
        <p>خادم وسيط لحماية مفاتيح Firebase من التسريب</p>
        <p style="margin-top:10px;">⚠️ جميع الطلبات محمية ومراقبة</p>
      </footer>
    </div>
  </body>
  </html>
  `;
  
  res.send(html);
});

// ============================================
// التعامل مع الأخطاء العامة
// ============================================

// معالجة المسارات غير الموجودة
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'المسار غير موجود',
    code: 404,
    path: req.path,
    timestamp: new Date().toISOString()
  });
});

// معالجة الأخطاء العامة
app.use((err, req, res, next) => {
  console.error('❌ خطأ عام:', err.message);
  
  // خطأ CORS
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      success: false,
      error: 'الوصول غير مسموح من هذا المصدر',
      code: 403
    });
  }
  
  // خطأ JSON
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      success: false,
      error: 'صيغة JSON غير صالحة',
      code: 400
    });
  }
  
  res.status(500).json({
    success: false,
    error: 'حدث خطأ داخلي في الخادم',
    code: 500,
    timestamp: new Date().toISOString()
  });
});

// ============================================
// بدء الخادم
// ============================================
const server = app.listen(PORT, () => {
  console.log('\n' + '═'.repeat(50));
  console.log('🛡️  Firebase Proxy Server v2.1.0');
  console.log('═'.repeat(50));
  console.log(`📡 URL: http://localhost:${PORT}`);
  console.log(`🌍 Environment: ${isProduction ? 'Production' : 'Development'}`);
  console.log(`🔥 Firebase: ${process.env.FIREBASE_URL ? '✅ Configured' : '❌ Missing'}`);
  console.log(`🔑 API Key: ${process.env.APP_API_KEY ? '✅ Set' : '⚠️ Using default'}`);
  console.log(`👑 Admin Key: ${process.env.ADMIN_API_KEY ? '✅ Set' : '⚠️ Not set'}`);
  console.log(`⏰ Started: ${new Date().toLocaleString('ar-SA')}`);
  console.log('═'.repeat(50) + '\n');
});

// إعداد المهلة
server.timeout = 30000; // 30 ثانية

// ============================================
// معالجة إيقاف الخادم
// ============================================
const gracefulShutdown = (signal) => {
  console.log(`\n📴 استقبال إشارة ${signal}...`);
  
  server.close(() => {
    console.log('✅ تم إغلاق الاتصالات بنجاح');
    console.log('👋 وداعاً!');
    process.exit(0);
  });
  
  // إجبار الإغلاق بعد 10 ثواني
  setTimeout(() => {
    console.error('⚠️ إجبار الإغلاق...');
    process.exit(1);
  }, 10000);
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// معالجة الأخطاء غير المتوقعة
process.on('uncaughtException', (error) => {
  console.error('❌ خطأ غير متوقع:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Promise rejection:', reason);
});
