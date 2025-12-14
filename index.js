/**
 * Firebase Proxy Server
 * خادم وسيط آمن لحماية مفاتيح Firebase
 * إصدار: 2.0.0
 */

// ============================================
// استيراد المكتبات
// ============================================
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// ============================================
// إعدادات التطبيق
// ============================================
const app = express();
const PORT = process.env.PORT || 10000;

// تحقق من وجود المتغيرات البيئية الأساسية
const requiredEnvVars = ['FIREBASE_URL', 'FIREBASE_KEY'];
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    console.error(`❌ خطأ: المتغير البيئي ${varName} غير موجود`);
    console.log('⚙️  رجاءً أضفه في Render Dashboard → Environment');
    process.exit(1);
  }
});

// ============================================
// Middleware
// ============================================

// 1. حماية Headers
app.use(helmet({
  contentSecurityPolicy: false, // تعطيل CSP للتوافق
  hidePoweredBy: true, // إخفاء معلومات التطبيق
}));

// 2. CORS - السماح بتطبيقات محددة فقط
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : ['https://play.google.com'];

app.use(cors({
  origin: (origin, callback) => {
    // السماح بطلبات بدون origin (مثل mobile apps)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin) || origin.includes('localhost')) {
      callback(null, true);
    } else {
      console.warn(`⚠️  محاولة وصول من مصدر غير مسموح: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-api-key', 'x-app-version', 'x-device-id']
}));

// 3. Rate Limiting لمنع الهجمات
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: process.env.RATE_LIMIT_MAX || 100, // 100 طلب لكل IP
  message: {
    success: false,
    error: 'تم تجاوز الحد المسموح للطلبات. حاول مرة أخرى لاحقاً.',
    code: 429
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// 4. تحليل JSON
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ============================================
// Middleware للتحقق من الطلبات
// ============================================
const authenticateRequest = (req, res, next) => {
  try {
    // الحصول على API Key من الهيدر
    const apiKey = req.headers['x-api-key'];
    const appVersion = req.headers['x-app-version'] || '1.0.0';
    const deviceId = req.headers['x-device-id'];
    
    // تسجيل الطلب
    console.log(`📥 ${new Date().toISOString()} | ${req.method} ${req.path} | App: ${appVersion} | Device: ${deviceId?.substring(0, 8) || 'Unknown'}`);
    
    // التحقق من API Key
    const expectedApiKey = process.env.APP_API_KEY || 'default-key';
    if (apiKey !== expectedApiKey) {
      console.warn(`🚫 محاولة وصول برمز API غير صحيح: ${apiKey?.substring(0, 10)}...`);
      return res.status(401).json({
        success: false,
        error: 'غير مصرح',
        code: 401,
        message: 'رمز API غير صحيح'
      });
    }
    
    // التحقق من نسخة التطبيق (يمكن إضافة شروط إضافية)
    if (appVersion && appVersion < '1.0.0') {
      return res.status(426).json({
        success: false,
        error: 'يرجى تحديث التطبيق',
        code: 426,
        updateUrl: 'https://play.google.com/store/apps/details?id=com.google.impl'
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
// وظائف مساعدة
// ============================================

/**
 * حساب الأيام المتبقية حتى انتهاء الصلاحية
 */
function calculateRemainingDays(expiryDate) {
  try {
    if (!expiryDate || expiryDate.trim() === '') {
      return -1;
    }
    
    // تنسيق التاريخ: dd/MM/yyyy HH:mm
    const [datePart, timePart] = expiryDate.split(' ');
    const [day, month, year] = datePart.split('/').map(Number);
    const [hour, minute] = (timePart || '00:00').split(':').map(Number);
    
    const expiryTime = new Date(year, month - 1, day, hour, minute);
    const now = new Date();
    
    // إضافة وقت الخادم إذا لم يتم ضبطه
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
 * تجزئة كلمة المرور (SHA-256)
 */
async function calculatePasswordHash(password) {
  try {
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256');
    hash.update(password, 'utf8');
    return hash.digest('hex');
  } catch (error) {
    console.error('❌ خطأ في تجزئة كلمة المرور:', error);
    return null;
  }
}

/**
 * استخراج بيانات من Firebase Response
 */
function extractUserData(firebaseResponse) {
  try {
    if (!firebaseResponse || typeof firebaseResponse !== 'object') {
      return null;
    }
    
    const userKey = Object.keys(firebaseResponse)[0];
    if (!userKey) return null;
    
    const userData = firebaseResponse[userKey];
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

// ============================================
// Endpoints
// ============================================

/**
 * 🔍 1. جلب بيانات المستخدم من Firebase
 * Endpoint: POST /api/getUser
 */
app.post('/api/getUser', authenticateRequest, async (req, res) => {
  try {
    const { username } = req.body;
    
    // التحقق من البيانات
    if (!username || typeof username !== 'string' || username.trim() === '') {
      return res.status(400).json({
        success: false,
        error: 'اسم المستخدم مطلوب',
        code: 400
      });
    }
    
    console.log(`🔍 جلب بيانات المستخدم: ${username}`);
    
    // بناء رابط Firebase مع المفتاح المخفي
    const encodedUsername = encodeURIComponent(username.trim());
    const firebaseUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodedUsername}"&auth=${process.env.FIREBASE_KEY}`;
    
    // إرسال الطلب إلى Firebase
    const response = await axios({
      method: 'GET',
      url: firebaseUrl,
      timeout: 10000, // 10 ثواني
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Firebase-Proxy-Server/2.0.0'
      }
    });
    
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
      created_at: userData.created_at || '',
      last_login: new Date().toISOString()
    };
    
    console.log(`✅ تم جلب بيانات المستخدم: ${username} (${safeUserData.remaining_days} يوم متبقي)`);
    
    res.json({
      success: true,
      data: safeUserData,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ خطأ في /api/getUser:', error.message);
    
    let errorCode = 0;
    let errorMessage = 'خطأ في الاتصال بالخادم';
    
    if (error.code === 'ECONNABORTED') {
      errorCode = 13;
      errorMessage = 'انتهت مهلة الاتصال';
    } else if (error.response) {
      errorCode = error.response.status;
      errorMessage = 'خطأ في استجابة Firebase';
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
    const { username, deviceId } = req.body;
    
    // التحقق من البيانات
    if (!username || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'بيانات ناقصة',
        code: 400,
        required: ['username', 'deviceId']
      });
    }
    
    console.log(`📱 تحديث الجهاز للمستخدم: ${username}`);
    
    // 1. البحث عن المستخدم للحصول على المفتاح
    const searchUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const searchResponse = await axios.get(searchUrl, { timeout: 10000 });
    
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
    
    await axios.patch(updateUrl, updateData, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });
    
    console.log(`✅ تم تحديث الجهاز: ${deviceId.substring(0, 10)}...`);
    
    res.json({
      success: true,
      message: 'تم تحديث معرف الجهاز بنجاح',
      deviceId: deviceId.substring(0, 8) + '...',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ خطأ في /api/updateDevice:', error.message);
    
    res.status(500).json({
      success: false,
      error: 'فشل في تحديث البيانات',
      code: 11,
      details: error.message
    });
  }
});

/**
 * ✅ 3. التحقق الكامل من الحساب
 * Endpoint: POST /api/verifyAccount
 */
app.post('/api/verifyAccount', authenticateRequest, async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    
    // التحقق من البيانات
    if (!username || !password || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'بيانات الاعتماد ناقصة',
        code: 400,
        required: ['username', 'password', 'deviceId']
      });
    }
    
    console.log(`🔐 التحقق من الحساب: ${username}`);
    
    // 1. حساب تجزئة كلمة المرور
    const passwordHash = await calculatePasswordHash(password);
    if (!passwordHash) {
      return res.json({
        success: false,
        error: 'خطأ في تشفير كلمة المرور',
        code: 15
      });
    }
    
    // 2. جلب بيانات المستخدم من Firebase
    const userUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const userResponse = await axios.get(userUrl, { timeout: 10000 });
    
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
    if (user.device_id && user.device_id !== deviceId) {
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
    await axios.patch(updateUrl, {
      device_id: deviceId,
      last_login: new Date().toISOString(),
      login_count: (user.login_count || 0) + 1
    });
    
    console.log(`✅ تحقق ناجح: ${username} | متبقي: ${remainingDays} يوم | الجهاز: ${deviceId.substring(0, 8)}...`);
    
    // 8. إرجاع النتيجة الناجحة
    res.json({
      success: true,
      data: {
        username: user.username,
        expiry_date: user.expiry_date,
        remaining_days: remainingDays,
        is_active: user.is_active,
        device_id: deviceId,
        last_login: new Date().toISOString()
      },
      message: 'تم التحقق بنجاح',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ خطأ في /api/verifyAccount:', error.message);
    
    let errorCode = 0;
    let errorMessage = 'حدث خطأ غير متوقع';
    
    if (error.code === 'ECONNABORTED') {
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
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * ⏰ 4. الحصول على وقت السيرفر
 * Endpoint: GET /api/serverTime
 */
app.get('/api/serverTime', async (req, res) => {
  try {
    const worldTimeResponse = await axios.get('http://worldtimeapi.org/api/timezone/Asia/Riyadh', {
      timeout: 5000
    });
    
    const serverTime = worldTimeResponse.data.unixtime * 1000;
    
    res.json({
      success: true,
      server_time: serverTime,
      server_time_formatted: new Date(serverTime).toISOString(),
      timezone: worldTimeResponse.data.timezone,
      client_time: Date.now(),
      difference: Math.abs(serverTime - Date.now()),
      source: 'worldtimeapi.org'
    });
    
  } catch (error) {
    // استخدام وقت الخادم كبديل
    const fallbackTime = Date.now();
    
    res.json({
      success: true,
      server_time: fallbackTime,
      server_time_formatted: new Date(fallbackTime).toISOString(),
      timezone: 'UTC',
      client_time: fallbackTime,
      difference: 0,
      source: 'server-local',
      note: 'استخدام وقت الخادم المحلي'
    });
  }
});

/**
 * 🩺 5. فحص صحة الخادم
 * Endpoint: GET /api/health
 */
app.get('/api/health', (req, res) => {
  const health = {
    status: '✅ نشط',
    timestamp: new Date().toISOString(),
    server: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      node_version: process.version,
      platform: process.platform
    },
    firebase: {
      connected: !!process.env.FIREBASE_URL,
      url_configured: !!process.env.FIREBASE_URL,
      key_configured: !!process.env.FIREBASE_KEY
    },
    environment: process.env.NODE_ENV || 'development',
    endpoints: [
      { path: '/api/getUser', method: 'POST', protected: true },
      { path: '/api/updateDevice', method: 'POST', protected: true },
      { path: '/api/verifyAccount', method: 'POST', protected: true },
      { path: '/api/serverTime', method: 'GET', protected: false },
      { path: '/api/health', method: 'GET', protected: false }
    ]
  };
  
  res.json(health);
});

/**
 * 🏠 6. الصفحة الرئيسية
 * Endpoint: GET /
 */
app.get('/', (req, res) => {
  const html = `
  <!DOCTYPE html>
  <html lang="ar" dir="rtl">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firebase Proxy Server - V2</title>
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
        font-family: 'Segoe UI', system-ui, sans-serif;
      }
      
      body {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        color: #fff;
        min-height: 100vh;
        padding: 20px;
      }
      
      .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 40px 20px;
      }
      
      header {
        text-align: center;
        margin-bottom: 60px;
        padding: 30px;
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border-radius: 20px;
        border: 1px solid rgba(255, 255, 255, 0.1);
      }
      
      .logo {
        font-size: 48px;
        margin-bottom: 20px;
        color: #4cc9f0;
      }
      
      h1 {
        font-size: 36px;
        margin-bottom: 10px;
        background: linear-gradient(90deg, #4cc9f0, #4361ee);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }
      
      .tagline {
        font-size: 18px;
        color: #a5b4fc;
        margin-bottom: 30px;
      }
      
      .status-badge {
        display: inline-block;
        background: #10b981;
        color: white;
        padding: 8px 20px;
        border-radius: 50px;
        font-weight: bold;
        margin-bottom: 20px;
      }
      
      .endpoints {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 25px;
        margin-bottom: 50px;
      }
      
      .endpoint-card {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 15px;
        padding: 25px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        transition: all 0.3s ease;
      }
      
      .endpoint-card:hover {
        transform: translateY(-5px);
        border-color: #4cc9f0;
        box-shadow: 0 10px 30px rgba(76, 201, 240, 0.2);
      }
      
      .endpoint-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 15px;
      }
      
      .method {
        padding: 6px 15px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 14px;
      }
      
      .method.get { background: #10b981; }
      .method.post { background: #f59e0b; }
      .method.put { background: #3b82f6; }
      .method.patch { background: #8b5cf6; }
      .method.delete { background: #ef4444; }
      
      .path {
        font-family: 'Courier New', monospace;
        font-size: 16px;
        color: #a5b4fc;
        word-break: break-all;
      }
      
      .description {
        color: #cbd5e1;
        line-height: 1.6;
        margin-bottom: 15px;
      }
      
      .protected {
        color: #f59e0b;
        font-size: 14px;
        display: flex;
        align-items: center;
        gap: 5px;
      }
      
      .info-section {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 15px;
        padding: 30px;
        margin-top: 40px;
        border: 1px solid rgba(255, 255, 255, 0.1);
      }
      
      .info-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
        margin-top: 20px;
      }
      
      .info-item {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      
      .info-label {
        color: #94a3b8;
        font-size: 14px;
      }
      
      .info-value {
        font-size: 18px;
        font-weight: bold;
        color: #4cc9f0;
      }
      
      footer {
        text-align: center;
        margin-top: 60px;
        padding-top: 30px;
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        color: #94a3b8;
        font-size: 14px;
      }
      
      .version {
        color: #a5b4fc;
        font-weight: bold;
      }
      
      @media (max-width: 768px) {
        .container {
          padding: 20px 10px;
        }
        
        h1 {
          font-size: 28px;
        }
        
        .endpoints {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <div class="container">
      <header>
        <div class="logo">🚀</div>
        <h1>Firebase Proxy Server</h1>
        <div class="tagline">خادم وسيط آمن لحماية مفاتيح Firebase - الإصدار 2.0.0</div>
        <div class="status-badge">✅ الخادم يعمل بشكل طبيعي</div>
        <p>تم النشر بنجاح على Render.com | ${new Date().toLocaleDateString('ar-SA')}</p>
      </header>
      
      <section>
        <h2 style="margin-bottom: 25px; color: #a5b4fc;">🔗 نقاط الوصول (Endpoints)</h2>
        <div class="endpoints">
          
          <div class="endpoint-card">
            <div class="endpoint-header">
              <span class="method post">POST</span>
              <span class="protected">🔒 محمي بـ API Key</span>
            </div>
            <div class="path">/api/getUser</div>
            <div class="description">
              جلب بيانات مستخدم من Firebase بناءً على اسم المستخدم.
            </div>
            <div class="info-label">المعاملات المطلوبة:</div>
            <div class="path">{"username": "اسم_المستخدم"}</div>
          </div>
          
          <div class="endpoint-card">
            <div class="endpoint-header">
              <span class="method post">POST</span>
              <span class="protected">🔒 محمي بـ API Key</span>
            </div>
            <div class="path">/api/updateDevice</div>
            <div class="description">
              تحديث معرف الجهاز لمستخدم معين في قاعدة البيانات.
            </div>
            <div class="info-label">المعاملات المطلوبة:</div>
            <div class="path">{"username": "xxx", "deviceId": "xxx"}</div>
          </div>
          
          <div class="endpoint-card">
            <div class="endpoint-header">
              <span class="method post">POST</span>
              <span class="protected">🔒 محمي بـ API Key</span>
            </div>
            <div class="path">/api/verifyAccount</div>
            <div class="description">
              التحقق الكامل من الحساب (اسم المستخدم، كلمة المرور، الجهاز، الصلاحية).
            </div>
            <div class="info-label">المعاملات المطلوبة:</div>
            <div class="path">{"username": "xxx", "password": "xxx", "deviceId": "xxx"}</div>
          </div>
          
          <div class="endpoint-card">
            <div class="endpoint-header">
              <span class="method get">GET</span>
              <span class="protected">🔓 عام</span>
            </div>
            <div class="path">/api/serverTime</div>
            <div class="description">
              الحصول على وقت السيرفر الدقيق لمزامنة الوقت بين التطبيق والخادم.
            </div>
          </div>
          
          <div class="endpoint-card">
            <div class="endpoint-header">
              <span class="method get">GET</span>
              <span class="protected">🔓 عام</span>
            </div>
            <div class="path">/api/health</div>
            <div class="description">
              فحص صحة الخادم والتحقق من اتصال Firebase.
            </div>
          </div>
          
        </div>
      </section>
      
      <section class="info-section">
        <h2 style="margin-bottom: 25px; color: #a5b4fc;">📊 معلومات النظام</h2>
        <div class="info-grid">
          <div class="info-item">
            <span class="info-label">الحالة:</span>
            <span class="info-value">✅ نشط</span>
          </div>
          <div class="info-item">
            <span class="info-label">وقت التشغيل:</span>
            <span class="info-value">${Math.floor(process.uptime() / 3600)} ساعة</span>
          </div>
          <div class="info-item">
            <span class="info-label">بيئة التشغيل:</span>
            <span class="info-value">${process.env.NODE_ENV || 'development'}</span>
          </div>
          <div class="info-item">
            <span class="info-label">إصدار Node.js:</span>
            <span class="info-value">${process.version}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Firebase:</span>
            <span class="info-value">${process.env.FIREBASE_URL ? '✅ متصل' : '❌ غير متصل'}</span>
          </div>
          <div class="info-item">
            <span class="info-label">الوقت الحالي:</span>
            <span class="info-value">${new Date().toLocaleString('ar-SA')}</span>
          </div>
        </div>
      </section>
      
      <footer>
        <p>تم تطويره لحماية تطبيقات Android من سرقة مفاتيح Firebase</p>
        <p class="version">الإصدار 2.0.0 | آخر تحديث: ${new Date().toLocaleDateString('ar-SA')}</p>
        <p style="margin-top: 15px; color: #64748b;">
          ⚠️ هذا الخادم محمي بـ API Key ولا يقبل الطلبات غير المصادق عليها
        </p>
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
    path: req.path,
    availableEndpoints: [
      '/api/getUser',
      '/api/updateDevice',
      '/api/verifyAccount',
      '/api/serverTime',
      '/api/health'
    ]
  });
});

// معالجة الأخطاء العامة
app.use((err, req, res, next) => {
  console.error('❌ خطأ عام:', err);
  
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
app.listen(PORT, () => {
  console.log(`\n🚀 ===========================================`);
  console.log(`   Firebase Proxy Server - V2.0.0`);
  console.log(`   🔗 http://localhost:${PORT}`);
  console.log(`   ⏰ ${new Date().toLocaleString('ar-SA')}`);
  console.log(`   📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   🔑 Firebase: ${process.env.FIREBASE_URL ? '✅' : '❌'}`);
  console.log(`   🛡️  API Protection: ${process.env.APP_API_KEY ? '✅' : '⚠️'}`);
  console.log(`=============================================\n`);
});

// ============================================
// معالجة إيقاف الخادم
// ============================================
process.on('SIGINT', () => {
  console.log('\n👋 إيقاف الخادم بشكل آمن...');
  console.log('✅ تم إيقاف الخادم بنجاح');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🔚 استقبال إشارة الإيقاف...');
  console.log('✅ تم إيقاف الخادم بنجاح');
  process.exit(0);
});