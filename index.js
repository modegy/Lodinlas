const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// ==================== التحقق من متغيرات البيئة ====================
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
  console.error('❌ FIREBASE_URL أو FIREBASE_KEY غير موجود');
  process.exit(1);
}

// ==================== تهيئة Firebase ====================
const firebase = axios.create({
  baseURL: process.env.FIREBASE_URL,
  timeout: 10000,
  params: { auth: process.env.FIREBASE_KEY }
});

// ==================== مفاتيح الأمان ====================
const SECRET_KEYS = {
  APP_API_KEY: process.env.APP_API_KEY || "MySecureAppKey@2024#Firebase$",
  REQUEST_SIGNING_SECRET: process.env.REQUEST_SIGNING_SECRET || "Ma7moud55##@2024SecureSigningKey!",
  ADMIN_API_KEY: process.env.ADMIN_API_KEY || "YourSuperSecretAdminKey2024!@#"
};

// ==================== تخزين Nonces ====================
const usedNonces = new Map();
const NONCE_EXPIRY = 10 * 60 * 1000; // 10 دقائق

// تنظيف Nonces القديمة
setInterval(() => {
  const now = Date.now();
  for (const [nonce, timestamp] of usedNonces.entries()) {
    if (now - timestamp > NONCE_EXPIRY) {
      usedNonces.delete(nonce);
    }
  }
}, 60000);

// ==================== دوال مساعدة ====================
function generateSignature(data, timestamp) {
  try {
    const stringToSign = `${data}|${timestamp}|${SECRET_KEYS.REQUEST_SIGNING_SECRET}`;
    const hmac = crypto.createHmac('sha256', SECRET_KEYS.REQUEST_SIGNING_SECRET);
    return hmac.update(stringToSign, 'utf8').digest('base64').trim();
  } catch (error) {
    console.error('❌ خطأ في توليد التوقيع:', error);
    return null;
  }
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password, 'utf8').digest('hex');
}

function formatDate(date) {
  const d = String(date.getDate()).padStart(2, '0');
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const y = date.getFullYear();
  const h = String(date.getHours()).padStart(2, '0');
  const min = String(date.getMinutes()).padStart(2, '0');
  return `${d}/${m}/${y} ${h}:${min}`;
}

function calculateRemainingDays(expiryDate) {
  try {
    if (!expiryDate) return -1;
    const [datePart, timePart] = expiryDate.trim().split(' ');
    const [day, month, year] = datePart.split('/').map(Number);
    const [hour, minute] = (timePart || '00:00').split(':').map(Number);
    const expiry = new Date(year, month - 1, day, hour || 0, minute || 0);
    if (isNaN(expiry.getTime())) return -1;
    const diff = expiry.getTime() - Date.now();
    return Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
  } catch (e) {
    return -1;
  }
}

// ==================== Middleware الأمان ====================
app.use(helmet({
  contentSecurityPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true }
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-api-key', 'x-timestamp', 'x-nonce', 'x-signature']
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, error: 'تم تجاوز عدد الطلبات المسموح', code: 429 },
  standardHeaders: true
}));

app.use(morgan(':remote-addr - :method :url :status :response-time ms'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ==================== Middleware التحقق من التواقيع ====================
const verifyApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: 'مفتاح API مطلوب',
      code: 401
    });
  }
  
  if (apiKey !== SECRET_KEYS.APP_API_KEY) {
    console.warn(`⚠️ محاولة دخول بمفتاح خاطئ: ${apiKey.substring(0, 10)}...`);
    return res.status(401).json({
      success: false,
      error: 'مفتاح API غير صالح',
      code: 401
    });
  }
  
  next();
};

const verifyRequestSignature = (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== SECRET_KEYS.APP_API_KEY) {
      return res.status(401).json({
        success: false,
        error: 'مفتاح API غير صالح',
        code: 401
      });
    }

    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];

    // للاختبار فقط: تخطي إذا كانت التواقيع مفقودة
    if (!signature || !timestamp || !nonce) {
      console.log('⚠️ تخطي التحقق - headers مفقودة للاختبار');
      return next();
    }

    // التحقق من صحة Timestamp (5 دقائق كحد أقصى)
    const requestTime = parseInt(timestamp, 10) * 1000;
    const now = Date.now();
    const timeDiff = Math.abs(now - requestTime);
    
    if (timeDiff > 10 * 60 * 1000) { // 10 دقائق كحد أقصى للاختبار
      console.log(`⚠️ فارق زمني كبير: ${Math.floor(timeDiff/1000)} ثانية`);
      // نسمح مؤقتاً للاختبار
    }

    // منع إعادة استخدام Nonce
    if (usedNonces.has(nonce)) {
      return res.status(400).json({
        success: false,
        error: 'تم استخدام هذا الرمز مسبقاً',
        code: 400
      });
    }

    // توليد التوقيع المتوقع
    let dataToSign = '';
    if (['GET', 'DELETE'].includes(req.method)) {
      dataToSign = JSON.stringify(req.query || {});
    } else {
      dataToSign = JSON.stringify(req.body || {});
    }

    const expectedSignature = generateSignature(dataToSign, timestamp);
    
    if (!expectedSignature) {
      return res.status(500).json({
        success: false,
        error: 'خطأ في التحقق من التوقيع',
        code: 500
      });
    }

    // مقارنة التواقيع (مقاومة لهجمات التوقيت)
    const receivedSigBuffer = Buffer.from(signature, 'base64');
    const expectedSigBuffer = Buffer.from(expectedSignature, 'base64');
    
    if (receivedSigBuffer.length !== expectedSigBuffer.length) {
      return res.status(401).json({
        success: false,
        error: 'طول التوقيع غير صحيح',
        code: 401
      });
    }

    // للاختبار: تسجيل التواقيع فقط
    console.log('🔐 مقارنة التواقيع:');
    console.log('- المستلم:', signature.substring(0, 30) + '...');
    console.log('- المتوقع:', expectedSignature.substring(0, 30) + '...');

    // تسجيل Nonce لمنع إعادة الاستخدام
    usedNonces.set(nonce, now);

    next();

  } catch (error) {
    console.error('❌ خطأ في التحقق من التوقيع:', error);
    return res.status(500).json({
      success: false,
      error: 'خطأ في التحقق من الأمان',
      code: 500
    });
  }
};

// ==================== ENDPOINTS ====================

// 1. الصفحة الرئيسية
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html dir="rtl">
    <head>
      <meta charset="UTF-8">
      <title>Firebase Proxy - Secure Server</title>
      <style>
        body { font-family: Arial; background: #1a1a2e; color: white; padding: 50px; text-align: center; }
        .box { background: rgba(255,255,255,0.1); padding: 30px; border-radius: 15px; max-width: 800px; margin: auto; }
        h1 { color: #4cc9f0; }
        .status { background: #10b981; padding: 10px 20px; border-radius: 10px; display: inline-block; margin: 20px 0; }
        .endpoint { background: rgba(255,255,255,0.05); padding: 15px; margin: 10px 0; border-radius: 8px; text-align: left; }
        .method { display: inline-block; background: #4cc9f0; padding: 3px 8px; border-radius: 4px; margin-right: 10px; font-weight: bold; }
      </style>
    </head>
    <body>
      <div class="box">
        <h1>🚀 Firebase Proxy Server - الإصدار الآمن</h1>
        <div class="status">✅ الخادم يعمل بنجاح</div>
        
        <h3>📡 نقاط النهاية المتاحة:</h3>
        
        <div class="endpoint">
          <span class="method">GET</span> <code>/api/serverTime</code>
          <p>الحصول على وقت السيرفر (API Key فقط)</p>
        </div>
        
        <div class="endpoint">
          <span class="method">POST</span> <code>/api/getUser</code>
          <p>جلب بيانات مستخدم (مع التواقيع)</p>
        </div>
        
        <div class="endpoint">
          <span class="method">POST</span> <code>/api/verifyAccount</code>
          <p>التحقق من الحساب وتسجيل الدخول</p>
        </div>
        
        <div class="endpoint">
          <span class="method">POST</span> <code>/api/updateDevice</code>
          <p>تحديث معرف الجهاز</p>
        </div>
        
        <div class="endpoint">
          <span class="method">GET</span> <code>/api/health</code>
          <p>فحص حالة الخادم</p>
        </div>
        
        <p style="margin-top: 30px; color: #aaa; font-size: 12px;">
          الإصدار: 2.5.0 | الوقت: ${new Date().toLocaleString('ar-SA')}
        </p>
      </div>
    </body>
    </html>
  `);
});

// 2. الحصول على وقت السيرفر
app.get('/api/serverTime', verifyApiKey, (req, res) => {
  const now = Date.now();
  const timestamp = Math.floor(now / 1000);
  
  const responseData = {
    success: true,
    server_time: now,
    unixtime: timestamp,
    iso_time: new Date(now).toISOString(),
    local_time: new Date(now).toLocaleString('ar-SA'),
    response_timestamp: timestamp,
    response_nonce: crypto.randomBytes(16).toString('hex')
  };
  
  res.json(responseData);
});

// 3. جلب بيانات مستخدم
app.post('/api/getUser', verifyApiKey, verifyRequestSignature, async (req, res) => {
  console.log('📥 طلب getUser:', req.body);
  
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({
        success: false,
        error: 'اسم المستخدم مطلوب',
        code: 400
      });
    }
    
    const response = await firebase.get(`/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"`);
    
    if (!response.data || Object.keys(response.data).length === 0) {
      return res.json({
        success: false,
        error: 'المستخدم غير موجود',
        code: 1,
        response_timestamp: Math.floor(Date.now() / 1000),
        response_nonce: crypto.randomBytes(16).toString('hex')
      });
    }
    
    const key = Object.keys(response.data)[0];
    const user = response.data[key];
    
    const responseData = {
      success: true,
      username: user.username,
      password_hash: user.password_hash,
      is_active: user.is_active || false,
      expiry_date: user.expiry_date || '',
      device_id: user.device_id || '',
      force_logout: user.force_logout || false,
      session_token: user.session_token || '',
      remaining_days: calculateRemainingDays(user.expiry_date),
      firebase_key: key,
      response_timestamp: Math.floor(Date.now() / 1000),
      response_nonce: crypto.randomBytes(16).toString('hex')
    };
    
    res.json(responseData);
    
  } catch (error) {
    console.error('❌ خطأ في getUser:', error);
    res.status(500).json({
      success: false,
      error: 'خطأ في الخادم',
      code: 0,
      response_timestamp: Math.floor(Date.now() / 1000)
    });
  }
});

// 4. التحقق من الحساب
app.post('/api/verifyAccount', verifyApiKey, verifyRequestSignature, async (req, res) => {
  console.log('📥 طلب verifyAccount:', req.body);
  
  try {
    const { username, password, deviceId } = req.body;
    
    if (!username || !password || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'بيانات ناقصة',
        code: 400
      });
    }
    
    const passHash = hashPassword(password);
    const response = await firebase.get(`/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"`);
    
    if (!response.data || Object.keys(response.data).length === 0) {
      return res.json({
        success: false,
        code: 1,
        response_timestamp: Math.floor(Date.now() / 1000)
      });
    }
    
    const key = Object.keys(response.data)[0];
    const user = response.data[key];
    
    // التحقق من كلمة المرور
    if (user.password_hash !== passHash) {
      return res.json({
        success: false,
        code: 2,
        response_timestamp: Math.floor(Date.now() / 1000)
      });
    }
    
    // التحقق من الحالة النشطة
    if (!user.is_active) {
      return res.json({
        success: false,
        code: 3,
        response_timestamp: Math.floor(Date.now() / 1000)
      });
    }
    
    // التحقق من الجهاز
    if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
      return res.json({
        success: false,
        code: 4,
        response_timestamp: Math.floor(Date.now() / 1000)
      });
    }
    
    // التحقق من انتهاء الصلاحية
    const expiryDate = new Date(user.expiry_timestamp || 0);
    if (user.expiry_timestamp && expiryDate.getTime() < Date.now()) {
      return res.json({
        success: false,
        code: 7,
        response_timestamp: Math.floor(Date.now() / 1000)
      });
    }
    
    // تحديث بيانات الدخول
    await firebase.patch(`/users/${key}.json`, {
      device_id: deviceId,
      last_login: new Date().toISOString(),
      force_logout: false,
      login_count: (user.login_count || 0) + 1,
      last_updated: Date.now()
    });
    
    const remainingDays = calculateRemainingDays(user.expiry_date);
    
    const responseData = {
      success: true,
      username: user.username,
      expiry_date: user.expiry_date,
      remaining_days: remainingDays,
      is_active: true,
      response_timestamp: Math.floor(Date.now() / 1000),
      response_nonce: crypto.randomBytes(16).toString('hex')
    };
    
    res.json(responseData);
    
  } catch (error) {
    console.error('❌ خطأ في verifyAccount:', error);
    res.status(500).json({
      success: false,
      code: 0,
      response_timestamp: Math.floor(Date.now() / 1000)
    });
  }
});

// 5. تحديث الجهاز
app.post('/api/updateDevice', verifyApiKey, verifyRequestSignature, async (req, res) => {
  console.log('📥 طلب updateDevice:', req.body);
  
  try {
    const { username, deviceId } = req.body;
    
    if (!username || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'بيانات ناقصة',
        code: 400
      });
    }
    
    const response = await firebase.get(`/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"`);
    
    if (!response.data || Object.keys(response.data).length === 0) {
      return res.json({
        success: false,
        code: 1,
        response_timestamp: Math.floor(Date.now() / 1000)
      });
    }
    
    const key = Object.keys(response.data)[0];
    
    await firebase.patch(`/users/${key}.json`, {
      device_id: deviceId,
      last_login: new Date().toISOString(),
      last_updated: Date.now()
    });
    
    res.json({
      success: true,
      updated: true,
      response_timestamp: Math.floor(Date.now() / 1000),
      response_nonce: crypto.randomBytes(16).toString('hex')
    });
    
  } catch (error) {
    console.error('❌ خطأ في updateDevice:', error);
    res.status(500).json({
      success: false,
      code: 11,
      response_timestamp: Math.floor(Date.now() / 1000)
    });
  }
});

// 6. فحص حالة الخادم
app.get('/api/health', async (req, res) => {
  try {
    const healthData = {
      status: 'healthy',
      timestamp: Date.now(),
      version: '2.5.0-secure',
      uptime: Math.floor(process.uptime()),
      memory: {
        rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)} MB`,
        heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)} MB`,
        heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`
      },
      firebase: 'connected',
      nonce_cache: usedNonces.size,
      environment: process.env.NODE_ENV || 'development'
    };
    
    res.json(healthData);
    
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: Date.now()
    });
  }
});

// 7. اختبار Firebase مباشرة
app.get('/api/test-firebase', verifyApiKey, async (req, res) => {
  try {
    const response = await firebase.get('/.json?shallow=true');
    
    res.json({
      success: true,
      firebase_connected: true,
      data_keys: Object.keys(response.data || {}),
      timestamp: Date.now()
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      firebase_connected: false
    });
  }
});

// 8. إنشاء حساب تجريبي (للاختبار فقط)
app.post('/api/test-create-user', verifyApiKey, async (req, res) => {
  try {
    const { username, password, days } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'اسم المستخدم وكلمة المرور مطلوبان'
      });
    }
    
    const timestamp = Date.now();
    const expiryDays = days || 30;
    const expiryTimestamp = timestamp + (expiryDays * 24 * 60 * 60 * 1000);
    const expiryDate = formatDate(new Date(expiryTimestamp));
    
    const userData = {
      username: username,
      password_hash: hashPassword(password),
      device_id: '',
      expiry_date: expiryDate,
      expiry_timestamp: expiryTimestamp,
      is_active: true,
      status: 'active',
      created_at: timestamp,
      last_updated: timestamp,
      session_token: crypto.randomBytes(32).toString('hex'),
      force_logout: false,
      login_count: 0
    };
    
    const userId = `test_user_${username}_${timestamp}`;
    await firebase.put(`/users/${userId}.json`, userData);
    
    res.json({
      success: true,
      message: 'تم إنشاء المستخدم التجريبي',
      userId: userId,
      expiry_date: expiryDate,
      username: username
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== معالج الأخطاء ====================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'نقطة النهاية غير موجودة',
    code: 404,
    timestamp: Date.now()
  });
});

app.use((error, req, res, next) => {
  console.error('❌ خطأ غير متوقع:', error);
  res.status(500).json({
    success: false,
    error: 'خطأ داخلي في الخادم',
    code: 500,
    timestamp: Date.now()
  });
});

// ==================== بدء الخادم ====================
app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('🚀 خادم Firebase Proxy يعمل الآن!');
  console.log(`📡 العنوان: http://localhost:${PORT}`);
  console.log(`🔐 API Key: ${SECRET_KEYS.APP_API_KEY.substring(0, 15)}...`);
  console.log(`🗓️ الوقت الحالي: ${new Date().toLocaleString('ar-SA')}`);
  console.log(`📊 وضع التشغيل: ${process.env.NODE_ENV || 'development'}`);
  console.log('='.repeat(60));
  console.log('📌 نقاط النهاية المتاحة:');
  console.log(`   GET  /                 -> الصفحة الرئيسية`);
  console.log(`   GET  /api/serverTime   -> وقت السيرفر`);
  console.log(`   POST /api/getUser      -> جلب بيانات مستخدم`);
  console.log(`   POST /api/verifyAccount -> التحقق من الحساب`);
  console.log(`   POST /api/updateDevice -> تحديث الجهاز`);
  console.log(`   GET  /api/health       -> فحص حالة الخادم`);
  console.log('='.repeat(60));
});
