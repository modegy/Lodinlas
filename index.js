/**
 * Firebase Proxy Server
 * خادم وسيط آمن لحماية مفاتيح Firebase
 * إصدار: 2.2.0 - متوافق مع تطبيق Android
 */

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

// تحقق من المتغيرات البيئية
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
  console.error('❌ خطأ: FIREBASE_URL أو FIREBASE_KEY غير موجود');
  process.exit(1);
}

// ============================================
// Middleware
// ============================================

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

// CORS - السماح لجميع المصادر
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-api-key', 'x-app-version', 'x-device-id', 'x-admin-key']
}));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, error: 'تم تجاوز الحد المسموح', code: 429 }
});
app.use('/api/', limiter);

app.use(express.json({ limit: '10mb' }));

// منع التخزين المؤقت
app.use('/api/', (req, res, next) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });
  next();
});

// ============================================
// التحقق من API Key
// ============================================
const authenticateRequest = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const expectedApiKey = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
  
  console.log(`📥 ${new Date().toISOString()} | ${req.method} ${req.path}`);
  
  if (!apiKey || apiKey !== expectedApiKey) {
    console.warn(`🚫 API Key غير صحيح`);
    return res.status(401).json({
      success: false,
      error: 'غير مصرح',
      code: 401
    });
  }
  
  next();
};

// ============================================
// وظائف مساعدة
// ============================================

function calculateRemainingDays(expiryDate) {
  try {
    if (!expiryDate || expiryDate.trim() === '') return -1;
    
    const [datePart, timePart] = expiryDate.trim().split(' ');
    const [day, month, year] = datePart.split('/').map(Number);
    const [hour, minute] = (timePart || '00:00').split(':').map(Number);
    
    const expiryTime = new Date(year, month - 1, day, hour || 0, minute || 0);
    if (isNaN(expiryTime.getTime())) return -1;
    
    const diffMs = expiryTime - Date.now();
    return Math.max(0, Math.ceil(diffMs / (1000 * 60 * 60 * 24)));
  } catch (error) {
    return -1;
  }
}

function calculatePasswordHash(password) {
  try {
    const hash = crypto.createHash('sha256');
    hash.update(password, 'utf8');
    return hash.digest('hex');
  } catch (error) {
    return null;
  }
}

// Axios for Firebase
const firebaseAxios = axios.create({
  timeout: 15000,
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
  }
});

// ============================================
// ENDPOINTS
// ============================================

/**
 * ⏰ وقت السيرفر - متوافق مع Android
 */
app.get('/api/serverTime', (req, res) => {
  const serverTime = Date.now();
  
  res.json({
    success: true,
    server_time: serverTime,
    unixtime: Math.floor(serverTime / 1000),
    server_time_formatted: new Date(serverTime).toISOString(),
    timezone: 'Asia/Riyadh',
    timestamp: new Date().toISOString()
  });
});

/**
 * 🔍 جلب بيانات المستخدم - متوافق مع Android
 */
app.post('/api/getUser', authenticateRequest, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username || username.trim() === '') {
      return res.status(400).json({
        success: false,
        error: 'اسم المستخدم مطلوب',
        code: 400
      });
    }
    
    console.log(`🔍 جلب بيانات: ${username}`);
    
    const encodedUsername = encodeURIComponent(username.trim());
    const firebaseUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodedUsername}"&auth=${process.env.FIREBASE_KEY}`;
    
    const response = await firebaseAxios.get(firebaseUrl);
    
    // إذا لم يوجد المستخدم - إرجاع {} للتوافق مع التطبيق
    if (!response.data || Object.keys(response.data).length === 0) {
      console.log(`⚠️ المستخدم غير موجود: ${username}`);
      return res.json({});
    }
    
    const userKey = Object.keys(response.data)[0];
    const userData = response.data[userKey];
    
    // إرجاع البيانات بالصيغة التي يتوقعها التطبيق
    const result = {
      username: userData.username,
      password_hash: userData.password_hash,
      is_active: userData.is_active || false,
      expiry_date: userData.expiry_date || '',
      device_id: userData.device_id || '',
      remaining_days: calculateRemainingDays(userData.expiry_date || ''),
      created_at: userData.created_at || '',
      firebase_key: userKey
    };
    
    console.log(`✅ تم جلب: ${username} (${result.remaining_days} يوم متبقي)`);
    
    res.json(result);
    
  } catch (error) {
    console.error('❌ خطأ في /api/getUser:', error.message);
    res.status(500).json({
      success: false,
      error: 'خطأ في الاتصال',
      code: 0
    });
  }
});

/**
 * 📱 تحديث معرف الجهاز
 */
app.post('/api/updateDevice', authenticateRequest, async (req, res) => {
  try {
    const { username, deviceId } = req.body;
    
    if (!username || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'بيانات ناقصة',
        code: 400
      });
    }
    
    console.log(`📱 تحديث جهاز: ${username}`);
    
    // البحث عن المستخدم
    const searchUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const searchResponse = await firebaseAxios.get(searchUrl);
    
    if (!searchResponse.data || Object.keys(searchResponse.data).length === 0) {
      return res.json({ success: false, error: 'المستخدم غير موجود', code: 1 });
    }
    
    const userKey = Object.keys(searchResponse.data)[0];
    
    // تحديث الجهاز
    const updateUrl = `${process.env.FIREBASE_URL}/users/${userKey}.json?auth=${process.env.FIREBASE_KEY}`;
    await firebaseAxios.patch(updateUrl, {
      device_id: deviceId,
      last_login: new Date().toISOString()
    });
    
    console.log(`✅ تم تحديث الجهاز: ${username}`);
    
    res.json({ success: true, message: 'تم التحديث بنجاح' });
    
  } catch (error) {
    console.error('❌ خطأ في /api/updateDevice:', error.message);
    res.status(500).json({ success: false, error: 'فشل التحديث', code: 11 });
  }
});

/**
 * ✅ التحقق الكامل من الحساب
 */
app.post('/api/verifyAccount', authenticateRequest, async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    
    if (!username || !password || !deviceId) {
      return res.status(400).json({
        success: false,
        error: 'بيانات ناقصة',
        code: 400
      });
    }
    
    console.log(`🔐 التحقق من: ${username}`);
    
    const passwordHash = calculatePasswordHash(password);
    if (!passwordHash) {
      return res.json({ success: false, error: 'خطأ في التشفير', code: 15 });
    }
    
    // جلب بيانات المستخدم
    const userUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const userResponse = await firebaseAxios.get(userUrl);
    
    if (!userResponse.data || Object.keys(userResponse.data).length === 0) {
      return res.json({ success: false, error: 'المستخدم غير موجود', code: 1 });
    }
    
    const userKey = Object.keys(userResponse.data)[0];
    const user = userResponse.data[userKey];
    
    // التحقق من كلمة المرور
    if (user.password_hash !== passwordHash) {
      return res.json({ success: false, error: 'كلمة المرور خاطئة', code: 2 });
    }
    
    // التحقق من حالة الحساب
    if (!user.is_active) {
      return res.json({ success: false, error: 'الحساب غير نشط', code: 3 });
    }
    
    // التحقق من الجهاز
    if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
      return res.json({ success: false, error: 'الحساب مربوط بجهاز آخر', code: 4 });
    }
    
    // التحقق من الصلاحية
    if (!user.expiry_date) {
      return res.json({ success: false, error: 'لا يوجد تاريخ انتهاء', code: 5 });
    }
    
    const remainingDays = calculateRemainingDays(user.expiry_date);
    if (remainingDays <= 0) {
      return res.json({ success: false, error: 'انتهت الصلاحية', code: 7 });
    }
    
    // تحديث الجهاز
    const updateUrl = `${process.env.FIREBASE_URL}/users/${userKey}.json?auth=${process.env.FIREBASE_KEY}`;
    await firebaseAxios.patch(updateUrl, {
      device_id: deviceId,
      last_login: new Date().toISOString(),
      login_count: (user.login_count || 0) + 1
    });
    
    console.log(`✅ تحقق ناجح: ${username} | متبقي: ${remainingDays} يوم`);
    
    res.json({
      success: true,
      username: user.username,
      expiry_date: user.expiry_date,
      remaining_days: remainingDays,
      is_active: user.is_active,
      device_id: deviceId
    });
    
  } catch (error) {
    console.error('❌ خطأ في /api/verifyAccount:', error.message);
    res.status(500).json({ success: false, error: 'خطأ في الاتصال', code: 0 });
  }
});

/**
 * 🔄 إعادة تعيين الجهاز (للمدير)
 */
app.post('/api/resetDevice', authenticateRequest, async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    const { username } = req.body;
    
    const expectedAdminKey = process.env.ADMIN_API_KEY;
    if (!expectedAdminKey || adminKey !== expectedAdminKey) {
      return res.status(403).json({ success: false, error: 'غير مصرح', code: 403 });
    }
    
    if (!username) {
      return res.status(400).json({ success: false, error: 'اسم المستخدم مطلوب', code: 400 });
    }
    
    console.log(`🔄 إعادة تعيين جهاز: ${username}`);
    
    const searchUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const searchResponse = await firebaseAxios.get(searchUrl);
    
    if (!searchResponse.data || Object.keys(searchResponse.data).length === 0) {
      return res.json({ success: false, error: 'المستخدم غير موجود', code: 1 });
    }
    
    const userKey = Object.keys(searchResponse.data)[0];
    const updateUrl = `${process.env.FIREBASE_URL}/users/${userKey}.json?auth=${process.env.FIREBASE_KEY}`;
    
    await firebaseAxios.patch(updateUrl, {
      device_id: '',
      device_reset_at: new Date().toISOString()
    });
    
    console.log(`✅ تم إعادة تعيين: ${username}`);
    res.json({ success: true, message: 'تم إعادة تعيين الجهاز' });
    
  } catch (error) {
    console.error('❌ خطأ:', error.message);
    res.status(500).json({ success: false, error: 'فشل العملية', code: 500 });
  }
});

/**
 * 🩺 فحص صحة الخادم
 */
app.get('/api/health', async (req, res) => {
  let firebaseStatus = 'unknown';
  
  try {
    const testUrl = `${process.env.FIREBASE_URL}/.json?shallow=true&auth=${process.env.FIREBASE_KEY}`;
    await firebaseAxios.get(testUrl, { timeout: 5000 });
    firebaseStatus = 'connected';
  } catch (error) {
    firebaseStatus = 'disconnected';
  }
  
  res.json({
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
      rate_limit: 200
    },
    environment: process.env.NODE_ENV || 'development',
    version: '2.2.0',
    endpoints: [
      'GET  /api/serverTime',
      'GET  /api/health',
      'POST /api/getUser',
      'POST /api/updateDevice',
      'POST /api/verifyAccount',
      'POST /api/resetDevice'
    ]
  });
});

/**
 * 🏠 الصفحة الرئيسية
 */
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Firebase Proxy Server v2.2.0</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
      color: #fff;
      min-height: 100vh;
      padding: 20px;
    }
    .container { max-width: 800px; margin: 0 auto; }
    header {
      text-align: center;
      padding: 40px 20px;
      background: rgba(255,255,255,0.05);
      border-radius: 20px;
      margin-bottom: 30px;
      backdrop-filter: blur(10px);
    }
    h1 { font-size: 2.5em; color: #4cc9f0; margin-bottom: 10px; }
    .version { color: #a0aec0; margin-bottom: 20px; }
    .status {
      display: inline-block;
      background: linear-gradient(90deg, #10b981, #059669);
      padding: 12px 30px;
      border-radius: 50px;
      font-weight: bold;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
      50% { box-shadow: 0 0 0 15px rgba(16, 185, 129, 0); }
    }
    .endpoints {
      background: rgba(255,255,255,0.05);
      border-radius: 15px;
      padding: 25px;
      margin-bottom: 20px;
    }
    .endpoints h2 { color: #4cc9f0; margin-bottom: 20px; }
    .endpoint {
      display: flex;
      align-items: center;
      padding: 12px 15px;
      background: rgba(255,255,255,0.03);
      border-radius: 8px;
      margin-bottom: 10px;
      font-family: monospace;
    }
    .method {
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: bold;
      margin-left: 15px;
      min-width: 50px;
      text-align: center;
    }
    .get { background: #10b981; }
    .post { background: #f59e0b; }
    .path { color: #a78bfa; }
    .desc { color: #9ca3af; font-size: 12px; margin-top: 5px; font-family: system-ui; }
    footer {
      text-align: center;
      padding: 20px;
      color: #9ca3af;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ Firebase Proxy Server</h1>
      <div class="version">الإصدار 2.2.0 - متوافق مع Android</div>
      <div class="status">✅ الخادم يعمل بنجاح</div>
    </header>
    
    <div class="endpoints">
      <h2>📡 نقاط الوصول المتاحة</h2>
      
      <div class="endpoint">
        <span class="method get">GET</span>
        <div>
          <span class="path">/api/serverTime</span>
          <div class="desc">الحصول على وقت السيرفر (unixtime)</div>
        </div>
      </div>
      
      <div class="endpoint">
        <span class="method get">GET</span>
        <div>
          <span class="path">/api/health</span>
          <div class="desc">فحص صحة الخادم واتصال Firebase</div>
        </div>
      </div>
      
      <div class="endpoint">
        <span class="method post">POST</span>
        <div>
          <span class="path">/api/getUser</span>
          <div class="desc">جلب بيانات المستخدم {username}</div>
        </div>
      </div>
      
      <div class="endpoint">
        <span class="method post">POST</span>
        <div>
          <span class="path">/api/updateDevice</span>
          <div class="desc">تحديث معرف الجهاز {username, deviceId}</div>
        </div>
      </div>
      
      <div class="endpoint">
        <span class="method post">POST</span>
        <div>
          <span class="path">/api/verifyAccount</span>
          <div class="desc">التحقق الكامل {username, password, deviceId}</div>
        </div>
      </div>
      
      <div class="endpoint">
        <span class="method post">POST</span>
        <div>
          <span class="path">/api/resetDevice</span>
          <div class="desc">إعادة تعيين الجهاز (للمدير)</div>
        </div>
      </div>
    </div>
    
    <footer>
      <p>⚠️ جميع الطلبات محمية بـ API Key</p>
      <p>🔥 Firebase: متصل | ⏰ ${new Date().toLocaleString('ar-SA')}</p>
    </footer>
  </div>
</body>
</html>
  `);
});

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

// معالجة الأخطاء
app.use((err, req, res, next) => {
  console.error('❌ خطأ:', err.message);
  res.status(500).json({ success: false, error: 'خطأ داخلي', code: 500 });
});

// بدء الخادم
app.listen(PORT, () => {
  console.log('\n' + '═'.repeat(50));
  console.log('🛡️  Firebase Proxy Server v2.2.0');
  console.log('═'.repeat(50));
  console.log(`📡 http://localhost:${PORT}`);
  console.log(`🔥 Firebase: ✅ Configured`);
  console.log(`🔑 API Key: ${process.env.APP_API_KEY ? '✅' : '⚠️ Using default'}`);
  console.log('═'.repeat(50));
  console.log('📋 Endpoints:');
  console.log('   GET  /api/serverTime');
  console.log('   GET  /api/health');
  console.log('   POST /api/getUser');
  console.log('   POST /api/updateDevice');
  console.log('   POST /api/verifyAccount');
  console.log('   POST /api/resetDevice');
  console.log('═'.repeat(50) + '\n');
});

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
