const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// ==================== التحقق من متغيرات البيئة ====================
console.log('🔧 تهيئة السيرفر...');
console.log('📡 FIREBASE_URL:', process.env.FIREBASE_URL ? '✓ موجود' : '✗ مفقود');
console.log('🔑 APP_API_KEY:', process.env.APP_API_KEY ? '✓ موجود' : '✗ مفقود');

if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
  console.error('❌ خطأ: FIREBASE_URL أو FIREBASE_KEY غير موجود في متغيرات البيئة');
  console.error('❌ أضف في Render: FIREBASE_URL, FIREBASE_KEY, APP_API_KEY');
  process.exit(1);
}

// ==================== تهيئة Firebase ====================
const firebase = axios.create({
  baseURL: process.env.FIREBASE_URL,
  timeout: 20000,
  params: { auth: process.env.FIREBASE_KEY }
});

// ==================== مفاتيح الأمان ====================
const APP_API_KEY = process.env.APP_API_KEY || "MySecureAppKey@2024#Firebase$";
const SIGNING_SECRET = process.env.REQUEST_SIGNING_SECRET || "Ma7moud55##@2024SecureSigningKey!";

// ==================== Middleware ====================
app.use(cors());
app.use(express.json());

// Middleware للتصحيح
app.use((req, res, next) => {
  console.log(`📥 ${req.method} ${req.path}`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('📝 Body:', JSON.stringify(req.body));
  }
  next();
});

// ==================== دوال مساعدة ====================
function hashPassword(password) {
  return crypto.createHash('sha256').update(password, 'utf8').digest('hex');
}

function generateSignature(data, timestamp) {
  try {
    const stringToSign = `${data}|${timestamp}|${SIGNING_SECRET}`;
    const hmac = crypto.createHmac('sha256', SIGNING_SECRET);
    return hmac.update(stringToSign, 'utf8').digest('base64').trim();
  } catch (error) {
    console.error('❌ خطأ في توليد التوقيع:', error);
    return null;
  }
}

// ==================== ENDPOINTS ====================

// 1. الصفحة الرئيسية
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html dir="rtl">
    <head>
      <meta charset="UTF-8">
      <title>Firebase Proxy Server v2.2.0</title>
      <style>
        body { font-family: Tahoma; background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 20px; }
        .container { max-width: 900px; margin: 50px auto; background: rgba(255,255,255,0.05); padding: 40px; border-radius: 20px; border: 1px solid rgba(255,255,255,0.1); }
        h1 { color: #4cc9f0; text-align: center; margin-bottom: 30px; }
        .status { background: #10b981; padding: 15px; border-radius: 10px; text-align: center; font-size: 18px; margin: 20px 0; }
        .endpoint { background: rgba(255,255,255,0.07); margin: 15px 0; padding: 20px; border-radius: 10px; border-right: 4px solid #4cc9f0; }
        .method { display: inline-block; background: #3b82f6; padding: 5px 15px; border-radius: 5px; margin-left: 10px; font-weight: bold; }
        .url { color: #93c5fd; font-family: monospace; margin: 10px 0; }
        .desc { color: #cbd5e1; margin-top: 10px; }
        .footer { text-align: center; margin-top: 40px; color: #94a3b8; font-size: 14px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🔥 Firebase Proxy Server v2.2.0</h1>
        <div class="status">✅ الخادم يعمل بنجاح - جاهز للطلبات</div>
        
        <h3>📡 نقاط النهاية المتاحة:</h3>
        
        <div class="endpoint">
          <span class="method">GET</span>
          <div class="url">/api/serverTime</div>
          <div class="desc">الحصول على وقت السيرفر الحالي (لا يتطلب توقيع)</div>
        </div>
        
        <div class="endpoint">
          <span class="method">POST</span>
          <div class="url">/api/getUser</div>
          <div class="desc">جلب بيانات مستخدم (يتطلب API Key فقط)</div>
        </div>
        
        <div class="endpoint">
          <span class="method">POST</span>
          <div class="url">/api/verifyAccount</div>
          <div class="desc">التحقق من الحساب وتحديث الجهاز</div>
        </div>
        
        <div class="endpoint">
          <span class="method">POST</span>
          <div class="url">/api/updateDevice</div>
          <div class="desc">تحديث معرف الجهاز للمستخدم</div>
        </div>
        
        <div class="endpoint">
          <span class="method">GET</span>
          <div class="url">/api/health</div>
          <div class="desc">فحص حالة الخادم واتصال Firebase</div>
        </div>
        
        <div class="footer">
          <p>⏰ وقت الخادم: ${new Date().toLocaleString('ar-SA')}</p>
          <p>📊 الإصدار: 2.2.0 | Node.js ${process.version}</p>
          <p>🔐 API Key: ${APP_API_KEY.substring(0, 15)}...</p>
        </div>
      </div>
    </body>
    </html>
  `);
});

// 2. وقت السيرفر
app.get('/api/serverTime', (req, res) => {
  const now = Date.now();
  const timestamp = Math.floor(now / 1000);
  
  const responseData = {
    success: true,
    server_time: now,
    unixtime: timestamp,
    iso_time: new Date(now).toISOString(),
    local_time: new Date(now).toLocaleString('ar-SA'),
    timezone: 'Asia/Riyadh'
  };
  
  res.json(responseData);
});

// 3. جلب مستخدم (مبسط بدون تواقيع)
app.post('/api/getUser', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: 'API key is required',
      code: 401
    });
  }
  
  if (apiKey !== APP_API_KEY) {
    return res.status(401).json({
      success: false,
      error: 'Invalid API key',
      code: 401
    });
  }
  
  const { username } = req.body;
  
  if (!username) {
    return res.status(400).json({
      success: false,
      error: 'Username is required',
      code: 400
    });
  }
  
  console.log(`🔍 جلب بيانات المستخدم: ${username}`);
  
  firebase.get(`/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"`)
    .then(response => {
      if (!response.data || Object.keys(response.data).length === 0) {
        return res.json({
          success: false,
          error: 'User not found',
          code: 1,
          timestamp: Date.now()
        });
      }
      
      const key = Object.keys(response.data)[0];
      const user = response.data[key];
      
      res.json({
        success: true,
        username: user.username,
        password_hash: user.password_hash,
        is_active: user.is_active || false,
        expiry_date: user.expiry_date || '',
        device_id: user.device_id || '',
        firebase_key: key,
        timestamp: Date.now()
      });
    })
    .catch(error => {
      console.error('❌ خطأ في Firebase:', error.message);
      res.status(500).json({
        success: false,
        error: 'Database error',
        code: 0,
        timestamp: Date.now()
      });
    });
});

// 4. التحقق من الحساب
app.post('/api/verifyAccount', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || apiKey !== APP_API_KEY) {
    return res.status(401).json({
      success: false,
      error: 'Invalid API key',
      code: 401
    });
  }
  
  const { username, password, deviceId } = req.body;
  
  if (!username || !password || !deviceId) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields',
      code: 400
    });
  }
  
  console.log(`🔐 التحقق من الحساب: ${username}`);
  
  const passHash = hashPassword(password);
  
  firebase.get(`/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"`)
    .then(response => {
      if (!response.data || Object.keys(response.data).length === 0) {
        return res.json({
          success: false,
          code: 1,
          message: 'User not found'
        });
      }
      
      const key = Object.keys(response.data)[0];
      const user = response.data[key];
      
      // التحقق من كلمة المرور
      if (user.password_hash !== passHash) {
        return res.json({
          success: false,
          code: 2,
          message: 'Wrong password'
        });
      }
      
      // التحقق من الحالة النشطة
      if (!user.is_active) {
        return res.json({
          success: false,
          code: 3,
          message: 'Account inactive'
        });
      }
      
      // التحقق من الجهاز
      if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
        return res.json({
          success: false,
          code: 4,
          message: 'Account linked to another device'
        });
      }
      
      // التحقق من انتهاء الصلاحية
      if (user.expiry_timestamp && user.expiry_timestamp < Date.now()) {
        return res.json({
          success: false,
          code: 7,
          message: 'Subscription expired'
        });
      }
      
      // تحديث الجهاز وآخر دخول
      const updates = {
        device_id: deviceId,
        last_login: new Date().toISOString(),
        login_count: (user.login_count || 0) + 1,
        last_updated: Date.now()
      };
      
      return firebase.patch(`/users/${key}.json`, updates)
        .then(() => {
          // حساب الأيام المتبقية
          let remainingDays = 0;
          if (user.expiry_timestamp) {
            const diff = user.expiry_timestamp - Date.now();
            remainingDays = Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
          }
          
          res.json({
            success: true,
            username: user.username,
            expiry_date: user.expiry_date || '',
            remaining_days: remainingDays,
            is_active: true,
            message: 'Login successful'
          });
        });
    })
    .catch(error => {
      console.error('❌ خطأ في التحقق:', error);
      res.status(500).json({
        success: false,
        code: 0,
        message: 'Server error'
      });
    });
});

// 5. تحديث الجهاز
app.post('/api/updateDevice', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || apiKey !== APP_API_KEY) {
    return res.status(401).json({
      success: false,
      error: 'Invalid API key',
      code: 401
    });
  }
  
  const { username, deviceId } = req.body;
  
  if (!username || !deviceId) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields',
      code: 400
    });
  }
  
  firebase.get(`/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"`)
    .then(response => {
      if (!response.data || Object.keys(response.data).length === 0) {
        return res.json({
          success: false,
          code: 1,
          message: 'User not found'
        });
      }
      
      const key = Object.keys(response.data)[0];
      
      return firebase.patch(`/users/${key}.json`, {
        device_id: deviceId,
        last_updated: Date.now()
      })
      .then(() => {
        res.json({
          success: true,
          updated: true,
          message: 'Device updated successfully'
        });
      });
    })
    .catch(error => {
      console.error('❌ خطأ في تحديث الجهاز:', error);
      res.status(500).json({
        success: false,
        code: 11,
        message: 'Update failed'
      });
    });
});

// 6. فحص الصحة
app.get('/api/health', (req, res) => {
  firebase.get('/.json?shallow=true')
    .then(() => {
      res.json({
        status: 'healthy',
        timestamp: Date.now(),
        version: '2.2.0',
        firebase: 'connected',
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
      });
    })
    .catch(error => {
      res.status(500).json({
        status: 'unhealthy',
        timestamp: Date.now(),
        firebase: 'disconnected',
        error: error.message
      });
    });
});

// 7. اختبار Firebase مباشرة
app.get('/api/test', (req, res) => {
  firebase.get('/.json?shallow=true')
    .then(response => {
      res.json({
        success: true,
        firebase_connected: true,
        data_keys: Object.keys(response.data || {}),
        timestamp: Date.now()
      });
    })
    .catch(error => {
      res.status(500).json({
        success: false,
        firebase_connected: false,
        error: error.message
      });
    });
});

// ==================== بدء الخادم ====================
app.listen(PORT, () => {
  console.log('\n' + '='.repeat(60));
  console.log('🚀 Firebase Proxy Server v2.2.0');
  console.log('📡 Running on port:', PORT);
  console.log('🔐 API Key:', APP_API_KEY.substring(0, 15) + '...');
  console.log('🗓️ Server time:', new Date().toLocaleString('ar-SA'));
  console.log('='.repeat(60));
  console.log('✅ Ready to accept connections!');
  console.log('='.repeat(60));
});
