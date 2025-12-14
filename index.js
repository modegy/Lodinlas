const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// التحقق من المتغيرات البيئية
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
  console.error('❌ FIREBASE_URL أو FIREBASE_KEY غير موجود');
  process.exit(1);
}

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));
app.use(express.json());

// التحقق من API Key
const authenticate = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const expected = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
  
  console.log(`📥 ${req.method} ${req.path}`);
  
  if (apiKey !== expected) {
    return res.status(401).json({ success: false, error: 'غير مصرح', code: 401 });
  }
  next();
};

// وظائف مساعدة
function calculateRemainingDays(expiryDate) {
  try {
    if (!expiryDate) return -1;
    const [datePart, timePart] = expiryDate.trim().split(' ');
    const [day, month, year] = datePart.split('/').map(Number);
    const [hour, minute] = (timePart || '00:00').split(':').map(Number);
    const expiry = new Date(year, month - 1, day, hour || 0, minute || 0);
    if (isNaN(expiry.getTime())) return -1;
    return Math.max(0, Math.ceil((expiry - Date.now()) / (1000 * 60 * 60 * 24)));
  } catch (e) { return -1; }
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password, 'utf8').digest('hex');
}

const firebase = axios.create({ timeout: 15000 });

// ═══════════════════════════════════════════
// ENDPOINTS
// ═══════════════════════════════════════════

// ⏰ وقت السيرفر
app.get('/api/serverTime', (req, res) => {
  const now = Date.now();
  res.json({
    success: true,
    server_time: now,
    unixtime: Math.floor(now / 1000),
    server_time_formatted: new Date(now).toISOString()
  });
});

// 🔍 جلب بيانات المستخدم
app.post('/api/getUser', authenticate, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) {
      return res.status(400).json({ success: false, error: 'اسم المستخدم مطلوب', code: 400 });
    }
    
    console.log(`🔍 جلب: ${username}`);
    
    const url = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const response = await firebase.get(url);
    
    if (!response.data || Object.keys(response.data).length === 0) {
      return res.json({});
    }
    
    const key = Object.keys(response.data)[0];
    const user = response.data[key];
    
    console.log(`✅ وجد: ${username}`);
    
    res.json({
      username: user.username,
      password_hash: user.password_hash,
      is_active: user.is_active || false,
      expiry_date: user.expiry_date || '',
      device_id: user.device_id || '',
      remaining_days: calculateRemainingDays(user.expiry_date),
      firebase_key: key
    });
    
  } catch (error) {
    console.error('❌ خطأ:', error.message);
    res.status(500).json({ success: false, error: 'خطأ في الاتصال', code: 0 });
  }
});

// 📱 تحديث الجهاز
app.post('/api/updateDevice', authenticate, async (req, res) => {
  try {
    const { username, deviceId } = req.body;
    if (!username || !deviceId) {
      return res.status(400).json({ success: false, error: 'بيانات ناقصة', code: 400 });
    }
    
    console.log(`📱 تحديث: ${username}`);
    
    const searchUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const searchRes = await firebase.get(searchUrl);
    
    if (!searchRes.data || Object.keys(searchRes.data).length === 0) {
      return res.json({ success: false, error: 'المستخدم غير موجود', code: 1 });
    }
    
    const key = Object.keys(searchRes.data)[0];
    const updateUrl = `${process.env.FIREBASE_URL}/users/${key}.json?auth=${process.env.FIREBASE_KEY}`;
    
    await firebase.patch(updateUrl, {
      device_id: deviceId,
      last_login: new Date().toISOString()
    });
    
    console.log(`✅ تم التحديث: ${username}`);
    res.json({ success: true });
    
  } catch (error) {
    console.error('❌ خطأ:', error.message);
    res.status(500).json({ success: false, error: 'فشل التحديث', code: 11 });
  }
});

// ✅ التحقق الكامل
app.post('/api/verifyAccount', authenticate, async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    if (!username || !password || !deviceId) {
      return res.status(400).json({ success: false, error: 'بيانات ناقصة', code: 400 });
    }
    
    console.log(`🔐 تحقق: ${username}`);
    
    const passHash = hashPassword(password);
    const url = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const response = await firebase.get(url);
    
    if (!response.data || Object.keys(response.data).length === 0) {
      return res.json({ success: false, error: 'المستخدم غير موجود', code: 1 });
    }
    
    const key = Object.keys(response.data)[0];
    const user = response.data[key];
    
    if (user.password_hash !== passHash) {
      return res.json({ success: false, error: 'كلمة المرور خاطئة', code: 2 });
    }
    if (!user.is_active) {
      return res.json({ success: false, error: 'الحساب غير نشط', code: 3 });
    }
    if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
      return res.json({ success: false, error: 'جهاز آخر', code: 4 });
    }
    
    const remaining = calculateRemainingDays(user.expiry_date);
    if (remaining <= 0) {
      return res.json({ success: false, error: 'انتهت الصلاحية', code: 7 });
    }
    
    // تحديث الجهاز
    const updateUrl = `${process.env.FIREBASE_URL}/users/${key}.json?auth=${process.env.FIREBASE_KEY}`;
    await firebase.patch(updateUrl, {
      device_id: deviceId,
      last_login: new Date().toISOString(),
      login_count: (user.login_count || 0) + 1
    });
    
    console.log(`✅ نجح: ${username} (${remaining} يوم)`);
    
    res.json({
      success: true,
      username: user.username,
      expiry_date: user.expiry_date,
      remaining_days: remaining,
      is_active: true,
      device_id: deviceId
    });
    
  } catch (error) {
    console.error('❌ خطأ:', error.message);
    res.status(500).json({ success: false, error: 'خطأ', code: 0 });
  }
});

// 🔄 إعادة تعيين الجهاز
app.post('/api/resetDevice', authenticate, async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey !== process.env.ADMIN_API_KEY) {
      return res.status(403).json({ success: false, error: 'غير مصرح', code: 403 });
    }
    
    const { username } = req.body;
    if (!username) {
      return res.status(400).json({ success: false, error: 'اسم المستخدم مطلوب', code: 400 });
    }
    
    const searchUrl = `${process.env.FIREBASE_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${process.env.FIREBASE_KEY}`;
    const searchRes = await firebase.get(searchUrl);
    
    if (!searchRes.data || Object.keys(searchRes.data).length === 0) {
      return res.json({ success: false, error: 'غير موجود', code: 1 });
    }
    
    const key = Object.keys(searchRes.data)[0];
    const updateUrl = `${process.env.FIREBASE_URL}/users/${key}.json?auth=${process.env.FIREBASE_KEY}`;
    await firebase.patch(updateUrl, { device_id: '' });
    
    console.log(`✅ تم إعادة تعيين: ${username}`);
    res.json({ success: true });
    
  } catch (error) {
    res.status(500).json({ success: false, error: 'فشل', code: 500 });
  }
});

// 🩺 فحص الصحة
app.get('/api/health', async (req, res) => {
  let fbStatus = 'unknown';
  try {
    await firebase.get(`${process.env.FIREBASE_URL}/.json?shallow=true&auth=${process.env.FIREBASE_KEY}`, { timeout: 5000 });
    fbStatus = 'connected';
  } catch (e) { fbStatus = 'disconnected'; }
  
  res.json({
    status: 'healthy',
    version: '2.2.0',
    firebase: { status: fbStatus },
    uptime: Math.floor(process.uptime()),
    endpoints: ['serverTime', 'getUser', 'updateDevice', 'verifyAccount', 'resetDevice', 'health']
  });
});

// 🏠 الصفحة الرئيسية
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Firebase Proxy</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:system-ui;background:#1a1a2e;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center}
    .box{background:rgba(255,255,255,0.05);padding:40px;border-radius:20px;text-align:center;max-width:500px}
    h1{color:#4cc9f0;margin-bottom:20px}
    .ok{background:#10b981;padding:10px 30px;border-radius:50px;display:inline-block;margin:20px 0}
    .ep{background:rgba(255,255,255,0.05);padding:10px;margin:5px 0;border-radius:8px;font-family:monospace;text-align:left}
    .g{color:#10b981}.p{color:#f59e0b}
  </style>
</head>
<body>
  <div class="box">
    <h1>🛡️ Firebase Proxy v2.2.0</h1>
    <div class="ok">✅ يعمل</div>
    <div class="ep"><span class="g">GET</span> /api/serverTime</div>
    <div class="ep"><span class="g">GET</span> /api/health</div>
    <div class="ep"><span class="p">POST</span> /api/getUser</div>
    <div class="ep"><span class="p">POST</span> /api/updateDevice</div>
    <div class="ep"><span class="p">POST</span> /api/verifyAccount</div>
    <div class="ep"><span class="p">POST</span> /api/resetDevice</div>
  </div>
</body>
</html>
  `);
});

// 404
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'غير موجود', code: 404, path: req.path });
});

// بدء الخادم
app.listen(PORT, () => {
  console.log('═'.repeat(40));
  console.log('🛡️  Firebase Proxy v2.2.0');
  console.log(`📡 http://localhost:${PORT}`);
  console.log('═'.repeat(40));
});
