const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
  console.error('❌ FIREBASE_URL أو FIREBASE_KEY غير موجود');
  process.exit(1);
}

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));
app.use(express.json({ limit: '10mb' }));

// Firebase Axios
const firebase = axios.create({ timeout: 15000 });
const FB_URL = process.env.FIREBASE_URL;
const FB_KEY = process.env.FIREBASE_KEY;

// ═══════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════

const authApp = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const expected = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
  if (apiKey !== expected) {
    return res.status(401).json({ success: false, error: 'غير مصرح', code: 401 });
  }
  next();
};

const authAdmin = (req, res, next) => {
  const adminKey = req.headers['x-admin-key'];
  const expected = process.env.ADMIN_API_KEY;
  if (!expected || adminKey !== expected) {
    return res.status(403).json({ success: false, error: 'صلاحيات الأدمن مطلوبة', code: 403 });
  }
  next();
};

// ═══════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════

function hashPassword(password) {
  return crypto.createHash('sha256').update(password, 'utf8').digest('hex');
}

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

function formatDate(date) {
  const d = String(date.getDate()).padStart(2, '0');
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const y = date.getFullYear();
  const h = String(date.getHours()).padStart(2, '0');
  const min = String(date.getMinutes()).padStart(2, '0');
  return `${d}/${m}/${y} ${h}:${min}`;
}

function generateApiKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = 'sk_';
  for (let i = 0; i < 48; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

// ═══════════════════════════════════════════
// APP ENDPOINTS (للتطبيق)
// ═══════════════════════════════════════════

app.get('/api/serverTime', (req, res) => {
  const now = Date.now();
  res.json({
    success: true,
    server_time: now,
    unixtime: Math.floor(now / 1000)
  });
});

app.post('/api/getUser', authApp, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ success: false, error: 'مطلوب', code: 400 });
    
    const url = `${FB_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    
    if (!response.data || Object.keys(response.data).length === 0) {
      return res.json({});
    }
    
    const key = Object.keys(response.data)[0];
    const user = response.data[key];
    
    res.json({
      username: user.username,
      password_hash: user.password_hash,
      is_active: user.is_active || false,
      expiry_date: user.expiry_date || '',
      device_id: user.device_id || '',
      force_logout: user.force_logout || false,
      session_token: user.session_token || '',
      remaining_days: calculateRemainingDays(user.expiry_date),
      firebase_key: key
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'خطأ', code: 0 });
  }
});

app.post('/api/updateDevice', authApp, async (req, res) => {
  try {
    const { username, deviceId } = req.body;
    if (!username || !deviceId) return res.status(400).json({ success: false, error: 'ناقص', code: 400 });
    
    const searchUrl = `${FB_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const searchRes = await firebase.get(searchUrl);
    
    if (!searchRes.data || Object.keys(searchRes.data).length === 0) {
      return res.json({ success: false, code: 1 });
    }
    
    const key = Object.keys(searchRes.data)[0];
    await firebase.patch(`${FB_URL}/users/${key}.json?auth=${FB_KEY}`, {
      device_id: deviceId,
      last_login: new Date().toISOString()
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, code: 11 });
  }
});

app.post('/api/verifyAccount', authApp, async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    if (!username || !password || !deviceId) {
      return res.status(400).json({ success: false, error: 'ناقص', code: 400 });
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
    if (user.force_logout) {
      return res.json({ success: false, code: 8, error: 'تم إجبارك على الخروج' });
    }
    
    const remaining = calculateRemainingDays(user.expiry_date);
    if (remaining <= 0) return res.json({ success: false, code: 7 });
    
    await firebase.patch(`${FB_URL}/users/${key}.json?auth=${FB_KEY}`, {
      device_id: deviceId,
      last_login: new Date().toISOString(),
      force_logout: false,
      login_count: (user.login_count || 0) + 1
    });
    
    res.json({
      success: true,
      username: user.username,
      expiry_date: user.expiry_date,
      remaining_days: remaining,
      is_active: true
    });
  } catch (error) {
    res.status(500).json({ success: false, code: 0 });
  }
});

// ═══════════════════════════════════════════
// ADMIN ENDPOINTS (للوحة التحكم)
// ═══════════════════════════════════════════

// 📋 جلب جميع المستخدمين
app.get('/api/admin/users', authAdmin, async (req, res) => {
  try {
    const response = await firebase.get(`${FB_URL}/users.json?auth=${FB_KEY}`);
    res.json({ success: true, data: response.data || {} });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ➕ إضافة مستخدم جديد
app.post('/api/admin/users', authAdmin, async (req, res) => {
  try {
    const { username, password, expiryMinutes, maxDevices, status, notes } = req.body;
    
    if (!username || !password || !expiryMinutes) {
      return res.status(400).json({ success: false, error: 'بيانات ناقصة' });
    }
    
    const timestamp = Date.now();
    const expiryTimestamp = timestamp + (expiryMinutes * 60 * 1000);
    const expiryDate = formatDate(new Date(expiryTimestamp));
    const userId = `user_${username}_${timestamp}`;
    
    const userData = {
      username,
      password_hash: hashPassword(password),
      device_id: '',
      expiry_date: expiryDate,
      expiry_timestamp: expiryTimestamp,
      is_active: status !== 'inactive',
      status: status || 'active',
      max_devices: maxDevices || 1,
      created_at: timestamp,
      last_updated: timestamp,
      created_by: 'admin',
      notes: notes || '',
      session_token: crypto.randomBytes(32).toString('hex'),
      force_logout: false,
      login_count: 0
    };
    
    await firebase.put(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`, userData);
    
    res.json({ success: true, userId, expiryDate });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 📝 تحديث مستخدم
app.patch('/api/admin/users/:userId', authAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const updates = { ...req.body, last_updated: Date.now() };
    
    await firebase.patch(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`, updates);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🗑️ حذف مستخدم
app.delete('/api/admin/users/:userId', authAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    await firebase.delete(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ⏰ تمديد مستخدم
app.post('/api/admin/users/:userId/extend', authAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { minutes } = req.body;
    
    const userRes = await firebase.get(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`);
    const user = userRes.data;
    
    if (!user) return res.status(404).json({ success: false, error: 'غير موجود' });
    
    const newTimestamp = user.expiry_timestamp + (minutes * 60 * 1000);
    const newDate = formatDate(new Date(newTimestamp));
    
    await firebase.patch(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`, {
      expiry_timestamp: newTimestamp,
      expiry_date: newDate,
      last_updated: Date.now()
    });
    
    res.json({ success: true, newExpiry: newDate });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🚪 إجبار خروج
app.post('/api/admin/users/:userId/force-logout', authAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    await firebase.patch(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`, {
      force_logout: true,
      session_token: null,
      device_id: '',
      logout_timestamp: Date.now()
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🔄 إعادة تعيين الجهاز
app.post('/api/admin/users/:userId/reset-device', authAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    await firebase.patch(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`, {
      device_id: '',
      force_logout: false,
      session_token: crypto.randomBytes(32).toString('hex'),
      last_updated: Date.now()
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ═══════════════════════════════════════════
// API KEYS MANAGEMENT
// ═══════════════════════════════════════════

// 📋 جلب جميع المفاتيح
app.get('/api/admin/api-keys', authAdmin, async (req, res) => {
  try {
    const response = await firebase.get(`${FB_URL}/api_keys.json?auth=${FB_KEY}`);
    res.json({ success: true, data: response.data || {} });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ➕ إنشاء مفتاح API
app.post('/api/admin/api-keys', authAdmin, async (req, res) => {
  try {
    const { adminName, permissionLevel, expiryDays } = req.body;
    
    if (!adminName) {
      return res.status(400).json({ success: false, error: 'اسم المدير مطلوب' });
    }
    
    const timestamp = Date.now();
    const apiKey = generateApiKey();
    const keyId = `key_${timestamp}`;
    const expiryTimestamp = timestamp + ((expiryDays || 30) * 24 * 60 * 60 * 1000);
    
    const keyData = {
      admin_name: adminName,
      api_key: apiKey,
      permission_level: permissionLevel || 'full',
      is_active: true,
      created_at: timestamp,
      expiry_timestamp: expiryTimestamp,
      usage_count: 0
    };
    
    await firebase.put(`${FB_URL}/api_keys/${keyId}.json?auth=${FB_KEY}`, keyData);
    
    res.json({ success: true, keyId, apiKey });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 📝 تحديث مفتاح
app.patch('/api/admin/api-keys/:keyId', authAdmin, async (req, res) => {
  try {
    const { keyId } = req.params;
    await firebase.patch(`${FB_URL}/api_keys/${keyId}.json?auth=${FB_KEY}`, req.body);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 🗑️ حذف مفتاح
app.delete('/api/admin/api-keys/:keyId', authAdmin, async (req, res) => {
  try {
    const { keyId } = req.params;
    await firebase.delete(`${FB_URL}/api_keys/${keyId}.json?auth=${FB_KEY}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ═══════════════════════════════════════════
// STATS & HEALTH
// ═══════════════════════════════════════════

app.get('/api/admin/stats', authAdmin, async (req, res) => {
  try {
    const [usersRes, keysRes] = await Promise.all([
      firebase.get(`${FB_URL}/users.json?auth=${FB_KEY}`),
      firebase.get(`${FB_URL}/api_keys.json?auth=${FB_KEY}`)
    ]);
    
    const users = usersRes.data || {};
    const keys = keysRes.data || {};
    const now = Date.now();
    
    const totalUsers = Object.keys(users).length;
    const activeUsers = Object.values(users).filter(u => u.is_active && u.expiry_timestamp > now).length;
    const expiredUsers = Object.values(users).filter(u => u.expiry_timestamp <= now).length;
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        activeUsers,
        expiredUsers,
        totalKeys: Object.keys(keys).length
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/health', async (req, res) => {
  let fbStatus = 'unknown';
  try {
    await firebase.get(`${FB_URL}/.json?shallow=true&auth=${FB_KEY}`, { timeout: 5000 });
    fbStatus = 'connected';
  } catch (e) { fbStatus = 'disconnected'; }
  
  res.json({
    status: 'healthy',
    version: '2.3.0',
    firebase: fbStatus,
    uptime: Math.floor(process.uptime())
  });
});

// الصفحة الرئيسية
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>Firebase Proxy v2.3.0</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:system-ui;background:#1a1a2e;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center}
    .box{background:rgba(255,255,255,0.05);padding:40px;border-radius:20px;text-align:center}
    h1{color:#4cc9f0;margin-bottom:20px}
    .ok{background:#10b981;padding:10px 30px;border-radius:50px;display:inline-block;margin:20px 0}
    .section{margin:20px 0;text-align:right}
    .section h3{color:#4cc9f0;margin-bottom:10px}
    .ep{background:rgba(255,255,255,0.05);padding:8px 12px;margin:5px 0;border-radius:8px;font-family:monospace;font-size:13px}
  </style>
</head>
<body>
  <div class="box">
    <h1>🛡️ Firebase Proxy v2.3.0</h1>
    <div class="ok">✅ يعمل</div>
    
    <div class="section">
      <h3>📱 App Endpoints</h3>
      <div class="ep">GET /api/serverTime</div>
      <div class="ep">POST /api/getUser</div>
      <div class="ep">POST /api/updateDevice</div>
      <div class="ep">POST /api/verifyAccount</div>
    </div>
    
    <div class="section">
      <h3>👑 Admin Endpoints</h3>
      <div class="ep">GET /api/admin/users</div>
      <div class="ep">POST /api/admin/users</div>
      <div class="ep">PATCH /api/admin/users/:id</div>
      <div class="ep">DELETE /api/admin/users/:id</div>
      <div class="ep">POST /api/admin/users/:id/extend</div>
      <div class="ep">POST /api/admin/users/:id/force-logout</div>
      <div class="ep">GET /api/admin/api-keys</div>
      <div class="ep">POST /api/admin/api-keys</div>
    </div>
  </div>
</body>
</html>
  `);
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: 'غير موجود', code: 404 });
});

app.listen(PORT, () => {
  console.log('═'.repeat(40));
  console.log('🛡️  Firebase Proxy v2.3.0 + Admin API');
  console.log(`📡 http://localhost:${PORT}`);
  console.log('═'.repeat(40));
});
