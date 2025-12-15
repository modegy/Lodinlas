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
// 🔐 نظام الجلسات الجديد
// ═══════════════════════════════════════════

const adminSessions = new Map();

// بيانات الأدمن من Environment Variables
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USERNAME || 'admin',
  password: process.env.ADMIN_PASSWORD || 'ChangeThisPassword123!'
};

// إنشاء session token آمن
function generateSessionToken() {
  return crypto.randomBytes(64).toString('hex');
}

// تنظيف الجلسات المنتهية كل ساعة
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of adminSessions.entries()) {
    if (now - session.createdAt > 24 * 60 * 60 * 1000) {
      adminSessions.delete(token);
    }
  }
}, 60 * 60 * 1000);

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

// ✅ Middleware جديد للأدمن - يدعم الجلسات
const authAdmin = (req, res, next) => {
  // طريقة 1: التحقق عبر Session Token (للوحة التحكم الجديدة)
  const sessionToken = req.headers['x-session-token'];
  if (sessionToken) {
    const session = adminSessions.get(sessionToken);
    
    if (!session) {
      return res.status(401).json({ 
        success: false, 
        error: 'جلسة غير صالحة - سجل الدخول مرة أخرى', 
        code: 401 
      });
    }
    
    // تحقق من انتهاء الجلسة (24 ساعة)
    if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
      adminSessions.delete(sessionToken);
      return res.status(401).json({ 
        success: false, 
        error: 'انتهت صلاحية الجلسة', 
        code: 401 
      });
    }
    
    // تحديث آخر نشاط
    session.lastActivity = Date.now();
    req.adminUser = session.username;
    return next();
  }
  
  // طريقة 2: التحقق عبر API Key (للتوافق مع الأنظمة القديمة)
  const adminKey = req.headers['x-admin-key'];
  const expected = process.env.ADMIN_API_KEY;
  if (expected && adminKey === expected) {
    req.adminUser = 'api-key-user';
    return next();
  }
  
  // لا يوجد مصادقة صالحة
  return res.status(401).json({ 
    success: false, 
    error: 'غير مصرح - سجل الدخول أولاً', 
    code: 401 
  });
};



// ═══════════════════════════════════════════
// 🔑 AUTH للـ SUB ADMIN (عبر API Key)
// ═══════════════════════════════════════════

const authSubAdmin = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ 
      success: false, 
      error: 'مفتاح API مطلوب', 
      code: 401 
    });
  }
  
  try {
    // البحث عن المفتاح في Firebase
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
    
    if (!foundKey) {
      return res.status(401).json({ 
        success: false, 
        error: 'مفتاح API غير صالح', 
        code: 401 
      });
    }
    
    // تحقق من أن المفتاح نشط
    if (!foundKey.is_active) {
      return res.status(403).json({ 
        success: false, 
        error: 'مفتاح API معطل', 
        code: 403 
      });
    }
    
    // تحقق من انتهاء الصلاحية
    if (foundKey.expiry_timestamp && foundKey.expiry_timestamp < Date.now()) {
      return res.status(403).json({ 
        success: false, 
        error: 'مفتاح API منتهي الصلاحية', 
        code: 403 
      });
    }
    
    // تحديث عداد الاستخدام
    await firebase.patch(`${FB_URL}/api_keys/${keyId}.json?auth=${FB_KEY}`, {
      usage_count: (foundKey.usage_count || 0) + 1,
      last_used: Date.now()
    });
    
    // إضافة معلومات المفتاح للـ request
    req.subAdmin = {
      name: foundKey.admin_name,
      permission: foundKey.permission_level || 'view_only',
      keyId: keyId
    };
    
    next();
    
  } catch (error) {
    console.error('خطأ في التحقق من API Key:', error);
    res.status(500).json({ 
      success: false, 
      error: 'خطأ في التحقق', 
      code: 500 
    });
  }
};

// التحقق من الصلاحية
const checkPermission = (required) => {
  return (req, res, next) => {
    const permission = req.subAdmin?.permission || 'view_only';
    
    const permissions = {
      'full': ['view', 'add', 'edit', 'delete', 'extend'],
      'add_only': ['view', 'add'],
      'extend_only': ['view', 'extend'],
      'view_only': ['view']
    };
    
    const allowed = permissions[permission] || ['view'];
    
    if (!allowed.includes(required)) {
      return res.status(403).json({ 
        success: false, 
        error: 'ليس لديك صلاحية لهذا الإجراء', 
        code: 403 
      });
    }
    
    next();
  };
};

// ═══════════════════════════════════════════
// 🔐 SUB ADMIN ENDPOINTS
// ═══════════════════════════════════════════

// التحقق من المفتاح والحصول على الصلاحيات
app.post('/api/sub/verify-key', async (req, res) => {
  const { apiKey } = req.body;
  
  if (!apiKey) {
    return res.status(400).json({ success: false, error: 'المفتاح مطلوب' });
  }
  
  try {
    const response = await firebase.get(`${FB_URL}/api_keys.json?auth=${FB_KEY}`);
    const keys = response.data || {};
    
    for (const [id, keyData] of Object.entries(keys)) {
      if (keyData.api_key === apiKey) {
        
        if (!keyData.is_active) {
          return res.json({ success: false, error: 'المفتاح معطل' });
        }
        
        if (keyData.expiry_timestamp && keyData.expiry_timestamp < Date.now()) {
          return res.json({ success: false, error: 'المفتاح منتهي' });
        }
        
        return res.json({ 
          success: true,
          name: keyData.admin_name,
          permission: keyData.permission_level || 'view_only',
          expiresAt: keyData.expiry_timestamp
        });
      }
    }
    
    res.json({ success: false, error: 'مفتاح غير صالح' });
    
  } catch (error) {
    res.status(500).json({ success: false, error: 'خطأ في الخادم' });
  }
});

// عرض المستخدمين (للجميع)
app.get('/api/sub/users', authSubAdmin, checkPermission('view'), async (req, res) => {
  try {
    const response = await firebase.get(`${FB_URL}/users.json?auth=${FB_KEY}`);
    res.json({ success: true, data: response.data || {} });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// إضافة مستخدم (add_only أو full)
app.post('/api/sub/users', authSubAdmin, checkPermission('add'), async (req, res) => {
  try {
    const { username, password, expiryMinutes, maxDevices, status } = req.body;
    
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
      created_by: req.subAdmin.name,
      session_token: crypto.randomBytes(32).toString('hex'),
      force_logout: false,
      login_count: 0
    };
    
    await firebase.put(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`, userData);
    
    console.log(`➕ Sub Admin "${req.subAdmin.name}" أضاف: ${username}`);
    
    res.json({ success: true, userId, expiryDate });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// تمديد مستخدم (extend_only أو full)
app.post('/api/sub/users/:userId/extend', authSubAdmin, checkPermission('extend'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { minutes } = req.body;
    
    if (!minutes || minutes < 1) {
      return res.status(400).json({ success: false, error: 'المدة مطلوبة' });
    }
    
    const userRes = await firebase.get(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`);
    const user = userRes.data;
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'المستخدم غير موجود' });
    }
    
    const currentExpiry = user.expiry_timestamp || Date.now();
    const newTimestamp = currentExpiry + (minutes * 60 * 1000);
    const newDate = formatDate(new Date(newTimestamp));
    
    await firebase.patch(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`, {
      expiry_timestamp: newTimestamp,
      expiry_date: newDate,
      last_updated: Date.now()
    });
    
    console.log(`⏰ Sub Admin "${req.subAdmin.name}" مدد: ${userId} بـ ${minutes} دقيقة`);
    
    res.json({ success: true, newExpiry: newDate });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// حذف مستخدم (full فقط)
app.delete('/api/sub/users/:userId', authSubAdmin, checkPermission('delete'), async (req, res) => {
  try {
    const { userId } = req.params;
    await firebase.delete(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`);
    console.log(`🗑️ Sub Admin "${req.subAdmin.name}" حذف: ${userId}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// تعديل مستخدم (full فقط)
app.patch('/api/sub/users/:userId', authSubAdmin, checkPermission('edit'), async (req, res) => {
  try {
    const { userId } = req.params;
    const updates = { ...req.body, last_updated: Date.now() };
    await firebase.patch(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`, updates);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// إعادة تعيين الجهاز (full فقط)
app.post('/api/sub/users/:userId/reset-device', authSubAdmin, checkPermission('edit'), async (req, res) => {
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

// الإحصائيات
app.get('/api/sub/stats', authSubAdmin, checkPermission('view'), async (req, res) => {
  try {
    const response = await firebase.get(`${FB_URL}/users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    const now = Date.now();
    
    const totalUsers = Object.keys(users).length;
    const activeUsers = Object.values(users).filter(u => u.is_active && u.expiry_timestamp > now).length;
    const expiredUsers = Object.values(users).filter(u => u.expiry_timestamp <= now).length;
    
    res.json({
      success: true,
      stats: { totalUsers, activeUsers, expiredUsers }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});


// ═══════════════════════════════════════════
// 🔑 ADMIN LOGIN ENDPOINTS
// ═══════════════════════════════════════════

// تسجيل الدخول
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  // التحقق من البيانات المطلوبة
  if (!username || !password) {
    return res.status(400).json({ 
      success: false, 
      error: 'اسم المستخدم وكلمة المرور مطلوبان' 
    });
  }
  
  // التحقق من صحة البيانات
  if (username !== ADMIN_CREDENTIALS.username || 
      password !== ADMIN_CREDENTIALS.password) {
    
    // تأخير للحماية من brute force
    console.log(`❌ محاولة دخول فاشلة: ${username} من ${req.ip}`);
    
    return setTimeout(() => {
      res.status(401).json({ 
        success: false, 
        error: 'اسم المستخدم أو كلمة المرور غير صحيحة' 
      });
    }, 1500); // تأخير 1.5 ثانية
  }
  
  // إنشاء جلسة جديدة
  const sessionToken = generateSessionToken();
  
  adminSessions.set(sessionToken, {
    username,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    ip: req.ip || req.connection.remoteAddress
  });
  
  console.log(`✅ تسجيل دخول ناجح: ${username} من ${req.ip}`);
  
  res.json({ 
    success: true, 
    sessionToken,
    expiresIn: '24 hours',
    message: 'تم تسجيل الدخول بنجاح'
  });
});

// تسجيل الخروج
app.post('/api/admin/logout', (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  
  if (sessionToken && adminSessions.has(sessionToken)) {
    const session = adminSessions.get(sessionToken);
    console.log(`👋 تسجيل خروج: ${session.username}`);
    adminSessions.delete(sessionToken);
  }
  
  res.json({ success: true, message: 'تم تسجيل الخروج' });
});

// التحقق من صلاحية الجلسة
app.get('/api/admin/verify-session', (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  
  if (!sessionToken) {
    return res.status(401).json({ success: false, error: 'لا يوجد token' });
  }
  
  const session = adminSessions.get(sessionToken);
  
  if (!session) {
    return res.status(401).json({ success: false, error: 'جلسة غير صالحة' });
  }
  
  // تحقق من انتهاء الصلاحية
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    adminSessions.delete(sessionToken);
    return res.status(401).json({ success: false, error: 'انتهت الجلسة' });
  }
  
  res.json({ 
    success: true, 
    username: session.username,
    createdAt: session.createdAt,
    lastActivity: session.lastActivity
  });
});

// معلومات الجلسات النشطة (للأدمن فقط)
app.get('/api/admin/active-sessions', authAdmin, (req, res) => {
  const sessions = [];
  
  for (const [token, session] of adminSessions.entries()) {
    sessions.push({
      username: session.username,
      createdAt: new Date(session.createdAt).toISOString(),
      lastActivity: new Date(session.lastActivity).toISOString(),
      ip: session.ip,
      tokenPreview: token.substring(0, 8) + '...'
    });
  }
  
  res.json({ success: true, count: sessions.length, sessions });
});

// إنهاء جميع الجلسات
app.post('/api/admin/logout-all', authAdmin, (req, res) => {
  const count = adminSessions.size;
  adminSessions.clear();
  console.log(`🔒 تم إنهاء ${count} جلسة`);
  res.json({ success: true, message: `تم إنهاء ${count} جلسة` });
});

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

// 📋 جلب مستخدم واحد
app.get('/api/admin/users/:userId', authAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const response = await firebase.get(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`);
    
    if (!response.data) {
      return res.status(404).json({ success: false, error: 'المستخدم غير موجود' });
    }
    
    res.json({ success: true, data: response.data });
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
      created_by: req.adminUser || 'admin',
      notes: notes || '',
      session_token: crypto.randomBytes(32).toString('hex'),
      force_logout: false,
      login_count: 0
    };
    
    await firebase.put(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`, userData);
    
    console.log(`➕ مستخدم جديد: ${username} بواسطة ${req.adminUser}`);
    
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
    console.log(`🗑️ حذف مستخدم: ${userId} بواسطة ${req.adminUser}`);
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
    
    if (!minutes || minutes < 1) {
      return res.status(400).json({ success: false, error: 'المدة مطلوبة' });
    }
    
    const userRes = await firebase.get(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`);
    const user = userRes.data;
    
    if (!user) return res.status(404).json({ success: false, error: 'غير موجود' });
    
    const currentExpiry = user.expiry_timestamp || Date.now();
    const newTimestamp = currentExpiry + (minutes * 60 * 1000);
    const newDate = formatDate(new Date(newTimestamp));
    
    await firebase.patch(`${FB_URL}/users/${userId}.json?auth=${FB_KEY}`, {
      expiry_timestamp: newTimestamp,
      expiry_date: newDate,
      last_updated: Date.now()
    });
    
    console.log(`⏰ تمديد: ${userId} بـ ${minutes} دقيقة بواسطة ${req.adminUser}`);
    
    res.json({ success: true, newExpiry: newDate, newTimestamp });
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
    
    console.log(`🚪 إجبار خروج: ${userId} بواسطة ${req.adminUser}`);
    
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
      usage_count: 0,
      created_by: req.adminUser || 'admin'
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
        totalKeys: Object.keys(keys).length,
        activeSessions: adminSessions.size
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
    version: '2.4.0',
    firebase: fbStatus,
    uptime: Math.floor(process.uptime()),
    activeSessions: adminSessions.size
  });
});

// الصفحة الرئيسية
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>Firebase Proxy v2.4.0</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:system-ui;background:#1a1a2e;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center}
    .box{background:rgba(255,255,255,0.05);padding:40px;border-radius:20px;text-align:center;max-width:600px}
    h1{color:#4cc9f0;margin-bottom:20px}
    .ok{background:#10b981;padding:10px 30px;border-radius:50px;display:inline-block;margin:20px 0}
    .section{margin:20px 0;text-align:right}
    .section h3{color:#4cc9f0;margin-bottom:10px}
    .ep{background:rgba(255,255,255,0.05);padding:8px 12px;margin:5px 0;border-radius:8px;font-family:monospace;font-size:13px}
    .new{background:rgba(16,185,129,0.2);border:1px solid #10b981}
  </style>
</head>
<body>
  <div class="box">
    <h1>🛡️ Firebase Proxy v2.4.0</h1>
    <div class="ok">✅ يعمل بنظام الجلسات الآمن</div>
    
    <div class="section">
      <h3>🔐 Auth Endpoints (جديد)</h3>
      <div class="ep new">POST /api/admin/login</div>
      <div class="ep new">POST /api/admin/logout</div>
      <div class="ep new">GET /api/admin/verify-session</div>
    </div>
    
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
    
    <p style="margin-top:20px;color:#666;font-size:12px">
      الجلسات النشطة: يتم تنظيفها تلقائياً كل ساعة
    </p>
  </div>
</body>
</html>
  `);
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: 'غير موجود', code: 404 });
});

app.listen(PORT, () => {
  console.log('═'.repeat(50));
  console.log('🛡️  Firebase Proxy v2.4.0 + Secure Sessions');
  console.log(`📡 http://localhost:${PORT}`);
  console.log('🔐 نظام الجلسات: مفعّل');
  console.log('═'.repeat(50));
});
