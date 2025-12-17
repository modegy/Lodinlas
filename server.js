const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// ═══════════════════════════════════════════
// 🛡️ TRUST PROXY FOR RENDER
// ═══════════════════════════════════════════
app.set('trust proxy', 'loopback, linklocal, uniquelocal');

// ═══════════════════════════════════════════
// 1️⃣ ENVIRONMENT VALIDATION
// ═══════════════════════════════════════════
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
  console.error('❌ FIREBASE_URL أو FIREBASE_KEY غير موجود');
  process.exit(1);
}

// ═══════════════════════════════════════════
// 2️⃣ BASIC SECURITY MIDDLEWARES
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
// 3️⃣ RATE LIMITING
// ═══════════════════════════════════════════
const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs, max,
    message: { success: false, error: message },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
             req.headers['x-real-ip'] || req.ip || req.connection.remoteAddress;
    }
  });
};

const globalLimiter = createRateLimiter(60 * 1000, 100, 'Too many requests');
app.use('/', globalLimiter);

const loginLimiter = createRateLimiter(15 * 60 * 1000, 5, 'Too many login attempts');
const apiLimiter = createRateLimiter(60 * 1000, 50, 'API rate limit exceeded');

// ═══════════════════════════════════════════
// 4️⃣ BODY PARSER
// ═══════════════════════════════════════════
app.use(express.json({ limit: '2mb' }));

// ═══════════════════════════════════════════
// 5️⃣ ANTI-BRUTE FORCE
// ═══════════════════════════════════════════
const loginAttempts = new Map();

const bruteForceProtection = (req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  if (!loginAttempts.has(ip)) {
    loginAttempts.set(ip, { count: 0, lastAttempt: Date.now() });
  }
  const attempt = loginAttempts.get(ip);
  if (Date.now() - attempt.lastAttempt > 15 * 60 * 1000) attempt.count = 0;
  if (attempt.count >= 5) {
    return res.status(429).json({
      success: false,
      error: `Too many attempts. Try again in ${Math.ceil((15 * 60 * 1000 - (Date.now() - attempt.lastAttempt)) / 1000 / 60)} minutes`
    });
  }
  next();
};

setInterval(() => {
  const now = Date.now();
  for (const [ip, attempt] of loginAttempts.entries()) {
    if (now - attempt.lastAttempt > 60 * 60 * 1000) loginAttempts.delete(ip);
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// 6️⃣ FIREBASE CONFIGURATION
// ═══════════════════════════════════════════
const firebase = axios.create({ 
  baseURL: process.env.FIREBASE_URL,
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' }
});
const FB_KEY = process.env.FIREBASE_KEY;

// ═══════════════════════════════════════════
// 7️⃣ SESSION & AUTH
// ═══════════════════════════════════════════
const adminSessions = new Map();
const APP_API_KEY = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USERNAME || 'admin',
  password: process.env.ADMIN_PASSWORD || 'Admin@123456'
};

function generateToken() { return crypto.randomBytes(32).toString('hex'); }
function hashPassword(password) { return crypto.createHash('sha256').update(password).digest('hex'); }

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of adminSessions.entries()) {
    if (now - session.createdAt > 24 * 60 * 60 * 1000) adminSessions.delete(token);
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// 8️⃣ MIDDLEWARES
// ═══════════════════════════════════════════
const authApp = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ success: false, error: 'API Key required', code: 401 });
  if (apiKey === APP_API_KEY) return next();
  res.status(401).json({ success: false, error: 'Invalid API Key', code: 401 });
};

const authAdmin = (req, res, next) => {
  const sessionToken = req.headers['x-session-token'];
  if (!sessionToken) return res.status(401).json({ success: false, error: 'Session token required', code: 401 });
  const session = adminSessions.get(sessionToken);
  if (!session) return res.status(401).json({ success: false, error: 'Invalid or expired session', code: 401 });
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    adminSessions.delete(sessionToken);
    return res.status(401).json({ success: false, error: 'Session expired', code: 401 });
  }
  req.adminUser = session.username;
  next();
};

// ═══════════════════════════════════════════
// 9️⃣ LOGGING
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
// 🔟 PUBLIC ENDPOINTS
// ═══════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', version: '3.0.0', uptime: Math.floor(process.uptime()), timestamp: Date.now() });
});

app.get('/api/serverTime', apiLimiter, (req, res) => {
  res.json({ success: true, server_time: Date.now(), formatted: new Date().toISOString() });
});

// ═══════════════════════════════════════════
// 🔐 ADMIN AUTH ENDPOINTS
// ═══════════════════════════════════════════
app.post('/api/admin/login', loginLimiter, bruteForceProtection, (req, res) => {
  try {
    const { username, password } = req.body;
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password required' });
    }
    
    if (username !== ADMIN_CREDENTIALS.username || password !== ADMIN_CREDENTIALS.password) {
      const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
      attempt.count++;
      attempt.lastAttempt = Date.now();
      loginAttempts.set(ip, attempt);
      return setTimeout(() => res.status(401).json({ success: false, error: 'Invalid credentials' }), 1500);
    }
    
    loginAttempts.delete(ip);
    const sessionToken = generateToken();
    adminSessions.set(sessionToken, { username, ip, createdAt: Date.now(), userAgent: req.headers['user-agent'] });
    console.log(`✅ Admin login: ${username} from ${ip}`);
    res.json({ success: true, sessionToken, expiresIn: '24 hours' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/admin/logout', authAdmin, (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  if (sessionToken) adminSessions.delete(sessionToken);
  res.json({ success: true, message: 'Logged out' });
});

app.get('/api/admin/verify-session', authAdmin, (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  const session = adminSessions.get(sessionToken);
  const expiresIn = 24 * 60 * 60 * 1000 - (Date.now() - session.createdAt);
  res.json({
    success: true,
    session: { username: session.username, expires_in: Math.floor(expiresIn / 1000 / 60) + ' minutes' },
    server_info: { active_sessions: adminSessions.size, uptime: Math.floor(process.uptime()) }
  });
});

// ═══════════════════════════════════════════
// 👥 USER MANAGEMENT ENDPOINTS
// ═══════════════════════════════════════════

// Get All Users
app.get('/api/admin/users', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const formattedUsers = {};
    for (const [id, user] of Object.entries(users)) {
      formattedUsers[id] = {
        username: user.username || '',
        is_active: user.is_active !== false,
        expiry_timestamp: user.subscription_end || null,
        expiry_date: user.subscription_end ? new Date(user.subscription_end).toLocaleString('ar-SA') : null,
        created_at: user.created_at || null,
        last_login: user.last_login || null,
        device_id: user.device_id || '',
        max_devices: user.max_devices || 1,
        notes: user.notes || ''
      };
    }
    
    res.json({ success: true, data: formattedUsers, count: Object.keys(formattedUsers).length });
  } catch (error) {
    console.error('Get users error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to fetch users' });
  }
});

// Get Single User
app.get('/api/admin/users/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);
    if (!response.data) return res.status(404).json({ success: false, error: 'User not found' });
    
    const user = response.data;
    res.json({
      success: true,
      data: {
        id: req.params.id,
        username: user.username,
        is_active: user.is_active !== false,
        expiry_timestamp: user.subscription_end,
        expiry_date: user.subscription_end ? new Date(user.subscription_end).toLocaleString('ar-SA') : null,
        device_id: user.device_id || '',
        max_devices: user.max_devices || 1
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch user' });
  }
});

// Create User
app.post('/api/admin/users', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password required' });
    }
    
    // Check if username exists
    const checkUrl = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const checkRes = await firebase.get(checkUrl);
    if (checkRes.data && Object.keys(checkRes.data).length > 0) {
      return res.status(400).json({ success: false, error: 'Username already exists' });
    }
    
    let expiryTimestamp;
    if (customExpiryDate) {
      expiryTimestamp = new Date(customExpiryDate).getTime();
    } else if (expiryMinutes) {
      expiryTimestamp = Date.now() + (expiryMinutes * 60 * 1000);
    } else {
      return res.status(400).json({ success: false, error: 'Expiry time required' });
    }
    
    const userData = {
      username,
      password_hash: hashPassword(password),
      is_active: status !== 'inactive',
      subscription_end: expiryTimestamp,
      max_devices: maxDevices || 1,
      device_id: '',
      created_at: Date.now(),
      last_login: null
    };
    
    const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
    console.log(`✅ User created: ${username}`);
    
    res.json({ success: true, message: 'User created', userId: createRes.data.name });
  } catch (error) {
    console.error('Create user error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to create user' });
  }
});

// Update User
app.patch('/api/admin/users/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { is_active, max_devices, notes } = req.body;
    const updateData = {};
    
    if (typeof is_active === 'boolean') updateData.is_active = is_active;
    if (max_devices) updateData.max_devices = max_devices;
    if (notes !== undefined) updateData.notes = notes;
    
    await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, updateData);
    res.json({ success: true, message: 'User updated' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to update user' });
  }
});

// Delete User
app.delete('/api/admin/users/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.delete(`users/${req.params.id}.json?auth=${FB_KEY}`);
    console.log(`🗑️ User deleted: ${req.params.id}`);
    res.json({ success: true, message: 'User deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to delete user' });
  }
});

// Extend Subscription
app.post('/api/admin/users/:id/extend', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { minutes, days, hours } = req.body;
    
    const userRes = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);
    if (!userRes.data) return res.status(404).json({ success: false, error: 'User not found' });
    
    const user = userRes.data;
    const now = Date.now();
    const currentEnd = user.subscription_end || now;
    
    let extensionMs = 0;
    if (minutes) extensionMs = minutes * 60 * 1000;
    else if (days || hours) extensionMs = ((days || 0) * 24 * 60 * 60 * 1000) + ((hours || 0) * 60 * 60 * 1000);
    
    if (!extensionMs) return res.status(400).json({ success: false, error: 'Extension time required' });
    
    const newEndDate = (currentEnd > now ? currentEnd : now) + extensionMs;
    
    await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, {
      subscription_end: newEndDate,
      is_active: true
    });
    
    res.json({ success: true, message: 'Subscription extended', new_end_date: newEndDate });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to extend subscription' });
  }
});

// Reset Device
app.post('/api/admin/users/:id/reset-device', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, { device_id: '' });
    console.log(`🔄 Device reset for user: ${req.params.id}`);
    res.json({ success: true, message: 'Device reset' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to reset device' });
  }
});

// ═══════════════════════════════════════════
// 🔑 API KEYS MANAGEMENT
// ═══════════════════════════════════════════

// Get All API Keys
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
    
    res.json({ success: true, data: formattedKeys, count: Object.keys(formattedKeys).length });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch API keys' });
  }
});

// Create API Key
app.post('/api/admin/api-keys', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { adminName, permissionLevel, expiryDays } = req.body;
    
    if (!adminName) return res.status(400).json({ success: false, error: 'Admin name required' });
    
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
    
    res.json({ success: true, message: 'API Key created', apiKey });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to create API key' });
  }
});

// Update API Key
app.patch('/api/admin/api-keys/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { is_active } = req.body;
    await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, { is_active });
    res.json({ success: true, message: 'API Key updated' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to update API key' });
  }
});

// Delete API Key
app.delete('/api/admin/api-keys/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.delete(`api_keys/${req.params.id}.json?auth=${FB_KEY}`);
    res.json({ success: true, message: 'API Key deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to delete API key' });
  }
});

// Unbind Device from API Key
app.post('/api/admin/api-keys/:id/unbind-device', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, { bound_device: null });
    res.json({ success: true, message: 'Device unbound' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to unbind device' });
  }
});

// ═══════════════════════════════════════════
// 📱 MOBILE APP ENDPOINTS
// ═══════════════════════════════════════════
app.post('/api/verifyAccount', authApp, apiLimiter, async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, error: 'Missing fields', code: 400 });
    
    const passHash = hashPassword(password);
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) return res.json({ success: false, code: 1 });
    
    const userId = Object.keys(users)[0];
    const user = users[userId];
    
    if (user.password_hash !== passHash) return res.json({ success: false, code: 2 });
    if (!user.is_active) return res.json({ success: false, code: 3 });
    if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
      return res.json({ success: false, code: 4 });
    }
    
    res.json({ success: true, username: user.username, code: 200 });
  } catch (error) {
    res.status(500).json({ success: false, code: 0, error: 'Server error' });
  }
});

app.post('/api/updateDevice', authApp, apiLimiter, async (req, res) => {
  try {
    const { username, deviceId } = req.body;
    if (!username || !deviceId) return res.status(400).json({ success: false, error: 'Missing data' });
    
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) return res.status(404).json({ success: false, error: 'User not found' });
    
    const userId = Object.keys(users)[0];
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { device_id: deviceId, last_login: Date.now() });
    
    res.json({ success: true, message: 'Device updated' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ═══════════════════════════════════════════
// 🏠 HOME PAGE
// ═══════════════════════════════════════════
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html><html dir="rtl"><head><meta charset="UTF-8"><title>🛡️ Secure API</title>
  <style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;min-height:100vh;padding:40px 20px;text-align:center}
  .container{max-width:800px;margin:0 auto}h1{color:#4cc9f0;margin-bottom:20px}.badge{background:linear-gradient(135deg,#10b981,#059669);padding:10px 20px;border-radius:20px;display:inline-block;margin:20px 0}
  .endpoints{background:rgba(255,255,255,0.05);padding:20px;border-radius:15px;text-align:left;margin-top:30px}.ep{margin:10px 0;padding:10px;background:rgba(255,255,255,0.02);border-radius:8px;border-left:3px solid #4cc9f0}
  .m{display:inline-block;padding:3px 10px;border-radius:5px;margin-left:10px;font-weight:bold;font-size:12px}.get{background:#10b981}.post{background:#f59e0b}.patch{background:#8b5cf6}.delete{background:#ef4444}</style></head>
  <body><div class="container"><h1>🛡️ Secure Firebase Proxy v3.0</h1><div class="badge">✅ All Systems Online</div>
  <div class="endpoints"><h3>📋 API Endpoints:</h3>
  <div class="ep"><span class="m get">GET</span><strong>/api/health</strong></div>
  <div class="ep"><span class="m post">POST</span><strong>/api/admin/login</strong></div>
  <div class="ep"><span class="m get">GET</span><strong>/api/admin/users</strong></div>
  <div class="ep"><span class="m post">POST</span><strong>/api/admin/users</strong></div>
  <div class="ep"><span class="m patch">PATCH</span><strong>/api/admin/users/:id</strong></div>
  <div class="ep"><span class="m delete">DELETE</span><strong>/api/admin/users/:id</strong></div>
  <div class="ep"><span class="m post">POST</span><strong>/api/admin/users/:id/extend</strong></div>
  <div class="ep"><span class="m post">POST</span><strong>/api/admin/users/:id/reset-device</strong></div>
  <div class="ep"><span class="m get">GET</span><strong>/api/admin/api-keys</strong></div>
  <div class="ep"><span class="m post">POST</span><strong>/api/admin/api-keys</strong></div>
  </div></div></body></html>`);
});

// ═══════════════════════════════════════════
// 🚫 ERROR HANDLERS
// ═══════════════════════════════════════════
app.use('*', (req, res) => res.status(404).json({ success: false, error: 'Not found', code: 404 }));
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({ success: false, error: 'Internal error', code: 500 });
});

// ═══════════════════════════════════════════
// 🚀 START
// ═══════════════════════════════════════════
app.listen(PORT, () => {
  console.log('═'.repeat(50));
  console.log('🛡️  Secure Firebase Proxy v3.0');
  console.log(`📡 Port: ${PORT}`);
  console.log('✓ All endpoints ready');
  console.log('═'.repeat(50));
});
