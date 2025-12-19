const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', 'loopback, linklocal, uniquelocal');

// ═══════════════════════════════════════════
// التحقق من المتغيرات البيئية
// ═══════════════════════════════════════════
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
  console.error('❌ FIREBASE_URL أو FIREBASE_KEY غير موجود');
  process.exit(1);
}

// ═══════════════════════════════════════════
// الأمان والحماية
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
app.use(express.json({ limit: '2mb' }));

// ═══════════════════════════════════════════
// Brute Force Protection
// ═══════════════════════════════════════════
const loginAttempts = new Map();

const bruteForceProtection = (req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  
  if (!loginAttempts.has(ip)) {
    loginAttempts.set(ip, { count: 0, lastAttempt: Date.now() });
  }
  
  const attempt = loginAttempts.get(ip);
  
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
// دوال مساعدة
// ═══════════════════════════════════════════
const adminSessions = new Map();
const subAdminKeys = new Map();

const APP_API_KEY = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USERNAME || 'admin',
  password: process.env.ADMIN_PASSWORD || 'Admin@123456'
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

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of adminSessions.entries()) {
    if (now - session.createdAt > 24 * 60 * 60 * 1000) {
      adminSessions.delete(token);
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// المصادقة - Middlewares
// ═══════════════════════════════════════════

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
    return next();
  }
  
  res.status(401).json({ 
    success: false, 
    error: 'Invalid API Key', 
    code: 401 
  });
};

// ✅ مصادقة Master Admin مع دعم Direct Token
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
    
    const cached = subAdminKeys.get(apiKey);
    if (cached && cached.device === deviceFingerprint) {
      if (cached.expiry_timestamp > Date.now() && cached.is_active) {
        req.subAdminKey = cached;
        req.subAdminKeyId = cached.keyId;
        return next();
      }
    }
    
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

const checkSubAdminPermission = (requiredPermission) => {
  return (req, res, next) => {
    const keyData = req.subAdminKey;
    
    const permissions = {
      'full': ['view', 'add', 'extend', 'edit', 'delete'],
      'add_only': ['view', 'add'],
      'extend_only': ['view', 'extend'],
      'view_only': ['view'],
      'delete_only': ['view', 'delete'],
      'stats_only': ['view']
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

// ═══════════════════════════════════════════
// Logger Middleware
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
// PUBLIC ENDPOINTS
// ═══════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    version: '3.4.0', 
    uptime: Math.floor(process.uptime()), 
    timestamp: Date.now() 
  });
});

app.get('/api/serverTime', apiLimiter, (req, res) => {
  res.json({ 
    success: true, 
    server_time: Date.now(), 
    formatted: new Date().toISOString() 
  });
});

// ═══════════════════════════════════════════
// 📱 MOBILE APP ENDPOINTS
// ═══════════════════════════════════════════
app.post('/api/getUser', authApp, apiLimiter, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json(null);
    }
    
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) {
      return res.json(null);
    }
    
    const userId = Object.keys(users)[0];
    const user = users[userId];
    
    res.json({
      username: user.username,
      password_hash: user.password_hash,
      is_active: user.is_active !== false,
      device_id: user.device_id || '',
      expiry_date: formatDate(user.subscription_end),
      subscription_end: user.subscription_end
    });
    
  } catch (error) {
    console.error('Get user error:', error.message);
    res.status(500).json(null);
  }
});

app.post('/api/verifyAccount', authApp, apiLimiter, async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing fields', 
        code: 400 
      });
    }
    
    const passHash = hashPassword(password);
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) {
      return res.json({ success: false, code: 1 });
    }
    
    const userId = Object.keys(users)[0];
    const user = users[userId];
    
    if (user.password_hash !== passHash) {
      return res.json({ success: false, code: 2 });
    }
    
    if (!user.is_active) {
      return res.json({ success: false, code: 3 });
    }
    
    if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
      return res.json({ success: false, code: 4 });
    }
    
    res.json({ 
      success: true, 
      username: user.username, 
      code: 200 
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

app.post('/api/updateDevice', authApp, apiLimiter, async (req, res) => {
  try {
    const { username, deviceId } = req.body;
    
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
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
      device_id: deviceId, 
      last_login: Date.now(),
      login_count: (user.login_count || 0) + 1
    });
    
    res.json({ 
      success: true, 
      message: 'Device updated' 
    });
    
  } catch (error) {
    console.error('Update device error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Server error' 
    });
  }
});

// ═══════════════════════════════════════════
// 👑 MASTER ADMIN - AUTH
// ═══════════════════════════════════════════

app.post('/api/admin/login', loginLimiter, bruteForceProtection, async (req, res) => {
  try {
    const { username, password } = req.body;
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username and password required' 
      });
    }
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    if (username !== ADMIN_CREDENTIALS.username || password !== ADMIN_CREDENTIALS.password) {
      const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
      attempt.count++;
      attempt.lastAttempt = Date.now();
      loginAttempts.set(ip, attempt);
      
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid credentials' 
      });
    }
    
    loginAttempts.delete(ip);
    const sessionToken = generateToken();
    
    adminSessions.set(sessionToken, { 
      username, 
      ip, 
      createdAt: Date.now(), 
      userAgent: req.headers['user-agent'] 
    });
    
    console.log(`✅ Admin login: ${username} from ${ip}`);
    
    res.json({ 
      success: true, 
      sessionToken, 
      expiresIn: '24 hours' 
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error' 
    });
  }
});

app.post('/api/admin/logout', authAdmin, (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  if (sessionToken) {
    adminSessions.delete(sessionToken);
  }
  res.json({ 
    success: true, 
    message: 'Logged out' 
  });
});

app.get('/api/admin/verify-session', authAdmin, (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  const session = adminSessions.get(sessionToken);
  
  if (session) {
    const expiresIn = 24 * 60 * 60 * 1000 - (Date.now() - session.createdAt);
    res.json({
      success: true,
      session: { 
        username: session.username, 
        expires_in: Math.floor(expiresIn / 1000 / 60) + ' minutes' 
      },
      server_info: { 
        active_sessions: adminSessions.size, 
        uptime: Math.floor(process.uptime()) 
      }
    });
  } else {
    res.json({
      success: true,
      session: { 
        username: 'master_owner', 
        expires_in: 'unlimited' 
      },
      server_info: { 
        active_sessions: adminSessions.size, 
        uptime: Math.floor(process.uptime()) 
      }
    });
  }
});

// ═══════════════════════════════════════════
// 👑 MASTER ADMIN - USER MANAGEMENT
// ═══════════════════════════════════════════
app.get('/api/admin/users', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const formattedUsers = {};
    for (const [id, user] of Object.entries(users)) {
      const subEnd = user.subscription_end || 0;
      formattedUsers[id] = {
        username: user.username || '',
        is_active: user.is_active !== false,
        status: user.status || 'active',
        expiry_timestamp: subEnd,
        expiry_date: formatDate(subEnd),
        created_at: user.created_at || null,
        last_login: user.last_login || null,
        login_count: user.login_count || 0,
        device_id: user.device_id || '',
        max_devices: user.max_devices || 1,
        storage_used: user.storage_used || 0,
        max_storage: user.max_storage || 100,
        speed_limit: user.speed_limit || 10,
        notes: user.notes || '',
        created_by_key: user.created_by_key || 'master'
      };
    }
    
    res.json({ 
      success: true, 
      data: formattedUsers, 
      count: Object.keys(formattedUsers).length 
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
        status: user.status || 'active',
        expiry_timestamp: user.subscription_end || 0,
        expiry_date: formatDate(user.subscription_end),
        device_id: user.device_id || '',
        max_devices: user.max_devices || 1,
        created_by_key: user.created_by_key || 'master'
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

// ✅ NEW: Get detailed user information
app.get('/api/admin/users/:id/details', authAdmin, apiLimiter, async (req, res) => {
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
        username: user.username || '',
        email: user.email || '',
        is_active: user.is_active !== false,
        status: user.status || 'active',
        device_id: user.device_id || '',
        max_devices: user.max_devices || 1,
        created_at: user.created_at || null,
        last_login: user.last_login || null,
        login_count: user.login_count || 0,
        expiry_timestamp: user.subscription_end || 0,
        expiry_date: formatDate(user.subscription_end),
        storage_used: user.storage_used || 0,
        max_storage: user.max_storage || 100,
        speed_limit: user.speed_limit || 10,
        notes: user.notes || '',
        ip_address: user.ip_address || null,
        user_agent: user.user_agent || null,
        created_by_key: user.created_by_key || 'master'
      }
    });
    
  } catch (error) {
    console.error('Get user details error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch user details' 
    });
  }
});

app.post('/api/admin/users', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { 
      username, 
      password, 
      expiryMinutes, 
      customExpiryDate, 
      unlimited,
      maxDevices, 
      status,
      storage_limit,
      speed_limit
    } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username and password required' 
      });
    }
    
    const checkUrl = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const checkRes = await firebase.get(checkUrl);
    
    if (checkRes.data && Object.keys(checkRes.data).length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username already exists' 
      });
    }
    
    let expiryTimestamp;
    if (unlimited) {
      expiryTimestamp = 0;
    } else if (customExpiryDate) {
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
      status: status || 'active',
      subscription_end: expiryTimestamp,
      max_devices: maxDevices || 1,
      max_storage: storage_limit || 100,
      speed_limit: speed_limit || 10,
      storage_used: 0,
      device_id: '',
      created_at: Date.now(),
      last_login: null,
      login_count: 0,
      created_by_key: 'master'
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

app.patch('/api/admin/users/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { is_active, max_devices, notes, status, storage_limit, speed_limit } = req.body;
    const updateData = {};
    
    if (typeof is_active === 'boolean') updateData.is_active = is_active;
    if (max_devices) updateData.max_devices = max_devices;
    if (notes !== undefined) updateData.notes = notes;
    if (status) updateData.status = status;
    if (storage_limit) updateData.max_storage = storage_limit;
    if (speed_limit) updateData.speed_limit = speed_limit;
    
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

app.delete('/api/admin/users/:id', authAdmin, apiLimiter, async (req, res) => {
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

app.post('/api/admin/users/delete-expired', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    const now = Date.now();
    
    const deletePromises = [];
    let expiredIds = [];
    
    for (const [id, user] of Object.entries(users)) {
      if (user.subscription_end && user.subscription_end > 0 && user.subscription_end <= now) {
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

app.post('/api/admin/users/:id/extend', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { minutes, days, hours } = req.body;
    
    const userRes = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    const now = Date.now();
    const currentEnd = user.subscription_end || now;
    
    let extensionMs = 0;
    if (minutes) {
      extensionMs = minutes * 60 * 1000;
    } else if (days || hours) {
      extensionMs = ((days || 0) * 24 * 60 * 60 * 1000) + ((hours || 0) * 60 * 60 * 1000);
    }
    
    if (!extensionMs) {
      return res.status(400).json({ 
        success: false, 
        error: 'Extension time required' 
      });
    }
    
    const newEndDate = (currentEnd > now ? currentEnd : now) + extensionMs;
    
    await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, {
      subscription_end: newEndDate,
      is_active: true
    });
    
    res.json({ 
      success: true, 
      message: 'Subscription extended', 
      new_end_date: newEndDate 
    });
    
  } catch (error) {
    console.error('Extend subscription error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to extend subscription' 
    });
  }
});

app.post('/api/admin/users/:id/reset-device', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, { 
      device_id: '' 
    });
    
    console.log(`🔄 Device reset for user: ${req.params.id}`);
    
    res.json({ 
      success: true, 
      message: 'Device reset' 
    });
    
  } catch (error) {
    console.error('Reset device error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to reset device' 
    });
  }
});

// ═══════════════════════════════════════════
// 👑 MASTER ADMIN - API KEYS MANAGEMENT
// ═══════════════════════════════════════════
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
        created_at: key.created_at || null,
        last_used: key.last_used || null
      };
    }
    
    res.json({ 
      success: true, 
      data: formattedKeys, 
      count: Object.keys(formattedKeys).length 
    });
    
  } catch (error) {
    console.error('Get API keys error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch API keys' 
    });
  }
});

app.post('/api/admin/api-keys', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { 
      adminName, 
      permissionLevel, 
      expiryDays, 
      unlimited
    } = req.body;
    
    if (!adminName) {
      return res.status(400).json({ 
        success: false, 
        error: 'Admin name required' 
      });
    }
    
    const apiKey = `AK_${crypto.randomBytes(16).toString('hex')}`;
    
    let expiryTimestamp;
    if (unlimited) {
      expiryTimestamp = null;
    } else {
      expiryTimestamp = Date.now() + ((expiryDays || 30) * 24 * 60 * 60 * 1000);
    }
    
    const keyData = {
      api_key: apiKey,
      admin_name: adminName,
      permission_level: permissionLevel || 'view_only',
      is_active: true,
      expiry_timestamp: expiryTimestamp,
      usage_count: 0,
      bound_device: null,
      created_at: Date.now(),
      last_used: null
    };
    
    await firebase.post(`api_keys.json?auth=${FB_KEY}`, keyData);
    
    console.log(`🔑 API Key created for: ${adminName}`);
    
    res.json({ 
      success: true, 
      message: 'API Key created', 
      apiKey 
    });
    
  } catch (error) {
    console.error('Create API key error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create API key' 
    });
  }
});

app.patch('/api/admin/api-keys/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { is_active } = req.body;
    
    await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, { 
      is_active 
    });
    
    res.json({ 
      success: true, 
      message: 'API Key updated' 
    });
    
  } catch (error) {
    console.error('Update API key error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update API key' 
    });
  }
});

app.delete('/api/admin/api-keys/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.delete(`api_keys/${req.params.id}.json?auth=${FB_KEY}`);
    
    console.log(`🗑️ API Key deleted: ${req.params.id}`);
    
    res.json({ 
      success: true, 
      message: 'API Key deleted' 
    });
    
  } catch (error) {
    console.error('Delete API key error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete API key' 
    });
  }
});

app.post('/api/admin/api-keys/:id/unbind-device', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, { 
      bound_device: null 
    });
    
    console.log(`🔓 Device unbound from API key: ${req.params.id}`);
    
    res.json({ 
      success: true, 
      message: 'Device unbound' 
    });
    
  } catch (error) {
    console.error('Unbind device error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to unbind device' 
    });
  }
});

// ═══════════════════════════════════════════
// 👨‍💼 MASTER ADMIN - SUB-ADMINS MANAGEMENT
// ═══════════════════════════════════════════

app.get('/api/admin/subadmins', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`subadmins.json?auth=${FB_KEY}`);
    const subadmins = response.data || {};
    
    const formattedSubadmins = {};
    for (const [id, subadmin] of Object.entries(subadmins)) {
      formattedSubadmins[id] = {
        name: subadmin.name || '',
        email: subadmin.email || '',
        permissions: subadmin.permissions || [],
        is_active: subadmin.is_active !== false,
        expiry_timestamp: subadmin.expiry_timestamp || null,
        expiry_date: formatDate(subadmin.expiry_timestamp),
        max_devices: subadmin.max_devices || 1,
        access_token: subadmin.access_token || '',
        created_at: subadmin.created_at || null,
        last_active: subadmin.last_active || null,
        usage_count: subadmin.usage_count || 0
      };
    }
    
    res.json({ 
      success: true, 
      data: formattedSubadmins, 
      count: Object.keys(formattedSubadmins).length 
    });
    
  } catch (error) {
    console.error('Get subadmins error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch subadmins' 
    });
  }
});

app.post('/api/admin/subadmins', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { 
      name, 
      email, 
      permissions, 
      expiry_days, 
      max_devices 
    } = req.body;
    
    if (!name || !permissions || permissions.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Name and at least one permission required' 
      });
    }
    
    const accessToken = `SA_${crypto.randomBytes(20).toString('hex')}`;
    
    const expiryTimestamp = expiry_days === 0 
      ? null 
      : Date.now() + (expiry_days * 24 * 60 * 60 * 1000);
    
    const subadminData = {
      name,
      email: email || '',
      permissions,
      is_active: true,
      expiry_timestamp: expiryTimestamp,
      max_devices: max_devices || 2,
      access_token: accessToken,
      created_at: Date.now(),
      last_active: null,
      usage_count: 0
    };
    
    const createRes = await firebase.post(`subadmins.json?auth=${FB_KEY}`, subadminData);
    
    console.log(`👨‍💼 Sub-Admin created: ${name}`);
    
    res.json({ 
      success: true, 
      message: 'Sub-Admin created', 
      access_token: accessToken,
      subadmin_id: createRes.data.name
    });
    
  } catch (error) {
    console.error('Create subadmin error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create subadmin' 
    });
  }
});

app.post('/api/admin/subadmins/:id/toggle', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { is_active } = req.body;
    
    await firebase.patch(`subadmins/${req.params.id}.json?auth=${FB_KEY}`, { 
      is_active 
    });
    
    console.log(`🔄 Sub-Admin toggled: ${req.params.id} -> ${is_active ? 'active' : 'inactive'}`);
    
    res.json({ 
      success: true, 
      message: 'Sub-Admin status updated' 
    });
    
  } catch (error) {
    console.error('Toggle subadmin error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to toggle subadmin' 
    });
  }
});

app.delete('/api/admin/subadmins/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    await firebase.delete(`subadmins/${req.params.id}.json?auth=${FB_KEY}`);
    
    console.log(`🗑️ Sub-Admin deleted: ${req.params.id}`);
    
    res.json({ 
      success: true, 
      message: 'Sub-Admin deleted' 
    });
    
  } catch (error) {
    console.error('Delete subadmin error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete subadmin' 
    });
  }
});

// ═══════════════════════════════════════════
// 🔑 SUB ADMIN API
// ═══════════════════════════════════════════

app.post('/api/sub/verify-key', apiLimiter, async (req, res) => {
  try {
    const { apiKey, deviceFingerprint } = req.body;
    
    if (!apiKey) {
      return res.status(400).json({ 
        success: false, 
        error: 'API key required' 
      });
    }
    
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
    
    if (!foundKey.bound_device) {
      await firebase.patch(`api_keys/${keyId}.json?auth=${FB_KEY}`, { 
        bound_device: deviceFingerprint 
      });
    } else if (foundKey.bound_device !== deviceFingerprint) {
      return res.status(403).json({ 
        success: false, 
        error: 'Key is bound to another device' 
      });
    }
    
    await firebase.patch(`api_keys/${keyId}.json?auth=${FB_KEY}`, {
      usage_count: (foundKey.usage_count || 0) + 1,
      last_used: Date.now()
    });
    
    subAdminKeys.set(apiKey, {
      ...foundKey,
      keyId,
      device: deviceFingerprint,
      last_used: Date.now()
    });
    
    console.log(`✅ Sub Admin verified: ${foundKey.admin_name} (ID: ${keyId})`);
    
    res.json({
      success: true,
      name: foundKey.admin_name,
      permission: foundKey.permission_level || 'view_only',
      key_id: keyId
    });
    
  } catch (error) {
    console.error('Verify key error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Server error' 
    });
  }
});

app.get('/api/sub/users', authSubAdmin, checkSubAdminPermission('view'), apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const currentKeyId = req.subAdminKeyId;
    const formattedUsers = {};
    
    for (const [id, user] of Object.entries(users)) {
      if (user.created_by_key === currentKeyId) {
        const subEnd = user.subscription_end || 0;
        formattedUsers[id] = {
          username: user.username || '',
          is_active: user.is_active !== false,
          status: user.status || 'active',
          expiry_timestamp: subEnd,
          expiry_date: formatDate(subEnd),
          device_id: user.device_id || '',
          max_devices: user.max_devices || 1,
          last_login: user.last_login || 0,
          login_count: user.login_count || 0,
          created_at: user.created_at || 0,
          created_by: user.created_by || 'sub_admin',
          created_by_key: user.created_by_key || null
        };
      }
    }
    
    res.json({ 
      success: true, 
      data: formattedUsers, 
      count: Object.keys(formattedUsers).length 
    });
    
  } catch (error) {
    console.error('Sub Admin get users error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch users' 
    });
  }
});

app.get('/api/sub/users/:id/details', authSubAdmin, checkSubAdminPermission('view'), apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    if (user.created_by_key !== currentKeyId) {
      return res.status(403).json({ 
        success: false, 
        error: 'You can only view users you created' 
      });
    }
    
    res.json({
      success: true,
      data: {
        username: user.username || '',
        is_active: user.is_active !== false,
        status: user.status || 'active',
        device_id: user.device_id || '',
        max_devices: user.max_devices || 1,
        last_login: user.last_login || 0,
        login_count: user.login_count || 0,
        created_at: user.created_at || 0,
        subscription_end: user.subscription_end || 0,
        expiry_date: formatDate(user.subscription_end),
        created_by: user.created_by || 'sub_admin',
        notes: user.notes || '',
        email: user.email || '',
        storage_used: user.storage_used || 0,
        max_storage: user.max_storage || 100
      }
    });
    
  } catch (error) {
    console.error('Get user details error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to get user details' 
    });
  }
});

app.get('/api/sub/stats', authSubAdmin, checkSubAdminPermission('view'), apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const currentKeyId = req.subAdminKeyId;
    const now = Date.now();
    
    let totalUsers = 0;
    let activeUsers = 0;
    let expiredUsers = 0;
    
    for (const user of Object.values(users)) {
      if (user.created_by_key === currentKeyId) {
        totalUsers++;
        if (user.is_active !== false) {
          activeUsers++;
        }
        if (user.subscription_end && user.subscription_end > 0 && user.subscription_end <= now) {
          expiredUsers++;
        }
      }
    }
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        activeUsers,
        expiredUsers
      }
    });
    
  } catch (error) {
    console.error('Sub Admin stats error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to get stats' 
    });
  }
});

app.post('/api/sub/users', authSubAdmin, checkSubAdminPermission('add'), apiLimiter, async (req, res) => {
  try {
    const { username, password, expiryMinutes, customExpiryDate, maxDevices, status, storage_limit, speed_limit } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username and password required' 
      });
    }
    
    const checkUrl = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const checkRes = await firebase.get(checkUrl);
    
    if (checkRes.data && Object.keys(checkRes.data).length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username already exists' 
      });
    }
    
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
      status: status || 'active',
      subscription_end: expiryTimestamp,
      max_devices: maxDevices || 1,
      max_storage: storage_limit || 100,
      speed_limit: speed_limit || 10,
      storage_used: 0,
      device_id: '',
      created_at: Date.now(),
      last_login: null,
      login_count: 0,
      created_by_key: req.subAdminKeyId,
      created_by: req.subAdminKey.admin_name || 'sub_admin'
    };
    
    const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
    
    console.log(`✅ User created by Sub Admin [${req.subAdminKeyId}]: ${username}`);
    
    res.json({ 
      success: true, 
      message: 'User created', 
      userId: createRes.data.name,
      expiry_date: formatDate(expiryTimestamp)
    });
    
  } catch (error) {
    console.error('Sub Admin create user error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create user' 
    });
  }
});

app.post('/api/sub/users/:id/extend', authSubAdmin, checkSubAdminPermission('extend'), apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    const { minutes, days, hours } = req.body;
    
    if (!minutes && !days && !hours) {
      return res.status(400).json({ 
        success: false, 
        error: 'Extension time required' 
      });
    }
    
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    if (user.created_by_key !== currentKeyId) {
      return res.status(403).json({ 
        success: false, 
        error: 'You can only extend users you created' 
      });
    }
    
    const now = Date.now();
    const currentEnd = user.subscription_end || now;
    
    let extensionMs = 0;
    if (minutes) {
      extensionMs = minutes * 60 * 1000;
    } else if (days || hours) {
      extensionMs = ((days || 0) * 24 * 60 * 60 * 1000) + ((hours || 0) * 60 * 60 * 1000);
    }
    
    const newEndDate = (currentEnd > now ? currentEnd : now) + extensionMs;
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, {
      subscription_end: newEndDate,
      is_active: true
    });
    
    res.json({ 
      success: true, 
      message: 'Subscription extended', 
      new_end_date: newEndDate,
      formatted_date: formatDate(newEndDate)
    });
    
  } catch (error) {
    console.error('Sub Admin extend error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to extend subscription' 
    });
  }
});

app.patch('/api/sub/users/:id', authSubAdmin, checkSubAdminPermission('edit'), apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    const { is_active, status } = req.body;
    
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    if (user.created_by_key !== currentKeyId) {
      return res.status(403).json({ 
        success: false, 
        error: 'You can only edit users you created' 
      });
    }
    
    const updateData = {};
    if (typeof is_active === 'boolean') updateData.is_active = is_active;
    if (status) updateData.status = status;
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, updateData);
    
    res.json({ 
      success: true, 
      message: 'User updated' 
    });
    
  } catch (error) {
    console.error('Sub Admin update user error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update user' 
    });
  }
});

app.post('/api/sub/users/:id/reset-device', authSubAdmin, checkSubAdminPermission('edit'), apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    if (user.created_by_key !== currentKeyId) {
      return res.status(403).json({ 
        success: false, 
        error: 'You can only reset device for users you created' 
      });
    }
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
      device_id: '' 
    });
    
    res.json({ 
      success: true, 
      message: 'Device reset' 
    });
    
  } catch (error) {
    console.error('Sub Admin reset device error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to reset device' 
    });
  }
});

app.delete('/api/sub/users/:id', authSubAdmin, checkSubAdminPermission('delete'), apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    if (user.created_by_key !== currentKeyId) {
      return res.status(403).json({ 
        success: false, 
        error: 'You can only delete users you created' 
      });
    }
    
    await firebase.delete(`users/${userId}.json?auth=${FB_KEY}`);
    
    res.json({ 
      success: true, 
      message: 'User deleted' 
    });
    
  } catch (error) {
    console.error('Sub Admin delete user error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete user' 
    });
  }
});

// ═══════════════════════════════════════════
// تنظيف دوري
// ═══════════════════════════════════════════
setInterval(() => {
  const now = Date.now();
  for (const [apiKey, keyData] of subAdminKeys.entries()) {
    if (now - keyData.last_used > 30 * 60 * 1000) {
      subAdminKeys.delete(apiKey);
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// 🛠️ MAINTENANCE ENDPOINTS
// ═══════════════════════════════════════════

app.post('/api/admin/fix-old-users', authAdmin, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    let fixed = 0;
    let alreadyFixed = 0;
    
    for (const [id, user] of Object.entries(users)) {
      if (!user.created_by_key) {
        await firebase.patch(`users/${id}.json?auth=${FB_KEY}`, {
          created_by_key: 'master'
        });
        fixed++;
      } else {
        alreadyFixed++;
      }
    }
    
    res.json({ 
      success: true, 
      message: `Fixed ${fixed} old users. ${alreadyFixed} already had created_by_key`,
      fixed,
      alreadyFixed
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

app.get('/api/admin/debug-users', authAdmin, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const debugInfo = [];
    let withKey = 0;
    let withoutKey = 0;
    let masterUsers = 0;
    let subAdminUsers = 0;
    
    for (const [id, user] of Object.entries(users)) {
      const keyStatus = user.created_by_key || 'MISSING';
      
      debugInfo.push({
        id: id.substring(0, 10) + '...',
        username: user.username,
        created_by_key: keyStatus,
        created_at: formatDate(user.created_at)
      });
      
      if (user.created_by_key) {
        withKey++;
        if (user.created_by_key === 'master') {
          masterUsers++;
        } else {
          subAdminUsers++;
        }
      } else {
        withoutKey++;
      }
    }
    
    res.json({
      success: true,
      summary: {
        total: Object.keys(users).length,
        withKey,
        withoutKey,
        masterUsers,
        subAdminUsers
      },
      users: debugInfo
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// ═══════════════════════════════════════════
// HOME PAGE
// ═══════════════════════════════════════════
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🛡️ Secure API v3.4.0</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #1a1a2e, #16213e);
      color: #fff;
      min-height: 100vh;
      padding: 40px 20px;
      text-align: center;
    }
    .container { max-width: 900px; margin: 0 auto; }
    h1 { color: #4cc9f0; margin-bottom: 20px; font-size: 2.5rem; }
    .badge {
      background: linear-gradient(135deg, #10b981, #059669);
      padding: 10px 20px;
      border-radius: 20px;
      display: inline-block;
      margin: 20px 0;
      font-weight: bold;
    }
    .new { 
      background: #ef4444;
      color: white;
      padding: 2px 8px;
      border-radius: 3px;
      font-size: 10px;
      margin-right: 8px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Secure Firebase Proxy</h1>
    <div class="badge">✅ v3.4.0 - All Endpoints Active</div>
    
    <p style="margin-top: 30px; color: #64748b; font-size: 0.9rem;">
      <span class="new">FIXED</span> User details endpoint active<br>
      <span class="new">FIXED</span> Sub-Admins endpoints active<br>
      🔒 Protected by Rate Limiting & Authentication<br>
      ✅ Master Admin Direct Access Enabled
    </p>
  </div>
</body>
</html>`);
});

// ═══════════════════════════════════════════
// ERROR HANDLERS
// ═══════════════════════════════════════════
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    error: 'Endpoint not found', 
    code: 404 
  });
});

app.use((err, req, res, next) => {
  console.error('Server error:', err.message);
  res.status(500).json({ 
    success: false, 
    error: 'Internal server error', 
    code: 500 
  });
});

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════
app.listen(PORT, () => {
  console.log('═'.repeat(60));
  console.log('🛡️  Secure Firebase Proxy v3.4.0');
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'production'}`);
  console.log('');
  console.log('✓ Master Admin endpoints ready');
  console.log('✓ User details endpoint active');
  console.log('✓ Sub-Admins endpoints active');
  console.log('✓ Sub Admin endpoints ready');
  console.log('✓ Mobile App endpoints ready');
  console.log('');
  console.log('═'.repeat(60));
});
