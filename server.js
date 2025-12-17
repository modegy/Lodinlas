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
  contentSecurityPolicy: false, // تسبب مشاكل في Render
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
// 3️⃣ RATE LIMITING (متعدد المستويات)
// ═══════════════════════════════════════════
const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: { success: false, error: message },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      // الحصول على IP حقيقي على Render
      return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
             req.headers['x-real-ip'] || 
             req.ip || 
             req.connection.remoteAddress;
    }
  });
};

// Global limiter
const globalLimiter = createRateLimiter(60 * 1000, 100, 'Too many requests, please try again later');
app.use('/', globalLimiter);

// Login limiter
const loginLimiter = createRateLimiter(15 * 60 * 1000, 5, 'Too many login attempts');
// API limiter
const apiLimiter = createRateLimiter(60 * 1000, 50, 'API rate limit exceeded');

// ═══════════════════════════════════════════
// 4️⃣ BODY PARSER
// ═══════════════════════════════════════════
app.use(express.json({ 
  limit: '2mb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf.toString());
    } catch (e) {
      res.status(400).json({ success: false, error: 'Invalid JSON' });
    }
  }
}));

// ═══════════════════════════════════════════
// 5️⃣ ANTI-BRUTE FORCE (مبسط)
// ═══════════════════════════════════════════
const loginAttempts = new Map();

const bruteForceProtection = (req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  
  if (!loginAttempts.has(ip)) {
    loginAttempts.set(ip, { count: 0, lastAttempt: Date.now() });
  }
  
  const attempt = loginAttempts.get(ip);
  
  // Reset if last attempt was more than 15 minutes ago
  if (Date.now() - attempt.lastAttempt > 15 * 60 * 1000) {
    attempt.count = 0;
  }
  
  // If blocked
  if (attempt.count >= 5) {
    return res.status(429).json({
      success: false,
      error: `Too many attempts. Try again in ${Math.ceil((15 * 60 * 1000 - (Date.now() - attempt.lastAttempt)) / 1000 / 60)} minutes`
    });
  }
  
  next();
};

// Clean old attempts every hour
setInterval(() => {
  const now = Date.now();
  for (const [ip, attempt] of loginAttempts.entries()) {
    if (now - attempt.lastAttempt > 60 * 60 * 1000) {
      loginAttempts.delete(ip);
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// 6️⃣ FIREBASE CONFIGURATION
// ═══════════════════════════════════════════
const firebase = axios.create({ 
  baseURL: process.env.FIREBASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
});

const FB_KEY = process.env.FIREBASE_KEY;

// ═══════════════════════════════════════════
// 7️⃣ SESSION MANAGEMENT
// ═══════════════════════════════════════════
const adminSessions = new Map();
const APP_API_KEY = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';

// Admin credentials
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

// Session cleanup every hour
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of adminSessions.entries()) {
    if (now - session.createdAt > 24 * 60 * 60 * 1000) {
      adminSessions.delete(token);
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// 8️⃣ AUTHENTICATION MIDDLEWARES
// ═══════════════════════════════════════════
const authApp = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ 
      success: false, 
      error: 'API Key is required',
      code: 401 
    });
  }
  
  // Simple comparison for now
  if (apiKey === APP_API_KEY) {
    return next();
  }
  
  res.status(401).json({ 
    success: false, 
    error: 'Invalid API Key',
    code: 401 
  });
};

const authAdmin = (req, res, next) => {
  const sessionToken = req.headers['x-session-token'];
  
  if (!sessionToken) {
    return res.status(401).json({ 
      success: false, 
      error: 'Session token required',
      code: 401 
    });
  }
  
  const session = adminSessions.get(sessionToken);
  
  if (!session) {
    return res.status(401).json({ 
      success: false, 
      error: 'Invalid or expired session',
      code: 401 
    });
  }
  
  // Check if session expired (24 hours)
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

// ═══════════════════════════════════════════
// 9️⃣ REQUEST LOGGING
// ═══════════════════════════════════════════
app.use((req, res, next) => {
  const startTime = Date.now();
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    // Log slow requests or errors
    if (duration > 1000 || res.statusCode >= 400) {
      console.log(`📊 ${req.method} ${req.path} | IP: ${ip} | Status: ${res.statusCode} | Time: ${duration}ms`);
    }
  });
  
  next();
});

// ═══════════════════════════════════════════
// 🔟 API ENDPOINTS
// ═══════════════════════════════════════════

// 🔹 Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: '3.0.0-secure',
    uptime: Math.floor(process.uptime()),
    timestamp: Date.now(),
    features: {
      rateLimiting: true,
      bruteForceProtection: true,
      helmet: true,
      cors: true
    }
  });
});

// 🔹 Server Time
app.get('/api/serverTime', apiLimiter, (req, res) => {
  res.json({
    success: true,
    server_time: Date.now(),
    unixtime: Math.floor(Date.now() / 1000),
    formatted: new Date().toISOString()
  });
});

// 🔹 Admin Login
app.post('/api/admin/login', loginLimiter, bruteForceProtection, (req, res) => {
  try {
    const { username, password } = req.body;
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username and password are required' 
      });
    }
    
    // Compare with admin credentials
    if (username !== ADMIN_CREDENTIALS.username || password !== ADMIN_CREDENTIALS.password) {
      // Record failed attempt
      const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
      attempt.count++;
      attempt.lastAttempt = Date.now();
      loginAttempts.set(ip, attempt);
      
      // Delayed response for security
      setTimeout(() => {
        res.status(401).json({ 
          success: false, 
          error: 'Invalid credentials' 
        });
      }, 1500);
      
      return;
    }
    
    // Reset attempts on successful login
    loginAttempts.delete(ip);
    
    // Generate session token
    const sessionToken = generateToken();
    
    adminSessions.set(sessionToken, {
      username,
      ip,
      createdAt: Date.now(),
      userAgent: req.headers['user-agent']
    });
    
    console.log(`✅ Admin login successful: ${username} from ${ip}`);
    
    res.json({
      success: true,
      sessionToken,
      expiresIn: '24 hours',
      message: 'Login successful'
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// 🔹 Admin Logout
app.post('/api/admin/logout', authAdmin, (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  
  if (sessionToken && adminSessions.has(sessionToken)) {
    adminSessions.delete(sessionToken);
  }
  
  res.json({ success: true, message: 'Logged out successfully' });
});

// 🔹 Verify Account (For Mobile App)
app.post('/api/verifyAccount', authApp, apiLimiter, async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields',
        code: 400 
      });
    }
    
    const passHash = hashPassword(password);
    
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) {
      return res.json({ success: false, code: 1 }); // User not found
    }
    
    const userId = Object.keys(users)[0];
    const user = users[userId];
    
    // Check password
    if (user.password_hash !== passHash) {
      return res.json({ success: false, code: 2 }); // Wrong password
    }
    
    // Check if user is active
    if (!user.is_active) {
      return res.json({ success: false, code: 3 }); // User inactive
    }
    
    // Check device binding if exists
    if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
      return res.json({ success: false, code: 4 }); // Wrong device
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
      code: 0, // Server error
      error: 'Server error' 
    });
  }
});

// 🔹 Update Device
app.post('/api/updateDevice', authApp, apiLimiter, async (req, res) => {
  try {
    const { username, deviceId } = req.body;
    
    if (!username || !deviceId) {
      return res.status(400).json({ success: false, error: 'Missing data' });
    }
    
    const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    
    const users = response.data || {};
    
    if (Object.keys(users).length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    const userId = Object.keys(users)[0];
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, {
      device_id: deviceId,
      last_login: Date.now()
    });
    
    res.json({ success: true, message: 'Device updated successfully' });
    
  } catch (error) {
    console.error('Update device error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ═══════════════════════════════════════════
// 🆕 ADMIN PANEL ENDPOINTS
// ═══════════════════════════════════════════

// 🔹 1. Get All Users
app.get('/api/admin/users', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    // Format users data
    const formattedUsers = Object.keys(users).map(userId => ({
      id: userId,
      username: users[userId].username || '',
      is_active: users[userId].is_active || false,
      subscription_end: users[userId].subscription_end || null,
      created_at: users[userId].created_at || null,
      last_login: users[userId].last_login || null,
      device_id: users[userId].device_id || '',
      notes: users[userId].notes || ''
    }));
    
    res.json({
      success: true,
      count: formattedUsers.length,
      users: formattedUsers
    });
    
  } catch (error) {
    console.error('Get users error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch users' 
    });
  }
});

// 🔹 2. Get Single User by ID
app.get('/api/admin/users/:id', authAdmin, apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }
    
    const response = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    const user = response.data;
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    res.json({
      success: true,
      user: {
        id: userId,
        username: user.username || '',
        password_hash: user.password_hash || '',
        is_active: user.is_active || false,
        subscription_end: user.subscription_end || null,
        created_at: user.created_at || null,
        last_login: user.last_login || null,
        device_id: user.device_id || '',
        notes: user.notes || ''
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

// 🔹 3. Extend User Subscription
app.post('/api/admin/users/:id/extend', authAdmin, apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const { days, hours } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }
    
    if ((!days && !hours) || (days < 0 || hours < 0)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Please provide valid extension time (days or hours)' 
      });
    }
    
    // Get current user data
    const userResponse = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    const user = userResponse.data;
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const now = Date.now();
    const currentEnd = user.subscription_end || now;
    const extensionMs = (parseInt(days || 0) * 24 * 60 * 60 * 1000) + 
                       (parseInt(hours || 0) * 60 * 60 * 1000);
    
    let newEndDate;
    
    if (currentEnd > now) {
      // Extend from current end date
      newEndDate = currentEnd + extensionMs;
    } else {
      // Start from now
      newEndDate = now + extensionMs;
    }
    
    // Update user
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, {
      subscription_end: newEndDate,
      is_active: true,
      last_updated: now
    });
    
    res.json({
      success: true,
      message: `Subscription extended successfully`,
      new_end_date: newEndDate,
      formatted_end: new Date(newEndDate).toISOString(),
      user_id: userId,
      username: user.username
    });
    
  } catch (error) {
    console.error('Extend subscription error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to extend subscription' 
    });
  }
});

// 🔹 4. API Keys Management
app.get('/api/admin/api-keys', authAdmin, apiLimiter, async (req, res) => {
  try {
    // في الإصدار الحالي، نستخدم API Key واحد
    // يمكنك توسيع هذا ليدير مفاتيح متعددة
    res.json({
      success: true,
      api_keys: [
        {
          name: 'Main App API Key',
          key: APP_API_KEY.substring(0, 8) + '...',
          created_at: 'System',
          is_active: true,
          usage: 'Mobile app authentication'
        }
      ],
      total: 1,
      message: 'Current API key configuration'
    });
    
  } catch (error) {
    console.error('Get API keys error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch API keys' 
    });
  }
});

// 🔹 5. Verify Admin Session
app.get('/api/admin/verify-session', authAdmin, (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  const session = adminSessions.get(sessionToken);
  
  if (!session) {
    return res.status(401).json({ 
      success: false, 
      error: 'Invalid session' 
    });
  }
  
  const sessionAge = Date.now() - session.createdAt;
  const expiresIn = 24 * 60 * 60 * 1000 - sessionAge;
  
  res.json({
    success: true,
    session: {
      username: session.username,
      ip: session.ip,
      created_at: session.createdAt,
      expires_in: Math.floor(expiresIn / 1000 / 60) + ' minutes',
      user_agent: session.userAgent
    },
    server_info: {
      active_sessions: adminSessions.size,
      uptime: Math.floor(process.uptime()),
      version: '3.0.0-secure'
    }
  });
});

// 🔹 Home Page
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>🛡️ Secure Firebase Proxy</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: system-ui; 
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); 
      color: #fff; 
      min-height: 100vh; 
      padding: 40px 20px;
      text-align: center;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { margin-bottom: 40px; }
    .header h1 { 
      font-size: 2.5em; 
      color: #4cc9f0; 
      margin-bottom: 20px;
    }
    .security-badge {
      background: linear-gradient(135deg, #10b981, #059669);
      padding: 15px 30px;
      border-radius: 50px;
      display: inline-block;
      margin: 20px 0;
      font-weight: bold;
    }
    .endpoints {
      background: rgba(255,255,255,0.05);
      padding: 30px;
      border-radius: 15px;
      border: 1px solid rgba(76,201,240,0.2);
      margin: 30px 0;
      text-align: left;
    }
    .endpoint {
      margin: 15px 0;
      padding: 15px;
      background: rgba(255,255,255,0.02);
      border-radius: 10px;
      border-left: 4px solid #4cc9f0;
    }
    .method { 
      display: inline-block; 
      padding: 5px 15px; 
      background: #4cc9f0; 
      border-radius: 5px; 
      margin-right: 10px;
      font-weight: bold;
    }
    .method.get { background: #10b981; }
    .method.post { background: #f59e0b; }
    .method.patch { background: #8b5cf6; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ Secure Firebase Proxy v3.0</h1>
      <div class="security-badge">
        ✅ جميع أنظمة الحماية مفعلة + لوحة إدارة جديدة
      </div>
    </div>
    
    <div class="endpoints">
      <h3>📋 Available Endpoints:</h3>
      
      <div class="endpoint">
        <span class="method get">GET</span>
        <strong>/api/health</strong> - حالة الخادم
      </div>
      
      <div class="endpoint">
        <span class="method post">POST</span>
        <strong>/api/admin/login</strong> - دخول الإدارة
      </div>
      
      <div class="endpoint">
        <span class="method get">GET</span>
        <strong>/api/admin/users</strong> - عرض جميع المستخدمين
      </div>
      
      <div class="endpoint">
        <span class="method get">GET</span>
        <strong>/api/admin/users/:id</strong> - عرض مستخدم محدد
      </div>
      
      <div class="endpoint">
        <span class="method post">POST</span>
        <strong>/api/admin/users/:id/extend</strong> - تجديد اشتراك مستخدم
      </div>
      
      <div class="endpoint">
        <span class="method get">GET</span>
        <strong>/api/admin/api-keys</strong> - إدارة مفاتيح API
      </div>
      
      <div class="endpoint">
        <span class="method get">GET</span>
        <strong>/api/admin/verify-session</strong> - التحقق من الجلسة
      </div>
      
      <div class="endpoint">
        <span class="method post">POST</span>
        <strong>/api/verifyAccount</strong> - التحقق من الحساب (للتطبيق)
      </div>
      
      <div class="endpoint">
        <span class="method get">GET</span>
        <strong>/api/serverTime</strong> - وقت الخادم
      </div>
    </div>
    
    <p style="color: #94a3b8; margin-top: 40px;">
      🔐 Secure Proxy System | Render Hosted | Advanced Protection | Admin Panel v1.0
    </p>
  </div>
</body>
</html>
  `);
});

// ═══════════════════════════════════════════
// 🚫 404 HANDLER
// ═══════════════════════════════════════════
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    error: 'Endpoint not found',
    code: 404 
  });
});

// ═══════════════════════════════════════════
// ⚠️ ERROR HANDLER
// ═══════════════════════════════════════════
app.use((err, req, res, next) => {
  console.error('Server error:', err.message || err);
  
  res.status(500).json({ 
    success: false, 
    error: 'Internal server error',
    code: 500 
  });
});

// ═══════════════════════════════════════════
// 🚀 START SERVER
// ═══════════════════════════════════════════
app.listen(PORT, () => {
  console.log('═'.repeat(50));
  console.log('🛡️  SECURE Firebase Proxy v3.0');
  console.log(`📡 Server is running on port: ${PORT}`);
  console.log(`🌐 URL: https://lodinlas.onrender.com`);
  console.log('🔐 Security Features:');
  console.log('   ✓ Rate Limiting (100 req/min)');
  console.log('   ✓ Brute Force Protection');
  console.log('   ✓ CORS Protection');
  console.log('   ✓ Helmet Security');
  console.log('   ✓ Admin Panel Endpoints');
  console.log('═'.repeat(50));
  console.log('📊 Admin Endpoints Added:');
  console.log('   ✓ GET /api/admin/users');
  console.log('   ✓ GET /api/admin/users/:id');
  console.log('   ✓ POST /api/admin/users/:id/extend');
  console.log('   ✓ GET /api/admin/api-keys');
  console.log('   ✓ GET /api/admin/verify-session');
  console.log('═'.repeat(50));
});
