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
// 🔐 إعدادات التوقيع الآمنة
// ═══════════════════════════════════════════
const SIGNING_SALT = process.env.SIGNING_SALT || 'SubAdminSecureSalt@2024!NoOneKnows';

// دالة توليد مفتاح التوقيع من API Key
function deriveSigningKey(apiKey) {
    return crypto.createHmac('sha256', SIGNING_SALT)
        .update(apiKey)
        .digest('hex');
}

// ═══════════════════════════════════════════
// الأمان والحماية
// ═══════════════════════════════════════════
app.use(helmet({ 
  contentSecurityPolicy: false, 
  crossOriginEmbedderPolicy: false 
}));

// ═══════════════════════════════════════════
// 🛡️ ADVANCED DDOS & SECURITY PROTECTION
// ═══════════════════════════════════════════
const requestTracker = new Map();
const blockedIPs = new Set();

const ddosProtection = (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const now = Date.now();
    
    if (blockedIPs.has(ip)) {
        return res.status(403).end();
    }
    
    if (!requestTracker.has(ip)) {
        requestTracker.set(ip, { 
            count: 0, 
            firstRequest: now, 
            blocked: false,
            violations: 0
        });
    }
    
    const tracker = requestTracker.get(ip);
    
    if (tracker.blocked) {
        if (now - tracker.blockedAt < 600000) {
            return res.status(429).json({ 
                error: 'Blocked. Try again later.',
                retry_after: Math.ceil((600000 - (now - tracker.blockedAt)) / 1000)
            });
        } else {
            tracker.blocked = false;
            tracker.count = 0;
        }
    }
    
    if (now - tracker.firstRequest > 60000) {
        tracker.count = 0;
        tracker.firstRequest = now;
    }
    
    tracker.count++;
    
    if (tracker.count > 60 && tracker.count <= 100) {
        console.warn(`⚠️ [WARNING] High traffic from: ${ip} (${tracker.count} req/min)`);
    }
    
    if (tracker.count > 100) {
        tracker.blocked = true;
        tracker.blockedAt = now;
        tracker.violations++;
        
        console.error(`🚫 [BLOCKED] IP: ${ip} (violation #${tracker.violations})`);
        
        if (tracker.violations >= 3) {
            blockedIPs.add(ip);
            console.error(`⛔ [BANNED] IP permanently: ${ip}`);
        }
        
        return res.status(429).json({ error: 'Rate limit exceeded' });
    }
    
    next();
};

const suspiciousRequestFilter = (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const userAgent = req.headers['user-agent'] || '';
    
    if (!userAgent || userAgent.length < 5) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    const blockedAgents = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 
        'gobuster', 'dirbuster', 'hydra', 'burp', 'zap',
        'slowloris', 'hulk', 'goldeneye', 'loic', 'hoic'
    ];
    
    const userAgentLower = userAgent.toLowerCase();
    for (const agent of blockedAgents) {
        if (userAgentLower.includes(agent)) {
            blockedIPs.add(ip);
            console.error(`⛔ [BANNED] Attack tool: ${agent} from ${ip}`);
            return res.status(403).end();
        }
    }
    
    const fullUrl = req.originalUrl || req.url;
    if (/union.*select|select.*from|drop.*table|insert.*into/i.test(fullUrl)) {
        blockedIPs.add(ip);
        console.error(`⛔ [SQL INJECTION] from: ${ip}`);
        return res.status(403).end();
    }
    
    if (/<script|javascript:|on\w+\s*=/i.test(fullUrl)) {
        console.error(`⛔ [XSS] from: ${ip}`);
        return res.status(403).end();
    }
    
    next();
};

const attackLogger = (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const sensitiveEndpoints = ['/api/admin', '/api/sub'];
    
    if (sensitiveEndpoints.some(ep => req.path.startsWith(ep))) {
        console.log(`📋 [AUDIT] ${req.method} ${req.path} | IP: ${ip}`);
    }
    
    next();
};

app.use(ddosProtection);
app.use(suspiciousRequestFilter);
app.use(attackLogger);

// تنظيف دوري
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of requestTracker.entries()) {
        if (now - data.firstRequest > 3600000) {
            requestTracker.delete(ip);
        }
    }
    console.log(`📊 [STATS] Tracking: ${requestTracker.size} IPs | Blocked: ${blockedIPs.size}`);
}, 3600000);

// ═══════════════════════════════════════════
// CORS
// ═══════════════════════════════════════════
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
// SIGNATURE VERIFICATION SYSTEM
// ═══════════════════════════════════════════
const SIGNED_ENDPOINTS = [
    '/api/getUser',
    '/api/verifyAccount',
    '/api/updateDevice',
    '/api/sub/verify-key',
    '/api/sub/users',
    '/api/sub/users/:id/extend',
    '/api/sub/users/:id',
    '/api/sub/users/:id/reset-device',
    '/api/sub/users/:id/details',
    '/api/sub/stats'
];

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

// حفظ الـ raw body
app.use(express.json({ 
    limit: '2mb',
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));

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
// 🔐 دالة مساعدة لجلب signing_secret
// ═══════════════════════════════════════════
async function getSubAdminSigningSecret(clientId, currentPath) {
    try {
        // 1. تحقق من الكاش أولاً
        const cachedKey = subAdminKeys.get(clientId);
        if (cachedKey && cachedKey.signing_secret) {
            console.log(`🔑 [SIGNATURE] Found in cache: ${clientId.substring(0, 10)}...`);
            return cachedKey.signing_secret;
        }

        // 2. للطلب الأول (verify-key): استخدم derived key
        if (currentPath === '/api/sub/verify-key') {
            console.log(`🔑 [SIGNATURE] Using derived key for verify-key: ${clientId.substring(0, 10)}...`);
            return deriveSigningKey(clientId);
        }

        // 3. للطلبات الأخرى: جلب من Firebase
        console.log(`🔍 [SIGNATURE] Fetching from Firebase for: ${clientId.substring(0, 10)}...`);
        
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
        const keys = response.data || {};
        
        let foundKey = null;
        for (const key of Object.values(keys)) {
            if (key.api_key === clientId) {
                foundKey = key;
                break;
            }
        }
        
        if (foundKey && foundKey.signing_secret) {
            // حفظ في الكاش
            subAdminKeys.set(clientId, foundKey);
            console.log(`✅ [SIGNATURE] Retrieved secret from Firebase for: ${clientId.substring(0, 10)}...`);
            return foundKey.signing_secret;
        }
        
        // 4. كحل أخير: استخدام derived key
        console.warn(`⚠️ [SIGNATURE] Using fallback derived key for: ${clientId.substring(0, 10)}...`);
        return deriveSigningKey(clientId);
        
    } catch (error) {
        console.error('❌ [SIGNATURE] Error getting signing secret:', error.message);
        return deriveSigningKey(clientId); // fallback
    }
}

// ═══════════════════════════════════════════
// 🔐 SIGNATURE VERIFICATION MIDDLEWARE
// ═══════════════════════════════════════════
const verifySignature = async (req, res, next) => {
    try {
        console.log('🔐 [SIGNATURE] Starting verification for:', req.method, req.path);
        
        const path = req.path;
        const needsSignature = SIGNED_ENDPOINTS.some(endpoint => {
            if (endpoint.includes(':')) {
                const pattern = endpoint.replace(/:[^/]+/g, '([^/]+)');
                const regex = new RegExp(`^${pattern}$`);
                return regex.test(path);
            }
            return endpoint === path;
        });

        if (!needsSignature) {
            console.log('🔐 [SIGNATURE] No signature required for:', path);
            return next();
        }

        console.log('🔐 [SIGNATURE] Signature required for:', path);

        const signature = req.headers['x-api-signature'];
        const timestamp = req.headers['x-timestamp'];
        const nonce = req.headers['x-nonce'];
        const clientId = req.headers['x-client-id'] || req.headers['x-api-key'];

        console.log('🔐 [SIGNATURE] Headers received:', {
            signature: signature ? `${signature.substring(0, 15)}...` : 'none',
            timestamp: timestamp,
            nonce: nonce,
            clientId: clientId ? `${clientId.substring(0, 10)}...` : 'none'
        });

        if (!signature || !timestamp || !nonce || !clientId) {
            console.log('❌ [SIGNATURE] Missing signature headers');
            return res.status(401).json({
                success: false,
                error: 'Missing signature headers',
                code: 401
            });
        }

        const now = Date.now();
        let requestTime = parseInt(timestamp);
        
        if (requestTime < 10000000000) {
            requestTime = requestTime * 1000;
        }
        
        const timeDiff = Math.abs(now - requestTime);
        
        if (isNaN(requestTime) || timeDiff > 300000) {
            console.warn(`❌ [SIGNATURE] Invalid timestamp: diff ${timeDiff}ms`);
            return res.status(401).json({
                success: false,
                error: 'Request timestamp is invalid or too old',
                code: 401
            });
        }

        // 🔑 الحصول على المفتاح السري
        let secretKey;
        let keySource = 'unknown';
        
        if (clientId === process.env.APP_API_KEY) {
            secretKey = process.env.APP_SIGNING_SECRET;
            keySource = 'app_signing_secret';
        }
        else if (clientId === process.env.MASTER_ADMIN_TOKEN) {
            secretKey = process.env.MASTER_SIGNING_SECRET;
            keySource = 'master_signing_secret';
        }
        else {
            // 🔄 للحصول على مفتاح Sub Admin
            secretKey = await getSubAdminSigningSecret(clientId, path);
            keySource = 'sub_admin_secret';
        }

        if (!secretKey) {
            console.error('❌ [SIGNATURE] No signing secret found for client');
            return res.status(401).json({
                success: false,
                error: 'Authentication failed',
                code: 401
            });
        }

        console.log(`🔑 [SIGNATURE] Using key from: ${keySource}`);

        let stringToSign = '';
        
        if (req.method === 'GET' || req.method === 'DELETE') {
            stringToSign = `${req.method.toUpperCase()}:${req.path}|${timestamp}|${nonce}`;
            
            if (Object.keys(req.query).length > 0) {
                const sortedParams = Object.keys(req.query)
                    .sort()
                    .map(key => `${key}=${req.query[key]}`)
                    .join('&');
                stringToSign = `${req.method.toUpperCase()}:${req.path}?${sortedParams}|${timestamp}|${nonce}`;
            }
        } else {
            const bodyString = req.rawBody || '{}';
            const bodyHash = crypto.createHash('sha256')
                .update(bodyString)
                .digest('hex');
            stringToSign = `${req.method.toUpperCase()}:${req.path}|${bodyHash}|${timestamp}|${nonce}`;
        }

        stringToSign += `|${secretKey}`;

        const expectedSignature = crypto.createHmac('sha256', secretKey)
            .update(stringToSign)
            .digest('base64')
            .replace(/=+$/, '');

        const isValid = (signature === expectedSignature);

        if (!isValid) {
            console.error(`❌ [SIGNATURE] Invalid signature`);
            console.error('   Expected:', expectedSignature.substring(0, 20) + '...');
            console.error('   Received:', signature.substring(0, 20) + '...');

            return res.status(401).json({
                success: false,
                error: 'Invalid signature',
                code: 401
            });
        }

        console.log(`✅ [SIGNATURE] Valid signature for ${req.method} ${req.path}`);
        next();

    } catch (error) {
        console.error('❌ [SIGNATURE] Verification error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Signature verification failed',
            code: 500
        });
    }
};

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
  
  if (masterToken && sessionToken === masterToken) {
    req.adminUser = 'master_owner';
    return next();
  }
  
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
      'view_only': ['view']
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

const checkUserOwnership = async (req, res, next) => {
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
    
    if (!user.created_by_key || user.created_by_key !== currentKeyId) {
      console.log(`🚫 Ownership denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
      return res.status(403).json({ 
        success: false, 
        error: 'You can only manage users you created' 
      });
    }
    
    req.targetUser = user;
    next();
    
  } catch (error) {
    console.error('Ownership check error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to verify ownership' 
    });
  }
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
    version: '3.3.0', 
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
app.post('/api/getUser', verifySignature, authApp, apiLimiter, async (req, res) => {
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

app.post('/api/verifyAccount', verifySignature, authApp, apiLimiter, async (req, res) => {
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

app.post('/api/updateDevice', verifySignature, authApp, apiLimiter, async (req, res) => {
  try {
    const { username, deviceId, deviceInfo } = req.body;
    
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
    
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const userAgent = req.headers['user-agent'] || '';
    
    const updateData = {
      device_id: deviceId,
      last_login: Date.now(),
      login_count: (user.login_count || 0) + 1,
      ip_address: ip,
      user_agent: userAgent
    };
    
    if (deviceInfo) {
      updateData.device_model = deviceInfo.device_model || 'Unknown';
      updateData.device_brand = deviceInfo.device_brand || 'Unknown';
      updateData.device_manufacturer = deviceInfo.device_manufacturer || 'Unknown';
      updateData.device_product = deviceInfo.device_product || 'Unknown';
      updateData.device_type = deviceInfo.device_type || 'Phone';
      updateData.android_version = deviceInfo.android_version || 'Unknown';
      updateData.sdk_version = deviceInfo.sdk_version || 0;
      updateData.is_rooted = deviceInfo.is_rooted || false;
      updateData.has_screen_lock = deviceInfo.has_screen_lock || false;
      updateData.fingerprint_enabled = deviceInfo.fingerprint_enabled || false;
      updateData.total_ram = deviceInfo.total_ram || 'Unknown';
      updateData.screen_size = deviceInfo.screen_size || 'Unknown';
      updateData.screen_density = deviceInfo.screen_density || 0;
      updateData.network_type = deviceInfo.network_type || 'Unknown';
      updateData.carrier_name = deviceInfo.carrier_name || 'Unknown';
      updateData.battery_level = deviceInfo.battery_level || 0;
      updateData.is_charging = deviceInfo.is_charging || false;
      
      if (deviceInfo.location) {
        updateData.location = deviceInfo.location;
      }
    }
    
    const loginEntry = {
      timestamp: Date.now(),
      ip: ip,
      device: deviceInfo?.device_model || 'Unknown',
      os_version: deviceInfo?.android_version || 'Unknown',
      network: deviceInfo?.network_type || 'Unknown',
      carrier: deviceInfo?.carrier_name || 'Unknown',
      battery: deviceInfo?.battery_level || 0,
      is_rooted: deviceInfo?.is_rooted || false
    };
    
    const existingHistory = user.login_history || [];
    updateData.login_history = [
      ...existingHistory.slice(-9),
      loginEntry
    ];
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, updateData);
    
    console.log(`📱 Login: ${username} | Device: ${deviceInfo?.device_brand || 'Unknown'} ${deviceInfo?.device_model || 'Unknown'} | IP: ${ip}`);
    
    if (deviceInfo?.is_rooted) {
      console.warn(`🚨 WARNING: User "${username}" is using a ROOTED device!`);
    }
    
    res.json({ 
      success: true, 
      message: 'Device updated successfully',
      user_info: {
        username: user.username,
        login_count: updateData.login_count,
        is_rooted: updateData.is_rooted,
        last_login: updateData.last_login
      }
    });
    
  } catch (error) {
    console.error('❌ Update device error:', error.message);
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
  const sessionToken = req.headers['x-session-token');
  const session = adminSessions.get(sessionToken);
  
  if (!session) {
    return res.json({ success: true, session: { username: 'master_owner' } });
  }
  
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
        expiry_timestamp: subEnd,
        expiry_date: formatDate(subEnd),
        created_at: user.created_at || null,
        last_login: user.last_login || null,
        device_id: user.device_id || '',
        max_devices: user.max_devices || 1,
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

app.post('/api/admin/users', authAdmin, apiLimiter, async (req, res) => {
  try {
    const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;
    
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
      subscription_end: expiryTimestamp,
      max_devices: maxDevices || 1,
      device_id: '',
      created_at: Date.now(),
      last_login: null,
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
    const { is_active, max_devices, notes } = req.body;
    const updateData = {};
    
    if (typeof is_active === 'boolean') updateData.is_active = is_active;
    if (max_devices) updateData.max_devices = max_devices;
    if (notes !== undefined) updateData.notes = notes;
    
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
      if (user.subscription_end && user.subscription_end <= now) {
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
        signing_secret: key.signing_secret ? '*****' : null
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
    const { adminName, permissionLevel, expiryDays } = req.body;
    
    if (!adminName) {
      return res.status(400).json({ 
        success: false, 
        error: 'Admin name required' 
      });
    }
    
    const apiKey = `AK_${crypto.randomBytes(16).toString('hex')}`;
    const signingSecret = `SS_${crypto.randomBytes(32).toString('hex')}`;
    
    const keyData = {
      api_key: apiKey,
      admin_name: adminName,
      permission_level: permissionLevel || 'view_only',
      is_active: true,
      expiry_timestamp: Date.now() + ((expiryDays || 30) * 24 * 60 * 60 * 1000),
      usage_count: 0,
      bound_device: null,
      created_at: Date.now(),
      signing_secret: signingSecret
    };
    
    await firebase.post(`api_keys.json?auth=${FB_KEY}`, keyData);
    
    console.log(`🔑 API Key created for: ${adminName}`);
    
    res.json({ 
      success: true, 
      message: 'API Key created', 
      apiKey,
      signingSecret,
      warning: 'Save the signing secret immediately. It will not be shown again.'
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

app.post('/api/admin/api-keys/:id/regenerate-secret', authAdmin, apiLimiter, async (req, res) => {
  try {
    const newSecret = `SS_${crypto.randomBytes(32).toString('hex')}`;
    
    await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, { 
      signing_secret: newSecret,
      last_secret_update: Date.now()
    });
    
    console.log(`🔄 Regenerated signing secret for API Key: ${req.params.id}`);
    
    res.json({ 
      success: true, 
      message: 'Signing secret regenerated',
      signingSecret: newSecret,
      warning: 'Save this new secret immediately.'
    });
    
  } catch (error) {
    console.error('Regenerate secret error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to regenerate secret' 
    });
  }
});

// ═══════════════════════════════════════════
// 📡 Security Stats Endpoints
// ═══════════════════════════════════════════
app.get('/api/admin/security-stats', authAdmin, (req, res) => {
    res.json({
        success: true,
        stats: {
            tracked_ips: requestTracker.size,
            blocked_ips: blockedIPs.size,
            blocked_list: Array.from(blockedIPs).slice(0, 20)
        }
    });
});

app.post('/api/admin/unblock-ip', authAdmin, (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP required' });
    
    blockedIPs.delete(ip);
    requestTracker.delete(ip);
    
    res.json({ success: true, message: `IP ${ip} unblocked` });
});

// ═══════════════════════════════════════════
// 📊 Device Stats
// ═══════════════════════════════════════════
app.get('/api/admin/device-stats', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const stats = {
      total_users: Object.keys(users).length,
      total_devices: 0,
      rooted_devices: 0,
      device_brands: {},
      android_versions: {},
      active_last_day: 0,
      active_last_week: 0
    };
    
    const now = Date.now();
    const oneDay = 24 * 60 * 60 * 1000;
    const oneWeek = 7 * oneDay;
    
    for (const user of Object.values(users)) {
      if (user.device_id) {
        stats.total_devices++;
        if (user.is_rooted) stats.rooted_devices++;
        
        const brand = user.device_brand || 'Unknown';
        stats.device_brands[brand] = (stats.device_brands[brand] || 0) + 1;
        
        const version = user.android_version || 'Unknown';
        stats.android_versions[version] = (stats.android_versions[version] || 0) + 1;
      }
      
      if (user.last_login) {
        const timeSince = now - user.last_login;
        if (timeSince < oneDay) stats.active_last_day++;
        if (timeSince < oneWeek) stats.active_last_week++;
      }
    }
    
    res.json({ success: true, data: stats });
    
  } catch (error) {
    console.error('Device stats error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to fetch device stats' });
  }
});

app.get('/api/admin/rooted-devices', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    const rootedDevices = [];
    
    for (const [userId, user] of Object.entries(users)) {
      if (user.is_rooted) {
        rootedDevices.push({
          user_id: userId,
          username: user.username,
          device_model: user.device_model || 'Unknown',
          device_brand: user.device_brand || 'Unknown',
          android_version: user.android_version || 'Unknown',
          last_login: user.last_login,
          ip_address: user.ip_address || 'Unknown'
        });
      }
    }
    
    res.json({ success: true, data: rootedDevices, count: rootedDevices.length });
    
  } catch (error) {
    console.error('Rooted devices error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to fetch rooted devices' });
  }
});

app.get('/api/admin/users/:id/login-history', authAdmin, apiLimiter, async (req, res) => {
  try {
    const response = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);
    
    if (!response.data) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    const user = response.data;
    const history = user.login_history || [];
    
    res.json({ 
      success: true, 
      data: {
        username: user.username,
        total_logins: user.login_count || 0,
        login_history: history.reverse()
      }
    });
    
  } catch (error) {
    console.error('Login history error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to fetch login history' });
  }
});

// ═══════════════════════════════════════════
// 🔑 SUB ADMIN API
// ═══════════════════════════════════════════
app.post('/api/sub/verify-key', verifySignature, apiLimiter, async (req, res) => {
  try {
    const { apiKey, deviceFingerprint } = req.body;
    
    console.log('🔍 Sub Admin verify key request');
    
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
    
    // ⚠️ **التعديل الهام**: تأكد من وجود signing_secret
    if (!foundKey.signing_secret) {
      // إذا لم يكن موجودًا، قم بإنشاء واحد
      const newSigningSecret = `SS_${crypto.randomBytes(32).toString('hex')}`;
      await firebase.patch(`api_keys/${keyId}.json?auth=${FB_KEY}`, {
        signing_secret: newSigningSecret,
        last_secret_update: Date.now()
      });
      foundKey.signing_secret = newSigningSecret;
      console.log(`🔄 Generated new signing secret for: ${keyId}`);
    }
    
    if (!foundKey.bound_device) {
      await firebase.patch(`api_keys/${keyId}.json?auth=${FB_KEY}`, { 
        bound_device: deviceFingerprint 
      });
      console.log(`🔗 Device bound to key: ${keyId}`);
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
    
    // ⚠️ **التعديل الهام**: حفظ في الكاش مع signing_secret
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
      key_id: keyId,
      signing_secret: foundKey.signing_secret  // ⚠️ تأكد من إرساله
    });
    
  } catch (error) {
    console.error('Verify key error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Server error' 
    });
  }
});

app.get('/api/sub/users', verifySignature, authSubAdmin, checkSubAdminPermission('view'), apiLimiter, async (req, res) => {
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
          expiry_timestamp: subEnd,
          expiry_date: formatDate(subEnd),
          device_id: user.device_id || '',
          max_devices: user.max_devices || 1,
          last_login: user.last_login || 0,
          created_at: user.created_at || 0,
          created_by: user.created_by || 'sub_admin',
          created_by_key: user.created_by_key || null
        };
      }
    }
    
    console.log(`👥 Sub Admin [${currentKeyId}] sees ${Object.keys(formattedUsers).length} users`);
    
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

app.get('/api/sub/users/:id/details', verifySignature, authSubAdmin, checkSubAdminPermission('view'), apiLimiter, async (req, res) => {
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
            user: {
                username: user.username || '',
                is_active: user.is_active !== false,
                device_id: user.device_id || '',
                max_devices: user.max_devices || 1,
                last_login: user.last_login || 0,
                created_at: user.created_at || 0,
                subscription_end: user.subscription_end || 0,
                created_by: user.created_by || 'sub_admin',
                notes: user.notes || ''
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

app.get('/api/sub/stats', verifySignature, authSubAdmin, checkSubAdminPermission('view'), apiLimiter, async (req, res) => {
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
        if (user.subscription_end && user.subscription_end <= now) {
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

app.post('/api/sub/users', verifySignature, authSubAdmin, checkSubAdminPermission('add'), apiLimiter, async (req, res) => {
  try {
    const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;
    
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
      subscription_end: expiryTimestamp,
      max_devices: maxDevices || 1,
      device_id: '',
      created_at: Date.now(),
      last_login: null,
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

app.post('/api/sub/users/:id/extend', verifySignature, authSubAdmin, checkSubAdminPermission('extend'), apiLimiter, async (req, res) => {
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
      console.log(`🚫 Extend denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
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
    
    console.log(`⏰ Sub Admin [${currentKeyId}] extended user: ${user.username}`);
    
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

app.patch('/api/sub/users/:id', verifySignature, authSubAdmin, checkSubAdminPermission('edit'), apiLimiter, async (req, res) => {
  try {
    const userId = req.params.id;
    const currentKeyId = req.subAdminKeyId;
    const { is_active } = req.body;
    
    const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
    
    if (!userRes.data) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const user = userRes.data;
    
    if (user.created_by_key !== currentKeyId) {
      console.log(`🚫 Edit denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
      return res.status(403).json({ 
        success: false, 
        error: 'You can only edit users you created' 
      });
    }
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
      is_active 
    });
    
    console.log(`✏️ Sub Admin [${currentKeyId}] updated user: ${user.username}`);
    
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

app.post('/api/sub/users/:id/reset-device', verifySignature, authSubAdmin, checkSubAdminPermission('edit'), apiLimiter, async (req, res) => {
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
      console.log(`🚫 Reset device denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
      return res.status(403).json({ 
        success: false, 
        error: 'You can only reset device for users you created' 
      });
    }
    
    await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
      device_id: '' 
    });
    
    console.log(`🔄 Sub Admin [${currentKeyId}] reset device for user: ${user.username}`);
    
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

app.delete('/api/sub/users/:id', verifySignature, authSubAdmin, checkSubAdminPermission('delete'), apiLimiter, async (req, res) => {
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
      console.log(`🚫 Delete denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
      return res.status(403).json({ 
        success: false, 
        error: 'You can only delete users you created' 
      });
    }
    
    await firebase.delete(`users/${userId}.json?auth=${FB_KEY}`);
    
    console.log(`🗑️ User deleted by Sub Admin [${currentKeyId}]: ${user.username}`);
    
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
// 🛠️ MAINTENANCE ENDPOINTS
// ═══════════════════════════════════════════
app.post('/api/admin/fix-old-users', authAdmin, async (req, res) => {
  try {
    console.log('🔧 Starting fix-old-users process...');
    
    const response = await firebase.get(`users.json?auth=${FB_KEY}`);
    const users = response.data || {};
    
    let fixed = 0;
    let alreadyFixed = 0;
    const fixedUsers = [];
    
    for (const [id, user] of Object.entries(users)) {
      if (!user.created_by_key) {
        await firebase.patch(`users/${id}.json?auth=${FB_KEY}`, {
          created_by_key: 'master'
        });
        console.log(`   ✅ Fixed: ${user.username} → created_by_key: "master"`);
        fixedUsers.push(user.username);
        fixed++;
      } else {
        alreadyFixed++;
      }
    }
    
    console.log(`🎉 Fix completed: ${fixed} fixed, ${alreadyFixed} already had key`);
    
    res.json({ 
      success: true, 
      message: `Fixed ${fixed} old users. ${alreadyFixed} already had created_by_key`,
      fixed: fixed,
      alreadyFixed: alreadyFixed,
      fixedUsers: fixedUsers
    });
  } catch (error) {
    console.error('❌ Fix-old-users error:', error.message);
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

// تنظيف الكاش دوريًا
setInterval(() => {
  const now = Date.now();
  for (const [apiKey, keyData] of subAdminKeys.entries()) {
    // حذف إذا لم يستخدم لأكثر من 30 دقيقة
    if (now - (keyData.last_used || 0) > 30 * 60 * 1000) {
      subAdminKeys.delete(apiKey);
      console.log(`🧹 Cleared cache for: ${apiKey.substring(0, 10)}...`);
    }
  }
}, 15 * 60 * 1000); // كل 15 دقيقة

// ═══════════════════════════════════════════
// HOME PAGE
// ═══════════════════════════════════════════
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🛡️ Secure API v3.3.0</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, sans-serif;
      background: linear-gradient(135deg, #1a1a2e, #16213e);
      color: #fff;
      min-height: 100vh;
      padding: 40px 20px;
      text-align: center;
    }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { color: #4cc9f0; margin-bottom: 20px; }
    .badge {
      background: linear-gradient(135deg, #10b981, #059669);
      padding: 10px 20px;
      border-radius: 20px;
      display: inline-block;
      margin: 20px 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Secure Firebase Proxy</h1>
    <div class="badge">✅ v3.3.0 - Secure Signature System</div>
    <p style="margin-top: 30px; color: #64748b;">
      🔐 Protected by HMAC-SHA256 Signatures<br>
      🔑 Derived Keys from API Key<br>
      🛡️ DDoS & Rate Limiting Protection
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
  console.log('🛡️  Secure Firebase Proxy v3.3.0');
  console.log(`📡 Port: ${PORT}`);
  console.log('');
  console.log('🔐 SECURE SIGNATURE SYSTEM ENABLED');
  console.log('   - Derived keys from API Key + Salt');
  console.log('   - No hardcoded secrets in client');
  console.log('');
  console.log('═'.repeat(60));
});
