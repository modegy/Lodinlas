const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// ═══════════════════════════════════════════════════════════════
// 🛡️ TRUST PROXY FOR RENDER
// ═══════════════════════════════════════════════════════════════
app.set('trust proxy', 1);

// ═══════════════════════════════════════════════════════════════
// 1️⃣ ENVIRONMENT VALIDATION
// ═══════════════════════════════════════════════════════════════
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
  console.error('❌ Missing FIREBASE_URL or FIREBASE_KEY');
  process.exit(1);
}

// ═══════════════════════════════════════════════════════════════
// 2️⃣ HELMET SECURITY
// ═══════════════════════════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// ═══════════════════════════════════════════════════════════════
// 3️⃣ DDOS PROTECTION CLASS
// ═══════════════════════════════════════════════════════════════
class DDoSProtection {
  constructor() {
    this.requestTracker = new Map();
    this.dynamicBlacklist = new Map();
    this.permanentBlacklist = new Set(
      process.env.IP_BLACKLIST ? process.env.IP_BLACKLIST.split(',') : []
    );
    this.attackCounter = new Map();
    
    this.limits = {
      requestsPerSecond: 10,
      requestsPerMinute: 100,
      maxSuspiciousScore: 100,
      blockDuration: 30 * 60 * 1000,
      permanentBlockThreshold: 5
    };

    this.startCleanup();
  }

  getClientIP(req) {
    return req.ip || 
           req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] ||
           req.connection?.remoteAddress ||
           'unknown';
  }

  generateFingerprint(req) {
    const components = [
      req.headers['user-agent'] || '',
      req.headers['accept-language'] || '',
      req.headers['accept-encoding'] || ''
    ];
    return crypto.createHash('md5').update(components.join('|')).digest('hex');
  }

  isSuspiciousUserAgent(ua) {
    if (!ua || ua.length < 10) return true;
    const patterns = [/^python/i, /^java\//i, /curl/i, /wget/i, /scrapy/i, /bot(?!.*google)/i, /headless/i, /phantom/i, /selenium/i];
    return patterns.some(p => p.test(ua));
  }

  calculateThreatScore(req, tracker) {
    let score = 0;
    
    const timeSince = Date.now() - (tracker.lastRequest || 0);
    if (timeSince < 50) score += 20;
    
    if (tracker.requestsLastSecond > this.limits.requestsPerSecond) {
      score += (tracker.requestsLastSecond - this.limits.requestsPerSecond) * 5;
    }
    
    if (tracker.requestsLastMinute > this.limits.requestsPerMinute) {
      score += (tracker.requestsLastMinute - this.limits.requestsPerMinute) * 2;
    }
    
    if (this.isSuspiciousUserAgent(req.headers['user-agent'])) {
      score += 30;
    }
    
    if (!req.headers['accept']) score += 10;
    if (tracker.errorCount > 5) score += tracker.errorCount * 3;
    
    return score;
  }

  checkRequest(req) {
    const ip = this.getClientIP(req);
    const now = Date.now();
    
    if (this.permanentBlacklist.has(ip)) {
      return { blocked: true, reason: 'PERMANENT_BAN', code: 403 };
    }
    
    const ban = this.dynamicBlacklist.get(ip);
    if (ban && now < ban.until) {
      return { 
        blocked: true, 
        reason: 'TEMPORARY_BAN', 
        code: 429,
        retryAfter: Math.ceil((ban.until - now) / 1000)
      };
    }
    
    let tracker = this.requestTracker.get(ip);
    if (!tracker) {
      tracker = {
        ip,
        firstSeen: now,
        lastRequest: now,
        timestamps: [],
        requestsLastSecond: 0,
        requestsLastMinute: 0,
        errorCount: 0,
        threatScore: 0
      };
      this.requestTracker.set(ip, tracker);
    }
    
    // Update tracker
    tracker.timestamps.push(now);
    tracker.lastRequest = now;
    
    const oneSecAgo = now - 1000;
    const oneMinAgo = now - 60000;
    tracker.timestamps = tracker.timestamps.filter(t => t > oneMinAgo);
    tracker.requestsLastSecond = tracker.timestamps.filter(t => t > oneSecAgo).length;
    tracker.requestsLastMinute = tracker.timestamps.length;
    
    const threatScore = this.calculateThreatScore(req, tracker);
    tracker.threatScore = threatScore;
    
    if (threatScore >= this.limits.maxSuspiciousScore) {
      this.blockIP(ip, 'HIGH_THREAT', threatScore);
      return { blocked: true, reason: 'THREAT_DETECTED', code: 429 };
    }
    
    if (tracker.requestsLastMinute > this.limits.requestsPerMinute * 2) {
      this.blockIP(ip, 'RATE_LIMIT', tracker.requestsLastMinute);
      return { blocked: true, reason: 'RATE_LIMIT', code: 429 };
    }
    
    return { blocked: false, threatScore };
  }

  blockIP(ip, reason, score) {
    const attackCount = (this.attackCounter.get(ip) || 0) + 1;
    this.attackCounter.set(ip, attackCount);
    
    if (attackCount >= this.limits.permanentBlockThreshold) {
      this.permanentBlacklist.add(ip);
      console.error(`🚨 PERMANENT BAN: ${ip} | Reason: ${reason}`);
      return;
    }
    
    const duration = this.limits.blockDuration * attackCount;
    this.dynamicBlacklist.set(ip, {
      reason,
      score,
      until: Date.now() + duration,
      attackCount
    });
    
    console.warn(`⚠️ BLOCKED: ${ip} | ${reason} | ${duration/60000}min`);
  }

  recordError(req) {
    const ip = this.getClientIP(req);
    const tracker = this.requestTracker.get(ip);
    if (tracker) tracker.errorCount++;
  }

  startCleanup() {
    setInterval(() => {
      const now = Date.now();
      
      for (const [ip, tracker] of this.requestTracker.entries()) {
        if (now - tracker.lastRequest > 3600000) {
          this.requestTracker.delete(ip);
        }
      }
      
      for (const [ip, ban] of this.dynamicBlacklist.entries()) {
        if (now > ban.until) {
          this.dynamicBlacklist.delete(ip);
        }
      }
    }, 5 * 60 * 1000);
  }

  getStats() {
    return {
      trackedIPs: this.requestTracker.size,
      dynamicBlocks: this.dynamicBlacklist.size,
      permanentBlocks: this.permanentBlacklist.size
    };
  }
}

const ddos = new DDoSProtection();

// ═══════════════════════════════════════════════════════════════
// 4️⃣ DDOS MIDDLEWARE
// ═══════════════════════════════════════════════════════════════
app.use((req, res, next) => {
  const result = ddos.checkRequest(req);
  
  if (result.blocked) {
    if (result.retryAfter) {
      res.set('Retry-After', result.retryAfter);
    }
    return res.status(result.code).json({
      success: false,
      error: 'Access Denied',
      code: result.code
    });
  }
  
  res.on('finish', () => {
    if (res.statusCode >= 400) ddos.recordError(req);
  });
  
  next();
});

// ═══════════════════════════════════════════════════════════════
// 5️⃣ BODY PARSER & SANITIZATION
// ═══════════════════════════════════════════════════════════════
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

const sanitize = (obj) => {
  if (typeof obj === 'string') {
    return obj.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
              .replace(/javascript:/gi, '')
              .trim()
              .substring(0, 1000);
  }
  if (Array.isArray(obj)) return obj.slice(0, 100).map(sanitize);
  if (obj && typeof obj === 'object') {
    const result = {};
    for (const key of Object.keys(obj).slice(0, 50)) {
      result[sanitize(key)] = sanitize(obj[key]);
    }
    return result;
  }
  return obj;
};

app.use((req, res, next) => {
  if (req.body) req.body = sanitize(req.body);
  if (req.query) req.query = sanitize(req.query);
  next();
});

// ═══════════════════════════════════════════════════════════════
// 6️⃣ CORS
// ═══════════════════════════════════════════════════════════════
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-session-token', 
                   'x-admin-key', 'x-device-fingerprint', 'x-timestamp', 'x-nonce', 'x-signature']
}));

// ═══════════════════════════════════════════════════════════════
// 7️⃣ RATE LIMITING
// ═══════════════════════════════════════════════════════════════
const createLimiter = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { success: false, error: message },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ddos.getClientIP(req)
});

const globalLimiter = createLimiter(60 * 1000, 60, 'Too many requests');
const loginLimiter = createLimiter(15 * 60 * 1000, 5, 'Too many login attempts');
const apiLimiter = createLimiter(60 * 1000, 30, 'API rate limit exceeded');

app.use(globalLimiter);

// ═══════════════════════════════════════════════════════════════
// 8️⃣ BRUTE FORCE PROTECTION
// ═══════════════════════════════════════════════════════════════
const bruteForce = {
  attempts: new Map(),
  lockouts: new Map(),
  
  isLocked(key) {
    const lockout = this.lockouts.get(key);
    if (lockout && Date.now() < lockout.until) {
      return { locked: true, remainingTime: Math.ceil((lockout.until - Date.now()) / 1000) };
    }
    return { locked: false };
  },
  
  recordAttempt(key, success) {
    if (success) {
      this.attempts.delete(key);
      this.lockouts.delete(key);
      return;
    }
    
    const now = Date.now();
    let record = this.attempts.get(key) || { count: 0, timestamps: [], lockCount: 0 };
    
    record.timestamps = record.timestamps.filter(t => now - t < 15 * 60 * 1000);
    record.timestamps.push(now);
    record.count = record.timestamps.length;
    
    if (record.count >= 5) {
      record.lockCount++;
      this.lockouts.set(key, {
        until: now + (30 * 60 * 1000 * record.lockCount)
      });
      record.timestamps = [];
      record.count = 0;
    }
    
    this.attempts.set(key, record);
  }
};

// ═══════════════════════════════════════════════════════════════
// 9️⃣ FIREBASE & HELPERS
// ═══════════════════════════════════════════════════════════════
const firebase = axios.create({ timeout: 15000 });
const FB_URL = process.env.FIREBASE_URL;
const FB_KEY = process.env.FIREBASE_KEY;
const adminSessions = new Map();

const ADMIN = {
  username: process.env.ADMIN_USERNAME || 'admin',
  passwordHash: crypto.createHash('sha256')
    .update(process.env.ADMIN_PASSWORD || 'ChangeThis123!')
    .digest('hex')
};

const generateToken = () => crypto.randomBytes(32).toString('hex');
const hashPassword = (p) => crypto.createHash('sha256').update(p).digest('hex');

// Session cleanup
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of adminSessions.entries()) {
    if (now - session.createdAt > 24 * 60 * 60 * 1000) {
      adminSessions.delete(token);
    }
  }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════
// 🔐 AUTH MIDDLEWARES
// ═══════════════════════════════════════════════════════════════
const authApp = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const expected = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
  
  if (!apiKey || apiKey !== expected) {
    return res.status(401).json({ success: false, error: 'Unauthorized', code: 401 });
  }
  next();
};

const authAdmin = (req, res, next) => {
  const token = req.headers['x-session-token'];
  
  if (token) {
    const session = adminSessions.get(token);
    if (session && Date.now() - session.createdAt < 24 * 60 * 60 * 1000) {
      req.adminUser = session.username;
      return next();
    }
  }
  
  res.status(401).json({ success: false, error: 'Unauthorized', code: 401 });
};

// ═══════════════════════════════════════════════════════════════
// 🔑 API ENDPOINTS
// ═══════════════════════════════════════════════════════════════

app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: '4.0.0',
    uptime: Math.floor(process.uptime()),
    stats: ddos.getStats()
  });
});

app.get('/api/serverTime', apiLimiter, (req, res) => {
  const now = Date.now();
  res.json({
    success: true,
    server_time: now,
    unixtime: Math.floor(now / 1000)
  });
});

app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  const ip = ddos.getClientIP(req);
  
  const lockStatus = bruteForce.isLocked(ip);
  if (lockStatus.locked) {
    return res.status(429).json({
      success: false,
      error: 'Too many attempts',
      retryAfter: lockStatus.remainingTime
    });
  }
  
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Missing credentials' });
  }
  
  const passHash = hashPassword(password);
  
  if (username !== ADMIN.username || passHash !== ADMIN.passwordHash) {
    bruteForce.recordAttempt(ip, false);
    return setTimeout(() => {
      res.status(401).json({ success: false, error: 'Invalid credentials' });
    }, 1000);
  }
  
  bruteForce.recordAttempt(ip, true);
  
  const sessionToken = generateToken();
  adminSessions.set(sessionToken, {
    username,
    createdAt: Date.now(),
    ip
  });
  
  console.log(`✅ Admin login: ${username} from ${ip}`);
  res.json({ success: true, sessionToken, expiresIn: '24h' });
});

app.post('/api/admin/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) adminSessions.delete(token);
  res.json({ success: true });
});

app.post('/api/getUser', authApp, apiLimiter, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username || username.length > 50) {
      return res.status(400).json({ success: false, error: 'Invalid username' });
    }
    
    const url = `${FB_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    
    if (!response.data || Object.keys(response.data).length === 0) {
      return res.json({});
    }
    
    const key = Object.keys(response.data)[0];
    const user = { ...response.data[key] };
    delete user.password;
    
    res.json(user);
  } catch (error) {
    console.error('getUser error:', error.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/verifyAccount', authApp, apiLimiter, async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    
    if (!username || !password || !deviceId) {
      return res.status(400).json({ success: false, error: 'Missing data', code: 400 });
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
    
    res.json({ success: true, username: user.username });
  } catch (error) {
    console.error('verifyAccount error:', error.message);
    res.status(500).json({ success: false, code: 0 });
  }
});

app.post('/api/updateDevice', authApp, apiLimiter, async (req, res) => {
  try {
    const { username, deviceId } = req.body;
    
    if (!username || !deviceId) {
      return res.status(400).json({ success: false, error: 'Missing data' });
    }
    
    const url = `${FB_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
    const response = await firebase.get(url);
    
    if (!response.data || Object.keys(response.data).length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    const key = Object.keys(response.data)[0];
    
    await firebase.patch(`${FB_URL}/users/${key}.json?auth=${FB_KEY}`, {
      device_id: deviceId,
      last_login: Date.now()
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('updateDevice error:', error.message);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// 🏠 HOME
// ═══════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  const stats = ddos.getStats();
  res.send(`
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>🛡️ Secure Proxy v4</title>
<style>
body{font-family:system-ui;background:#1a1a2e;color:#fff;padding:40px;text-align:center}
h1{color:#4cc9f0;font-size:2.5em}
.badge{background:#10b981;padding:15px 30px;border-radius:50px;display:inline-block;margin:20px}
.stats{display:flex;justify-content:center;gap:30px;margin:30px 0}
.stat{background:rgba(255,255,255,0.05);padding:20px 40px;border-radius:15px}
.stat-value{font-size:2em;color:#4cc9f0}
</style></head>
<body>
<h1>🛡️ Ultra Secure Proxy v4.0</h1>
<div class="badge">✅ All Security Active</div>
<div class="stats">
<div class="stat"><div class="stat-value">${stats.trackedIPs}</div><div>Tracked</div></div>
<div class="stat"><div class="stat-value">${stats.dynamicBlocks}</div><div>Blocked</div></div>
<div class="stat"><div class="stat-value">${Math.floor(process.uptime())}s</div><div>Uptime</div></div>
</div>
</body></html>
  `);
});

// 404 & Errors
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Not found', code: 404 });
});

app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({ success: false, error: 'Server error', code: 500 });
});

// ═══════════════════════════════════════════════════════════════
// 🚀 START
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log('═'.repeat(50));
  console.log('🛡️  Ultra Secure Proxy v4.0 Started!');
  console.log(`📡 Port: ${PORT}`);
  console.log('🔐 Security: DDoS + Brute Force + Rate Limit');
  console.log('═'.repeat(50));
});
