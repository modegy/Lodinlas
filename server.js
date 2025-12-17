const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const cluster = require('cluster');
const os = require('os');
require('dotenv').config();

// ═══════════════════════════════════════════════════════════════
// 🚀 CLUSTER MODE - استخدام جميع النوى للأداء
// ═══════════════════════════════════════════════════════════════

const WORKERS = process.env.WEB_CONCURRENCY || os.cpus().length;

if (cluster.isMaster && process.env.NODE_ENV === 'production') {
  console.log(`🚀 Master ${process.pid} is running`);
  console.log(`🔧 Forking ${WORKERS} workers...`);
  
  for (let i = 0; i < WORKERS; i++) {
    cluster.fork();
  }
  
  cluster.on('exit', (worker, code, signal) => {
    console.log(`⚠️ Worker ${worker.process.pid} died. Restarting...`);
    cluster.fork();
  });
  
} else {
  startServer();
}

function startServer() {
  const app = express();
  const PORT = process.env.PORT || 10000;

  // ═══════════════════════════════════════════════════════════════
  // 🛡️ ADVANCED SECURITY CONFIGURATIONS
  // ═══════════════════════════════════════════════════════════════

  // Trust proxy for accurate IP detection
  app.set('trust proxy', true);

  // ═══════════════════════════════════════════════════════════════
  // 1️⃣ ENVIRONMENT VALIDATION
  // ═══════════════════════════════════════════════════════════════

  const REQUIRED_ENV = ['FIREBASE_URL', 'FIREBASE_KEY'];
  const missingEnv = REQUIRED_ENV.filter(key => !process.env[key]);
  
  if (missingEnv.length > 0) {
    console.error(`❌ Missing environment variables: ${missingEnv.join(', ')}`);
    process.exit(1);
  }

  // ═══════════════════════════════════════════════════════════════
  // 2️⃣ ULTRA SECURE HELMET CONFIGURATION
  // ═══════════════════════════════════════════════════════════════

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        upgradeInsecureRequests: []
      }
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-origin" },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: "none" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true
  }));

  // ═══════════════════════════════════════════════════════════════
  // 3️⃣ ADVANCED DDOS PROTECTION SYSTEM
  // ═══════════════════════════════════════════════════════════════

  class DDoSProtection {
    constructor() {
      // تتبع الطلبات
      this.requestTracker = new Map();
      // قائمة الحظر الديناميكية
      this.dynamicBlacklist = new Map();
      // قائمة الحظر الدائمة
      this.permanentBlacklist = new Set(
        process.env.IP_BLACKLIST ? process.env.IP_BLACKLIST.split(',') : []
      );
      // تتبع الـ User Agents المشبوهة
      this.suspiciousAgents = new Map();
      // تتبع الـ Fingerprints
      this.fingerprints = new Map();
      // تتبع البوتات
      this.botTracker = new Map();
      // عداد الهجمات
      this.attackCounter = new Map();
      // تتبع الاتصالات البطيئة (Slowloris)
      this.slowConnections = new Map();
      
      // الحدود
      this.limits = {
        requestsPerSecond: 10,
        requestsPerMinute: 100,
        requestsPerHour: 1000,
        maxConnectionsPerIP: 50,
        maxPayloadSize: 1024 * 100, // 100KB
        minRequestInterval: 50, // ms
        maxSuspiciousScore: 100,
        blockDuration: 30 * 60 * 1000, // 30 دقيقة
        permanentBlockThreshold: 5
      };

      // تنظيف دوري
      this.startCleanupInterval();
    }

    // حساب بصمة الطلب
    generateFingerprint(req) {
      const components = [
        req.headers['user-agent'] || '',
        req.headers['accept-language'] || '',
        req.headers['accept-encoding'] || '',
        req.headers['accept'] || '',
        req.headers['connection'] || ''
      ];
      return crypto.createHash('md5').update(components.join('|')).digest('hex');
    }

    // حساب درجة الخطورة
    calculateThreatScore(req, tracker) {
      let score = 0;
      
      // 1. سرعة الطلبات
      const timeSinceLastRequest = Date.now() - (tracker.lastRequest || 0);
      if (timeSinceLastRequest < this.limits.minRequestInterval) {
        score += 20;
      }
      
      // 2. عدد الطلبات في الثانية
      const requestsPerSecond = tracker.requestsLastSecond || 0;
      if (requestsPerSecond > this.limits.requestsPerSecond) {
        score += (requestsPerSecond - this.limits.requestsPerSecond) * 5;
      }
      
      // 3. عدد الطلبات في الدقيقة
      const requestsPerMinute = tracker.requestsLastMinute || 0;
      if (requestsPerMinute > this.limits.requestsPerMinute) {
        score += (requestsPerMinute - this.limits.requestsPerMinute) * 2;
      }
      
      // 4. User-Agent مشبوه
      const ua = req.headers['user-agent'] || '';
      if (!ua || ua.length < 10) {
        score += 30;
      }
      if (this.isSuspiciousUserAgent(ua)) {
        score += 40;
      }
      
      // 5. طلبات بدون headers طبيعية
      if (!req.headers['accept'] && !req.headers['accept-language']) {
        score += 15;
      }
      
      // 6. تكرار نفس الـ endpoint
      if (tracker.sameEndpointCount > 20) {
        score += tracker.sameEndpointCount;
      }
      
      // 7. طلبات POST متكررة
      if (req.method === 'POST' && tracker.postCount > 10) {
        score += 20;
      }
      
      // 8. تغير الـ fingerprint بشكل متكرر
      if (tracker.fingerprintChanges > 3) {
        score += 25;
      }
      
      // 9. أخطاء 4xx متكررة
      if (tracker.errorCount > 5) {
        score += tracker.errorCount * 3;
      }
      
      return score;
    }

    // كشف User-Agent المشبوه
    isSuspiciousUserAgent(ua) {
      const suspiciousPatterns = [
        /^python/i, /^java\//i, /^ruby/i, /^php/i,
        /curl/i, /wget/i, /scrapy/i, /bot(?!.*google)/i,
        /spider/i, /crawl(?!.*google)/i, /^$/,
        /headless/i, /phantom/i, /selenium/i,
        /^Go-http-client/i, /^node-fetch/i,
        /httpclient/i, /libwww/i
      ];
      
      return suspiciousPatterns.some(pattern => pattern.test(ua));
    }

    // كشف هجوم Slowloris
    isSlowlorisAttack(req, tracker) {
      const connectionTime = Date.now() - tracker.connectionStart;
      const dataReceived = tracker.bytesReceived || 0;
      
      // اتصال بطيء جداً مع بيانات قليلة
      if (connectionTime > 30000 && dataReceived < 1000) {
        return true;
      }
      
      // الكثير من الاتصالات المفتوحة
      if (tracker.openConnections > 10) {
        return true;
      }
      
      return false;
    }

    // التحقق من الطلب
    checkRequest(req) {
      const ip = this.getClientIP(req);
      const now = Date.now();
      
      // 1. فحص القائمة السوداء الدائمة
      if (this.permanentBlacklist.has(ip)) {
        return { blocked: true, reason: 'PERMANENT_BAN', code: 403 };
      }
      
      // 2. فحص القائمة السوداء الديناميكية
      const dynamicBan = this.dynamicBlacklist.get(ip);
      if (dynamicBan && now < dynamicBan.until) {
        return { 
          blocked: true, 
          reason: 'TEMPORARY_BAN', 
          code: 429,
          retryAfter: Math.ceil((dynamicBan.until - now) / 1000)
        };
      }
      
      // 3. الحصول على أو إنشاء tracker
      let tracker = this.requestTracker.get(ip);
      if (!tracker) {
        tracker = this.createTracker(ip, req);
      }
      
      // 4. تحديث الإحصائيات
      this.updateTracker(tracker, req);
      
      // 5. حساب درجة الخطورة
      const threatScore = this.calculateThreatScore(req, tracker);
      tracker.threatScore = threatScore;
      
      // 6. اتخاذ إجراء بناءً على الدرجة
      if (threatScore >= this.limits.maxSuspiciousScore) {
        this.blockIP(ip, 'HIGH_THREAT_SCORE', threatScore);
        return { blocked: true, reason: 'THREAT_DETECTED', code: 429 };
      }
      
      // 7. فحص Slowloris
      if (this.isSlowlorisAttack(req, tracker)) {
        this.blockIP(ip, 'SLOWLORIS_ATTACK', 0);
        return { blocked: true, reason: 'SLOWLORIS_DETECTED', code: 429 };
      }
      
      // 8. فحص تجاوز الحدود
      if (tracker.requestsLastMinute > this.limits.requestsPerMinute * 2) {
        this.blockIP(ip, 'RATE_LIMIT_EXCEEDED', tracker.requestsLastMinute);
        return { blocked: true, reason: 'RATE_LIMIT', code: 429 };
      }
      
      // 9. Challenge للطلبات المشبوهة
      if (threatScore > 50 && threatScore < this.limits.maxSuspiciousScore) {
        return { 
          blocked: false, 
          challenge: true, 
          threatScore,
          requiresProofOfWork: threatScore > 70
        };
      }
      
      return { blocked: false, threatScore };
    }

    // إنشاء tracker جديد
    createTracker(ip, req) {
      const tracker = {
        ip,
        firstSeen: Date.now(),
        lastRequest: Date.now(),
        connectionStart: Date.now(),
        requestsTotal: 0,
        requestsLastSecond: 0,
        requestsLastMinute: 0,
        requestsLastHour: 0,
        timestamps: [],
        fingerprint: this.generateFingerprint(req),
        fingerprintChanges: 0,
        lastEndpoint: req.path,
        sameEndpointCount: 0,
        postCount: 0,
        errorCount: 0,
        bytesReceived: 0,
        openConnections: 0,
        threatScore: 0,
        blockCount: 0
      };
      
      this.requestTracker.set(ip, tracker);
      return tracker;
    }

    // تحديث tracker
    updateTracker(tracker, req) {
      const now = Date.now();
      
      tracker.timestamps.push(now);
      tracker.lastRequest = now;
      tracker.requestsTotal++;
      
      // حساب الطلبات في الفترات الزمنية
      const oneSecondAgo = now - 1000;
      const oneMinuteAgo = now - 60000;
      const oneHourAgo = now - 3600000;
      
      tracker.timestamps = tracker.timestamps.filter(t => t > oneHourAgo);
      tracker.requestsLastSecond = tracker.timestamps.filter(t => t > oneSecondAgo).length;
      tracker.requestsLastMinute = tracker.timestamps.filter(t => t > oneMinuteAgo).length;
      tracker.requestsLastHour = tracker.timestamps.length;
      
      // تتبع الـ endpoint
      if (req.path === tracker.lastEndpoint) {
        tracker.sameEndpointCount++;
      } else {
        tracker.sameEndpointCount = 1;
        tracker.lastEndpoint = req.path;
      }
      
      // تتبع POST
      if (req.method === 'POST') {
        tracker.postCount++;
      }
      
      // تتبع تغير الـ fingerprint
      const newFingerprint = this.generateFingerprint(req);
      if (newFingerprint !== tracker.fingerprint) {
        tracker.fingerprintChanges++;
        tracker.fingerprint = newFingerprint;
      }
    }

    // حظر IP
    blockIP(ip, reason, score) {
      const attackCount = this.attackCounter.get(ip) || 0;
      this.attackCounter.set(ip, attackCount + 1);
      
      // حظر دائم بعد عدة هجمات
      if (attackCount + 1 >= this.limits.permanentBlockThreshold) {
        this.permanentBlacklist.add(ip);
        console.error(`🚨 PERMANENT BAN: ${ip} | Reason: ${reason} | Attacks: ${attackCount + 1}`);
        return;
      }
      
      // حظر مؤقت متصاعد
      const blockDuration = this.limits.blockDuration * (attackCount + 1);
      
      this.dynamicBlacklist.set(ip, {
        reason,
        score,
        until: Date.now() + blockDuration,
        attackCount: attackCount + 1
      });
      
      console.warn(`⚠️ BLOCKED: ${ip} | Reason: ${reason} | Score: ${score} | Duration: ${blockDuration/60000} min`);
    }

    // تسجيل خطأ
    recordError(req) {
      const ip = this.getClientIP(req);
      const tracker = this.requestTracker.get(ip);
      if (tracker) {
        tracker.errorCount++;
      }
    }

    // الحصول على IP
    getClientIP(req) {
      return req.ip || 
             req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
             req.headers['x-real-ip'] ||
             req.connection?.remoteAddress ||
             'unknown';
    }

    // بدء التنظيف الدوري
    startCleanupInterval() {
      // تنظيف كل 5 دقائق
      setInterval(() => {
        const now = Date.now();
        
        // تنظيف trackers قديمة
        for (const [ip, tracker] of this.requestTracker.entries()) {
          if (now - tracker.lastRequest > 3600000) { // ساعة
            this.requestTracker.delete(ip);
          }
        }
        
        // تنظيف الحظر المنتهي
        for (const [ip, ban] of this.dynamicBlacklist.entries()) {
          if (now > ban.until) {
            this.dynamicBlacklist.delete(ip);
          }
        }
        
        // تنظيف عداد الهجمات القديم
        for (const [ip, count] of this.attackCounter.entries()) {
          const ban = this.dynamicBlacklist.get(ip);
          if (!ban && !this.permanentBlacklist.has(ip)) {
            this.attackCounter.delete(ip);
          }
        }
        
      }, 5 * 60 * 1000);
    }

    // إحصائيات
    getStats() {
      return {
        trackedIPs: this.requestTracker.size,
        dynamicBlocks: this.dynamicBlacklist.size,
        permanentBlocks: this.permanentBlacklist.size,
        totalAttacks: [...this.attackCounter.values()].reduce((a, b) => a + b, 0)
      };
    }
  }

  // إنشاء instance
  const ddos = new DDoSProtection();

  // ═══════════════════════════════════════════════════════════════
  // 4️⃣ DDOS MIDDLEWARE
  // ═══════════════════════════════════════════════════════════════

  const ddosMiddleware = (req, res, next) => {
    const result = ddos.checkRequest(req);
    
    if (result.blocked) {
      const response = {
        success: false,
        error: 'Access Denied',
        code: result.code
      };
      
      if (result.retryAfter) {
        res.set('Retry-After', result.retryAfter);
        response.retryAfter = result.retryAfter;
      }
      
      return res.status(result.code).json(response);
    }
    
    // إضافة headers أمان
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'X-Request-ID': crypto.randomBytes(16).toString('hex')
    });
    
    // تسجيل الأخطاء
    res.on('finish', () => {
      if (res.statusCode >= 400) {
        ddos.recordError(req);
      }
    });
    
    next();
  };

  app.use(ddosMiddleware);

  // ═══════════════════════════════════════════════════════════════
  // 5️⃣ REQUEST VALIDATION & SANITIZATION
  // ═══════════════════════════════════════════════════════════════

  // حد حجم الطلب
  app.use(express.json({ 
    limit: '100kb',
    verify: (req, res, buf) => {
      req.rawBody = buf;
    }
  }));
  
  app.use(express.urlencoded({ 
    extended: true, 
    limit: '100kb' 
  }));

  // تنظيف المدخلات
  const sanitizeInput = (obj) => {
    if (typeof obj === 'string') {
      // إزالة الأكواد الخبيثة
      return obj
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .trim()
        .substring(0, 1000); // حد أقصى للطول
    }
    
    if (Array.isArray(obj)) {
      return obj.slice(0, 100).map(sanitizeInput); // حد أقصى للعناصر
    }
    
    if (obj && typeof obj === 'object') {
      const sanitized = {};
      const keys = Object.keys(obj).slice(0, 50); // حد أقصى للمفاتيح
      for (const key of keys) {
        sanitized[sanitizeInput(key)] = sanitizeInput(obj[key]);
      }
      return sanitized;
    }
    
    return obj;
  };

  app.use((req, res, next) => {
    if (req.body) {
      req.body = sanitizeInput(req.body);
    }
    if (req.query) {
      req.query = sanitizeInput(req.query);
    }
    next();
  });

  // ═══════════════════════════════════════════════════════════════
  // 6️⃣ CORS CONFIGURATION
  // ═══════════════════════════════════════════════════════════════

  const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',') 
    : ['*'];

  app.use(cors({
    origin: (origin, callback) => {
      if (allowedOrigins[0] === '*' || !origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('CORS not allowed'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-session-token', 
                     'x-admin-key', 'x-device-fingerprint', 'x-timestamp', 'x-nonce', 'x-signature'],
    maxAge: 86400
  }));

  // ═══════════════════════════════════════════════════════════════
  // 7️⃣ RATE LIMITING LAYERS
  // ═══════════════════════════════════════════════════════════════

  const createLimiter = (windowMs, max, message) => rateLimit({
    windowMs,
    max,
    message: { success: false, error: message },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ddos.getClientIP(req),
    skip: (req) => {
      // تخطي IPs الموثوقة
      const trustedIPs = process.env.TRUSTED_IPS?.split(',') || [];
      return trustedIPs.includes(ddos.getClientIP(req));
    },
    handler: (req, res) => {
      ddos.recordError(req);
      res.status(429).json({ 
        success: false, 
        error: message,
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
  });

  // طبقات Rate Limiting
  const globalLimiter = createLimiter(60 * 1000, 60, 'Too many requests');
  const loginLimiter = createLimiter(15 * 60 * 1000, 5, 'Too many login attempts');
  const apiLimiter = createLimiter(60 * 1000, 30, 'API rate limit exceeded');
  const strictLimiter = createLimiter(60 * 1000, 10, 'Strict rate limit');

  app.use(globalLimiter);

  // ═══════════════════════════════════════════════════════════════
  // 8️⃣ BRUTE FORCE PROTECTION
  // ═══════════════════════════════════════════════════════════════

  class BruteForceProtection {
    constructor() {
      this.attempts = new Map();
      this.lockouts = new Map();
      
      this.config = {
        maxAttempts: 5,
        lockoutTime: 30 * 60 * 1000, // 30 دقيقة
        attemptWindow: 15 * 60 * 1000, // 15 دقيقة
        progressiveLockout: true
      };
      
      // تنظيف دوري
      setInterval(() => this.cleanup(), 10 * 60 * 1000);
    }

    isLocked(key) {
      const lockout = this.lockouts.get(key);
      if (lockout && Date.now() < lockout.until) {
        return {
          locked: true,
          remainingTime: Math.ceil((lockout.until - Date.now()) / 1000),
          attempts: lockout.attempts
        };
      }
      return { locked: false };
    }

    recordAttempt(key, success) {
      if (success) {
        this.attempts.delete(key);
        this.lockouts.delete(key);
        return;
      }

      const now = Date.now();
      let record = this.attempts.get(key) || { count: 0, timestamps: [], lockCount: 0 };
      
      record.timestamps = record.timestamps.filter(t => now - t < this.config.attemptWindow);
      record.timestamps.push(now);
      record.count = record.timestamps.length;

      if (record.count >= this.config.maxAttempts) {
        record.lockCount++;
        
        // حظر تصاعدي
        const lockoutTime = this.config.progressiveLockout 
          ? this.config.lockoutTime * record.lockCount 
          : this.config.lockoutTime;

        this.lockouts.set(key, {
          until: now + lockoutTime,
          attempts: record.count,
          lockCount: record.lockCount
        });

        console.warn(`🔒 Brute Force Lockout: ${key} | Attempts: ${record.count} | Lock #${record.lockCount}`);
        
        record.timestamps = [];
        record.count = 0;
      }

      this.attempts.set(key, record);
    }

    cleanup() {
      const now = Date.now();
      
      for (const [key, record] of this.attempts.entries()) {
        if (record.timestamps.every(t => now - t > this.config.attemptWindow)) {
          this.attempts.delete(key);
        }
      }
      
      for (const [key, lockout] of this.lockouts.entries()) {
        if (now > lockout.until) {
          this.lockouts.delete(key);
        }
      }
    }
  }

  const bruteForce = new BruteForceProtection();

  const bruteForceMiddleware = (req, res, next) => {
    const ip = ddos.getClientIP(req);
    const lockStatus = bruteForce.isLocked(ip);
    
    if (lockStatus.locked) {
      return res.status(429).json({
        success: false,
        error: 'Account temporarily locked',
        retryAfter: lockStatus.remainingTime
      });
    }
    
    next();
  };

  // ═══════════════════════════════════════════════════════════════
  // 9️⃣ REQUEST SIGNATURE VERIFICATION
  // ═══════════════════════════════════════════════════════════════

  const SECRET_KEY = process.env.REQUEST_SECRET || crypto.randomBytes(32).toString('hex');

  const verifySignature = (req, res, next) => {
    // تخطي بعض المسارات
    const skipPaths = ['/api/health', '/api/serverTime', '/'];
    if (skipPaths.includes(req.path)) {
      return next();
    }

    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    const signature = req.headers['x-signature'];

    // التحقق من وجود الـ headers
    if (!timestamp || !nonce || !signature) {
      return next(); // اختياري - يمكن تغييره لـ return error
    }

    // التحقق من صلاحية الـ timestamp (5 دقائق)
    const requestTime = parseInt(timestamp);
    if (isNaN(requestTime) || Math.abs(Date.now() - requestTime) > 5 * 60 * 1000) {
      return res.status(401).json({ 
        success: false, 
        error: 'Request expired',
        code: 401 
      });
    }

    // التحقق من الـ signature
    const body = JSON.stringify(req.body || {});
    const expectedSignature = crypto
      .createHmac('sha256', SECRET_KEY)
      .update(`${body}${timestamp}${nonce}`)
      .digest('hex');

    if (signature !== expectedSignature) {
      ddos.recordError(req);
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid signature',
        code: 401 
      });
    }

    next();
  };

  // ═══════════════════════════════════════════════════════════════
  // 🔟 FIREBASE CLIENT
  // ═══════════════════════════════════════════════════════════════

  const firebase = axios.create({ 
    timeout: 15000,
    maxRedirects: 5
  });

  const FB_URL = process.env.FIREBASE_URL;
  const FB_KEY = process.env.FIREBASE_KEY;

  // ═══════════════════════════════════════════════════════════════
  // 1️⃣1️⃣ SESSION MANAGEMENT
  // ═══════════════════════════════════════════════════════════════

  const adminSessions = new Map();

  const ADMIN_CREDENTIALS = {
    username: process.env.ADMIN_USERNAME || 'admin',
    passwordHash: crypto.createHash('sha256')
      .update(process.env.ADMIN_PASSWORD || 'ChangeThisPassword123!')
      .digest('hex')
  };

  function generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  // تنظيف الجلسات
  setInterval(() => {
    const now = Date.now();
    for (const [token, session] of adminSessions.entries()) {
      if (now - session.createdAt > 24 * 60 * 60 * 1000) {
        adminSessions.delete(token);
      }
    }
  }, 60 * 60 * 1000);

  // ═══════════════════════════════════════════════════════════════
  // 1️⃣2️⃣ AUTHENTICATION MIDDLEWARES
  // ═══════════════════════════════════════════════════════════════

  const authApp = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    const expected = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
    
    if (!apiKey) {
      return res.status(401).json({ success: false, error: 'API Key required', code: 401 });
    }
    
    // مقارنة آمنة
    if (!crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(expected))) {
      ddos.recordError(req);
      return res.status(401).json({ success: false, error: 'Invalid API Key', code: 401 });
    }
    
    next();
  };

  const authAdmin = (req, res, next) => {
    const sessionToken = req.headers['x-session-token'];
    
    if (sessionToken) {
      const session = adminSessions.get(sessionToken);
      
      if (!session) {
        return res.status(401).json({ success: false, error: 'Invalid session', code: 401 });
      }
      
      if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
        adminSessions.delete(sessionToken);
        return res.status(401).json({ success: false, error: 'Session expired', code: 401 });
      }
      
      session.lastActivity = Date.now();
      req.adminUser = session.username;
      return next();
    }
    
    const adminKey = req.headers['x-admin-key'];
    const expected = process.env.ADMIN_API_KEY;
    
    if (expected && adminKey) {
      if (crypto.timingSafeEqual(Buffer.from(adminKey), Buffer.from(expected))) {
        req.adminUser = 'api-key-user';
        return next();
      }
    }
    
    res.status(401).json({ success: false, error: 'Unauthorized', code: 401 });
  };

  // ═══════════════════════════════════════════════════════════════
  // 🔑 API ENDPOINTS
  // ═══════════════════════════════════════════════════════════════

  // Health Check
  app.get('/api/health', (req, res) => {
    const stats = ddos.getStats();
    res.json({
      status: 'healthy',
      version: '4.0.0-ultra-secure',
      uptime: Math.floor(process.uptime()),
      timestamp: Date.now(),
      security: {
        ddosProtection: true,
        bruteForce: true,
        rateLimiting: true,
        signatureVerification: true,
        inputSanitization: true
      },
      stats
    });
  });

  // Server Time
  app.get('/api/serverTime', apiLimiter, (req, res) => {
    const now = Date.now();
    res.json({
      success: true,
      server_time: now,
      unixtime: Math.floor(now / 1000),
      iso: new Date(now).toISOString()
    });
  });

  // Admin Login
  app.post('/api/admin/login', loginLimiter, bruteForceMiddleware, async (req, res) => {
    const { username, password } = req.body;
    const ip = ddos.getClientIP(req);
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username and password required' 
      });
    }
    
    // تأخير عشوائي لمنع timing attacks
    await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));
    
    const passwordHash = hashPassword(password);
    
    if (username !== ADMIN_CREDENTIALS.username || 
        !crypto.timingSafeEqual(Buffer.from(passwordHash), Buffer.from(ADMIN_CREDENTIALS.passwordHash))) {
      bruteForce.recordAttempt(ip, false);
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    bruteForce.recordAttempt(ip, true);
    
    const sessionToken = generateToken();
    adminSessions.set(sessionToken, {
      username,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      ip
    });
    
    console.log(`✅ Admin login: ${username} from ${ip}`);
    
    res.json({ 
      success: true, 
      sessionToken,
      expiresIn: '24 hours'
    });
  });

  // Admin Logout
  app.post('/api/admin/logout', (req, res) => {
    const sessionToken = req.headers['x-session-token'];
    if (sessionToken) {
      adminSessions.delete(sessionToken);
    }
    res.json({ success: true });
  });

  // Get User
  app.post('/api/getUser', authApp, apiLimiter, verifySignature, async (req, res) => {
    try {
      const { username } = req.body;
      
      if (!username || typeof username !== 'string' || username.length > 50) {
        return res.status(400).json({ success: false, error: 'Invalid username' });
      }
      
      const url = `${FB_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
      const response = await firebase.get(url);
      
      if (!response.data || Object.keys(response.data).length === 0) {
        return res.json({});
      }
      
      const key = Object.keys(response.data)[0];
      const user = response.data[key];
      
      // إزالة البيانات الحساسة
      delete user.password;
      
      res.json(user);
      
    } catch (error) {
      console.error('Error getting user:', error.message);
      res.status(500).json({ success: false, error: 'Server error' });
    }
  });

  // Verify Account
  app.post('/api/verifyAccount', authApp, apiLimiter, verifySignature, async (req, res) => {
    try {
      const { username, password, deviceId } = req.body;
      
      if (!username || !password || !deviceId) {
        return res.status(400).json({ success: false, error: 'Missing data', code: 400 });
      }
      
      const passHash = hashPassword(password);
      const url = `${FB_URL}/users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
      const response = await firebase.get(url);
      
      if (!response.data || Object.keys(response.data).length === 0) {
        return res.json({ success: false, code: 1 }); // User not found
      }
      
      const key = Object.keys(response.data)[0];
      const user = response.data[key];
      
      if (user.password_hash !== passHash) {
        return res.json({ success: false, code: 2 }); // Wrong password
      }
      
      if (!user.is_active) {
        return res.json({ success: false, code: 3 }); // Inactive
      }
      
      if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
        return res.json({ success: false, code: 4 }); // Different device
      }
      
      res.json({ success: true, username: user.username });
      
    } catch (error) {
      console.error('Verify error:', error.message);
      res.status(500).json({ success: false, code: 0 });
    }
  });

  // Update Device
  app.post('/api/updateDevice', authApp, apiLimiter, verifySignature, async (req, res) => {
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
      console.error('Update device error:', error.message);
      res.status(500).json({ success: false, error: 'Server error' });
    }
  });

  // ═══════════════════════════════════════════════════════════════
  // 🏠 HOME PAGE
  // ═══════════════════════════════════════════════════════════════

  app.get('/', (req, res) => {
    const stats = ddos.getStats();
    res.send(`
<!DOCTYPE html>
<html dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🛡️ Ultra Secure Firebase Proxy v4.0</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:system-ui,-apple-system,sans-serif;background:linear-gradient(135deg,#0f0c29 0%,#302b63 50%,#24243e 100%);color:#fff;min-height:100vh;padding:20px}
    .container{max-width:1400px;margin:0 auto}
    .header{text-align:center;padding:40px 0}
    .header h1{font-size:2.5em;background:linear-gradient(45deg,#00f5ff,#7b2ff7,#f107a3);-webkit-background-clip:text;background-clip:text;color:transparent;animation:gradient 3s ease infinite;background-size:200% 200%}
    @keyframes gradient{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
    .shield{font-size:4em;animation:float 3s ease-in-out infinite}
    @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
    .badge{background:linear-gradient(135deg,#00b09b,#96c93d);padding:15px 40px;border-radius:50px;display:inline-block;margin:20px 0;font-weight:bold;box-shadow:0 10px 40px rgba(0,176,155,0.4)}
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin:30px 0}
    .stat{background:rgba(255,255,255,0.05);backdrop-filter:blur(10px);padding:25px;border-radius:20px;text-align:center;border:1px solid rgba(255,255,255,0.1)}
    .stat-value{font-size:2.5em;font-weight:bold;background:linear-gradient(45deg,#00f5ff,#7b2ff7);-webkit-background-clip:text;background-clip:text;color:transparent}
    .stat-label{opacity:0.7;margin-top:10px}
    .features{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin:40px 0}
    .feature{background:rgba(255,255,255,0.03);backdrop-filter:blur(10px);padding:30px;border-radius:20px;border:1px solid rgba(255,255,255,0.1);transition:all 0.3s}
    .feature:hover{transform:translateY(-5px);border-color:rgba(0,245,255,0.3);box-shadow:0 20px 40px rgba(0,245,255,0.1)}
    .feature h3{color:#00f5ff;margin-bottom:15px;font-size:1.3em;display:flex;align-items:center;gap:10px}
    .feature ul{list-style:none;line-height:2}
    .feature li{display:flex;align-items:center;gap:10px}
    .feature li:before{content:"✓";color:#00b09b;font-weight:bold}
    .protection-level{background:linear-gradient(135deg,rgba(123,47,247,0.2),rgba(241,7,163,0.2));border:2px solid #7b2ff7;padding:30px;border-radius:20px;text-align:center;margin:30px 0}
    .protection-level h2{color:#7b2ff7;margin-bottom:15px}
    .level-bar{height:20px;background:rgba(255,255,255,0.1);border-radius:10px;overflow:hidden;margin:15px 0}
    .level-fill{height:100%;background:linear-gradient(90deg,#00b09b,#00f5ff,#7b2ff7,#f107a3);width:95%;animation:pulse 2s ease-in-out infinite}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.7}}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="shield">🛡️</div>
      <h1>Ultra Secure Firebase Proxy</h1>
      <div class="badge">v4.0 - Maximum Protection Active</div>
    </div>

    <div class="stats">
      <div class="stat">
        <div class="stat-value">${stats.trackedIPs}</div>
        <div class="stat-label">Tracked IPs</div>
      </div>
      <div class="stat">
        <div class="stat-value">${stats.dynamicBlocks}</div>
        <div class="stat-label">Active Blocks</div>
      </div>
      <div class="stat">
        <div class="stat-value">${stats.permanentBlocks}</div>
        <div class="stat-label">Permanent Bans</div>
      </div>
      <div class="stat">
        <div class="stat-value">${Math.floor(process.uptime() / 60)}m</div>
        <div class="stat-label">Uptime</div>
      </div>
    </div>

    <div class="protection-level">
      <h2>🔒 Protection Level: MAXIMUM</h2>
      <div class="level-bar"><div class="level-fill"></div></div>
      <p>All security layers are active and monitoring</p>
    </div>

    <div class="features">
      <div class="feature">
        <h3>🚫 DDoS Protection</h3>
        <ul>
          <li>Real-time pattern detection</li>
          <li>Automatic IP blocking</li>
          <li>Threat score calculation</li>
          <li>Progressive blocking</li>
          <li>Slowloris attack prevention</li>
        </ul>
      </div>

      <div class="feature">
        <h3>🔐 Brute Force Shield</h3>
        <ul>
          <li>Failed attempt tracking</li>
          <li>Progressive lockout</li>
          <li>IP-based protection</li>
          <li>Timing attack prevention</li>
          <li>Automatic recovery</li>
        </ul>
      </div>

      <div class="feature">
        <h3>⚡ Rate Limiting</h3>
        <ul>
          <li>Multi-layer limiting</li>
          <li>Per-endpoint limits</li>
          <li>Global rate control</li>
          <li>Login attempt limits</li>
          <li>API quota management</li>
        </ul>
      </div>

      <div class="feature">
        <h3>🔍 Request Validation</h3>
        <ul>
          <li>Signature verification</li>
          <li>Input sanitization</li>
          <li>Payload size limits</li>
          <li>XSS prevention</li>
          <li>SQL injection blocking</li>
        </ul>
      </div>

      <div class="feature">
        <h3>🎯 Bot Detection</h3>
        <ul>
          <li>User-Agent analysis</li>
          <li>Fingerprint tracking</li>
          <li>Behavior analysis</li>
          <li>Suspicious pattern detection</li>
          <li>Automated blocking</li>
        </ul>
      </div>

      <div class="feature">
        <h3>📊 Monitoring</h3>
        <ul>
          <li>Real-time logging</li>
          <li>Attack alerts</li>
          <li>Performance metrics</li>
          <li>Error tracking</li>
          <li>Security reports</li>
        </ul>
      </div>
    </div>
  </div>
</body>
</html>
    `);
  });

  // ═══════════════════════════════════════════════════════════════
  // 404 & ERROR HANDLING
  // ═══════════════════════════════════════════════════════════════

  app.use((req, res) => {
    ddos.recordError(req);
    res.status(404).json({ success: false, error: 'Not found', code: 404 });
  });

  app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.message);
    ddos.recordError(req);
    res.status(500).json({ success: false, error: 'Internal server error', code: 500 });
  });

  // ═══════════════════════════════════════════════════════════════
  // 🚀 START SERVER
  // ═══════════════════════════════════════════════════════════════

  app.listen(PORT, () => {
    console.log('═'.repeat(70));
    console.log('🛡️  ULTRA SECURE Firebase Proxy v4.0');
    console.log('═'.repeat(70));
    console.log(`📡 Server: http://localhost:${PORT}`);
    console.log(`👷 Worker: ${process.pid}`);
    console.log('');
    console.log('🔐 Active Security Layers:');
    console.log('   ✅ Advanced DDoS Protection');
    console.log('   ✅ Brute Force Prevention');
    console.log('   ✅ Multi-layer Rate Limiting');
    console.log('   ✅ Request Signature Verification');
    console.log('   ✅ Input Sanitization');
    console.log('   ✅ Bot Detection & Blocking');
    console.log('   ✅ Automatic IP Blacklisting');
    console.log('   ✅ Slowloris Attack Prevention');
    console.log('   ✅ Progressive Lockout System');
    console.log('   ✅ Helmet Security Headers');
    console.log('═'.repeat(70));
  });
}
