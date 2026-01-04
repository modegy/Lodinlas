// server.js - SecureArmor Main Server v14.1
'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const config = require('./config');

const app = express();

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 1. SECURITY MIDDLEWARE - تحميل أولاً
// ═══════════════════════════════════════════════════════════════════
let security = null;
try {
    const securityModule = require('./middleware/security');
    security = securityModule.init(config);
    app.use(security.middleware());
    console.log('✅ Security middleware loaded successfully');
} catch (err) {
    console.warn('⚠️ Security middleware not found, continuing without it');
}

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 2. CORS
// ═══════════════════════════════════════════════════════════════════
const corsOptions = {
    origin: (origin, callback) => {
        const allowedOrigins = config.CORS?.ALLOWED_ORIGINS || [];
        
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes('*') && process.env.NODE_ENV !== 'production') {
            return callback(null, true);
        }
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`🚫 CORS Blocked: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type', 'Authorization', 'Accept',
        'X-API-Key', 'X-Client-ID', 'X-Session-Token',
        'X-Device-Fingerprint', 'X-API-Signature',
        'X-Timestamp', 'X-Nonce', 'X-Master-Token',
        'X-Admin-Key', 'X-API-Timestamp', 'X-API-Nonce'
    ],
    exposedHeaders: ['X-Session-Token'],
    maxAge: 86400
};

app.use(cors(corsOptions));

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 3. Security Headers (Helmet)
// ═══════════════════════════════════════════════════════════════════
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            frameSrc: ["'none'"],
            frameAncestors: ["'none'"]
        }
    },
    crossOriginResourcePolicy: { policy: "same-site" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginEmbedderPolicy: false,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 4. Body Parsers
// ═══════════════════════════════════════════════════════════════════
app.use(express.json({ 
    limit: '2mb',
    verify: (req, res, buf) => { req.rawBody = buf.toString(); }
}));
app.use(express.urlencoded({ extended: true, limit: '2mb', parameterLimit: 50 }));

// ═══════════════════════════════════════════════════════════════════
// 📝 5. Request Logger
// ═══════════════════════════════════════════════════════════════════
app.use((req, res, next) => {
    const ip = req.clientIP || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
    console.log(`[${timestamp}] ${ip} - ${req.method} ${req.path}`);
    next();
});

// ═══════════════════════════════════════════════════════════════════
// 📡 6. المسارات العامة (بدون توثيق)
// ═══════════════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
    const mem = process.memoryUsage();
    const securityStats = security?.getStats() || {};
    
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        memory: {
            used: Math.round(mem.heapUsed / 1024 / 1024) + 'MB',
            total: Math.round(mem.heapTotal / 1024 / 1024) + 'MB'
        },
        security: {
            active: !!security,
            blockedIPs: securityStats.blockedIPs || 0,
            totalRequests: securityStats.totalRequests || 0
        },
        version: '14.1.0'
    });
});

app.get('/api/serverTime', (req, res) => {
    const now = new Date();
    res.json({
        unixtime: Math.floor(now.getTime() / 1000),
        datetime: now.toISOString(),
        timestamp: now.getTime()
    });
});

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 7. Content-Type Validation
// ═══════════════════════════════════════════════════════════════════
app.use('/api', (req, res, next) => {
    if (req.path === '/serverTime' || req.method === 'GET') return next();
    
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
        const contentType = req.headers['content-type'];
        if (!contentType || !contentType.includes('application/json')) {
            return res.status(415).json({
                success: false,
                error: 'Unsupported Media Type. Use application/json'
            });
        }
    }
    next();
});

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 8. NoSQL Injection Protection
// ═══════════════════════════════════════════════════════════════════
app.use('/api', (req, res, next) => {
    const dangerousPatterns = [
        /\$where/i, /\$ne/i, /\$gt/i, /\$lt/i, /\$in/i,
        /\$nin/i, /\$exists/i, /\$regex/i,
        /\.\.\//, /\/etc\/passwd/, /\/proc\/self/
    ];
    
    const checkObj = (obj) => {
        for (let key in obj) {
            const val = obj[key];
            if (typeof val === 'string') {
                for (let pattern of dangerousPatterns) {
                    if (pattern.test(val) || pattern.test(key)) {
                        console.warn(`⚠️ Injection attempt from IP: ${req.clientIP || req.ip}`);
                        return false;
                    }
                }
            } else if (typeof val === 'object' && val !== null) {
                if (!checkObj(val)) return false;
            }
        }
        return true;
    };
    
    if (!checkObj(req.body) || !checkObj(req.query)) {
        return res.status(400).json({ success: false, error: 'Invalid input detected' });
    }
    next();
});

// ═══════════════════════════════════════════════════════════════════
// ⏱️ 9. Rate Limiting (Express)
// ═══════════════════════════════════════════════════════════════════
const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: config.SECURITY?.RATE_LIMITS?.API?.capacity || 50,
    message: { success: false, error: 'Too many requests', retryAfter: '15 minutes' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/serverTime',
    keyGenerator: (req) => req.clientIP || req.ip
});

app.use('/api', apiLimiter);

// ═══════════════════════════════════════════════════════════════════
// 🔐 10. استيراد Auth Middleware
// ═══════════════════════════════════════════════════════════════════
let authApp, authAdmin, authSubAdmin, checkSubAdminPermission, checkUserOwnership;

try {
    const authModule = require('./middleware/auth');
    authApp = authModule.authApp;
    authAdmin = authModule.authAdmin;
    authSubAdmin = authModule.authSubAdmin;
    checkSubAdminPermission = authModule.checkSubAdminPermission;
    checkUserOwnership = authModule.checkUserOwnership;
    console.log('✅ Auth middleware loaded successfully');
} catch (err) {
    console.error('❌ Failed to load auth middleware:', err.message);
    const fallback = (req, res, next) => next();
    authApp = fallback;
    authAdmin = fallback;
    authSubAdmin = fallback;
    checkSubAdminPermission = () => fallback;
    checkUserOwnership = fallback;
}

// ═══════════════════════════════════════════════════════════════════
// 🔐 11. تطبيق التوثيق على المسارات
// ═══════════════════════════════════════════════════════════════════

// المسارات المحمية للتطبيق (API Key + Signature)
const appProtectedPaths = ['/api/verifyAccount', '/api/getUser', '/api/updateDevice'];
app.use(appProtectedPaths, authApp);

// مسارات الأدمن (Session Token / Master Token)
app.use('/api/admin', authAdmin);

// مسارات الـ Sub-Admin (API Key خاص)
app.use('/api/sub', authSubAdmin);

// ═══════════════════════════════════════════════════════════════════
// 📡 12. ROUTES
// ═══════════════════════════════════════════════════════════════════
const loadRoute = (path, mountPath, name) => {
    try {
        const route = require(path);
        app.use(mountPath, route);
        console.log(`✅ ${name} routes loaded: ${mountPath}/*`);
        return true;
    } catch (e) {
        console.warn(`⚠️ Failed to load ${name} routes:`, e.message);
        return false;
    }
};

loadRoute('./routes/mobile', '/api', 'Mobile');
loadRoute('./routes/admin', '/api/admin', 'Admin');
loadRoute('./routes/subadmin', '/api/sub', 'SubAdmin');

// ═══════════════════════════════════════════════════════════════════
// 📡 13. Fallback Routes
// ═══════════════════════════════════════════════════════════════════
app.post('/api/getUser', async (req, res) => {
    try {
        const { firebase, FB_KEY } = require('./services/firebase');
        const { username } = req.body;
        if (!username) return res.status(400).json(null);
        
        const response = await firebase.get(`users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`);
        const users = response.data || {};
        if (Object.keys(users).length === 0) return res.json(null);
        
        const userId = Object.keys(users)[0];
        const user = users[userId];
        res.json({
            username: user.username,
            is_active: user.is_active !== false,
            device_id: user.device_id || '',
            subscription_end: user.subscription_end
        });
    } catch (error) {
        console.error('Fallback getUser error:', error.message);
        res.status(500).json(null);
    }
});

app.post('/api/verifyAccount', async (req, res) => {
    try {
        const { firebase, FB_KEY } = require('./services/firebase');
        const crypto = require('crypto');
        const { username, password, deviceId } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Missing fields', code: 400 });
        }
        
        const passHash = crypto.createHash('sha256').update(password, 'utf8').digest('hex');
        const response = await firebase.get(`users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`);
        const users = response.data || {};
        
        if (Object.keys(users).length === 0) return res.json({ success: false, code: 1 });
        
        const userId = Object.keys(users)[0];
        const user = users[userId];
        
        if (user.password_hash !== passHash) return res.json({ success: false, code: 2 });
        if (user.is_active === false) return res.json({ success: false, code: 3 });
        if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
            return res.json({ success: false, code: 4 });
        }
        
        res.json({ success: true, username: user.username, code: 200 });
    } catch (error) {
        console.error('Fallback verifyAccount error:', error.message);
        res.status(500).json({ success: false, code: 0 });
    }
});

// ═══════════════════════════════════════════════════════════════════
// ❌ 14. Error Handlers
// ═══════════════════════════════════════════════════════════════════
app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
    const errorId = `ERR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    console.error(`[${errorId}] Error:`, err.message);
    
    const statusCode = err.message.includes('CORS') ? 403 : 500;
    res.status(statusCode).json({
        success: false,
        error: statusCode === 403 ? 'Access forbidden' : 'Internal server error',
        reference: errorId
    });
});

// ═══════════════════════════════════════════════════════════════════
// 🚀 15. START SERVER
// ═══════════════════════════════════════════════════════════════════
const PORT = config.PORT || 10000;

app.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '═'.repeat(60));
    console.log('🚀 SecureArmor Server v14.1');
    console.log('═'.repeat(60));
    console.log(`📍 Port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'production'}`);
    console.log(`🔐 API Key: ${config.APP_API_KEY ? '✅ Set' : '❌ Missing!'}`);
    console.log(`🔏 Signing Secret: ${config.APP_SIGNING_SECRET ? '✅ Set' : '❌ Missing!'}`);
    console.log(`🛡️ Security Middleware: ${security ? '✅ Active' : '⚠️ Not loaded'}`);
    console.log(`📊 Rate Limiting: ✅ Active`);
    console.log('═'.repeat(60) + '\n');
});

// ═══════════════════════════════════════════════════════════════════
// 🔄 16. Graceful Shutdown
// ═══════════════════════════════════════════════════════════════════
['SIGTERM', 'SIGINT'].forEach(signal => {
    process.on(signal, () => {
        console.log(`📴 ${signal} received, shutting down gracefully...`);
        if (security) security.destroy();
        setTimeout(() => process.exit(0), 5000);
    });
});

process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught Exception:', err.message);
});

process.on('unhandledRejection', (reason) => {
    console.error('❌ Unhandled Rejection:', reason);
});

module.exports = app;
