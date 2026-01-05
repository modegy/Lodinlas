// server.js - SecureArmor Main Server v14.1
'use strict';

const express = require('express');
const helmet = require('helmet');
const config = require('./config');

const app = express();

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 1. CORS - يجب أن يكون أول شيء!
// ═══════════════════════════════════════════════════════════════════
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, X-API-Key, X-Client-ID, X-Session-Token, X-Device-Fingerprint, X-API-Signature, X-Timestamp, X-Nonce, X-Master-Token, X-Admin-Key, X-Fresh-Login, X-API-Timestamp, X-API-Nonce');
    res.setHeader('Access-Control-Expose-Headers', 'X-Session-Token');
    res.setHeader('Access-Control-Max-Age', '86400');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    next();
});

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 2. SECURITY MIDDLEWARE
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
// 🛡️ 3. Security Headers (Helmet)
// ═══════════════════════════════════════════════════════════════════
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginOpenerPolicy: false,
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false
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
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        memory: {
            used: Math.round(mem.heapUsed / 1024 / 1024) + 'MB',
            total: Math.round(mem.heapTotal / 1024 / 1024) + 'MB'
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
    if (req.path === '/serverTime' || req.method === 'GET' || req.method === 'OPTIONS') return next();
    
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
// ⏱️ 8. Rate Limiting
// ═══════════════════════════════════════════════════════════════════
const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, error: 'Too many requests' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/serverTime' || req.method === 'OPTIONS'
});

app.use('/api', apiLimiter);

// ═══════════════════════════════════════════════════════════════════
// 🔐 9. استيراد Auth Middleware
// ═══════════════════════════════════════════════════════════════════
let authApp, authAdmin, authSubAdmin;

try {
    const authModule = require('./middleware/auth');
    authApp = authModule.authApp;
    authAdmin = authModule.authAdmin;
    authSubAdmin = authModule.authSubAdmin;
    console.log('✅ Auth middleware loaded successfully');
} catch (err) {
    console.error('❌ Failed to load auth middleware:', err.message);
    const fallback = (req, res, next) => next();
    authApp = fallback;
    authAdmin = fallback;
    authSubAdmin = fallback;
}

// ═══════════════════════════════════════════════════════════════════
// 🔐 10. تطبيق التوثيق على المسارات
// ═══════════════════════════════════════════════════════════════════

// المسارات المحمية للتطبيق
app.use(['/api/verifyAccount', '/api/getUser', '/api/updateDevice'], authApp);

// مسارات الأدمن - استثناء login
app.use('/api/admin', (req, res, next) => {
    if (req.path === '/login' || req.path === '/auth') {
        return next();
    }
    authAdmin(req, res, next);
});

// مسارات Sub-Admin - استثناء verify-key و login و logout
app.use('/api/sub', (req, res, next) => {
    const publicPaths = ['/verify-key', '/login', '/logout'];
    if (publicPaths.includes(req.path)) {
        return next();
    }
    authSubAdmin(req, res, next);
});

// ═══════════════════════════════════════════════════════════════════
// 📡 11. ROUTES
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
// 📡 12. Fallback Routes
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
// ❌ 13. Error Handlers
// ═══════════════════════════════════════════════════════════════════
app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
    console.error('Error:', err.message);
    res.status(500).json({ success: false, error: 'Internal server error' });
});

// ═══════════════════════════════════════════════════════════════════
// 🚀 14. START SERVER
// ═══════════════════════════════════════════════════════════════════
const PORT = config.PORT || 10000;

app.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '═'.repeat(60));
    console.log('🚀 SecureArmor Server v14.1');
    console.log('═'.repeat(60));
    console.log(`📍 Port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'production'}`);
    console.log(`🔐 API Key: ${config.APP_API_KEY ? '✅' : '❌'}`);
    console.log(`🛡️ Security: ${security ? '✅' : '⚠️'}`);
    console.log('═'.repeat(60) + '\n');
});

// Graceful Shutdown
['SIGTERM', 'SIGINT'].forEach(signal => {
    process.on(signal, () => {
        console.log(`📴 ${signal} received`);
        if (security) security.destroy();
        setTimeout(() => process.exit(0), 5000);
    });
});

process.on('uncaughtException', (err) => console.error('❌ Uncaught:', err.message));
process.on('unhandledRejection', (reason) => console.error('❌ Unhandled:', reason));

module.exports = app;
