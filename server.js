// ═══════════════════════════════════════════════════════════════════
// 🚀 SERVER.JS - SecureArmor v14.1 - Fixed Version
// ═══════════════════════════════════════════════════════════════════

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const config = require('./config');

const app = express();

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 1. CORS - يجب أن يكون أول شيء (قبل أي middleware آخر)
// ═══════════════════════════════════════════════════════════════════
app.use((req, res, next) => {
    // السماح لجميع الأصول أو الأصول المحددة
    const allowedOrigins = config.CORS?.ALLOWED_ORIGINS || ['*'];
    const origin = req.headers.origin;
    
    if (allowedOrigins.includes('*')) {
        res.header('Access-Control-Allow-Origin', '*');
    } else if (origin && allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    } else if (!origin) {
        // للطلبات من التطبيق (بدون origin header)
        res.header('Access-Control-Allow-Origin', '*');
    }
    
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    res.header('Access-Control-Allow-Headers', 
        'Content-Type, Authorization, Accept, Origin, ' +
        'X-API-Key, X-Client-ID, X-Session-Token, X-Device-Fingerprint, ' +
        'X-API-Signature, X-Timestamp, X-Nonce, X-Requested-With'
    );
    res.header('Access-Control-Expose-Headers', 'X-Session-Token, X-RateLimit-Remaining');
    res.header('Access-Control-Max-Age', '86400');
    
    // معالجة طلبات OPTIONS (Preflight)
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    next();
});

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 2. Security Headers (Helmet) - بعد CORS
// ═══════════════════════════════════════════════════════════════════
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginOpenerPolicy: false,
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false,
    xssFilter: true,
    noSniff: true,
    hidePoweredBy: true
}));

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 3. Body Parsers
// ═══════════════════════════════════════════════════════════════════
app.use(express.json({ 
    limit: '10mb',
    verify: (req, res, buf) => {
        req.rawBody = buf.toString();
    }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 4. Request Logger (للتشخيص)
// ═══════════════════════════════════════════════════════════════════
app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const timestamp = new Date().toISOString();
    
    // تسجيل الطلبات المهمة فقط
    if (!req.path.includes('health') && !req.path.includes('favicon')) {
        console.log(`[${timestamp}] ${req.method} ${req.path} | IP: ${ip}`);
    }
    
    next();
});

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 5. Rate Limiting (اختياري - يمكن تفعيله)
// ═══════════════════════════════════════════════════════════════════
let rateLimiter;
try {
    const rateLimit = require('express-rate-limit');
    rateLimiter = rateLimit({
        windowMs: 60 * 1000, // دقيقة واحدة
        max: config.SECURITY?.RATE_LIMITS?.GLOBAL?.capacity || 100,
        message: { success: false, error: 'Too many requests, please try again later' },
        standardHeaders: true,
        legacyHeaders: false,
        skip: (req) => {
            // تخطي بعض المسارات
            return req.path === '/health' || req.path === '/api/serverTime';
        }
    });
    app.use('/api/', rateLimiter);
    console.log('✅ Rate limiting enabled');
} catch (e) {
    console.log('⚠️ Rate limiting not available');
}

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 6. Security Middleware (إذا موجود)
// ═══════════════════════════════════════════════════════════════════
let securityMiddleware;
try {
    const security = require('./middleware/security');
    if (security.securityMiddleware) {
        app.use(security.securityMiddleware);
        console.log('✅ Security middleware loaded');
    }
} catch (e) {
    console.log('⚠️ Security middleware not found, continuing without it');
}



// في server.js - إضافة التوثيق المتقدم
const { signatureAuth, apiKeyAuth, adminAuth, apiKeyRateLimit } = require('./middleware/auth');

// ... بعد security middleware ...

// 🔐 تطبيق التوثيق المتقدم
app.use(signatureAuth);
app.use(apiKeyAuth);
app.use(apiKeyRateLimit);

// 👤 توثيق الإدارة (للمسارات الإدارية فقط)
app.use('/api/admin', adminAuth);
app.use('/api/sub', adminAuth);

// ... بقية الكود ...




// ═══════════════════════════════════════════════════════════════════
// 📡 7. API ENDPOINTS - الأساسية (قبل الـ routes)
// ═══════════════════════════════════════════════════════════════════

// ✅ Server Time - مطلوب من التطبيق
app.get('/api/serverTime', (req, res) => {
    const now = new Date();
    res.json({
        unixtime: Math.floor(now.getTime() / 1000),
        datetime: now.toISOString(),
        timestamp: now.getTime(),
        timezone: 'UTC',
        formatted: now.toLocaleString('en-US', { timeZone: 'UTC' })
    });
});

// ✅ Health Check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        version: '3.4.1',
        memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB'
    });
});

// ✅ Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'SecureArmor API Server v14.1',
        version: '3.4.1',
        status: 'running',
        timestamp: new Date().toISOString(),
        endpoints: {
            health: '/health',
            serverTime: '/api/serverTime',
            mobile: '/api/*',
            admin: '/api/admin/*',
            subadmin: '/api/sub/*'
        }
    });
});

// ═══════════════════════════════════════════════════════════════════
// 📡 8. ROUTES - استيراد الـ routes الموجودة
// ═══════════════════════════════════════════════════════════════════

// Mobile Routes (للتطبيق)
try {
    const mobileRoutes = require('./routes/mobile');
    app.use('/api', mobileRoutes);
    console.log('✅ Mobile routes loaded: /api/*');
} catch (e) {
    console.error('❌ Failed to load mobile routes:', e.message);
}

// Admin Routes (للوحة التحكم)
try {
    const adminRoutes = require('./routes/admin');
    app.use('/api/admin', adminRoutes);
    console.log('✅ Admin routes loaded: /api/admin/*');
} catch (e) {
    console.error('❌ Failed to load admin routes:', e.message);
}

// SubAdmin Routes (للمشرفين الفرعيين)
try {
    const subAdminRoutes = require('./routes/subadmin');
    app.use('/api/sub', subAdminRoutes);
    console.log('✅ SubAdmin routes loaded: /api/sub/*');
} catch (e) {
    console.error('❌ Failed to load subadmin routes:', e.message);
}

// ═══════════════════════════════════════════════════════════════════
// 📡 9. FALLBACK ROUTES - في حالة عدم وجود mobile.js
// ═══════════════════════════════════════════════════════════════════

// Fallback getUser إذا لم يكن موجوداً
app.post('/api/getUser', async (req, res, next) => {
    // إذا تم التعامل معه بالفعل، تخطي
    if (res.headersSent) return;
    
    try {
        const { firebase, FB_KEY } = require('./services/firebase');
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
        
        // تنسيق التاريخ
        const formatDate = (timestamp) => {
            if (!timestamp) return '';
            const date = new Date(timestamp);
            const day = String(date.getDate()).padStart(2, '0');
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const year = date.getFullYear();
            const hours = String(date.getHours()).padStart(2, '0');
            const minutes = String(date.getMinutes()).padStart(2, '0');
            return `${day}/${month}/${year} ${hours}:${minutes}`;
        };
        
        res.json({
            username: user.username,
            password_hash: user.password_hash,
            is_active: user.is_active !== false,
            device_id: user.device_id || '',
            expiry_date: formatDate(user.subscription_end || user.expiry_timestamp),
            subscription_end: user.subscription_end || user.expiry_timestamp
        });
        
    } catch (error) {
        console.error('Fallback getUser error:', error.message);
        res.status(500).json(null);
    }
});

// Fallback updateDevice إذا لم يكن موجوداً
app.post('/api/updateDevice', async (req, res, next) => {
    if (res.headersSent) return;
    
    try {
        const { firebase, FB_KEY } = require('./services/firebase');
        const { username, deviceId, deviceInfo } = req.body;
        
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
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
        
        const updateData = {
            device_id: deviceId,
            last_login: Date.now(),
            ip_address: ip
        };
        
        if (deviceInfo) {
            Object.assign(updateData, {
                device_model: deviceInfo.device_model || 'Unknown',
                device_brand: deviceInfo.device_brand || 'Unknown',
                android_version: deviceInfo.android_version || 'Unknown',
                is_rooted: deviceInfo.is_rooted || false
            });
        }
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, updateData);
        
        console.log(`📱 Device updated: ${username} | IP: ${ip}`);
        
        res.json({ success: true, message: 'Device updated successfully' });
        
    } catch (error) {
        console.error('Fallback updateDevice error:', error.message);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// Fallback verifyAccount إذا لم يكن موجوداً
app.post('/api/verifyAccount', async (req, res, next) => {
    if (res.headersSent) return;
    
    try {
        const { firebase, FB_KEY } = require('./services/firebase');
        const crypto = require('crypto');
        const { username, password, deviceId } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Missing fields', code: 400 });
        }
        
        const passHash = crypto.createHash('sha256').update(password, 'utf8').digest('hex');
        
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
        
        if (user.is_active === false) {
            return res.json({ success: false, code: 3 });
        }
        
        if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
            return res.json({ success: false, code: 4 });
        }
        
        res.json({ success: true, username: user.username, code: 200 });
        
    } catch (error) {
        console.error('Fallback verifyAccount error:', error.message);
        res.status(500).json({ success: false, code: 0, error: 'Server error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// ❌ 10. Error Handlers
// ═══════════════════════════════════════════════════════════════════

// 404 Handler
app.use((req, res, next) => {
    res.status(404).json({ 
        success: false, 
        error: 'Endpoint not found',
        path: req.path,
        method: req.method
    });
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.message);
    console.error(err.stack);
    
    res.status(err.status || 500).json({
        success: false,
        error: config.NODE_ENV === 'production' ? 'Internal server error' : err.message,
        ...(config.NODE_ENV !== 'production' && { stack: err.stack })
    });
});

// ═══════════════════════════════════════════════════════════════════
// 🚀 11. START SERVER
// ═══════════════════════════════════════════════════════════════════

const PORT = config.PORT || process.env.PORT || 10000;

app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('🚀 SecureArmor Server v14.1 Started Successfully!');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`📍 Port: ${PORT}`);
    console.log(`🌍 Environment: ${config.NODE_ENV || 'production'}`);
    console.log(`🔥 Firebase: ${config.FIREBASE_URL ? '✅ Configured' : '❌ Not configured'}`);
    console.log(`👤 Admin: ${config.ADMIN_CREDENTIALS?.username || 'Not set'}`);
    console.log(`🔑 API Key: ${config.APP_API_KEY ? '✅ Set' : '⚠️ Using default'}`);
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('📡 Available Endpoints:');
    console.log('   GET  /health          - Health check');
    console.log('   GET  /api/serverTime  - Server time');
    console.log('   POST /api/getUser     - Get user data');
    console.log('   POST /api/updateDevice - Update device');
    console.log('   POST /api/verifyAccount - Verify account');
    console.log('   POST /api/admin/login - Admin login');
    console.log('   POST /api/sub/verify-key - SubAdmin verify');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('');
});

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 12. Graceful Shutdown
// ═══════════════════════════════════════════════════════════════════

process.on('SIGTERM', () => {
    console.log('📴 SIGTERM received, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('📴 SIGINT received, shutting down gracefully...');
    process.exit(0);
});

process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught Exception:', err.message);
    console.error(err.stack);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise);
    console.error('Reason:', reason);
});

module.exports = app;
