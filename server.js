const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const config = require('./config');

const app = express();

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 1. CORS - إعدادات آمنة للإنتاج
// ═══════════════════════════════════════════════════════════════════
const corsOptions = {
    origin: (origin, callback) => {
        // في الإنتاج: أصل محدد فقط، لا تسمح بـ '*' أبداً
        const allowedOrigins = config.CORS?.ALLOWED_ORIGINS || [];
        
        // للطلبات بدون origin (mobile apps, curl, etc)
        if (!origin && process.env.NODE_ENV === 'production') {
            return callback(null, false);
        }
        
        // في التطوير: السماح بالطلبات بدون origin للاختبار
        if (!origin && process.env.NODE_ENV === 'development') {
            return callback(null, true);
        }
        
        // التحقق من القائمة البيضاء
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
        'Content-Type', 
        'Authorization', 
        'Accept',
        'X-API-Key',
        'X-Client-ID',
        'X-Session-Token',
        'X-Device-Fingerprint',
        'X-API-Signature',
        'X-Timestamp',
        'X-Nonce'
    ],
    exposedHeaders: ['X-Session-Token'],
    maxAge: 86400
};

app.use(cors(corsOptions));

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 2. Security Headers - إعدادات قوية للإنتاج
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
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            frameAncestors: ["'none'"]
        }
    },
    crossOriginResourcePolicy: { policy: "same-site" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginEmbedderPolicy: false,
    xssFilter: true,
    noSniff: true,
    hidePoweredBy: true,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: {
        action: 'deny'
    },
    referrerPolicy: {
        policy: 'strict-origin-when-cross-origin'
    }
}));

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 3. Body Parsers مع حدود حجم آمنة
// ═══════════════════════════════════════════════════════════════════
app.use(express.json({ 
    limit: '2mb',
    verify: (req, res, buf) => {
        req.rawBody = buf.toString();
    }
}));

app.use(express.urlencoded({ 
    extended: true, 
    limit: '2mb',
    parameterLimit: 50 // منع هجمات الكثافة البارامترية
}));

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 4. Request Logger مبسط للإنتاج
// ═══════════════════════════════════════════════════════════════════
app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
    
    // تسجيل مختصر للإنتاج
    console.log(`[${timestamp}] ${ip} - ${req.method} ${req.path}`);
    
    next();
});

// ═══════════════════════════════════════════════════════════════════
// 📡 5. المسارات العامة المطلوبة (بدون توثيق)
// ═══════════════════════════════════════════════════════════════════

// ✅ Health Check - ضروري لـ load balancers و monitoring
app.get('/health', (req, res) => {
    const memoryUsage = process.memoryUsage();
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        memory: {
            used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
            total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB'
        },
        version: '3.4.1'
    });
});

// ✅ Server Time - مطلوب من التطبيق
app.get('/api/serverTime', (req, res) => {
    const now = new Date();
    res.json({
        unixtime: Math.floor(now.getTime() / 1000),
        datetime: now.toISOString(),
        timestamp: now.getTime()
    });
});

// ═══════════════════════════════════════════════════════════════════
// 🔐 6. API Key Authentication - الحماية الأساسية
// ═══════════════════════════════════════════════════════════════════
app.use('/api/*', (req, res, next) => {
    // تخطي المسارات العامة
    if (req.path === '/api/serverTime') {
        return next();
    }
    
    const apiKey = req.headers['x-api-key'] || req.headers['x-api-key'] || req.query.apiKey;
    const validApiKey = config.APP_API_KEY;
    
    if (!validApiKey) {
        console.error('❌ APP_API_KEY غير معين في الإنتاج!');
        return res.status(500).json({ 
            success: false, 
            error: 'Server configuration error' 
        });
    }
    
    if (!apiKey || apiKey !== validApiKey) {
        console.warn(`🚫 محاولة وصول بمفتاح غير صحيح من IP: ${req.ip}`);
        return res.status(401).json({ 
            success: false, 
            error: 'Invalid API key',
            code: 'INVALID_API_KEY'
        });
    }
    
    next();
});

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 7. Rate Limiting للإنتاج
// ═══════════════════════════════════════════════════════════════════
const rateLimit = require('express-rate-limit');

// Rate Limiting للـ API
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: config.SECURITY?.RATE_LIMITS?.API || 50, // 50 طلب لكل 15 دقيقة
    message: {
        success: false,
        error: 'Too many requests, please try again later',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/health' || req.path === '/api/serverTime',
    keyGenerator: (req) => req.ip // استخدام الـ IP كمعرف
});

app.use('/api/*', apiLimiter);

// ═══════════════════════════════════════════════════════════════════
// 🔐 8. التوثيق المتقدم - فقط للمسارات التي تحتاجه
// ═══════════════════════════════════════════════════════════════════

// استيراد middlewares التوثيق
const { signatureAuth, adminAuth } = require('./middleware/auth');

// تطبيق التوثيق الموقعي فقط على المسارات الحساسة
const protectedPaths = [
    '/api/verifyAccount',
    '/api/getUser',
    '/api/updateDevice'
];

app.use(protectedPaths, signatureAuth);

// التوثيق الإداري
app.use('/api/admin', adminAuth);
app.use('/api/sub', adminAuth);

// ═══════════════════════════════════════════════════════════════════
// 📡 9. ROUTES المحمية
// ═══════════════════════════════════════════════════════════════════

// Mobile Routes
try {
    const mobileRoutes = require('./routes/mobile');
    app.use('/api', mobileRoutes);
    console.log('✅ Mobile routes loaded: /api/*');
} catch (e) {
    console.error('❌ Failed to load mobile routes:', e.message);
    // Fallback routes ستتعامل مع هذا
}

// Admin Routes
try {
    const adminRoutes = require('./routes/admin');
    app.use('/api/admin', adminRoutes);
    console.log('✅ Admin routes loaded: /api/admin/*');
} catch (e) {
    console.error('❌ Failed to load admin routes:', e.message);
}

// SubAdmin Routes
try {
    const subAdminRoutes = require('./routes/subadmin');
    app.use('/api/sub', subAdminRoutes);
    console.log('✅ SubAdmin routes loaded: /api/sub/*');
} catch (e) {
    console.error('❌ Failed to load subadmin routes:', e.message);
}

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 10. أمان إضافي للإنتاج
// ═══════════════════════════════════════════════════════════════════

// التحقق من Content-Type للطلبات
app.use('/api/*', (req, res, next) => {
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

// منع هجمات NoSQL Injection
app.use((req, res, next) => {
    const checkForInjection = (obj) => {
        for (let key in obj) {
            if (typeof obj[key] === 'string') {
                // حماية ضد محاولات NoSQL Injection
                const dangerousPatterns = [
                    /\$where/i,
                    /\$ne/i,
                    /\$gt/i,
                    /\$lt/i,
                    /\$in/i,
                    /\$nin/i,
                    /\$exists/i,
                    /\$regex/i,
                    /\.\.\//, // Directory traversal
                    /\/etc\/passwd/,
                    /\/proc\/self/
                ];
                
                for (let pattern of dangerousPatterns) {
                    if (pattern.test(obj[key])) {
                        console.warn(`⚠️ محاولة هجوم محتملة: ${pattern} من IP: ${req.ip}`);
                        throw new Error('Invalid input detected');
                    }
                }
            } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                checkForInjection(obj[key]);
            }
        }
    };
    
    try {
        if (req.body) checkForInjection(req.body);
        if (req.query) checkForInjection(req.query);
        next();
    } catch (error) {
        res.status(400).json({
            success: false,
            error: 'Invalid input detected'
        });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 📡 11. Fallback Routes (إذا فشل تحميل المسارات الأساسية)
// ═══════════════════════════════════════════════════════════════════

// Fallback getUser
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

// Fallback verifyAccount
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
        res.status(500).json({ success: false, code: 0 });
    }
});

// ═══════════════════════════════════════════════════════════════════
// ❌ 12. Error Handlers للإنتاج
// ═══════════════════════════════════════════════════════════════════

// 404 Handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

// Global Error Handler
app.use((err, req, res, next) => {
    const timestamp = new Date().toISOString();
    const errorId = `ERR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    console.error(`[${timestamp}] [${errorId}] Error:`, {
        message: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        path: req.path,
        method: req.method,
        ip: req.ip
    });
    
    // تحديد نوع الخطأ
    let statusCode = 500;
    let errorMessage = 'Internal server error';
    
    if (err.message.includes('CORS')) {
        statusCode = 403;
        errorMessage = 'Access forbidden';
    } else if (err.message.includes('Invalid input')) {
        statusCode = 400;
        errorMessage = 'Invalid request data';
    }
    
    res.status(statusCode).json({
        success: false,
        error: errorMessage,
        reference: errorId, // للإبلاغ عن الأخطاء
        timestamp: timestamp
    });
});

// ═══════════════════════════════════════════════════════════════════
// 🚀 13. START SERVER
// ═══════════════════════════════════════════════════════════════════

const PORT = config.PORT || process.env.PORT || 10000;

// التحقق من الإعدادات قبل التشغيل
if (process.env.NODE_ENV === 'production') {
    const requiredConfigs = ['APP_API_KEY', 'CORS.ALLOWED_ORIGINS'];
    const missingConfigs = [];
    
    if (!config.APP_API_KEY || config.APP_API_KEY.includes('default')) {
        missingConfigs.push('APP_API_KEY must be set and secure');
    }
    
    if (!config.CORS?.ALLOWED_ORIGINS || config.CORS.ALLOWED_ORIGINS.length === 0) {
        missingConfigs.push('CORS.ALLOWED_ORIGINS must be configured');
    }
    
    if (missingConfigs.length > 0) {
        console.error('❌ إعدادات الإنتاج المطلوبة مفقودة:');
        missingConfigs.forEach(msg => console.error(`   - ${msg}`));
        console.error('❌ لا يمكن تشغيل الخادم في وضع الإنتاج بدون هذه الإعدادات');
        process.exit(1);
    }
}

app.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '═'.repeat(60));
    console.log('🚀 SecureArmor Server - PRODUCTION MODE');
    console.log('═'.repeat(60));
    console.log(`📍 Port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'production'}`);
    console.log(`🔐 API Key Protection: ${config.APP_API_KEY ? '✅ ENABLED' : '❌ DISABLED'}`);
    console.log(`🛡️ CORS Protection: ${config.CORS?.ALLOWED_ORIGINS?.length > 0 ? '✅ RESTRICTED' : '❌ OPEN'}`);
    console.log(`📊 Rate Limiting: ✅ ENABLED (${config.SECURITY?.RATE_LIMITS?.API || 50}/15min)`);
    console.log(`🛡️ Security Headers: ✅ FULLY ENABLED`);
    console.log('═'.repeat(60));
    console.log('📡 Server is ready to handle requests');
    console.log('═'.repeat(60) + '\n');
});

// ═══════════════════════════════════════════════════════════════════
// 🛡️ 14. Graceful Shutdown للإنتاج
// ═══════════════════════════════════════════════════════════════════

let isShuttingDown = false;

process.on('SIGTERM', () => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    
    console.log('📴 SIGTERM received, starting graceful shutdown...');
    setTimeout(() => {
        console.log('✅ Graceful shutdown completed');
        process.exit(0);
    }, 10000); // انتظار 10 ثوانٍ لإكمال الطلبات الحالية
});

process.on('SIGINT', () => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    
    console.log('📴 SIGINT received, starting graceful shutdown...');
    setTimeout(() => {
        console.log('✅ Graceful shutdown completed');
        process.exit(0);
    }, 10000);
});

process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught Exception:', {
        message: err.message,
        stack: err.stack,
        timestamp: new Date().toISOString()
    });
    
    // في الإنتاج، لا تخرج فوراً، دع الخادم يستمر
    if (process.env.NODE_ENV === 'production') {
        console.error('⚠️ Keeping server alive despite uncaught exception');
    } else {
        process.exit(1);
    }
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise);
    console.error('Reason:', reason);
});

module.exports = app;
