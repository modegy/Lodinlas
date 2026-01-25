// server.js - Secure Server v16.0 (Complete with Control System)
'use strict';

const express = require('express');
const cors = require('cors');
require('dotenv').config();

// ═══════════════════════════════════════════════════════════════════
// 🚨 SECURITY: VALIDATE ENVIRONMENT FIRST!
// ═══════════════════════════════════════════════════════════════════
console.log('');
console.log('═'.repeat(60));
console.log('🔐 SECURITY VALIDATION');
console.log('═'.repeat(60));

// Required environment variables - NO DEFAULTS ALLOWED!
const REQUIRED_ENV = {
    FIREBASE_URL: process.env.FIREBASE_URL,
    FIREBASE_KEY: process.env.FIREBASE_KEY,
    MASTER_ADMIN_USERNAME: process.env.MASTER_ADMIN_USERNAME,
    MASTER_ADMIN_PASSWORD_HASH: process.env.MASTER_ADMIN_PASSWORD_HASH,
    SESSION_SECRET: process.env.SESSION_SECRET,
    SIGNING_SALT: process.env.SIGNING_SALT
};

// Check for missing variables
const missing = Object.entries(REQUIRED_ENV)
    .filter(([key, value]) => !value)
    .map(([key]) => key);

if (missing.length > 0) {
    console.error('');
    console.error('🚨 '.repeat(20));
    console.error('');
    console.error('   ⛔ CRITICAL SECURITY ERROR ⛔');
    console.error('');
    console.error('   Missing required environment variables:');
    console.error('');
    missing.forEach(key => {
        console.error(`   ❌ ${key}`);
    });
    console.error('');
    console.error('   ⚠️  SERVER CANNOT START WITHOUT THESE!');
    console.error('   ⚠️  NO DEFAULT CREDENTIALS ARE ALLOWED!');
    console.error('');
    console.error('   📝 Create a .env file with all required variables.');
    console.error('   📝 Use the provided .env.example as a template.');
    console.error('');
    console.error('🚨 '.repeat(20));
    console.error('');
    process.exit(1);
}

// Validate password hash format
if (!REQUIRED_ENV.MASTER_ADMIN_PASSWORD_HASH.startsWith('$2a$') && 
    !REQUIRED_ENV.MASTER_ADMIN_PASSWORD_HASH.startsWith('$2b$')) {
    console.error('');
    console.error('🚨 INVALID PASSWORD HASH FORMAT!');
    console.error('   MASTER_ADMIN_PASSWORD_HASH must be a bcrypt hash.');
    console.error('');
    console.error('   Generate one using:');
    console.error('   node -e "console.log(require(\'bcryptjs\').hashSync(\'YOUR_PASSWORD\', 12))"');
    console.error('');
    process.exit(1);
}

// Validate secret lengths
if (REQUIRED_ENV.SESSION_SECRET.length < 32) {
    console.error('🚨 SESSION_SECRET must be at least 32 characters!');
    process.exit(1);
}

console.log('✅ All required environment variables present');
console.log('✅ Password hash format valid');
console.log('✅ Secret lengths valid');
console.log('═'.repeat(60));
console.log('');

// ═══════════════════════════════════════════════════════════════════
// 📦 IMPORTS (After validation)
// ═══════════════════════════════════════════════════════════════════
const constants = require('./config/constants');
const { helmetConfig, init: initSecurity } = require('./middleware/security');
const { startSessionCleanup } = require('./middleware/auth');

// ✅ Notifications & Telegram Bot
const { testNotifications } = require('./middleware/notifications');
const { 
    handleTelegramUpdate, 
    setupTelegramWebhook,
    sendServerAlert 
} = require('./middleware/telegramBot');

// ✅ Admin Control System
const { 
    router: adminControlRouter, 
    checkServerState,
    addLog 
} = require('./routes/adminControl');

// Routes
const masterAdminRoutes = require('./routes/masterAdmin');
const subAdminRoutes = require('./routes/subAdmin');
const mobileAppRoutes = require('./routes/mobileApp');
const publicRoutes = require('./routes/public');

// ═══════════════════════════════════════════════════════════════════
// 🚀 APP INITIALIZATION
// ═══════════════════════════════════════════════════════════════════
const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', 'loopback, linklocal, uniquelocal');

// ═══════════════════════════════════════════════════════════════════
// 🛡️ SECURITY MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════
const security = initSecurity(constants);
app.use(helmetConfig);
app.use(security.middleware());

// ═══════════════════════════════════════════════════════════════════
// 🌐 CORS
// ═══════════════════════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════════════════════
// 📝 BODY PARSER
// ═══════════════════════════════════════════════════════════════════
app.use(express.json({ 
    limit: '2mb',
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ═══════════════════════════════════════════════════════════════════
// 📊 SECURITY REQUEST LOGGER (محسّن مع addLog)
// ═══════════════════════════════════════════════════════════════════
app.use((req, res, next) => {
    const startTime = Date.now();
    const ip = req.clientIP || req.ip;
    
    if (req.path.includes('/admin/')) {
        console.log(`🔒 Admin request: ${req.method} ${req.path} | IP: ${ip}`);
    }
    
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        
        if (duration > 1000 || res.statusCode >= 400) {
            const emoji = res.statusCode >= 400 ? '⚠️' : '📊';
            console.log(`${emoji} ${req.method} ${req.path} | IP: ${ip} | Status: ${res.statusCode} | ${duration}ms`);
        }
        
        if (res.statusCode === 401 || res.statusCode === 403) {
            console.log(`🚫 AUTH FAIL: ${req.method} ${req.path} | IP: ${ip} | Status: ${res.statusCode}`);
            
            // إضافة للـ Log
            addLog('AUTH_FAIL', `${req.method} ${req.path} - ${res.statusCode}`, {
                ip,
                path: req.path,
                method: req.method
            });
        }
        
        // تسجيل جميع الطلبات
        addLog('REQUEST', `${req.method} ${req.path}`, {
            ip,
            status: res.statusCode,
            duration: `${duration}ms`
        });
    });
    
    next();
});

// ═══════════════════════════════════════════════════════════════════
// 🛣️ ROUTES (بترتيب الأولوية)
// ═══════════════════════════════════════════════════════════════════

// 1. Health Check (بدون checkServerState)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// 2. Telegram Webhook (بدون checkServerState)
app.post('/telegram/webhook', async (req, res) => {
    try {
        await handleTelegramUpdate(req.body);
        res.sendStatus(200);
    } catch (error) {
        console.error('Telegram webhook error:', error);
        res.sendStatus(500);
    }
});

// 3. Admin Control Routes (بدون checkServerState - للتحكم بالسيرفر)
app.use('/api/control', adminControlRouter);

// 4. Public Routes (بدون checkServerState)
app.use('/api', publicRoutes);
app.use('/', publicRoutes);

// 5. Mobile App Routes (مع checkServerState)
app.use('/api', checkServerState, mobileAppRoutes);

// 6. Master Admin Routes (مع checkServerState)
app.use('/api/admin', checkServerState, masterAdminRoutes);

// 7. Sub Admin Routes (مع checkServerState)
app.use('/api/sub', checkServerState, subAdminRoutes);

// ═══════════════════════════════════════════════════════════════════
// ❌ ERROR HANDLERS
// ═══════════════════════════════════════════════════════════════════
app.use('*', (req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Endpoint not found', 
        code: 404 
    });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err.message);
    
    // تسجيل الأخطاء
    addLog('ERROR', err.message, {
        stack: err.stack,
        path: req.path
    });
    
    const errorMessage = process.env.NODE_ENV === 'production' 
        ? 'Internal server error' 
        : err.message;
    
    res.status(500).json({ 
        success: false, 
        error: errorMessage, 
        code: 500 
    });
});

// ═══════════════════════════════════════════════════════════════════
// 🧹 START CLEANUP TASKS
// ═══════════════════════════════════════════════════════════════════
startSessionCleanup();

// ═══════════════════════════════════════════════════════════════════
// 🚀 START SERVER (مع النظام الكامل)
// ═══════════════════════════════════════════════════════════════════
app.listen(PORT, async () => {
    console.log('');
    console.log('═'.repeat(60));
    console.log('🛡️  Secure Firebase Proxy v16.0');
    console.log('═'.repeat(60));
    console.log(`📡 Port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('');
    console.log('🔐 SECURITY FEATURES:');
    console.log('   ✅ NO Default Credentials');
    console.log('   ✅ Bcrypt Password Hashing');
    console.log('   ✅ Secure Session Management');
    console.log('   ✅ IP-Bound Sessions');
    console.log('   ✅ Brute Force Protection');
    console.log('   ✅ Timing-Safe Comparisons');
    console.log('   ✅ HMAC-SHA256 Signatures');
    console.log('   ✅ WAF Protection');
    console.log('   ✅ DDoS Protection');
    console.log('   ✅ Rate Limiting');
    console.log('');
    console.log('🎛️  CONTROL FEATURES:');
    console.log('   ✅ Server Start/Stop Control');
    console.log('   ✅ Maintenance Mode');
    console.log('   ✅ IP Blocking Management');
    console.log('   ✅ Cache Control');
    console.log('   ✅ Live Logs Viewer');
    console.log('   ✅ Telegram Bot Integration');
    console.log('   ✅ Email & Telegram Alerts');
    console.log('');
    console.log('👤 Master Admin: Configured via Environment');
    console.log('');
    console.log('═'.repeat(60));

    // 🔔 Setup Telegram Webhook (Production only)
    if (process.env.NODE_ENV === 'production' && process.env.RENDER_EXTERNAL_URL) {
        try {
            const webhookUrl = `${process.env.RENDER_EXTERNAL_URL}/telegram/webhook`;
            await setupTelegramWebhook(webhookUrl);
            console.log('✅ Telegram webhook configured:', webhookUrl);
        } catch (error) {
            console.error('⚠️ Telegram webhook setup failed:', error.message);
        }
    }

    // 🔔 Test Notifications (Production only)
    if (process.env.NODE_ENV === 'production') {
        try {
            await testNotifications();
            console.log('✅ Notifications test executed successfully');
        } catch (err) {
            console.error('⚠️ Notifications test failed:', err.message);
        }
    }

    // 📢 Send Server Started Alert
    try {
        await sendServerAlert('SERVER_STARTED', {
            port: PORT,
            environment: process.env.NODE_ENV || 'development',
            url: process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`,
            version: '16.0'
        });
        console.log('✅ Server start notification sent');
    } catch (error) {
        console.log('⚠️ Could not send start notification');
    }

    console.log('');
    console.log('🚀 Server is ready to accept connections!');
    console.log('═'.repeat(60));
    console.log('');
});

// ═══════════════════════════════════════════════════════════════════
// 🛑 GRACEFUL SHUTDOWN (محسّن مع إشعارات)
// ═══════════════════════════════════════════════════════════════════
const shutdown = async (signal) => {
    console.log(`\n🛑 ${signal} received. Shutting down gracefully...`);
    
    try {
        await sendServerAlert('SERVER_STOPPED', {
            reason: signal,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.log('⚠️ Could not send shutdown notification');
    }
    
    security.destroy();
    process.exit(0);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// ═══════════════════════════════════════════════════════════════════
// 🚨 UNCAUGHT ERRORS (محسّن مع إشعارات)
// ═══════════════════════════════════════════════════════════════════
process.on('uncaughtException', async (error) => {
    console.error('💥 Uncaught Exception:', error);
    
    try {
        await sendServerAlert('SERVER_CRASHED', {
            error: error.message,
            stack: error.stack
        });
    } catch (e) {
        console.log('⚠️ Could not send crash notification');
    }
    
    process.exit(1);
});

process.on('unhandledRejection', async (reason, promise) => {
    console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
    
    try {
        await sendServerAlert('SERVER_ERROR', {
            error: String(reason)
        });
    } catch (e) {
        console.log('⚠️ Could not send error notification');
    }
});

module.exports = app;
