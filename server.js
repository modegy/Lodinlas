// index.js - الملف الرئيسي للسيرفر
// متوافق مع SecureArmor v14.1

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const config = require('./config');

// ✅ تحديد NODE_ENV
const NODE_ENV = config.NODE_ENV || process.env.NODE_ENV || 'production';

// ✅ استيراد من security.js مع fallback
let securityMiddleware, bruteForceProtection, getClientIP, securityAdmin;

try {
    const security = require('./middleware/security');
    securityMiddleware = security.securityMiddleware;
    bruteForceProtection = security.bruteForceProtection;
    getClientIP = security.getClientIP;
    securityAdmin = security.securityAdmin;
    console.log('✅ Security module loaded successfully');
} catch (error) {
    console.error('⚠️ Security module error:', error.message);
    // Fallback - الحماية الأساسية فقط
    securityMiddleware = (req, res, next) => next();
    bruteForceProtection = (req, res, next) => next();
    getClientIP = (req) => req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '127.0.0.1';
    securityAdmin = { 
        getStats: () => ({ error: 'Security module not loaded' }),
        getBlockedIPs: () => [],
        unblockIP: () => ({ success: false })
    };
}

// Initialize Express
const app = express();

// ✅ إعداد trust proxy بشكل آمن
app.set('trust proxy', 1);

// ═══════════════════════════════════════════
// SECURITY MIDDLEWARE
// ═══════════════════════════════════════════

// Helmet - حماية أساسية للـ headers
app.use(helmet({ 
    contentSecurityPolicy: false, 
    crossOriginEmbedderPolicy: false 
}));

// ✅ SecureArmor v14 - الحماية الشاملة
app.use(securityMiddleware);

// ═══════════════════════════════════════════
// CORS
// ═══════════════════════════════════════════
app.use(cors({
    origin: function(origin, callback) {
        const allowedOrigins = process.env.ALLOWED_ORIGINS 
            ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
            : ['*'];
        
        if (allowedOrigins.includes('*') || !origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Signature', 'X-Timestamp', 'X-Request-ID', 'X-Session-Token'],
    optionsSuccessStatus: 200
}));

// ═══════════════════════════════════════════
// BODY PARSER (مع حفظ raw body للتوقيع)
// ═══════════════════════════════════════════
app.use(express.json({ 
    limit: '2mb',
    verify: (req, res, buf) => { 
        req.rawBody = buf.toString('utf8'); 
    }
}));

app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ═══════════════════════════════════════════
// LOGGER MIDDLEWARE
// ═══════════════════════════════════════════
app.use((req, res, next) => {
    const startTime = Date.now();
    
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const ip = req.security?.ip || getClientIP(req);
        
        // تسجيل الطلبات البطيئة أو الفاشلة فقط
        if (duration > 1000 || res.statusCode >= 400) {
            console.log(`📊 ${req.method} ${req.path} | IP: ${ip} | Status: ${res.statusCode} | ${duration}ms`);
        }
    });
    next();
});

// ═══════════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════════
const mobileRoutes = require('./routes/mobile');
const adminRoutes = require('./routes/admin');
const subAdminRoutes = require('./routes/subadmin');

// ───────────────────────────────────────────
// Public Endpoints
// ───────────────────────────────────────────
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        version: '3.4.1',
        security: 'SecureArmor v14.1',
        uptime: Math.floor(process.uptime()), 
        timestamp: Date.now() 
    });
});

app.get('/api/serverTime', (req, res) => {
    res.json({ 
        success: true, 
        server_time: Date.now(), 
        formatted: new Date().toISOString() 
    });
});

// ───────────────────────────────────────────
// Security Admin Endpoints (للمراقبة)
// ───────────────────────────────────────────
app.get('/api/admin/security/stats', (req, res) => {
    try {
        res.json(securityAdmin.getStats());
    } catch (error) {
        res.json({ error: error.message });
    }
});

app.get('/api/admin/security/blocked', (req, res) => {
    try {
        res.json(securityAdmin.getBlockedIPs());
    } catch (error) {
        res.json([]);
    }
});

app.post('/api/admin/security/unblock', (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP required' });
    try {
        res.json(securityAdmin.unblockIP(ip));
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

// ───────────────────────────────────────────
// API Routes
// ───────────────────────────────────────────
app.use('/api', mobileRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/sub', subAdminRoutes);

// ═══════════════════════════════════════════
// HOME PAGE
// ═══════════════════════════════════════════
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Secure API v3.4.1</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #0f0f23, #1a1a3e);
            color: #fff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container { 
            max-width: 600px; 
            text-align: center;
            background: rgba(255,255,255,0.05);
            padding: 40px;
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        h1 { color: #4cc9f0; margin-bottom: 20px; font-size: 2em; }
        .badge {
            background: linear-gradient(135deg, #10b981, #059669);
            padding: 12px 24px;
            border-radius: 25px;
            display: inline-block;
            margin: 20px 0;
            font-weight: 600;
        }
        .features {
            text-align: right;
            margin-top: 30px;
            padding: 20px;
            background: rgba(0,0,0,0.2);
            border-radius: 10px;
        }
        .feature {
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            color: #94a3b8;
        }
        .feature:last-child { border-bottom: none; }
        .feature span { color: #4cc9f0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Secure Firebase Proxy</h1>
        <div class="badge">✅ v3.4.1 - SecureArmor v14.1</div>
        <div class="features">
            <div class="feature"><span>🔐</span> HMAC-SHA256 Signatures</div>
            <div class="feature"><span>🛡️</span> Advanced WAF Protection</div>
            <div class="feature"><span>⚡</span> DDoS & Rate Limiting</div>
            <div class="feature"><span>🤖</span> Bot Detection</div>
            <div class="feature"><span>🔍</span> Behavior Analysis</div>
            <div class="feature"><span>🍯</span> Honeypot Traps</div>
        </div>
    </div>
</body>
</html>`);
});

// ═══════════════════════════════════════════
// ERROR HANDLERS
// ═══════════════════════════════════════════

// 404 Handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Endpoint not found', 
        code: 404,
        path: req.originalUrl
    });
});

// Global Error Handler
app.use((err, req, res, next) => {
    const ip = req.security?.ip || getClientIP(req);
    console.error(`❌ Error: ${err.message} | IP: ${ip} | Path: ${req.path}`);
    
    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({ success: false, error: 'CORS policy violation', code: 403 });
    }
    
    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ success: false, error: 'Invalid JSON', code: 400 });
    }
    
    res.status(500).json({ 
        success: false, 
        error: NODE_ENV === 'production' ? 'Internal server error' : err.message, 
        code: 500 
    });
});

// ═══════════════════════════════════════════
// GRACEFUL SHUTDOWN
// ═══════════════════════════════════════════
const gracefulShutdown = (signal) => {
    console.log(`\n⚠️ ${signal} received. Shutting down gracefully...`);
    
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
    
    setTimeout(() => {
        console.error('❌ Forced shutdown');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════
const PORT = config.PORT || process.env.PORT || 10000;

const server = app.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║               🛡️  SECURE API SERVER                      ║');
    console.log('╠══════════════════════════════════════════════════════════╣');
    console.log(`║  📡 Port: ${PORT}                                          ║`);
    console.log(`║  🌍 Environment: ${NODE_ENV}                              ║`);
    console.log('║  🔐 Security: SecureArmor v14.1                          ║');
    console.log('║  ✅ Status: RUNNING                                       ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log('');
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use`);
    } else {
        console.error('❌ Server error:', err.message);
    }
    process.exit(1);
});
