// index.js - الملف الرئيسي للسيرفر
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const config = require('./config');
const { ddosProtection, suspiciousRequestFilter, attackLogger } = require('./middleware/security');

// Initialize Express
const app = express();
app.set('trust proxy', 'loopback, linklocal, uniquelocal');

// ═══════════════════════════════════════════
// SECURITY MIDDLEWARE
// ═══════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(ddosProtection);
app.use(suspiciousRequestFilter);
app.use(attackLogger);

// ═══════════════════════════════════════════
// CORS
// ═══════════════════════════════════════════
app.use(cors({
    origin: function(origin, callback) {
        const allowedOrigins = process.env.ALLOWED_ORIGINS 
            ? process.env.ALLOWED_ORIGINS.split(',') : ['*'];
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
// RATE LIMITING
// ═══════════════════════════════════════════
const createRateLimiter = (windowMs, max, message) => {
    return rateLimit({
        windowMs, max,
        message: { success: false, error: message },
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req) => req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip
    });
};

const globalLimiter = createRateLimiter(60000, 100, 'Too many requests');
const apiLimiter = createRateLimiter(60000, 50, 'API rate limit exceeded');

app.use('/', globalLimiter);

// ═══════════════════════════════════════════
// BODY PARSER (مع حفظ raw body للتوقيع)
// ═══════════════════════════════════════════
app.use(express.json({ 
    limit: '2mb',
    verify: (req, res, buf) => { req.rawBody = buf.toString('utf8'); }
}));

// ═══════════════════════════════════════════
// LOGGER MIDDLEWARE
// ═══════════════════════════════════════════
app.use((req, res, next) => {
    const startTime = Date.now();
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    
    res.on('finish', () => {
        const duration = Date.now() - startTime;
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

// Public Endpoints
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

// API Routes
app.use('/api', apiLimiter, mobileRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/sub', apiLimiter, subAdminRoutes);

// ═══════════════════════════════════════════
// HOME PAGE
// ═══════════════════════════════════════════
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
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
    res.status(404).json({ success: false, error: 'Endpoint not found', code: 404 });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err.message);
    res.status(500).json({ success: false, error: 'Internal server error', code: 500 });
});

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════
app.listen(config.PORT, () => {
    console.log('═'.repeat(60));
    console.log('🛡️  Secure Firebase Proxy v3.3.0');
    console.log(`📡 Port: ${config.PORT}`);
    console.log('🔐 SECURE SIGNATURE SYSTEM ENABLED');
    console.log('═'.repeat(60));
});
