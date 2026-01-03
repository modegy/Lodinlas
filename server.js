// index.js - Hardened for Render (Admin UNTOUCHED)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('./config');

// ───────────────────────────────────────────
// ENV
// ───────────────────────────────────────────
const NODE_ENV = config.NODE_ENV || process.env.NODE_ENV || 'production';
const IS_PROD = NODE_ENV === 'production';

// ───────────────────────────────────────────
// LOAD SECURITY MODULE (MANDATORY IN PROD)
// ──────────────────────────────────────────
let securityMiddleware, bruteForceProtection, getClientIP, securityAdmin;

try {
    const security = require('./middleware/security');
    securityMiddleware = security.securityMiddleware;
    bruteForceProtection = security.bruteForceProtection;
    getClientIP = security.getClientIP;
    securityAdmin = security.securityAdmin;
    console.log('✅ Security module loaded successfully');
} catch (error) {
    console.error('❌ Security module error:', error.message);

    if (IS_PROD) {
        console.error('❌ Security module is required in production');
        process.exit(1);
    }

    // DEV fallback فقط
    securityMiddleware = (req, res, next) => next();
    bruteForceProtection = (req, res, next) => next();
    getClientIP = (req) => req.ip;
    securityAdmin = {
        getStats: () => ({ error: 'Security disabled (dev)' }),
        getBlockedIPs: () => [],
        unblockIP: () => ({ success: false })
    };
}

// ───────────────────────────────────────────
// INIT EXPRESS
// ───────────────────────────────────────────
const app = express();
app.disable('x-powered-by');

// Render reverse proxy
app.set('trust proxy', 1);

// ───────────────────────────────────────────
// HELMET
// ───────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'no-referrer' }
}));

// ───────────────────────────────────────────
// RATE LIMIT (FALLBACK GLOBAL)
// ───────────────────────────────────────────
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false
}));

// ───────────────────────────────────────────
// SECURITY ARMOR
// ───────────────────────────────────────────
app.use(securityMiddleware);
app.use(bruteForceProtection);

// ───────────────────────────────────────────
// CORS (FIXED, NO WILDCARD WITH CREDENTIALS)
// ───────────────────────────────────────────
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : [];

app.use(cors({
    origin(origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET','POST','PUT','DELETE','PATCH','OPTIONS'],
    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Signature',
        'X-Timestamp',
        'X-Request-ID',
        'X-Session-Token'
    ]
}));

// ───────────────────────────────────────────
// BODY PARSER
// ───────────────────────────────────────────
app.use(express.json({
    limit: '2mb',
    verify: (req, res, buf) => {
        if (req.headers['x-signature']) {
            req.rawBody = buf.toString('utf8');
        }
    }
}));

app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ───────────────────────────────────────────
// LOGGER
// ───────────────────────────────────────────
app.use((req, res, next) => {
    const startTime = Date.now();

    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const ip = req.security?.ip || req.ip;

        if (duration > 1000 || res.statusCode >= 400) {
            console.log(`📊 ${req.method} ${req.originalUrl} | IP: ${ip} | Status: ${res.statusCode} | ${duration}ms`);
        }
    });

    next();
});

// ───────────────────────────────────────────
// ROUTES
// ───────────────────────────────────────────
const mobileRoutes = require('./routes/mobile');
const adminRoutes = require('./routes/admin');
const subAdminRoutes = require('./routes/subadmin');

// HEALTH
app.get('/health', (req, res) => res.send('OK'));

app.get('/api/health', (req, res) => {
    if (IS_PROD) return res.json({ status: 'ok' });

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
// ADMIN SECURITY ROUTES (UNCHANGED)
// ───────────────────────────────────────────
app.get('/api/admin/security/stats', (req, res) => {
    res.json(securityAdmin.getStats());
});

app.get('/api/admin/security/blocked', (req, res) => {
    res.json(securityAdmin.getBlockedIPs());
});

app.post('/api/admin/security/unblock', (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP required' });
    res.json(securityAdmin.unblockIP(ip));
});

// ───────────────────────────────────────────
// API ROUTES
// ───────────────────────────────────────────
app.use('/api', mobileRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/sub', subAdminRoutes);

// ───────────────────────────────────────────
// HOME PAGE (UNCHANGED)
// ───────────────────────────────────────────
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>...`); // نفس HTML السابق
});

// ───────────────────────────────────────────
// ERRORS
// ───────────────────────────────────────────
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        code: 404,
        path: req.originalUrl
    });
});

app.use((err, req, res, next) => {
    const ip = req.security?.ip || req.ip;
    console.error(`❌ Error: ${err.message} | IP: ${ip} | Path: ${req.path}`);

    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({ error: 'CORS policy violation' });
    }

    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ error: 'Invalid JSON' });
    }

    res.status(500).json({
        error: IS_PROD ? 'Internal server error' : err.message
    });
});

// ───────────────────────────────────────────
// START SERVER
// ───────────────────────────────────────────
const PORT = config.PORT || process.env.PORT || 10000;

const server = app.listen(PORT, () => {
    console.log(`🛡️ Secure API running on port ${PORT} (${NODE_ENV})`);
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));
