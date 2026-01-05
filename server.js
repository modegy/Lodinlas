// server.js - Main Server v14.1
'use strict';

const express = require('express');
const cors = require('cors');
require('dotenv').config();

// ═══════════════════════════════════════════════════════════════════
// 📦 IMPORTS
// ═══════════════════════════════════════════════════════════════════
const constants = require('./config/constants');
const { helmetConfig, init: initSecurity } = require('./middleware/security');
const { startSessionCleanup } = require('./middleware/auth');

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
// Use constants directly instead of getFullConfig()
const config = constants;
const security = initSecurity(config);

// Helmet
app.use(helmetConfig);

// Main Security Middleware (DDoS, WAF, Rate Limiting, Bot Detection)
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
// 📝 BODY PARSER (with raw body for signature)
// ═══════════════════════════════════════════════════════════════════
app.use(express.json({ 
    limit: '2mb',
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));

app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ═══════════════════════════════════════════════════════════════════
// 📊 REQUEST LOGGER
// ═══════════════════════════════════════════════════════════════════
app.use((req, res, next) => {
    const startTime = Date.now();
    const ip = req.clientIP || req.ip;
    
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        if (duration > 1000 || res.statusCode >= 400) {
            console.log(`📊 ${req.method} ${req.path} | IP: ${ip} | Status: ${res.statusCode} | Time: ${duration}ms`);
        }
    });
    
    next();
});

// ═══════════════════════════════════════════════════════════════════
// 🛣️ ROUTES
// ═══════════════════════════════════════════════════════════════════

// Public Routes (Health, Server Time, Home)
app.use('/api', publicRoutes);
app.use('/', publicRoutes);

// Mobile App Routes
app.use('/api', mobileAppRoutes);

// Master Admin Routes
app.use('/api/admin', masterAdminRoutes);

// Sub Admin Routes
app.use('/api/sub', subAdminRoutes);

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
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error', 
        code: 500 
    });
});

// ═══════════════════════════════════════════════════════════════════
// 🧹 START CLEANUP TASKS
// ═══════════════════════════════════════════════════════════════════
startSessionCleanup();

// ═══════════════════════════════════════════════════════════════════
// 🚀 START SERVER
// ═══════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
    console.log('');
    console.log('═'.repeat(60));
    console.log('🛡️  Secure Firebase Proxy v14.1');
    console.log('═'.repeat(60));
    console.log(`📡 Port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('');
    console.log('🔐 SECURITY FEATURES:');
    console.log('   ✅ HMAC-SHA256 Signature Verification');
    console.log('   ✅ Timing-Safe Comparison');
    console.log('   ✅ Nonce Replay Protection');
    console.log('   ✅ WAF (SQL, XSS, NoSQL, XXE, SSTI)');
    console.log('   ✅ DDoS Protection');
    console.log('   ✅ Token Bucket Rate Limiting');
    console.log('   ✅ Bot Detection');
    console.log('   ✅ Brute Force Protection');
    console.log('');
    console.log('═'.repeat(60));
});

// ═══════════════════════════════════════════════════════════════════
// 🛑 GRACEFUL SHUTDOWN
// ═══════════════════════════════════════════════════════════════════
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received. Shutting down gracefully...');
    security.destroy();
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🛑 SIGINT received. Shutting down gracefully...');
    security.destroy();
    process.exit(0);
});

module.exports = app;
