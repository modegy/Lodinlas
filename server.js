// server.js - مُصحح بالكامل
const express = require('express');
const path = require('path');
const config = require('./config');

const app = express();

// ═══════════════════════════════════════════
// 🔧 TRUST PROXY - مهم جداً لـ Render/Heroku
// ═══════════════════════════════════════════
app.set('trust proxy', 1); // ✅ يجب أن يكون قبل أي middleware

// ═══════════════════════════════════════════
// 🛡️ CORS الآمن
// ═══════════════════════════════════════════
const ALLOWED_ORIGINS = [
    'https://lodinlas.onrender.com',
    'https://your-domain.com',
    // أضف الدومينات المسموح بها
];

// في بيئة التطوير
if (process.env.NODE_ENV !== 'production') {
    ALLOWED_ORIGINS.push('http://localhost:3000');
    ALLOWED_ORIGINS.push('http://localhost:10000');
    ALLOWED_ORIGINS.push('http://127.0.0.1:3000');
}

app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    // ✅ CORS آمن - لا نستخدم * مع credentials
    if (origin && ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    } else if (!origin) {
        // طلبات من نفس الدومين أو من التطبيق
        res.setHeader('Access-Control-Allow-Origin', '*');
        // ❌ لا نضع credentials مع *
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Session-Token, X-Timestamp, X-Signature, X-Device-ID');
    res.setHeader('Access-Control-Max-Age', '86400');
    
    // Security Headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }
    
    next();
});

// ═══════════════════════════════════════════
// 📦 Body Parser
// ═══════════════════════════════════════════
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ═══════════════════════════════════════════
// 🔍 Request Logger
// ═══════════════════════════════════════════
app.use((req, res, next) => {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    // استخدام req.ip بعد trust proxy
    const clientIP = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || '127.0.0.1';
    req.clientIP = clientIP; // حفظها للاستخدام لاحقاً
    console.log(`[${timestamp}] ${clientIP} - ${req.method} ${req.path}`);
    next();
});

// ═══════════════════════════════════════════
// 🛡️ Security Middleware
// ═══════════════════════════════════════════
try {
    const security = require('./middleware/security');
    app.use(security.protect());
    console.log('✅ Security middleware loaded successfully');
} catch (error) {
    console.warn('⚠️ Security middleware not loaded:', error.message);
}

// ═══════════════════════════════════════════
// 📂 Static Files
// ═══════════════════════════════════════════
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════
// 🛣️ Routes
// ═══════════════════════════════════════════
try {
    const mobileRoutes = require('./routes/mobile');
    app.use('/api', mobileRoutes);
    console.log('✅ Mobile routes loaded: /api/*');
} catch (error) {
    console.error('❌ Mobile routes error:', error.message);
}

try {
    const adminRoutes = require('./routes/admin');
    app.use('/api/admin', adminRoutes);
    console.log('✅ Admin routes loaded: /api/admin/*');
} catch (error) {
    console.error('❌ Admin routes error:', error.message);
}

try {
    const subAdminRoutes = require('./routes/subadmin');
    app.use('/api/sub', subAdminRoutes);
    console.log('✅ SubAdmin routes loaded: /api/sub/*');
} catch (error) {
    console.warn('⚠️ SubAdmin routes not loaded:', error.message);
}

// ═══════════════════════════════════════════
// 🏠 Home Route
// ═══════════════════════════════════════════
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═══════════════════════════════════════════
// 🚫 404 Handler
// ═══════════════════════════════════════════
app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Endpoint not found',
        path: req.path 
    });
});

// ═══════════════════════════════════════════
// ❌ Error Handler
// ═══════════════════════════════════════════
app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.message);
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error' 
    });
});

// ═══════════════════════════════════════════
// 🚀 Start Server
// ═══════════════════════════════════════════
const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
    console.log('\n════════════════════════════════════════════════════════════');
    console.log('🚀 SecureArmor Server v14.2 (Fixed)');
    console.log('════════════════════════════════════════════════════════════');
    console.log(`📍 Port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔐 Trust Proxy: ✅`);
    console.log(`🛡️ CORS: ✅ Secure`);
    console.log('════════════════════════════════════════════════════════════\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('📴 SIGTERM received, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('📴 SIGINT received, shutting down gracefully...');
    process.exit(0);
});

module.exports = app;
