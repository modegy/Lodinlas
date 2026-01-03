// middleware/auth.js - Authentication Middleware (مُصلح)
const config = require('../config');

// ═══════════════════════════════════════════
// SESSION STORAGE
// ═══════════════════════════════════════════
const adminSessions = new Map();

// تنظيف الجلسات المنتهية كل 10 دقائق
setInterval(() => {
    const now = Date.now();
    const sessionExpiry = config.SESSION?.EXPIRY || 86400000; // 24 ساعة افتراضياً
    
    for (const [token, session] of adminSessions.entries()) {
        if (now - session.createdAt > sessionExpiry) {
            adminSessions.delete(token);
            console.log(`🧹 Expired session cleaned: ${session.username}`);
        }
    }
}, 10 * 60 * 1000);

// ═══════════════════════════════════════════
// ADMIN AUTH MIDDLEWARE
// ═══════════════════════════════════════════
const authAdmin = (req, res, next) => {
    try {
        const sessionToken = req.headers['x-session-token'];
        
        if (!sessionToken) {
            return res.status(401).json({ 
                success: false, 
                error: 'No session token provided',
                code: 'NO_TOKEN'
            });
        }
        
        const session = adminSessions.get(sessionToken);
        
        if (!session) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid or expired session',
                code: 'INVALID_SESSION'
            });
        }
        
        // التحقق من انتهاء الجلسة
        const sessionExpiry = config.SESSION?.EXPIRY || 86400000;
        if (Date.now() - session.createdAt > sessionExpiry) {
            adminSessions.delete(sessionToken);
            return res.status(401).json({ 
                success: false, 
                error: 'Session expired',
                code: 'SESSION_EXPIRED'
            });
        }
        
        // تحديث وقت النشاط الأخير
        session.lastActive = Date.now();
        adminSessions.set(sessionToken, session);
        
        // إضافة معلومات الجلسة للـ request
        req.adminSession = session;
        req.adminUsername = session.username;
        
        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Authentication error',
            code: 'AUTH_ERROR'
        });
    }
};

// ═══════════════════════════════════════════
// API KEY AUTH MIDDLEWARE (للـ Sub Admins)
// ═══════════════════════════════════════════
const authApiKey = (requiredPermissions = []) => {
    return async (req, res, next) => {
        try {
            const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
            
            if (!apiKey) {
                return res.status(401).json({
                    success: false,
                    error: 'API key required',
                    code: 'NO_API_KEY'
                });
            }
            
            // هنا يمكنك إضافة التحقق من API Key من قاعدة البيانات
            // const keyData = await validateApiKey(apiKey);
            
            req.apiKey = apiKey;
            next();
        } catch (error) {
            console.error('API Key auth error:', error);
            res.status(401).json({
                success: false,
                error: 'Invalid API key',
                code: 'INVALID_API_KEY'
            });
        }
    };
};

// ═══════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════
module.exports = {
    adminSessions,
    authAdmin,
    authApiKey
};
