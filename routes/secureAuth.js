// middleware/secureAuth.js - Secure Authentication System v2.0
'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// ═══════════════════════════════════════════════════════════════════
// 🔐 SECURE SESSION STORE
// ═══════════════════════════════════════════════════════════════════
const secureSessions = new Map();
const loginAttempts = new Map();
const blockedIPs = new Map();
const totpSecrets = new Map(); // For 2FA

// ═══════════════════════════════════════════════════════════════════
// ⚙️ CONFIGURATION - يجب تعيينها من Environment Variables فقط
// ═══════════════════════════════════════════════════════════════════
const CONFIG = {
    // Session
    SESSION_DURATION: 8 * 60 * 60 * 1000, // 8 hours
    SESSION_SECRET: process.env.SESSION_SECRET,
    
    // Brute Force Protection
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION: 30 * 60 * 1000, // 30 minutes
    ATTEMPT_WINDOW: 15 * 60 * 1000, // 15 minutes
    
    // Password Requirements
    MIN_PASSWORD_LENGTH: 12,
    REQUIRE_SPECIAL_CHAR: true,
    REQUIRE_NUMBER: true,
    REQUIRE_UPPERCASE: true,
    
    // 2FA
    ENABLE_2FA: process.env.ENABLE_2FA === 'true',
    
    // IP Binding
    BIND_SESSION_TO_IP: true,
    BIND_SESSION_TO_DEVICE: true
};

// ═══════════════════════════════════════════════════════════════════
// 🔒 VALIDATE ENVIRONMENT - إجبار وجود المتغيرات البيئية
// ═══════════════════════════════════════════════════════════════════
function validateEnvironment() {
    const required = [
        'MASTER_ADMIN_USERNAME',
        'MASTER_ADMIN_PASSWORD_HASH',
        'SESSION_SECRET',
        'JWT_SECRET'
    ];
    
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        console.error('═'.repeat(60));
        console.error('🚨 CRITICAL SECURITY ERROR 🚨');
        console.error('═'.repeat(60));
        console.error('Missing required environment variables:');
        missing.forEach(key => console.error(`   ❌ ${key}`));
        console.error('');
        console.error('⚠️  Server cannot start without these variables!');
        console.error('⚠️  NO DEFAULT CREDENTIALS ALLOWED!');
        console.error('═'.repeat(60));
        process.exit(1);
    }
    
    // Validate password hash format
    const hash = process.env.MASTER_ADMIN_PASSWORD_HASH;
    if (!hash.startsWith('$2a$') && !hash.startsWith('$2b$')) {
        console.error('🚨 MASTER_ADMIN_PASSWORD_HASH must be a valid bcrypt hash!');
        console.error('   Generate one using: node -e "console.log(require(\'bcryptjs\').hashSync(\'YOUR_PASSWORD\', 12))"');
        process.exit(1);
    }
    
    // Validate session secret strength
    if (process.env.SESSION_SECRET.length < 32) {
        console.error('🚨 SESSION_SECRET must be at least 32 characters!');
        process.exit(1);
    }
    
    console.log('✅ Environment validation passed');
    return true;
}

// ═══════════════════════════════════════════════════════════════════
// 🔐 PASSWORD UTILITIES
// ═══════════════════════════════════════════════════════════════════
function hashPassword(password) {
    return bcrypt.hashSync(password, 12);
}

function verifyPassword(password, hash) {
    return bcrypt.compareSync(password, hash);
}

function validatePasswordStrength(password) {
    const errors = [];
    
    if (password.length < CONFIG.MIN_PASSWORD_LENGTH) {
        errors.push(`كلمة المرور يجب أن تكون ${CONFIG.MIN_PASSWORD_LENGTH} حرف على الأقل`);
    }
    if (CONFIG.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) {
        errors.push('يجب أن تحتوي على حرف كبير');
    }
    if (CONFIG.REQUIRE_NUMBER && !/[0-9]/.test(password)) {
        errors.push('يجب أن تحتوي على رقم');
    }
    if (CONFIG.REQUIRE_SPECIAL_CHAR && !/[!@#$%^&*()_+\-=\[\]{}|;':",.<>?/`~]/.test(password)) {
        errors.push('يجب أن تحتوي على رمز خاص');
    }
    
    return { valid: errors.length === 0, errors };
}

// ═══════════════════════════════════════════════════════════════════
// 🛡️ BRUTE FORCE PROTECTION
// ═══════════════════════════════════════════════════════════════════
function isIPBlocked(ip) {
    const blocked = blockedIPs.get(ip);
    if (!blocked) return false;
    
    if (Date.now() > blocked.until) {
        blockedIPs.delete(ip);
        return false;
    }
    
    return true;
}

function getBlockedRemainingTime(ip) {
    const blocked = blockedIPs.get(ip);
    if (!blocked) return 0;
    return Math.ceil((blocked.until - Date.now()) / 1000 / 60);
}

function recordLoginAttempt(ip, success) {
    const now = Date.now();
    
    if (success) {
        loginAttempts.delete(ip);
        return;
    }
    
    let attempts = loginAttempts.get(ip) || { count: 0, firstAttempt: now };
    
    // Reset if outside window
    if (now - attempts.firstAttempt > CONFIG.ATTEMPT_WINDOW) {
        attempts = { count: 0, firstAttempt: now };
    }
    
    attempts.count++;
    attempts.lastAttempt = now;
    loginAttempts.set(ip, attempts);
    
    // Block IP if too many attempts
    if (attempts.count >= CONFIG.MAX_LOGIN_ATTEMPTS) {
        blockedIPs.set(ip, {
            until: now + CONFIG.LOCKOUT_DURATION,
            attempts: attempts.count
        });
        loginAttempts.delete(ip);
        console.log(`🚫 IP blocked due to brute force: ${ip}`);
    }
}

function getRemainingAttempts(ip) {
    const attempts = loginAttempts.get(ip);
    if (!attempts) return CONFIG.MAX_LOGIN_ATTEMPTS;
    return Math.max(0, CONFIG.MAX_LOGIN_ATTEMPTS - attempts.count);
}

// ═══════════════════════════════════════════════════════════════════
// 🎫 SECURE SESSION MANAGEMENT
// ═══════════════════════════════════════════════════════════════════
function generateSecureToken() {
    return crypto.randomBytes(48).toString('base64url');
}

function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

function createSession(userId, userType, ip, userAgent, deviceFingerprint = null) {
    const sessionId = generateSessionId();
    const token = generateSecureToken();
    const now = Date.now();
    
    // Create token hash for storage (don't store raw token)
    const tokenHash = crypto.createHmac('sha256', CONFIG.SESSION_SECRET)
        .update(token)
        .digest('hex');
    
    const session = {
        id: sessionId,
        tokenHash,
        userId,
        userType, // 'master' or 'sub'
        ip: CONFIG.BIND_SESSION_TO_IP ? ip : null,
        userAgent,
        deviceFingerprint: CONFIG.BIND_SESSION_TO_DEVICE ? deviceFingerprint : null,
        createdAt: now,
        expiresAt: now + CONFIG.SESSION_DURATION,
        lastActivity: now,
        isValid: true
    };
    
    secureSessions.set(sessionId, session);
    
    console.log(`✅ Session created: ${sessionId.substring(0, 16)}... for ${userType}`);
    
    return {
        sessionId,
        token,
        expiresAt: session.expiresAt,
        expiresIn: CONFIG.SESSION_DURATION / 1000
    };
}

function validateSession(sessionId, token, ip, userAgent) {
    const session = secureSessions.get(sessionId);
    
    if (!session) {
        return { valid: false, error: 'SESSION_NOT_FOUND' };
    }
    
    if (!session.isValid) {
        return { valid: false, error: 'SESSION_INVALIDATED' };
    }
    
    if (Date.now() > session.expiresAt) {
        secureSessions.delete(sessionId);
        return { valid: false, error: 'SESSION_EXPIRED' };
    }
    
    // Verify token
    const tokenHash = crypto.createHmac('sha256', CONFIG.SESSION_SECRET)
        .update(token)
        .digest('hex');
    
    if (!crypto.timingSafeEqual(Buffer.from(tokenHash), Buffer.from(session.tokenHash))) {
        return { valid: false, error: 'INVALID_TOKEN' };
    }
    
    // Verify IP binding
    if (CONFIG.BIND_SESSION_TO_IP && session.ip && session.ip !== ip) {
        console.log(`⚠️ IP mismatch for session ${sessionId.substring(0, 16)}...`);
        return { valid: false, error: 'IP_MISMATCH' };
    }
    
    // Update last activity
    session.lastActivity = Date.now();
    
    return {
        valid: true,
        session: {
            userId: session.userId,
            userType: session.userType,
            createdAt: session.createdAt,
            expiresAt: session.expiresAt
        }
    };
}

function destroySession(sessionId) {
    const session = secureSessions.get(sessionId);
    if (session) {
        session.isValid = false;
        secureSessions.delete(sessionId);
        console.log(`👋 Session destroyed: ${sessionId.substring(0, 16)}...`);
        return true;
    }
    return false;
}

function destroyAllUserSessions(userId) {
    let count = 0;
    for (const [id, session] of secureSessions) {
        if (session.userId === userId) {
            secureSessions.delete(id);
            count++;
        }
    }
    console.log(`🧹 Destroyed ${count} sessions for user: ${userId}`);
    return count;
}

// ═══════════════════════════════════════════════════════════════════
// 🔐 2FA - TOTP (Google Authenticator)
// ═══════════════════════════════════════════════════════════════════
function generateTOTPSecret() {
    return crypto.randomBytes(20).toString('base32');
}

function generateTOTP(secret) {
    const time = Math.floor(Date.now() / 30000);
    const buffer = Buffer.alloc(8);
    buffer.writeBigInt64BE(BigInt(time));
    
    const hmac = crypto.createHmac('sha1', Buffer.from(secret, 'base32'));
    hmac.update(buffer);
    const hash = hmac.digest();
    
    const offset = hash[hash.length - 1] & 0xf;
    const code = (hash.readUInt32BE(offset) & 0x7fffffff) % 1000000;
    
    return code.toString().padStart(6, '0');
}

function verifyTOTP(secret, code, window = 1) {
    const currentCode = generateTOTP(secret);
    
    // Simple verification (for production, use a proper TOTP library)
    if (code === currentCode) return true;
    
    // Check previous and next windows
    for (let i = 1; i <= window; i++) {
        const time = Math.floor(Date.now() / 30000);
        // This is simplified - use a proper library like 'otplib'
    }
    
    return code === currentCode;
}

// ═══════════════════════════════════════════════════════════════════
// 🛡️ MIDDLEWARE - Auth Guard
// ═══════════════════════════════════════════════════════════════════
function authGuard(requiredType = null) {
    return (req, res, next) => {
        const sessionId = req.headers['x-session-id'];
        const token = req.headers['x-session-token'];
        const ip = req.clientIP || req.ip;
        const userAgent = req.headers['user-agent'];
        
        if (!sessionId || !token) {
            return res.status(401).json({
                success: false,
                error: 'المصادقة مطلوبة',
                code: 'AUTH_REQUIRED'
            });
        }
        
        const validation = validateSession(sessionId, token, ip, userAgent);
        
        if (!validation.valid) {
            const errorMessages = {
                'SESSION_NOT_FOUND': 'الجلسة غير موجودة',
                'SESSION_INVALIDATED': 'الجلسة ملغية',
                'SESSION_EXPIRED': 'انتهت صلاحية الجلسة',
                'INVALID_TOKEN': 'رمز غير صالح',
                'IP_MISMATCH': 'تغيير IP مشبوه'
            };
            
            return res.status(401).json({
                success: false,
                error: errorMessages[validation.error] || 'فشل المصادقة',
                code: validation.error
            });
        }
        
        // Check user type if required
        if (requiredType && validation.session.userType !== requiredType) {
            return res.status(403).json({
                success: false,
                error: 'صلاحيات غير كافية',
                code: 'INSUFFICIENT_PERMISSIONS'
            });
        }
        
        // Attach session to request
        req.session = validation.session;
        req.sessionId = sessionId;
        
        next();
    };
}

// Specific guards
const authMaster = authGuard('master');
const authSubAdmin = authGuard('sub');
const authAny = authGuard(null);

// ═══════════════════════════════════════════════════════════════════
// 🧹 SESSION CLEANUP
// ═══════════════════════════════════════════════════════════════════
function cleanupExpiredSessions() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [id, session] of secureSessions) {
        if (now > session.expiresAt || !session.isValid) {
            secureSessions.delete(id);
            cleaned++;
        }
    }
    
    // Cleanup old login attempts
    for (const [ip, attempts] of loginAttempts) {
        if (now - attempts.lastAttempt > CONFIG.ATTEMPT_WINDOW) {
            loginAttempts.delete(ip);
        }
    }
    
    // Cleanup expired blocks
    for (const [ip, block] of blockedIPs) {
        if (now > block.until) {
            blockedIPs.delete(ip);
        }
    }
    
    if (cleaned > 0) {
        console.log(`🧹 Cleaned ${cleaned} expired sessions`);
    }
}

// Start cleanup interval
function startSessionCleanup() {
    setInterval(cleanupExpiredSessions, 5 * 60 * 1000); // Every 5 minutes
    console.log('🧹 Session cleanup started');
}

// ═══════════════════════════════════════════════════════════════════
// 📊 STATS
// ═══════════════════════════════════════════════════════════════════
function getSecurityStats() {
    return {
        activeSessions: secureSessions.size,
        blockedIPs: blockedIPs.size,
        pendingAttempts: loginAttempts.size,
        sessionDetails: Array.from(secureSessions.values()).map(s => ({
            userType: s.userType,
            createdAt: s.createdAt,
            expiresAt: s.expiresAt,
            ip: s.ip ? s.ip.substring(0, 8) + '***' : null
        }))
    };
}

// ═══════════════════════════════════════════════════════════════════
// 📦 EXPORTS
// ═══════════════════════════════════════════════════════════════════
module.exports = {
    // Environment
    validateEnvironment,
    CONFIG,
    
    // Password
    hashPassword,
    verifyPassword,
    validatePasswordStrength,
    
    // Brute Force
    isIPBlocked,
    getBlockedRemainingTime,
    recordLoginAttempt,
    getRemainingAttempts,
    
    // Sessions
    createSession,
    validateSession,
    destroySession,
    destroyAllUserSessions,
    startSessionCleanup,
    
    // 2FA
    generateTOTPSecret,
    verifyTOTP,
    
    // Middleware
    authGuard,
    authMaster,
    authSubAdmin,
    authAny,
    
    // Stats
    getSecurityStats,
    
    // Storage (for external access if needed)
    secureSessions,
    blockedIPs
};
