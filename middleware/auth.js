// middleware/auth.js - Secure Authentication v15.0
// 🔐 Merged: Secure Master Auth + Sub Admin Auth + App Auth
'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy'); // إضافة لـ MFA (TOTP)
const { admin, db } = require('../config/firebase-admin');
const redis = require('redis'); // إضافة Redis
const client = redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
client.connect();

const { APP_API_KEY, subAdminKeys } = require('../config/constants');

// ═══════════════════════════════════════════════════════════════════
// 🔐 SECURE SESSION STORE (Master Admin)
// ═══════════════════════════════════════════════════════════════════
// const secureSessions = new Map(); // نقل إلى Redis
// const loginAttempts = new Map();
// const blockedIPs = new Map();

// ═══════════════════════════════════════════════════════════════════
// ⚙️ CONFIGURATION
// ═══════════════════════════════════════════════════════════════════
const AUTH_CONFIG = {
    // Session
    SESSION_DURATION: 8 * 60 * 60 * 1000, // 8 hours
    
    // Brute Force Protection
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION: 30 * 60 * 1000, // 30 minutes
    ATTEMPT_WINDOW: 15 * 60 * 1000, // 15 minutes
    
    // Password Requirements
    MIN_PASSWORD_LENGTH: 12,
    
    // Session Security
    BIND_SESSION_TO_IP: true
};

// ═══════════════════════════════════════════════════════════════════
// 🔒 ENVIRONMENT VALIDATION
// ═══════════════════════════════════════════════════════════════════
function validateAuthEnvironment() {
    const required = [
        'MASTER_ADMIN_USERNAME',
        'MASTER_ADMIN_PASSWORD_HASH',
        'SESSION_SECRET'
    ];
    
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        console.error('═'.repeat(60));
        console.error('🚨 CRITICAL: Missing auth environment variables:');
        missing.forEach(key => console.error(`   ❌ ${key}`));
        console.error('═'.repeat(60));
        process.exit(1); // إصلاح: إيقاف الخادم
        return false;
    }
    
    // Validate bcrypt hash format
    const hash = process.env.MASTER_ADMIN_PASSWORD_HASH;
    if (!hash.startsWith('$2a$') && !hash.startsWith('$2b$')) {
        console.error('🚨 MASTER_ADMIN_PASSWORD_HASH must be a bcrypt hash!');
        process.exit(1);
        return false;
    }
    
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
    if (password.length < AUTH_CONFIG.MIN_PASSWORD_LENGTH) {
        errors.push(`كلمة المرور يجب أن تكون ${AUTH_CONFIG.MIN_PASSWORD_LENGTH} حرف على الأقل`);
    }
    if (!/[A-Z]/.test(password)) errors.push('يجب أن تحتوي على حرف كبير');
    if (!/[0-9]/.test(password)) errors.push('يجب أن تحتوي على رقم');
    if (!/[!@#$%^&*()_+\-=\[\]{}|;':",.<>?/`~]/.test(password)) {
        errors.push('يجب أن تحتوي على رمز خاص');
    }
    return { valid: errors.length === 0, errors };
}

// إضافة MFA utilities
function generateMFASecret() {
    return speakeasy.generateSecret({ length: 20 });
}

function verifyMFAToken(secret, token) {
    return speakeasy.totp.verify({
        secret: secret.base32,
        encoding: 'base32',
        token,
        window: 1
    });
}

// ═══════════════════════════════════════════════════════════════════
// 🛡️ BRUTE FORCE PROTECTION
// ═══════════════════════════════════════════════════════════════════
async function isIPBlocked(ip) {
    const blocked = await client.get(`block:${ip}`);
    if (!blocked) return false;
    
    if (Date.now() > blocked.until) {
        await client.del(`block:${ip}`);
        return false;
    }
    return true;
}

function getBlockedRemainingTime(ip) {
    const blocked = JSON.parse(await client.get(`block:${ip}`));
    if (!blocked) return 0;
    return Math.ceil((blocked.until - Date.now()) / 1000 / 60);
}

async function recordLoginAttempt(ip, success, username = null) { // إضافة username لربط بالحساب
    const ipKey = `brute:ip:${ip}`;
    const userKey = username ? `brute:user:${username}` : null;

    const now = Date.now();
    let attempts = JSON.parse(await client.get(ipKey)) || { count: 0, firstAttempt: now };
    
    if (now - attempts.firstAttempt > AUTH_CONFIG.ATTEMPT_WINDOW) {
        attempts = { count: 0, firstAttempt: now };
    }
    
    if (!success) {
        attempts.count++;
        attempts.lastAttempt = now;
        await client.set(ipKey, JSON.stringify(attempts), { EX: AUTH_CONFIG.ATTEMPT_WINDOW / 1000 });
        
        if (userKey) {
            let userAttempts = JSON.parse(await client.get(userKey)) || { count: 0 };
            userAttempts.count++;
            await client.set(userKey, JSON.stringify(userAttempts), { EX: AUTH_CONFIG.ATTEMPT_WINDOW / 1000 });
            if (userAttempts.count >= AUTH_CONFIG.MAX_LOGIN_ATTEMPTS) {
                // حظر الحساب أيضاً
            }
        }
        
        if (attempts.count >= AUTH_CONFIG.MAX_LOGIN_ATTEMPTS) {
            await client.set(`block:${ip}`, JSON.stringify({
                until: now + AUTH_CONFIG.LOCKOUT_DURATION,
                attempts: attempts.count
            }), { EX: AUTH_CONFIG.LOCKOUT_DURATION / 1000 });
            await client.del(ipKey);
            console.log(`🚫 IP blocked due to brute force: ${crypto.createHash('sha256').update(ip).digest('hex')}`);
        }
    } else {
        await client.del(ipKey);
        if (userKey) await client.del(userKey);
    }
}

async function getRemainingAttempts(ip) {
    const attempts = JSON.parse(await client.get(`brute:ip:${ip}`));
    if (!attempts) return AUTH_CONFIG.MAX_LOGIN_ATTEMPTS;
    return Math.max(0, AUTH_CONFIG.MAX_LOGIN_ATTEMPTS - attempts.count);
}

// ═══════════════════════════════════════════════════════════════════
// 🎫 SECURE SESSION MANAGEMENT (Master Admin)
// ═══════════════════════════════════════════════════════════════════
function generateSecureToken() {
    return crypto.randomBytes(48).toString('base64url');
}

function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

async function createSession(userId, userType, ip, userAgent, deviceFingerprint = null) {
    const sessionId = generateSessionId();
    const token = generateSecureToken();
    const now = Date.now();
    
    const SESSION_SECRET = process.env.SESSION_SECRET;
    const tokenHash = crypto.createHmac('sha256', SESSION_SECRET)
        .update(token)
        .digest('hex');
    
    const session = {
        id: sessionId,
        tokenHash,
        userId,
        userType,
        ip: AUTH_CONFIG.BIND_SESSION_TO_IP ? ip : null,
        userAgent,
        deviceFingerprint,
        createdAt: now,
        expiresAt: now + AUTH_CONFIG.SESSION_DURATION,
        lastActivity: now,
        isValid: true
    };
    
    await client.set(`session:${sessionId}`, JSON.stringify(session), { EX: AUTH_CONFIG.SESSION_DURATION / 1000 });
    console.log(`✅ Session created: ${sessionId.substring(0, 16)}... for ${userType}`);
    
    return { sessionId, token, expiresAt: session.expiresAt, expiresIn: AUTH_CONFIG.SESSION_DURATION / 1000 };
}

async function validateSession(sessionId, token, ip) {
    const sessionStr = await client.get(`session:${sessionId}`);
    if (!sessionStr) return { valid: false, error: 'SESSION_NOT_FOUND' };
    const session = JSON.parse(sessionStr);
    
    if (!session.isValid) return { valid: false, error: 'SESSION_INVALIDATED' };
    if (Date.now() > session.expiresAt) {
        await client.del(`session:${sessionId}`);
        return { valid: false, error: 'SESSION_EXPIRED' };
    }
    
    const SESSION_SECRET = process.env.SESSION_SECRET;
    const tokenHash = crypto.createHmac('sha256', SESSION_SECRET)
        .update(token)
        .digest('hex');
    
    if (!crypto.timingSafeEqual(Buffer.from(tokenHash), Buffer.from(session.tokenHash))) {
        return { valid: false, error: 'INVALID_TOKEN' };
    }
    
    if (AUTH_CONFIG.BIND_SESSION_TO_IP && session.ip && session.ip !== ip) {
        console.log(`⚠️ IP mismatch for session ${sessionId.substring(0, 16)}...`);
        return { valid: false, error: 'IP_MISMATCH' };
    }
    
    session.lastActivity = Date.now();
    await client.set(`session:${sessionId}`, JSON.stringify(session), { EX: (session.expiresAt - Date.now()) / 1000 });
    return { valid: true, session };
}

async function destroySession(sessionId) {
    const sessionStr = await client.get(`session:${sessionId}`);
    if (sessionStr) {
        await client.del(`session:${sessionId}`);
        console.log(`👋 Session destroyed: ${sessionId.substring(0, 16)}...`);
        return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════
// 🔐 APP AUTHENTICATION (Mobile App)
// ═══════════════════════════════════════════════════════════════════
const authApp = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({
            success: false,
            error: 'API Key required',
            code: 'API_KEY_REQUIRED'
        });
    }

    if (apiKey === APP_API_KEY) {
        return next();
    }

    res.status(401).json({
        success: false,
        error: 'Invalid API Key',
        code: 'INVALID_API_KEY'
    });
};

// ═══════════════════════════════════════════════════════════════════
// 👑 MASTER ADMIN AUTHENTICATION (Secure Version)
// ═══════════════════════════════════════════════════════════════════
const authAdmin = async (req, res, next) => { // async لـ Redis
    const sessionId = req.headers['x-session-id'];
    const sessionToken = req.headers['x-session-token'];
    const ip = req.clientIP || req.ip;
    
    // Support both old and new header format during transition
    const legacyToken = req.headers['x-session-token'];
    
    if (!sessionId && legacyToken) {
        // Legacy support: check if it's an old-style session
        // This will be removed after transition
        console.warn('⚠️ Legacy session format detected, please update client');
    }

    if (!sessionId || !sessionToken) {
        return res.status(401).json({
            success: false,
            error: 'المصادقة مطلوبة',
            code: 'AUTH_REQUIRED'
        });
    }

    const validation = await validateSession(sessionId, sessionToken, ip);

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

    // Check if master admin
    if (validation.session.userType !== 'master') {
        return res.status(403).json({
            success: false,
            error: 'صلاحيات غير كافية',
            code: 'INSUFFICIENT_PERMISSIONS'
        });
    }

    req.session = validation.session;
    req.sessionId = sessionId;
    req.adminUser = validation.session.userId;
    
    next();
};

// ═══════════════════════════════════════════════════════════════════
// 🔑 SUB ADMIN AUTHENTICATION (Keep existing logic)
// ═══════════════════════════════════════════════════════════════════
const authSubAdmin = async (req, res, next) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const deviceFingerprint = req.headers['x-device-fingerprint'];

        if (!apiKey) {
            return res.status(401).json({
                success: false,
                error: 'API key required',
                code: 'API_KEY_REQUIRED'
            });
        }

        // Check cache first
        const cached = subAdminKeys.get(apiKey);
        if (cached && cached.device === deviceFingerprint) {
            if (cached.expiry_timestamp > Date.now() && cached.is_active) {
                req.subAdminKey = cached;
                req.subAdminKeyId = cached.keyId;
                return next();
            }
        }

        // Fetch from Firebase using Admin SDK - إصلاح: تجنب HTTP
        const db = admin.database();
        const snapshot = await db.ref('api_keys')
            .orderByChild('api_key')
            .equalTo(apiKey)
            .once('value');

        if (!snapshot.exists()) {
            return res.status(401).json({
                success: false,
                error: 'Invalid API key',
                code: 'INVALID_API_KEY'
            });
        }

        const data = snapshot.val();
        const [[keyId, foundKey]] = Object.entries(data);

        if (!foundKey.is_active) {
            return res.status(403).json({
                success: false,
                error: 'Key is inactive',
                code: 'KEY_INACTIVE'
            });
        }

        if (foundKey.expiry_timestamp && Date.now() > foundKey.expiry_timestamp) {
            return res.status(403).json({
                success: false,
                error: 'Key expired',
                code: 'KEY_EXPIRED'
            });
        }

        if (foundKey.bound_device && foundKey.bound_device !== deviceFingerprint) {
            return res.status(403).json({
                success: false,
                error: 'Key is bound to another device',
                code: 'DEVICE_MISMATCH'
            });
        }

        // Cache the key
        subAdminKeys.set(apiKey, {
            ...foundKey,
            keyId,
            device: deviceFingerprint,
            last_used: Date.now()
        });

        req.subAdminKey = foundKey;
        req.subAdminKeyId = keyId;
        next();

    } catch (error) {
        console.error('Auth Sub Admin error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Authentication error',
            code: 'AUTH_ERROR'
        });
    }
};

// ═══════════════════════════════════════════════════════════════════
// 🔒 PERMISSION CHECK (Sub Admin)
// ═══════════════════════════════════════════════════════════════════
const checkSubAdminPermission = (requiredPermission) => {
    return (req, res, next) => {
        const keyData = req.subAdminKey;

        const permissions = {
            'full': ['view', 'add', 'extend', 'edit', 'delete'],
            'add_only': ['view', 'add'],
            'extend_only': ['view', 'extend'],
            'view_only': ['view']
        };

        const allowedPermissions = permissions[keyData.permission_level] || permissions.view_only;

        if (!allowedPermissions.includes(requiredPermission)) {
            return res.status(403).json({
                success: false,
                error: 'Permission denied',
                code: 'PERMISSION_DENIED'
            });
        }

        next();
    };
};

// ═══════════════════════════════════════════════════════════════════
// 👤 USER OWNERSHIP CHECK (Sub Admin)
// ═══════════════════════════════════════════════════════════════════
const checkUserOwnership = async (req, res, next) => {
    try {
        const userId = req.params.id;
        const currentKeyId = req.subAdminKeyId;

        const db = admin.database(); // Admin SDK
        const userSnapshot = await db.ref(`users/${userId}`).once('value');
        const user = userSnapshot.val();

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        if (!user.created_by_key || user.created_by_key !== currentKeyId) {
            return res.status(403).json({
                success: false,
                error: 'You can only manage users you created',
                code: 'OWNERSHIP_DENIED'
            });
        }

        req.targetUser = user;
        next();

    } catch (error) {
        console.error('Ownership check error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to verify ownership',
            code: 'OWNERSHIP_CHECK_ERROR'
        });
    }
};

// ═══════════════════════════════════════════════════════════════════
// 🧹 SESSION CLEANUP
// ═══════════════════════════════════════════════════════════════════
const startSessionCleanup = () => {
    // Clean master admin sessions
    setInterval(async () => {
        const now = Date.now();
        let cleaned = 0;

        const sessionKeys = await client.keys('session:*');
        for (const key of sessionKeys) {
            const session = JSON.parse(await client.get(key));
            if (now > session.expiresAt || !session.isValid) {
                await client.del(key);
                cleaned++;
            }
        }

        // Clean login attempts
        const attemptKeys = await client.keys('brute:*');
        for (const key of attemptKeys) {
            const attempts = JSON.parse(await client.get(key));
            if (now - attempts.lastAttempt > AUTH_CONFIG.ATTEMPT_WINDOW) {
                await client.del(key);
            }
        }

        // Clean expired blocks
        const blockKeys = await client.keys('block:*');
        for (const key of blockKeys) {
            const block = JSON.parse(await client.get(key));
            if (now > block.until) {
                await client.del(key);
            }
        }

        if (cleaned > 0) {
            console.log(`🧹 Cleaned ${cleaned} expired master sessions`);
        }
    }, 5 * 60 * 1000); // Every 5 minutes

    // Clean sub admin cache
    setInterval(() => {
        const now = Date.now();
        let cleaned = 0;

        for (const [apiKey, keyData] of subAdminKeys.entries()) {
            if (now - (keyData.last_used || 0) > 30 * 60 * 1000) {
                subAdminKeys.delete(apiKey);
                cleaned++;
            }
        }

        if (cleaned > 0) {
            console.log(`🧹 Cleaned ${cleaned} sub admin cache entries`);
        }
    }, 15 * 60 * 1000);
    
    console.log('🧹 Session cleanup started');
};

// ═══════════════════════════════════════════════════════════════════
// 📊 AUTH STATS
// ═══════════════════════════════════════════════════════════════════
async function getAuthStats() {
    return {
        activeMasterSessions: await client.keys('session:*').length,
        blockedIPs: await client.keys('block:*').length,
        pendingAttempts: await client.keys('brute:*').length,
        cachedSubAdminKeys: subAdminKeys.size
    };
}

// ═══════════════════════════════════════════════════════════════════
// 📦 EXPORT
// ═══════════════════════════════════════════════════════════════════
module.exports = {
    // Environment
    validateAuthEnvironment,
    AUTH_CONFIG,
    
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
    secureSessions, // محافظ عليه للتوافق، لكن غير مستخدم
    
    // Middleware
    authApp,
    authAdmin,
    authSubAdmin,
    checkSubAdminPermission,
    checkUserOwnership,
    
    // Cleanup
    startSessionCleanup,
    
    // Stats
    getAuthStats,
    
    // Storage references
    blockedIPs, // محافظ عليه
    loginAttempts,
    
    // MFA
    generateMFASecret,
    verifyMFAToken
};
