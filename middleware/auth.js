// middleware/auth.js - Secure Authentication v15.0
// 🔐 Merged: Secure Master Auth + Sub Admin Auth + App Auth
'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { firebase, FB_KEY } = require('../config/database');
const { APP_API_KEY, subAdminKeys } = require('../config/constants');

// ═══════════════════════════════════════════════════════════════════
// 🔐 SECURE SESSION STORE (Master Admin)
// ═══════════════════════════════════════════════════════════════════
const secureSessions = new Map();
const loginAttempts = new Map();
const blockedIPs = new Map();

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
        return false;
    }
    
    // Validate bcrypt hash format
    const hash = process.env.MASTER_ADMIN_PASSWORD_HASH;
    if (!hash.startsWith('$2a$') && !hash.startsWith('$2b$')) {
        console.error('🚨 MASTER_ADMIN_PASSWORD_HASH must be a bcrypt hash!');
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
    if (success) {
        loginAttempts.delete(ip);
        return;
    }
    
    const now = Date.now();
    let attempts = loginAttempts.get(ip) || { count: 0, firstAttempt: now };
    
    if (now - attempts.firstAttempt > AUTH_CONFIG.ATTEMPT_WINDOW) {
        attempts = { count: 0, firstAttempt: now };
    }
    
    attempts.count++;
    attempts.lastAttempt = now;
    loginAttempts.set(ip, attempts);
    
    if (attempts.count >= AUTH_CONFIG.MAX_LOGIN_ATTEMPTS) {
        blockedIPs.set(ip, {
            until: now + AUTH_CONFIG.LOCKOUT_DURATION,
            attempts: attempts.count
        });
        loginAttempts.delete(ip);
        console.log(`🚫 IP blocked due to brute force: ${ip}`);
    }
}

function getRemainingAttempts(ip) {
    const attempts = loginAttempts.get(ip);
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

function createSession(userId, userType, ip, userAgent, deviceFingerprint = null) {
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
    
    secureSessions.set(sessionId, session);
    console.log(`✅ Session created: ${sessionId.substring(0, 16)}... for ${userType}`);
    
    return { sessionId, token, expiresAt: session.expiresAt, expiresIn: AUTH_CONFIG.SESSION_DURATION / 1000 };
}

function validateSession(sessionId, token, ip) {
    const session = secureSessions.get(sessionId);
    
    if (!session) return { valid: false, error: 'SESSION_NOT_FOUND' };
    if (!session.isValid) return { valid: false, error: 'SESSION_INVALIDATED' };
    if (Date.now() > session.expiresAt) {
        secureSessions.delete(sessionId);
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
    return { valid: true, session };
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
const authAdmin = (req, res, next) => {
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

    const validation = validateSession(sessionId, sessionToken, ip);

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

        // Fetch from Firebase
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
        const keys = response.data || {};

        let foundKey = null;
        let keyId = null;

        for (const [id, key] of Object.entries(keys)) {
            if (key.api_key === apiKey) {
                foundKey = key;
                keyId = id;
                break;
            }
        }

        if (!foundKey) {
            return res.status(401).json({
                success: false,
                error: 'Invalid API key',
                code: 'INVALID_API_KEY'
            });
        }

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

        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);

        if (!userRes.data) {
            return res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        const user = userRes.data;

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
    setInterval(() => {
        const now = Date.now();
        let cleaned = 0;

        for (const [id, session] of secureSessions.entries()) {
            if (now > session.expiresAt || !session.isValid) {
                secureSessions.delete(id);
                cleaned++;
            }
        }

        // Clean login attempts
        for (const [ip, attempts] of loginAttempts.entries()) {
            if (now - attempts.lastAttempt > AUTH_CONFIG.ATTEMPT_WINDOW) {
                loginAttempts.delete(ip);
            }
        }

        // Clean expired blocks
        for (const [ip, block] of blockedIPs.entries()) {
            if (now > block.until) {
                blockedIPs.delete(ip);
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
function getAuthStats() {
    return {
        activeMasterSessions: secureSessions.size,
        blockedIPs: blockedIPs.size,
        pendingAttempts: loginAttempts.size,
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
    secureSessions,
    
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
    blockedIPs,
    loginAttempts
};
