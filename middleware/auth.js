// middleware/auth.js
const crypto = require('crypto');
const config = require('../config');
const { firebase, FB_KEY } = require('../services/firebase');

// Admin Sessions Storage
const adminSessions = new Map();

// App Authentication
const authApp = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
        logAuthAttempt(req, false, 'API Key missing');
        return res.status(401).json({ 
            success: false, 
            error: 'API Key required', 
            code: 401 
        });
    }
    
    if (apiKey === config.APP_API_KEY) {
        logAuthAttempt(req, true);
        return next();
    }
    
    logAuthAttempt(req, false, 'Invalid API Key');
    res.status(401).json({ 
        success: false, 
        error: 'Invalid API Key', 
        code: 401 
    });
};

// Admin Authentication
const authAdmin = (req, res, next) => {
    const sessionToken = req.headers['x-session-token'];
    
    if (!sessionToken) {
        logAuthAttempt(req, false, 'Session token missing');
        return res.status(401).json({ 
            success: false, 
            error: 'Session token required', 
            code: 401 
        });
    }
    
    // Validate token format
    if (!/^[a-zA-Z0-9\-_]{20,}$/.test(sessionToken)) {
        logAuthAttempt(req, false, 'Invalid token format');
        return res.status(401).json({ 
            success: false, 
            error: 'Invalid token format', 
            code: 401 
        });
    }
    
    // Check master token
    if (config.MASTER_ADMIN_TOKEN && sessionToken === config.MASTER_ADMIN_TOKEN) {
        logAuthAttempt(req, true, 'Master token used');
        req.adminUser = 'master_owner';
        return next();
    }
    
    const session = adminSessions.get(sessionToken);
    
    if (!session) {
        logAuthAttempt(req, false, 'Session not found');
        return res.status(401).json({ 
            success: false, 
            error: 'Invalid or expired session', 
            code: 401 
        });
    }
    
    if (Date.now() - session.createdAt > config.SESSION.EXPIRY) {
        adminSessions.delete(sessionToken);
        logAuthAttempt(req, false, 'Session expired');
        return res.status(401).json({ 
            success: false, 
            error: 'Session expired', 
            code: 401 
        });
    }
    
    // Update last activity
    session.lastActivity = Date.now();
    adminSessions.set(sessionToken, session);
    
    req.adminUser = session.username;
    req.sessionId = sessionToken;
    next();
};

// Sub Admin Authentication
const authSubAdmin = async (req, res, next) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const deviceFingerprint = req.headers['x-device-fingerprint'];
        
        if (!apiKey) {
            logAuthAttempt(req, false, 'API key missing');
            return res.status(401).json({ 
                success: false, 
                error: 'API key required' 
            });
        }
        
        if (!deviceFingerprint) {
            logAuthAttempt(req, false, 'Device fingerprint missing');
            return res.status(401).json({ 
                success: false, 
                error: 'Device fingerprint required' 
            });
        }
        
        // Check cache first
        const cached = global.subAdminCache?.get(apiKey);
        if (cached && cached.device === deviceFingerprint) {
            if (isKeyValid(cached)) {
                req.subAdminKey = cached;
                req.subAdminKeyId = cached.keyId;
                logAuthAttempt(req, true, 'Cache hit');
                return next();
            }
        }
        
        // Fetch from Firebase
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}&orderBy="api_key"&equalTo="${apiKey}"`);
        const keys = response.data || {};
        
        if (Object.keys(keys).length === 0) {
            logAuthAttempt(req, false, 'API key not found');
            return res.status(401).json({ success: false, error: 'Invalid API key' });
        }
        
        const keyId = Object.keys(keys)[0];
        const foundKey = keys[keyId];
        
        // Validate key
        const validationError = validateKey(foundKey, deviceFingerprint);
        if (validationError) {
            logAuthAttempt(req, false, validationError);
            return res.status(403).json({ success: false, error: validationError });
        }
        
        // Prepare key data
        const keyData = {
            ...foundKey,
            keyId,
            device: deviceFingerprint,
            last_used: Date.now(),
            cache_time: Date.now()
        };
        
        // Update cache
        if (!global.subAdminCache) {
            global.subAdminCache = new Map();
        }
        global.subAdminCache.set(apiKey, keyData);
        
        req.subAdminKey = keyData;
        req.subAdminKeyId = keyId;
        logAuthAttempt(req, true, 'Firebase validation');
        next();
        
    } catch (error) {
        console.error('Auth Sub Admin error:', error.message);
        logAuthAttempt(req, false, `Server error: ${error.message}`);
        res.status(500).json({ success: false, error: 'Authentication error' });
    }
};

// Key validation helper
const validateKey = (keyData, deviceFingerprint) => {
    if (!keyData.is_active) {
        return 'Key is inactive';
    }
    
    if (keyData.expiry_timestamp) {
        const expiryTime = parseInt(keyData.expiry_timestamp);
        if (isNaN(expiryTime) || expiryTime <= 0) {
            return 'Invalid expiry configuration';
        }
        
        if (Date.now() > expiryTime) {
            return 'Key expired';
        }
    }
    
    if (keyData.bound_device && keyData.bound_device !== deviceFingerprint) {
        return 'Key is bound to another device';
    }
    
    return null;
};

// Check if cached key is valid
const isKeyValid = (cachedKey) => {
    if (!cachedKey.is_active) return false;
    
    if (cachedKey.expiry_timestamp && Date.now() > cachedKey.expiry_timestamp) {
        return false;
    }
    
    // Cache validity: 5 minutes
    if (Date.now() - cachedKey.cache_time > 5 * 60 * 1000) {
        return false;
    }
    
    return true;
};

// Permission Check
const checkSubAdminPermission = (requiredPermission) => {
    return (req, res, next) => {
        const keyData = req.subAdminKey;
        
        if (!keyData) {
            return res.status(403).json({ 
                success: false, 
                error: 'Authentication required' 
            });
        }
        
        const PERMISSION_MATRIX = {
            'full': {
                view: true,
                add: true,
                extend: true,
                edit: true,
                delete: true,
                export: true
            },
            'add_only': {
                view: true,
                add: true,
                extend: false,
                edit: false,
                delete: false,
                export: false
            },
            'extend_only': {
                view: true,
                add: false,
                extend: true,
                edit: false,
                delete: false,
                export: false
            },
            'view_only': {
                view: true,
                add: false,
                extend: false,
                edit: false,
                delete: false,
                export: false
            }
        };
        
        const permissions = PERMISSION_MATRIX[keyData.permission_level] || PERMISSION_MATRIX.view_only;
        
        if (!permissions[requiredPermission]) {
            logAuthAttempt(req, false, `Permission denied: ${requiredPermission}`);
            return res.status(403).json({ 
                success: false, 
                error: 'Permission denied',
                required: requiredPermission,
                has: keyData.permission_level
            });
        }
        
        next();
    };
};

// Ownership Check
const checkUserOwnership = async (req, res, next) => {
    try {
        const userId = req.params.id;
        const currentKeyId = req.subAdminKeyId;
        
        if (!userId || !/^[a-zA-Z0-9_-]+$/.test(userId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid user ID format' 
            });
        }
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const user = userRes.data;
        
        if (!user.created_by_key || user.created_by_key !== currentKeyId) {
            logAuthAttempt(req, false, 'Ownership violation');
            return res.status(403).json({ 
                success: false, 
                error: 'You can only manage users you created' 
            });
        }
        
        req.targetUser = user;
        next();
        
    } catch (error) {
        console.error('Ownership check error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to verify ownership' });
    }
};

// Authentication logging
const logAuthAttempt = (req, success, reason = '') => {
    const logEntry = {
        timestamp: new Date().toISOString(),
        ip: req.ip || req.connection.remoteAddress,
        method: req.method,
        path: req.path,
        success,
        reason,
        userAgent: req.get('User-Agent') || 'Unknown',
        xApiKey: req.headers['x-api-key'] ? '***' + req.headers['x-api-key'].slice(-4) : 'None'
    };
    
    console.log('[AUTH_LOG]', JSON.stringify(logEntry));
    
    // Store failed attempts for rate limiting
    if (!success) {
        const key = `${req.ip}-${req.headers['x-api-key']}`;
        const now = Date.now();
        
        if (!global.failedAttempts) {
            global.failedAttempts = new Map();
        }
        
        const attempts = global.failedAttempts.get(key) || [];
        attempts.push(now);
        
        // Keep only last hour attempts
        const recentAttempts = attempts.filter(time => now - time < 60 * 60 * 1000);
        global.failedAttempts.set(key, recentAttempts);
        
        // Check for brute force
        if (recentAttempts.length > 10) {
            console.warn(`[SECURITY] Brute force detected from ${req.ip}`);
        }
    }
};

// Session cleanup
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    
    // Clean admin sessions
    for (const [token, session] of adminSessions.entries()) {
        if (now - session.lastActivity > config.SESSION.EXPIRY) {
            adminSessions.delete(token);
            cleaned++;
        }
    }
    
    // Clean sub-admin cache
    if (global.subAdminCache) {
        for (const [apiKey, keyData] of global.subAdminCache.entries()) {
            if (now - keyData.cache_time > 5 * 60 * 1000) {
                global.subAdminCache.delete(apiKey);
                cleaned++;
            }
        }
    }
    
    if (cleaned > 0) {
        console.log(`[CLEANUP] Cleaned ${cleaned} expired entries`);
    }
}, 60 * 1000); // Run every minute

module.exports = {
    authApp,
    authAdmin,
    authSubAdmin,
    checkSubAdminPermission,
    checkUserOwnership,
    adminSessions,
    validateKey,
    logAuthAttempt
};
