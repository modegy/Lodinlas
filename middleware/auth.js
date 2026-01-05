// middleware/auth.js - Authentication Middleware v14.1
'use strict';

const { firebase, FB_KEY } = require('../config/database');
const { APP_API_KEY, adminSessions, subAdminKeys, MASTER_ADMIN_TOKEN } = require('../config/constants');

// ═══════════════════════════════════════════════════════════════════
// 🔐 APP AUTHENTICATION
// ═══════════════════════════════════════════════════════════════════
const authApp = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({
            success: false,
            error: 'API Key required',
            code: 401
        });
    }

    if (apiKey === APP_API_KEY) {
        return next();
    }

    res.status(401).json({
        success: false,
        error: 'Invalid API Key',
        code: 401
    });
};

// ═══════════════════════════════════════════════════════════════════
// 👑 ADMIN AUTHENTICATION
// ═══════════════════════════════════════════════════════════════════
const authAdmin = (req, res, next) => {
    const sessionToken = req.headers['x-session-token'];

    if (!sessionToken) {
        return res.status(401).json({
            success: false,
            error: 'Session token required',
            code: 401
        });
    }

    // Check master token
    if (MASTER_ADMIN_TOKEN && sessionToken === MASTER_ADMIN_TOKEN) {
        req.adminUser = 'master_owner';
        return next();
    }

    // Check session
    const session = adminSessions.get(sessionToken);

    if (!session) {
        return res.status(401).json({
            success: false,
            error: 'Invalid or expired session',
            code: 401
        });
    }

    // Check expiry (24 hours)
    if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
        adminSessions.delete(sessionToken);
        return res.status(401).json({
            success: false,
            error: 'Session expired',
            code: 401
        });
    }

    req.adminUser = session.username;
    next();
};

// ═══════════════════════════════════════════════════════════════════
// 🔑 SUB ADMIN AUTHENTICATION
// ═══════════════════════════════════════════════════════════════════
const authSubAdmin = async (req, res, next) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const deviceFingerprint = req.headers['x-device-fingerprint'];

        if (!apiKey) {
            return res.status(401).json({
                success: false,
                error: 'API key required'
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
                error: 'Invalid API key'
            });
        }

        if (!foundKey.is_active) {
            return res.status(403).json({
                success: false,
                error: 'Key is inactive'
            });
        }

        if (foundKey.expiry_timestamp && Date.now() > foundKey.expiry_timestamp) {
            return res.status(403).json({
                success: false,
                error: 'Key expired'
            });
        }

        if (foundKey.bound_device && foundKey.bound_device !== deviceFingerprint) {
            return res.status(403).json({
                success: false,
                error: 'Key is bound to another device'
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
            error: 'Authentication error'
        });
    }
};

// ═══════════════════════════════════════════════════════════════════
// 🔒 PERMISSION CHECK
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
                error: 'Permission denied'
            });
        }

        next();
    };
};

// ═══════════════════════════════════════════════════════════════════
// 👤 USER OWNERSHIP CHECK
// ═══════════════════════════════════════════════════════════════════
const checkUserOwnership = async (req, res, next) => {
    try {
        const userId = req.params.id;
        const currentKeyId = req.subAdminKeyId;

        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);

        if (!userRes.data) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        const user = userRes.data;

        if (!user.created_by_key || user.created_by_key !== currentKeyId) {
            console.log(`🚫 Ownership denied: User created_by_key="${user.created_by_key}" vs Current key="${currentKeyId}"`);
            return res.status(403).json({
                success: false,
                error: 'You can only manage users you created'
            });
        }

        req.targetUser = user;
        next();

    } catch (error) {
        console.error('Ownership check error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to verify ownership'
        });
    }
};

// ═══════════════════════════════════════════════════════════════════
// 🧹 SESSION CLEANUP
// ═══════════════════════════════════════════════════════════════════
const startSessionCleanup = () => {
    // Clean admin sessions every hour
    setInterval(() => {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [token, session] of adminSessions.entries()) {
            if (now - session.createdAt > 24 * 60 * 60 * 1000) {
                adminSessions.delete(token);
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            console.log(`🧹 [AUTH] Cleaned ${cleaned} expired admin sessions`);
        }
    }, 60 * 60 * 1000);

    // Clean sub admin cache every 15 minutes
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
            console.log(`🧹 [AUTH] Cleaned ${cleaned} sub admin cache entries`);
        }
    }, 15 * 60 * 1000);
};

// ═══════════════════════════════════════════════════════════════════
// 📦 EXPORT
// ═══════════════════════════════════════════════════════════════════
module.exports = {
    authApp,
    authAdmin,
    authSubAdmin,
    checkSubAdminPermission,
    checkUserOwnership,
    startSessionCleanup
};
