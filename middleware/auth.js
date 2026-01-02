// middleware/auth.js
const config = require('../config');
const { firebase, FB_KEY } = require('../services/firebase');
const { subAdminKeys } = require('./signature');

// Admin Sessions Storage
const adminSessions = new Map();

// App Authentication
const authApp = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
        return res.status(401).json({ 
            success: false, 
            error: 'API Key required', 
            code: 401 
        });
    }
    
    if (apiKey === config.APP_API_KEY) {
        return next();
    }
    
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
        return res.status(401).json({ 
            success: false, 
            error: 'Session token required', 
            code: 401 
        });
    }
    
    // Check master token
    if (config.MASTER_ADMIN_TOKEN && sessionToken === config.MASTER_ADMIN_TOKEN) {
        req.adminUser = 'master_owner';
        return next();
    }
    
    const session = adminSessions.get(sessionToken);
    
    if (!session) {
        return res.status(401).json({ 
            success: false, 
            error: 'Invalid or expired session', 
            code: 401 
        });
    }
    
    if (Date.now() - session.createdAt > config.SESSION.EXPIRY) {
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

// Sub Admin Authentication
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
        
        // Check cache
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
            return res.status(401).json({ success: false, error: 'Invalid API key' });
        }
        
        if (!foundKey.is_active) {
            return res.status(403).json({ success: false, error: 'Key is inactive' });
        }
        
        if (foundKey.expiry_timestamp && Date.now() > foundKey.expiry_timestamp) {
            return res.status(403).json({ success: false, error: 'Key expired' });
        }
        
        if (foundKey.bound_device && foundKey.bound_device !== deviceFingerprint) {
            return res.status(403).json({ success: false, error: 'Key is bound to another device' });
        }
        
        // Update cache
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
        res.status(500).json({ success: false, error: 'Authentication error' });
    }
};

// Permission Check
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
            return res.status(403).json({ success: false, error: 'Permission denied' });
        }
        
        next();
    };
};

// Ownership Check
const checkUserOwnership = async (req, res, next) => {
    try {
        const userId = req.params.id;
        const currentKeyId = req.subAdminKeyId;
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const user = userRes.data;
        
        if (!user.created_by_key || user.created_by_key !== currentKeyId) {
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

// Session cleanup
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of adminSessions.entries()) {
        if (now - session.createdAt > config.SESSION.EXPIRY) {
            adminSessions.delete(token);
        }
    }
}, 60 * 60 * 1000);

module.exports = {
    authApp,
    authAdmin,
    authSubAdmin,
    checkSubAdminPermission,
    checkUserOwnership,
    adminSessions
};
