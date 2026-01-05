// routes/admin.js - نقاط النهاية للوحة الإدارة (مُحدث بالكامل)
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const config = require('../config');
const { firebase, FB_KEY } = require('../services/firebase');
const { authAdmin, createAdminSession, invalidateAdminSession } = require('../middleware/auth');
const { generateToken, hashPassword, formatDate, generateApiKey, generateSigningSecret } = require('../helpers/utils');

// ═══════════════════════════════════════════
// ✅ FALLBACK للمتغيرات من security.js
// ═══════════════════════════════════════════
let bruteForceProtection, loginAttempts, blockedIPs, requestTracker;

try {
    const security = require('../middleware/security');
    const securityInstance = security.getInstance();
    bruteForceProtection = (req, res, next) => next();
    loginAttempts = new Map();
    blockedIPs = securityInstance?.blockedIPs || new Set();
    requestTracker = new Map();
} catch (error) {
    console.warn('⚠️ Security module not loaded, using fallbacks');
    bruteForceProtection = (req, res, next) => next();
    loginAttempts = new Map();
    blockedIPs = new Set();
    requestTracker = new Map();
}

// ═══════════════════════════════════════════
// AUTH - تسجيل الدخول/الخروج
// ═══════════════════════════════════════════
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.clientIP || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '127.0.0.1';
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Username and password required',
                code: 'MISSING_CREDENTIALS'
            });
        }
        
        if (!config.ADMIN_CREDENTIALS?.username || !config.ADMIN_CREDENTIALS?.password) {
            console.error('❌ Admin credentials not configured in environment');
            return res.status(500).json({ 
                success: false, 
                error: 'Admin system not configured',
                code: 'CONFIG_ERROR'
            });
        }
        
        await new Promise(resolve => setTimeout(resolve, 500));
        
        const isValidUsername = username === config.ADMIN_CREDENTIALS.username;
        const isValidPassword = password === config.ADMIN_CREDENTIALS.password;
        
        if (!isValidUsername || !isValidPassword) {
            const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
            attempt.count++;
            attempt.lastAttempt = Date.now();
            loginAttempts.set(ip, attempt);
            
            console.log(`❌ Failed admin login attempt from ${ip}: ${username}`);
            
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid username or password',
                code: 'INVALID_CREDENTIALS'
            });
        }
        
        loginAttempts.delete(ip);
        
        let sessionData;
        if (typeof createAdminSession === 'function') {
            sessionData = createAdminSession(username, ip, userAgent);
        } else {
            const sessionToken = crypto.randomBytes(32).toString('hex');
            sessionData = {
                token: sessionToken,
                sessionToken: sessionToken,
                expiresIn: config.SESSION?.EXPIRY || 86400000,
                createdAt: Date.now()
            };
        }
        
        console.log(`✅ Admin login successful: ${username} from ${ip}`);
        
        res.json({ 
            success: true,
            message: 'Login successful',
            sessionToken: sessionData.token || sessionData.sessionToken,
            expiresIn: sessionData.expiresIn || config.SESSION?.EXPIRY || 86400000,
            username,
            timestamp: Date.now()
        });
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Server error during login',
            code: 'SERVER_ERROR'
        });
    }
});

router.post('/logout', authAdmin, (req, res) => {
    try {
        const sessionToken = req.headers['x-session-token'];
        if (sessionToken && typeof invalidateAdminSession === 'function') {
            invalidateAdminSession(sessionToken);
        }
        console.log(`👋 Admin logout: ${req.adminUser} from ${req.ip}`);
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ success: false, error: 'Logout failed' });
    }
});

router.get('/verify-session', authAdmin, (req, res) => {
    res.json({
        success: true,
        session: { username: req.adminUser, role: req.adminRole || 'admin', ip: req.ip },
        server_info: { 
            uptime: Math.floor(process.uptime()),
            memory_usage: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB'
        }
    });
});

// ═══════════════════════════════════════════
// USERS MANAGEMENT - إدارة المستخدمين
// ═══════════════════════════════════════════
router.get('/users', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        
        const formattedUsers = {};
        let activeCount = 0, expiredCount = 0;
        const now = Date.now();
        
        for (const [id, user] of Object.entries(users)) {
            if (!user) continue;
            
            const isExpired = user.subscription_end && user.subscription_end < now;
            const isActive = user.is_active !== false && !isExpired;
            
            if (isActive) activeCount++;
            if (isExpired) expiredCount++;
            
            formattedUsers[id] = {
                id,
                username: user.username || '',
                is_active: isActive,
                expiry_timestamp: user.subscription_end || user.expiry_timestamp || 0,
                expiry_date: formatDate(user.subscription_end || user.expiry_timestamp),
                created_at: user.created_at || null,
                last_login: user.last_login || null,
                device_id: user.device_id || '',
                created_by_key: user.created_by_key || 'master',
                status: isActive ? 'active' : (isExpired ? 'expired' : 'inactive')
            };
        }
        
        res.json({ 
            success: true, 
            data: formattedUsers, 
            count: Object.keys(formattedUsers).length,
            stats: { active: activeCount, expired: expiredCount, inactive: Object.keys(formattedUsers).length - activeCount - expiredCount }
        });
    } catch (error) {
        console.error('Error fetching users:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch users: ' + error.message });
    }
});

// ═══════════════════════════════════════════
// 👁️ GET USER DETAILS - عرض تفاصيل المستخدم
// ═══════════════════════════════════════════
router.get('/users/:id', authAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const user = userRes.data;
        
        res.json({
            success: true,
            user: {
                id: userId,
                username: user.username,
                is_active: user.is_active,
                subscription_end: user.subscription_end,
                expiry_date: formatDate(user.subscription_end),
                device_id: user.device_id || '',
                max_devices: user.max_devices || 1,
                created_at: user.created_at,
                created_at_formatted: formatDate(user.created_at),
                last_login: user.last_login,
                last_login_formatted: user.last_login ? formatDate(user.last_login) : 'لم يسجل دخول',
                created_by_key: user.created_by_key || 'admin'
            }
        });
    } catch (error) {
        console.error('Error getting user:', error.message);
        res.status(500).json({ success: false, error: 'Failed to get user' });
    }
});

router.post('/users', authAdmin, async (req, res) => {
    try {
        const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password required' });
        }
        
        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ success: false, error: 'Username must be between 3-20 characters' });
        }
        
        if (password.length < 4) {
            return res.status(400).json({ success: false, error: 'Password must be at least 4 characters' });
        }
        
        try {
            const checkRes = await firebase.get(`users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`);
            if (checkRes.data && Object.keys(checkRes.data).length > 0) {
                return res.status(400).json({ success: false, error: 'Username already exists' });
            }
        } catch (e) { /* ignore */ }
        
        let expiryTimestamp;
        if (customExpiryDate) {
            expiryTimestamp = new Date(customExpiryDate).getTime();
        } else if (expiryMinutes) {
            expiryTimestamp = Date.now() + (expiryMinutes * 60 * 1000);
        } else {
            return res.status(400).json({ success: false, error: 'Expiry time required' });
        }
        
        if (expiryTimestamp <= Date.now()) {
            return res.status(400).json({ success: false, error: 'Expiry time must be in the future' });
        }
        
        const userData = {
            username,
            password_hash: hashPassword(password),
            is_active: status !== 'inactive',
            subscription_end: expiryTimestamp,
            expiry_timestamp: expiryTimestamp,
            max_devices: maxDevices || 1,
            device_id: '',
            created_at: Date.now(),
            created_by_key: 'admin_panel'
        };
        
        const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
        console.log(`✅ User created: ${username} (ID: ${createRes.data.name})`);
        
        res.json({ 
            success: true, 
            message: 'User created successfully',
            userId: createRes.data.name,
            username,
            expiry_date: formatDate(expiryTimestamp)
        });
        
    } catch (error) {
        console.error('Error creating user:', error.message);
        res.status(500).json({ success: false, error: 'Failed to create user: ' + error.message });
    }
});

router.delete('/users/:id', authAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        await firebase.delete(`users/${userId}.json?auth=${FB_KEY}`);
        console.log(`🗑️ User deleted: ${userId} (${userRes.data.username})`);
        
        res.json({ success: true, message: 'User deleted successfully', deletedUser: { id: userId, username: userRes.data.username } });
    } catch (error) {
        console.error('Error deleting user:', error.message);
        res.status(500).json({ success: false, error: 'Failed to delete user' });
    }
});

router.post('/users/:id/extend', authAdmin, async (req, res) => {
    try {
        const { minutes, days, hours } = req.body;
        const userId = req.params.id;
        
        if (!minutes && !days && !hours) {
            return res.status(400).json({ success: false, error: 'Extension time required' });
        }
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const user = userRes.data;
        const now = Date.now();
        const currentEnd = user.subscription_end || user.expiry_timestamp || now;
        
        let extensionMs = 0;
        if (minutes) extensionMs = minutes * 60 * 1000;
        if (days) extensionMs += days * 24 * 60 * 60 * 1000;
        if (hours) extensionMs += hours * 60 * 60 * 1000;
        
        const newEndDate = Math.max(currentEnd, now) + extensionMs;
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
            subscription_end: newEndDate,
            expiry_timestamp: newEndDate,
            is_active: true 
        });
        
        console.log(`📅 User extended: ${user.username} (ID: ${userId})`);
        
        res.json({ 
            success: true, 
            message: 'Subscription extended successfully',
            userId,
            username: user.username,
            old_end_date: formatDate(currentEnd),
            new_end_date: formatDate(newEndDate)
        });
    } catch (error) {
        console.error('Error extending user:', error.message);
        res.status(500).json({ success: false, error: 'Failed to extend subscription' });
    }
});

router.post('/users/:id/reset-device', authAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { device_id: '', last_device_reset: Date.now() });
        console.log(`🔄 Device reset for user: ${userId} (${userRes.data.username})`);
        
        res.json({ success: true, message: 'Device reset successfully', userId, username: userRes.data.username });
    } catch (error) {
        console.error('Error resetting device:', error.message);
        res.status(500).json({ success: false, error: 'Failed to reset device' });
    }
});

// ═══════════════════════════════════════════
// USER STATUS MANAGEMENT
// ═══════════════════════════════════════════
router.post('/disable-user', authAdmin, async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) return res.status(400).json({ success: false, error: 'User ID is required' });

        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) return res.status(404).json({ success: false, error: 'User not found' });

        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { is_active: false, disabled_at: Date.now() });
        console.log(`🚫 User disabled: ${userId} (${userRes.data.username})`);
        res.json({ success: true, message: 'User disabled successfully', userId, username: userRes.data.username });
    } catch (error) {
        console.error('Error disabling user:', error.message);
        res.status(500).json({ success: false, error: 'Failed to disable user' });
    }
});

router.post('/enable-user', authAdmin, async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) return res.status(400).json({ success: false, error: 'User ID is required' });

        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) return res.status(404).json({ success: false, error: 'User not found' });

        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { is_active: true, enabled_at: Date.now() });
        console.log(`✅ User enabled: ${userId} (${userRes.data.username})`);
        res.json({ success: true, message: 'User enabled successfully', userId, username: userRes.data.username });
    } catch (error) {
        console.error('Error enabling user:', error.message);
        res.status(500).json({ success: false, error: 'Failed to enable user' });
    }
});

// ═══════════════════════════════════════════
// API KEYS MANAGEMENT
// ═══════════════════════════════════════════
router.get('/api-keys', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
        const keys = response.data || {};
        
        const now = Date.now();
        const formattedKeys = {};
        
        for (const [id, key] of Object.entries(keys)) {
            if (!key) continue;
            
            const isExpired = key.expiry_timestamp && key.expiry_timestamp < now;
            const isActive = key.is_active !== false && !isExpired;
            
            formattedKeys[id] = {
                id,
                api_key: key.api_key || '',
                admin_name: key.admin_name || '',
                permission_level: key.permission_level || 'view_only',
                is_active: isActive,
                expiry_date: formatDate(key.expiry_timestamp),
                status: isActive ? 'active' : (isExpired ? 'expired' : 'inactive')
            };
        }
        
        res.json({ success: true, data: formattedKeys });
    } catch (error) {
        console.error('Error fetching API keys:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch API keys' });
    }
});

router.post('/api-keys', authAdmin, async (req, res) => {
    try {
        const { adminName, permissionLevel, expiryDays } = req.body;
        
        if (!adminName || adminName.trim().length < 2) {
            return res.status(400).json({ success: false, error: 'Admin name required' });
        }
        
        const apiKey = generateApiKey();
        const signingSecret = generateSigningSecret();
        const expiryTimestamp = Date.now() + ((expiryDays || 30) * 24 * 60 * 60 * 1000);
        
        const keyData = {
            api_key: apiKey,
            admin_name: adminName.trim(),
            permission_level: permissionLevel || 'view_only',
            is_active: true,
            expiry_timestamp: expiryTimestamp,
            created_at: Date.now(),
            signing_secret: signingSecret
        };
        
        const response = await firebase.post(`api_keys.json?auth=${FB_KEY}`, keyData);
        console.log(`🔑 API Key created for: ${adminName}`);
        
        res.json({ 
            success: true, 
            keyId: response.data.name,
            apiKey,
            signingSecret,
            adminName: adminName.trim(),
            expiry_date: formatDate(expiryTimestamp)
        });
    } catch (error) {
        console.error('Error creating API key:', error.message);
        res.status(500).json({ success: false, error: 'Failed to create API key' });
    }
});

// ═══════════════════════════════════════════
// 🗑️ DELETE API KEY - حذف مفتاح API
// ═══════════════════════════════════════════
router.delete('/api-keys/:id', authAdmin, async (req, res) => {
    try {
        const keyId = req.params.id;
        
        const keyRes = await firebase.get(`api_keys/${keyId}.json?auth=${FB_KEY}`);
        if (!keyRes.data) {
            return res.status(404).json({ success: false, error: 'API Key not found' });
        }
        
        await firebase.delete(`api_keys/${keyId}.json?auth=${FB_KEY}`);
        console.log(`🗑️ API Key deleted: ${keyId} (${keyRes.data.admin_name})`);
        
        res.json({ 
            success: true, 
            message: 'API Key deleted',
            deletedKey: { id: keyId, name: keyRes.data.admin_name }
        });
    } catch (error) {
        console.error('Error deleting API key:', error.message);
        res.status(500).json({ success: false, error: 'Failed to delete API key' });
    }
});

// ═══════════════════════════════════════════
// SERVER STATS
// ═══════════════════════════════════════════
router.get('/server-stats', authAdmin, (req, res) => {
    const memoryUsage = process.memoryUsage();
    res.json({ 
        success: true, 
        stats: {
            uptime: Math.floor(process.uptime()),
            memory: {
                heap_used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + ' MB',
                heap_total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + ' MB'
            },
            timestamp: Date.now(),
            node_version: process.version
        }
    });
});

router.get('/security-stats', authAdmin, (req, res) => {
    res.json({
        success: true,
        stats: {
            blocked_ips: blockedIPs.size,
            login_attempts: loginAttempts.size
        }
    });
});

module.exports = router;
