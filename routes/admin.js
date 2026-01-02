// routes/admin.js - نقاط النهاية للوحة الإدارة
const express = require('express');
const router = express.Router();
const config = require('../config');
const { firebase, FB_KEY } = require('../services/firebase');
const { authAdmin, adminSessions } = require('../middleware/auth');
const { bruteForceProtection, loginAttempts, blockedIPs, requestTracker } = require('../middleware/security');
const { generateToken, hashPassword, formatDate, generateApiKey, generateSigningSecret } = require('../helpers/utils');

// ═══════════════════════════════════════════
// AUTH - تسجيل الدخول/الخروج
// ═══════════════════════════════════════════
router.post('/login', bruteForceProtection, async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password required' });
        }
        
        await new Promise(resolve => setTimeout(resolve, 1000)); // Rate limiting delay
        
        if (username !== config.ADMIN_CREDENTIALS.username || password !== config.ADMIN_CREDENTIALS.password) {
            const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
            attempt.count++;
            attempt.lastAttempt = Date.now();
            loginAttempts.set(ip, attempt);
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
        
        loginAttempts.delete(ip);
        const sessionToken = generateToken();
        
        adminSessions.set(sessionToken, { 
            username, ip, createdAt: Date.now(), userAgent: req.headers['user-agent'] 
        });
        
        console.log(`✅ Admin login: ${username} from ${ip}`);
        res.json({ success: true, sessionToken, expiresIn: '24 hours' });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

router.post('/logout', authAdmin, (req, res) => {
    const sessionToken = req.headers['x-session-token'];
    if (sessionToken) adminSessions.delete(sessionToken);
    res.json({ success: true, message: 'Logged out' });
});

router.get('/verify-session', authAdmin, (req, res) => {
    const session = adminSessions.get(req.headers['x-session-token']);
    if (!session) return res.json({ success: true, session: { username: 'master_owner' } });
    
    const expiresIn = config.SESSION.EXPIRY - (Date.now() - session.createdAt);
    res.json({
        success: true,
        session: { username: session.username, expires_in: Math.floor(expiresIn / 1000 / 60) + ' minutes' },
        server_info: { active_sessions: adminSessions.size, uptime: Math.floor(process.uptime()) }
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
        for (const [id, user] of Object.entries(users)) {
            formattedUsers[id] = {
                username: user.username || '',
                is_active: user.is_active !== false,
                expiry_timestamp: user.subscription_end || 0,
                expiry_date: formatDate(user.subscription_end),
                created_at: user.created_at || null,
                last_login: user.last_login || null,
                device_id: user.device_id || '',
                created_by_key: user.created_by_key || 'master'
            };
        }
        
        res.json({ success: true, data: formattedUsers, count: Object.keys(formattedUsers).length });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch users' });
    }
});

router.post('/users', authAdmin, async (req, res) => {
    try {
        const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password required' });
        }
        
        // Check if exists
        const checkUrl = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const checkRes = await firebase.get(checkUrl);
        if (checkRes.data && Object.keys(checkRes.data).length > 0) {
            return res.status(400).json({ success: false, error: 'Username already exists' });
        }
        
        let expiryTimestamp;
        if (customExpiryDate) expiryTimestamp = new Date(customExpiryDate).getTime();
        else if (expiryMinutes) expiryTimestamp = Date.now() + (expiryMinutes * 60 * 1000);
        else return res.status(400).json({ success: false, error: 'Expiry time required' });
        
        const userData = {
            username,
            password_hash: hashPassword(password),
            is_active: status !== 'inactive',
            subscription_end: expiryTimestamp,
            max_devices: maxDevices || 1,
            device_id: '',
            created_at: Date.now(),
            created_by_key: 'master'
        };
        
        const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
        console.log(`✅ User created: ${username}`);
        res.json({ success: true, message: 'User created', userId: createRes.data.name });
        
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to create user' });
    }
});

router.delete('/users/:id', authAdmin, async (req, res) => {
    try {
        await firebase.delete(`users/${req.params.id}.json?auth=${FB_KEY}`);
        console.log(`🗑️ User deleted: ${req.params.id}`);
        res.json({ success: true, message: 'User deleted' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to delete user' });
    }
});

router.post('/users/:id/extend', authAdmin, async (req, res) => {
    try {
        const { minutes, days, hours } = req.body;
        const userRes = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);
        if (!userRes.data) return res.status(404).json({ success: false, error: 'User not found' });
        
        const user = userRes.data;
        const now = Date.now();
        const currentEnd = user.subscription_end || now;
        
        let extensionMs = 0;
        if (minutes) extensionMs = minutes * 60 * 1000;
        else if (days || hours) extensionMs = ((days || 0) * 24 * 60 * 60 * 1000) + ((hours || 0) * 60 * 60 * 1000);
        if (!extensionMs) return res.status(400).json({ success: false, error: 'Extension time required' });
        
        const newEndDate = (currentEnd > now ? currentEnd : now) + extensionMs;
        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, { subscription_end: newEndDate, is_active: true });
        
        res.json({ success: true, message: 'Extended', new_end_date: newEndDate });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to extend' });
    }
});

router.post('/users/:id/reset-device', authAdmin, async (req, res) => {
    try {
        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, { device_id: '' });
        res.json({ success: true, message: 'Device reset' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to reset device' });
    }
});

// ═══════════════════════════════════════════
// API KEYS MANAGEMENT
// ═══════════════════════════════════════════
router.get('/api-keys', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
        const keys = response.data || {};
        
        const formattedKeys = {};
        for (const [id, key] of Object.entries(keys)) {
            formattedKeys[id] = {
                api_key: key.api_key || '',
                admin_name: key.admin_name || '',
                permission_level: key.permission_level || 'view_only',
                is_active: key.is_active !== false,
                expiry_timestamp: key.expiry_timestamp || null,
                signing_secret: key.signing_secret ? '*****' : null
            };
        }
        res.json({ success: true, data: formattedKeys });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch API keys' });
    }
});

router.post('/api-keys', authAdmin, async (req, res) => {
    try {
        const { adminName, permissionLevel, expiryDays } = req.body;
        if (!adminName) return res.status(400).json({ success: false, error: 'Admin name required' });
        
        const apiKey = generateApiKey();
        const signingSecret = generateSigningSecret();
        
        const keyData = {
            api_key: apiKey,
            admin_name: adminName,
            permission_level: permissionLevel || 'view_only',
            is_active: true,
            expiry_timestamp: Date.now() + ((expiryDays || 30) * 24 * 60 * 60 * 1000),
            created_at: Date.now(),
            signing_secret: signingSecret
        };
        
        await firebase.post(`api_keys.json?auth=${FB_KEY}`, keyData);
        console.log(`🔑 API Key created for: ${adminName}`);
        
        res.json({ success: true, apiKey, signingSecret, warning: 'Save the signing secret immediately!' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to create API key' });
    }
});

// ═══════════════════════════════════════════
// SECURITY STATS
// ═══════════════════════════════════════════
router.get('/security-stats', authAdmin, (req, res) => {
    res.json({
        success: true,
        stats: {
            tracked_ips: requestTracker.size,
            blocked_ips: blockedIPs.size,
            blocked_list: Array.from(blockedIPs).slice(0, 20)
        }
    });
});

router.post('/unblock-ip', authAdmin, (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP required' });
    blockedIPs.delete(ip);
    requestTracker.delete(ip);
    res.json({ success: true, message: `IP ${ip} unblocked` });
});

module.exports = router;
