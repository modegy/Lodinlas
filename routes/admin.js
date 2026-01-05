// routes/admin.js - مُصحح بالكامل مع كل الميزات
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const config = require('../config');
const { firebase, FB_KEY } = require('../services/firebase');
const { authAdmin, createAdminSession, invalidateAdminSession } = require('../middleware/auth');
const { generateToken, hashPassword, formatDate, generateApiKey, generateSigningSecret } = require('../helpers/utils');

// ═══════════════════════════════════════════
// ✅ FALLBACK
// ═══════════════════════════════════════════
let loginAttempts = new Map();
let blockedIPs = new Set();

try {
    const security = require('../middleware/security');
    const inst = security.getInstance();
    if (inst?.blockedIPs) blockedIPs = inst.blockedIPs;
} catch (e) {}

// ═══════════════════════════════════════════
// 🔐 AUTH
// ═══════════════════════════════════════════
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.clientIP || req.ip || '127.0.0.1';
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password required' });
        }
        
        if (!config.ADMIN_CREDENTIALS?.username || !config.ADMIN_CREDENTIALS?.password) {
            return res.status(500).json({ success: false, error: 'Admin not configured' });
        }
        
        await new Promise(r => setTimeout(r, 500));
        
        if (username !== config.ADMIN_CREDENTIALS.username || password !== config.ADMIN_CREDENTIALS.password) {
            console.log(`❌ Failed login from ${ip}: ${username}`);
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
        
        let sessionData;
        if (typeof createAdminSession === 'function') {
            sessionData = createAdminSession(username, ip, userAgent);
        } else {
            sessionData = { token: crypto.randomBytes(32).toString('hex'), expiresIn: 86400000 };
        }
        
        console.log(`✅ Admin login successful: ${username} from ${ip}`);
        
        res.json({ 
            success: true,
            sessionToken: sessionData.token || sessionData.sessionToken,
            expiresIn: sessionData.expiresIn || 86400000,
            username
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

router.post('/logout', authAdmin, (req, res) => {
    const token = req.headers['x-session-token'];
    if (token && typeof invalidateAdminSession === 'function') {
        invalidateAdminSession(token);
    }
    console.log(`👋 Admin logout: ${req.adminUser}`);
    res.json({ success: true, message: 'Logged out' });
});

router.get('/verify-session', authAdmin, (req, res) => {
    res.json({
        success: true,
        session: { username: req.adminUser, role: 'admin' },
        server_info: { uptime: Math.floor(process.uptime()) }
    });
});

// ═══════════════════════════════════════════
// 👥 USERS MANAGEMENT
// ═══════════════════════════════════════════
router.get('/users', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        
        const formattedUsers = {};
        let activeCount = 0, expiredCount = 0, inactiveCount = 0;
        const now = Date.now();
        
        for (const [id, user] of Object.entries(users)) {
            if (!user) continue;
            
            const expiry = user.subscription_end || user.expiry_timestamp || 0;
            const isExpired = expiry && expiry < now;
            const isActive = user.is_active !== false && !isExpired;
            
            if (isExpired) expiredCount++;
            else if (!user.is_active) inactiveCount++;
            else activeCount++;
            
            formattedUsers[id] = {
                id,
                username: user.username || '',
                is_active: isActive,
                expiry_timestamp: expiry,
                expiry_date: formatDate(expiry),
                created_at: user.created_at || null,
                device_id: user.device_id || '',
                status: isActive ? 'active' : (isExpired ? 'expired' : 'inactive')
            };
        }
        
        res.json({ 
            success: true, 
            data: formattedUsers, 
            count: Object.keys(formattedUsers).length,
            stats: { active: activeCount, expired: expiredCount, inactive: inactiveCount }
        });
    } catch (error) {
        console.error('Error fetching users:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch users' });
    }
});

router.get('/users/:id', authAdmin, async (req, res) => {
    try {
        const userRes = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const user = userRes.data;
        res.json({
            success: true,
            user: {
                id: req.params.id,
                username: user.username,
                is_active: user.is_active,
                expiry_date: formatDate(user.subscription_end),
                device_id: user.device_id || '',
                max_devices: user.max_devices || 1,
                created_at_formatted: formatDate(user.created_at),
                last_login_formatted: user.last_login ? formatDate(user.last_login) : 'لم يسجل دخول',
                created_by_key: user.created_by_key || 'admin'
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to get user' });
    }
});

router.post('/users', authAdmin, async (req, res) => {
    try {
        const { username, password, expiryMinutes, maxDevices, status } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password required' });
        }
        
        if (username.length < 3 || password.length < 4) {
            return res.status(400).json({ success: false, error: 'Username min 3, password min 4 chars' });
        }
        
        // Check duplicate
        const checkRes = await firebase.get(`users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`);
        if (checkRes.data && Object.keys(checkRes.data).length > 0) {
            return res.status(400).json({ success: false, error: 'Username exists' });
        }
        
        const expiryTimestamp = Date.now() + ((expiryMinutes || 43200) * 60 * 1000);
        
        const userData = {
            username,
            password_hash: hashPassword(password),
            is_active: status !== 'inactive',
            subscription_end: expiryTimestamp,
            max_devices: maxDevices || 1,
            device_id: '',
            created_at: Date.now(),
            created_by_key: 'admin_panel'
        };
        
        const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
        console.log(`✅ User created: ${username}`);
        
        res.json({ success: true, userId: createRes.data.name, username, expiry_date: formatDate(expiryTimestamp) });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to create user' });
    }
});

router.delete('/users/:id', authAdmin, async (req, res) => {
    try {
        const userRes = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
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
        
        const now = Date.now();
        const currentEnd = userRes.data.subscription_end || now;
        
        let extensionMs = 0;
        if (minutes) extensionMs += minutes * 60 * 1000;
        if (hours) extensionMs += hours * 60 * 60 * 1000;
        if (days) extensionMs += days * 24 * 60 * 60 * 1000;
        
        const newEnd = Math.max(currentEnd, now) + extensionMs;
        
        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, { 
            subscription_end: newEnd, 
            is_active: true 
        });
        
        res.json({ success: true, new_end_date: formatDate(newEnd) });
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

router.post('/disable-user', authAdmin, async (req, res) => {
    try {
        const { userId } = req.body;
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { is_active: false });
        res.json({ success: true, message: 'User disabled' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to disable user' });
    }
});

router.post('/enable-user', authAdmin, async (req, res) => {
    try {
        const { userId } = req.body;
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { is_active: true });
        res.json({ success: true, message: 'User enabled' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to enable user' });
    }
});

// ═══════════════════════════════════════════
// 🗑️ BULK DELETE OPERATIONS
// ═══════════════════════════════════════════
router.delete('/delete-expired', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        const now = Date.now();
        let count = 0;
        
        const deletePromises = [];
        
        for (const [id, user] of Object.entries(users)) {
            if (!user) continue;
            const expiry = user.subscription_end || user.expiry_timestamp || 0;
            if (expiry && expiry < now) {
                deletePromises.push(firebase.delete(`users/${id}.json?auth=${FB_KEY}`));
                count++;
            }
        }
        
        await Promise.all(deletePromises);
        console.log(`🗑️ Deleted ${count} expired users`);
        
        res.json({ success: true, message: `Deleted ${count} expired users`, count });
    } catch (error) {
        console.error('Error deleting expired:', error.message);
        res.status(500).json({ success: false, error: 'Failed to delete expired users' });
    }
});

router.delete('/delete-inactive', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        let count = 0;
        
        const deletePromises = [];
        
        for (const [id, user] of Object.entries(users)) {
            if (!user) continue;
            if (user.is_active === false) {
                deletePromises.push(firebase.delete(`users/${id}.json?auth=${FB_KEY}`));
                count++;
            }
        }
        
        await Promise.all(deletePromises);
        console.log(`🗑️ Deleted ${count} inactive users`);
        
        res.json({ success: true, message: `Deleted ${count} inactive users`, count });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to delete inactive users' });
    }
});

router.post('/bulk-disable-expired', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        const now = Date.now();
        let count = 0;
        
        const updatePromises = [];
        
        for (const [id, user] of Object.entries(users)) {
            if (!user) continue;
            const expiry = user.subscription_end || user.expiry_timestamp || 0;
            if (expiry && expiry < now && user.is_active !== false) {
                updatePromises.push(firebase.patch(`users/${id}.json?auth=${FB_KEY}`, { is_active: false }));
                count++;
            }
        }
        
        await Promise.all(updatePromises);
        res.json({ success: true, count });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to disable expired' });
    }
});

// ═══════════════════════════════════════════
// 🔑 API KEYS MANAGEMENT
// ═══════════════════════════════════════════
router.get('/api-keys', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
        const keys = response.data || {};
        
        const now = Date.now();
        const formattedKeys = {};
        
        for (const [id, key] of Object.entries(keys)) {
            if (!key) continue;
            
            const expiry = key.expiry_timestamp || 0;
            const isExpired = expiry && expiry < now;
            const isActive = key.is_active !== false && !isExpired;
            
            formattedKeys[id] = {
                id,
                api_key: key.api_key || '',
                admin_name: key.admin_name || 'بدون اسم',
                permission_level: key.permission_level || 'view_only',
                is_active: isActive,
                expiry_timestamp: expiry,
                expiry_date: expiry ? formatDate(expiry) : 'غير محدود',
                created_at: key.created_at,
                created_at_formatted: formatDate(key.created_at),
                status: isActive ? 'active' : (isExpired ? 'expired' : 'inactive'),
                // إحصائيات
                users_created: key.users_created || 0,
                last_used: key.last_used ? formatDate(key.last_used) : 'لم يُستخدم'
            };
        }
        
        res.json({ success: true, data: formattedKeys, count: Object.keys(formattedKeys).length });
    } catch (error) {
        console.error('Error fetching API keys:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch API keys' });
    }
});

router.post('/api-keys', authAdmin, async (req, res) => {
    try {
        const { adminName, permissionLevel, expiryDays } = req.body;
        
        if (!adminName || adminName.trim().length < 2) {
            return res.status(400).json({ success: false, error: 'Admin name required (min 2 chars)' });
        }
        
        const apiKey = generateApiKey();
        const signingSecret = generateSigningSecret();
        
        // إذا كان expiryDays = 0 أو undefined = غير محدود
        const expiryTimestamp = expiryDays && expiryDays > 0 
            ? Date.now() + (expiryDays * 24 * 60 * 60 * 1000) 
            : null;
        
        const keyData = {
            api_key: apiKey,
            admin_name: adminName.trim(),
            permission_level: permissionLevel || 'view_only',
            is_active: true,
            expiry_timestamp: expiryTimestamp,
            created_at: Date.now(),
            signing_secret: signingSecret,
            users_created: 0
        };
        
        const response = await firebase.post(`api_keys.json?auth=${FB_KEY}`, keyData);
        console.log(`🔑 API Key created for: ${adminName}`);
        
        res.json({ 
            success: true, 
            keyId: response.data.name,
            apiKey,
            signingSecret,
            adminName: adminName.trim(),
            expiry_date: expiryTimestamp ? formatDate(expiryTimestamp) : 'غير محدود'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to create API key' });
    }
});

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

// تعطيل/تفعيل مفتاح API
router.post('/api-keys/:id/toggle', authAdmin, async (req, res) => {
    try {
        const keyRes = await firebase.get(`api_keys/${req.params.id}.json?auth=${FB_KEY}`);
        if (!keyRes.data) {
            return res.status(404).json({ success: false, error: 'API Key not found' });
        }
        
        const newStatus = !keyRes.data.is_active;
        await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, { is_active: newStatus });
        
        res.json({ success: true, is_active: newStatus });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to toggle API key' });
    }
});

// ═══════════════════════════════════════════
// 📊 STATS
// ═══════════════════════════════════════════
router.get('/server-stats', authAdmin, (req, res) => {
    const mem = process.memoryUsage();
    res.json({ 
        success: true, 
        stats: {
            uptime: Math.floor(process.uptime()),
            memory: {
                heap_used: Math.round(mem.heapUsed / 1024 / 1024) + ' MB',
                heap_total: Math.round(mem.heapTotal / 1024 / 1024) + ' MB'
            },
            node_version: process.version
        }
    });
});

router.get('/security-stats', authAdmin, (req, res) => {
    res.json({
        success: true,
        stats: { blocked_ips: blockedIPs.size, login_attempts: loginAttempts.size }
    });
});

module.exports = router;
