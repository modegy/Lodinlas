// routes/subadmin.js - Sub Admin Routes (Fixed)
'use strict';

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const config = require('../config');
const { firebase, FB_KEY } = require('../services/firebase');
const { hashPassword, formatDate, generateToken } = require('../helpers/utils');

// ═══════════════════════════════════════════
// ✅ Local Cache (بدلاً من استيراد من auth.js)
// ═══════════════════════════════════════════
const subAdminCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 دقائق

function getCachedKey(apiKey) {
    const cached = subAdminCache.get(apiKey);
    if (!cached) return null;
    if (Date.now() - cached.cachedAt > CACHE_TTL) {
        subAdminCache.delete(apiKey);
        return null;
    }
    return cached;
}

function setCachedKey(apiKey, data) {
    subAdminCache.set(apiKey, {
        ...data,
        cachedAt: Date.now()
    });
}

function clearCachedKey(apiKey) {
    subAdminCache.delete(apiKey);
}

// ═══════════════════════════════════════════
// 🔐 VERIFY KEY - تسجيل الدخول
// ═══════════════════════════════════════════
router.post('/verify-key', async (req, res) => {
    try {
        const { apiKey, deviceFingerprint } = req.body;
        const headerKey = req.headers['x-api-key'];
        const key = apiKey || headerKey;
        
        if (!key) {
            return res.status(400).json({
                success: false,
                error: 'API key required'
            });
        }
        
        console.log(`🔍 Verifying sub-admin key: ${key.substring(0, 10)}...`);
        
        // البحث في Firebase
        const response = await firebase.get(
            `api_keys.json?orderBy="api_key"&equalTo="${encodeURIComponent(key)}"&auth=${FB_KEY}`
        );
        
        const keys = response.data || {};
        
        if (Object.keys(keys).length === 0) {
            console.log('❌ API key not found');
            return res.status(401).json({
                success: false,
                error: 'Invalid API key'
            });
        }
        
        const keyId = Object.keys(keys)[0];
        const keyData = keys[keyId];
        
        // التحقق من الصلاحية
        if (!keyData.is_active) {
            return res.status(403).json({
                success: false,
                error: 'API key is inactive'
            });
        }
        
        // التحقق من انتهاء الصلاحية
        if (keyData.expiry_timestamp && Date.now() > keyData.expiry_timestamp) {
            return res.status(403).json({
                success: false,
                error: 'API key expired'
            });
        }
        
        // حفظ في الـ cache
        const cacheData = {
            keyId,
            ...keyData,
            deviceFingerprint
        };
        setCachedKey(key, cacheData);
        
        // توليد signing secret إذا لم يكن موجوداً
        let signingSecret = keyData.signing_secret;
        if (!signingSecret) {
            signingSecret = crypto.createHmac('sha256', config.SIGNING_SALT || 'default-salt')
                .update(key)
                .digest('hex');
        }
        
        console.log(`✅ Sub-admin verified: ${keyData.admin_name}`);
        
        res.json({
            success: true,
            name: keyData.admin_name,
            permission: keyData.permission_level || 'view_only',
            signing_secret: signingSecret,
            expires_at: keyData.expiry_timestamp
        });
        
    } catch (error) {
        console.error('❌ Verify key error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Verification failed: ' + error.message
        });
    }
});

// ═══════════════════════════════════════════
// 🚪 LOGOUT
// ═══════════════════════════════════════════
router.post('/logout', (req, res) => {
    const apiKey = req.headers['x-api-key'] || req.body.apiKey;
    if (apiKey) {
        clearCachedKey(apiKey);
        console.log(`👋 Sub-admin logged out`);
    }
    res.json({ success: true, message: 'Logged out' });
});

// ═══════════════════════════════════════════
// 📊 STATS
// ═══════════════════════════════════════════
router.get('/stats', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const cached = getCachedKey(apiKey);
        
        if (!cached) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        
        const now = Date.now();
        let total = 0, active = 0, expired = 0;
        
        for (const [id, user] of Object.entries(users)) {
            if (!user || user.created_by_key !== cached.keyId) continue;
            total++;
            
            const isExpired = user.subscription_end && user.subscription_end < now;
            if (isExpired) expired++;
            else if (user.is_active !== false) active++;
        }
        
        res.json({
            success: true,
            stats: {
                totalUsers: total,
                activeUsers: active,
                expiredUsers: expired
            }
        });
        
    } catch (error) {
        console.error('Stats error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ═══════════════════════════════════════════
// 👥 GET USERS (المستخدمين التابعين للـ Sub Admin)
// ═══════════════════════════════════════════
router.get('/users', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const cached = getCachedKey(apiKey);
        
        if (!cached) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        
        const now = Date.now();
        const myUsers = {};
        
        for (const [id, user] of Object.entries(users)) {
            if (!user || user.created_by_key !== cached.keyId) continue;
            
            const isExpired = user.subscription_end && user.subscription_end < now;
            
            myUsers[id] = {
                id,
                username: user.username,
                is_active: user.is_active !== false && !isExpired,
                expiry_timestamp: user.subscription_end || user.expiry_timestamp,
                expiry_date: formatDate(user.subscription_end || user.expiry_timestamp),
                device_id: user.device_id || '',
                last_login: user.last_login,
                created_at: user.created_at
            };
        }
        
        res.json({ success: true, data: myUsers });
        
    } catch (error) {
        console.error('Get users error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ═══════════════════════════════════════════
// ➕ ADD USER
// ═══════════════════════════════════════════
router.post('/users', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const cached = getCachedKey(apiKey);
        
        if (!cached) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        
        // التحقق من الصلاحيات
        const permission = cached.permission_level || 'view_only';
        if (permission !== 'full' && permission !== 'add_only') {
            return res.status(403).json({ success: false, error: 'No permission to add users' });
        }
        
        const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password required' });
        }
        
        // التحقق من عدم وجود المستخدم
        const checkRes = await firebase.get(`users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`);
        if (checkRes.data && Object.keys(checkRes.data).length > 0) {
            return res.status(400).json({ success: false, error: 'Username already exists' });
        }
        
        // حساب وقت الانتهاء
        let expiryTimestamp;
        if (customExpiryDate) {
            expiryTimestamp = new Date(customExpiryDate).getTime();
        } else if (expiryMinutes) {
            expiryTimestamp = Date.now() + (expiryMinutes * 60 * 1000);
        } else {
            return res.status(400).json({ success: false, error: 'Expiry time required' });
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
            created_by_key: cached.keyId
        };
        
        const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
        
        console.log(`✅ User created by sub-admin: ${username}`);
        
        res.json({
            success: true,
            message: 'User created',
            userId: createRes.data.name,
            username,
            expiry_date: formatDate(expiryTimestamp)
        });
        
    } catch (error) {
        console.error('Add user error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ═══════════════════════════════════════════
// 👁️ USER DETAILS
// ═══════════════════════════════════════════
router.get('/users/:id/details', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const cached = getCachedKey(apiKey);
        
        if (!cached) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        
        const userId = req.params.id;
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const user = userRes.data;
        
        // التحقق من الملكية
        if (user.created_by_key !== cached.keyId) {
            return res.status(403).json({ success: false, error: 'Not your user' });
        }
        
        res.json({
            success: true,
            user: {
                id: userId,
                username: user.username,
                is_active: user.is_active,
                subscription_end: user.subscription_end,
                device_id: user.device_id,
                max_devices: user.max_devices,
                created_at: user.created_at,
                last_login: user.last_login
            }
        });
        
    } catch (error) {
        console.error('User details error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ═══════════════════════════════════════════
// ⏰ EXTEND USER
// ═══════════════════════════════════════════
router.post('/users/:id/extend', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const cached = getCachedKey(apiKey);
        
        if (!cached) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        
        const permission = cached.permission_level || 'view_only';
        if (permission !== 'full' && permission !== 'extend_only') {
            return res.status(403).json({ success: false, error: 'No permission to extend' });
        }
        
        const userId = req.params.id;
        const { minutes } = req.body;
        
        if (!minutes) {
            return res.status(400).json({ success: false, error: 'Minutes required' });
        }
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const user = userRes.data;
        
        if (user.created_by_key !== cached.keyId) {
            return res.status(403).json({ success: false, error: 'Not your user' });
        }
        
        const now = Date.now();
        const currentEnd = user.subscription_end || now;
        const newEnd = Math.max(currentEnd, now) + (minutes * 60 * 1000);
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, {
            subscription_end: newEnd,
            expiry_timestamp: newEnd,
            is_active: true
        });
        
        res.json({
            success: true,
            message: 'Extended',
            new_expiry: formatDate(newEnd)
        });
        
    } catch (error) {
        console.error('Extend error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ═══════════════════════════════════════════
// 🔄 RESET DEVICE
// ═══════════════════════════════════════════
router.post('/users/:id/reset-device', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const cached = getCachedKey(apiKey);
        
        if (!cached) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        
        const permission = cached.permission_level || 'view_only';
        if (permission !== 'full' && permission !== 'add_only') {
            return res.status(403).json({ success: false, error: 'No permission' });
        }
        
        const userId = req.params.id;
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        if (userRes.data.created_by_key !== cached.keyId) {
            return res.status(403).json({ success: false, error: 'Not your user' });
        }
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { device_id: '' });
        
        res.json({ success: true, message: 'Device reset' });
        
    } catch (error) {
        console.error('Reset device error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ═══════════════════════════════════════════
// ✏️ UPDATE USER STATUS
// ═══════════════════════════════════════════
router.patch('/users/:id', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const cached = getCachedKey(apiKey);
        
        if (!cached) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        
        const permission = cached.permission_level || 'view_only';
        if (permission !== 'full') {
            return res.status(403).json({ success: false, error: 'No permission' });
        }
        
        const userId = req.params.id;
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        if (userRes.data.created_by_key !== cached.keyId) {
            return res.status(403).json({ success: false, error: 'Not your user' });
        }
        
        const updates = {};
        if (req.body.is_active !== undefined) updates.is_active = req.body.is_active;
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, updates);
        
        res.json({ success: true, message: 'Updated' });
        
    } catch (error) {
        console.error('Update error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ═══════════════════════════════════════════
// 🗑️ DELETE USER
// ═══════════════════════════════════════════
router.delete('/users/:id', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const cached = getCachedKey(apiKey);
        
        if (!cached) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        
        const permission = cached.permission_level || 'view_only';
        if (permission !== 'full') {
            return res.status(403).json({ success: false, error: 'No permission to delete' });
        }
        
        const userId = req.params.id;
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        if (userRes.data.created_by_key !== cached.keyId) {
            return res.status(403).json({ success: false, error: 'Not your user' });
        }
        
        await firebase.delete(`users/${userId}.json?auth=${FB_KEY}`);
        
        res.json({ success: true, message: 'Deleted' });
        
    } catch (error) {
        console.error('Delete error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
