// routes/subadmin.js - نقاط النهاية للمشرفين الفرعيين
const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { firebase, FB_KEY } = require('../services/firebase');
const { verifySignature, subAdminKeys } = require('../middleware/signature');
const { authSubAdmin, checkSubAdminPermission } = require('../middleware/auth');
const { hashPassword, formatDate } = require('../helpers/utils');

// ═══════════════════════════════════════════
// VERIFY KEY - التحقق من مفتاح API
// ═══════════════════════════════════════════
router.post('/verify-key', verifySignature, async (req, res) => {
    try {
        const { apiKey, deviceFingerprint } = req.body;
        
        if (!apiKey) {
            return res.status(400).json({ success: false, error: 'API key required' });
        }
        
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
        
        if (!foundKey) return res.status(401).json({ success: false, error: 'Invalid API key' });
        if (!foundKey.is_active) return res.status(403).json({ success: false, error: 'Key is inactive' });
        if (foundKey.expiry_timestamp && Date.now() > foundKey.expiry_timestamp) {
            return res.status(403).json({ success: false, error: 'Key expired' });
        }
        
        // Generate signing_secret if not exists
        if (!foundKey.signing_secret) {
            const newSigningSecret = `SS_${crypto.randomBytes(32).toString('hex')}`;
            await firebase.patch(`api_keys/${keyId}.json?auth=${FB_KEY}`, {
                signing_secret: newSigningSecret,
                last_secret_update: Date.now()
            });
            foundKey.signing_secret = newSigningSecret;
        }
        
        // Bind device
        if (!foundKey.bound_device) {
            await firebase.patch(`api_keys/${keyId}.json?auth=${FB_KEY}`, { bound_device: deviceFingerprint });
        } else if (foundKey.bound_device !== deviceFingerprint) {
            return res.status(403).json({ success: false, error: 'Key is bound to another device' });
        }
        
        // Update usage
        await firebase.patch(`api_keys/${keyId}.json?auth=${FB_KEY}`, {
            usage_count: (foundKey.usage_count || 0) + 1,
            last_used: Date.now()
        });
        
        // Cache
        subAdminKeys.set(apiKey, { ...foundKey, keyId, device: deviceFingerprint, last_used: Date.now() });
        
        console.log(`✅ Sub Admin verified: ${foundKey.admin_name}`);
        
        res.json({
            success: true,
            name: foundKey.admin_name,
            permission: foundKey.permission_level || 'view_only',
            key_id: keyId,
            signing_secret: foundKey.signing_secret
        });
        
    } catch (error) {
        console.error('Verify key error:', error.message);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// ═══════════════════════════════════════════
// GET USERS - جلب المستخدمين (الخاصين بهذا المشرف)
// ═══════════════════════════════════════════
router.get('/users', verifySignature, authSubAdmin, checkSubAdminPermission('view'), async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        const currentKeyId = req.subAdminKeyId;
        
        const formattedUsers = {};
        for (const [id, user] of Object.entries(users)) {
            if (user.created_by_key === currentKeyId) {
                formattedUsers[id] = {
                    username: user.username || '',
                    is_active: user.is_active !== false,
                    expiry_timestamp: user.subscription_end || 0,
                    expiry_date: formatDate(user.subscription_end),
                    device_id: user.device_id || '',
                    last_login: user.last_login || 0,
                    created_at: user.created_at || 0
                };
            }
        }
        
        res.json({ success: true, data: formattedUsers, count: Object.keys(formattedUsers).length });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch users' });
    }
});

// ═══════════════════════════════════════════
// CREATE USER - إنشاء مستخدم جديد
// ═══════════════════════════════════════════
router.post('/users', verifySignature, authSubAdmin, checkSubAdminPermission('add'), async (req, res) => {
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
            created_by_key: req.subAdminKeyId,
            created_by: req.subAdminKey.admin_name || 'sub_admin'
        };
        
        const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
        console.log(`✅ User created by Sub Admin: ${username}`);
        
        res.json({ 
            success: true, 
            message: 'User created', 
            userId: createRes.data.name,
            expiry_date: formatDate(expiryTimestamp)
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to create user' });
    }
});

// ═══════════════════════════════════════════
// EXTEND USER - تمديد اشتراك
// ═══════════════════════════════════════════
router.post('/users/:id/extend', verifySignature, authSubAdmin, checkSubAdminPermission('extend'), async (req, res) => {
    try {
        const userId = req.params.id;
        const currentKeyId = req.subAdminKeyId;
        const { minutes, days, hours } = req.body;
        
        if (!minutes && !days && !hours) {
            return res.status(400).json({ success: false, error: 'Extension time required' });
        }
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) return res.status(404).json({ success: false, error: 'User not found' });
        
        const user = userRes.data;
        
        // Ownership check
        if (user.created_by_key !== currentKeyId) {
            return res.status(403).json({ success: false, error: 'You can only extend users you created' });
        }
        
        const now = Date.now();
        const currentEnd = user.subscription_end || now;
        
        let extensionMs = 0;
        if (minutes) extensionMs = minutes * 60 * 1000;
        else if (days || hours) extensionMs = ((days || 0) * 24 * 60 * 60 * 1000) + ((hours || 0) * 60 * 60 * 1000);
        
        const newEndDate = (currentEnd > now ? currentEnd : now) + extensionMs;
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, {
            subscription_end: newEndDate,
            is_active: true
        });
        
        res.json({ 
            success: true, 
            message: 'Subscription extended', 
            new_end_date: newEndDate,
            formatted_date: formatDate(newEndDate)
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to extend subscription' });
    }
});

// ═══════════════════════════════════════════
// DELETE USER - حذف مستخدم
// ═══════════════════════════════════════════
router.delete('/users/:id', verifySignature, authSubAdmin, checkSubAdminPermission('delete'), async (req, res) => {
    try {
        const userId = req.params.id;
        const currentKeyId = req.subAdminKeyId;
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) return res.status(404).json({ success: false, error: 'User not found' });
        
        const user = userRes.data;
        
        if (user.created_by_key !== currentKeyId) {
            return res.status(403).json({ success: false, error: 'You can only delete users you created' });
        }
        
        await firebase.delete(`users/${userId}.json?auth=${FB_KEY}`);
        console.log(`🗑️ User deleted by Sub Admin: ${user.username}`);
        
        res.json({ success: true, message: 'User deleted' });
        
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to delete user' });
    }
});

// ═══════════════════════════════════════════
// RESET DEVICE - إعادة تعيين الجهاز
// ═══════════════════════════════════════════
router.post('/users/:id/reset-device', verifySignature, authSubAdmin, checkSubAdminPermission('edit'), async (req, res) => {
    try {
        const userId = req.params.id;
        const currentKeyId = req.subAdminKeyId;
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) return res.status(404).json({ success: false, error: 'User not found' });
        
        if (userRes.data.created_by_key !== currentKeyId) {
            return res.status(403).json({ success: false, error: 'Permission denied' });
        }
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { device_id: '' });
        res.json({ success: true, message: 'Device reset' });
        
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to reset device' });
    }
});

// ═══════════════════════════════════════════
// STATS - إحصائيات
// ═══════════════════════════════════════════
router.get('/stats', verifySignature, authSubAdmin, checkSubAdminPermission('view'), async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        const currentKeyId = req.subAdminKeyId;
        const now = Date.now();
        
        let totalUsers = 0, activeUsers = 0, expiredUsers = 0;
        
        for (const user of Object.values(users)) {
            if (user.created_by_key === currentKeyId) {
                totalUsers++;
                if (user.is_active !== false) activeUsers++;
                if (user.subscription_end && user.subscription_end <= now) expiredUsers++;
            }
        }
        
        res.json({ success: true, stats: { totalUsers, activeUsers, expiredUsers } });
        
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to get stats' });
    }
});

module.exports = router;
