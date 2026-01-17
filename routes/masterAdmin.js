// routes/masterAdmin.js - Master Admin Routes v14.2 Complete
'use strict';

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const { firebase, FB_KEY } = require('../config/database');
const { ADMIN_CREDENTIALS, adminSessions } = require('../config/constants');
const { authAdmin } = require('../middleware/auth');
const { getInstance: getSecurityInstance } = require('../middleware/security');
const { generateToken, hashPassword, formatDate, getClientIP } = require('../utils/helpers');

// ═══════════════════════════════════════════════════════════════════
// 🔐 LOGIN
// ═══════════════════════════════════════════════════════════════════
router.post('/login', async (req, res) => {
    const security = getSecurityInstance();
    
    try {
        const { username, password } = req.body;
        const ip = req.clientIP || getClientIP(req);

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'اسم المستخدم وكلمة المرور مطلوبان'
            });
        }

        await new Promise(resolve => setTimeout(resolve, 1000));

        const ADMIN_USERNAME = process.env.ADMIN_USERNAME || ADMIN_CREDENTIALS.username || 'admin';
        const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || ADMIN_CREDENTIALS.password || 'admin123';

        console.log('🔐 Login attempt:', username, 'from IP:', ip);

        if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
            if (security) security.recordLoginAttempt(ip, false);
            console.log('❌ Login failed: Invalid credentials');
            return res.status(401).json({
                success: false,
                error: 'اسم المستخدم أو كلمة المرور غير صحيحة'
            });
        }

        if (security) security.recordLoginAttempt(ip, true);

        const sessionToken = generateToken();

        adminSessions.set(sessionToken, {
            username,
            ip,
            createdAt: Date.now(),
            userAgent: req.headers['user-agent']
        });

        console.log(`✅ Admin login successful: ${username} from ${ip}`);
        console.log(`📝 Session created: ${sessionToken.substring(0, 20)}... | Total sessions: ${adminSessions.size}`);

        return res.json({
            success: true,
            sessionToken,
            username,
            message: 'تم تسجيل الدخول بنجاح',
            expiresIn: '24 hours'
        });

    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ success: false, error: 'خطأ في تسجيل الدخول' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 🚪 LOGOUT
// ═══════════════════════════════════════════════════════════════════
router.post('/logout', authAdmin, (req, res) => {
    const sessionToken = req.headers['x-session-token'];
    if (sessionToken) {
        adminSessions.delete(sessionToken);
        console.log('👋 Admin logged out');
    }
    res.json({ success: true, message: 'تم تسجيل الخروج بنجاح' });
});

// ═══════════════════════════════════════════════════════════════════
// ✅ VERIFY SESSION
// ═══════════════════════════════════════════════════════════════════
router.get('/verify-session', authAdmin, (req, res) => {
    const sessionToken = req.headers['x-session-token'];
    const session = adminSessions.get(sessionToken);

    res.json({
        success: true,
        session: {
            username: session?.username || req.adminUser,
            expires_in: session ? Math.floor((24 * 60 * 60 * 1000 - (Date.now() - session.createdAt)) / 1000 / 60) + ' دقيقة' : 'N/A'
        }
    });
});

// ═══════════════════════════════════════════════════════════════════
// 👥 GET ALL USERS
// ═══════════════════════════════════════════════════════════════════
router.get('/users', authAdmin, async (req, res) => {
    try {
        console.log('📥 Fetching users...');
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};

        const formattedUsers = {};
        for (const [id, user] of Object.entries(users)) {
            const subEnd = user.subscription_end || 0;
            formattedUsers[id] = {
                username: user.username || '',
                is_active: user.is_active !== false,
                expiry_timestamp: subEnd,
                expiry_date: formatDate(subEnd),
                created_at: user.created_at || null,
                last_login: user.last_login || null,
                device_id: user.device_id || '',
                device_info: user.device_model ? `${user.device_brand || ''} ${user.device_model}` : '',
                device_type: user.device_type || '',
                ip_address: user.ip_address || '',
                login_count: user.login_count || 0,
                max_devices: user.max_devices || 1,
                created_by_key: user.created_by_key || 'master'
            };
        }

        console.log(`✅ Loaded ${Object.keys(formattedUsers).length} users`);
        res.json({ success: true, data: formattedUsers, count: Object.keys(formattedUsers).length });

    } catch (error) {
        console.error('Get users error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في جلب المستخدمين' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// ➕ CREATE USER
// ═══════════════════════════════════════════════════════════════════
router.post('/users', authAdmin, async (req, res) => {
    try {
        const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;

        console.log('📝 Creating user:', { username, expiryMinutes, maxDevices, status });

        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'اسم المستخدم وكلمة المرور مطلوبان' });
        }

        // Check duplicate
        const checkUrl = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const checkRes = await firebase.get(checkUrl);

        if (checkRes.data && Object.keys(checkRes.data).length > 0) {
            return res.status(400).json({ success: false, error: 'اسم المستخدم موجود بالفعل' });
        }

        let expiryTimestamp;
        if (customExpiryDate) {
            expiryTimestamp = new Date(customExpiryDate).getTime();
        } else if (expiryMinutes && expiryMinutes > 0) {
            expiryTimestamp = Date.now() + (expiryMinutes * 60 * 1000);
        } else {
            return res.status(400).json({ success: false, error: 'يجب تحديد مدة الاشتراك' });
        }

        const userData = {
            username,
            password_hash: hashPassword(password),
            is_active: status !== 'inactive',
            subscription_end: expiryTimestamp,
            max_devices: maxDevices || 1,
            device_id: '',
            created_at: Date.now(),
            last_login: null,
            created_by_key: 'master'
        };

        const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
        console.log(`✅ User created: ${username} -> ID: ${createRes.data.name}`);

        res.json({ 
            success: true, 
            message: 'تم إنشاء المستخدم بنجاح', 
            userId: createRes.data.name,
            expiryDate: formatDate(expiryTimestamp)
        });

    } catch (error) {
        console.error('Create user error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في إنشاء المستخدم' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// ✏️ UPDATE USER
// ═══════════════════════════════════════════════════════════════════
router.patch('/users/:id', authAdmin, async (req, res) => {
    try {
        const { is_active, max_devices, notes } = req.body;
        const updateData = {};

        if (typeof is_active === 'boolean') updateData.is_active = is_active;
        if (max_devices) updateData.max_devices = max_devices;
        if (notes !== undefined) updateData.notes = notes;

        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, updateData);
        console.log(`✅ User updated: ${req.params.id}`);
        res.json({ success: true, message: 'تم تحديث المستخدم بنجاح' });

    } catch (error) {
        console.error('Update user error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في تحديث المستخدم' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 🗑️ DELETE USER
// ═══════════════════════════════════════════════════════════════════
router.delete('/users/:id', authAdmin, async (req, res) => {
    try {
        await firebase.delete(`users/${req.params.id}.json?auth=${FB_KEY}`);
        console.log(`🗑️ User deleted: ${req.params.id}`);
        res.json({ success: true, message: 'تم حذف المستخدم بنجاح' });

    } catch (error) {
        console.error('Delete user error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في حذف المستخدم' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// ⏰ EXTEND USER SUBSCRIPTION
// ═══════════════════════════════════════════════════════════════════
router.post('/users/:id/extend', authAdmin, async (req, res) => {
    try {
        const { minutes, days, hours } = req.body;
        const userRes = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);

        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'المستخدم غير موجود' });
        }

        const user = userRes.data;
        const now = Date.now();
        const currentEnd = user.subscription_end || now;

        let extensionMs = 0;
        if (minutes) extensionMs = minutes * 60 * 1000;
        else if (days || hours) extensionMs = ((days || 0) * 24 * 60 * 60 * 1000) + ((hours || 0) * 60 * 60 * 1000);

        if (!extensionMs) {
            return res.status(400).json({ success: false, error: 'يجب تحديد مدة التمديد' });
        }

        const newEndDate = (currentEnd > now ? currentEnd : now) + extensionMs;

        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, {
            subscription_end: newEndDate,
            is_active: true
        });

        console.log(`⏰ User extended: ${req.params.id}`);
        res.json({ success: true, message: 'تم تمديد الاشتراك بنجاح', new_end_date: newEndDate });

    } catch (error) {
        console.error('Extend subscription error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في تمديد الاشتراك' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 🔄 RESET USER DEVICE
// ═══════════════════════════════════════════════════════════════════
router.post('/users/:id/reset-device', authAdmin, async (req, res) => {
    try {
        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, { device_id: '' });
        console.log(`🔄 Device reset: ${req.params.id}`);
        res.json({ success: true, message: 'تم إعادة تعيين الجهاز بنجاح' });

    } catch (error) {
        console.error('Reset device error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في إعادة تعيين الجهاز' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 🗑️ DELETE EXPIRED USERS
// ═══════════════════════════════════════════════════════════════════
router.post('/users/delete-expired', authAdmin, async (req, res) => {
    try {
        console.log('🗑️ Deleting expired users...');
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        const now = Date.now();

        const deletePromises = [];
        const deletedUsers = [];

        for (const [id, user] of Object.entries(users)) {
            if (user.subscription_end && user.subscription_end <= now) {
                deletePromises.push(firebase.delete(`users/${id}.json?auth=${FB_KEY}`));
                deletedUsers.push(user.username || id);
            }
        }

        if (deletePromises.length === 0) {
            return res.json({ success: true, message: 'لا توجد حسابات منتهية', count: 0 });
        }

        await Promise.all(deletePromises);
        console.log(`🗑️ Deleted ${deletedUsers.length} expired users`);

        res.json({ success: true, message: `تم حذف ${deletedUsers.length} حساب منتهي`, count: deletedUsers.length });

    } catch (error) {
        console.error('Delete expired error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في حذف الحسابات المنتهية' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// ⏸️ BULK DISABLE EXPIRED USERS (NEW!)
// ═══════════════════════════════════════════════════════════════════
router.post('/users/bulk-disable-expired', authAdmin, async (req, res) => {
    try {
        console.log('⏸️ Disabling expired users...');
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        const now = Date.now();

        const updatePromises = [];
        const disabledUsers = [];

        for (const [id, user] of Object.entries(users)) {
            if (user.subscription_end && user.subscription_end <= now && user.is_active !== false) {
                updatePromises.push(firebase.patch(`users/${id}.json?auth=${FB_KEY}`, { is_active: false }));
                disabledUsers.push(user.username || id);
            }
        }

        if (updatePromises.length === 0) {
            return res.json({ success: true, message: 'لا يوجد مستخدمين منتهيين نشطين', count: 0 });
        }

        await Promise.all(updatePromises);
        console.log(`⏸️ Disabled ${disabledUsers.length} expired users`);

        res.json({ success: true, message: `تم تعطيل ${disabledUsers.length} مستخدم منتهي`, count: disabledUsers.length });

    } catch (error) {
        console.error('Bulk disable error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في تعطيل المستخدمين' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 🗑️ DELETE INACTIVE USERS (NEW!)
// ═══════════════════════════════════════════════════════════════════
router.post('/users/delete-inactive', authAdmin, async (req, res) => {
    try {
        console.log('🗑️ Deleting inactive users...');
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};

        const deletePromises = [];
        const deletedUsers = [];

        for (const [id, user] of Object.entries(users)) {
            if (user.is_active === false) {
                deletePromises.push(firebase.delete(`users/${id}.json?auth=${FB_KEY}`));
                deletedUsers.push(user.username || id);
            }
        }

        if (deletePromises.length === 0) {
            return res.json({ success: true, message: 'لا يوجد مستخدمين معطلين', count: 0 });
        }

        await Promise.all(deletePromises);
        console.log(`🗑️ Deleted ${deletedUsers.length} inactive users`);

        res.json({ success: true, message: `تم حذف ${deletedUsers.length} مستخدم معطل`, count: deletedUsers.length });

    } catch (error) {
        console.error('Delete inactive error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في حذف المستخدمين المعطلين' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 🔑 GET ALL API KEYS
// ═══════════════════════════════════════════════════════════════════
router.get('/api-keys', authAdmin, async (req, res) => {
    try {
        console.log('📥 Fetching API keys...');
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
                usage_count: key.usage_count || 0,
                bound_device: key.bound_device || null,
                created_at: key.created_at || null,
                last_used: key.last_used || null
            };
        }

        console.log(`✅ Loaded ${Object.keys(formattedKeys).length} API keys`);
        res.json({ success: true, data: formattedKeys, count: Object.keys(formattedKeys).length });

    } catch (error) {
        console.error('Get API keys error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في جلب مفاتيح API' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// ➕ CREATE API KEY
// ═══════════════════════════════════════════════════════════════════
router.post('/api-keys', authAdmin, async (req, res) => {
    try {
        const { adminName, permissionLevel, expiryDays } = req.body;

        if (!adminName) {
            return res.status(400).json({ success: false, error: 'اسم المشرف مطلوب' });
        }

        const apiKey = `AK_${crypto.randomBytes(16).toString('hex')}`;
        const signingSecret = `SS_${crypto.randomBytes(32).toString('hex')}`;

        const keyData = {
            api_key: apiKey,
            admin_name: adminName,
            permission_level: permissionLevel || 'view_only',
            is_active: true,
            expiry_timestamp: Date.now() + ((expiryDays || 30) * 24 * 60 * 60 * 1000),
            usage_count: 0,
            bound_device: null,
            created_at: Date.now(),
            last_used: null,
            signing_secret: signingSecret
        };

        await firebase.post(`api_keys.json?auth=${FB_KEY}`, keyData);
        console.log(`🔑 API Key created for: ${adminName}`);

        res.json({
            success: true,
            message: 'تم إنشاء مفتاح API بنجاح',
            apiKey,
            signingSecret,
            warning: 'احفظ الـ signing secret فوراً.'
        });

    } catch (error) {
        console.error('Create API key error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في إنشاء مفتاح API' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// ✏️ UPDATE API KEY (Toggle Status)
// ═══════════════════════════════════════════════════════════════════
router.patch('/api-keys/:id', authAdmin, async (req, res) => {
    try {
        const { is_active } = req.body;
        await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, { is_active });
        console.log(`🔑 API Key ${req.params.id} -> is_active: ${is_active}`);
        res.json({ success: true, message: 'تم تحديث مفتاح API بنجاح' });

    } catch (error) {
        console.error('Update API key error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في تحديث مفتاح API' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 🗑️ DELETE API KEY
// ═══════════════════════════════════════════════════════════════════
router.delete('/api-keys/:id', authAdmin, async (req, res) => {
    try {
        await firebase.delete(`api_keys/${req.params.id}.json?auth=${FB_KEY}`);
        console.log(`🗑️ API Key deleted: ${req.params.id}`);
        res.json({ success: true, message: 'تم حذف مفتاح API بنجاح' });

    } catch (error) {
        console.error('Delete API key error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في حذف مفتاح API' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 🗑️ DELETE EXPIRED API KEYS (NEW!)
// ═══════════════════════════════════════════════════════════════════
router.post('/api-keys/delete-expired', authAdmin, async (req, res) => {
    try {
        console.log('🗑️ Deleting expired API keys...');
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
        const keys = response.data || {};
        const now = Date.now();

        const deletePromises = [];
        const deletedKeys = [];

        for (const [id, key] of Object.entries(keys)) {
            if (key.expiry_timestamp && key.expiry_timestamp <= now) {
                deletePromises.push(firebase.delete(`api_keys/${id}.json?auth=${FB_KEY}`));
                deletedKeys.push(key.admin_name || id);
            }
        }

        if (deletePromises.length === 0) {
            return res.json({ success: true, message: 'لا توجد مفاتيح منتهية', count: 0 });
        }

        await Promise.all(deletePromises);
        console.log(`🗑️ Deleted ${deletedKeys.length} expired API keys`);

        res.json({ success: true, message: `تم حذف ${deletedKeys.length} مفتاح منتهي`, count: deletedKeys.length });

    } catch (error) {
        console.error('Delete expired API keys error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في حذف المفاتيح المنتهية' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 📊 SECURITY STATS
// ═══════════════════════════════════════════════════════════════════
router.get('/security-stats', authAdmin, (req, res) => {
    const security = getSecurityInstance();
    if (security) {
        res.json({ success: true, stats: security.getStats() });
    } else {
        res.json({ success: true, stats: { message: 'نظام الحماية غير مفعل' } });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 📦 EXPORT
// ═══════════════════════════════════════════════════════════════════
module.exports = router;
