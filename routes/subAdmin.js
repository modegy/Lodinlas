const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { body, validationResult, param } = require('express-validator');
const NodeCache = require('node-cache');
const router = express.Router();
const { v4: uuidv4 } = require('uuid'); // إضافة لـ UUIDs لإغلاق ثغرة push IDs
const redis = require('redis'); // إضافة Redis لـ caching و limits
const client = redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
client.connect(); // اتصال Redis

// ═══════════════════════════════════════════
// 📦 IMPORTS
// ═══════════════════════════════════════════
const { admin, db } = require('../config/firebase-admin');
const db = admin.database();

const { authSubAdmin, checkSubAdminPermission } = require('../middleware/auth');
const { verifySignature } = require('../middleware/signature');
const { apiLimiter } = require('../middleware/security');
const { formatDate } = require('../utils/helpers');

// ═══════════════════════════════════════════
// 🗂️ CACHE مع TTL
// ═══════════════════════════════════════════
const subAdminKeys = new NodeCache({
    stdTTL: 3600, // ساعة
    checkperiod: 600, // 10 دقائق
    maxKeys: 1000
});

// ═══════════════════════════════════════════
// 🛠️ HELPER FUNCTIONS
// ═══════════════════════════════════════════
async function hashPassword(password) {
    return await bcrypt.hash(password, 12);
}

function verifyDeviceSignature(deviceId, signature) {
    const secret = process.env.DEVICE_SECRET;
    if (!secret) throw new Error('DEVICE_SECRET is not set'); // إصلاح: إزالة fallback، جعله إلزامي
    const expected = crypto
        .createHmac('sha256', secret)
        .update(deviceId)
        .digest('hex');
    return signature === expected;
}

// إضافة: Brute-force protection لـ /verify-key باستخدام Redis
async function checkVerifyKeyBruteForce(apiKey) {
    const key = `brute:verify:${apiKey}`;
    const attempts = await client.get(key) || 0;
    if (attempts >= 5) {
        throw new Error('Too many attempts');
    }
    await client.incr(key);
    await client.expire(key, 3600); // 1 hour
}

// ═══════════════════════════════════════════
// 🔑 VERIFY KEY
// ═══════════════════════════════════════════
router.post('/verify-key',
    verifySignature,
    apiLimiter,
    [
        body('apiKey')
            .isString()
            .isLength({ min: 32, max: 128 })
            .withMessage('Invalid API key format'),
        
        body('deviceFingerprint')
            .isString()
            .isLength({ min: 10, max: 128 })
            .withMessage('Invalid device fingerprint'),
        
        body('deviceSignature')
            .optional()
            .isString()
            .isLength({ min: 64, max: 64 })
            .withMessage('Invalid device signature')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const { apiKey, deviceFingerprint, deviceSignature } = req.body;

            await checkVerifyKeyBruteForce(apiKey); // إضافة: brute-force check

            console.log('🔍 Sub Admin verify key request');

            // تحقق من الكاش أولاً
            const cached = subAdminKeys.get(apiKey);
            if (cached && cached.device === deviceFingerprint) {
                console.log('✅ Key verified from cache');
                return res.json({
                    success: true,
                    name: cached.admin_name,
                    permission: cached.permission_level || 'view_only',
                    key_id: cached.keyId
                    // ❌ لا ترسل signing_secret
                });
            }

            // البحث في Firebase باستخدام Query محسّن
            const snapshot = await db.ref('api_keys')
                .orderByChild('api_key')
                .equalTo(apiKey)
                .limitToFirst(1)
                .once('value');

            if (!snapshot.exists()) {
                return res.status(401).json({
                    success: false,
                    error: 'Invalid API key'
                });
            }

            const data = snapshot.val();
            const [[keyId, foundKey]] = Object.entries(data);

            // التحققات الأمنية
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

            // توليد Signing Secret إذا لم يكن موجوداً
            if (!foundKey.signing_secret) {
                const newSecret = `SS_${crypto.randomBytes(32).toString('hex')}`;
                await db.ref(`api_keys/${keyId}`).update({
                    signing_secret: newSecret,
                    last_secret_update: Date.now()
                });
                foundKey.signing_secret = newSecret;
                console.log(`🔄 Generated signing secret for: ${keyId}`);
            }

            // Device Binding مع التحقق من التوقيع
            if (deviceSignature) {
                if (!verifyDeviceSignature(deviceFingerprint, deviceSignature)) {
                    return res.status(403).json({
                        success: false,
                        error: 'Invalid device signature'
                    });
                }
            }

            if (!foundKey.bound_device) {
                await db.ref(`api_keys/${keyId}`).update({
                    bound_device: deviceFingerprint,
                    device_bound_at: Date.now()
                });
                console.log(`🔗 Device bound to key: ${keyId}`);
            } else if (foundKey.bound_device !== deviceFingerprint) {
                return res.status(403).json({
                    success: false,
                    error: 'Key is bound to another device'
                });
            }

            // تحديث آخر استخدام
            await db.ref(`api_keys/${keyId}`).update({
                usage_count: admin.database.ServerValue.increment(1),
                last_used: Date.now()
            });

            // حفظ في الكاش (بدون signing_secret - إصلاح ثغرة)
            subAdminKeys.set(apiKey, {
                admin_name: foundKey.admin_name,
                permission_level: foundKey.permission_level,
                keyId,
                device: deviceFingerprint
            }, 3600);

            console.log(`✅ Sub Admin verified: ${foundKey.admin_name} (ID: ${keyId})`);

            res.json({
                success: true,
                name: foundKey.admin_name,
                permission: foundKey.permission_level || 'view_only',
                key_id: keyId
                // ❌ signing_secret محذوف من هنا
            });

        } catch (error) {
            console.error('Verify key error:', error.message);
            res.status(500).json({
                success: false,
                error: 'Server error'
            });
        }
    }
);

// ═══════════════════════════════════════════
// 📊 STATS
// ═══════════════════════════════════════════
router.get('/stats',
    verifySignature,
    authSubAdmin,
    checkSubAdminPermission('view'),
    apiLimiter,
    async (req, res) => {
        try {
            const currentKeyId = req.subAdminKeyId;

            // استعلام محسّن - جلب مستخدمي هذا الـ Key فقط
            const snapshot = await db.ref('users')
                .orderByChild('created_by_key')
                .equalTo(currentKeyId)
                .once('value');

            const users = snapshot.val() || {};
            const now = Date.now();

            let totalUsers = 0;
            let activeUsers = 0;
            let expiredUsers = 0;

            for (const user of Object.values(users)) {
                totalUsers++;
                if (user.is_active !== false) {
                    activeUsers++;
                }
                if (user.subscription_end && user.subscription_end <= now) {
                    expiredUsers++;
                }
            }

            res.json({
                success: true,
                stats: {
                    totalUsers,
                    activeUsers,
                    expiredUsers
                }
            });

        } catch (error) {
            console.error('Sub Admin stats error:', error.message);
            res.status(500).json({
                success: false,
                error: 'Failed to get stats'
            });
        }
    }
);

// ═══════════════════════════════════════════
// 👥 GET USERS
// ═══════════════════════════════════════════
router.get('/users',
    verifySignature,
    authSubAdmin,
    checkSubAdminPermission('view'),
    apiLimiter,
    async (req, res) => {
        try {
            const currentKeyId = req.subAdminKeyId;

            // استعلام محسّن
            const snapshot = await db.ref('users')
                .orderByChild('created_by_key')
                .equalTo(currentKeyId)
                .once('value');

            const users = snapshot.val() || {};
            const formattedUsers = {};

            for (const [id, user] of Object.entries(users)) {
                const subEnd = user.subscription_end || 0;
                formattedUsers[id] = {
                    username: user.username || '',
                    is_active: user.is_active !== false,
                    expiry_timestamp: subEnd,
                    expiry_date: formatDate(subEnd),
                    device_id: user.device_id || '',
                    max_devices: user.max_devices || 1,
                    last_login: user.last_login || 0,
                    created_at: user.created_at || 0,
                    created_by: user.created_by || 'sub_admin'
                };
            }

            console.log(`👥 Sub Admin [${currentKeyId}] sees ${Object.keys(formattedUsers).length} users`);

            res.json({
                success: true,
                data: formattedUsers,
                count: Object.keys(formattedUsers).length
            });

        } catch (error) {
            console.error('Sub Admin get users error:', error.message);
            res.status(500).json({
                success: false,
                error: 'Failed to fetch users'
            });
        }
    }
);

// ═══════════════════════════════════════════
// ➕ CREATE USER
// ═══════════════════════════════════════════
router.post('/users',
    verifySignature,
    authSubAdmin,
    checkSubAdminPermission('add'),
    [
        body('username')
            .trim()
            .isLength({ min: 3, max: 50 })
            .matches(/^[a-zA-Z0-9_]+$/)
            .withMessage('Username: 3-50 chars, alphanumeric + underscore'),
        
        body('password')
            .isLength({ min: 8, max: 128 })
            .withMessage('Password: 8-128 characters'),
        
        body('maxDevices')
            .optional()
            .isInt({ min: 1, max: 10 })
            .toInt(),
        
        body('expiryMinutes')
            .optional()
            .isInt({ min: 1, max: 525600 })
            .toInt(),
        
        body('status')
            .optional()
            .isIn(['active', 'inactive'])
    ],
    apiLimiter,
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;

            // تحقق من وجود Username
            const checkSnapshot = await db.ref('users')
                .orderByChild('username')
                .equalTo(username)
                .limitToFirst(1)
                .once('value');

            if (checkSnapshot.exists()) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid username or already taken' // إصلاح: generic message لمنع enumeration
                });
            }

            // حساب Expiry
            let expiryTimestamp;
            if (customExpiryDate) {
                expiryTimestamp = new Date(customExpiryDate).getTime();
            } else if (expiryMinutes) {
                expiryTimestamp = Date.now() + (expiryMinutes * 60 * 1000);
            } else {
                return res.status(400).json({
                    success: false,
                    error: 'Expiry time required'
                });
            }

            // Hash Password
            const passwordHash = await hashPassword(password);

            const userData = {
                username,
                password_hash: passwordHash,
                is_active: status !== 'inactive',
                subscription_end: expiryTimestamp,
                max_devices: maxDevices || 1,
                device_id: '',
                created_at: Date.now(),
                last_login: null,
                created_by_key: req.subAdminKeyId,
                created_by: req.subAdminKey.admin_name || 'sub_admin'
            };

            // استخدام UUID بدلاً من push - إصلاح ثغرة تخمين IDs
            const userId = uuidv4();
            await db.ref(`users/${userId}`).set(userData);

            console.log(`✅ User created by Sub Admin [${req.subAdminKeyId}]: ${username}`);

            res.json({
                success: true,
                message: 'User created',
                userId: userId,
                expiry_date: formatDate(expiryTimestamp)
            });

        } catch (error) {
            console.error('Sub Admin create user error:', error.message);
            res.status(500).json({
                success: false,
                error: 'Failed to create user'
            });
        }
    }
);

// ═══════════════════════════════════════════
// ⏰ EXTEND SUBSCRIPTION
// ═══════════════════════════════════════════
router.post('/users/:id/extend',
    verifySignature,
    authSubAdmin,
    checkSubAdminPermission('extend'),
    [
        param('id').isString().isLength({ min: 10, max: 50 }),
        body('minutes').optional().isInt({ min: 1, max: 525600 }).toInt(),
        body('days').optional().isInt({ min: 1, max: 365 }).toInt(),
        body('hours').optional().isInt({ min: 1, max: 8760 }).toInt()
    ],
    apiLimiter,
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const userId = req.params.id;
            const currentKeyId = req.subAdminKeyId;
            const { minutes, days, hours } = req.body;

            if (!minutes && !days && !hours) {
                return res.status(400).json({
                    success: false,
                    error: 'Extension time required'
                });
            }

            // استخدام Transaction للأمان
            const result = await db.ref(`users/${userId}`).transaction((user) => {
                if (!user) {
                    throw new Error('User not found');
                }

                if (user.created_by_key !== currentKeyId) {
                    throw new Error('Permission denied');
                }

                const now = Date.now();
                const currentEnd = user.subscription_end || now;

                let extensionMs = 0;
                if (minutes) {
                    extensionMs = minutes * 60 * 1000;
                } else if (days || hours) {
                    extensionMs = ((days || 0) * 24 * 60 * 60 * 1000) + 
                                  ((hours || 0) * 60 * 60 * 1000);
                }

                user.subscription_end = (currentEnd > now ? currentEnd : now) + extensionMs;
                user.is_active = true;

                return user;
            });

            if (!result.committed) {
                return res.status(500).json({
                    success: false,
                    error: 'Transaction failed'
                });
            }

            const newEndDate = result.snapshot.val().subscription_end;

            console.log(`⏰ Sub Admin [${currentKeyId}] extended user subscription`);

            res.json({
                success: true,
                message: 'Subscription extended',
                new_end_date: newEndDate,
                formatted_date: formatDate(newEndDate)
            });

        } catch (error) {
            console.error('Sub Admin extend error:', error.message);
            
            if (error.message === 'User not found') {
                return res.status(404).json({ success: false, error: 'User not found' });
            }
            
            if (error.message === 'Permission denied') {
                return res.status(403).json({ 
                    success: false, 
                    error: 'You can only extend users you created' 
                });
            }
            
            res.status(500).json({
                success: false,
                error: 'Failed to extend subscription'
            });
        }
    }
);

// ═══════════════════════════════════════════
// ✏️ UPDATE USER
// ═══════════════════════════════════════════
router.patch('/users/:id',
    verifySignature,
    authSubAdmin,
    checkSubAdminPermission('edit'),
    [
        param('id').isString().isLength({ min: 10, max: 50 }),
        body('is_active').isBoolean()
    ],
    apiLimiter,
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const userId = req.params.id;
            const currentKeyId = req.subAdminKeyId;
            const { is_active } = req.body;

            // تحقق من الملكية
            const userSnapshot = await db.ref(`users/${userId}`).once('value');
            const user = userSnapshot.val();

            if (!user) {
                return res.status(404).json({
                    success: false,
                    error: 'User not found'
                });
            }

            if (user.created_by_key !== currentKeyId) {
                return res.status(403).json({
                    success: false,
                    error: 'You can only edit users you created'
                });
            }

            await db.ref(`users/${userId}`).update({
                is_active
            });

            console.log(`✏️ Sub Admin [${currentKeyId}] updated user: ${user.username}`);

            res.json({
                success: true,
                message: 'User updated'
            });

        } catch (error) {
            console.error('Sub Admin update user error:', error.message);
            res.status(500).json({
                success: false,
                error: 'Failed to update user'
            });
        }
    }
);

// ═══════════════════════════════════════════
// 🔄 RESET DEVICE
// ═══════════════════════════════════════════
router.post('/users/:id/reset-device',
    verifySignature,
    authSubAdmin,
    checkSubAdminPermission('edit'),
    [
        param('id').isString().isLength({ min: 10, max: 50 })
    ],
    apiLimiter,
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const userId = req.params.id;
            const currentKeyId = req.subAdminKeyId;

            const userSnapshot = await db.ref(`users/${userId}`).once('value');
            const user = userSnapshot.val();

            if (!user) {
                return res.status(404).json({
                    success: false,
                    error: 'User not found'
                });
            }

            if (user.created_by_key !== currentKeyId) {
                return res.status(403).json({
                    success: false,
                    error: 'You can only reset device for users you created'
                });
            }

            await db.ref(`users/${userId}`).update({
                device_id: ''
            });

            console.log(`🔄 Sub Admin [${currentKeyId}] reset device for user: ${user.username}`);

            res.json({
                success: true,
                message: 'Device reset'
            });

        } catch (error) {
            console.error('Sub Admin reset device error:', error.message);
            res.status(500).json({
                success: false,
                error: 'Failed to reset device'
            });
        }
    }
);

// ═══════════════════════════════════════════
// 🗑️ DELETE USER
// ═══════════════════════════════════════════
router.delete('/users/:id',
    verifySignature,
    authSubAdmin,
    checkSubAdminPermission('delete'),
    [
        param('id').isString().isLength({ min: 10, max: 50 })
    ],
    apiLimiter,
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const userId = req.params.id;
            const currentKeyId = req.subAdminKeyId;

            const userSnapshot = await db.ref(`users/${userId}`).once('value');
            const user = userSnapshot.val();

            if (!user) {
                return res.status(404).json({
                    success: false,
                    error: 'User not found'
                });
            }

            if (user.created_by_key !== currentKeyId) {
                return res.status(403).json({
                    success: false,
                    error: 'You can only delete users you created'
                });
            }

            await db.ref(`users/${userId}`).remove();

            console.log(`🗑️ User deleted by Sub Admin [${currentKeyId}]: ${user.username}`);

            res.json({
                success: true,
                message: 'User deleted'
            });

        } catch (error) {
            console.error('Sub Admin delete user error:', error.message);
            res.status(500).json({
                success: false,
                error: 'Failed to delete user'
            });
        }
    }
);

// تعليق: أضف index في Firebase console على 'created_by_key' و 'username' لتحسين الأداء

module.exports = router;
