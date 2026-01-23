// routes/masterAdmin.js - Secure Master Admin Routes v2.0
'use strict';

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const { firebase, FB_KEY } = require('../config/database');
const { 
    verifyPassword, 
    hashPassword,
    isIPBlocked, 
    getBlockedRemainingTime,
    recordLoginAttempt, 
    getRemainingAttempts,
    createSession, 
    destroySession,
    authMaster,
    getSecurityStats,
    validatePasswordStrength
} = require('../middleware/secureAuth');
const { generateToken, formatDate, getClientIP } = require('../utils/helpers');

// ═══════════════════════════════════════════════════════════════════
// 🔐 SECURE LOGIN - No Default Credentials!
// ═══════════════════════════════════════════════════════════════════
router.post('/login', async (req, res) => {
    const ip = req.clientIP || getClientIP(req);
    const userAgent = req.headers['user-agent'] || 'unknown';
    
    try {
        // 1. Check if IP is blocked
        if (isIPBlocked(ip)) {
            const remaining = getBlockedRemainingTime(ip);
            console.log(`🚫 Blocked IP attempted login: ${ip}`);
            return res.status(429).json({
                success: false,
                error: `تم حظر IP مؤقتاً. حاول بعد ${remaining} دقيقة`,
                code: 'IP_BLOCKED',
                retryAfter: remaining * 60
            });
        }
        
        const { username, password, totpCode, deviceFingerprint } = req.body;
        
        // 2. Validate input
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'اسم المستخدم وكلمة المرور مطلوبان',
                code: 'MISSING_CREDENTIALS'
            });
        }
        
        // 3. Add delay to prevent timing attacks
        await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 500));
        
        // 4. Get credentials from environment ONLY (no fallback!)
        const MASTER_USERNAME = process.env.MASTER_ADMIN_USERNAME;
        const MASTER_PASSWORD_HASH = process.env.MASTER_ADMIN_PASSWORD_HASH;
        
        // 5. Verify credentials exist (server should not start without them)
        if (!MASTER_USERNAME || !MASTER_PASSWORD_HASH) {
            console.error('🚨 CRITICAL: Admin credentials not configured!');
            return res.status(500).json({
                success: false,
                error: 'خطأ في تكوين الخادم',
                code: 'SERVER_CONFIG_ERROR'
            });
        }
        
        console.log(`🔐 Login attempt: ${username} from IP: ${ip}`);
        
        // 6. Verify username (timing-safe)
        const usernameBuffer = Buffer.from(username.padEnd(100));
        const expectedBuffer = Buffer.from(MASTER_USERNAME.padEnd(100));
        const usernameValid = crypto.timingSafeEqual(usernameBuffer, expectedBuffer);
        
        // 7. Verify password with bcrypt
        const passwordValid = verifyPassword(password, MASTER_PASSWORD_HASH);
        
        // 8. Both must be valid
        if (!usernameValid || !passwordValid) {
            recordLoginAttempt(ip, false);
            const remaining = getRemainingAttempts(ip);
            
            console.log(`❌ Login failed: ${username} | Remaining attempts: ${remaining}`);
            
            return res.status(401).json({
                success: false,
                error: 'اسم المستخدم أو كلمة المرور غير صحيحة',
                code: 'INVALID_CREDENTIALS',
                remainingAttempts: remaining
            });
        }
        
        // 9. Check 2FA if enabled
        const is2FAEnabled = process.env.MASTER_ADMIN_2FA_SECRET;
        if (is2FAEnabled) {
            if (!totpCode) {
                return res.status(200).json({
                    success: false,
                    requires2FA: true,
                    message: 'أدخل رمز التحقق الثنائي',
                    code: '2FA_REQUIRED'
                });
            }
            
            // Verify TOTP (simplified - use proper library in production)
            const { verifyTOTP } = require('../middleware/secureAuth');
            if (!verifyTOTP(is2FAEnabled, totpCode)) {
                return res.status(401).json({
                    success: false,
                    error: 'رمز التحقق غير صحيح',
                    code: 'INVALID_2FA'
                });
            }
        }
        
        // 10. Success! Record and create session
        recordLoginAttempt(ip, true);
        
        const sessionData = createSession(
            'master_admin',
            'master',
            ip,
            userAgent,
            deviceFingerprint
        );
        
        // 11. Log successful login
        console.log('═'.repeat(50));
        console.log(`✅ MASTER ADMIN LOGIN SUCCESSFUL`);
        console.log(`   User: ${username}`);
        console.log(`   IP: ${ip}`);
        console.log(`   Session: ${sessionData.sessionId.substring(0, 16)}...`);
        console.log(`   Expires: ${new Date(sessionData.expiresAt).toISOString()}`);
        console.log('═'.repeat(50));
        
        return res.json({
            success: true,
            message: 'تم تسجيل الدخول بنجاح',
            sessionId: sessionData.sessionId,
            sessionToken: sessionData.token,
            expiresAt: sessionData.expiresAt,
            expiresIn: sessionData.expiresIn,
            user: {
                username: username,
                type: 'master',
                permissions: ['full']
            }
        });
        
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'خطأ في تسجيل الدخول',
            code: 'LOGIN_ERROR'
        });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 🚪 SECURE LOGOUT
// ═══════════════════════════════════════════════════════════════════
router.post('/logout', authMaster, (req, res) => {
    const sessionId = req.sessionId;
    
    if (sessionId) {
        destroySession(sessionId);
        console.log(`👋 Master Admin logged out`);
    }
    
    res.json({ 
        success: true, 
        message: 'تم تسجيل الخروج بنجاح' 
    });
});

// ═══════════════════════════════════════════════════════════════════
// ✅ VERIFY SESSION
// ═══════════════════════════════════════════════════════════════════
router.get('/verify-session', authMaster, (req, res) => {
    const session = req.session;
    
    res.json({
        success: true,
        valid: true,
        session: {
            userId: session.userId,
            userType: session.userType,
            createdAt: session.createdAt,
            expiresAt: session.expiresAt,
            remainingTime: Math.floor((session.expiresAt - Date.now()) / 1000 / 60) + ' دقيقة'
        }
    });
});

// ═══════════════════════════════════════════════════════════════════
// 🔄 REFRESH SESSION (Extend expiry)
// ═══════════════════════════════════════════════════════════════════
router.post('/refresh-session', authMaster, (req, res) => {
    const ip = req.clientIP || getClientIP(req);
    const userAgent = req.headers['user-agent'];
    const { deviceFingerprint } = req.body;
    
    // Destroy old session
    destroySession(req.sessionId);
    
    // Create new session
    const newSession = createSession(
        req.session.userId,
        'master',
        ip,
        userAgent,
        deviceFingerprint
    );
    
    res.json({
        success: true,
        message: 'تم تجديد الجلسة',
        sessionId: newSession.sessionId,
        sessionToken: newSession.token,
        expiresAt: newSession.expiresAt
    });
});

// ═══════════════════════════════════════════════════════════════════
// 🔐 CHANGE PASSWORD
// ═══════════════════════════════════════════════════════════════════
router.post('/change-password', authMaster, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;
        
        // Validate input
        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({
                success: false,
                error: 'جميع الحقول مطلوبة'
            });
        }
        
        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                success: false,
                error: 'كلمة المرور الجديدة غير متطابقة'
            });
        }
        
        // Validate password strength
        const validation = validatePasswordStrength(newPassword);
        if (!validation.valid) {
            return res.status(400).json({
                success: false,
                error: 'كلمة المرور ضعيفة',
                requirements: validation.errors
            });
        }
        
        // Verify current password
        const currentHash = process.env.MASTER_ADMIN_PASSWORD_HASH;
        if (!verifyPassword(currentPassword, currentHash)) {
            return res.status(401).json({
                success: false,
                error: 'كلمة المرور الحالية غير صحيحة'
            });
        }
        
        // Generate new hash
        const newHash = hashPassword(newPassword);
        
        // In production, you would update this in a secure config store
        // For now, we'll just return the new hash for manual update
        console.log('🔐 Password change requested');
        console.log('   New hash (update in .env):');
        console.log(`   MASTER_ADMIN_PASSWORD_HASH=${newHash}`);
        
        res.json({
            success: true,
            message: 'تم إنشاء كلمة المرور الجديدة',
            newHash: newHash,
            instruction: 'قم بتحديث MASTER_ADMIN_PASSWORD_HASH في ملف .env ثم أعد تشغيل الخادم'
        });
        
    } catch (error) {
        console.error('Change password error:', error.message);
        res.status(500).json({ success: false, error: 'خطأ في تغيير كلمة المرور' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 📊 SECURITY STATS (Master Only)
// ═══════════════════════════════════════════════════════════════════
router.get('/security-stats', authMaster, (req, res) => {
    const stats = getSecurityStats();
    res.json({ success: true, stats });
});

// ═══════════════════════════════════════════════════════════════════
// 👥 USER MANAGEMENT (Existing routes with authMaster)
// ═══════════════════════════════════════════════════════════════════

// GET ALL USERS
router.get('/users', authMaster, async (req, res) => {
    try {
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
                login_count: user.login_count || 0,
                max_devices: user.max_devices || 1,
                created_by_key: user.created_by_key || 'master'
            };
        }

        res.json({ success: true, data: formattedUsers, count: Object.keys(formattedUsers).length });
    } catch (error) {
        console.error('Get users error:', error.message);
        res.status(500).json({ success: false, error: 'فشل في جلب المستخدمين' });
    }
});

// CREATE USER
router.post('/users', authMaster, async (req, res) => {
    try {
        const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;

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
            created_by: req.session.userId
        };

        const createRes = await firebase.post(`users.json?auth=${FB_KEY}`, userData);
        
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

// UPDATE USER
router.patch('/users/:id', authMaster, async (req, res) => {
    try {
        const { is_active, max_devices, notes } = req.body;
        const updateData = {};

        if (typeof is_active === 'boolean') updateData.is_active = is_active;
        if (max_devices) updateData.max_devices = max_devices;
        if (notes !== undefined) updateData.notes = notes;

        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, updateData);
        res.json({ success: true, message: 'تم تحديث المستخدم بنجاح' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'فشل في تحديث المستخدم' });
    }
});

// DELETE USER
router.delete('/users/:id', authMaster, async (req, res) => {
    try {
        await firebase.delete(`users/${req.params.id}.json?auth=${FB_KEY}`);
        res.json({ success: true, message: 'تم حذف المستخدم بنجاح' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'فشل في حذف المستخدم' });
    }
});

// EXTEND SUBSCRIPTION
router.post('/users/:id/extend', authMaster, async (req, res) => {
    try {
        const { minutes } = req.body;
        const userRes = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);

        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'المستخدم غير موجود' });
        }

        const now = Date.now();
        const currentEnd = userRes.data.subscription_end || now;
        const newEndDate = (currentEnd > now ? currentEnd : now) + (minutes * 60 * 1000);

        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, {
            subscription_end: newEndDate,
            is_active: true
        });

        res.json({ success: true, message: 'تم تمديد الاشتراك', new_end_date: newEndDate });
    } catch (error) {
        res.status(500).json({ success: false, error: 'فشل في تمديد الاشتراك' });
    }
});

// RESET DEVICE
router.post('/users/:id/reset-device', authMaster, async (req, res) => {
    try {
        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, { device_id: '' });
        res.json({ success: true, message: 'تم إعادة تعيين الجهاز' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'فشل في إعادة تعيين الجهاز' });
    }
});

// DELETE EXPIRED
router.post('/users/delete-expired', authMaster, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        const now = Date.now();
        const deletePromises = [];

        for (const [id, user] of Object.entries(users)) {
            if (user.subscription_end && user.subscription_end <= now) {
                deletePromises.push(firebase.delete(`users/${id}.json?auth=${FB_KEY}`));
            }
        }

        await Promise.all(deletePromises);
        res.json({ success: true, message: `تم حذف ${deletePromises.length} مستخدم`, count: deletePromises.length });
    } catch (error) {
        res.status(500).json({ success: false, error: 'فشل في الحذف' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// 🔑 API KEYS MANAGEMENT (with authMaster)
// ═══════════════════════════════════════════════════════════════════
router.get('/api-keys', authMaster, async (req, res) => {
    try {
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
        const keys = response.data || {};
        res.json({ success: true, data: keys, count: Object.keys(keys).length });
    } catch (error) {
        res.status(500).json({ success: false, error: 'فشل في جلب المفاتيح' });
    }
});

router.post('/api-keys', authMaster, async (req, res) => {
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
            expiry_timestamp: expiryDays ? Date.now() + (expiryDays * 86400000) : null,
            created_at: Date.now(),
            signing_secret: signingSecret,
            created_by: req.session.userId
        };

        await firebase.post(`api_keys.json?auth=${FB_KEY}`, keyData);
        
        res.json({
            success: true,
            message: 'تم إنشاء المفتاح',
            apiKey,
            signingSecret,
            warning: 'احفظ signing secret فوراً!'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'فشل في إنشاء المفتاح' });
    }
});

router.patch('/api-keys/:id', authMaster, async (req, res) => {
    try {
        const { is_active } = req.body;
        await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, { is_active });
        res.json({ success: true, message: 'تم التحديث' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'فشل في التحديث' });
    }
});

router.delete('/api-keys/:id', authMaster, async (req, res) => {
    try {
        await firebase.delete(`api_keys/${req.params.id}.json?auth=${FB_KEY}`);
        res.json({ success: true, message: 'تم الحذف' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'فشل في الحذف' });
    }
});

module.exports = router;
