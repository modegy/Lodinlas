const express = require('express');
const router = express.Router();

const { firebase, FB_KEY } = require('../config/database');
const { authApp, verifyPassword } = require('../middleware/auth');
const { verifySignature } = require('../middleware/signature');
const { apiLimiter } = require('../middleware/security');
const { formatDate, getClientIP } = require('../utils/helpers');

// ═══════════════════════════════════════════
// ❌ إزالة GET USER (غير آمن)
// ═══════════════════════════════════════════
// router.post('/getUser', ...) // تم حذفها لأنها ترسل password_hash

// ═══════════════════════════════════════════
// ✅ VERIFY ACCOUNT - التحقق الآمن بـ bcrypt
// ═══════════════════════════════════════════
router.post('/verifyAccount', verifySignature, authApp, apiLimiter, async (req, res) => {
    console.log('📱 Verify Account Request:', req.body);
    
    try {
        const { username, password, deviceId } = req.body;

        // التحقق من المدخلات
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'Missing fields',
                code: 400
            });
        }

        // جلب المستخدم من Firebase
        const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const response = await firebase.get(url);
        const users = response.data || {};

        if (Object.keys(users).length === 0) {
            return res.json({ success: false, code: 1 }); // المستخدم غير موجود
        }

        const userId = Object.keys(users)[0];
        const user = users[userId];

        // ✅ التحقق من كلمة المرور باستخدام bcrypt
        if (!verifyPassword(password, user.password_hash)) {
            return res.json({ success: false, code: 2 }); // كلمة مرور خاطئة
        }

        // التحقق من حالة الحساب
        if (!user.is_active) {
            return res.json({ success: false, code: 3 }); // الحساب غير مفعل
        }

        // التحقق من Device ID
        if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
            return res.json({ success: false, code: 4 }); // جهاز غير متطابق
        }

        // التحقق من تاريخ الانتهاء
        const now = Date.now();
        if (!user.subscription_end) {
            return res.json({ success: false, code: 5 }); // تاريخ الانتهاء غير موجود
        }

        if (user.subscription_end <= now) {
            return res.json({ success: false, code: 7 }); // الاشتراك منتهي
        }

        // ✅ نجح التحقق - إرجاع البيانات الأساسية فقط
        res.json({
            success: true,
            username: user.username,
            expiry_date: formatDate(user.subscription_end),
            subscription_end: user.subscription_end,
            is_active: user.is_active,
            device_id: user.device_id || '',
            code: 200
        });

    } catch (error) {
        console.error('Verify account error:', error.message);
        res.status(500).json({
            success: false,
            code: 0,
            error: 'Server error'
        });
    }
});

// ═══════════════════════════════════════════
// 📱 UPDATE DEVICE
// ═══════════════════════════════════════════
router.post('/updateDevice', verifySignature, authApp, apiLimiter, async (req, res) => {
    try {
        const { username, deviceId, deviceInfo } = req.body;

        if (!username || !deviceId) {
            return res.status(400).json({
                success: false,
                error: 'Missing data'
            });
        }

        const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const response = await firebase.get(url);
        const users = response.data || {};

        if (Object.keys(users).length === 0) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        const userId = Object.keys(users)[0];
        const user = users[userId];

        const ip = getClientIP(req);
        const userAgent = req.headers['user-agent'] || '';

        const updateData = {
            device_id: deviceId,
            last_login: Date.now(),
            login_count: (user.login_count || 0) + 1,
            ip_address: ip,
            user_agent: userAgent
        };

        if (deviceInfo) {
            updateData.device_model = deviceInfo.device_model || 'Unknown';
            updateData.device_brand = deviceInfo.device_brand || 'Unknown';
            updateData.device_manufacturer = deviceInfo.device_manufacturer || 'Unknown';
            updateData.device_product = deviceInfo.device_product || 'Unknown';
            updateData.device_type = deviceInfo.device_type || 'Phone';
            updateData.android_version = deviceInfo.android_version || 'Unknown';
            updateData.sdk_version = deviceInfo.sdk_version || 0;
            updateData.is_rooted = deviceInfo.is_rooted || false;
            updateData.has_screen_lock = deviceInfo.has_screen_lock || false;
            updateData.fingerprint_enabled = deviceInfo.fingerprint_enabled || false;
            updateData.total_ram = deviceInfo.total_ram || 'Unknown';
            updateData.screen_size = deviceInfo.screen_size || 'Unknown';
            updateData.screen_density = deviceInfo.screen_density || 0;
            updateData.network_type = deviceInfo.network_type || 'Unknown';
            updateData.carrier_name = deviceInfo.carrier_name || 'Unknown';
            updateData.battery_level = deviceInfo.battery_level || 0;
            updateData.is_charging = deviceInfo.is_charging || false;

            if (deviceInfo.location) {
                updateData.location = deviceInfo.location;
            }
        }

        const loginEntry = {
            timestamp: Date.now(),
            ip: ip,
            device: deviceInfo?.device_model || 'Unknown',
            os_version: deviceInfo?.android_version || 'Unknown',
            network: deviceInfo?.network_type || 'Unknown',
            carrier: deviceInfo?.carrier_name || 'Unknown',
            battery: deviceInfo?.battery_level || 0,
            is_rooted: deviceInfo?.is_rooted || false
        };

        const existingHistory = user.login_history || [];
        updateData.login_history = [
            ...existingHistory.slice(-9),
            loginEntry
        ];

        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, updateData);

        console.log(`📱 Login: ${username} | Device: ${deviceInfo?.device_brand || 'Unknown'} ${deviceInfo?.device_model || 'Unknown'} | IP: ${ip}`);

        if (deviceInfo?.is_rooted) {
            console.warn(`🚨 WARNING: User "${username}" is using a ROOTED device!`);
        }

        res.json({
            success: true,
            message: 'Device updated successfully',
            user_info: {
                username: user.username,
                login_count: updateData.login_count,
                is_rooted: updateData.is_rooted,
                last_login: updateData.last_login
            }
        });

    } catch (error) {
        console.error('❌ Update device error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Server error'
        });
    }
});

module.exports = router;
