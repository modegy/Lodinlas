// routes/mobile.js - نقاط النهاية للتطبيق المحمول
const express = require('express');
const router = express.Router();
const { firebase, FB_KEY } = require('../services/firebase');
const { verifySignature } = require('../middleware/signature');
const { authApp } = require('../middleware/auth');
const { hashPassword, formatDate, getClientIP } = require('../helpers/utils');

// ═══════════════════════════════════════════
// GET USER - جلب بيانات المستخدم
// ═══════════════════════════════════════════
router.post('/getUser', verifySignature, authApp, async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username) {
            return res.status(400).json(null);
        }
        
        const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const response = await firebase.get(url);
        const users = response.data || {};
        
        if (Object.keys(users).length === 0) {
            return res.json(null);
        }
        
        const userId = Object.keys(users)[0];
        const user = users[userId];
        
        res.json({
            username: user.username,
            password_hash: user.password_hash,
            is_active: user.is_active !== false,
            device_id: user.device_id || '',
            expiry_date: formatDate(user.subscription_end),
            subscription_end: user.subscription_end
        });
        
    } catch (error) {
        console.error('Get user error:', error.message);
        res.status(500).json(null);
    }
});

// ═══════════════════════════════════════════
// VERIFY ACCOUNT - التحقق من الحساب
// ═══════════════════════════════════════════
router.post('/verifyAccount', verifySignature, authApp, async (req, res) => {
    try {
        const { username, password, deviceId } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing fields', 
                code: 400 
            });
        }
        
        const passHash = hashPassword(password);
        const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const response = await firebase.get(url);
        const users = response.data || {};
        
        if (Object.keys(users).length === 0) {
            return res.json({ success: false, code: 1 }); // User not found
        }
        
        const userId = Object.keys(users)[0];
        const user = users[userId];
        
        if (user.password_hash !== passHash) {
            return res.json({ success: false, code: 2 }); // Wrong password
        }
        
        if (!user.is_active) {
            return res.json({ success: false, code: 3 }); // Inactive
        }
        
        if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
            return res.json({ success: false, code: 4 }); // Different device
        }
        
        res.json({ 
            success: true, 
            username: user.username, 
            code: 200 
        });
        
    } catch (error) {
        console.error('Verify account error:', error.message);
        res.status(500).json({ success: false, code: 0, error: 'Server error' });
    }
});

// ═══════════════════════════════════════════
// UPDATE DEVICE - تحديث بيانات الجهاز
// ═══════════════════════════════════════════
router.post('/updateDevice', verifySignature, authApp, async (req, res) => {
    try {
        const { username, deviceId, deviceInfo } = req.body;
        
        if (!username || !deviceId) {
            return res.status(400).json({ success: false, error: 'Missing data' });
        }
        
        const ip = getClientIP(req);
        
        // ═══════════════════════════════════════════
        // 🛡️ فحص الأمان - Frida / Security Threat
        // ═══════════════════════════════════════════
        if (deviceInfo?.security_threat === true) {
            console.error(`⛔ [FRIDA/SECURITY BLOCKED] User: ${username} | IP: ${ip}`);
            return res.status(403).json({ 
                success: false, 
                error: 'Security violation detected',
                code: 403
            });
        }
        
        // ═══════════════════════════════════════════
        // 🛡️ فحص الأمان - Rooted (اختياري - أزله إذا لا تريده)
        // ═══════════════════════════════════════════
        // if (deviceInfo?.is_rooted === true) {
        //     console.error(`⛔ [ROOTED BLOCKED] User: ${username} | IP: ${ip}`);
        //     return res.status(403).json({ 
        //         success: false, 
        //         error: 'Rooted devices not allowed',
        //         code: 403
        //     });
        // }
        
        const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const response = await firebase.get(url);
        const users = response.data || {};
        
        if (Object.keys(users).length === 0) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const userId = Object.keys(users)[0];
        const user = users[userId];
        const userAgent = req.headers['user-agent'] || '';
        
        const updateData = {
            device_id: deviceId,
            last_login: Date.now(),
            login_count: (user.login_count || 0) + 1,
            ip_address: ip,
            user_agent: userAgent
        };
        
        // Add device info if provided
        if (deviceInfo) {
            Object.assign(updateData, {
                device_model: deviceInfo.device_model || 'Unknown',
                device_brand: deviceInfo.device_brand || 'Unknown',
                device_manufacturer: deviceInfo.device_manufacturer || 'Unknown',
                device_product: deviceInfo.device_product || 'Unknown',
                device_type: deviceInfo.device_type || 'Phone',
                android_version: deviceInfo.android_version || 'Unknown',
                sdk_version: deviceInfo.sdk_version || 0,
                is_rooted: deviceInfo.is_rooted || false,
                security_threat: deviceInfo.security_threat || false,
                has_screen_lock: deviceInfo.has_screen_lock || false,
                fingerprint_enabled: deviceInfo.fingerprint_enabled || false,
                total_ram: deviceInfo.total_ram || 'Unknown',
                screen_size: deviceInfo.screen_size || 'Unknown',
                screen_density: deviceInfo.screen_density || 0,
                network_type: deviceInfo.network_type || 'Unknown',
                carrier_name: deviceInfo.carrier_name || 'Unknown',
                battery_level: deviceInfo.battery_level || 0,
                is_charging: deviceInfo.is_charging || false
            });
            
            if (deviceInfo.location) {
                updateData.location = deviceInfo.location;
            }
        }
        
        // Login history
        const loginEntry = {
            timestamp: Date.now(),
            ip: ip,
            device: deviceInfo?.device_model || 'Unknown',
            os_version: deviceInfo?.android_version || 'Unknown',
            is_rooted: deviceInfo?.is_rooted || false,
            security_threat: deviceInfo?.security_threat || false
        };
        
        const existingHistory = user.login_history || [];
        updateData.login_history = [...existingHistory.slice(-9), loginEntry];
        
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
                is_rooted: updateData.is_rooted
            }
        });
        
    } catch (error) {
        console.error('❌ Update device error:', error.message);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

module.exports = router;
