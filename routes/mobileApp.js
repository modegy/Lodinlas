const express = require('express');
const router = express.Router();

const { firebase, FB_KEY } = require('../config/database');
const { authApp, verifyPassword } = require('../middleware/auth');
const { verifySignature } = require('../middleware/signature');
const { apiLimiter } = require('../middleware/security');
const { formatDate, getClientIP } = require('../utils/helpers');
const { sendSecurityAlert } = require('../middleware/notifications');

// Cache للحماية
const blockedIPs = new Map();
const suspiciousIPs = new Map();
const failedAttempts = new Map();

// إحصائيات يومية
const dailyStats = {
    blockedIPs: 0,
    failedAttempts: 0,
    suspiciousRequests: 0,
    rootedDevices: 0,
    successfulLogins: 0,
    uniqueUsers: new Set(),
    totalRequests: 0,
    ipActivity: new Map()
};

// تنظيف تلقائي كل ساعة
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of blockedIPs.entries()) {
        if (data.until < now) blockedIPs.delete(ip);
    }
    for (const [ip, data] of suspiciousIPs.entries()) {
        if (now - data.firstSeen > 3600000) suspiciousIPs.delete(ip);
    }
}, 3600000);

// ══════════════════════════════════════════
// 🚫 IP Block Checker
// ══════════════════════════════════════════
const checkBlockedIP = (req, res, next) => {
    const ip = getClientIP(req);
    const blocked = blockedIPs.get(ip);
    
    if (blocked && blocked.until > Date.now()) {
        const remainingTime = Math.ceil((blocked.until - Date.now()) / 1000 / 60);
        console.warn(`🚫 Blocked IP attempt: ${ip} | Reason: ${blocked.reason}`);
        
        return res.status(403).json({
            success: false,
            code: 403,
            error: 'Access denied'
        });
    }
    
    next();
};

// ══════════════════════════════════════════
// 🔍 Malicious Request Detector - مع إشعارات
// ══════════════════════════════════════════
const detectMaliciousRequest = async (req, res, next) => {
    const ip = getClientIP(req);
    const userAgent = req.headers['user-agent'] || '';
    const suspicious = suspiciousIPs.get(ip) || { count: 0, firstSeen: Date.now() };
    
    dailyStats.totalRequests++;
    
    // تسجيل نشاط IP
    const ipActivity = dailyStats.ipActivity.get(ip) || 0;
    dailyStats.ipActivity.set(ip, ipActivity + 1);
    
    let suspicionScore = 0;
    const reasons = [];

    // 1️⃣ فحص User-Agent
    const maliciousAgents = [
        /bot/i, /crawler/i, /spider/i, /scraper/i,
        /curl/i, /wget/i, /python/i, /java/i,
        /postman/i, /insomnia/i, /http/i,
        /nikto/i, /nmap/i, /masscan/i, /zap/i
    ];
    
    if (!userAgent || userAgent.length < 10) {
        suspicionScore += 3;
        reasons.push('Empty/Short User-Agent');
    } else if (maliciousAgents.some(regex => regex.test(userAgent))) {
        suspicionScore += 5;
        reasons.push('Malicious User-Agent');
    }

    // 2️⃣ فحص Headers
    const requiredHeaders = ['accept', 'accept-language', 'accept-encoding'];
    const missingHeaders = requiredHeaders.filter(h => !req.headers[h]);
    if (missingHeaders.length > 0) {
        suspicionScore += missingHeaders.length * 2;
        reasons.push(`Missing headers: ${missingHeaders.join(', ')}`);
    }

    // 3️⃣ فحص Content-Type
    if (req.method === 'POST' && !req.headers['content-type']) {
        suspicionScore += 2;
        reasons.push('No Content-Type');
    }

    // 4️⃣ فحص Body
    const bodySize = JSON.stringify(req.body).length;
    if (bodySize > 10000) {
        suspicionScore += 3;
        reasons.push('Oversized Request');
    }

    // 5️⃣ فحص SQL Injection / XSS
    const bodyString = JSON.stringify(req.body).toLowerCase();
    const maliciousPatterns = [
        /union.*select/i, /drop.*table/i, /insert.*into/i,
        /<script>/i, /javascript:/i, /onerror=/i,
        /\.\.\/\.\.\//g,
        /exec\s*\(/i, /eval\s*\(/i
    ];
    
    if (maliciousPatterns.some(regex => regex.test(bodyString))) {
        suspicionScore += 10;
        reasons.push('Malicious Payload (SQL/XSS)');
        
        // 🔔 إشعار فوري
        sendSecurityAlert('SQL_INJECTION', {
            ip,
            endpoint: req.path,
            payload: bodyString.substring(0, 200),
            userAgent
        });
    }

    // 6️⃣ فحص معدل الطلبات
    suspicious.count++;
    const timeWindow = Date.now() - suspicious.firstSeen;
    if (timeWindow < 60000 && suspicious.count > 20) {
        suspicionScore += 8;
        reasons.push('Rapid Requests (DDoS)');
        
        // 🔔 إشعار DDoS
        sendSecurityAlert('DDOS_ATTEMPT', {
            ip,
            requestCount: suspicious.count,
            timeWindow: '60 ثانية',
            status: 'تم تفعيل الحد من المعدل',
            userAgent
        });
    }

    suspiciousIPs.set(ip, suspicious);

    // ══════════════════════════════════════════
    // 🚨 اتخاذ إجراء + إشعار
    // ══════════════════════════════════════════
    if (suspicionScore >= 10) {
        blockedIPs.set(ip, {
            until: Date.now() + 3600000,
            reason: reasons.join(', ')
        });
        
        dailyStats.blockedIPs++;
        
        console.error(`🚨 BLOCKED: ${ip} | Score: ${suspicionScore}`);
        
        // 🔔 إشعار حظر IP
        sendSecurityAlert('IP_BLOCKED', {
            ip,
            reason: reasons.join(', '),
            score: suspicionScore,
            duration: 'ساعة واحدة',
            userAgent
        });
        
        return res.status(403).json({
            success: false,
            code: 403,
            error: 'Suspicious activity detected'
        });
    } else if (suspicionScore >= 5) {
        dailyStats.suspiciousRequests++;
        
        console.warn(`⚠️ Suspicious: ${ip} | Score: ${suspicionScore}`);
        
        // 🔔 إشعار نشاط مشبوه
        sendSecurityAlert('SUSPICIOUS_ACTIVITY', {
            ip,
            details: reasons.join(', '),
            score: suspicionScore,
            action: 'تأخير 2 ثانية'
        });
        
        return new Promise(resolve => setTimeout(resolve, 2000))
            .then(() => next());
    }

    next();
};

// ══════════════════════════════════════════
// 🔐 Rate Limiter - مع إشعار
// ══════════════════════════════════════════
const userRateLimiter = async (req, res, next) => {
    const { username } = req.body;
    if (!username) return next();

    const key = `rate:${username}`;
    const attempts = failedAttempts.get(key) || { count: 0, lastAttempt: 0 };
    const now = Date.now();

    if (now - attempts.lastAttempt > 900000) {
        failedAttempts.delete(key);
        return next();
    }

    if (attempts.count >= 5) {
        const ip = getClientIP(req);
        const waitTime = Math.ceil((900000 - (now - attempts.lastAttempt)) / 1000 / 60);
        
        console.warn(`⏱️ Rate limit: ${username} from ${ip}`);
        
        // 🔔 إشعار Brute Force
        if (attempts.count === 5) { // فقط عند أول حظر
            const timeSinceFirst = Math.ceil((now - attempts.firstAttempt) / 1000 / 60);
            sendSecurityAlert('BRUTE_FORCE', {
                username,
                ip,
                attempts: attempts.count,
                lastAttempt: `منذ ${timeSinceFirst} دقيقة`
            });
        }
        
        return res.status(429).json({
            success: false,
            code: 429,
            error: 'Too many attempts'
        });
    }

    next();
};

router.use(checkBlockedIP);
router.use(detectMaliciousRequest);

// ═══════════════════════════════════════════
// ✅ VERIFY ACCOUNT
// ═══════════════════════════════════════════
router.post('/verifyAccount', 
    verifySignature, 
    authApp, 
    apiLimiter, 
    userRateLimiter,
    async (req, res) => {
        const startTime = Date.now();
        const ip = getClientIP(req);
        
        try {
            const { username, password, deviceId } = req.body;

            if (!username || !password || !deviceId) {
                return res.status(400).json({
                    success: false,
                    error: 'Missing required fields',
                    code: 400
                });
            }

            const cleanUsername = username.trim().toLowerCase();
            
            const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(cleanUsername)}"&auth=${FB_KEY}`;
            const response = await firebase.get(url);
            const users = response.data || {};

            const userExists = Object.keys(users).length > 0;
            const userId = userExists ? Object.keys(users)[0] : null;
            const user = userExists ? users[userId] : null;
            
            const dummyHash = '$2b$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW';
            const hashToCheck = user ? user.password_hash : dummyHash;
            const passwordValid = verifyPassword(password, hashToCheck);

            if (!userExists || !passwordValid) {
                const key = `rate:${cleanUsername}`;
                const attempts = failedAttempts.get(key) || { count: 0, lastAttempt: 0, firstAttempt: Date.now() };
                failedAttempts.set(key, {
                    count: attempts.count + 1,
                    lastAttempt: Date.now(),
                    firstAttempt: attempts.firstAttempt
                });

                dailyStats.failedAttempts++;
                
                console.warn(`❌ Failed: ${cleanUsername} from ${ip} (${attempts.count + 1})`);
                
                return res.json({ 
                    success: false, 
                    code: 401,
                    error: 'Invalid credentials'
                });
            }

            failedAttempts.delete(`rate:${cleanUsername}`);

            if (!user.is_active) {
                return res.json({ success: false, code: 403, error: 'Account disabled' });
            }

            // 🔔 إشعار عدم تطابق الجهاز
            if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
                sendSecurityAlert('DEVICE_MISMATCH', {
                    username: cleanUsername,
                    ip,
                    expectedDevice: user.device_id.substring(0, 8) + '***',
                    actualDevice: deviceId.substring(0, 8) + '***'
                });
                
                return res.json({ success: false, code: 409, error: 'Device not authorized' });
            }

            const now = Date.now();
            if (!user.subscription_end || user.subscription_end <= now) {
                return res.json({ success: false, code: 402, error: 'Subscription expired' });
            }

            // ✅ نجاح
            dailyStats.successfulLogins++;
            dailyStats.uniqueUsers.add(cleanUsername);
            
            console.log(`✅ Success: ${cleanUsername} from ${ip}`);

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
            console.error('❌ Error:', error.message);
            res.status(500).json({
                success: false,
                code: 500,
                error: 'Server error'
            });
        }
    }
);

// ═══════════════════════════════════════════
// 📱 UPDATE DEVICE
// ═══════════════════════════════════════════
router.post('/updateDevice', 
    verifySignature, 
    authApp, 
    apiLimiter,
    async (req, res) => {
        try {
            const { username, deviceId, deviceInfo } = req.body;

            if (!username || !deviceId) {
                return res.status(400).json({
                    success: false,
                    error: 'Missing required data'
                });
            }

            const cleanUsername = username.trim().toLowerCase();
            const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(cleanUsername)}"&auth=${FB_KEY}`;
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

            const sanitize = (str, max = 100) => {
                if (!str) return 'Unknown';
                return String(str).substring(0, max).replace(/[<>]/g, '');
            };

            const updateData = {
                device_id: deviceId,
                last_login: Date.now(),
                login_count: (user.login_count || 0) + 1,
                ip_address: ip,
                user_agent: sanitize(req.headers['user-agent'] || '', 200)
            };

            if (deviceInfo) {
                updateData.device_model = sanitize(deviceInfo.device_model);
                updateData.device_brand = sanitize(deviceInfo.device_brand);
                updateData.android_version = sanitize(deviceInfo.android_version, 20);
                updateData.is_rooted = Boolean(deviceInfo.is_rooted);
                updateData.network_type = sanitize(deviceInfo.network_type, 20);
                
                // 🔔 إشعار Rooted Device
                if (deviceInfo.is_rooted) {
                    dailyStats.rootedDevices++;
                    
                    sendSecurityAlert('ROOTED_DEVICE', {
                        username: cleanUsername,
                        device: `${deviceInfo.device_brand} ${deviceInfo.device_model}`,
                        ip,
                        os: deviceInfo.android_version
                    });
                }
            }

            const loginEntry = {
                timestamp: Date.now(),
                ip,
                device: updateData.device_model,
                is_rooted: updateData.is_rooted
            };

            updateData.login_history = [
                ...(user.login_history || []).slice(-19),
                loginEntry
            ];

            await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, updateData);

            res.json({
                success: true,
                message: 'Device updated',
                user_info: {
                    username: user.username,
                    login_count: updateData.login_count,
                    is_rooted: updateData.is_rooted
                }
            });

        } catch (error) {
            console.error('❌ Error:', error.message);
            res.status(500).json({ success: false, error: 'Server error' });
        }
    }
);

// ═══════════════════════════════════════════
// 📊 ADMIN: إحصائيات
// ═══════════════════════════════════════════
router.get('/admin/stats', authApp, (req, res) => {
    const topIPs = Array.from(dailyStats.ipActivity.entries())
        .map(([address, count]) => ({ address, count }))
        .sort((a, b) => b.count - a.count);

    res.json({
        blockedIPs: dailyStats.blockedIPs,
        failedAttempts: dailyStats.failedAttempts,
        suspiciousRequests: dailyStats.suspiciousRequests,
        rootedDevices: dailyStats.rootedDevices,
        successfulLogins: dailyStats.successfulLogins,
        uniqueUsers: dailyStats.uniqueUsers.size,
        totalRequests: dailyStats.totalRequests,
        topIPs: topIPs.slice(0, 10),
        currentlyBlocked: blockedIPs.size
    });
});

module.exports = router;
