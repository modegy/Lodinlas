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
        
        // تحقق من أن بيانات الاعتماد موجودة
        if (!config.ADMIN_CREDENTIALS || !config.ADMIN_CREDENTIALS.username || !config.ADMIN_CREDENTIALS.password) {
            console.error('❌ Admin credentials not configured');
            return res.status(500).json({ success: false, error: 'Admin system not configured' });
        }
        
        await new Promise(resolve => setTimeout(resolve, 1000)); // Rate limiting delay
        
        if (username !== config.ADMIN_CREDENTIALS.username || password !== config.ADMIN_CREDENTIALS.password) {
            const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
            attempt.count++;
            attempt.lastAttempt = Date.now();
            loginAttempts.set(ip, attempt);
            
            // تسجيل محاولة الدخول الفاشلة
            console.log(`❌ Failed admin login attempt from ${ip}: ${username}`);
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
        
        // نجاح تسجيل الدخول
        loginAttempts.delete(ip);
        const sessionToken = generateToken();
        
        adminSessions.set(sessionToken, { 
            username, 
            ip, 
            createdAt: Date.now(), 
            userAgent: req.headers['user-agent'],
            lastActive: Date.now()
        });
        
        console.log(`✅ Admin login successful: ${username} from ${ip}`);
        res.json({ 
            success: true, 
            sessionToken, 
            expiresIn: config.SESSION?.EXPIRY || 86400000,
            username,
            timestamp: Date.now()
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

router.post('/logout', authAdmin, (req, res) => {
    try {
        const sessionToken = req.headers['x-session-token'];
        if (sessionToken && adminSessions.has(sessionToken)) {
            const session = adminSessions.get(sessionToken);
            console.log(`👋 Admin logout: ${session.username} from ${session.ip}`);
            adminSessions.delete(sessionToken);
        }
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ success: false, error: 'Logout failed' });
    }
});

router.get('/verify-session', authAdmin, (req, res) => {
    try {
        const sessionToken = req.headers['x-session-token'];
        const session = adminSessions.get(sessionToken);
        
        if (!session) {
            return res.status(401).json({ success: false, error: 'Session expired or invalid' });
        }
        
        // تحديث وقت النشاط الأخير
        session.lastActive = Date.now();
        adminSessions.set(sessionToken, session);
        
        const expiresIn = (config.SESSION?.EXPIRY || 86400000) - (Date.now() - session.createdAt);
        const minutesLeft = Math.max(0, Math.floor(expiresIn / 1000 / 60));
        
        res.json({
            success: true,
            session: { 
                username: session.username, 
                expires_in: minutesLeft + ' minutes',
                ip: session.ip,
                created_at: session.createdAt
            },
            server_info: { 
                active_sessions: adminSessions.size, 
                uptime: Math.floor(process.uptime()),
                memory_usage: process.memoryUsage().heapUsed / 1024 / 1024 + ' MB'
            }
        });
    } catch (error) {
        console.error('Verify session error:', error);
        res.status(500).json({ success: false, error: 'Session verification failed' });
    }
});

// ═══════════════════════════════════════════
// USERS MANAGEMENT - إدارة المستخدمين
// ═══════════════════════════════════════════
router.get('/users', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        
        const formattedUsers = {};
        let activeCount = 0;
        let expiredCount = 0;
        const now = Date.now();
        
        for (const [id, user] of Object.entries(users)) {
            const isExpired = user.subscription_end && user.subscription_end < now;
            const isActive = user.is_active !== false && !isExpired;
            
            if (isActive) activeCount++;
            if (isExpired) expiredCount++;
            
            formattedUsers[id] = {
                id,
                username: user.username || '',
                is_active: isActive,
                expiry_timestamp: user.subscription_end || 0,
                expiry_date: formatDate(user.subscription_end),
                created_at: user.created_at ? formatDate(user.created_at) : null,
                last_login: user.last_login ? formatDate(user.last_login) : null,
                device_id: user.device_id || '',
                created_by_key: user.created_by_key || 'master',
                status: isActive ? 'active' : (isExpired ? 'expired' : 'inactive')
            };
        }
        
        res.json({ 
            success: true, 
            data: formattedUsers, 
            count: Object.keys(formattedUsers).length,
            stats: {
                active: activeCount,
                expired: expiredCount,
                inactive: Object.keys(formattedUsers).length - activeCount - expiredCount
            }
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch users' });
    }
});

router.post('/users', authAdmin, async (req, res) => {
    try {
        const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password required' });
        }
        
        // التحقق من صحة اسم المستخدم
        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ success: false, error: 'Username must be between 3-20 characters' });
        }
        
        // التحقق من صحة كلمة المرور
        if (password.length < 4) {
            return res.status(400).json({ success: false, error: 'Password must be at least 4 characters' });
        }
        
        // التحقق من عدم وجود مستخدم بنفس الاسم
        const checkUrl = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const checkRes = await firebase.get(checkUrl);
        if (checkRes.data && Object.keys(checkRes.data).length > 0) {
            return res.status(400).json({ success: false, error: 'Username already exists' });
        }
        
        // حساب وقت الانتهاء
        let expiryTimestamp;
        if (customExpiryDate) {
            expiryTimestamp = new Date(customExpiryDate).getTime();
            if (isNaN(expiryTimestamp)) {
                return res.status(400).json({ success: false, error: 'Invalid date format' });
            }
        } else if (expiryMinutes) {
            expiryTimestamp = Date.now() + (expiryMinutes * 60 * 1000);
        } else {
            return res.status(400).json({ success: false, error: 'Expiry time required' });
        }
        
        // التأكد من أن وقت الانتهاء في المستقبل
        if (expiryTimestamp <= Date.now()) {
            return res.status(400).json({ success: false, error: 'Expiry time must be in the future' });
        }
        
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
        console.log(`✅ User created: ${username} (ID: ${createRes.data.name})`);
        
        res.json({ 
            success: true, 
            message: 'User created successfully',
            userId: createRes.data.name,
            username,
            expiry_date: formatDate(expiryTimestamp)
        });
        
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ success: false, error: 'Failed to create user' });
    }
});

router.delete('/users/:id', authAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        // التحقق من وجود المستخدم أولاً
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        await firebase.delete(`users/${userId}.json?auth=${FB_KEY}`);
        console.log(`🗑️ User deleted: ${userId} (${userRes.data.username})`);
        
        res.json({ 
            success: true, 
            message: 'User deleted successfully',
            deletedUser: { id: userId, username: userRes.data.username }
        });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ success: false, error: 'Failed to delete user' });
    }
});

router.post('/users/:id/extend', authAdmin, async (req, res) => {
    try {
        const { minutes, days, hours } = req.body;
        const userId = req.params.id;
        
        if (!minutes && !days && !hours) {
            return res.status(400).json({ success: false, error: 'Extension time required (minutes, days, or hours)' });
        }
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const user = userRes.data;
        const now = Date.now();
        const currentEnd = user.subscription_end || now;
        
        // حساب وقت التمديد
        let extensionMs = 0;
        if (minutes) extensionMs = minutes * 60 * 1000;
        if (days) extensionMs += days * 24 * 60 * 60 * 1000;
        if (hours) extensionMs += hours * 60 * 60 * 1000;
        
        const newEndDate = Math.max(currentEnd, now) + extensionMs;
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
            subscription_end: newEndDate, 
            is_active: true 
        });
        
        console.log(`📅 User extended: ${user.username} (ID: ${userId})`);
        
        res.json({ 
            success: true, 
            message: 'Subscription extended successfully',
            userId,
            username: user.username,
            old_end_date: formatDate(currentEnd),
            new_end_date: formatDate(newEndDate),
            extension_ms: extensionMs
        });
    } catch (error) {
        console.error('Error extending user:', error);
        res.status(500).json({ success: false, error: 'Failed to extend subscription' });
    }
});

router.post('/users/:id/reset-device', authAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
            device_id: '',
            last_device_reset: Date.now()
        });
        
        console.log(`🔄 Device reset for user: ${userId} (${userRes.data.username})`);
        
        res.json({ 
            success: true, 
            message: 'Device reset successfully',
            userId,
            username: userRes.data.username
        });
    } catch (error) {
        console.error('Error resetting device:', error);
        res.status(500).json({ success: false, error: 'Failed to reset device' });
    }
});

// ═══════════════════════════════════════════
// USER STATUS MANAGEMENT - إدارة حالة المستخدمين
// ═══════════════════════════════════════════
router.post('/disable-user', authAdmin, async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) {
            return res.status(400).json({ success: false, error: 'User ID is required' });
        }

        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
            is_active: false,
            disabled_at: Date.now(),
            disabled_by: 'admin',
            status_note: 'Manually disabled by admin'
        });

        console.log(`🚫 User disabled: ${userId} (${userRes.data.username})`);
        
        res.json({ 
            success: true, 
            message: 'User disabled successfully',
            userId,
            username: userRes.data.username
        });
    } catch (error) {
        console.error('Error disabling user:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to disable user'
        });
    }
});

router.post('/enable-user', authAdmin, async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) {
            return res.status(400).json({ success: false, error: 'User ID is required' });
        }

        const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
        if (!userRes.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        // التحقق من أن الاشتراك لم ينتهِ
        const now = Date.now();
        const isExpired = userRes.data.subscription_end && userRes.data.subscription_end < now;
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
            is_active: !isExpired,
            enabled_at: Date.now(),
            enabled_by: 'admin',
            status_note: isExpired ? 'Enabled but subscription expired' : 'Manually enabled by admin'
        });

        console.log(`✅ User enabled: ${userId} (${userRes.data.username})`);
        
        res.json({ 
            success: true, 
            message: isExpired ? 'User enabled but subscription has expired' : 'User enabled successfully',
            userId,
            username: userRes.data.username,
            is_expired: isExpired
        });
    } catch (error) {
        console.error('Error enabling user:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to enable user'
        });
    }
});

router.post('/bulk-disable-expired', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};

        const now = Date.now();
        let disabledCount = 0;

        for (const userId in users) {
            const user = users[userId];
            // تعطيل المستخدمين المنتهية صلاحيتهم والنشطين
            if (user.subscription_end && user.subscription_end < now && user.is_active !== false) {
                await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, { 
                    is_active: false,
                    auto_disabled_at: Date.now(),
                    reason: 'Subscription expired',
                    status_note: 'Auto-disabled: Subscription expired'
                });
                disabledCount++;
                console.log(`Auto-disabled expired user: ${userId} (${user.username})`);
            }
        }

        res.json({ 
            success: true, 
            message: `Disabled ${disabledCount} expired users`,
            count: disabledCount,
            timestamp: Date.now()
        });
    } catch (error) {
        console.error('Error bulk disabling expired users:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to disable expired users' 
        });
    }
});

router.delete('/delete-expired', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};

        const now = Date.now();
        let deletedCount = 0;
        const deletedUsers = [];

        for (const userId in users) {
            const user = users[userId];
            // حذف المستخدمين المنتهية صلاحيتهم
            if (user.subscription_end && user.subscription_end < now) {
                await firebase.delete(`users/${userId}.json?auth=${FB_KEY}`);
                deletedCount++;
                deletedUsers.push({ id: userId, username: user.username });
                console.log(`🗑️ Deleted expired user: ${userId} (${user.username})`);
            }
        }

        res.json({ 
            success: true, 
            message: `Deleted ${deletedCount} expired users`,
            count: deletedCount,
            deleted_users: deletedUsers,
            timestamp: Date.now()
        });
    } catch (error) {
        console.error('Error deleting expired users:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to delete expired users' 
        });
    }
});

router.delete('/delete-inactive', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};

        let deletedCount = 0;
        const deletedUsers = [];

        for (const userId in users) {
            const user = users[userId];
            // حذف المستخدمين المعطلين
            if (user.is_active === false) {
                await firebase.delete(`users/${userId}.json?auth=${FB_KEY}`);
                deletedCount++;
                deletedUsers.push({ id: userId, username: user.username });
                console.log(`🗑️ Deleted inactive user: ${userId} (${user.username})`);
            }
        }

        res.json({ 
            success: true, 
            message: `Deleted ${deletedCount} inactive users`,
            count: deletedCount,
            deleted_users: deletedUsers,
            timestamp: Date.now()
        });
    } catch (error) {
        console.error('Error deleting inactive users:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to delete inactive users' 
        });
    }
});

// ═══════════════════════════════════════════
// API KEYS MANAGEMENT
// ═══════════════════════════════════════════
router.get('/api-keys', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
        const keys = response.data || {};
        
        const now = Date.now();
        const formattedKeys = {};
        let activeCount = 0;
        let expiredCount = 0;
        
        for (const [id, key] of Object.entries(keys)) {
            const isExpired = key.expiry_timestamp && key.expiry_timestamp < now;
            const isActive = key.is_active !== false && !isExpired;
            
            if (isActive) activeCount++;
            if (isExpired) expiredCount++;
            
            formattedKeys[id] = {
                id,
                api_key: key.api_key ? key.api_key.substring(0, 8) + '...' : '',
                admin_name: key.admin_name || '',
                permission_level: key.permission_level || 'view_only',
                is_active: isActive,
                expiry_timestamp: key.expiry_timestamp || null,
                expiry_date: formatDate(key.expiry_timestamp),
                created_at: key.created_at ? formatDate(key.created_at) : null,
                signing_secret: key.signing_secret ? '••••••••' : null,
                status: isActive ? 'active' : (isExpired ? 'expired' : 'inactive')
            };
        }
        
        res.json({ 
            success: true, 
            data: formattedKeys,
            stats: {
                total: Object.keys(formattedKeys).length,
                active: activeCount,
                expired: expiredCount,
                inactive: Object.keys(formattedKeys).length - activeCount - expiredCount
            }
        });
    } catch (error) {
        console.error('Error fetching API keys:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch API keys' });
    }
});

router.post('/api-keys', authAdmin, async (req, res) => {
    try {
        const { adminName, permissionLevel, expiryDays } = req.body;
        
        if (!adminName || adminName.trim().length < 2) {
            return res.status(400).json({ success: false, error: 'Admin name must be at least 2 characters' });
        }
        
        const apiKey = generateApiKey();
        const signingSecret = generateSigningSecret();
        const expiryTimestamp = Date.now() + ((expiryDays || 30) * 24 * 60 * 60 * 1000);
        
        const keyData = {
            api_key: apiKey,
            admin_name: adminName.trim(),
            permission_level: permissionLevel || 'view_only',
            is_active: true,
            expiry_timestamp: expiryTimestamp,
            created_at: Date.now(),
            signing_secret: signingSecret,
            created_by: 'admin_panel'
        };
        
        const response = await firebase.post(`api_keys.json?auth=${FB_KEY}`, keyData);
        const keyId = response.data.name;
        
        console.log(`🔑 API Key created for: ${adminName} (ID: ${keyId})`);
        
        res.json({ 
            success: true, 
            message: 'API Key created successfully',
            keyId,
            apiKey,
            signingSecret,
            adminName: adminName.trim(),
            expiry_date: formatDate(expiryTimestamp),
            warning: 'Save the signing secret immediately! It will not be shown again.'
        });
    } catch (error) {
        console.error('Error creating API key:', error);
        res.status(500).json({ success: false, error: 'Failed to create API key' });
    }
});

// ═══════════════════════════════════════════
// SECURITY STATS
// ═══════════════════════════════════════════
router.get('/security-stats', authAdmin, (req, res) => {
    try {
        const now = Date.now();
        const oneHourAgo = now - (60 * 60 * 1000);
        
        // تنظيف محاولات الدخول القديمة
        for (const [ip, data] of loginAttempts.entries()) {
            if (data.lastAttempt < oneHourAgo) {
                loginAttempts.delete(ip);
            }
        }
        
        // تنظيف تتبع الطلبات القديمة
        for (const [ip, data] of requestTracker.entries()) {
            if (data.lastRequest < oneHourAgo) {
                requestTracker.delete(ip);
            }
        }
        
        res.json({
            success: true,
            stats: {
                tracked_ips: requestTracker.size,
                blocked_ips: blockedIPs.size,
                blocked_list: Array.from(blockedIPs).slice(0, 20),
                active_sessions: adminSessions.size,
                login_attempts: Array.from(loginAttempts.entries()).map(([ip, data]) => ({ 
                    ip, 
                    attempts: data.count,
                    last_attempt: formatDate(data.lastAttempt)
                })).slice(0, 20),
                request_stats: Array.from(requestTracker.entries()).map(([ip, data]) => ({
                    ip,
                    count: data.count,
                    last_request: formatDate(data.lastRequest)
                })).slice(0, 20)
            },
            timestamp: now
        });
    } catch (error) {
        console.error('Error getting security stats:', error);
        res.status(500).json({ success: false, error: 'Failed to get security stats' });
    }
});

router.post('/unblock-ip', authAdmin, (req, res) => {
    try {
        const { ip } = req.body;
        if (!ip) {
            return res.status(400).json({ success: false, error: 'IP address required' });
        }
        
        const wasBlocked = blockedIPs.has(ip);
        blockedIPs.delete(ip);
        requestTracker.delete(ip);
        
        console.log(`🔓 IP unblocked: ${ip} (was blocked: ${wasBlocked})`);
        
        res.json({ 
            success: true, 
            message: `IP ${ip} has been unblocked`,
            ip,
            was_blocked: wasBlocked,
            timestamp: Date.now()
        });
    } catch (error) {
        console.error('Error unblocking IP:', error);
        res.status(500).json({ success: false, error: 'Failed to unblock IP' });
    }
});

// ═══════════════════════════════════════════
// ADMIN UTILITIES
// ═══════════════════════════════════════════
router.get('/server-stats', authAdmin, (req, res) => {
    try {
        const memoryUsage = process.memoryUsage();
        const stats = {
            uptime: Math.floor(process.uptime()),
            uptime_formatted: formatUptime(process.uptime()),
            memory: {
                heap_used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + ' MB',
                heap_total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + ' MB',
                rss: Math.round(memoryUsage.rss / 1024 / 1024) + ' MB'
            },
            timestamp: Date.now(),
            date: new Date().toISOString(),
            version: config.VERSION || '3.3.0',
            node_version: process.version,
            platform: process.platform,
            arch: process.arch,
            environment: process.env.NODE_ENV || 'production',
            pid: process.pid,
            admin_sessions: adminSessions.size
        };
        
        res.json({ success: true, stats });
    } catch (error) {
        console.error('Error getting server stats:', error);
        res.status(500).json({ success: false, error: 'Failed to get server stats' });
    }
});

router.get('/endpoints', authAdmin, (req, res) => {
    const endpoints = [
        { method: 'POST', path: '/api/admin/login', description: 'تسجيل دخول الأدمن', auth: false },
        { method: 'POST', path: '/api/admin/logout', description: 'تسجيل خروج الأدمن', auth: true },
        { method: 'GET', path: '/api/admin/verify-session', description: 'التحقق من الجلسة', auth: true },
        { method: 'GET', path: '/api/admin/users', description: 'جلب جميع المستخدمين', auth: true },
        { method: 'POST', path: '/api/admin/users', description: 'إنشاء مستخدم جديد', auth: true },
        { method: 'DELETE', path: '/api/admin/users/:id', description: 'حذف مستخدم', auth: true },
        { method: 'POST', path: '/api/admin/users/:id/extend', description: 'تمديد اشتراك مستخدم', auth: true },
        { method: 'POST', path: '/api/admin/users/:id/reset-device', description: 'إعادة تعيين جهاز المستخدم', auth: true },
        { method: 'POST', path: '/api/admin/disable-user', description: 'تعطيل مستخدم', auth: true },
        { method: 'POST', path: '/api/admin/enable-user', description: 'تفعيل مستخدم', auth: true },
        { method: 'DELETE', path: '/api/admin/delete-expired', description: 'حذف المستخدمين المنتهية صلاحيتهم', auth: true },
        { method: 'DELETE', path: '/api/admin/delete-inactive', description: 'حذف المستخدمين المعطلين', auth: true },
        { method: 'POST', path: '/api/admin/bulk-disable-expired', description: 'تعطيل جميع المستخدمين المنتهية صلاحيتهم', auth: true },
        { method: 'GET', path: '/api/admin/api-keys', description: 'جلب مفاتيح API', auth: true },
        { method: 'POST', path: '/api/admin/api-keys', description: 'إنشاء مفتاح API جديد', auth: true },
        { method: 'GET', path: '/api/admin/security-stats', description: 'إحصائيات الأمان', auth: true },
        { method: 'POST', path: '/api/admin/unblock-ip', description: 'إلغاء حظر عنوان IP', auth: true },
        { method: 'GET', path: '/api/admin/server-stats', description: 'إحصائيات الخادم', auth: true },
        { method: 'GET', path: '/api/admin/endpoints', description: 'قائمة نقاط النهاية المتاحة', auth: true }
    ];
    
    res.json({ 
        success: true, 
        endpoints,
        count: endpoints.length,
        timestamp: Date.now()
    });
});

// دالة مساعدة لتنسيق وقت التشغيل
function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    const parts = [];
    if (days > 0) parts.push(`${days} يوم`);
    if (hours > 0) parts.push(`${hours} ساعة`);
    if (minutes > 0) parts.push(`${minutes} دقيقة`);
    if (secs > 0) parts.push(`${secs} ثانية`);
    
    return parts.join(' و ') || '0 ثانية';
}

module.exports = router;
