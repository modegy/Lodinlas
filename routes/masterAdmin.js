const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const { firebase, FB_KEY } = require('../config/database');
const { ADMIN_CREDENTIALS, adminSessions, loginAttempts } = require('../config/constants');
const { authAdmin } = require('../middleware/auth');
const { loginLimiter, apiLimiter, bruteForceProtection, getSecurityStats, unblockIP } = require('../middleware/security');
const { generateToken, hashPassword, formatDate, getClientIP } = require('../utils/helpers');

// ═══════════════════════════════════════════
// 👑 AUTH ENDPOINTS
// ═══════════════════════════════════════════
router.post('/login', loginLimiter, bruteForceProtection, async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = getClientIP(req);

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username and password required'
            });
        }

        await new Promise(resolve => setTimeout(resolve, 1000));

        if (username !== ADMIN_CREDENTIALS.username || password !== ADMIN_CREDENTIALS.password) {
            const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
            attempt.count++;
            attempt.lastAttempt = Date.now();
            loginAttempts.set(ip, attempt);

            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }

        loginAttempts.delete(ip);
        const sessionToken = generateToken();

        adminSessions.set(sessionToken, {
            username,
            ip,
            createdAt: Date.now(),
            userAgent: req.headers['user-agent']
        });

        console.log(`✅ Admin login: ${username} from ${ip}`);

        res.json({
            success: true,
            sessionToken,
            expiresIn: '24 hours'
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Server error'
        });
    }
});

router.post('/logout', authAdmin, (req, res) => {
    const sessionToken = req.headers['x-session-token'];
    if (sessionToken) {
        adminSessions.delete(sessionToken);
    }
    res.json({
        success: true,
        message: 'Logged out'
    });
});

router.get('/verify-session', authAdmin, (req, res) => {
    const sessionToken = req.headers['x-session-token'];
    const session = adminSessions.get(sessionToken);

    if (!session) {
        return res.json({ success: true, session: { username: 'master_owner' } });
    }

    const expiresIn = 24 * 60 * 60 * 1000 - (Date.now() - session.createdAt);

    res.json({
        success: true,
        session: {
            username: session.username,
            expires_in: Math.floor(expiresIn / 1000 / 60) + ' minutes'
        },
        server_info: {
            active_sessions: adminSessions.size,
            uptime: Math.floor(process.uptime())
        }
    });
});

// ═══════════════════════════════════════════
// 👥 USER MANAGEMENT
// ═══════════════════════════════════════════
router.get('/users', authAdmin, apiLimiter, async (req, res) => {
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
                max_devices: user.max_devices || 1,
                notes: user.notes || '',
                created_by_key: user.created_by_key || 'master'
            };
        }

        res.json({
            success: true,
            data: formattedUsers,
            count: Object.keys(formattedUsers).length
        });

    } catch (error) {
        console.error('Get users error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch users'
        });
    }
});

router.get('/users/:id', authAdmin, apiLimiter, async (req, res) => {
    try {
        const response = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);

        if (!response.data) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        const user = response.data;
        res.json({
            success: true,
            data: {
                id: req.params.id,
                username: user.username,
                is_active: user.is_active !== false,
                expiry_timestamp: user.subscription_end || 0,
                expiry_date: formatDate(user.subscription_end),
                device_id: user.device_id || '',
                max_devices: user.max_devices || 1,
                created_by_key: user.created_by_key || 'master'
            }
        });

    } catch (error) {
        console.error('Get user error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch user'
        });
    }
});

router.post('/users', authAdmin, apiLimiter, async (req, res) => {
    try {
        const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username and password required'
            });
        }

        const checkUrl = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const checkRes = await firebase.get(checkUrl);

        if (checkRes.data && Object.keys(checkRes.data).length > 0) {
            return res.status(400).json({
                success: false,
                error: 'Username already exists'
            });
        }

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

        console.log(`✅ User created by Master Admin: ${username}`);

        res.json({
            success: true,
            message: 'User created',
            userId: createRes.data.name
        });

    } catch (error) {
        console.error('Create user error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to create user'
        });
    }
});

router.patch('/users/:id', authAdmin, apiLimiter, async (req, res) => {
    try {
        const { is_active, max_devices, notes } = req.body;
        const updateData = {};

        if (typeof is_active === 'boolean') updateData.is_active = is_active;
        if (max_devices) updateData.max_devices = max_devices;
        if (notes !== undefined) updateData.notes = notes;

        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, updateData);

        res.json({
            success: true,
            message: 'User updated'
        });

    } catch (error) {
        console.error('Update user error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to update user'
        });
    }
});

router.delete('/users/:id', authAdmin, apiLimiter, async (req, res) => {
    try {
        await firebase.delete(`users/${req.params.id}.json?auth=${FB_KEY}`);

        console.log(`🗑️ User deleted: ${req.params.id}`);

        res.json({
            success: true,
            message: 'User deleted'
        });

    } catch (error) {
        console.error('Delete user error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to delete user'
        });
    }
});

router.post('/users/delete-expired', authAdmin, apiLimiter, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        const now = Date.now();

        const deletePromises = [];
        let expiredIds = [];

        for (const [id, user] of Object.entries(users)) {
            if (user.subscription_end && user.subscription_end <= now) {
                expiredIds.push(id);
                deletePromises.push(
                    firebase.delete(`users/${id}.json?auth=${FB_KEY}`)
                );
            }
        }

        if (deletePromises.length === 0) {
            return res.json({
                success: true,
                message: 'No expired users found',
                count: 0
            });
        }

        await Promise.all(deletePromises);

        console.log(`🗑️ Bulk deleted ${expiredIds.length} expired users`);

        res.json({
            success: true,
            message: `Deleted ${expiredIds.length} expired users`,
            count: expiredIds.length
        });

    } catch (error) {
        console.error('Delete expired error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to delete expired users'
        });
    }
});

router.post('/users/:id/extend', authAdmin, apiLimiter, async (req, res) => {
    try {
        const { minutes, days, hours } = req.body;

        const userRes = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);

        if (!userRes.data) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        const user = userRes.data;
        const now = Date.now();
        const currentEnd = user.subscription_end || now;

        let extensionMs = 0;
        if (minutes) {
            extensionMs = minutes * 60 * 1000;
        } else if (days || hours) {
            extensionMs = ((days || 0) * 24 * 60 * 60 * 1000) + ((hours || 0) * 60 * 60 * 1000);
        }

        if (!extensionMs) {
            return res.status(400).json({
                success: false,
                error: 'Extension time required'
            });
        }

        const newEndDate = (currentEnd > now ? currentEnd : now) + extensionMs;

        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, {
            subscription_end: newEndDate,
            is_active: true
        });

        res.json({
            success: true,
            message: 'Subscription extended',
            new_end_date: newEndDate
        });

    } catch (error) {
        console.error('Extend subscription error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to extend subscription'
        });
    }
});

router.post('/users/:id/reset-device', authAdmin, apiLimiter, async (req, res) => {
    try {
        await firebase.patch(`users/${req.params.id}.json?auth=${FB_KEY}`, {
            device_id: ''
        });

        console.log(`🔄 Device reset for user: ${req.params.id}`);

        res.json({
            success: true,
            message: 'Device reset'
        });

    } catch (error) {
        console.error('Reset device error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to reset device'
        });
    }
});

router.get('/users/:id/login-history', authAdmin, apiLimiter, async (req, res) => {
    try {
        const response = await firebase.get(`users/${req.params.id}.json?auth=${FB_KEY}`);

        if (!response.data) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const user = response.data;
        const history = user.login_history || [];

        res.json({
            success: true,
            data: {
                username: user.username,
                total_logins: user.login_count || 0,
                login_history: history.reverse()
            }
        });

    } catch (error) {
        console.error('Login history error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch login history' });
    }
});

// ═══════════════════════════════════════════
// 🔑 API KEYS MANAGEMENT
// ═══════════════════════════════════════════
router.get('/api-keys', authAdmin, apiLimiter, async (req, res) => {
    try {
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
                signing_secret: key.signing_secret ? '*****' : null
            };
        }

        res.json({
            success: true,
            data: formattedKeys,
            count: Object.keys(formattedKeys).length
        });

    } catch (error) {
        console.error('Get API keys error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch API keys'
        });
    }
});

router.post('/api-keys', authAdmin, apiLimiter, async (req, res) => {
    try {
        const { adminName, permissionLevel, expiryDays } = req.body;

        if (!adminName) {
            return res.status(400).json({
                success: false,
                error: 'Admin name required'
            });
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
            signing_secret: signingSecret
        };

        await firebase.post(`api_keys.json?auth=${FB_KEY}`, keyData);

        console.log(`🔑 API Key created for: ${adminName}`);

        res.json({
            success: true,
            message: 'API Key created',
            apiKey,
            signingSecret,
            warning: 'Save the signing secret immediately. It will not be shown again.'
        });

    } catch (error) {
        console.error('Create API key error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to create API key'
        });
    }
});

router.patch('/api-keys/:id', authAdmin, apiLimiter, async (req, res) => {
    try {
        const { is_active } = req.body;

        await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, {
            is_active
        });

        res.json({
            success: true,
            message: 'API Key updated'
        });

    } catch (error) {
        console.error('Update API key error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to update API key'
        });
    }
});

router.delete('/api-keys/:id', authAdmin, apiLimiter, async (req, res) => {
    try {
        await firebase.delete(`api_keys/${req.params.id}.json?auth=${FB_KEY}`);

        console.log(`🗑️ API Key deleted: ${req.params.id}`);

        res.json({
            success: true,
            message: 'API Key deleted'
        });

    } catch (error) {
        console.error('Delete API key error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to delete API key'
        });
    }
});

router.post('/api-keys/:id/unbind-device', authAdmin, apiLimiter, async (req, res) => {
    try {
        await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, {
            bound_device: null
        });

        console.log(`🔓 Device unbound from API key: ${req.params.id}`);

        res.json({
            success: true,
            message: 'Device unbound'
        });

    } catch (error) {
        console.error('Unbind device error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to unbind device'
        });
    }
});

router.post('/api-keys/:id/regenerate-secret', authAdmin, apiLimiter, async (req, res) => {
    try {
        const newSecret = `SS_${crypto.randomBytes(32).toString('hex')}`;

        await firebase.patch(`api_keys/${req.params.id}.json?auth=${FB_KEY}`, {
            signing_secret: newSecret,
            last_secret_update: Date.now()
        });

        console.log(`🔄 Regenerated signing secret for API Key: ${req.params.id}`);

        res.json({
            success: true,
            message: 'Signing secret regenerated',
            signingSecret: newSecret,
            warning: 'Save this new secret immediately.'
        });

    } catch (error) {
        console.error('Regenerate secret error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to regenerate secret'
        });
    }
});

// ═══════════════════════════════════════════
// 📡 SECURITY & STATS
// ═══════════════════════════════════════════
router.get('/security-stats', authAdmin, (req, res) => {
    res.json({
        success: true,
        stats: getSecurityStats()
    });
});

router.post('/unblock-ip', authAdmin, (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP required' });

    unblockIP(ip);

    res.json({ success: true, message: `IP ${ip} unblocked` });
});

router.get('/device-stats', authAdmin, apiLimiter, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};

        const stats = {
            total_users: Object.keys(users).length,
            total_devices: 0,
            rooted_devices: 0,
            device_brands: {},
            android_versions: {},
            active_last_day: 0,
            active_last_week: 0
        };

        const now = Date.now();
        const oneDay = 24 * 60 * 60 * 1000;
        const oneWeek = 7 * oneDay;

        for (const user of Object.values(users)) {
            if (user.device_id) {
                stats.total_devices++;
                if (user.is_rooted) stats.rooted_devices++;

                const brand = user.device_brand || 'Unknown';
                stats.device_brands[brand] = (stats.device_brands[brand] || 0) + 1;

                const version = user.android_version || 'Unknown';
                stats.android_versions[version] = (stats.android_versions[version] || 0) + 1;
            }

            if (user.last_login) {
                const timeSince = now - user.last_login;
                if (timeSince < oneDay) stats.active_last_day++;
                if (timeSince < oneWeek) stats.active_last_week++;
            }
        }

        res.json({ success: true, data: stats });

    } catch (error) {
        console.error('Device stats error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch device stats' });
    }
});

router.get('/rooted-devices', authAdmin, apiLimiter, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};

        const rootedDevices = [];

        for (const [userId, user] of Object.entries(users)) {
            if (user.is_rooted) {
                rootedDevices.push({
                    user_id: userId,
                    username: user.username,
                    device_model: user.device_model || 'Unknown',
                    device_brand: user.device_brand || 'Unknown',
                    android_version: user.android_version || 'Unknown',
                    last_login: user.last_login,
                    ip_address: user.ip_address || 'Unknown'
                });
            }
        }

        res.json({ success: true, data: rootedDevices, count: rootedDevices.length });

    } catch (error) {
        console.error('Rooted devices error:', error.message);
        res.status(500).json({ success: false, error: 'Failed to fetch rooted devices' });
    }
});

// ═══════════════════════════════════════════
// 🛠️ MAINTENANCE
// ═══════════════════════════════════════════
router.post('/fix-old-users', authAdmin, async (req, res) => {
    try {
        console.log('🔧 Starting fix-old-users process...');

        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};

        let fixed = 0;
        let alreadyFixed = 0;
        const fixedUsers = [];

        for (const [id, user] of Object.entries(users)) {
            if (!user.created_by_key) {
                await firebase.patch(`users/${id}.json?auth=${FB_KEY}`, {
                    created_by_key: 'master'
                });
                console.log(`   ✅ Fixed: ${user.username} → created_by_key: "master"`);
                fixedUsers.push(user.username);
                fixed++;
            } else {
                alreadyFixed++;
            }
        }

        console.log(`🎉 Fix completed: ${fixed} fixed, ${alreadyFixed} already had key`);

        res.json({
            success: true,
            message: `Fixed ${fixed} old users. ${alreadyFixed} already had created_by_key`,
            fixed: fixed,
            alreadyFixed: alreadyFixed,
            fixedUsers: fixedUsers
        });
    } catch (error) {
        console.error('❌ Fix-old-users error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.get('/debug-users', authAdmin, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};

        const debugInfo = [];
        let withKey = 0;
        let withoutKey = 0;
        let masterUsers = 0;
        let subAdminUsers = 0;

        for (const [id, user] of Object.entries(users)) {
            const keyStatus = user.created_by_key || 'MISSING';

            debugInfo.push({
                id: id.substring(0, 10) + '...',
                username: user.username,
                created_by_key: keyStatus,
                created_at: formatDate(user.created_at)
            });

            if (user.created_by_key) {
                withKey++;
                if (user.created_by_key === 'master') {
                    masterUsers++;
                } else {
                    subAdminUsers++;
                }
            } else {
                withoutKey++;
            }
        }

        res.json({
            success: true,
            summary: {
                total: Object.keys(users).length,
                withKey,
                withoutKey,
                masterUsers,
                subAdminUsers
            },
            users: debugInfo
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

module.exports = router;
