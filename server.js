
// ═══════════════════════════════════════════════════════════════════════════
// 🛡️ SECURE SERVER v17.0 - Complete Edition
// ═══════════════════════════════════════════════════════════════════════════
'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// ═══════════════════════════════════════════════════════════════════════════
// 🚨 SECURITY: VALIDATE ENVIRONMENT
// ═══════════════════════════════════════════════════════════════════════════
console.log('');
console.log('═'.repeat(60));
console.log('🔐 SECURITY VALIDATION');
console.log('═'.repeat(60));

const REQUIRED_ENV = {
    FIREBASE_URL: process.env.FIREBASE_URL,
    FIREBASE_KEY: process.env.FIREBASE_KEY,
    MASTER_ADMIN_USERNAME: process.env.MASTER_ADMIN_USERNAME,
    MASTER_ADMIN_PASSWORD_HASH: process.env.MASTER_ADMIN_PASSWORD_HASH,
    SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    ADMIN_CONTROL_TOKEN: process.env.ADMIN_CONTROL_TOKEN || 'master-admin-token'
};

const missing = Object.entries(REQUIRED_ENV)
    .filter(([key, value]) => !value && !['SESSION_SECRET', 'ADMIN_CONTROL_TOKEN'].includes(key))
    .map(([key]) => key);

if (missing.length > 0) {
    console.error('');
    console.error('🚨 CRITICAL: Missing environment variables:');
    missing.forEach(key => console.error(`   ❌ ${key}`));
    console.error('');
    process.exit(1);
}

console.log('✅ Environment validated');
console.log('═'.repeat(60));

// ═══════════════════════════════════════════════════════════════════════════
// 📦 FIREBASE SETUP
// ═══════════════════════════════════════════════════════════════════════════
const FIREBASE_URL = process.env.FIREBASE_URL;
const FIREBASE_KEY = process.env.FIREBASE_KEY;

async function firebaseRequest(path, method = 'GET', data = null) {
    const url = `${FIREBASE_URL}${path}.json?auth=${FIREBASE_KEY}`;
    
    const options = {
        method,
        headers: { 'Content-Type': 'application/json' }
    };
    
    if (data && method !== 'GET') {
        options.body = JSON.stringify(data);
    }
    
    const response = await fetch(url, options);
    return response.json();
}

// ═══════════════════════════════════════════════════════════════════════════
// 🎛️ SERVER STATE (للتحكم بالسيرفر)
// ═══════════════════════════════════════════════════════════════════════════
const serverState = {
    isRunning: true,
    isPaused: false,
    maintenanceMode: false,
    blockedIPs: new Set(),
    allowedIPs: new Set(),
    stats: {
        totalRequests: 0,
        blockedRequests: 0,
        lastRestart: Date.now(),
        activeUsers: 0
    }
};

// سجلات النشاط
const activityLogs = [];
const MAX_LOGS = 1000;

function addLog(type, message, data = {}) {
    const log = {
        id: Date.now().toString(),
        timestamp: new Date().toISOString(),
        type,
        message,
        data
    };
    
    activityLogs.unshift(log);
    
    if (activityLogs.length > MAX_LOGS) {
        activityLogs.pop();
    }
    
    console.log(`[${type}] ${message}`);
    return log;
}

// ═══════════════════════════════════════════════════════════════════════════
// 🚀 EXPRESS APP
// ═══════════════════════════════════════════════════════════════════════════
const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', true);

// ═══════════════════════════════════════════════════════════════════════════
// 🛡️ MIDDLEWARE: CORS
// ═══════════════════════════════════════════════════════════════════════════
app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Session-Id', 'X-Session-Token', 'X-Admin-Token']
}));

// ═══════════════════════════════════════════════════════════════════════════
// 📝 BODY PARSER
// ═══════════════════════════════════════════════════════════════════════════
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// ═══════════════════════════════════════════════════════════════════════════
// 📊 REQUEST LOGGER
// ═══════════════════════════════════════════════════════════════════════════
app.use((req, res, next) => {
    const startTime = Date.now();
    const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    
    req.clientIP = ip;
    serverState.stats.totalRequests++;
    
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        
        if (req.path.includes('/admin') || req.path.includes('/control')) {
            console.log(`🔒 ${req.method} ${req.path} | IP: ${ip} | ${res.statusCode} | ${duration}ms`);
        }
        
        if (res.statusCode >= 400) {
            addLog('ERROR', `${req.method} ${req.path} - ${res.statusCode}`, { ip, duration });
        }
    });
    
    next();
});

// ═══════════════════════════════════════════════════════════════════════════
// 🎯 MIDDLEWARE: CHECK SERVER STATE
// ═══════════════════════════════════════════════════════════════════════════
const checkServerState = (req, res, next) => {
    const ip = req.clientIP || req.ip;
    
    // تحقق من IP المحظور
    if (serverState.blockedIPs.has(ip)) {
        serverState.stats.blockedRequests++;
        addLog('BLOCKED', `Blocked request from ${ip}`, { path: req.path });
        return res.status(403).json({
            success: false,
            error: 'IP blocked',
            code: 403
        });
    }
    
    // تحقق من إيقاف السيرفر
    if (!serverState.isRunning || serverState.isPaused) {
        return res.status(503).json({
            success: false,
            error: 'Server is currently stopped',
            message: 'السيرفر متوقف حالياً',
            code: 503
        });
    }
    
    // تحقق من وضع الصيانة
    if (serverState.maintenanceMode) {
        return res.status(503).json({
            success: false,
            error: 'Server under maintenance',
            message: 'السيرفر تحت الصيانة',
            code: 503
        });
    }
    
    next();
};

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 MIDDLEWARE: ADMIN AUTH
// ═══════════════════════════════════════════════════════════════════════════
const verifyAdmin = async (req, res, next) => {
    try {
        const sessionId = req.headers['x-session-id'];
        const sessionToken = req.headers['x-session-token'];
        
        if (!sessionId || !sessionToken) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required'
            });
        }
        
        // تحقق من الجلسة في Firebase
        const session = await firebaseRequest(`/admin_sessions/${sessionId}`);
        
        if (!session || session.token !== sessionToken) {
            return res.status(401).json({
                success: false,
                error: 'Invalid session'
            });
        }
        
        // تحقق من انتهاء الجلسة
        if (session.expiresAt && Date.now() > session.expiresAt) {
            await firebaseRequest(`/admin_sessions/${sessionId}`, 'DELETE');
            return res.status(401).json({
                success: false,
                error: 'Session expired'
            });
        }
        
        req.adminId = sessionId;
        req.adminUser = session.user;
        next();
    } catch (error) {
        console.error('Auth error:', error);
        res.status(500).json({
            success: false,
            error: 'Authentication error'
        });
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// 🔑 MIDDLEWARE: CONTROL AUTH (للتحكم بالسيرفر)
// ═══════════════════════════════════════════════════════════════════════════
const verifyControlAccess = (req, res, next) => {
    const adminToken = req.headers['x-admin-token'];
    const sessionId = req.headers['x-session-id'];
    const sessionToken = req.headers['x-session-token'];
    
    // طريقة 1: X-Admin-Token
    if (adminToken === REQUIRED_ENV.ADMIN_CONTROL_TOKEN) {
        return next();
    }
    
    // طريقة 2: Session (للتحقق البسيط)
    if (sessionId && sessionToken) {
        return next();
    }
    
    return res.status(403).json({
        success: false,
        error: 'Unauthorized - Admin access required'
    });
};

// ═══════════════════════════════════════════════════════════════════════════
// 🏥 HEALTH CHECK
// ═══════════════════════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: Math.floor((Date.now() - serverState.stats.lastRestart) / 1000),
        version: '17.0'
    });
});

app.get('/api/test', (req, res) => {
    res.json({ success: true, message: 'API is working!' });
});

// ═══════════════════════════════════════════════════════════════════════════
// 🎛️ SERVER CONTROL ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// 📡 حالة السيرفر
app.get('/api/control/server/status', verifyControlAccess, (req, res) => {
    const uptime = Math.floor((Date.now() - serverState.stats.lastRestart) / 1000);
    
    res.json({
        success: true,
        status: {
            isRunning: serverState.isRunning,
            isPaused: serverState.isPaused,
            maintenanceMode: serverState.maintenanceMode,
            uptime: uptime,
            stats: serverState.stats,
            blockedIPs: serverState.blockedIPs.size,
            memory: {
                used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
            }
        }
    });
});

// 🔴 إيقاف السيرفر
app.post('/api/control/server/stop', verifyControlAccess, (req, res) => {
    serverState.isRunning = false;
    serverState.isPaused = true;
    
    addLog('WARNING', 'Server stopped by admin');
    
    res.json({
        success: true,
        message: 'Server stopped',
        status: { isRunning: false, isPaused: true }
    });
});

// 🟢 تشغيل السيرفر
app.post('/api/control/server/start', verifyControlAccess, (req, res) => {
    serverState.isRunning = true;
    serverState.isPaused = false;
    serverState.maintenanceMode = false;
    
    addLog('INFO', 'Server started by admin');
    
    res.json({
        success: true,
        message: 'Server started',
        status: { isRunning: true, isPaused: false, maintenanceMode: false }
    });
});

// 🔄 إعادة تشغيل السيرفر
app.post('/api/control/server/restart', verifyControlAccess, (req, res) => {
    addLog('WARNING', 'Server restart requested');
    
    serverState.stats.lastRestart = Date.now();
    serverState.stats.totalRequests = 0;
    serverState.stats.blockedRequests = 0;
    serverState.isRunning = true;
    serverState.isPaused = false;
    serverState.maintenanceMode = false;
    
    res.json({
        success: true,
        message: 'Server restarted (soft restart)',
        newStartTime: new Date().toISOString()
    });
});

// 🛠️ وضع الصيانة
app.post('/api/control/server/maintenance', verifyControlAccess, (req, res) => {
    const { enabled } = req.body;
    
    serverState.maintenanceMode = enabled === true;
    
    addLog(enabled ? 'WARNING' : 'INFO', `Maintenance mode ${enabled ? 'enabled' : 'disabled'}`);
    
    res.json({
        success: true,
        maintenanceMode: serverState.maintenanceMode,
        message: enabled ? 'Maintenance mode enabled' : 'Maintenance mode disabled'
    });
});

// 🧹 مسح الكاش
app.post('/api/control/cache/clear', verifyControlAccess, (req, res) => {
    serverState.stats.totalRequests = 0;
    serverState.stats.blockedRequests = 0;
    
    addLog('INFO', 'Cache cleared');
    
    res.json({
        success: true,
        message: 'Cache cleared'
    });
});

// 🚫 حظر IP
app.post('/api/control/ip/block', verifyControlAccess, (req, res) => {
    const { ip, reason, duration } = req.body;
    
    if (!ip) {
        return res.status(400).json({ success: false, error: 'IP required' });
    }
    
    serverState.blockedIPs.add(ip);
    
    addLog('WARNING', `IP blocked: ${ip}`, { reason: reason || 'Manual block' });
    
    // إزالة تلقائية بعد المدة (إذا محددة)
    if (duration) {
        setTimeout(() => {
            serverState.blockedIPs.delete(ip);
            addLog('INFO', `IP auto-unblocked: ${ip}`);
        }, duration * 60 * 1000);
    }
    
    res.json({
        success: true,
        message: `IP ${ip} blocked`,
        ip
    });
});

// 🔓 إلغاء حظر IP
app.post('/api/control/ip/unblock', verifyControlAccess, (req, res) => {
    const { ip } = req.body;
    
    if (!ip) {
        return res.status(400).json({ success: false, error: 'IP required' });
    }
    
    if (serverState.blockedIPs.has(ip)) {
        serverState.blockedIPs.delete(ip);
        addLog('INFO', `IP unblocked: ${ip}`);
        
        res.json({ success: true, message: `IP ${ip} unblocked` });
    } else {
        res.json({ success: false, error: 'IP not found in blocked list' });
    }
});

// 📋 قائمة IPs المحظورة
app.get('/api/control/ip/blocked', verifyControlAccess, (req, res) => {
    res.json({
        success: true,
        count: serverState.blockedIPs.size,
        ips: Array.from(serverState.blockedIPs)
    });
});

// 🧹 مسح جميع IPs
app.post('/api/control/ip/clear-all', verifyControlAccess, (req, res) => {
    const count = serverState.blockedIPs.size;
    serverState.blockedIPs.clear();
    
    addLog('WARNING', `All blocked IPs cleared (${count})`);
    
    res.json({
        success: true,
        message: `${count} IPs cleared`,
        count
    });
});

// 📝 السجلات
app.get('/api/control/logs', verifyControlAccess, (req, res) => {
    const { limit = 100, type } = req.query;
    
    let logs = activityLogs;
    
    if (type) {
        logs = logs.filter(log => log.type === type);
    }
    
    res.json({
        success: true,
        total: activityLogs.length,
        returned: Math.min(parseInt(limit), logs.length),
        logs: logs.slice(0, parseInt(limit))
    });
});

// 🗑️ مسح السجلات
app.post('/api/control/logs/clear', verifyControlAccess, (req, res) => {
    const count = activityLogs.length;
    activityLogs.length = 0;
    
    addLog('INFO', `Logs cleared (${count} entries)`);
    
    res.json({
        success: true,
        message: `${count} logs cleared`,
        count
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 ADMIN LOGIN/LOGOUT
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password, deviceFingerprint } = req.body;
        const ip = req.clientIP || req.ip;
        
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username and password required'
            });
        }
        
        // تحقق من Master Admin
        if (username === REQUIRED_ENV.MASTER_ADMIN_USERNAME) {
            const isValid = await bcrypt.compare(password, REQUIRED_ENV.MASTER_ADMIN_PASSWORD_HASH);
            
            if (!isValid) {
                addLog('AUTH_FAIL', `Failed login attempt for ${username}`, { ip });
                return res.status(401).json({
                    success: false,
                    error: 'Invalid credentials'
                });
            }
            
            // إنشاء جلسة
            const sessionId = crypto.randomBytes(32).toString('hex');
            const sessionToken = crypto.randomBytes(64).toString('hex');
            
            const sessionData = {
                user: {
                    username: username,
                    role: 'master_admin'
                },
                token: sessionToken,
                ip: ip,
                deviceFingerprint: deviceFingerprint,
                createdAt: Date.now(),
                expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 ساعة
            };
            
            await firebaseRequest(`/admin_sessions/${sessionId}`, 'PUT', sessionData);
            
            addLog('LOGIN', `Admin logged in: ${username}`, { ip });
            
            return res.json({
                success: true,
                message: 'Login successful',
                sessionId: sessionId,
                sessionToken: sessionToken,
                adminToken: REQUIRED_ENV.ADMIN_CONTROL_TOKEN,
                user: sessionData.user,
                expiresAt: sessionData.expiresAt
            });
        }
        
        // تحقق من Sub Admin في Firebase
        const subAdmins = await firebaseRequest('/sub_admins');
        
        if (subAdmins) {
            for (const [id, admin] of Object.entries(subAdmins)) {
                if (admin.username === username && admin.is_active) {
                    const isValid = await bcrypt.compare(password, admin.password_hash);
                    
                    if (isValid) {
                        const sessionId = crypto.randomBytes(32).toString('hex');
                        const sessionToken = crypto.randomBytes(64).toString('hex');
                        
                        const sessionData = {
                            user: {
                                id: id,
                                username: username,
                                role: 'sub_admin',
                                permissions: admin.permissions || []
                            },
                            token: sessionToken,
                            ip: ip,
                            createdAt: Date.now(),
                            expiresAt: Date.now() + (12 * 60 * 60 * 1000)
                        };
                        
                        await firebaseRequest(`/admin_sessions/${sessionId}`, 'PUT', sessionData);
                        
                        addLog('LOGIN', `Sub-admin logged in: ${username}`, { ip });
                        
                        return res.json({
                            success: true,
                            message: 'Login successful',
                            sessionId: sessionId,
                            sessionToken: sessionToken,
                            user: sessionData.user
                        });
                    }
                }
            }
        }
        
        addLog('AUTH_FAIL', `Invalid login: ${username}`, { ip });
        
        res.status(401).json({
            success: false,
            error: 'Invalid credentials'
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Login failed'
        });
    }
});

app.post('/api/admin/logout', verifyAdmin, async (req, res) => {
    try {
        await firebaseRequest(`/admin_sessions/${req.adminId}`, 'DELETE');
        
        addLog('LOGOUT', `Admin logged out`, { adminId: req.adminId });
        
        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Logout failed'
        });
    }
});

app.get('/api/admin/verify-session', verifyAdmin, (req, res) => {
    res.json({
        success: true,
        valid: true,
        user: req.adminUser
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// 👥 USERS MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

// جلب جميع المستخدمين
app.get('/api/admin/users', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const users = await firebaseRequest('/users');
        
        res.json({
            success: true,
            count: users ? Object.keys(users).length : 0,
            data: users || {}
        });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get users'
        });
    }
});

// إضافة مستخدم
app.post('/api/admin/users', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const { username, password, expiryMinutes, customExpiryDate, maxDevices, status } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username and password required'
            });
        }
        
        // تحقق من عدم وجود المستخدم
        const existingUsers = await firebaseRequest('/users');
        if (existingUsers) {
            const exists = Object.values(existingUsers).some(u => u.username === username);
            if (exists) {
                return res.status(400).json({
                    success: false,
                    error: 'Username already exists'
                });
            }
        }
        
        // حساب تاريخ الانتهاء
        let expiryDate = null;
        if (customExpiryDate) {
            expiryDate = customExpiryDate;
        } else if (expiryMinutes) {
            expiryDate = new Date(Date.now() + expiryMinutes * 60 * 1000).toISOString();
        }
        
        const userId = crypto.randomBytes(16).toString('hex');
        const passwordHash = await bcrypt.hash(password, 10);
        
        const userData = {
            username: username,
            password_hash: passwordHash,
            is_active: status !== 'inactive',
            expiry_date: expiryDate,
            max_devices: maxDevices || 1,
            device_id: null,
            device_info: null,
            is_rooted: false,
            login_count: 0,
            last_login: null,
            created_at: new Date().toISOString(),
            created_by: req.adminUser?.username || 'admin'
        };
        
        await firebaseRequest(`/users/${userId}`, 'PUT', userData);
        
        addLog('USER_CREATED', `User created: ${username}`, { by: req.adminUser?.username });
        
        res.json({
            success: true,
            message: 'User created successfully',
            userId: userId
        });
        
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to create user'
        });
    }
});

// تحديث مستخدم
app.patch('/api/admin/users/:id', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        const user = await firebaseRequest(`/users/${id}`);
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        // حذف الحقول الحساسة
        delete updates.password_hash;
        delete updates.id;
        
        await firebaseRequest(`/users/${id}`, 'PATCH', updates);
        
        addLog('USER_UPDATED', `User updated: ${user.username}`, { updates: Object.keys(updates) });
        
        res.json({
            success: true,
            message: 'User updated'
        });
        
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update user'
        });
    }
});

// حذف مستخدم
app.delete('/api/admin/users/:id', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const user = await firebaseRequest(`/users/${id}`);
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        await firebaseRequest(`/users/${id}`, 'DELETE');
        
        addLog('USER_DELETED', `User deleted: ${user.username}`, { by: req.adminUser?.username });
        
        res.json({
            success: true,
            message: 'User deleted'
        });
        
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete user'
        });
    }
});

// تمديد اشتراك
app.post('/api/admin/users/:id/extend', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { minutes } = req.body;
        
        if (!minutes || minutes < 1) {
            return res.status(400).json({
                success: false,
                error: 'Valid minutes required'
            });
        }
        
        const user = await firebaseRequest(`/users/${id}`);
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        const currentExpiry = user.expiry_date ? new Date(user.expiry_date).getTime() : Date.now();
        const baseTime = currentExpiry > Date.now() ? currentExpiry : Date.now();
        const newExpiry = new Date(baseTime + minutes * 60 * 1000).toISOString();
        
        await firebaseRequest(`/users/${id}`, 'PATCH', { expiry_date: newExpiry });
        
        addLog('USER_EXTENDED', `User extended: ${user.username}`, { minutes, newExpiry });
        
        res.json({
            success: true,
            message: 'Subscription extended',
            newExpiry: newExpiry
        });
        
    } catch (error) {
        console.error('Extend user error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to extend subscription'
        });
    }
});

// إعادة تعيين الجهاز
app.post('/api/admin/users/:id/reset-device', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const user = await firebaseRequest(`/users/${id}`);
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        await firebaseRequest(`/users/${id}`, 'PATCH', {
            device_id: null,
            device_info: null
        });
        
        addLog('DEVICE_RESET', `Device reset: ${user.username}`, { by: req.adminUser?.username });
        
        res.json({
            success: true,
            message: 'Device reset successful'
        });
        
    } catch (error) {
        console.error('Reset device error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to reset device'
        });
    }
});

// حذف المنتهيين
app.post('/api/admin/users/delete-expired', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const users = await firebaseRequest('/users');
        
        if (!users) {
            return res.json({
                success: true,
                message: 'No users to delete',
                count: 0
            });
        }
        
        const now = Date.now();
        let deletedCount = 0;
        
        for (const [id, user] of Object.entries(users)) {
            if (user.expiry_date) {
                const expiryTime = new Date(user.expiry_date).getTime();
                if (expiryTime <= now) {
                    await firebaseRequest(`/users/${id}`, 'DELETE');
                    deletedCount++;
                }
            }
        }
        
        addLog('EXPIRED_DELETED', `Deleted ${deletedCount} expired users`);
        
        res.json({
            success: true,
            message: `Deleted ${deletedCount} expired users`,
            count: deletedCount
        });
        
    } catch (error) {
        console.error('Delete expired error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete expired users'
        });
    }
});

// ═══════════════════════════════════════════════════════════════════════════
// 🔑 API KEYS MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

// جلب جميع المفاتيح
app.get('/api/admin/api-keys', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const apiKeys = await firebaseRequest('/api_keys');
        
        res.json({
            success: true,
            count: apiKeys ? Object.keys(apiKeys).length : 0,
            data: apiKeys || {}
        });
    } catch (error) {
        console.error('Get API keys error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get API keys'
        });
    }
});

// إنشاء مفتاح جديد
app.post('/api/admin/api-keys', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const { adminName, permissionLevel, expiryDays } = req.body;
        
        if (!adminName) {
            return res.status(400).json({
                success: false,
                error: 'Admin name required'
            });
        }
        
        const keyId = crypto.randomBytes(16).toString('hex');
        const apiKey = `ak_${crypto.randomBytes(32).toString('hex')}`;
        
        const keyData = {
            api_key: apiKey,
            admin_name: adminName,
            permission_level: permissionLevel || 'full',
            is_active: true,
            expiry_date: expiryDays ? new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString() : null,
            created_at: new Date().toISOString(),
            created_by: req.adminUser?.username || 'admin',
            usage_count: 0,
            last_used: null
        };
        
        await firebaseRequest(`/api_keys/${keyId}`, 'PUT', keyData);
        
        addLog('KEY_CREATED', `API key created for: ${adminName}`, { permission: permissionLevel });
        
        res.json({
            success: true,
            message: 'API key created',
            keyId: keyId,
            apiKey: apiKey
        });
        
    } catch (error) {
        console.error('Create API key error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to create API key'
        });
    }
});

// تحديث مفتاح
app.patch('/api/admin/api-keys/:id', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        delete updates.api_key;
        delete updates.id;
        
        await firebaseRequest(`/api_keys/${id}`, 'PATCH', updates);
        
        res.json({
            success: true,
            message: 'API key updated'
        });
        
    } catch (error) {
        console.error('Update API key error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update API key'
        });
    }
});

// حذف مفتاح
app.delete('/api/admin/api-keys/:id', checkServerState, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        await firebaseRequest(`/api_keys/${id}`, 'DELETE');
        
        addLog('KEY_DELETED', `API key deleted: ${id}`);
        
        res.json({
            success: true,
            message: 'API key deleted'
        });
        
    } catch (error) {
        console.error('Delete API key error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete API key'
        });
    }
});

// ═══════════════════════════════════════════════════════════════════════════
// 📱 MOBILE APP ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// تسجيل دخول المستخدم العادي
app.post('/api/login', checkServerState, async (req, res) => {
    try {
        const { username, password, device_id, device_info, is_rooted } = req.body;
        const ip = req.clientIP || req.ip;
        
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username and password required'
            });
        }
        
        const users = await firebaseRequest('/users');
        
        if (!users) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        let foundUser = null;
        let foundId = null;
        
        for (const [id, user] of Object.entries(users)) {
            if (user.username === username) {
                foundUser = user;
                foundId = id;
                break;
            }
        }
        
        if (!foundUser) {
            addLog('LOGIN_FAIL', `Invalid username: ${username}`, { ip });
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        // تحقق من كلمة المرور
        const isValid = await bcrypt.compare(password, foundUser.password_hash);
        if (!isValid) {
            addLog('LOGIN_FAIL', `Invalid password for: ${username}`, { ip });
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        // تحقق من الحالة
        if (!foundUser.is_active) {
            return res.status(403).json({
                success: false,
                error: 'Account is disabled'
            });
        }
        
        // تحقق من الانتهاء
        if (foundUser.expiry_date) {
            const expiryTime = new Date(foundUser.expiry_date).getTime();
            if (expiryTime <= Date.now()) {
                return res.status(403).json({
                    success: false,
                    error: 'Subscription expired'
                });
            }
        }
        
        // تحقق من الجهاز
        if (foundUser.device_id && foundUser.device_id !== device_id) {
            return res.status(403).json({
                success: false,
                error: 'Device mismatch. Contact admin to reset.'
            });
        }
        
        // تحديث بيانات المستخدم
        const updateData = {
            last_login: new Date().toISOString(),
            login_count: (foundUser.login_count || 0) + 1,
            last_ip: ip
        };
        
        if (!foundUser.device_id && device_id) {
            updateData.device_id = device_id;
            updateData.device_info = device_info || null;
        }
        
        if (is_rooted !== undefined) {
            updateData.is_rooted = is_rooted;
        }
        
        await firebaseRequest(`/users/${foundId}`, 'PATCH', updateData);
        
        addLog('USER_LOGIN', `User login: ${username}`, { ip, device_id });
        
        res.json({
            success: true,
            message: 'Login successful',
            user: {
                username: foundUser.username,
                expiry_date: foundUser.expiry_date,
                is_active: true
            }
        });
        
    } catch (error) {
        console.error('User login error:', error);
        res.status(500).json({
            success: false,
            error: 'Login failed'
        });
    }
});

// التحقق من الاشتراك
app.post('/api/verify', checkServerState, async (req, res) => {
    try {
        const { username, device_id } = req.body;
        
        if (!username) {
            return res.status(400).json({
                success: false,
                error: 'Username required'
            });
        }
        
        const users = await firebaseRequest('/users');
        
        if (!users) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        let foundUser = null;
        
        for (const user of Object.values(users)) {
            if (user.username === username) {
                foundUser = user;
                break;
            }
        }
        
        if (!foundUser) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        // تحقق من الجهاز
        if (foundUser.device_id && device_id && foundUser.device_id !== device_id) {
            return res.json({
                success: false,
                error: 'Device mismatch',
                valid: false
            });
        }
        
        // تحقق من الحالة
        if (!foundUser.is_active) {
            return res.json({
                success: true,
                valid: false,
                reason: 'Account disabled'
            });
        }
        
        // تحقق من الانتهاء
        if (foundUser.expiry_date) {
            const expiryTime = new Date(foundUser.expiry_date).getTime();
            if (expiryTime <= Date.now()) {
                return res.json({
                    success: true,
                    valid: false,
                    reason: 'Subscription expired'
                });
            }
        }
        
        res.json({
            success: true,
            valid: true,
            expiry_date: foundUser.expiry_date
        });
        
    } catch (error) {
        console.error('Verify error:', error);
        res.status(500).json({
            success: false,
            error: 'Verification failed'
        });
    }
});




// ═══════════════════════════════════════════════════════════════════════════
// ❌ ERROR HANDLERS
// ═══════════════════════════════════════════════════════════════════════════

// 404 Handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        path: req.originalUrl,
        code: 404
    });
});

// Error Handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    
    addLog('ERROR', err.message, { stack: err.stack, path: req.path });
    
    res.status(500).json({
        success: false,
        error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
        code: 500
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// 🚀 START SERVER
// ═══════════════════════════════════════════════════════════════════════════

app.listen(PORT, () => {
    console.log('');
    console.log('═'.repeat(60));
    console.log('🛡️  Secure Server v17.0');
    console.log('═'.repeat(60));
    console.log(`📡 Port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('');
    console.log('✅ FEATURES ENABLED:');
    console.log('   ✅ Admin Authentication');
    console.log('   ✅ User Management');
    console.log('   ✅ API Keys Management');
    console.log('   ✅ Server Control Panel');
    console.log('   ✅ IP Blocking');
    console.log('   ✅ Activity Logs');
    console.log('   ✅ Maintenance Mode');
    console.log('');
    console.log('🔗 ENDPOINTS:');
    console.log('   /health - Health check');
    console.log('   /api/admin/* - Admin routes');
    console.log('   /api/control/* - Server control');
    console.log('   /api/login - User login');
    console.log('   /api/verify - Verify subscription');
    console.log('');
    console.log('═'.repeat(60));
    console.log('🚀 Server is ready!');
    console.log('═'.repeat(60));
});

// ═══════════════════════════════════════════════════════════════════════════
// 🛑 GRACEFUL SHUTDOWN
// ═══════════════════════════════════════════════════════════════════════════

process.on('SIGTERM', () => {
    console.log('\n🛑 SIGTERM received. Shutting down...');
    addLog('SHUTDOWN', 'Server shutting down (SIGTERM)');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('\n🛑 SIGINT received. Shutting down...');
    addLog('SHUTDOWN', 'Server shutting down (SIGINT)');
    process.exit(0);
});

process.on('uncaughtException', (error) => {
    console.error('💥 Uncaught Exception:', error);
    addLog('CRASH', error.message, { stack: error.stack });
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 Unhandled Rejection:', reason);
    addLog('ERROR', 'Unhandled rejection: ' + String(reason));
});

module.exports = app;

