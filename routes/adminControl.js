// ═══════════════════════════════════════════
// 🎛️ ADMIN CONTROL ROUTES
// ملف: routes/adminControl.js
// ═══════════════════════════════════════════

const express = require('express');
const router = express.Router();
const { serverState, notifyAdmins } = require('../middleware/telegramBot');
const { sendSecurityAlert } = require('../middleware/notifications');

// Middleware للتحقق من Admin
const isAdmin = (req, res, next) => {
    // يمكنك إضافة التحقق من session/token هنا
    const adminToken = req.headers['x-admin-token'];
    
    if (!adminToken || adminToken !== process.env.ADMIN_CONTROL_TOKEN) {
        return res.status(403).json({
            success: false,
            error: 'Unauthorized'
        });
    }
    
    next();
};

// ═══════════════════════════════════════════
// 🔴 إيقاف السيرفر (Pause Mode)
// ═══════════════════════════════════════════
router.post('/server/stop', isAdmin, async (req, res) => {
    try {
        serverState.isRunning = false;
        serverState.isPaused = true;
        
        await notifyAdmins('⏸️ تم إيقاف السيرفر بنجاح من لوحة التحكم');
        
        res.json({
            success: true,
            message: 'Server stopped',
            status: {
                isRunning: false,
                isPaused: true
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 🟢 تشغيل السيرفر
// ═══════════════════════════════════════════
router.post('/server/start', isAdmin, async (req, res) => {
    try {
        serverState.isRunning = true;
        serverState.isPaused = false;
        serverState.maintenanceMode = false;
        
        await notifyAdmins('✅ تم تشغيل السيرفر من لوحة التحكم');
        
        res.json({
            success: true,
            message: 'Server started',
            status: {
                isRunning: true,
                isPaused: false,
                maintenanceMode: false
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 🔄 إعادة تشغيل السيرفر
// ═══════════════════════════════════════════
router.post('/server/restart', isAdmin, async (req, res) => {
    try {
        await notifyAdmins('🔄 جاري إعادة تشغيل السيرفر...');
        
        res.json({
            success: true,
            message: 'Server restarting...'
        });
        
        // إعادة تعيين الإحصائيات
        serverState.stats.lastRestart = Date.now();
        serverState.stats.totalRequests = 0;
        serverState.stats.blockedRequests = 0;
        
        // إذا كنت تستخدم PM2
        setTimeout(() => {
            process.exit(0);
        }, 1000);
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 🛠️ وضع الصيانة
// ═══════════════════════════════════════════
router.post('/server/maintenance', isAdmin, async (req, res) => {
    try {
        const { enabled } = req.body;
        
        serverState.maintenanceMode = enabled;
        
        const status = enabled ? 'مفعل' : 'معطل';
        await notifyAdmins(`🛠️ وضع الصيانة ${status}`);
        
        res.json({
            success: true,
            maintenanceMode: serverState.maintenanceMode
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 📊 حالة السيرفر
// ═══════════════════════════════════════════
router.get('/server/status', isAdmin, (req, res) => {
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
            },
            cpu: process.cpuUsage()
        }
    });
});

// ═══════════════════════════════════════════
// 🚫 حظر IP
// ═══════════════════════════════════════════
router.post('/ip/block', isAdmin, async (req, res) => {
    try {
        const { ip, reason, duration } = req.body;
        
        if (!ip) {
            return res.status(400).json({
                success: false,
                error: 'IP required'
            });
        }
        
        const until = duration ? Date.now() + (duration * 60000) : Date.now() + 3600000;
        
        serverState.blockedIPs.add(ip);
        
        await sendSecurityAlert('IP_BLOCKED', {
            ip,
            reason: reason || 'Manual block from admin',
            duration: duration ? `${duration} دقيقة` : 'ساعة واحدة'
        });
        
        res.json({
            success: true,
            message: 'IP blocked',
            ip,
            until
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 🔓 إلغاء حظر IP
// ═══════════════════════════════════════════
router.post('/ip/unblock', isAdmin, async (req, res) => {
    try {
        const { ip } = req.body;
        
        if (!ip) {
            return res.status(400).json({
                success: false,
                error: 'IP required'
            });
        }
        
        serverState.blockedIPs.delete(ip);
        
        await notifyAdmins(`🔓 تم إلغاء حظر IP: ${ip}`);
        
        res.json({
            success: true,
            message: 'IP unblocked',
            ip
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 📋 قائمة IPs المحظورة
// ═══════════════════════════════════════════
router.get('/ip/blocked', isAdmin, (req, res) => {
    res.json({
        success: true,
        count: serverState.blockedIPs.size,
        ips: Array.from(serverState.blockedIPs)
    });
});

// ═══════════════════════════════════════════
// 🧹 مسح جميع IPs المحظورة
// ═══════════════════════════════════════════
router.post('/ip/clear-all', isAdmin, async (req, res) => {
    try {
        const count = serverState.blockedIPs.size;
        serverState.blockedIPs.clear();
        
        await notifyAdmins(`🧹 تم مسح ${count} IP محظور`);
        
        res.json({
            success: true,
            message: 'All IPs cleared',
            count
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 🔍 معلومات عن IP معين
// ═══════════════════════════════════════════
router.get('/ip/info/:ip', isAdmin, async (req, res) => {
    try {
        const { ip } = req.params;
        
        // يمكنك استخدام API خارجي للحصول على معلومات
        // مثل: ipapi.co أو ip-api.com
        
        const isBlocked = serverState.blockedIPs.has(ip);
        
        res.json({
            success: true,
            ip,
            isBlocked,
            // يمكنك إضافة معلومات إضافية هنا
            info: {
                country: 'Unknown',
                city: 'Unknown',
                isp: 'Unknown'
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 🧹 مسح Cache
// ═══════════════════════════════════════════
router.post('/cache/clear', isAdmin, async (req, res) => {
    try {
        serverState.stats.totalRequests = 0;
        serverState.stats.blockedRequests = 0;
        
        await notifyAdmins('🧹 تم مسح الـ Cache');
        
        res.json({
            success: true,
            message: 'Cache cleared'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 📝 سجلات النشاط
// ═══════════════════════════════════════════
const activityLogs = [];
const MAX_LOGS = 1000;

function addLog(type, message, data = {}) {
    activityLogs.unshift({
        timestamp: Date.now(),
        type,
        message,
        data
    });
    
    if (activityLogs.length > MAX_LOGS) {
        activityLogs.pop();
    }
}

router.get('/logs', isAdmin, (req, res) => {
    const { limit = 100, type } = req.query;
    
    let logs = activityLogs;
    
    if (type) {
        logs = logs.filter(log => log.type === type);
    }
    
    res.json({
        success: true,
        count: logs.length,
        logs: logs.slice(0, parseInt(limit))
    });
});

// ═══════════════════════════════════════════
// 📊 إحصائيات متقدمة
// ═══════════════════════════════════════════
router.get('/stats/advanced', isAdmin, async (req, res) => {
    try {
        const stats = {
            server: {
                isRunning: serverState.isRunning,
                isPaused: serverState.isPaused,
                maintenanceMode: serverState.maintenanceMode,
                uptime: Math.floor((Date.now() - serverState.stats.lastRestart) / 1000),
                memory: {
                    used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                    total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
                    percentage: Math.round((process.memoryUsage().heapUsed / process.memoryUsage().heapTotal) * 100)
                }
            },
            requests: {
                total: serverState.stats.totalRequests,
                blocked: serverState.stats.blockedRequests,
                success: serverState.stats.totalRequests - serverState.stats.blockedRequests
            },
            security: {
                blockedIPs: serverState.blockedIPs.size,
                allowedIPs: serverState.allowedIPs.size
            },
            users: {
                active: serverState.stats.activeUsers
            }
        };
        
        res.json({
            success: true,
            stats
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 🔔 إرسال إشعار للمسؤولين
// ═══════════════════════════════════════════
router.post('/notify', isAdmin, async (req, res) => {
    try {
        const { message, type = 'info' } = req.body;
        
        if (!message) {
            return res.status(400).json({
                success: false,
                error: 'Message required'
            });
        }
        
        const icons = {
            info: 'ℹ️',
            success: '✅',
            warning: '⚠️',
            error: '❌'
        };
        
        await notifyAdmins(`${icons[type] || 'ℹ️'} ${message}`);
        
        res.json({
            success: true,
            message: 'Notification sent'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════
// 🎯 Middleware للتحقق من حالة السيرفر
// يستخدم في جميع routes العادية
// ═══════════════════════════════════════════
const checkServerState = (req, res, next) => {
    // إذا السيرفر متوقف
    if (!serverState.isRunning || serverState.isPaused) {
        return res.status(503).json({
            success: false,
            code: 503,
            error: 'Server is currently stopped',
            message: 'السيرفر متوقف حالياً. يرجى المحاولة لاحقاً.'
        });
    }
    
    // إذا وضع الصيانة مفعل
    if (serverState.maintenanceMode) {
        return res.status(503).json({
            success: false,
            code: 503,
            error: 'Server under maintenance',
            message: 'السيرفر تحت الصيانة حالياً. سنعود قريباً.'
        });
    }
    
    // إحصائيات
    serverState.stats.totalRequests++;
    
    next();
};

// Export
module.exports = {
    router,
    checkServerState,
    addLog
};
