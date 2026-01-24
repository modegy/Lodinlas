// ═══════════════════════════════════════════
// 🔔 NOTIFICATION SYSTEM
// ملف: middleware/notifications.js
// ═══════════════════════════════════════════

const axios = require('axios');
const nodemailer = require('nodemailer');

// ═══════════════════════════════════════════
// ⚙️ الإعدادات (ضعها في .env)
// ═══════════════════════════════════════════
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = process.env.SMTP_PORT || 587;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';

// تكوين الإيميل
let emailTransporter = null;
if (SMTP_USER && SMTP_PASS) {
    emailTransporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: false, // true for 465, false for other ports
        auth: {
            user: SMTP_USER,
            pass: SMTP_PASS
        }
    });
}

// ═══════════════════════════════════════════
// 📱 إرسال إشعار تليجرام
// ═══════════════════════════════════════════
async function sendTelegramAlert(message, severity = 'warning') {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
        console.log('⚠️ Telegram not configured');
        return;
    }

    try {
        const emoji = {
            critical: '🚨',
            warning: '⚠️',
            info: 'ℹ️',
            success: '✅'
        };

        const formattedMessage = `
${emoji[severity] || '⚠️'} <b>Security Alert</b>

${message}

<i>Time: ${new Date().toLocaleString('ar-EG', { timeZone: 'Africa/Cairo' })}</i>
<i>Server: ${process.env.RENDER_EXTERNAL_URL || 'Local'}</i>
        `.trim();

        await axios.post(
            `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
            {
                chat_id: TELEGRAM_CHAT_ID,
                text: formattedMessage,
                parse_mode: 'HTML'
            }
        );

        console.log('✅ Telegram alert sent');
    } catch (error) {
        console.error('❌ Telegram error:', error.message);
    }
}

// ═══════════════════════════════════════════
// 📧 إرسال إشعار إيميل
// ═══════════════════════════════════════════
async function sendEmailAlert(subject, message, severity = 'warning') {
    if (!emailTransporter || !ADMIN_EMAIL) {
        console.log('⚠️ Email not configured');
        return;
    }

    try {
        const colors = {
            critical: '#dc3545',
            warning: '#ffc107',
            info: '#17a2b8',
            success: '#28a745'
        };

        const htmlContent = `
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }
        .container { background: white; border-radius: 8px; padding: 30px; max-width: 600px; margin: 0 auto; }
        .header { background: ${colors[severity] || '#ffc107'}; color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -30px -30px 20px -30px; }
        .content { line-height: 1.8; color: #333; }
        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #888; }
        .badge { display: inline-block; padding: 5px 10px; border-radius: 4px; background: #e9ecef; margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🔐 تنبيه أمني</h2>
        </div>
        <div class="content">
            ${message.replace(/\n/g, '<br>')}
        </div>
        <div class="footer">
            <strong>الوقت:</strong> ${new Date().toLocaleString('ar-EG', { timeZone: 'Africa/Cairo' })}<br>
            <strong>السيرفر:</strong> ${process.env.RENDER_EXTERNAL_URL || 'Local'}
        </div>
    </div>
</body>
</html>
        `;

        await emailTransporter.sendMail({
            from: `"Security System" <${SMTP_USER}>`,
            to: ADMIN_EMAIL,
            subject: `[${severity.toUpperCase()}] ${subject}`,
            html: htmlContent
        });

        console.log('✅ Email alert sent');
    } catch (error) {
        console.error('❌ Email error:', error.message);
    }
}

// ═══════════════════════════════════════════
// 🚨 إرسال تنبيه شامل (تليجرام + إيميل)
// ═══════════════════════════════════════════
async function sendSecurityAlert(type, details = {}) {
    const alerts = {
        IP_BLOCKED: {
            severity: 'critical',
            title: '🚫 IP محظور',
            getMessage: (d) => `
<b>تم حظر IP مشبوه</b>

🌐 العنوان: <code>${d.ip}</code>
⏱ المدة: ${d.duration || 'ساعة واحدة'}
📋 السبب: ${d.reason}
🔢 نقاط الشك: ${d.score || 'N/A'}

${d.userAgent ? `🤖 User-Agent:\n<code>${d.userAgent}</code>` : ''}
            `
        },
        
        BRUTE_FORCE: {
            severity: 'warning',
            title: '🔐 محاولة Brute Force',
            getMessage: (d) => `
<b>محاولات تسجيل دخول مشبوهة</b>

👤 اسم المستخدم: <code>${d.username}</code>
🌐 IP: <code>${d.ip}</code>
🔢 عدد المحاولات: ${d.attempts}
⏱ آخر محاولة: منذ ${d.lastAttempt}

⚠️ تم تفعيل الحماية التلقائية
            `
        },

        ROOTED_DEVICE: {
            severity: 'warning',
            title: '📱 جهاز Rooted',
            getMessage: (d) => `
<b>تسجيل دخول من جهاز معدّل</b>

👤 المستخدم: <code>${d.username}</code>
📱 الجهاز: ${d.device}
🌐 IP: <code>${d.ip}</code>
🔧 نوع النظام: ${d.os}

⚠️ الجهاز يحتوي على صلاحيات Root
            `
        },

        SQL_INJECTION: {
            severity: 'critical',
            title: '💉 محاولة SQL Injection',
            getMessage: (d) => `
<b>محاولة اختراق SQL Injection</b>

🌐 IP: <code>${d.ip}</code>
🎯 Endpoint: ${d.endpoint}
📝 Payload: <code>${d.payload?.substring(0, 100)}</code>

🛡️ تم حظر الطلب تلقائياً
            `
        },

        DDOS_ATTEMPT: {
            severity: 'critical',
            title: '⚡ هجوم DDoS محتمل',
            getMessage: (d) => `
<b>نشاط غير طبيعي مكتشف</b>

🌐 IP: <code>${d.ip}</code>
📊 عدد الطلبات: ${d.requestCount}
⏱ خلال: ${d.timeWindow}
🚦 الحالة: ${d.status}

🛡️ تم تفعيل الحد من المعدل
            `
        },

        SUSPICIOUS_ACTIVITY: {
            severity: 'warning',
            title: '🔍 نشاط مشبوه',
            getMessage: (d) => `
<b>نشاط مشبوه مكتشف</b>

🌐 IP: <code>${d.ip}</code>
📋 التفاصيل: ${d.details}
🔢 نقاط الشك: ${d.score}

${d.action ? `⚙️ الإجراء: ${d.action}` : ''}
            `
        },

        DEVICE_MISMATCH: {
            severity: 'warning',
            title: '📱 عدم تطابق الجهاز',
            getMessage: (d) => `
<b>محاولة دخول من جهاز غير مصرح</b>

👤 المستخدم: <code>${d.username}</code>
🌐 IP: <code>${d.ip}</code>
📱 الجهاز المتوقع: ${d.expectedDevice}
📱 الجهاز المستخدم: ${d.actualDevice}

🚫 تم رفض الطلب
            `
        },

        SYSTEM_OVERLOAD: {
            severity: 'critical',
            title: '🔥 حمل زائد على النظام',
            getMessage: (d) => `
<b>تحذير: حمل زائد على السيرفر</b>

📊 الطلبات النشطة: ${d.activeRequests}
💾 استخدام الذاكرة: ${d.memoryUsage}%
⏱ متوسط وقت الاستجابة: ${d.avgResponseTime}ms

⚠️ قد يتأثر الأداء
            `
        }
    };

    const alert = alerts[type];
    if (!alert) {
        console.error(`Unknown alert type: ${type}`);
        return;
    }

    const message = alert.getMessage(details);
    const subject = alert.title;

    // إرسال للتليجرام والإيميل بالتوازي
    await Promise.all([
        sendTelegramAlert(message, alert.severity),
        sendEmailAlert(subject, message, alert.severity)
    ]);
}

// ═══════════════════════════════════════════
// 📊 تقرير يومي
// ═══════════════════════════════════════════
async function sendDailyReport(stats) {
    const message = `
<b>📊 التقرير اليومي - الأمان</b>

🔒 <b>إحصائيات الحماية:</b>
• IPs محظورة: ${stats.blockedIPs || 0}
• محاولات فاشلة: ${stats.failedAttempts || 0}
• طلبات مشبوهة: ${stats.suspiciousRequests || 0}
• أجهزة Rooted: ${stats.rootedDevices || 0}

✅ <b>نشاط المستخدمين:</b>
• تسجيلات دخول ناجحة: ${stats.successfulLogins || 0}
• مستخدمين فريدين: ${stats.uniqueUsers || 0}
• إجمالي الطلبات: ${stats.totalRequests || 0}

⚡ <b>أداء النظام:</b>
• متوسط وقت الاستجابة: ${stats.avgResponseTime || 0}ms
• وقت التشغيل: ${stats.uptime || 'N/A'}
• استخدام الذاكرة: ${stats.memoryUsage || 'N/A'}%

🏆 أكثر IPs نشاطاً:
${stats.topIPs?.slice(0, 5).map((ip, i) => `${i + 1}. ${ip.address} (${ip.count} طلب)`).join('\n') || 'لا توجد بيانات'}
    `.trim();

    await Promise.all([
        sendTelegramAlert(message, 'info'),
        sendEmailAlert('📊 التقرير اليومي', message, 'info')
    ]);
}

// ═══════════════════════════════════════════
// 🧪 اختبار الإشعارات
// ═══════════════════════════════════════════
async function testNotifications() {
    console.log('🧪 Testing notification system...\n');

    // اختبار تليجرام
    console.log('📱 Testing Telegram...');
    await sendTelegramAlert('✅ اختبار نظام التنبيهات - التليجرام يعمل بنجاح!', 'success');
    
    // اختبار الإيميل
    console.log('📧 Testing Email...');
    await sendEmailAlert(
        '✅ اختبار النظام',
        'هذا اختبار لنظام الإشعارات.\n\nإذا وصلتك هذه الرسالة، فالنظام يعمل بشكل صحيح!',
        'success'
    );

    console.log('\n✅ Test complete! Check your Telegram and Email.');
}

module.exports = {
    sendSecurityAlert,
    sendTelegramAlert,
    sendEmailAlert,
    sendDailyReport,
    testNotifications
};
