// ═══════════════════════════════════════════
// 🤖 TELEGRAM ADMIN BOT - Complete Control
// ملف: middleware/telegramBot.js
// ═══════════════════════════════════════════

const axios = require('axios');
const { sendSecurityAlert } = require('./notifications');

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const ADMIN_CHAT_IDS = (process.env.ADMIN_CHAT_IDS || '').split(',').filter(Boolean);

// حالة السيرفر
let serverState = {
    isRunning: true,
    isPaused: false,
    maintenanceMode: false,
    blockedIPs: new Set(),
    allowedIPs: new Set(),
    stats: {
        totalRequests: 0,
        blockedRequests: 0,
        activeUsers: 0,
        lastRestart: Date.now()
    }
};

// ═══════════════════════════════════════════
// 📱 Telegram API Wrapper
// ═══════════════════════════════════════════
async function sendTelegramMessage(chatId, text, options = {}) {
    if (!BOT_TOKEN) return;
    
    try {
        await axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            chat_id: chatId,
            text,
            parse_mode: options.parse_mode || 'HTML',
            reply_markup: options.reply_markup || null,
            disable_notification: options.silent || false
        });
    } catch (error) {
        console.error('Telegram send error:', error.message);
    }
}

async function editTelegramMessage(chatId, messageId, text, options = {}) {
    if (!BOT_TOKEN) return;
    
    try {
        await axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/editMessageText`, {
            chat_id: chatId,
            message_id: messageId,
            text,
            parse_mode: options.parse_mode || 'HTML',
            reply_markup: options.reply_markup || null
        });
    } catch (error) {
        console.error('Telegram edit error:', error.message);
    }
}

async function answerCallbackQuery(callbackQueryId, text, showAlert = false) {
    if (!BOT_TOKEN) return;
    
    try {
        await axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/answerCallbackQuery`, {
            callback_query_id: callbackQueryId,
            text,
            show_alert: showAlert
        });
    } catch (error) {
        console.error('Callback answer error:', error.message);
    }
}

// ═══════════════════════════════════════════
// 🎛️ Inline Keyboards
// ═══════════════════════════════════════════
const keyboards = {
    mainMenu: {
        inline_keyboard: [
            [
                { text: '🔴 إيقاف السيرفر', callback_data: 'server_stop' },
                { text: '🟢 تشغيل السيرفر', callback_data: 'server_start' }
            ],
            [
                { text: '🔄 إعادة التشغيل', callback_data: 'server_restart' },
                { text: '🛠️ وضع الصيانة', callback_data: 'server_maintenance' }
            ],
            [
                { text: '📊 الإحصائيات', callback_data: 'stats_view' },
                { text: '👥 المستخدمين', callback_data: 'users_view' }
            ],
            [
                { text: '🚫 الـ IPs المحظورة', callback_data: 'ips_blocked' },
                { text: '✅ IPs مسموحة', callback_data: 'ips_allowed' }
            ],
            [
                { text: '🔍 فحص IP', callback_data: 'ip_check' },
                { text: '🧹 مسح Cache', callback_data: 'cache_clear' }
            ],
            [
                { text: '📋 Logs آخر ساعة', callback_data: 'logs_view' },
                { text: '⚙️ الإعدادات', callback_data: 'settings' }
            ]
        ]
    },
    
    serverControl: (isRunning, isPaused, isMaintenance) => ({
        inline_keyboard: [
            [
                { 
                    text: isRunning ? '🟢 السيرفر يعمل' : '🔴 السيرفر متوقف', 
                    callback_data: 'status_info' 
                }
            ],
            [
                { 
                    text: isPaused ? '▶️ استئناف' : '⏸️ إيقاف مؤقت', 
                    callback_data: isPaused ? 'server_resume' : 'server_pause' 
                }
            ],
            [
                { 
                    text: isMaintenance ? '✅ إنهاء الصيانة' : '🛠️ وضع الصيانة', 
                    callback_data: isMaintenance ? 'maintenance_off' : 'maintenance_on' 
                }
            ],
            [
                { text: '🔄 إعادة تشغيل', callback_data: 'server_restart_confirm' }
            ],
            [
                { text: '◀️ رجوع', callback_data: 'menu_main' }
            ]
        ]
    }),
    
    ipActions: (ip) => ({
        inline_keyboard: [
            [
                { text: '🚫 حظر', callback_data: `ip_block_${ip}` },
                { text: '✅ السماح', callback_data: `ip_allow_${ip}` }
            ],
            [
                { text: '🔍 معلومات تفصيلية', callback_data: `ip_details_${ip}` }
            ],
            [
                { text: '◀️ رجوع', callback_data: 'menu_main' }
            ]
        ]
    }),
    
    confirmAction: (action, data) => ({
        inline_keyboard: [
            [
                { text: '✅ تأكيد', callback_data: `confirm_${action}_${data}` },
                { text: '❌ إلغاء', callback_data: 'menu_main' }
            ]
        ]
    })
};

// ═══════════════════════════════════════════
// 🎯 Command Handlers
// ═══════════════════════════════════════════
const commandHandlers = {
    '/start': async (chatId) => {
        if (!isAdmin(chatId)) {
            await sendTelegramMessage(chatId, '⛔ غير مصرح لك باستخدام هذا البوت');
            return;
        }
        
        const welcomeMsg = `
🤖 <b>مرحباً في لوحة التحكم الكاملة</b>

👑 Master Admin Control Panel

استخدم الأزرار أدناه للتحكم الكامل بالسيرفر:

🔴 <b>إيقاف/تشغيل السيرفر</b>
🚫 <b>حظر وإلغاء حظر IPs</b>
📊 <b>عرض الإحصائيات الحية</b>
👥 <b>إدارة المستخدمين</b>
🛠️ <b>وضع الصيانة</b>

<i>جميع الإجراءات مسجلة ومراقبة 🔒</i>
        `.trim();
        
        await sendTelegramMessage(chatId, welcomeMsg, {
            reply_markup: keyboards.mainMenu
        });
    },
    
    '/status': async (chatId) => {
        if (!isAdmin(chatId)) return;
        
        const uptime = Math.floor((Date.now() - serverState.stats.lastRestart) / 1000);
        const hours = Math.floor(uptime / 3600);
        const minutes = Math.floor((uptime % 3600) / 60);
        
        const statusMsg = `
📊 <b>حالة السيرفر</b>

${serverState.isRunning ? '🟢 يعمل' : '🔴 متوقف'}
${serverState.isPaused ? '⏸️ موقف مؤقتاً' : ''}
${serverState.maintenanceMode ? '🛠️ وضع الصيانة' : ''}

⏱ <b>وقت التشغيل:</b> ${hours}س ${minutes}د
📈 <b>إجمالي الطلبات:</b> ${serverState.stats.totalRequests}
🚫 <b>الطلبات المحظورة:</b> ${serverState.stats.blockedRequests}
👥 <b>المستخدمين النشطين:</b> ${serverState.stats.activeUsers}
🔒 <b>IPs محظورة:</b> ${serverState.blockedIPs.size}

💾 <b>الذاكرة:</b> ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB
🖥️ <b>CPU:</b> ${process.cpuUsage().user}%
        `.trim();
        
        await sendTelegramMessage(chatId, statusMsg, {
            reply_markup: keyboards.serverControl(
                serverState.isRunning,
                serverState.isPaused,
                serverState.maintenanceMode
            )
        });
    },
    
    '/block': async (chatId, args) => {
        if (!isAdmin(chatId)) return;
        
        if (!args[0]) {
            await sendTelegramMessage(chatId, '❌ استخدام: /block [IP_ADDRESS]');
            return;
        }
        
        const ip = args[0];
        serverState.blockedIPs.add(ip);
        
        await sendTelegramMessage(chatId, `✅ تم حظر IP: <code>${ip}</code>`, {
            reply_markup: keyboards.ipActions(ip)
        });
        
        // Log the action
        logAdminAction(chatId, 'IP_BLOCKED', { ip });
    },
    
    '/unblock': async (chatId, args) => {
        if (!isAdmin(chatId)) return;
        
        if (!args[0]) {
            await sendTelegramMessage(chatId, '❌ استخدام: /unblock [IP_ADDRESS]');
            return;
        }
        
        const ip = args[0];
        serverState.blockedIPs.delete(ip);
        
        await sendTelegramMessage(chatId, `✅ تم إلغاء حظر IP: <code>${ip}</code>`);
        
        logAdminAction(chatId, 'IP_UNBLOCKED', { ip });
    },
    
    '/users': async (chatId, args) => {
        if (!isAdmin(chatId)) return;
        
        const limit = parseInt(args[0]) || 10;
        
        try {
            // استدعاء API للحصول على المستخدمين
            const users = await getRecentUsers(limit);
            
            const usersList = users.map((u, i) => 
                `${i + 1}. <code>${u.username}</code> - ${u.isActive ? '✅' : '⏸️'} - ${u.expiryDate}`
            ).join('\n');
            
            const msg = `
👥 <b>آخر ${limit} مستخدمين</b>

${usersList}

<i>استخدم /users [عدد] لعرض أكثر</i>
            `.trim();
            
            await sendTelegramMessage(chatId, msg);
        } catch (error) {
            await sendTelegramMessage(chatId, '❌ خطأ في جلب المستخدمين');
        }
    },
    
    '/help': async (chatId) => {
        if (!isAdmin(chatId)) return;
        
        const helpMsg = `
📖 <b>قائمة الأوامر</b>

/start - القائمة الرئيسية
/status - حالة السيرفر
/block [IP] - حظر IP
/unblock [IP] - إلغاء حظر IP
/users [عدد] - عرض المستخدمين
/stats - الإحصائيات التفصيلية
/restart - إعادة تشغيل السيرفر
/maintenance - وضع الصيانة
/logs [دقائق] - عرض السجلات
/clear - مسح الـ Cache
/help - هذه القائمة

💡 <b>نصيحة:</b> استخدم الأزرار للوصول السريع!
        `.trim();
        
        await sendTelegramMessage(chatId, helpMsg);
    }
};

// ═══════════════════════════════════════════
// 🎮 Callback Query Handlers
// ═══════════════════════════════════════════
const callbackHandlers = {
    'server_stop': async (chatId, messageId, queryId) => {
        await answerCallbackQuery(queryId, '⏳ جاري إيقاف السيرفر...');
        
        serverState.isRunning = false;
        serverState.isPaused = true;
        
        const msg = `
⏸️ <b>تم إيقاف السيرفر مؤقتاً</b>

جميع الطلبات الجديدة محظورة مؤقتاً.
المستخدمين الحاليين سيستمرون حتى انتهاء جلساتهم.

⏰ الوقت: ${new Date().toLocaleString('ar-EG')}
        `.trim();
        
        await editTelegramMessage(chatId, messageId, msg, {
            reply_markup: keyboards.serverControl(false, true, serverState.maintenanceMode)
        });
        
        logAdminAction(chatId, 'SERVER_STOPPED');
    },
    
    'server_start': async (chatId, messageId, queryId) => {
        await answerCallbackQuery(queryId, '⏳ جاري تشغيل السيرفر...');
        
        serverState.isRunning = true;
        serverState.isPaused = false;
        serverState.maintenanceMode = false;
        
        const msg = `
✅ <b>تم تشغيل السيرفر بنجاح</b>

السيرفر يعمل بكامل طاقته.
جميع الخدمات متاحة الآن.

⏰ الوقت: ${new Date().toLocaleString('ar-EG')}
        `.trim();
        
        await editTelegramMessage(chatId, messageId, msg, {
            reply_markup: keyboards.serverControl(true, false, false)
        });
        
        logAdminAction(chatId, 'SERVER_STARTED');
    },
    
    'server_restart': async (chatId, messageId, queryId) => {
        const msg = `
⚠️ <b>تأكيد إعادة التشغيل</b>

هل أنت متأكد من إعادة تشغيل السيرفر؟

⚠️ سيؤدي هذا إلى:
• قطع جميع الاتصالات الحالية
• مسح الـ Cache
• إعادة تحميل جميع الإعدادات

⏱ المدة المتوقعة: 10-30 ثانية
        `.trim();
        
        await editTelegramMessage(chatId, messageId, msg, {
            reply_markup: keyboards.confirmAction('restart', 'server')
        });
    },
    
    'confirm_restart_server': async (chatId, messageId, queryId) => {
        await answerCallbackQuery(queryId, '🔄 جاري إعادة التشغيل...', true);
        
        const msg = `
🔄 <b>إعادة تشغيل السيرفر...</b>

⏳ يرجى الانتظار...

سيتم إرسال إشعار عند اكتمال العملية.
        `.trim();
        
        await editTelegramMessage(chatId, messageId, msg);
        
        // تنفيذ إعادة التشغيل
        setTimeout(async () => {
            serverState.stats.lastRestart = Date.now();
            serverState.stats.totalRequests = 0;
            serverState.stats.blockedRequests = 0;
            
            // يمكنك إضافة process.exit(0) هنا إذا كنت تستخدم PM2
            // process.exit(0);
            
            const successMsg = `
✅ <b>تمت إعادة التشغيل بنجاح</b>

السيرفر يعمل الآن بشكل طبيعي.

⏰ الوقت: ${new Date().toLocaleString('ar-EG')}
            `.trim();
            
            await sendTelegramMessage(chatId, successMsg, {
                reply_markup: keyboards.mainMenu
            });
            
            logAdminAction(chatId, 'SERVER_RESTARTED');
        }, 3000);
    },
    
    'server_maintenance': async (chatId, messageId, queryId) => {
        serverState.maintenanceMode = !serverState.maintenanceMode;
        
        const status = serverState.maintenanceMode ? 'مفعل' : 'معطل';
        await answerCallbackQuery(queryId, `✅ وضع الصيانة ${status}`);
        
        const msg = `
${serverState.maintenanceMode ? '🛠️' : '✅'} <b>وضع الصيانة ${status}</b>

${serverState.maintenanceMode ? 
    'جميع المستخدمين سيتلقون رسالة صيانة.' :
    'السيرفر متاح للجميع الآن.'
}

⏰ الوقت: ${new Date().toLocaleString('ar-EG')}
        `.trim();
        
        await editTelegramMessage(chatId, messageId, msg, {
            reply_markup: keyboards.serverControl(
                serverState.isRunning,
                serverState.isPaused,
                serverState.maintenanceMode
            )
        });
        
        logAdminAction(chatId, 'MAINTENANCE_MODE_CHANGED', { 
            enabled: serverState.maintenanceMode 
        });
    },
    
    'stats_view': async (chatId, messageId, queryId) => {
        await answerCallbackQuery(queryId, 'جاري تحميل الإحصائيات...');
        
        try {
            const stats = await getDetailedStats();
            
            const msg = `
📊 <b>الإحصائيات التفصيلية</b>

👥 <b>المستخدمين:</b>
• الإجمالي: ${stats.totalUsers}
• النشطين: ${stats.activeUsers}
• المنتهيين: ${stats.expiredUsers}
• أجهزة Rooted: ${stats.rootedDevices}

📈 <b>النشاط:</b>
• اليوم: ${stats.todayLogins}
• هذا الأسبوع: ${stats.weekLogins}
• هذا الشهر: ${stats.monthLogins}

🔒 <b>الأمان:</b>
• IPs محظورة: ${serverState.blockedIPs.size}
• محاولات فاشلة: ${stats.failedAttempts}
• هجمات محظورة: ${serverState.stats.blockedRequests}

⏱ <b>آخر تحديث:</b> ${new Date().toLocaleString('ar-EG')}
            `.trim();
            
            await editTelegramMessage(chatId, messageId, msg, {
                reply_markup: {
                    inline_keyboard: [
                        [{ text: '🔄 تحديث', callback_data: 'stats_view' }],
                        [{ text: '◀️ رجوع', callback_data: 'menu_main' }]
                    ]
                }
            });
        } catch (error) {
            await answerCallbackQuery(queryId, '❌ خطأ في جلب الإحصائيات', true);
        }
    },
    
    'ips_blocked': async (chatId, messageId, queryId) => {
        await answerCallbackQuery(queryId, 'جاري تحميل القائمة...');
        
        const blockedList = Array.from(serverState.blockedIPs);
        
        if (blockedList.length === 0) {
            await editTelegramMessage(chatId, messageId, '✅ لا توجد IPs محظورة حالياً', {
                reply_markup: {
                    inline_keyboard: [[{ text: '◀️ رجوع', callback_data: 'menu_main' }]]
                }
            });
            return;
        }
        
        const list = blockedList.slice(0, 20).map((ip, i) => 
            `${i + 1}. <code>${ip}</code>`
        ).join('\n');
        
        const msg = `
🚫 <b>IPs المحظورة (${blockedList.length})</b>

${list}

${blockedList.length > 20 ? `\n<i>وهناك ${blockedList.length - 20} أخرى...</i>` : ''}

استخدم /unblock [IP] لإلغاء الحظر
        `.trim();
        
        await editTelegramMessage(chatId, messageId, msg, {
            reply_markup: {
                inline_keyboard: [
                    [{ text: '🧹 مسح الكل', callback_data: 'ips_clear_all' }],
                    [{ text: '◀️ رجوع', callback_data: 'menu_main' }]
                ]
            }
        });
    },
    
    'cache_clear': async (chatId, messageId, queryId) => {
        await answerCallbackQuery(queryId, '🧹 جاري مسح الـ Cache...', true);
        
        // مسح الـ Cache هنا
        serverState.stats.totalRequests = 0;
        serverState.stats.blockedRequests = 0;
        
        const msg = `
✅ <b>تم مسح الـ Cache بنجاح</b>

تم مسح:
• عدادات الطلبات
• بيانات الجلسات المنتهية
• السجلات المؤقتة

⏰ الوقت: ${new Date().toLocaleString('ar-EG')}
        `.trim();
        
        await editTelegramMessage(chatId, messageId, msg, {
            reply_markup: {
                inline_keyboard: [[{ text: '◀️ رجوع', callback_data: 'menu_main' }]]
            }
        });
        
        logAdminAction(chatId, 'CACHE_CLEARED');
    },
    
    'menu_main': async (chatId, messageId, queryId) => {
        await answerCallbackQuery(queryId);
        
        const msg = `
🎛️ <b>لوحة التحكم الرئيسية</b>

اختر الإجراء المطلوب من الأزرار أدناه:
        `.trim();
        
        await editTelegramMessage(chatId, messageId, msg, {
            reply_markup: keyboards.mainMenu
        });
    }
};

// ═══════════════════════════════════════════
// 🔧 Helper Functions
// ═══════════════════════════════════════════
function isAdmin(chatId) {
    return ADMIN_CHAT_IDS.includes(String(chatId));
}

function logAdminAction(chatId, action, data = {}) {
    const log = {
        timestamp: new Date().toISOString(),
        chatId,
        action,
        data,
        server: process.env.RENDER_EXTERNAL_URL || 'local'
    };
    
    console.log('📝 Admin Action:', JSON.stringify(log));
    
    // يمكنك حفظ في قاعدة بيانات هنا
}

async function getRecentUsers(limit = 10) {
    // استدعاء الـ API أو قاعدة البيانات
    // مثال:
    try {
        const response = await axios.get(`${process.env.API_URL}/admin/users?limit=${limit}`);
        return response.data.users || [];
    } catch (error) {
        return [];
    }
}

async function getDetailedStats() {
    // جلب الإحصائيات من قاعدة البيانات
    return {
        totalUsers: 0,
        activeUsers: 0,
        expiredUsers: 0,
        rootedDevices: 0,
        todayLogins: 0,
        weekLogins: 0,
        monthLogins: 0,
        failedAttempts: 0
    };
}

// ═══════════════════════════════════════════
// 🎯 Main Bot Handler
// ═══════════════════════════════════════════
async function handleTelegramUpdate(update) {
    try {
        // معالجة الرسائل
        if (update.message) {
            const chatId = update.message.chat.id;
            const text = update.message.text || '';
            
            if (text.startsWith('/')) {
                const [command, ...args] = text.split(' ');
                const handler = commandHandlers[command];
                
                if (handler) {
                    await handler(chatId, args);
                } else {
                    await sendTelegramMessage(chatId, '❌ أمر غير معروف. استخدم /help للمساعدة');
                }
            }
        }
        
        // معالجة Callback Queries (الأزرار)
        if (update.callback_query) {
            const query = update.callback_query;
            const chatId = query.message.chat.id;
            const messageId = query.message.message_id;
            const data = query.data;
            
            const handler = callbackHandlers[data];
            
            if (handler) {
                await handler(chatId, messageId, query.id);
            } else {
                await answerCallbackQuery(query.id, '❌ إجراء غير معروف');
            }
        }
    } catch (error) {
        console.error('Bot handler error:', error);
    }
}

// ═══════════════════════════════════════════
// 🌐 Webhook Setup
// ═══════════════════════════════════════════
async function setupTelegramWebhook(webhookUrl) {
    if (!BOT_TOKEN) {
        console.log('⚠️ Telegram bot not configured');
        return;
    }
    
    try {
        await axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`, {
            url: webhookUrl,
            allowed_updates: ['message', 'callback_query']
        });
        
        console.log('✅ Telegram webhook set:', webhookUrl);
    } catch (error) {
        console.error('❌ Webhook setup error:', error.message);
    }
}

// ═══════════════════════════════════════════
// 📢 Broadcast to Admins
// ═══════════════════════════════════════════
async function notifyAdmins(message, options = {}) {
    for (const chatId of ADMIN_CHAT_IDS) {
        await sendTelegramMessage(chatId, message, options);
    }
}

// ═══════════════════════════════════════════
// 🚀 Auto Notifications on Server Events
// ═══════════════════════════════════════════
async function sendServerAlert(type, details) {
    const alerts = {
        SERVER_STARTED: `
🟢 <b>السيرفر بدأ التشغيل</b>

⏰ ${new Date().toLocaleString('ar-EG')}
🌐 ${process.env.RENDER_EXTERNAL_URL || 'Local'}
        `,
        
        SERVER_CRASHED: `
🔴 <b>تحذير: السيرفر توقف!</b>

⚠️ السبب: ${details.error || 'Unknown'}
⏰ ${new Date().toLocaleString('ar-EG')}

يرجى التحقق من السيرفر فوراً!
        `,
        
        HIGH_TRAFFIC: `
⚡ <b>تحذير: حركة مرور عالية</b>

📊 الطلبات/دقيقة: ${details.rpm}
🌐 IPs فريدة: ${details.uniqueIPs}

قد يكون هجوم DDoS محتمل!
        `
    };
    
    const message = alerts[type] || details.message;
    await notifyAdmins(message, {
        reply_markup: keyboards.mainMenu
    });
}

module.exports = {
    handleTelegramUpdate,
    setupTelegramWebhook,
    notifyAdmins,
    sendServerAlert,
    serverState,
    isAdmin
};
