const crypto = require('crypto');
const { SIGNING_SALT } = require('../config/constants');

// ═══════════════════════════════════════════
// دوال مساعدة عامة
// ═══════════════════════════════════════════

/**
 * توليد مفتاح التوقيع من API Key
 */
function deriveSigningKey(apiKey) {
    return crypto.createHmac('sha256', SIGNING_SALT)
        .update(apiKey)
        .digest('hex');
}

/**
 * توليد توكن عشوائي
 */
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * تشفير كلمة المرور
 */
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

/**
 * تنسيق التاريخ
 */
function formatDate(timestamp) {
    if (!timestamp) return null;
    const d = new Date(timestamp);
    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear();
    const hours = String(d.getHours()).padStart(2, '0');
    const mins = String(d.getMinutes()).padStart(2, '0');
    return `${day}/${month}/${year} ${hours}:${mins}`;
}

/**
 * استخراج IP من الطلب
 */
function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
}

module.exports = {
    deriveSigningKey,
    generateToken,
    hashPassword,
    formatDate,
    getClientIP
};
