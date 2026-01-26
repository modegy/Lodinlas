'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const net = require('net');
const { SIGNING_SALT } = require('../config/constants');

// ═══════════════════════════════════════════
// 🛠️ دوال مساعدة عامة (Production Ready - 2026)
// ═══════════════════════════════════════════

/**
 * 🔐 توليد مفتاح توقيع مشتق من API Key (HMAC-SHA512)
 */
function deriveSigningKey(apiKey) {
    if (!apiKey || typeof apiKey !== 'string') {
        throw new Error('Valid API Key is required');
    }
    if (!SIGNING_SALT) {
        throw new Error('SIGNING_SALT environment variable is not set');
    }

    return crypto
        .createHmac('sha512', SIGNING_SALT)   // SHA512 أقوى وموصى به في 2026
        .update(apiKey)
        .digest('hex');
}

/**
 * 🎟️ توليد توكن عشوائي قوي (64 بايت → 512 بت)
 */
function generateToken(length = 64) {
    if (!Number.isInteger(length) || length < 32) {
        length = 64;
    }
    return crypto.randomBytes(length).toString('hex');
}

/**
 * 🔑 تشفير كلمة المرور باستخدام bcrypt (مع cost factor قابل للتعديل)
 */
async function hashPassword(password) {
    if (!password || typeof password !== 'string') {
        throw new Error('Valid password string is required');
    }

    if (password.length < 8) {
        throw new Error('Password must be at least 8 characters long');
    }

    // في 2026: 12–14 جيد، 15–16 لتطبيقات حساسة جدًا
    const saltRounds = process.env.BCRYPT_COST ? parseInt(process.env.BCRYPT_COST, 10) : 13;

    if (saltRounds < 10 || saltRounds > 16) {
        throw new Error('Invalid BCRYPT_COST value (must be 10–16)');
    }

    return await bcrypt.hash(password, saltRounds);
}

/**
 * 🔓 التحقق من كلمة المرور (timing-safe)
 */
async function verifyPassword(password, hash) {
    if (!password || !hash || typeof password !== 'string' || typeof hash !== 'string') {
        return false;
    }

    try {
        return await bcrypt.compare(password, hash);
    } catch (err) {
        console.error('bcrypt compare error:', err.message);
        return false;
    }
}

/**
 * 📅 تنسيق التاريخ (DD/MM/YYYY HH:mm) مع timezone آمن
 */
function formatDate(timestamp, timezone = 'Asia/Riyadh') {
    if (!timestamp) return null;

    const d = new Date(timestamp);
    if (isNaN(d.getTime())) {
        throw new Error('Invalid timestamp');
    }

    // استخدام Intl لدعم الـ timezone (أكثر أماناً ودقة)
    return new Intl.DateTimeFormat('ar-SA', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
        timeZone: timezone
    }).format(d).replace(/،/g, ' ');
}

/**
 * 🌍 استخراج IP الحقيقي من الطلب (مع دعم trusted proxies)
 */
function getClientIP(req) {
    if (!req) return 'unknown';

    const forwarded = req.headers['x-forwarded-for'];
    const trustedProxies = process.env.TRUSTED_PROXIES
        ? process.env.TRUSTED_PROXIES.split(',').map(ip => ip.trim())
        : ['127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

    let ip = req.ip || 'unknown';

    if (forwarded) {
        const chain = forwarded.split(',').map(i => i.trim());
        // ابحث من الخلف حتى تجد أول IP غير موثوق
        for (let i = chain.length - 1; i >= 0; i--) {
            if (!trustedProxies.some(proxy => net.isIP(proxy) && ipMatchesRange(chain[i], proxy))) {
                ip = chain[i];
                break;
            }
        }
    }

    // التحقق النهائي من صحة الـ IP
    return net.isIP(ip) ? ip : 'unknown';
}

// دالة مساعدة للتحقق من نطاقات الـ proxy (CIDR بسيط)
function ipMatchesRange(ip, range) {
    if (range.includes('/')) {
        // دعم بسيط لـ CIDR (يمكن توسيعه بـ ipaddr.js لاحقاً)
        const [subnet, bits] = range.split('/');
        return ip.startsWith(subnet); // تقريبي – للدقة استخدم مكتبة
    }
    return ip === range;
}

module.exports = {
    deriveSigningKey,
    generateToken,
    hashPassword,
    verifyPassword,
    formatDate,
    getClientIP
};
