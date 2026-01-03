// helpers/utils.js - Utility Functions
const crypto = require('crypto');

// ═══════════════════════════════════════════
// TOKEN GENERATION
// ═══════════════════════════════════════════

/**
 * توليد Session Token آمن
 */
function generateToken(length = 64) {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * توليد API Key
 */
function generateApiKey() {
    const prefix = 'sk_';
    const randomPart = crypto.randomBytes(32).toString('base64')
        .replace(/[^a-zA-Z0-9]/g, '')
        .substring(0, 48);
    return prefix + randomPart;
}

/**
 * توليد Signing Secret
 */
function generateSigningSecret() {
    return crypto.randomBytes(32).toString('hex');
}

// ═══════════════════════════════════════════
// PASSWORD HASHING
// ═══════════════════════════════════════════

/**
 * تشفير كلمة المرور باستخدام SHA-256
 */
function hashPassword(password, salt = '') {
    const saltedPassword = password + salt;
    return crypto.createHash('sha256').update(saltedPassword).digest('hex');
}

/**
 * التحقق من كلمة المرور
 */
function verifyPassword(password, hash, salt = '') {
    const hashedInput = hashPassword(password, salt);
    return hashedInput === hash;
}

// ═══════════════════════════════════════════
// DATE FORMATTING
// ═══════════════════════════════════════════

/**
 * تنسيق التاريخ
 */
function formatDate(timestamp) {
    if (!timestamp || timestamp === 0) return 'غير محدد';
    
    try {
        const date = new Date(timestamp);
        
        if (isNaN(date.getTime())) return 'تاريخ غير صالح';
        
        const day = String(date.getDate()).padStart(2, '0');
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const year = date.getFullYear();
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        
        return `${day}/${month}/${year} ${hours}:${minutes}`;
    } catch (error) {
        return 'خطأ في التاريخ';
    }
}

/**
 * تنسيق التاريخ بصيغة ISO
 */
function formatDateISO(timestamp) {
    if (!timestamp) return null;
    return new Date(timestamp).toISOString();
}

/**
 * حساب الوقت المتبقي
 */
function getTimeRemaining(expiryTimestamp) {
    if (!expiryTimestamp || expiryTimestamp === 0) return 'غير محدود';
    
    const now = Date.now();
    const diff = expiryTimestamp - now;
    
    if (diff <= 0) return 'منتهي';
    
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    
    if (days > 0) return `${days} يوم ${hours} ساعة`;
    if (hours > 0) return `${hours} ساعة ${minutes} دقيقة`;
    return `${minutes} دقيقة`;
}

// ═══════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════

/**
 * التحقق من صحة اسم المستخدم
 */
function validateUsername(username) {
    if (!username || typeof username !== 'string') {
        return { valid: false, error: 'اسم المستخدم مطلوب' };
    }
    
    const trimmed = username.trim();
    
    if (trimmed.length < 3) {
        return { valid: false, error: 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل' };
    }
    
    if (trimmed.length > 20) {
        return { valid: false, error: 'اسم المستخدم يجب ألا يتجاوز 20 حرف' };
    }
    
    // التحقق من الأحرف المسموحة
    if (!/^[a-zA-Z0-9_\u0600-\u06FF]+$/.test(trimmed)) {
        return { valid: false, error: 'اسم المستخدم يحتوي على أحرف غير مسموحة' };
    }
    
    return { valid: true, username: trimmed };
}

/**
 * التحقق من صحة كلمة المرور
 */
function validatePassword(password) {
    if (!password || typeof password !== 'string') {
        return { valid: false, error: 'كلمة المرور مطلوبة' };
    }
    
    if (password.length < 4) {
        return { valid: false, error: 'كلمة المرور يجب أن تكون 4 أحرف على الأقل' };
    }
    
    if (password.length > 100) {
        return { valid: false, error: 'كلمة المرور طويلة جداً' };
    }
    
    return { valid: true };
}

// ═══════════════════════════════════════════
// IP UTILITIES
// ═══════════════════════════════════════════

/**
 * استخراج IP العميل
 */
function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.ip || req.connection?.remoteAddress || '127.0.0.1';
}

/**
 * إخفاء جزء من IP
 */
function maskIP(ip) {
    if (!ip) return 'غير معروف';
    const parts = ip.split('.');
    if (parts.length === 4) {
        return `${parts[0]}.${parts[1]}.*.*`;
    }
    return ip.substring(0, ip.length / 2) + '***';
}

// ═══════════════════════════════════════════
// MISC UTILITIES
// ═══════════════════════════════════════════

/**
 * تأخير async
 */
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * توليد ID عشوائي
 */
function generateId(prefix = '') {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(4).toString('hex');
    return prefix + timestamp + random;
}

/**
 * تنظيف النص من الأحرف الخطيرة
 */
function sanitizeString(str) {
    if (!str || typeof str !== 'string') return '';
    return str
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .trim();
}

// ═══════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════
module.exports = {
    // Token
    generateToken,
    generateApiKey,
    generateSigningSecret,
    
    // Password
    hashPassword,
    verifyPassword,
    
    // Date
    formatDate,
    formatDateISO,
    getTimeRemaining,
    
    // Validation
    validateUsername,
    validatePassword,
    
    // IP
    getClientIP,
    maskIP,
    
    // Misc
    delay,
    generateId,
    sanitizeString
};
