// config/constants.js - Constants v14.1 Fixed
'use strict';

require('dotenv').config();

// ═══════════════════════════════════════════
// 🔐 إعدادات التوقيع الآمنة
// ═══════════════════════════════════════════
const SIGNING_SALT = process.env.SIGNING_SALT || 'SubAdminSecureSalt@2024!NoOneKnows';

// ═══════════════════════════════════════════
// API Keys & Credentials
// ═══════════════════════════════════════════
const APP_API_KEY = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';

const ADMIN_CREDENTIALS = {
    username: process.env.ADMIN_USERNAME || 'admin',
    password: process.env.ADMIN_PASSWORD || 'Admin@123456'
};

// ═══════════════════════════════════════════
// 🔑 MASTER ADMIN TOKEN (اختياري - للوصول المباشر)
// ═══════════════════════════════════════════
const MASTER_ADMIN_TOKEN = process.env.MASTER_ADMIN_TOKEN || null;

// ═══════════════════════════════════════════
// Signed Endpoints List
// ═══════════════════════════════════════════
const SIGNED_ENDPOINTS = [
    '/api/getUser',
    '/api/verifyAccount',
    '/api/updateDevice',
    '/api/sub/verify-key',
    '/api/sub/users',
    '/api/sub/users/:id/extend',
    '/api/sub/users/:id',
    '/api/sub/users/:id/reset-device',
    '/api/sub/users/:id/details',
    '/api/sub/stats'
];

// ═══════════════════════════════════════════
// 🛡️ Security Configuration
// ═══════════════════════════════════════════
const SECURITY = {
    PROTECTION_LEVEL: process.env.PROTECTION_LEVEL || 'balanced',
    ENABLE_WAF: true,
    ENABLE_RATE_LIMIT: true,
    ENABLE_BOT_DETECTION: true,
    ANOMALY_THRESHOLD: 70,
    SOFT_BLOCK_VIOLATIONS: 3,
    IP_CACHE_TTL: 300,
    
    RATE_LIMITS: {
        AUTH: { capacity: 10, refill: 1 },
        ADMIN: { capacity: 100, refill: 20 },
        API: { capacity: 60, refill: 10 },
        GLOBAL: { capacity: 200, refill: 50 }
    },
    
    WAF: {
        MAX_URL_LENGTH: 2048,
        MAX_BODY_SIZE: 1048576
    },
    
    BRUTE_FORCE: {
        MAX_ATTEMPTS: 5,
        LOCKOUT_DURATION: 15 * 60 * 1000
    }
};

const DDOS = {
    MAX_REQUESTS_PER_MINUTE: 100,
    WARNING_THRESHOLD: 60,
    BLOCK_DURATION: 600000,
    IP_RPS: 10
};

// ═══════════════════════════════════════════
// Session Storage (In-Memory)
// ═══════════════════════════════════════════
const adminSessions = new Map();
const subAdminKeys = new Map();
const loginAttempts = new Map();
const requestTracker = new Map();
const blockedIPs = new Set();

// ═══════════════════════════════════════════
// 📦 EXPORT
// ═══════════════════════════════════════════
module.exports = {
    SIGNING_SALT,
    APP_API_KEY,
    ADMIN_CREDENTIALS,
    MASTER_ADMIN_TOKEN,  // ✅ أضفنا هذا
    SIGNED_ENDPOINTS,
    SECURITY,
    DDOS,
    adminSessions,
    subAdminKeys,
    loginAttempts,
    requestTracker,
    blockedIPs
};
