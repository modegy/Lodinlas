// config/constants.js - Secure Constants v15.0
// ⚠️ NO DEFAULT CREDENTIALS - All from Environment Variables!
'use strict';

require('dotenv').config();

// ═══════════════════════════════════════════════════════════════════
// 🔒 ENVIRONMENT VALIDATION
// ═══════════════════════════════════════════════════════════════════
const REQUIRED_ENV_VARS = [
    'FIREBASE_URL',
    'FIREBASE_KEY',
    'MASTER_ADMIN_USERNAME',
    'MASTER_ADMIN_PASSWORD_HASH',
    'SESSION_SECRET',
    'SIGNING_SALT'
];

// Check on load
const missingVars = REQUIRED_ENV_VARS.filter(v => !process.env[v]);
if (missingVars.length > 0) {
    console.error('\n🚨 CRITICAL: Missing required environment variables:');
    missingVars.forEach(v => console.error(`   ❌ ${v}`));
    console.error('\n⚠️  Server will not function correctly!\n');
}

// ═══════════════════════════════════════════════════════════════════
// 🔐 SIGNING SALT (For Sub Admin API Signatures)
// ═══════════════════════════════════════════════════════════════════
const SIGNING_SALT = process.env.SIGNING_SALT;

if (!SIGNING_SALT) {
    console.error('🚨 SIGNING_SALT is required for API signature verification!');
}

// ═══════════════════════════════════════════════════════════════════
// 📱 APP API KEY (For Mobile App)
// ═══════════════════════════════════════════════════════════════════
const APP_API_KEY = process.env.APP_API_KEY;

if (!APP_API_KEY) {
    console.warn('⚠️ APP_API_KEY not set - Mobile app authentication disabled');
}

// ═══════════════════════════════════════════════════════════════════
// ❌ NO DEFAULT ADMIN CREDENTIALS!
// ═══════════════════════════════════════════════════════════════════
// Master Admin credentials are ONLY read from environment in auth.js
// NEVER define default credentials here!

// ═══════════════════════════════════════════════════════════════════
// 🔐 SIGNED ENDPOINTS LIST
// ═══════════════════════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════════════════════
// 🛡️ SECURITY CONFIGURATION
// ═══════════════════════════════════════════════════════════════════
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
        LOCKOUT_DURATION: 30 * 60 * 1000 // 30 minutes
    }
};

const DDOS = {
    MAX_REQUESTS_PER_MINUTE: 100,
    WARNING_THRESHOLD: 60,
    BLOCK_DURATION: 600000,
    IP_RPS: 10
};

// ═══════════════════════════════════════════════════════════════════
// 💾 IN-MEMORY STORAGE
// ═══════════════════════════════════════════════════════════════════
const subAdminKeys = new Map();      // Sub Admin API keys cache
const requestTracker = new Map();    // Request tracking
const blockedIPs = new Set();        // Blocked IPs (security.js uses this)

// ═══════════════════════════════════════════════════════════════════
// 📦 EXPORT
// ═══════════════════════════════════════════════════════════════════
module.exports = {
    // Secrets (from env only)
    SIGNING_SALT,
    APP_API_KEY,
    
    // Signed endpoints
    SIGNED_ENDPOINTS,
    
    // Security config
    SECURITY,
    DDOS,
    
    // In-memory stores
    subAdminKeys,
    requestTracker,
    blockedIPs,
    
    // Environment check helper
    isConfigValid: () => missingVars.length === 0,
    getMissingVars: () => missingVars
};
