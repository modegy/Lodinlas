// config/index.js - Configuration for SecureArmor v14.1
require('dotenv').config();

const crypto = require('crypto');

module.exports = {
    // ═══════════════════════════════════════════
    // SERVER CONFIG
    // ═══════════════════════════════════════════
    PORT: process.env.PORT || 10000,
    NODE_ENV: process.env.NODE_ENV || 'production',
    
    // ══════════════════════════════════════════ 
    // FIREBASE CONFIG
    // ═══════════════════════════════════════════
    FIREBASE_URL: process.env.FIREBASE_URL,
    FIREBASE_KEY: process.env.FIREBASE_KEY,
    
    // ═══════════════════════════════════════════
    // SIGNING & API KEYS
    // ═══════════════════════════════════════════
    SIGNING_SALT: process.env.SIGNING_SALT || crypto.randomBytes(32).toString('hex'),
    APP_API_KEY: process.env.APP_API_KEY || crypto.randomBytes(32).toString('hex'),
    APP_SIGNING_SECRET: process.env.APP_SIGNING_SECRET,
    MASTER_ADMIN_TOKEN: process.env.MASTER_ADMIN_TOKEN,
    MASTER_SIGNING_SECRET: process.env.MASTER_SIGNING_SECRET,
    
    // ═══════════════════════════════════════════
    // ADMIN CREDENTIALS
    // ═══════════════════════════════════════════
    ADMIN_CREDENTIALS: {
        username: process.env.ADMIN_USERNAME || 'admin',
        password: process.env.ADMIN_PASSWORD || crypto.randomBytes(16).toString('hex')
    },
    
    // ═══════════════════════════════════════════
    // SESSION CONFIG
    // ═══════════════════════════════════════════
    SESSION: {
        EXPIRY: parseInt(process.env.SESSION_EXPIRY) || 24 * 60 * 60 * 1000,
        SECRET: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex')
    },
    
    // ═══════════════════════════════════════════
    // SECURITY CONFIG (لـ security.js v14.1)
    // ═══════════════════════════════════════════
    SECURITY: {
        // Redis Configuration
        REDIS_URL: process.env.REDIS_URL || null,
        REDIS_PASSWORD: process.env.REDIS_PASSWORD || null,
        REDIS_TLS: process.env.REDIS_TLS === 'true',
        
        // Rate Limiting
        RATE_LIMITS: {
            GLOBAL: { 
                capacity: parseInt(process.env.RATE_LIMIT_GLOBAL_CAPACITY) || 100, 
                refill: parseInt(process.env.RATE_LIMIT_GLOBAL_REFILL) || 10 
            },
            AUTH: { 
                capacity: parseInt(process.env.RATE_LIMIT_AUTH_CAPACITY) || 5, 
                refill: parseFloat(process.env.RATE_LIMIT_AUTH_REFILL) || 0.5 
            },
            API: { 
                capacity: parseInt(process.env.RATE_LIMIT_API_CAPACITY) || 50, 
                refill: parseInt(process.env.RATE_LIMIT_API_REFILL) || 5 
            },
            ADMIN: { 
                capacity: parseInt(process.env.RATE_LIMIT_ADMIN_CAPACITY) || 20, 
                refill: parseInt(process.env.RATE_LIMIT_ADMIN_REFILL) || 2 
            }
        },
        
        // Protection Level: 'low', 'balanced', 'high', 'paranoid'
        PROTECTION_LEVEL: process.env.PROTECTION_LEVEL || 'balanced',
        
        // Feature Toggles
        ENABLE_WAF: process.env.ENABLE_WAF !== 'false',
        ENABLE_RATE_LIMIT: process.env.ENABLE_RATE_LIMIT !== 'false',
        ENABLE_BOT_DETECTION: process.env.ENABLE_BOT_DETECTION !== 'false',
        ENABLE_HONEYPOT: process.env.ENABLE_HONEYPOT !== 'false',
        
        // Thresholds
        ANOMALY_THRESHOLD: parseInt(process.env.ANOMALY_THRESHOLD) || 70,
        SOFT_BLOCK_VIOLATIONS: parseInt(process.env.SOFT_BLOCK_VIOLATIONS) || 3,
        
        // Cache Settings (بالثواني)
        IP_CACHE_TTL: parseInt(process.env.IP_CACHE_TTL) || 300,
        THREAT_UPDATE_INTERVAL: parseInt(process.env.THREAT_UPDATE_INTERVAL) || 3600,
        
        // Alerting
        ALERT_WEBHOOK: process.env.SECURITY_WEBHOOK || null,
        APPEAL_CONTACT: process.env.APPEAL_CONTACT || 'security@yourdomain.com',
        
        // DDoS Settings
        DDOS: {
            GLOBAL_RPS: parseInt(process.env.DDOS_GLOBAL_RPS) || 10000,
            IP_RPS: parseInt(process.env.DDOS_IP_RPS) || 50,
            BURST_LIMIT: parseInt(process.env.DDOS_BURST_LIMIT) || 100,
            BLOCK_DURATION: parseInt(process.env.DDOS_BLOCK_DURATION) || 600000
        },
        
        // Brute Force Settings
        BRUTE_FORCE: {
            MAX_ATTEMPTS: parseInt(process.env.BRUTE_FORCE_MAX_ATTEMPTS) || 5,
            LOCKOUT_TIME: parseInt(process.env.BRUTE_FORCE_LOCKOUT_TIME) || 900000,
            ESCALATION_MULTIPLIER: parseFloat(process.env.BRUTE_FORCE_ESCALATION) || 2,
            MAX_LOCKOUT_TIME: parseInt(process.env.BRUTE_FORCE_MAX_LOCKOUT) || 86400000
        },
        
        // WAF Settings
        WAF: {
            MAX_URL_LENGTH: parseInt(process.env.WAF_MAX_URL_LENGTH) || 2048,
            MAX_BODY_SIZE: parseInt(process.env.WAF_MAX_BODY_SIZE) || 1048576,
            BLOCK_THRESHOLD: parseInt(process.env.WAF_BLOCK_THRESHOLD) || 10
        }
    },
    
    // ═══════════════════════════════════════════
    // LEGACY RATE LIMITS (للتوافق مع الكود القديم)
    // ═══════════════════════════════════════════
    RATE_LIMITS: {
        GLOBAL: { windowMs: 60 * 1000, max: 100 },
        LOGIN: { windowMs: 15 * 60 * 1000, max: 5 },
        API: { windowMs: 60 * 1000, max: 50 }
    },
    
    // ═══════════════════════════════════════════
    // LEGACY DDOS (للتوافق مع الكود القديم)
    // ═══════════════════════════════════════════
    DDOS: {
        MAX_REQUESTS_PER_MINUTE: 100,
        BLOCK_DURATION: 600000,
        WARNING_THRESHOLD: 60
    },
    
    // ═══════════════════════════════════════════
    // SIGNED ENDPOINTS
    // ═══════════════════════════════════════════
    SIGNED_ENDPOINTS: [
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
    ],
    
    // ═══════════════════════════════════════════
    // CORS SETTINGS
    // ═══════════════════════════════════════════
    CORS: {
        ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS 
            ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
            : ['*'],
        CREDENTIALS: true
    }
};
