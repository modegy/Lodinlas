// config/index.js
require('dotenv').config();

module.exports = {
    // Server Config
    PORT: process.env.PORT || 10000,
    
    // Firebase Config
    FIREBASE_URL: process.env.FIREBASE_URL,
    FIREBASE_KEY: process.env.FIREBASE_KEY,
    
    // Security Config
    SIGNING_SALT: process.env.SIGNING_SALT || 'SubAdminSecureSalt@2024!NoOneKnows',
    APP_API_KEY: process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$',
    APP_SIGNING_SECRET: process.env.APP_SIGNING_SECRET,
    MASTER_ADMIN_TOKEN: process.env.MASTER_ADMIN_TOKEN,
    MASTER_SIGNING_SECRET: process.env.MASTER_SIGNING_SECRET,
    
    // Admin Credentials
    ADMIN_CREDENTIALS: {
        username: process.env.ADMIN_USERNAME || 'admin',
        password: process.env.ADMIN_PASSWORD || 'Admin@123456'
    },
    
    // Rate Limits
    RATE_LIMITS: {
        GLOBAL: { windowMs: 60 * 1000, max: 100 },
        LOGIN: { windowMs: 15 * 60 * 1000, max: 5 },
        API: { windowMs: 60 * 1000, max: 50 }
    },
    
    // DDoS Protection
    DDOS: {
        MAX_REQUESTS_PER_MINUTE: 100,
        BLOCK_DURATION: 600000, // 10 minutes
        WARNING_THRESHOLD: 60
    },
    
    // Session Config
    SESSION: {
        EXPIRY: 24 * 60 * 60 * 1000 // 24 hours
    },
    
    // Signed Endpoints
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
    ]
};
