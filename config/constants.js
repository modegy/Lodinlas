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
// Session Storage (In-Memory)
// ═══════════════════════════════════════════
const adminSessions = new Map();
const subAdminKeys = new Map();
const loginAttempts = new Map();
const requestTracker = new Map();
const blockedIPs = new Set();

module.exports = {
    SIGNING_SALT,
    APP_API_KEY,
    ADMIN_CREDENTIALS,
    SIGNED_ENDPOINTS,
    adminSessions,
    subAdminKeys,
    loginAttempts,
    requestTracker,
    blockedIPs
};
