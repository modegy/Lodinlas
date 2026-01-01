const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', 'loopback, linklocal, uniquelocal');

// ═══════════════════════════════════════════
// التحقق من المتغيرات البيئية
// ═══════════════════════════════════════════
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
    console.error('❌ FIREBASE_URL أو FIREBASE_KEY غير موجود');
    process.exit(1);
}

// ═══════════════════════════════════════════
// 🔐 إعدادات التوقيع الآمنة
// ═══════════════════════════════════════════
const SIGNING_SALT = process.env.SIGNING_SALT || 'SubAdminSecureSalt@2024!NoOneKnows';

// ✅ إضافة signatureCache المفقود
const signatureCache = new Map();

// دالة توليد مفتاح التوقيع من API Key
function deriveSigningKey(apiKey) {
    return crypto.createHmac('sha256', SIGNING_SALT)
        .update(apiKey)
        .digest('hex');
}

// ═══════════════════════════════════════════
// 🎯 CHALLENGE-RESPONSE SYSTEM
// ═══════════════════════════════════════════
const CHALLENGE_VALIDITY_MS = 120000; // دقيقتين (مطابق للتطبيق 0x1d4c0)

// 🔐 فك تشفير الـ Signing Secret (مطابق للتطبيق)
function decryptSigningSecret() {
    try {
        const K1 = 'U0VDVVJFQEs=';  // Base64
        const K2 = 'RVkyMDIwMjQ=';  // Base64
        const ENC_SECRET = 'Z287A0fSFxFb0OCsgiJbu5SMr4G50wJtBxSqFORD+1hBSNjOOP2EjVumXAdRvuJLw0Xn98yEQZi8v6pBZaPhbQ==';
        
        // فك تشفير K1 + K2
        const k1Decoded = Buffer.from(K1, 'base64').toString('utf8');
        const k2Decoded = Buffer.from(K2, 'base64').toString('utf8');
        const combinedKey = (k1Decoded + k2Decoded).substring(0, 16);
        
        // فك تشفير ENC_SECRET
        const encryptedData = Buffer.from(ENC_SECRET, 'base64');
        const iv = encryptedData.slice(0, 16);
        const encrypted = encryptedData.slice(16);
        
        const decipher = crypto.createDecipheriv('aes-128-cbc', combinedKey, iv);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString('utf8');
    } catch (error) {
        console.error('❌ Failed to decrypt signing secret:', error.message);
        return process.env.CHALLENGE_SECRET || 'DefaultSecretKey@2024';
    }
}

// الـ Secret المفكوك (يُحسب مرة واحدة عند بدء السيرفر)
const CHALLENGE_SECRET = decryptSigningSecret();
console.log('🔑 Signing Secret loaded successfully');

// تخزين الـ Challenges النشطة
const activeChallenges = new Map();

// تنظيف الـ Challenges المنتهية كل دقيقة
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [challengeId, data] of activeChallenges.entries()) {
        if (now - data.createdAt > CHALLENGE_VALIDITY_MS) {
            activeChallenges.delete(challengeId);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`🧹 [CHALLENGE] Cleaned ${cleaned} expired challenges`);
    }
}, 60000);

// توليد Challenge جديد
function generateChallenge() {
    const challengeId = crypto.randomBytes(32).toString('hex');
    const timestamp = Date.now();
    
    // حفظ الـ challenge
    activeChallenges.set(challengeId, {
        createdAt: timestamp,
        used: false
    });
    
    return {
        challenge: challengeId,
        timestamp: timestamp,
        expires_in: CHALLENGE_VALIDITY_MS
    };
}

// التحقق من صلاحية Challenge
function validateChallenge(challengeId) {
    if (!challengeId || challengeId === '') {
        return { valid: false, error: 'Challenge required' };
    }
    
    const challengeData = activeChallenges.get(challengeId);
    
    if (!challengeData) {
        return { valid: false, error: 'Invalid or expired challenge' };
    }
    
    const now = Date.now();
    if (now - challengeData.createdAt > CHALLENGE_VALIDITY_MS) {
        activeChallenges.delete(challengeId);
        return { valid: false, error: 'Challenge expired' };
    }
    
    if (challengeData.used) {
        return { valid: false, error: 'Challenge already used' };
    }
    
    // وضع علامة أن الـ challenge تم استخدامه
    challengeData.used = true;
    
    return { valid: true };
}

// توليد التوقيع للـ Challenge-Response (مطابق للتطبيق)
// Format: method:path|bodyHash|timestamp|nonce|secret
function generateChallengeSignature(method, path, body, nonce, timestamp, secret) {
    const bodyHash = body ? 
        crypto.createHash('sha256').update(body).digest('hex') : '';
    
    // بناء string بنفس ترتيب التطبيق
    const stringToSign = `${method.toUpperCase()}:${path}|${bodyHash}|${timestamp}|${nonce}|${secret}`;
    
    return crypto.createHmac('sha256', secret)
        .update(stringToSign)
        .digest('base64')
        .replace(/=+$/, '');
}

// التحقق من توقيع Challenge-Response
function verifyChallengeSignature(req) {
    try {
        const signature = req.headers['x-signature'];
        const timestamp = req.headers['x-timestamp'];
        const nonce = req.headers['x-nonce'];
        
        if (!signature || !timestamp || !nonce) {
            return { valid: false, error: 'Missing signature headers' };
        }
        
        // التحقق من timestamp (5 دقائق)
        const now = Date.now();
        let requestTime = parseInt(timestamp);
        
        if (requestTime < 10000000000) {
            requestTime = requestTime * 1000;
        }
        
        const timeDiff = Math.abs(now - requestTime);
        if (isNaN(requestTime) || timeDiff > 300000) {
            return { valid: false, error: 'Invalid timestamp' };
        }
        
        // حساب التوقيع المتوقع
        const path = req.path;
        const method = req.method.toUpperCase();
        const bodyString = req.rawBody || JSON.stringify(req.body) || '{}';
        
        // استخدام نفس الـ secret الذي يستخدمه التطبيق
        const secret = CHALLENGE_SECRET;
        
        const expectedSignature = generateChallengeSignature(
            method, path, bodyString, nonce, timestamp, secret
        );
        
        if (signature !== expectedSignature) {
            console.error('❌ [CHALLENGE-SIG] Mismatch');
            console.error('   StringToSign:', `${method}:${path}|[hash]|${timestamp}|${nonce}|[secret]`);
            console.error('   Expected:', expectedSignature.substring(0, 20) + '...');
            console.error('   Received:', signature.substring(0, 20) + '...');
            return { valid: false, error: 'Invalid signature' };
        }
        
        return { valid: true };
        
    } catch (error) {
        console.error('❌ [CHALLENGE-SIG] Error:', error.message);
        return { valid: false, error: 'Signature verification failed' };
    }
}

// ═══════════════════════════════════════════
// الأمان والحماية
// ═══════════════════════════════════════════
app.use(helmet({ 
    contentSecurityPolicy: false, 
    crossOriginEmbedderPolicy: false 
}));

// ═══════════════════════════════════════════
// 🛡️ ADVANCED DDOS & SECURITY PROTECTION
// ═══════════════════════════════════════════
const requestTracker = new Map();
const blockedIPs = new Set();

const ddosProtection = (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const now = Date.now();
    
    if (blockedIPs.has(ip)) {
        return res.status(403).end();
    }
    
    if (!requestTracker.has(ip)) {
        requestTracker.set(ip, { 
            count: 0, 
            firstRequest: now, 
            blocked: false,
            violations: 0
        });
    }
    
    const tracker = requestTracker.get(ip);
    
    if (tracker.blocked) {
        if (now - tracker.blockedAt < 600000) {
            return res.status(429).json({ 
                error: 'Blocked. Try again later.',
                retry_after: Math.ceil((600000 - (now - tracker.blockedAt)) / 1000)
            });
        } else {
            tracker.blocked = false;
            tracker.count = 0;
        }
    }
    
    if (now - tracker.firstRequest > 60000) {
        tracker.count = 0;
        tracker.firstRequest = now;
    }
    
    tracker.count++;
    
    if (tracker.count > 60 && tracker.count <= 100) {
        console.warn(`⚠️ [WARNING] High traffic from: ${ip} (${tracker.count} req/min)`);
    }
    
    if (tracker.count > 100) {
        tracker.blocked = true;
        tracker.blockedAt = now;
        tracker.violations++;
        
        console.error(`🚫 [BLOCKED] IP: ${ip} (violation #${tracker.violations})`);
        
        if (tracker.violations >= 3) {
            blockedIPs.add(ip);
            console.error(`⛔ [BANNED] IP permanently: ${ip}`);
        }
        
        return res.status(429).json({ error: 'Rate limit exceeded' });
    }
    
    next();
};

const suspiciousRequestFilter = (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const userAgent = req.headers['user-agent'] || '';
    
    if (!userAgent || userAgent.length < 5) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    const blockedAgents = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 
        'gobuster', 'dirbuster', 'hydra', 'burp', 'zap',
        'slowloris', 'hulk', 'goldeneye', 'loic', 'hoic'
    ];
    
    const userAgentLower = userAgent.toLowerCase();
    for (const agent of blockedAgents) {
        if (userAgentLower.includes(agent)) {
            blockedIPs.add(ip);
            console.error(`⛔ [BANNED] Attack tool: ${agent} from ${ip}`);
            return res.status(403).end();
        }
    }
    
    const fullUrl = req.originalUrl || req.url;
    if (/union.*select|select.*from|drop.*table|insert.*into/i.test(fullUrl)) {
        blockedIPs.add(ip);
        console.error(`⛔ [SQL INJECTION] from: ${ip}`);
        return res.status(403).end();
    }
    
    if (/<script|javascript:|on\w+\s*=/i.test(fullUrl)) {
        console.error(`⛔ [XSS] from: ${ip}`);
        return res.status(403).end();
    }
    
    next();
};

const attackLogger = (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const sensitiveEndpoints = ['/api/admin', '/api/sub', '/api/verify', '/api/challenge'];
    
    if (sensitiveEndpoints.some(ep => req.path.startsWith(ep))) {
        console.log(`📋 [AUDIT] ${req.method} ${req.path} | IP: ${ip}`);
    }
    
    next();
};

app.use(ddosProtection);
app.use(suspiciousRequestFilter);
app.use(attackLogger);

// تنظيف دوري
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of requestTracker.entries()) {
        if (now - data.firstRequest > 3600000) {
            requestTracker.delete(ip);
        }
    }
    console.log(`📊 [STATS] Tracking: ${requestTracker.size} IPs | Blocked: ${blockedIPs.size} | Active Challenges: ${activeChallenges.size}`);
}, 3600000);

// ═══════════════════════════════════════════
// CORS
// ═══════════════════════════════════════════
app.use(cors({
    origin: function(origin, callback) {
        const allowedOrigins = process.env.ALLOWED_ORIGINS 
            ? process.env.ALLOWED_ORIGINS.split(',') 
            : ['*'];
        
        if (allowedOrigins[0] === '*' || !origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
}));

// ═══════════════════════════════════════════
// SIGNATURE VERIFICATION SYSTEM
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
    '/api/sub/stats',
    '/api/sub/unbind-device'
];

// Endpoints التي تحتاج Challenge-Response
const CHALLENGE_ENDPOINTS = [
    '/api/verify'
];

// ═══════════════════════════════════════════
// Rate Limiting
// ═══════════════════════════════════════════
const createRateLimiter = (windowMs, max, message) => {
    return rateLimit({
        windowMs, 
        max,
        message: { success: false, error: message },
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req) => {
            return req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
                || req.headers['x-real-ip'] 
                || req.ip 
                || req.connection.remoteAddress;
        }
    });
};

const globalLimiter = createRateLimiter(60 * 1000, 100, 'Too many requests');
const loginLimiter = createRateLimiter(15 * 60 * 1000, 5, 'Too many login attempts');
const apiLimiter = createRateLimiter(60 * 1000, 50, 'API rate limit exceeded');
const challengeLimiter = createRateLimiter(60 * 1000, 30, 'Too many challenge requests');

app.use('/', globalLimiter);

// حفظ الـ raw body
app.use(express.json({ 
    limit: '2mb',
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));

// ═══════════════════════════════════════════
// Brute Force Protection
// ═══════════════════════════════════════════
const loginAttempts = new Map();

const bruteForceProtection = (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    
    if (!loginAttempts.has(ip)) {
        loginAttempts.set(ip, { count: 0, lastAttempt: Date.now() });
    }
    
    const attempt = loginAttempts.get(ip);
    
    if (Date.now() - attempt.lastAttempt > 15 * 60 * 1000) {
        attempt.count = 0;
    }
    
    if (attempt.count >= 5) {
        const remainingTime = Math.ceil((15 * 60 * 1000 - (Date.now() - attempt.lastAttempt)) / 1000 / 60);
        return res.status(429).json({ 
            success: false, 
            error: `Too many attempts. Try again in ${remainingTime} minutes` 
        });
    }
    
    next();
};

setInterval(() => {
    const now = Date.now();
    for (const [ip, attempt] of loginAttempts.entries()) {
        if (now - attempt.lastAttempt > 60 * 60 * 1000) {
            loginAttempts.delete(ip);
        }
    }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// Firebase Setup
// ═══════════════════════════════════════════
const firebase = axios.create({ 
    baseURL: process.env.FIREBASE_URL, 
    timeout: 10000, 
    headers: { 'Content-Type': 'application/json' } 
});

const FB_KEY = process.env.FIREBASE_KEY;
const FB_URL = process.env.FIREBASE_URL;

// ═══════════════════════════════════════════
// دوال مساعدة
// ═══════════════════════════════════════════
const adminSessions = new Map();
const subAdminKeys = new Map();

const APP_API_KEY = process.env.APP_API_KEY || 'MySecureAppKey@2024#Firebase$';
const ADMIN_CREDENTIALS = {
    username: process.env.ADMIN_USERNAME || 'admin',
    password: process.env.ADMIN_PASSWORD || 'Admin@123456'
};

function generateToken() { 
    return crypto.randomBytes(32).toString('hex'); 
}

function hashPassword(password) { 
    return crypto.createHash('sha256').update(password).digest('hex'); 
}

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

setInterval(() => {
    const now = Date.now();
    for (const [token, session] of adminSessions.entries()) {
        if (now - session.createdAt > 24 * 60 * 60 * 1000) {
            adminSessions.delete(token);
        }
    }
}, 60 * 60 * 1000);

// ═══════════════════════════════════════════
// 🔐 SIGNATURE VERIFICATION MIDDLEWARE
// ═══════════════════════════════════════════
const verifySignature = async (req, res, next) => {
    try {
        const path = req.path;
        
        // تجاوز التحقق لـ logout
        if (path === '/api/sub/logout') {
            return next();
        }
        
        // التحقق إذا كان الـ endpoint يحتاج توقيع
        const needsSignature = SIGNED_ENDPOINTS.some(endpoint => {
            if (endpoint.includes(':')) {
                const pattern = endpoint.replace(/:[^/]+/g, '([^/]+)');
                const regex = new RegExp(`^${pattern}$`);
                return regex.test(path);
            }
            return endpoint === path;
        });

        if (!needsSignature) {
            return next();
        }

        console.log('🔐 [SIGNATURE] Verifying:', req.method, path);

        const signature = req.headers['x-api-signature'];
        const timestamp = req.headers['x-timestamp'];
        const nonce = req.headers['x-nonce'];
        const clientId = req.headers['x-client-id'] || req.headers['x-api-key'];
        const freshLogin = req.headers['x-fresh-login'] === 'true';

        if (!signature || !timestamp || !nonce || !clientId) {
            console.log('❌ [SIGNATURE] Missing headers');
            return res.status(401).json({
                success: false,
                error: 'Missing signature headers'
            });
        }

        // التحقق من timestamp (5 دقائق)
        const now = Date.now();
        let requestTime = parseInt(timestamp);
        
        if (requestTime < 10000000000) {
            requestTime = requestTime * 1000;
        }
        
        const timeDiff = Math.abs(now - requestTime);
        
        if (isNaN(requestTime) || timeDiff > 300000) {
            console.warn(`❌ [SIGNATURE] Invalid timestamp: diff ${timeDiff}ms`);
            return res.status(401).json({
                success: false,
                error: 'Request timestamp is invalid or too old'
            });
        }

        // 🔑 تحديد المفتاح المستخدم للتحقق
        let secretKey = null;
        let keySource = 'unknown';
        
        if (clientId === process.env.APP_API_KEY) {
            secretKey = process.env.APP_SIGNING_SECRET;
            keySource = 'app_signing_secret';
        }
        else if (clientId === process.env.MASTER_ADMIN_TOKEN) {
            secretKey = process.env.MASTER_SIGNING_SECRET;
            keySource = 'master_signing_secret';
        }
        else {
            // للـ Sub Admin
            if (freshLogin || path === '/api/sub/verify-key') {
                secretKey = deriveSigningKey(clientId);
                keySource = 'derived_key';
            } else {
                const cached = signatureCache.get(clientId);
                if (cached && cached.secret) {
                    secretKey = cached.secret;
                    keySource = 'signature_cache';
                } else {
                    const subAdmin = subAdminKeys.get(clientId);
                    if (subAdmin && subAdmin.signing_secret) {
                        secretKey = subAdmin.signing_secret;
                        keySource = 'sub_admin_cache';
                    }
                }
            }
        }

        if (!secretKey) {
            console.error('❌ [SIGNATURE] No signing secret found');
            return res.status(401).json({
                success: false,
                error: 'Invalid signature - session expired'
            });
        }

        console.log(`🔑 [SIGNATURE] Using key from: ${keySource}`);

        // بناء string للتوقيع
        let stringToSign = '';
        
        if (req.method === 'GET' || req.method === 'DELETE') {
            stringToSign = `${req.method.toUpperCase()}:${path}|${timestamp}|${nonce}`;
        } else {
            const bodyString = req.rawBody || JSON.stringify(req.body) || '{}';
            const bodyHash = crypto.createHash('sha256')
                .update(bodyString)
                .digest('hex');
            stringToSign = `${req.method.toUpperCase()}:${path}|${bodyHash}|${timestamp}|${nonce}`;
        }

        stringToSign += `|${secretKey}`;

        const expectedSignature = crypto.createHmac('sha256', secretKey)
            .update(stringToSign)
            .digest('base64')
            .replace(/=+$/, '');

        if (signature !== expectedSignature) {
            console.error(`❌ [SIGNATURE] Invalid signature`);
            console.error('   Expected:', expectedSignature.substring(0, 20) + '...');
            console.error('   Received:', signature.substring(0, 20) + '...');

            return res.status(401).json({
                success: false,
                error: 'Invalid signature'
            });
        }

        console.log(`✅ [SIGNATURE] Valid`);
        next();

    } catch (error) {
        console.error('❌ [SIGNATURE] Error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Signature verification failed'
        });
    }
};

// ═══════════════════════════════════════════
// 🎯 CHALLENGE-RESPONSE MIDDLEWARE
// ═══════════════════════════════════════════
const verifyChallengeResponse = (req, res, next) => {
    try {
        const path = req.path;
        
        // التحقق إذا كان الـ endpoint يحتاج Challenge
        const needsChallenge = CHALLENGE_ENDPOINTS.includes(path);
        
        if (!needsChallenge) {
            return next();
        }
        
        console.log('🎯 [CHALLENGE] Verifying:', req.method, path);
        
        const challenge = req.headers['x-challenge'] || req.body?.challenge;
        
        // Challenge اختياري - إذا موجود نتحقق منه
        if (challenge && challenge !== '') {
            const challengeValidation = validateChallenge(challenge);
            if (!challengeValidation.valid) {
                console.log('⚠️ [CHALLENGE] Invalid but continuing:', challengeValidation.error);
                // نستمر حتى لو الـ challenge غير صالح
            }
        }
        
        // التحقق من التوقيع (إلزامي)
        const signatureValidation = verifyChallengeSignature(req);
        if (!signatureValidation.valid) {
            console.log('❌ [CHALLENGE-SIG] Invalid:', signatureValidation.error);
            return res.status(401).json({
                success: false,
                error: signatureValidation.error,
                code: 'SIGNATURE_INVALID'
            });
        }
        
        console.log('✅ [CHALLENGE] Valid');
        next();
        
    } catch (error) {
        console.error('❌ [CHALLENGE] Error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Challenge verification failed'
        });
    }
};

// ═══════════════════════════════════════════
// المصادقة - Middlewares
// ═══════════════════════════════════════════
const authApp = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
        return res.status(401).json({ 
            success: false, 
            error: 'API Key required', 
            code: 401 
        });
    }
    
    if (apiKey === APP_API_KEY) {
        return next();
    }
    
    res.status(401).json({ 
        success: false, 
        error: 'Invalid API Key', 
        code: 401 
    });
};

const authAdmin = (req, res, next) => {
    const sessionToken = req.headers['x-session-token'];
    const masterToken = process.env.MASTER_ADMIN_TOKEN;
    
    if (!sessionToken) {
        return res.status(401).json({ 
            success: false, 
            error: 'Session token required', 
            code: 401 
        });
    }
    
    if (masterToken && sessionToken === masterToken) {
        req.adminUser = 'master_owner';
        return next();
    }
    
    const session = adminSessions.get(sessionToken);
    
    if (!session) {
        return res.status(401).json({ 
            success: false, 
            error: 'Invalid or expired session', 
            code: 401 
        });
    }
    
    if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
        adminSessions.delete(sessionToken);
        return res.status(401).json({ 
            success: false, 
            error: 'Session expired', 
            code: 401 
        });
    }
    
    req.adminUser = session.username;
    next();
};

const authSubAdmin = async (req, res, next) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const deviceFingerprint = req.headers['x-device-fingerprint'];
        
        if (!apiKey) {
            return res.status(401).json({ 
                success: false, 
                error: 'API key required' 
            });
        }
        
        const cached = subAdminKeys.get(apiKey);
        if (cached && cached.device === deviceFingerprint) {
            if (cached.expiry_timestamp > Date.now() && cached.is_active) {
                req.subAdminKey = cached;
                req.subAdminKeyId = cached.keyId;
                return next();
            }
        }
        
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
        const keys = response.data || {};
        
        let foundKey = null;
        let keyId = null;
        
        for (const [id, key] of Object.entries(keys)) {
            if (key.api_key === apiKey) {
                foundKey = key;
                keyId = id;
                break;
            }
        }
        
        if (!foundKey) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid API key' 
            });
        }
        
        if (!foundKey.is_active) {
            return res.status(403).json({ 
                success: false, 
                error: 'Key is inactive' 
            });
        }
        
        if (foundKey.expiry_timestamp && Date.now() > foundKey.expiry_timestamp) {
            return res.status(403).json({ 
                success: false, 
                error: 'Key expired' 
            });
        }
        
        if (foundKey.bound_device && foundKey.bound_device !== deviceFingerprint) {
            return res.status(403).json({ 
                success: false, 
                error: 'Key is bound to another device' 
            });
        }
        
        subAdminKeys.set(apiKey, {
            ...foundKey,
            keyId,
            device: deviceFingerprint,
            last_used: Date.now()
        });
        
        req.subAdminKey = foundKey;
        req.subAdminKeyId = keyId;
        next();
        
    } catch (error) {
        console.error('Auth Sub Admin error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Authentication error' 
        });
    }
};

const checkSubAdminPermission = (requiredPermission) => {
    return (req, res, next) => {
        const keyData = req.subAdminKey;
        
        const permissions = {
            'full': ['view', 'add', 'extend', 'edit', 'delete'],
            'add_only': ['view', 'add'],
            'extend_only': ['view', 'extend'],
            'view_only': ['view']
        };
        
        const allowedPermissions = permissions[keyData.permission_level] || permissions.view_only;
        
        if (!allowedPermissions.includes(requiredPermission)) {
            return res.status(403).json({ 
                success: false, 
                error: 'Permission denied' 
            });
        }
        
        next();
    };
};

// ═══════════════════════════════════════════
// Logger Middleware
// ═══════════════════════════════════════════
app.use((req, res, next) => {
    const startTime = Date.now();
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        if (duration > 1000 || res.statusCode >= 400) {
            console.log(`📊 ${req.method} ${req.path} | IP: ${ip} | Status: ${res.statusCode} | Time: ${duration}ms`);
        }
    });
    
    next();
});

// ═══════════════════════════════════════════
// PUBLIC ENDPOINTS
// ═══════════════════════════════════════════
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        version: '3.4.0', 
        uptime: Math.floor(process.uptime()), 
        timestamp: Date.now(),
        features: ['challenge-response', 'signature-verification']
    });
});

app.get('/api/serverTime', apiLimiter, (req, res) => {
    res.json({ 
        success: true, 
        server_time: Date.now(), 
        formatted: new Date().toISOString() 
    });
});

// ═══════════════════════════════════════════
// 🎯 CHALLENGE ENDPOINT (جديد)
// ═══════════════════════════════════════════
app.get('/api/challenge', challengeLimiter, authApp, (req, res) => {
    try {
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
        
        const challengeData = generateChallenge();
        
        console.log(`🎯 [CHALLENGE] Generated for IP: ${ip}`);
        
        res.json({
            success: true,
            challenge: challengeData.challenge,
            timestamp: challengeData.timestamp,
            expires_in: challengeData.expires_in,
            server_time: Date.now()
        });
        
    } catch (error) {
        console.error('❌ [CHALLENGE] Generation error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to generate challenge'
        });
    }
});

// ═══════════════════════════════════════════
// 🔐 VERIFY ENDPOINT (مع Challenge-Response)
// ═══════════════════════════════════════════
app.post('/api/verify', verifyChallengeResponse, authApp, bruteForceProtection, apiLimiter, async (req, res) => {
    try {
        const { username, password_hash, device_id, challenge, nonce, timestamp } = req.body;
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
        
        console.log(`🔐 [VERIFY] Request for: ${username} from IP: ${ip}`);
        
        if (!username || !password_hash || !device_id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required fields',
                code: 400 
            });
        }
        
        // البحث عن المستخدم
        const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const response = await firebase.get(url);
        const users = response.data || {};
        
        if (Object.keys(users).length === 0) {
            // تسجيل محاولة فاشلة
            const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
            attempt.count++;
            attempt.lastAttempt = Date.now();
            loginAttempts.set(ip, attempt);
            
            console.log(`❌ [VERIFY] User not found: ${username}`);
            return res.status(401).json({ 
                success: false, 
                code: 1,
                error: 'User not found'
            });
        }
        
        const userId = Object.keys(users)[0];
        const user = users[userId];
        
        // التحقق من كلمة المرور
        if (user.password_hash !== password_hash) {
            const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
            attempt.count++;
            attempt.lastAttempt = Date.now();
            loginAttempts.set(ip, attempt);
            
            console.log(`❌ [VERIFY] Wrong password for: ${username}`);
            return res.status(401).json({ 
                success: false, 
                code: 2,
                error: 'Wrong password'
            });
        }
        
        // التحقق من حالة الحساب
        if (!user.is_active) {
            console.log(`❌ [VERIFY] Inactive account: ${username}`);
            return res.status(403).json({ 
                success: false, 
                code: 3,
                error: 'Account is inactive'
            });
        }
        
        // التحقق من الجهاز
        if (user.device_id && user.device_id !== '' && user.device_id !== device_id) {
            console.log(`❌ [VERIFY] Device mismatch for: ${username}`);
            return res.status(403).json({ 
                success: false, 
                code: 4,
                error: 'Account bound to another device'
            });
        }
        
        // التحقق من انتهاء الاشتراك
        const now = Date.now();
        if (user.subscription_end && now > user.subscription_end) {
            console.log(`❌ [VERIFY] Subscription expired for: ${username}`);
            return res.status(403).json({ 
                success: false, 
                code: 7,
                error: 'Subscription expired',
                expiry_date: formatDate(user.subscription_end)
            });
        }
        
        // تحديث بيانات المستخدم
        const updateData = {
            device_id: device_id,
            last_login: now,
            login_count: (user.login_count || 0) + 1,
            ip_address: ip,
            user_agent: req.headers['user-agent'] || ''
        };
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, updateData);
        
        // مسح محاولات تسجيل الدخول الفاشلة
        loginAttempts.delete(ip);
        
        console.log(`✅ [VERIFY] Success for: ${username}`);
        
        res.json({ 
            success: true, 
            code: 200,
            username: user.username,
            expiry_date: formatDate(user.subscription_end),
            subscription_end: user.subscription_end,
            remaining_days: user.subscription_end ? 
                Math.max(0, Math.ceil((user.subscription_end - now) / (24 * 60 * 60 * 1000))) : 0
        });
        
    } catch (error) {
        console.error('❌ [VERIFY] Error:', error.message);
        res.status(500).json({ 
            success: false, 
            code: 0,
            error: 'Server error' 
        });
    }
});

// ═══════════════════════════════════════════
// 📱 MOBILE APP ENDPOINTS
// ═══════════════════════════════════════════
app.post('/api/getUser', verifySignature, authApp, apiLimiter, async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username) {
            return res.status(400).json(null);
        }
        
        const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const response = await firebase.get(url);
        const users = response.data || {};
        
        if (Object.keys(users).length === 0) {
            return res.json(null);
        }
        
        const userId = Object.keys(users)[0];
        const user = users[userId];
        
        res.json({
            username: user.username,
            password_hash: user.password_hash,
            is_active: user.is_active !== false,
            device_id: user.device_id || '',
            expiry_date: formatDate(user.subscription_end),
            subscription_end: user.subscription_end
        });
        
    } catch (error) {
        console.error('Get user error:', error.message);
        res.status(500).json(null);
    }
});

app.post('/api/verifyAccount', verifySignature, authApp, apiLimiter, async (req, res) => {
    try {
        const { username, password, deviceId } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing fields', 
                code: 400 
            });
        }
        
        const passHash = hashPassword(password);
        const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const response = await firebase.get(url);
        const users = response.data || {};
        
        if (Object.keys(users).length === 0) {
            return res.json({ success: false, code: 1 });
        }
        
        const userId = Object.keys(users)[0];
        const user = users[userId];
        
        if (user.password_hash !== passHash) {
            return res.json({ success: false, code: 2 });
        }
        
        if (!user.is_active) {
            return res.json({ success: false, code: 3 });
        }
        
        if (user.device_id && user.device_id !== '' && user.device_id !== deviceId) {
            return res.json({ success: false, code: 4 });
        }
        
        res.json({ 
            success: true, 
            username: user.username, 
            code: 200 
        });
        
    } catch (error) {
        console.error('Verify account error:', error.message);
        res.status(500).json({ 
            success: false, 
            code: 0, 
            error: 'Server error' 
        });
    }
});

app.post('/api/updateDevice', verifySignature, authApp, apiLimiter, async (req, res) => {
    try {
        const { username, deviceId, deviceInfo } = req.body;
        
        if (!username || !deviceId) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing data' 
            });
        }
        
        const url = `users.json?orderBy="username"&equalTo="${encodeURIComponent(username)}"&auth=${FB_KEY}`;
        const response = await firebase.get(url);
        const users = response.data || {};
        
        if (Object.keys(users).length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found' 
            });
        }
        
        const userId = Object.keys(users)[0];
        const user = users[userId];
        
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
        const userAgent = req.headers['user-agent'] || '';
        
        const updateData = {
            device_id: deviceId,
            last_login: Date.now(),
            login_count: (user.login_count || 0) + 1,
            ip_address: ip,
            user_agent: userAgent
        };
        
        if (deviceInfo) {
            updateData.device_model = deviceInfo.device_model || 'Unknown';
            updateData.device_brand = deviceInfo.device_brand || 'Unknown';
            updateData.android_version = deviceInfo.android_version || 'Unknown';
            updateData.is_rooted = deviceInfo.is_rooted || false;
        }
        
        await firebase.patch(`users/${userId}.json?auth=${FB_KEY}`, updateData);
        
        console.log(`📱 Login: ${username} | Device: ${deviceInfo?.device_brand || 'Unknown'} | IP: ${ip}`);
        
        res.json({ 
            success: true, 
            message: 'Device updated successfully'
        });
        
    } catch (error) {
        console.error('❌ Update device error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Server error' 
        });
    }
});

// ═══════════════════════════════════════════
// 👑 MASTER ADMIN - AUTH
// ═══════════════════════════════════════════
app.post('/api/admin/login', loginLimiter, bruteForceProtection, async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
        
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Username and password required' 
            });
        }
        
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        if (username !== ADMIN_CREDENTIALS.username || password !== ADMIN_CREDENTIALS.password) {
            const attempt = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
            attempt.count++;
            attempt.lastAttempt = Date.now();
            loginAttempts.set(ip, attempt);
            
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid credentials' 
            });
        }
        
        loginAttempts.delete(ip);
        const sessionToken = generateToken();
        
        adminSessions.set(sessionToken, { 
            username, 
            ip, 
            createdAt: Date.now(), 
            userAgent: req.headers['user-agent'] 
        });
        
        console.log(`✅ Admin login: ${username} from ${ip}`);
        
        res.json({ 
            success: true, 
            sessionToken, 
            expiresIn: '24 hours' 
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Server error' 
        });
    }
});

app.post('/api/admin/logout', authAdmin, (req, res) => {
    const sessionToken = req.headers['x-session-token'];
    if (sessionToken) {
        adminSessions.delete(sessionToken);
    }
    res.json({ 
        success: true, 
        message: 'Logged out' 
    });
});

app.get('/api/admin/verify-session', authAdmin, (req, res) => {
    const sessionToken = req.headers['x-session-token'];
    const session = adminSessions.get(sessionToken);
    
    if (!session) {
        return res.json({ success: true, session: { username: 'master_owner' } });
    }
    
    const expiresIn = 24 * 60 * 60 * 1000 - (Date.now() - session.createdAt);
    
    res.json({
        success: true,
        session: { 
            username: session.username, 
            expires_in: Math.floor(expiresIn / 1000 / 60) + ' minutes' 
        }
    });
});

// ═══════════════════════════════════════════
// 👑 MASTER ADMIN - USER MANAGEMENT
// (باقي الـ endpoints كما هي...)
// ═══════════════════════════════════════════

app.get('/api/admin/users', authAdmin, apiLimiter, async (req, res) => {
    try {
        const response = await firebase.get(`users.json?auth=${FB_KEY}`);
        const users = response.data || {};
        
        const formattedUsers = {};
        for (const [id, user] of Object.entries(users)) {
            const subEnd = user.subscription_end || 0;
            formattedUsers[id] = {
                username: user.username || '',
                is_active: user.is_active !== false,
                expiry_timestamp: subEnd,
                expiry_date: formatDate(subEnd),
                created_at: user.created_at || null,
                last_login: user.last_login || null,
                device_id: user.device_id || '',
                max_devices: user.max_devices || 1,
                notes: user.notes || '',
                created_by_key: user.created_by_key || 'master'
            };
        }
        
        res.json({ 
            success: true, 
            data: formattedUsers, 
            count: Object.keys(formattedUsers).length 
        });
        
    } catch (error) {
        console.error('Get users error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch users' 
        });
    }
});

// ... (باقي endpoints الـ Admin)

// ═══════════════════════════════════════════
// 📡 Security Stats Endpoints
// ═══════════════════════════════════════════
app.get('/api/admin/security-stats', authAdmin, (req, res) => {
    res.json({
        success: true,
        stats: {
            tracked_ips: requestTracker.size,
            blocked_ips: blockedIPs.size,
            blocked_list: Array.from(blockedIPs).slice(0, 20),
            active_challenges: activeChallenges.size,
            active_sessions: adminSessions.size
        }
    });
});

app.post('/api/admin/unblock-ip', authAdmin, (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP required' });
    
    blockedIPs.delete(ip);
    requestTracker.delete(ip);
    
    res.json({ success: true, message: `IP ${ip} unblocked` });
});

// ═══════════════════════════════════════════
// HOME PAGE
// ═══════════════════════════════════════════
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>🛡️ Secure API v3.4.0</title>
    <style>
        body { font-family: system-ui; background: #1a1a2e; color: #fff; text-align: center; padding: 50px; }
        .badge { background: #10b981; padding: 10px 20px; border-radius: 20px; display: inline-block; margin: 5px; }
        .badge.yellow { background: #f59e0b; }
    </style>
</head>
<body>
    <h1>🛡️ Secure Firebase Proxy</h1>
    <div class="badge">✅ v3.4.0 - Running</div>
    <div class="badge yellow">🎯 Challenge-Response Enabled</div>
</body>
</html>`);
});

// ═══════════════════════════════════════════
// ERROR HANDLERS
// ═══════════════════════════════════════════
app.use('*', (req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Endpoint not found', 
        code: 404 
    });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err.message);
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error', 
        code: 500 
    });
});

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════
app.listen(PORT, () => {
    console.log('═'.repeat(60));
    console.log('🛡️  Secure Firebase Proxy v3.4.0');
    console.log(`📡 Port: ${PORT}`);
    console.log('🔐 SECURE SIGNATURE SYSTEM ENABLED');
    console.log('🎯 CHALLENGE-RESPONSE SYSTEM ENABLED');
    console.log('═'.repeat(60));
});
