// middleware/auth.js - SecureArmor Enhanced Authentication v2.0
'use strict';

const crypto = require('crypto');
const config = require('../config');
const { firebase, FB_KEY, isFirebaseConnected } = require('../services/firebase');

// ============================================
// 🔐 ENHANCED ADMIN SESSIONS
// ============================================
class EnhancedAdminSessions {
    constructor() {
        this.sessions = new Map();
        this.failedAttempts = new Map();
        this.MAX_FAILED_ATTEMPTS = 10;
        this.FAILED_WINDOW = 3600000; // 1 hour
        this.SESSION_TTL = config.SESSION.EXPIRY || 86400000; // 24 hours
        
        // تنظيف دوري للجلسات
        setInterval(() => this.cleanup(), 300000); // كل 5 دقائق
    }
    
    create(username, ip, userAgent) {
        const sessionId = crypto.randomBytes(32).toString('hex');
        const sessionToken = this.generateSecureToken(username);
        
        const session = {
            id: sessionId,
            token: sessionToken,
            username,
            ip,
            userAgent,
            createdAt: Date.now(),
            lastActivity: Date.now(),
            expiresAt: Date.now() + this.SESSION_TTL,
            isActive: true
        };
        
        // توقيع الجلسة
        session.signature = this.signSession(session);
        
        this.sessions.set(sessionToken, session);
        
        // تسجيل في Redis إذا كان متاحاً
        if (global.redisAvailable) {
            this.saveToRedis(sessionToken, session);
        }
        
        return {
            sessionToken,
            sessionId,
            expiresIn: this.SESSION_TTL,
            createdAt: session.createdAt
        };
    }
    
    get(sessionToken) {
        if (!sessionToken) return null;
        
        // التحقق من التوقيع أولاً
        if (!this.verifyTokenFormat(sessionToken)) {
            return null;
        }
        
        let session = this.sessions.get(sessionToken);
        
        // إذا لم تكن في الذاكرة، حاول جلبها من Redis
        if (!session && global.redisAvailable) {
            session = this.getFromRedis(sessionToken);
            if (session) {
                this.sessions.set(sessionToken, session);
            }
        }
        
        if (!session || !session.isActive) return null;
        
        // التحقق من انتهاء الصلاحية
        if (Date.now() > session.expiresAt) {
            this.delete(sessionToken);
            return null;
        }
        
        // التحقق من التوقيع
        if (!this.verifySessionSignature(session)) {
            console.warn('❌ Invalid session signature');
            this.delete(sessionToken);
            return null;
        }
        
        // تحديث آخر نشاط
        session.lastActivity = Date.now();
        this.sessions.set(sessionToken, session);
        
        return session;
    }
    
    delete(sessionToken) {
        const deleted = this.sessions.delete(sessionToken);
        
        if (global.redisAvailable) {
            this.deleteFromRedis(sessionToken);
        }
        
        return deleted;
    }
    
    invalidateAllForUser(username) {
        let count = 0;
        for (const [token, session] of this.sessions.entries()) {
            if (session.username === username) {
                this.sessions.delete(token);
                if (global.redisAvailable) {
                    this.deleteFromRedis(token);
                }
                count++;
            }
        }
        return count;
    }
    
    generateSecureToken(username) {
        const timestamp = Date.now();
        const random = crypto.randomBytes(16).toString('hex');
        const data = `${username}:${timestamp}:${random}:${config.SESSION.SECRET}`;
        
        return crypto
            .createHash('sha256')
            .update(data)
            .digest('hex')
            .slice(0, 64);
    }
    
    signSession(session) {
        const data = `${session.id}:${session.username}:${session.createdAt}:${session.expiresAt}`;
        return crypto
            .createHmac('sha256', config.SESSION.SECRET)
            .update(data)
            .digest('hex');
    }
    
    verifySessionSignature(session) {
        const expected = this.signSession(session);
        return crypto.timingSafeEqual(
            Buffer.from(expected, 'hex'),
            Buffer.from(session.signature, 'hex')
        );
    }
    
    verifyTokenFormat(token) {
        return token && token.length === 64 && /^[a-f0-9]+$/i.test(token);
    }
    
    saveToRedis(token, session) {
        try {
            const redisClient = global.redisClient;
            if (redisClient) {
                const key = `session:${token}`;
                const ttl = Math.ceil((session.expiresAt - Date.now()) / 1000);
                redisClient.setex(key, ttl, JSON.stringify(session));
            }
        } catch (error) {
            console.warn('Failed to save session to Redis:', error.message);
        }
    }
    
    getFromRedis(token) {
        try {
            const redisClient = global.redisClient;
            if (redisClient) {
                const key = `session:${token}`;
                return redisClient.get(key)
                    .then(data => data ? JSON.parse(data) : null);
            }
        } catch (error) {
            console.warn('Failed to get session from Redis:', error.message);
        }
        return null;
    }
    
    deleteFromRedis(token) {
        try {
            const redisClient = global.redisClient;
            if (redisClient) {
                const key = `session:${token}`;
                redisClient.del(key);
            }
        } catch (error) {
            console.warn('Failed to delete session from Redis:', error.message);
        }
    }
    
    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [token, session] of this.sessions.entries()) {
            if (now > session.expiresAt) {
                this.sessions.delete(token);
                cleaned++;
            }
        }
        
        // تنظيف محاولات الفشل القديمة
        for (const [key, attempts] of this.failedAttempts.entries()) {
            const recent = attempts.filter(time => now - time < this.FAILED_WINDOW);
            if (recent.length === 0) {
                this.failedAttempts.delete(key);
            } else {
                this.failedAttempts.set(key, recent);
            }
        }
        
        return cleaned;
    }
    
    recordFailedAttempt(identifier) {
        const now = Date.now();
        const attempts = this.failedAttempts.get(identifier) || [];
        attempts.push(now);
        
        // الاحتفاظ بالمحاولات في الساعة الأخيرة فقط
        const recent = attempts.filter(time => now - time < this.FAILED_WINDOW);
        this.failedAttempts.set(identifier, recent);
        
        return recent.length;
    }
    
    isRateLimited(identifier) {
        const attempts = this.failedAttempts.get(identifier) || [];
        const now = Date.now();
        const recent = attempts.filter(time => now - time < this.FAILED_WINDOW);
        
        return recent.length >= this.MAX_FAILED_ATTEMPTS;
    }
}

const adminSessions = new EnhancedAdminSessions();

// ============================================
// 🗄️ SUB-ADMIN CACHE ENHANCED
// ============================================
class SubAdminCache {
    constructor() {
        this.cache = new Map();
        this.CACHE_TTL = 5 * 60 * 1000; // 5 دقائق
        this.failedAttempts = new Map();
        this.FAILED_WINDOW = 3600000; // 1 ساعة
        this.MAX_FAILED_ATTEMPTS = 10;
        
        setInterval(() => this.cleanup(), 60000); // تنظيف كل دقيقة
    }
    
    set(apiKey, keyData, deviceFingerprint) {
        const cacheEntry = {
            ...keyData,
            deviceFingerprint,
            cachedAt: Date.now(),
            lastUsed: Date.now(),
            hitCount: 0
        };
        
        this.cache.set(apiKey, cacheEntry);
        return cacheEntry;
    }
    
    get(apiKey) {
        const entry = this.cache.get(apiKey);
        if (!entry) return null;
        
        // التحقق من صلاحية الـ cache
        if (Date.now() - entry.cachedAt > this.CACHE_TTL) {
            this.cache.delete(apiKey);
            return null;
        }
        
        // تحديث الاستخدام
        entry.lastUsed = Date.now();
        entry.hitCount++;
        this.cache.set(apiKey, entry);
        
        return entry;
    }
    
    delete(apiKey) {
        return this.cache.delete(apiKey);
    }
    
    isValid(entry, deviceFingerprint) {
        if (!entry) return false;
        
        // التحقق من صلاحية الـ cache
        if (Date.now() - entry.cachedAt > this.CACHE_TTL) {
            return false;
        }
        
        // التحقق من تطابق device fingerprint
        if (entry.deviceFingerprint && entry.deviceFingerprint !== deviceFingerprint) {
            return false;
        }
        
        // التحقق من صلاحية المفتاح
        if (!entry.is_active) {
            return false;
        }
        
        // التحقق من تاريخ الانتهاء
        if (entry.expiry_timestamp && Date.now() > parseInt(entry.expiry_timestamp)) {
            return false;
        }
        
        return true;
    }
    
    recordFailedAttempt(apiKey, ip) {
        const identifier = apiKey || ip;
        const now = Date.now();
        const attempts = this.failedAttempts.get(identifier) || [];
        attempts.push(now);
        
        const recent = attempts.filter(time => now - time < this.FAILED_WINDOW);
        this.failedAttempts.set(identifier, recent);
        
        return recent.length;
    }
    
    isRateLimited(apiKey, ip) {
        const identifier = apiKey || ip;
        const attempts = this.failedAttempts.get(identifier) || [];
        const now = Date.now();
        const recent = attempts.filter(time => now - time < this.FAILED_WINDOW);
        
        return recent.length >= this.MAX_FAILED_ATTEMPTS;
    }
    
    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        
        // تنظيف الـ cache
        for (const [apiKey, entry] of this.cache.entries()) {
            if (now - entry.cachedAt > this.CACHE_TTL) {
                this.cache.delete(apiKey);
                cleaned++;
            }
        }
        
        // تنظيف محاولات الفشل
        for (const [identifier, attempts] of this.failedAttempts.entries()) {
            const recent = attempts.filter(time => now - time < this.FAILED_WINDOW);
            if (recent.length === 0) {
                this.failedAttempts.delete(identifier);
            } else {
                this.failedAttempts.set(identifier, recent);
            }
        }
        
        return cleaned;
    }
}

const subAdminCache = new SubAdminCache();

// ============================================
// 🔄 RETRY CONFIGURATION
// ============================================
const RETRY_CONFIG = {
    maxRetries: 3,
    baseDelay: 2000,
    maxDelay: 8000
};

async function retryWithBackoff(operation, operationName) {
    let lastError;
    
    for (let i = 0; i < RETRY_CONFIG.maxRetries; i++) {
        try {
            console.log(`🔄 [${operationName}] Attempt ${i + 1}/${RETRY_CONFIG.maxRetries}`);
            return await operation();
        } catch (error) {
            lastError = error;
            
            if (i < RETRY_CONFIG.maxRetries - 1) {
                const delay = Math.min(
                    RETRY_CONFIG.baseDelay * Math.pow(2, i),
                    RETRY_CONFIG.maxDelay
                );
                console.log(`⏳ [${operationName}] Retrying in ${delay}ms...`);
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
    }
    
    console.error(`❌ [${operationName}] All retries failed:`, lastError.message);
    throw lastError;
}

// ============================================
// 🔥 SIGNATURE VERIFICATION (NEW)
// ============================================
const verifyRequestSignature = (req) => {
    const path = req.path || req.url?.split('?')[0] || '';
    const isSignedEndpoint = config.SIGNED_ENDPOINTS.some(endpoint => {
        if (endpoint.includes(':')) {
            const pattern = endpoint.replace(/:[^/]+/g, '[^/]+');
            return new RegExp(`^${pattern}$`).test(path);
        }
        return path === endpoint;
    });
    
    if (!isSignedEndpoint) {
        return { valid: true, reason: 'Endpoint not signed' };
    }
    
    const signature = req.headers['x-api-signature'];
    const timestamp = req.headers['x-api-timestamp'];
    const nonce = req.headers['x-api-nonce'];
    const apiKey = req.headers['x-api-key'];
    
    // التحقق من البيانات الأساسية
    if (!signature || !timestamp || !apiKey) {
        return { 
            valid: false, 
            reason: 'Missing signature headers',
            code: 'MISSING_SIGNATURE_HEADERS'
        };
    }
    
    // التحقق من انتهاء الصلاحية
    const now = Date.now();
    const requestTime = parseInt(timestamp);
    
    if (isNaN(requestTime)) {
        return { 
            valid: false, 
            reason: 'Invalid timestamp',
            code: 'INVALID_TIMESTAMP'
        };
    }
    
    const expiryWindow = (config.SESSION.SIGNATURE_EXPIRY || 300) * 1000; // 5 دقائق
    if (Math.abs(now - requestTime) > expiryWindow) {
        return { 
            valid: false, 
            reason: 'Request expired',
            code: 'EXPIRED_REQUEST'
        };
    }
    
    // إنشاء البيانات للتوقيع
    const dataToSign = {
        method: req.method,
        path: req.path,
        query: req.query,
        body: req.body || {},
        timestamp: requestTime,
        nonce: nonce || '',
        apiKey: apiKey
    };
    
    // إنشاء التوقيع المتوقع
    const dataString = JSON.stringify(dataToSign);
    const expectedSignature = crypto
        .createHmac('sha256', config.APP_SIGNING_SECRET || config.SECRET_KEY)
        .update(dataString)
        .digest('hex');
    
    // التحقق من التوقيع
    try {
        const isValid = crypto.timingSafeEqual(
            Buffer.from(signature, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );
        
        if (!isValid) {
            return { 
                valid: false, 
                reason: 'Invalid signature',
                code: 'INVALID_SIGNATURE'
            };
        }
    } catch (error) {
        return { 
            valid: false, 
            reason: 'Signature verification error',
            code: 'SIGNATURE_ERROR'
        };
    }
    
    // التحقق من nonce لمنع replay attacks
    if (nonce && global.redisAvailable) {
        const nonceKey = `nonce:${apiKey}:${nonce}`;
        // يمكن إضافة تحقق من Redis هنا
    }
    
    return { valid: true, reason: 'Signature verified' };
};

// ============================================
// 📱 APP AUTHENTICATION WITH SIGNATURE
// ============================================
const authApp = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
        logAuthAttempt(req, false, 'API Key missing');
        return res.status(401).json({ 
            success: false, 
            error: 'API Key required', 
            code: 'MISSING_API_KEY'
        });
    }
    
    // التحقق من API Key
    if (apiKey !== config.APP_API_KEY) {
        logAuthAttempt(req, false, 'Invalid API Key');
        return res.status(401).json({ 
            success: false, 
            error: 'Invalid API Key', 
            code: 'INVALID_API_KEY'
        });
    }
    
    // التحقق من التوقيع إذا كان المطلوب
    const signatureCheck = verifyRequestSignature(req);
    if (!signatureCheck.valid && signatureCheck.reason !== 'Endpoint not signed') {
        logAuthAttempt(req, false, `Signature check failed: ${signatureCheck.reason}`);
        return res.status(401).json({
            success: false,
            error: 'Signature verification failed',
            code: signatureCheck.code || 'SIGNATURE_FAILED'
        });
    }
    
    logAuthAttempt(req, true, signatureCheck.reason);
    
    // إضافة معلومات التوثيق للطلب
    req.auth = {
        type: 'app',
        apiKey: apiKey,
        signed: signatureCheck.valid && signatureCheck.reason !== 'Endpoint not signed'
    };
    
    next();
};

// ============================================
// 👤 ADMIN AUTHENTICATION ENHANCED
// ============================================
const authAdmin = (req, res, next) => {
    const sessionToken = req.headers['x-session-token'];
    const masterToken = req.headers['x-master-token'];
    
    // التحقق من Master Token
    if (masterToken && masterToken === config.MASTER_ADMIN_TOKEN) {
        logAuthAttempt(req, true, 'Master token used');
        req.adminUser = 'master_owner';
        req.isMasterAdmin = true;
        req.adminRole = 'master';
        return next();
    }
    
    // التحقق من Admin API Key
    const adminApiKey = req.headers['x-admin-key'];
    if (adminApiKey && adminApiKey === config.ADMIN_API_KEY) {
        logAuthAttempt(req, true, 'Admin API key used');
        req.adminUser = 'admin_api_user';
        req.adminRole = 'admin';
        return next();
    }
    
    if (!sessionToken) {
        logAuthAttempt(req, false, 'Session token missing');
        return res.status(401).json({ 
            success: false, 
            error: 'Session token required', 
            code: 'MISSING_SESSION_TOKEN'
        });
    }
    
    // التحقق من صحة الجلسة
    const session = adminSessions.get(sessionToken);
    
    if (!session) {
        logAuthAttempt(req, false, 'Session not found');
        return res.status(401).json({ 
            success: false, 
            error: 'Invalid or expired session', 
            code: 'INVALID_SESSION'
        });
    }
    
    // التحقق من أن الجلسة لا تزال نشطة
    if (!session.isActive) {
        logAuthAttempt(req, false, 'Session inactive');
        return res.status(401).json({ 
            success: false, 
            error: 'Session is no longer active', 
            code: 'SESSION_INACTIVE'
        });
    }
    
    // تحديث آخر نشاط
    session.lastActivity = Date.now();
    adminSessions.sessions.set(sessionToken, session);
    
    req.adminUser = session.username;
    req.sessionId = sessionToken;
    req.adminRole = 'admin';
    req.session = session;
    
    logAuthAttempt(req, true, 'Admin session validated');
    next();
};

// ============================================
// 🔑 SUB ADMIN AUTHENTICATION ENHANCED
// ============================================
const authSubAdmin = async (req, res, next) => {
    try {
        const apiKey = req.headers['x-api-key'];
        const deviceFingerprint = req.headers['x-device-fingerprint'];
        const signature = req.headers['x-api-signature'];
        
        if (!apiKey) {
            logAuthAttempt(req, false, 'API key missing');
            return res.status(401).json({ 
                success: false, 
                error: 'API key required',
                code: 'MISSING_API_KEY'
            });
        }
        
        // Rate limiting check
        if (subAdminCache.isRateLimited(apiKey, req.ip)) {
            logAuthAttempt(req, false, 'Rate limited');
            return res.status(429).json({ 
                success: false, 
                error: 'Too many requests. Please try again later.',
                code: 'RATE_LIMITED'
            });
        }
        
        // Check cache first
        const cached = subAdminCache.get(apiKey);
        if (cached && subAdminCache.isValid(cached, deviceFingerprint)) {
            // Update last used
            cached.lastUsed = Date.now();
            subAdminCache.cache.set(apiKey, cached);
            
            req.subAdminKey = cached;
            req.subAdminKeyId = cached.keyId;
            
            logAuthAttempt(req, true, 'Cache hit');
            return next();
        }
        
        // Check Firebase connection
        if (!isFirebaseConnected()) {
            logAuthAttempt(req, false, 'Firebase not connected');
            return res.status(503).json({ 
                success: false, 
                error: 'Service temporarily unavailable',
                code: 'SERVICE_UNAVAILABLE'
            });
        }
        
        // Fetch from Firebase with retry
        const operation = async () => {
            const response = await firebase.get(
                `api_keys.json?auth=${FB_KEY}&orderBy="api_key"&equalTo="${encodeURIComponent(apiKey)}"`
            );
            return response.data || {};
        };
        
        const keys = await retryWithBackoff(() => operation(), 'authSubAdmin');
        
        if (Object.keys(keys).length === 0) {
            subAdminCache.recordFailedAttempt(apiKey, req.ip);
            logAuthAttempt(req, false, 'API key not found');
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid API key',
                code: 'INVALID_API_KEY'
            });
        }
        
        const keyId = Object.keys(keys)[0];
        const foundKey = keys[keyId];
        
        // Validate key
        const validationError = validateKey(foundKey, deviceFingerprint, req.ip);
        if (validationError) {
            subAdminCache.recordFailedAttempt(apiKey, req.ip);
            logAuthAttempt(req, false, validationError);
            return res.status(403).json({ 
                success: false, 
                error: validationError,
                code: 'KEY_VALIDATION_FAILED'
            });
        }
        
        // Prepare key data
        const keyData = {
            ...foundKey,
            keyId,
            deviceFingerprint,
            cachedAt: Date.now(),
            lastUsed: Date.now(),
            ip: req.ip
        };
        
        // Update cache
        subAdminCache.set(apiKey, keyData, deviceFingerprint);
        
        req.subAdminKey = keyData;
        req.subAdminKeyId = keyId;
        
        logAuthAttempt(req, true, 'Firebase validation');
        next();
        
    } catch (error) {
        console.error('❌ Auth Sub Admin error:', error.message);
        logAuthAttempt(req, false, `Server error: ${error.message}`);
        
        // Fallback to cached key if available
        const apiKey = req.headers['x-api-key'];
        const cached = subAdminCache.get(apiKey);
        
        if (cached && subAdminCache.isValid(cached, req.headers['x-device-fingerprint'])) {
            req.subAdminKey = cached;
            req.subAdminKeyId = cached.keyId;
            logAuthAttempt(req, true, 'Using cached key (fallback)');
            return next();
        }
        
        res.status(500).json({ 
            success: false, 
            error: 'Authentication service unavailable',
            code: 'AUTH_SERVICE_UNAVAILABLE'
        });
    }
};

// ============================================
// ✅ KEY VALIDATION ENHANCED
// ============================================
const validateKey = (keyData, deviceFingerprint, clientIp = null) => {
    if (!keyData.is_active) {
        return 'Key is inactive';
    }
    
    // Check expiry
    if (keyData.expiry_timestamp) {
        const expiryTime = parseInt(keyData.expiry_timestamp);
        if (isNaN(expiryTime) || expiryTime <= 0) {
            return 'Invalid expiry configuration';
        }
        
        if (Date.now() > expiryTime) {
            return 'Key expired';
        }
    }
    
    // Device binding
    if (keyData.bound_device && keyData.bound_device !== deviceFingerprint) {
        return 'Key is bound to another device';
    }
    
    // IP whitelist
    if (keyData.ip_whitelist && keyData.ip_whitelist.length > 0 && clientIp) {
        if (!keyData.ip_whitelist.includes(clientIp)) {
            return 'IP not authorized';
        }
    }
    
    // Daily usage limit
    if (keyData.daily_limit) {
        const today = new Date().toISOString().split('T')[0];
        const usageKey = `${keyData.keyId}:${today}`;
        
        if (!global.dailyUsage) global.dailyUsage = new Map();
        const todayUsage = global.dailyUsage.get(usageKey) || 0;
        
        if (todayUsage >= keyData.daily_limit) {
            return 'Daily limit exceeded';
        }
    }
    
    return null;
};

// ============================================
// 🔐 PERMISSION CHECK ENHANCED
// ============================================
const checkSubAdminPermission = (requiredPermission) => {
    return (req, res, next) => {
        const keyData = req.subAdminKey;
        
        if (!keyData) {
            return res.status(403).json({ 
                success: false, 
                error: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }
        
        const PERMISSION_MATRIX = {
            'full': ['view', 'add', 'extend', 'edit', 'delete', 'export', 'manage'],
            'add_only': ['view', 'add'],
            'extend_only': ['view', 'extend'],
            'view_only': ['view'],
            'custom': keyData.custom_permissions || ['view']
        };
        
        const permissions = PERMISSION_MATRIX[keyData.permission_level] || PERMISSION_MATRIX.view_only;
        
        if (!permissions.includes(requiredPermission)) {
            logAuthAttempt(req, false, `Permission denied: ${requiredPermission}`);
            return res.status(403).json({ 
                success: false, 
                error: 'Permission denied',
                required: requiredPermission,
                has: keyData.permission_level,
                code: 'PERMISSION_DENIED'
            });
        }
        
        // Track daily usage for add operations
        if (requiredPermission === 'add' && keyData.daily_limit) {
            const today = new Date().toISOString().split('T')[0];
            const usageKey = `${keyData.keyId}:${today}`;
            
            if (!global.dailyUsage) global.dailyUsage = new Map();
            const todayUsage = global.dailyUsage.get(usageKey) || 0;
            
            if (todayUsage >= keyData.daily_limit) {
                return res.status(429).json({
                    success: false,
                    error: 'Daily limit exceeded',
                    limit: keyData.daily_limit,
                    used: todayUsage,
                    code: 'DAILY_LIMIT_EXCEEDED'
                });
            }
            
            // Increment usage
            global.dailyUsage.set(usageKey, todayUsage + 1);
        }
        
        next();
    };
};

// ============================================
// 👤 OWNERSHIP CHECK ENHANCED
// ============================================
const checkUserOwnership = async (req, res, next) => {
    try {
        const userId = req.params.id;
        const currentKeyId = req.subAdminKeyId;
        
        if (!userId || !/^[a-zA-Z0-9_-]+$/.test(userId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid user ID format',
                code: 'INVALID_USER_ID'
            });
        }
        
        // Check Firebase connection
        if (!isFirebaseConnected()) {
            return res.status(503).json({ 
                success: false, 
                error: 'Service temporarily unavailable',
                code: 'SERVICE_UNAVAILABLE'
            });
        }
        
        const operation = async () => {
            const userRes = await firebase.get(`users/${userId}.json?auth=${FB_KEY}`);
            return userRes.data;
        };
        
        const user = await retryWithBackoff(() => operation(), 'checkUserOwnership');
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }
        
        // Master admin bypass
        if (req.isMasterAdmin && req.adminRole === 'master') {
            req.targetUser = user;
            req.ownershipBypass = true;
            return next();
        }
        
        // Sub-admin ownership check
        if (!user.created_by_key || user.created_by_key !== currentKeyId) {
            logAuthAttempt(req, false, 'Ownership violation');
            return res.status(403).json({ 
                success: false, 
                error: 'You can only manage users you created',
                code: 'OWNERSHIP_VIOLATION'
            });
        }
        
        req.targetUser = user;
        next();
        
    } catch (error) {
        console.error('❌ Ownership check error:', error.message);
        
        if (error.message.includes('Firebase') || error.message.includes('network')) {
            return res.status(503).json({ 
                success: false, 
                error: 'Service temporarily unavailable. Please try again.',
                code: 'SERVICE_UNAVAILABLE'
            });
        }
        
        res.status(500).json({ 
            success: false, 
            error: 'Failed to verify ownership',
            code: 'OWNERSHIP_CHECK_FAILED'
        });
    }
};

// ============================================
// 📝 AUTH LOGGING ENHANCED
// ============================================
const logAuthAttempt = (req, success, reason = '') => {
    const logEntry = {
        timestamp: new Date().toISOString(),
        ip: req.ip || req.connection?.remoteAddress || 'unknown',
        method: req.method,
        path: req.path,
        success,
        reason,
        userAgent: req.get('User-Agent') || 'Unknown',
        apiKeyPrefix: req.headers['x-api-key'] ? 
            '***' + req.headers['x-api-key'].slice(-4) : 
            (req.headers['x-admin-key'] ? '***admin' : 'None')
    };
    
    const logLevel = success ? 'INFO' : 'WARN';
    const emoji = success ? '✅' : '❌';
    
    console.log(`${emoji} [AUTH_${logLevel}] ${JSON.stringify(logEntry)}`);
    
    // Store failed attempts for rate limiting
    if (!success && !reason.includes('Cache')) {
        const apiKey = req.headers['x-api-key'] || req.headers['x-admin-key'];
        subAdminCache.recordFailedAttempt(apiKey, req.ip);
        
        // Check for brute force
        const attempts = subAdminCache.failedAttempts.get(apiKey || req.ip) || [];
        if (attempts.length >= subAdminCache.MAX_FAILED_ATTEMPTS) {
            console.warn(`🚨 [SECURITY] Brute force detected from ${req.ip}`);
        }
    }
};

// ============================================
// 🛠️ SESSION MANAGEMENT
// ============================================
const createAdminSession = (username, ip, userAgent) => {
    return adminSessions.create(username, ip, userAgent);
};

const invalidateAdminSession = (sessionToken) => {
    return adminSessions.delete(sessionToken);
};

const invalidateAllUserSessions = (username) => {
    return adminSessions.invalidateAllForUser(username);
};

// ============================================
// 📦 EXPORTS
// ============================================
module.exports = {
    // Authentication middlewares
    authApp,
    authAdmin,
    authSubAdmin,
    
    // Permission and ownership checks
    checkSubAdminPermission,
    checkUserOwnership,
    
    // Session management
    adminSessions: adminSessions.sessions,
    subAdminCache: subAdminCache.cache,
    validateKey,
    logAuthAttempt,
    createAdminSession,
    invalidateAdminSession,
    invalidateAllUserSessions,
    
    // Firebase connection check
    checkFirebaseConnection: isFirebaseConnected,
    
    // Signature verification (new)
    verifyRequestSignature,
    
    // Utility functions
    generateSecureToken: (data) => {
        return crypto
            .createHash('sha256')
            .update(data + config.SESSION.SECRET)
            .digest('hex');
    },
    
    // Encrypt sensitive data
    encryptSensitiveData: (data) => {
        return config.encryptData(data);
    },
    
    // Decrypt sensitive data
    decryptSensitiveData: (encrypted) => {
        return config.decryptData(encrypted);
    }
};
