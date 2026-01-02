// middleware/security.js - SecureArmor v14.0 Ultimate Edition
// حماية شاملة ضد جميع أنواع الهجمات المتقدمة
'use strict';

const crypto = require('crypto');
const config = require('../config');

// ============================================
// SECURE UTILITIES - أدوات آمنة
// ============================================
const SecureUtils = {
    generateSecureId: (length = 32) => crypto.randomBytes(length).toString('hex'),
    
    secureHash: (data) => crypto.createHash('sha256').update(String(data)).digest('hex'),
    
    secureCompare: (a, b) => {
        if (typeof a !== 'string' || typeof b !== 'string') return false;
        if (a.length !== b.length) return false;
        try {
            return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
        } catch { return false; }
    },
    
    sanitizeString: (str, maxLength = 1000) => {
        if (typeof str !== 'string') return '';
        return str.slice(0, maxLength).replace(/[\x00-\x1f\x7f]/g, '').trim();
    },
    
    isValidIP: (ip) => {
        if (!ip || typeof ip !== 'string') return false;
        const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6 = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
        return ipv4.test(ip) || ipv6.test(ip);
    },
    
    ipToInt: (ip) => ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0,
    
    isIPInRange: (ip, cidr) => {
        if (!SecureUtils.isValidIP(ip) || !ip.includes('.')) return ip === cidr;
        if (!cidr.includes('/')) return ip === cidr;
        
        try {
            const [range, bits] = cidr.split('/');
            const mask = ~(2 ** (32 - parseInt(bits)) - 1);
            return (SecureUtils.ipToInt(ip) & mask) === (SecureUtils.ipToInt(range) & mask);
        } catch { return false; }
    },
    
    isPrivateIP: (ip) => {
        const privateRanges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'];
        return privateRanges.some(range => SecureUtils.isIPInRange(ip, range));
    }
};

// ============================================
// CONFIGURATION - الإعدادات
// ============================================
const SECURITY_CONFIG = {
    RATE_LIMITS: {
        global: { capacity: config.SECURITY?.RATE_LIMITS?.GLOBAL?.capacity || 100, refillRate: config.SECURITY?.RATE_LIMITS?.GLOBAL?.refill || 10 },
        auth: { capacity: config.SECURITY?.RATE_LIMITS?.AUTH?.capacity || 5, refillRate: config.SECURITY?.RATE_LIMITS?.AUTH?.refill || 0.5 },
        api: { capacity: config.SECURITY?.RATE_LIMITS?.API?.capacity || 50, refillRate: config.SECURITY?.RATE_LIMITS?.API?.refill || 5 },
        admin: { capacity: config.SECURITY?.RATE_LIMITS?.ADMIN?.capacity || 20, refillRate: config.SECURITY?.RATE_LIMITS?.ADMIN?.refill || 2 }
    },
    PROTECTION_LEVEL: config.SECURITY?.PROTECTION_LEVEL || 'balanced',
    ENABLE_WAF: config.SECURITY?.ENABLE_WAF !== false,
    ENABLE_RATE_LIMIT: config.SECURITY?.ENABLE_RATE_LIMIT !== false,
    ANOMALY_THRESHOLD: config.SECURITY?.ANOMALY_THRESHOLD || 70,
    APPEAL_CONTACT: config.SECURITY?.APPEAL_CONTACT || 'security@yourdomain.com',
    ALERT_WEBHOOK: config.SECURITY?.ALERT_WEBHOOK || null,
    IP_CACHE_TTL: (config.SECURITY?.IP_CACHE_TTL || 300) * 1000,
    
    TRUSTED_PROXIES: ['127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
    EXEMPT_PATHS: ['/health', '/favicon.ico', '/robots.txt'],
    STATIC_EXTENSIONS: /\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map)$/i,
    
    WAF: { maxURLLength: 2048, maxBodySize: 1048576, blockThreshold: 10 },
    DDOS: { globalRPS: 10000, ipRPS: 50, burstLimit: 100 },
    BRUTE_FORCE: { maxAttempts: 5, lockoutTime: 900000, escalationMultiplier: 2, maxLockoutTime: 86400000 }
};

// ============================================
// REDIS CONNECTION
// ============================================
let redisClient = null;
let redisAvailable = false;

const initRedis = async () => {
    const redisUrl = config.SECURITY?.REDIS_URL || process.env.REDIS_URL;
    if (!redisUrl) return;
    
    try {
        const Redis = require('ioredis');
        redisClient = new Redis(redisUrl, {
            maxRetriesPerRequest: 3,
            retryStrategy: (times) => times > 10 ? null : Math.min(times * 100, 3000),
            lazyConnect: true
        });
        
        redisClient.on('connect', () => { redisAvailable = true; console.log('✅ Redis connected'); });
        redisClient.on('error', () => { redisAvailable = false; });
        redisClient.on('close', () => { redisAvailable = false; });
        
        await redisClient.connect();
    } catch (e) { console.warn('⚠️ Redis not available:', e.message); }
};

initRedis();

// ============================================
// SECURE STORAGE - تخزين آمن
// ============================================
class SecureStorage {
    constructor() {
        this.stores = new Map();
        this.MAX_ENTRIES = 50000;
        ['blockedIPs', 'rateLimits', 'loginAttempts', 'ipReputation', 'behaviorPatterns', 
         'challenges', 'fingerprints', 'threatLog', 'rateViolations', 'blockHistory'].forEach(name => 
            this.stores.set(name, new Map())
        );
        setInterval(() => this.cleanup(), 300000);
    }
    
    getStore(name) {
        if (!this.stores.has(name)) this.stores.set(name, new Map());
        return this.stores.get(name);
    }
    
    set(storeName, key, value, ttlMs = 3600000) {
        const store = this.getStore(storeName);
        if (store.size >= this.MAX_ENTRIES) this.evictOldest(store, Math.floor(this.MAX_ENTRIES * 0.1));
        store.set(SecureUtils.secureHash(String(key)), { value, createdAt: Date.now(), expiresAt: Date.now() + ttlMs });
    }
    
    get(storeName, key) {
        const store = this.getStore(storeName);
        const item = store.get(SecureUtils.secureHash(String(key)));
        if (!item) return null;
        if (Date.now() > item.expiresAt) { store.delete(SecureUtils.secureHash(String(key))); return null; }
        return item.value;
    }
    
    getWithMeta(storeName, key) {
        const store = this.getStore(storeName);
        const hashedKey = SecureUtils.secureHash(String(key));
        const item = store.get(hashedKey);
        if (!item || Date.now() > item.expiresAt) { if (item) store.delete(hashedKey); return null; }
        return { ...item };
    }
    
    delete(storeName, key) { return this.getStore(storeName).delete(SecureUtils.secureHash(String(key))); }
    has(storeName, key) { return this.get(storeName, key) !== null; }
    increment(storeName, key, ttlMs = 3600000) { const c = this.get(storeName, key) || 0; this.set(storeName, key, c + 1, ttlMs); return c + 1; }
    
    evictOldest(store, count = 1) {
        const entries = [...store.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt);
        for (let i = 0; i < Math.min(count, entries.length); i++) store.delete(entries[i][0]);
    }
    
    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        for (const store of this.stores.values()) {
            for (const [key, item] of store.entries()) {
                if (now > item.expiresAt) { store.delete(key); cleaned++; }
            }
        }
        return cleaned;
    }
    
    getStats() {
        const stats = { totalEntries: 0, stores: {} };
        for (const [name, store] of this.stores.entries()) { stats.stores[name] = store.size; stats.totalEntries += store.size; }
        return stats;
    }
}

const storage = new SecureStorage();

// ============================================
// RATE LIMITER - محدد المعدل
// ============================================
class RateLimiter {
    constructor(capacity, refillRate) {
        this.capacity = capacity;
        this.refillRate = refillRate;
        this.buckets = new Map();
    }
    
    async consume(identifier, tokens = 1) {
        if (redisAvailable) return this.consumeRedis(identifier, tokens);
        return this.consumeMemory(identifier, tokens);
    }
    
    async consumeRedis(identifier, tokens) {
        const key = `rl:${SecureUtils.secureHash(identifier)}`;
        try {
            const lua = `
                local key, cap, rate, tokens, now = KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
                local b = redis.call('HMGET', key, 'tokens', 'lastRefill')
                local t, lr = tonumber(b[1]) or cap, tonumber(b[2]) or now
                t = math.min(cap, t + math.floor((now - lr) / 1000 * rate))
                if t >= tokens then
                    redis.call('HMSET', key, 'tokens', t - tokens, 'lastRefill', now)
                    redis.call('EXPIRE', key, 3600)
                    return cjson.encode({allowed = true, remaining = t - tokens})
                end
                return cjson.encode({allowed = false, remaining = t, resetIn = math.ceil((tokens - t) / rate * 1000)})
            `;
            const result = await redisClient.eval(lua, 1, key, this.capacity, this.refillRate, tokens, Date.now());
            return JSON.parse(result);
        } catch { return this.consumeMemory(identifier, tokens); }
    }
    
    consumeMemory(identifier, tokens) {
        const key = SecureUtils.secureHash(identifier);
        const now = Date.now();
        let bucket = this.buckets.get(key) || { tokens: this.capacity, lastRefill: now };
        
        bucket.tokens = Math.min(this.capacity, bucket.tokens + Math.floor((now - bucket.lastRefill) / 1000 * this.refillRate));
        bucket.lastRefill = now;
        this.buckets.set(key, bucket);
        
        if (bucket.tokens >= tokens) {
            bucket.tokens -= tokens;
            return { allowed: true, remaining: bucket.tokens };
        }
        return { allowed: false, remaining: bucket.tokens, resetIn: Math.ceil((tokens - bucket.tokens) / this.refillRate * 1000) };
    }
}

const rateLimiters = {};
for (const [name, cfg] of Object.entries(SECURITY_CONFIG.RATE_LIMITS)) {
    rateLimiters[name] = new RateLimiter(cfg.capacity, cfg.refillRate);
}

// ============================================
// DDOS PROTECTION
// ============================================
class DDoSProtection {
    constructor() {
        this.globalCount = 0;
        this.connections = new Map();
        setInterval(() => { this.globalCount = 0; this.cleanConnections(); }, 1000);
    }
    
    cleanConnections() {
        const now = Date.now();
        for (const [ip, data] of this.connections.entries()) {
            if (now - data.lastSeen > 60000) this.connections.delete(ip);
        }
    }
    
    check(ip) {
        this.globalCount++;
        if (this.globalCount > SECURITY_CONFIG.DDOS.globalRPS) {
            return { allowed: false, reason: 'Server under high load', type: 'global_ddos' };
        }
        
        let data = this.connections.get(ip) || { count: 0, burst: 0, lastSeen: Date.now() };
        data.count++;
        data.burst++;
        data.lastSeen = Date.now();
        this.connections.set(ip, data);
        
        if (data.count > SECURITY_CONFIG.DDOS.ipRPS) {
            return { allowed: false, reason: 'Rate exceeded', type: 'ip_ddos' };
        }
        if (data.burst > SECURITY_CONFIG.DDOS.burstLimit) {
            return { allowed: false, reason: 'Burst limit', type: 'burst_ddos' };
        }
        return { allowed: true };
    }
    
    getStats() { return { globalRPS: this.globalCount, connections: this.connections.size }; }
}

const ddosProtection = new DDoSProtection();

// ============================================
// IP ANALYZER
// ============================================
class IPAnalyzer {
    constructor() {
        this.torNodes = new Set();
        this.lastUpdate = 0;
        this.isUpdating = false;
        this.updateLists();
        setInterval(() => this.updateLists(), SECURITY_CONFIG.IP_CACHE_TTL || 3600000);
    }
    
    async updateLists() {
        if (this.isUpdating || Date.now() - this.lastUpdate < 3600000) return;
        this.isUpdating = true;
        
        try {
            const fetch = (await import('node-fetch')).default;
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 15000);
            
            const res = await fetch('https://check.torproject.org/torbulkexitlist', { signal: controller.signal });
            const text = await res.text();
            this.torNodes = new Set(text.split('\n').map(ip => ip.trim()).filter(ip => SecureUtils.isValidIP(ip)));
            
            clearTimeout(timeout);
            this.lastUpdate = Date.now();
            console.log(`✅ Threat lists updated: ${this.torNodes.size} TOR nodes`);
        } catch (e) { console.error('❌ Threat list update failed:', e.message); }
        
        this.isUpdating = false;
    }
    
    async analyze(ip) {
        if (!SecureUtils.isValidIP(ip)) return { valid: false, reputation: 0, threats: ['invalid_ip'] };
        
        const cached = storage.get('ipReputation', ip);
        if (cached && Date.now() - cached.timestamp < SECURITY_CONFIG.IP_CACHE_TTL) return cached;
        
        const analysis = {
            valid: true, ip, isPrivate: SecureUtils.isPrivateIP(ip), isTor: this.torNodes.has(ip),
            threats: [], reputation: 100, timestamp: Date.now()
        };
        
        if (analysis.isTor) { analysis.reputation -= 50; analysis.threats.push('tor_exit_node'); }
        if (analysis.isPrivate) analysis.reputation -= 10;
        
        const previousBlocks = storage.get('blockHistory', ip) || 0;
        if (previousBlocks > 0) { analysis.reputation -= Math.min(previousBlocks * 10, 40); analysis.threats.push('previous_violations'); }
        
        analysis.reputation = Math.max(0, Math.min(100, analysis.reputation));
        storage.set('ipReputation', ip, analysis, SECURITY_CONFIG.IP_CACHE_TTL);
        
        return analysis;
    }
}

const ipAnalyzer = new IPAnalyzer();

// ============================================
// WAF ENGINE
// ============================================
class WAFEngine {
    constructor() {
        this.patterns = {
            sqlInjection: [
                /(?:union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table)/i,
                /(?:'\s*or\s*'|"\s*or\s*"|'\s*=\s*'|'\s*--)/i,
                /(?:benchmark|sleep|waitfor|pg_sleep)\s*\(/i
            ],
            xss: [
                /<script[^>]*>[\s\S]*?<\/script>/i,
                /javascript\s*:/i,
                /on(?:load|error|click|mouse|focus|blur)\s*=/i,
                /data\s*:\s*text\/html/i
            ],
            pathTraversal: [/(?:\.\.\/|\.\.\\){2,}/, /(?:\/etc\/passwd|\/etc\/shadow|\/proc\/)/i],
            commandInjection: [/[;&|`$]\s*(?:cat|ls|dir|wget|curl|nc|bash|sh|cmd|powershell)/i, /\$\([^)]+\)/, /`[^`]+`/]
        };
        
        this.badBots = [
            /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /dirbuster/i, /gobuster/i, /wfuzz/i, /ffuf/i,
            /burpsuite/i, /acunetix/i, /nessus/i, /openvas/i, /scrapy/i, /phantom/i, /selenium/i
        ];
    }
    
    scan(req) {
        const results = { blocked: false, score: 0, threats: [] };
        const cfg = SECURITY_CONFIG.WAF;
        
        if (req.url && req.url.length > cfg.maxURLLength) {
            results.threats.push({ type: 'oversized_url', severity: 5 });
            results.score += 5;
        }
        
        const url = SecureUtils.sanitizeString(decodeURIComponent(req.url || '').toLowerCase(), cfg.maxURLLength);
        
        for (const [category, patterns] of Object.entries(this.patterns)) {
            for (const pattern of patterns) {
                if (pattern.test(url)) {
                    const severity = { sqlInjection: 10, xss: 8, pathTraversal: 9, commandInjection: 10 }[category] || 5;
                    results.threats.push({ type: category, severity });
                    results.score += severity;
                    break;
                }
            }
        }
        
        if (req.body && typeof req.body === 'object') {
            const bodyStr = JSON.stringify(req.body).slice(0, cfg.maxBodySize);
            for (const [category, patterns] of Object.entries(this.patterns)) {
                for (const pattern of patterns) {
                    if (pattern.test(bodyStr)) {
                        results.threats.push({ type: `body_${category}`, severity: 8 });
                        results.score += 8;
                        break;
                    }
                }
            }
        }
        
        const ua = req.headers?.['user-agent'] || '';
        if (this.badBots.some(p => p.test(ua))) {
            results.threats.push({ type: 'malicious_bot', severity: 10 });
            results.score += 10;
        }
        
        results.blocked = results.score >= cfg.blockThreshold;
        return results;
    }
}

const waf = new WAFEngine();

// ============================================
// BEHAVIOR ANALYZER
// ============================================
class BehaviorAnalyzer {
    analyze(ip, req) {
        let behavior = storage.get('behaviorPatterns', ip) || { requests: [], endpoints: [], authFailures: 0, firstSeen: Date.now() };
        const now = Date.now();
        const oneMinuteAgo = now - 60000;
        
        behavior.requests = (behavior.requests || []).filter(r => r.timestamp > oneMinuteAgo);
        behavior.requests.push({ timestamp: now, path: req.path, method: req.method });
        
        if (!behavior.endpoints) behavior.endpoints = [];
        if (!behavior.endpoints.includes(req.path)) behavior.endpoints.push(req.path);
        if (behavior.endpoints.length > 100) behavior.endpoints = behavior.endpoints.slice(-100);
        
        let anomalyScore = 0;
        const requestRate = behavior.requests.length;
        
        if (requestRate > SECURITY_CONFIG.ANOMALY_THRESHOLD) anomalyScore += 30;
        if (behavior.endpoints.length > 50) anomalyScore += 25;
        if (behavior.authFailures > 5) anomalyScore += 25;
        
        behavior.anomalyScore = Math.min(100, anomalyScore);
        storage.set('behaviorPatterns', ip, behavior, 600000);
        
        return { anomalyScore: behavior.anomalyScore, requestRate, isAnomaly: behavior.anomalyScore > 50 };
    }
    
    recordAuthFailure(ip) {
        let b = storage.get('behaviorPatterns', ip) || { authFailures: 0 };
        b.authFailures = (b.authFailures || 0) + 1;
        storage.set('behaviorPatterns', ip, b, 600000);
    }
    
    resetAuthFailures(ip) {
        let b = storage.get('behaviorPatterns', ip);
        if (b) { b.authFailures = 0; storage.set('behaviorPatterns', ip, b, 600000); }
    }
}

const behaviorAnalyzer = new BehaviorAnalyzer();

// ============================================
// BOT DETECTOR
// ============================================
class BotDetector {
    constructor() {
        this.goodBots = [
            { name: 'Googlebot', pattern: /googlebot/i },
            { name: 'Bingbot', pattern: /bingbot/i },
            { name: 'DuckDuckBot', pattern: /duckduckbot/i }
        ];
        
        this.badBots = [
            /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /dirbuster/i, /gobuster/i, /wfuzz/i, /ffuf/i,
            /burpsuite/i, /acunetix/i, /nessus/i, /openvas/i, /scrapy/i, /wget\/[\d]/i, /curl\/[\d]/i,
            /python-requests/i, /go-http-client/i, /phantom/i, /selenium/i, /headless/i
        ];
    }
    
    detect(req) {
        const ua = req.headers?.['user-agent'] || '';
        const result = { isBot: false, botType: null, confidence: 0, action: 'allow' };
        
        for (const pattern of this.badBots) {
            if (pattern.test(ua)) {
                return { isBot: true, botType: 'malicious', confidence: 95, action: 'block' };
            }
        }
        
        for (const bot of this.goodBots) {
            if (bot.pattern.test(ua)) {
                return { isBot: true, botType: 'crawler', confidence: 80, action: 'allow' };
            }
        }
        
        // Header analysis
        if (!req.headers?.['accept-language']) { result.confidence += 20; }
        if (!req.headers?.['accept-encoding']) { result.confidence += 15; }
        if (ua.length < 20) { result.confidence += 25; }
        
        if (result.confidence >= 50) {
            result.isBot = true;
            result.botType = 'suspected';
            result.action = 'monitor';
        }
        
        return result;
    }
}

const botDetector = new BotDetector();

// ============================================
// HONEYPOT
// ============================================
class Honeypot {
    constructor() {
        this.trapPaths = [
            '/admin.php', '/wp-admin', '/wp-login.php', '/phpmyadmin', '/.env', '/.git/config',
            '/config.php', '/backup.sql', '/database.sql', '/.htaccess', '/.htpasswd'
        ];
        this.trapFields = ['website', 'url', 'homepage', 'fax'];
    }
    
    check(req) {
        const path = (req.path || '').toLowerCase();
        for (const trap of this.trapPaths) {
            if (path.includes(trap)) return { triggered: true, type: 'path', trap };
        }
        
        if (req.body && typeof req.body === 'object') {
            for (const field of this.trapFields) {
                if (req.body[field] && String(req.body[field]).trim()) {
                    return { triggered: true, type: 'form', trap: field };
                }
            }
        }
        
        return { triggered: false };
    }
}

const honeypot = new Honeypot();

// ============================================
// GET CLIENT IP - استخراج IP آمن
// ============================================
const getClientIP = (req) => {
    const connectionIP = (req.connection?.remoteAddress || req.socket?.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');
    
    const isTrustedProxy = SECURITY_CONFIG.TRUSTED_PROXIES.some(range => SecureUtils.isIPInRange(connectionIP, range));
    
    if (isTrustedProxy && req.headers?.['x-forwarded-for']) {
        const ips = req.headers['x-forwarded-for'].split(',').map(ip => ip.trim().replace(/^::ffff:/, '')).filter(ip => SecureUtils.isValidIP(ip));
        for (const ip of ips) {
            if (!SecureUtils.isPrivateIP(ip)) return ip;
        }
        if (ips.length > 0) return ips[0];
    }
    
    return connectionIP;
};

// ============================================
// SECURITY HEADERS
// ============================================
const addSecurityHeaders = (res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.removeHeader('X-Powered-By');
};

// ============================================
// LOG SECURITY EVENT
// ============================================
const logSecurityEvent = async (type, ip, details = {}) => {
    const event = { type, ip: ip ? ip.slice(0, 45) : 'unknown', timestamp: new Date().toISOString(), ...details };
    console.log(`🛡️ [SECURITY] ${JSON.stringify(event)}`);
    
    if (redisAvailable) {
        try {
            await redisClient.lpush('security:events', JSON.stringify(event));
            await redisClient.ltrim('security:events', 0, 9999);
        } catch {}
    }
    
    if (SECURITY_CONFIG.ALERT_WEBHOOK && ['waf_block', 'ddos_detected', 'brute_force'].includes(type)) {
        try {
            const fetch = (await import('node-fetch')).default;
            await fetch(SECURITY_CONFIG.ALERT_WEBHOOK, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(event)
            });
        } catch {}
    }
};

// ============================================
// BLOCK IP
// ============================================
const blockIP = (ip, reason, duration = 3600000) => {
    storage.set('blockedIPs', ip, { reason, blockedAt: Date.now() }, duration);
    storage.increment('blockHistory', ip, 86400000 * 7);
    logSecurityEvent('ip_blocked', ip, { reason, duration });
};

// ============================================
// MAIN SECURITY MIDDLEWARE
// ============================================
const securityMiddleware = async (req, res, next) => {
    const startTime = Date.now();
    const requestId = SecureUtils.generateSecureId(8);
    
    try {
        const path = req.path || req.url?.split('?')[0] || '/';
        
        // Skip static files
        if (SECURITY_CONFIG.STATIC_EXTENSIONS.test(path) || SECURITY_CONFIG.EXEMPT_PATHS.includes(path)) {
            return next();
        }
        
        const ip = getClientIP(req);
        if (!SecureUtils.isValidIP(ip)) {
            return res.status(400).json({ error: 'Invalid request', requestId });
        }
        
        // 1. Check blocked
        const blockData = storage.getWithMeta('blockedIPs', ip);
        if (blockData) {
            const remaining = Math.ceil((blockData.expiresAt - Date.now()) / 1000);
            return res.status(403).json({
                error: 'Access denied', reason: blockData.value.reason,
                remaining_seconds: remaining, appeal_contact: SECURITY_CONFIG.APPEAL_CONTACT, requestId
            });
        }
        
        // 2. DDoS Protection
        const ddosCheck = ddosProtection.check(ip);
        if (!ddosCheck.allowed) {
            logSecurityEvent('ddos_detected', ip, ddosCheck);
            return res.status(503).json({ error: 'Service temporarily unavailable', requestId });
        }
        
        // 3. Honeypot
        const honeypotCheck = honeypot.check(req);
        if (honeypotCheck.triggered) {
            logSecurityEvent('honeypot_triggered', ip, honeypotCheck);
            blockIP(ip, 'Honeypot triggered', 86400000);
            return setTimeout(() => res.status(404).json({ error: 'Not found' }), 3000);
        }
        
        // 4. Bot Detection
        const botResult = botDetector.detect(req);
        if (botResult.action === 'block') {
            logSecurityEvent('bot_blocked', ip, botResult);
            return res.status(403).json({ error: 'Access denied', requestId });
        }
        
        // 5. Rate Limiting
        if (SECURITY_CONFIG.ENABLE_RATE_LIMIT) {
            const endpointType = path.includes('/admin') ? 'admin' : path.includes('/api/auth') ? 'auth' : path.includes('/api') ? 'api' : 'global';
            const limiter = rateLimiters[endpointType] || rateLimiters.global;
            const rateResult = await limiter.consume(`${ip}:${endpointType}`);
            
            res.setHeader('X-RateLimit-Remaining', rateResult.remaining || 0);
            
            if (!rateResult.allowed) {
                const violations = storage.increment('rateViolations', ip, 300000);
                if (violations >= SECURITY_CONFIG.SOFT_BLOCK_VIOLATIONS) {
                    blockIP(ip, 'Rate limit violations', 600000);
                }
                return res.status(429).json({ error: 'Too many requests', retry_after: Math.ceil((rateResult.resetIn || 60000) / 1000), requestId });
            }
        }
        
        // 6. IP Analysis
        const ipAnalysis = await ipAnalyzer.analyze(ip);
        if (ipAnalysis.reputation < 30 && path.includes('/admin')) {
            return res.status(403).json({ error: 'Access denied', reason: 'Low reputation', requestId });
        }
        
        // 7. WAF
        if (SECURITY_CONFIG.ENABLE_WAF && shouldScanPath(path)) {
            const wafResult = waf.scan(req);
            if (wafResult.blocked) {
                logSecurityEvent('waf_block', ip, { threats: wafResult.threats, score: wafResult.score });
                blockIP(ip, 'WAF violation', 1800000);
                return res.status(403).json({ error: 'Request blocked', requestId });
            }
        }
        
        // 8. Behavior Analysis
        const behavior = behaviorAnalyzer.analyze(ip, req);
        if (behavior.isAnomaly && behavior.anomalyScore > 70) {
            logSecurityEvent('anomaly_detected', ip, { score: behavior.anomalyScore });
        }
        
        // 9. Security Headers
        addSecurityHeaders(res);
        
        // 10. Attach security info
        req.security = { ip, requestId, reputation: ipAnalysis.reputation, anomalyScore: behavior.anomalyScore };
        
        next();
    } catch (error) {
        console.error('Security middleware error:', error.message);
        next();
    }
};

// ============================================
// BRUTE FORCE PROTECTION
// ============================================
const bruteForceProtection = async (req, res, next) => {
    const ip = getClientIP(req);
    const cfg = SECURITY_CONFIG.BRUTE_FORCE;
    
    let attempts = storage.get('loginAttempts', ip) || { count: 0, lockUntil: 0, lockCount: 0 };
    
    if (attempts.lockUntil > Date.now()) {
        const remaining = Math.ceil((attempts.lockUntil - Date.now()) / 1000);
        return res.status(429).json({ error: 'Account locked', remaining_seconds: remaining });
    }
    
    req.recordFailedAttempt = () => {
        attempts.count++;
        behaviorAnalyzer.recordAuthFailure(ip);
        
        if (attempts.count >= cfg.maxAttempts) {
            const lockTime = Math.min(cfg.lockoutTime * Math.pow(cfg.escalationMultiplier, attempts.lockCount), cfg.maxLockoutTime);
            attempts.lockUntil = Date.now() + lockTime;
            attempts.lockCount++;
            attempts.count = 0;
            logSecurityEvent('brute_force', ip, { lockTime, lockCount: attempts.lockCount });
        }
        storage.set('loginAttempts', ip, attempts, 86400000);
    };
    
    req.resetFailedAttempts = () => {
        storage.delete('loginAttempts', ip);
        behaviorAnalyzer.resetAuthFailures(ip);
    };
    
    req.loginAttempts = { count: attempts.count, remaining: cfg.maxAttempts - attempts.count };
    next();
};

// ============================================
// HELPER FUNCTIONS
// ============================================
function shouldScanPath(path) {
    const sensitive = ['/admin', '/api/', '/login', '/register', '/auth', '/user', '/payment', '/upload'];
    return sensitive.some(p => path.includes(p));
}

// ============================================
// ADMIN FUNCTIONS
// ============================================
const securityAdmin = {
    getStats: () => ({
        storage: storage.getStats(),
        ddos: ddosProtection.getStats(),
        redis: { available: redisAvailable },
        threatLists: { torNodes: ipAnalyzer.torNodes.size, lastUpdate: ipAnalyzer.lastUpdate },
        config: { protectionLevel: SECURITY_CONFIG.PROTECTION_LEVEL, wafEnabled: SECURITY_CONFIG.ENABLE_WAF, rateLimitEnabled: SECURITY_CONFIG.ENABLE_RATE_LIMIT },
        timestamp: new Date().toISOString()
    }),
    
    getBlockedIPs: () => {
        const blocked = [];
        const store = storage.getStore('blockedIPs');
        for (const [, item] of store.entries()) {
            if (Date.now() < item.expiresAt) {
                blocked.push({
                    reason: item.value.reason,
                    blockedAt: new Date(item.value.blockedAt).toISOString(),
                    expiresAt: new Date(item.expiresAt).toISOString(),
                    remaining: Math.ceil((item.expiresAt - Date.now()) / 1000)
                });
            }
        }
        return blocked;
    },
    
    unblockIP: (ip) => {
        storage.delete('blockedIPs', ip);
        storage.delete('loginAttempts', ip);
        storage.delete('rateViolations', ip);
        storage.delete('behaviorPatterns', ip);
        logSecurityEvent('ip_unblocked', ip, { manual: true });
        return { success: true };
    },
    
    blockIP: (ip, reason, duration = 3600000) => {
        blockIP(ip, reason, duration);
        return { success: true };
    },
    
    getSecurityEvents: async (limit = 100) => {
        if (redisAvailable) {
            try {
                const events = await redisClient.lrange('security:events', 0, limit - 1);
                return events.map(e => JSON.parse(e));
            } catch { return []; }
        }
        return [];
    },
    
    cleanup: () => ({ success: true, cleaned: storage.cleanup() })
};

// ============================================
// MAINTENANCE
// ============================================
setInterval(() => {
    const cleaned = storage.cleanup();
    const stats = storage.getStats();
    console.log(`🔧 [MAINTENANCE] Cleaned: ${cleaned}, Total: ${stats.totalEntries}`);
}, 300000);

// ============================================
// EXPORTS
// ============================================
module.exports = {
    securityMiddleware,
    bruteForceProtection,
    getClientIP,
    addSecurityHeaders,
    securityAdmin,
    
    // للاختبار
    storage,
    ipAnalyzer,
    waf,
    behaviorAnalyzer,
    botDetector,
    honeypot,
    ddosProtection,
    rateLimiters,
    
    SECURITY_CONFIG,
    
    utils: {
        blockIP,
        logSecurityEvent,
        SecureUtils
    }
};
