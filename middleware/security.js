// middleware/security.js - SecureArmor v14.1 Enhanced Edition
// إصلاح جميع الثغرات المحتملة + تحسينات متقدمة
'use strict';

const crypto = require('crypto');
const config = require('../config');

// ============================================
// SECURE UTILITIES - أدوات آمنة محسّنة
// ============================================
const SecureUtils = {
    generateSecureId: (length = 32) => crypto.randomBytes(length).toString('hex'),
    
    secureHash: (data) => crypto.createHash('sha256').update(String(data)).digest('hex'),
    
    secureCompare: (a, b) => {
        if (typeof a !== 'string' || typeof b !== 'string') return false;
        if (a.length !== b.length) return false;
        try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } 
        catch { return false; }
    },
    
    sanitizeString: (str, maxLength = 1000) => {
        if (typeof str !== 'string') return '';
        return str.slice(0, maxLength).replace(/[\x00-\x1f\x7f]/g, '').trim();
    },
    
    // ✅ إصلاح #9: دعم IPv4 و IPv6
    isValidIP: (ip) => {
        if (!ip || typeof ip !== 'string') return false;
        const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6 = /^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)$/;
        return ipv4.test(ip) || ipv6.test(ip);
    },
    
    isIPv6: (ip) => ip && ip.includes(':'),
    
    ipToInt: (ip) => {
        if (!ip || ip.includes(':')) return 0; // IPv6 يُعامل بشكل مختلف
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
    },
    
    isIPInRange: (ip, cidr) => {
        if (!ip) return false;
        if (SecureUtils.isIPv6(ip)) return ip === cidr; // IPv6 exact match فقط
        if (!cidr.includes('/')) return ip === cidr;
        
        try {
            const [range, bits] = cidr.split('/');
            const mask = ~(2 ** (32 - parseInt(bits)) - 1);
            return (SecureUtils.ipToInt(ip) & mask) === (SecureUtils.ipToInt(range) & mask);
        } catch { return false; }
    },
    
    isPrivateIP: (ip) => {
        if (!ip) return false;
        if (SecureUtils.isIPv6(ip)) {
            return ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd');
        }
        const privateRanges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'];
        return privateRanges.some(range => SecureUtils.isIPInRange(ip, range));
    },
    
    // ✅ إصلاح #7: Fingerprint للجهاز
    generateFingerprint: (req) => {
        const components = [
            req.headers?.['user-agent'] || '',
            req.headers?.['accept-language'] || '',
            req.headers?.['accept-encoding'] || '',
            req.headers?.['accept'] || ''
        ];
        return SecureUtils.secureHash(components.join('|')).slice(0, 16);
    }
};

// ============================================
// CONFIGURATION - الإعدادات المحسّنة
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
    
    // ✅ إصلاح #2: تعريف SOFT_BLOCK_VIOLATIONS
    SOFT_BLOCK_VIOLATIONS: config.SECURITY?.SOFT_BLOCK_VIOLATIONS || 3,
    
    // ✅ إصلاح #1: Trusted Proxies محددة بدقة
    TRUSTED_PROXIES: process.env.TRUSTED_PROXIES 
        ? process.env.TRUSTED_PROXIES.split(',').map(p => p.trim())
        : ['127.0.0.1'],
    
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
            lazyConnect: true,
            // ✅ إصلاح #9: حماية Redis
            password: process.env.REDIS_PASSWORD || undefined,
            tls: process.env.REDIS_TLS === 'true' ? {} : undefined
        });
        
        redisClient.on('connect', () => { redisAvailable = true; console.log('✅ Redis connected'); });
        redisClient.on('error', () => { redisAvailable = false; });
        redisClient.on('close', () => { redisAvailable = false; });
        
        await redisClient.connect();
    } catch (e) { console.warn('⚠️ Redis not available:', e.message); }
};

initRedis();

// ============================================
// SECURE STORAGE
// ============================================
class SecureStorage {
    constructor() {
        this.stores = new Map();
        this.MAX_ENTRIES = 50000;
        ['blockedIPs', 'rateLimits', 'loginAttempts', 'ipReputation', 'behaviorPatterns', 
         'challenges', 'fingerprints', 'threatLog', 'rateViolations', 'blockHistory',
         'userAttempts', 'dynamicHoneypots'].forEach(name => this.stores.set(name, new Map()));
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
// RATE LIMITER - محسّن #2
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
            // ✅ إصلاح #2: Lua script محسّن للدقة
            const lua = `
                local key, cap, rate, tokens, now = KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
                local b = redis.call('HMGET', key, 'tokens', 'lastRefill')
                local t, lr = tonumber(b[1]) or cap, tonumber(b[2]) or now
                local elapsed = (now - lr) / 1000
                local refill = elapsed * rate
                t = math.min(cap, t + refill)
                if t >= tokens then
                    redis.call('HMSET', key, 'tokens', t - tokens, 'lastRefill', now)
                    redis.call('EXPIRE', key, 3600)
                    return cjson.encode({allowed = true, remaining = math.floor(t - tokens)})
                end
                local waitTime = math.ceil((tokens - t) / rate * 1000)
                return cjson.encode({allowed = false, remaining = math.floor(t), resetIn = waitTime})
            `;
            const result = await redisClient.eval(lua, 1, key, this.capacity, this.refillRate, tokens, Date.now());
            return JSON.parse(result);
        } catch { return this.consumeMemory(identifier, tokens); }
    }
    
    consumeMemory(identifier, tokens) {
        const key = SecureUtils.secureHash(identifier);
        const now = Date.now();
        let bucket = this.buckets.get(key) || { tokens: this.capacity, lastRefill: now };
        
        const elapsed = (now - bucket.lastRefill) / 1000;
        bucket.tokens = Math.min(this.capacity, bucket.tokens + (elapsed * this.refillRate));
        bucket.lastRefill = now;
        this.buckets.set(key, bucket);
        
        if (bucket.tokens >= tokens) {
            bucket.tokens -= tokens;
            return { allowed: true, remaining: Math.floor(bucket.tokens) };
        }
        return { allowed: false, remaining: Math.floor(bucket.tokens), resetIn: Math.ceil((tokens - bucket.tokens) / this.refillRate * 1000) };
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
            else data.burst = Math.max(0, data.burst - 10); // تقليل burst تدريجياً
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
            isIPv6: SecureUtils.isIPv6(ip), threats: [], reputation: 100, timestamp: Date.now()
        };
        
        if (analysis.isTor) { analysis.reputation -= 50; analysis.threats.push('tor_exit_node'); }
        if (analysis.isPrivate) analysis.reputation -= 10;
        
        const previousBlocks = storage.get('blockHistory', ip) || 0;
        if (previousBlocks > 0) { 
            analysis.reputation -= Math.min(previousBlocks * 15, 50); 
            analysis.threats.push('previous_violations'); 
        }
        
        analysis.reputation = Math.max(0, Math.min(100, analysis.reputation));
        storage.set('ipReputation', ip, analysis, SECURITY_CONFIG.IP_CACHE_TTL);
        
        return analysis;
    }
}

const ipAnalyzer = new IPAnalyzer();

// ============================================
// WAF ENGINE - محسّن #3
// ============================================
class WAFEngine {
    constructor() {
        // ✅ إصلاح #3: Patterns محسّنة ومتقدمة
        this.patterns = {
            sqlInjection: [
                // Classic SQL Injection
                /(?:union\s+(?:all\s+)?select)/i,
                /(?:select\s+.*?\s+from\s+)/i,
                /(?:insert\s+into\s+.*?\s+values)/i,
                /(?:update\s+.*?\s+set\s+)/i,
                /(?:delete\s+from\s+)/i,
                /(?:drop\s+(?:table|database|column))/i,
                /(?:truncate\s+table)/i,
                // Bypass attempts
                /(?:\/\*.*?\*\/)/i,                          // SQL comments
                /(?:--|#|\/\*).*$/i,                         // Line comments
                /(?:'\s*(?:or|and)\s*'?\d*'?\s*[=<>])/i,    // ' or '1'='1
                /(?:'\s*;\s*(?:select|insert|update|delete))/i,
                /(?:(?:0x|x')[0-9a-f]+)/i,                   // Hex encoding
                /(?:char\s*\(\s*\d+\s*\))/i,                 // CHAR() function
                /(?:concat\s*\()/i,                          // CONCAT()
                /(?:benchmark\s*\()/i,
                /(?:sleep\s*\()/i,
                /(?:waitfor\s+delay)/i,
                /(?:pg_sleep)/i,
                // NoSQL Injection
                /(?:\$(?:where|gt|lt|ne|eq|regex|in|nin|or|and|not|exists))/i,
                /(?:\{\s*["\']?\$)/i,                        // MongoDB operators
            ],
            xss: [
                /<script[^>]*>[\s\S]*?<\/script>/gi,
                /<script[^>]*>/gi,
                /javascript\s*:/gi,
                /on(?:load|error|click|mouse\w*|focus|blur|change|submit|key\w*|touch\w*|drag\w*|scroll)\s*=/gi,
                /<(?:img|iframe|object|embed|svg|math|video|audio|source)[^>]*\s+on\w+\s*=/gi,
                /data\s*:\s*text\/html/gi,
                /expression\s*\(/gi,
                /vbscript\s*:/gi,
                /<(?:link|meta|base|object)[^>]*>/gi,
                /document\s*\.\s*(?:cookie|domain|location|write)/gi,
                /window\s*\.\s*(?:location|open)/gi,
                /eval\s*\(/gi,
                /(?:alert|confirm|prompt)\s*\(/gi,
                /innerHTML\s*=/gi,
                /outerHTML\s*=/gi,
                /insertAdjacentHTML/gi,
                /fromCharCode/gi
            ],
            pathTraversal: [
                /(?:\.\.\/|\.\.\\){1,}/g,
                /(?:\/etc\/(?:passwd|shadow|hosts|group))/i,
                /(?:\/proc\/(?:self|version|cmdline))/i,
                /(?:\/var\/log\/)/i,
                /(?:c:\\windows\\)/i,
                /(?:boot\.ini|win\.ini|system32)/i,
                /(?:%2e%2e%2f|%2e%2e\/|\.\.%2f)/gi,          // URL encoded
                /(?:%252e%252e%252f)/gi,                     // Double encoded
                /(?:\.\.%c0%af|\.\.%c1%9c)/gi               // Overlong UTF-8
            ],
            commandInjection: [
                /(?:[;&|`]\s*(?:cat|ls|dir|type|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby|php))/gi,
                /(?:\$\([^)]+\))/g,                          // $(command)
                /(?:`[^`]+`)/g,                              // `command`
                /(?:\|\s*(?:cat|ls|dir|wget|curl|nc|bash|sh))/gi,
                /(?:>\s*\/)/gi,                              // Redirect to root
                /(?:;\s*(?:rm|del|format)\s)/gi,
                /(?:\$\{[^}]+\})/g                           // ${command}
            ],
            xxe: [
                /<!ENTITY/gi,
                /<!DOCTYPE[^>]*\[/gi,
                /SYSTEM\s+["'][^"']*["']/gi,
                /PUBLIC\s+["'][^"']*["']/gi
            ],
            ssrf: [
                /(?:(?:https?|ftp|gopher|dict|file|ldap):\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|::1|\[::1\]))/gi,
                /(?:@(?:localhost|127\.0\.0\.1))/gi
            ],
            lfi: [
                /(?:php:\/\/(?:filter|input|data))/gi,
                /(?:expect:\/\/)/gi,
                /(?:zip:\/\/)/gi,
                /(?:phar:\/\/)/gi
            ]
        };
        
        this.badBots = [
            /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /dirbuster/i, /gobuster/i, /wfuzz/i, /ffuf/i,
            /burpsuite/i, /acunetix/i, /nessus/i, /openvas/i, /scrapy/i, /w3af/i, /arachni/i,
            /skipfish/i, /havij/i, /pangolin/i, /httperf/i, /siege/i, /slowloris/i, /hulk/i,
            /hydra/i, /medusa/i, /metasploit/i, /ncrack/i, /patator/i,
            /^python-requests/i, /^python-urllib/i, /^java\//i, /^perl/i, /^ruby/i,
            /^go-http-client/i, /^php\//i, /^wget\//i, /^curl\//i,
            /phantom/i, /selenium/i, /puppeteer/i, /playwright/i, /headless/i, /chrome-lighthouse/i
        ];
    }
    
    scan(req) {
        const results = { blocked: false, score: 0, threats: [] };
        const cfg = SECURITY_CONFIG.WAF;
        
        if (req.url && req.url.length > cfg.maxURLLength) {
            results.threats.push({ type: 'oversized_url', severity: 5 });
            results.score += 5;
        }
        
        // ✅ تحسين: فحص URL مع decoding متعدد المستويات
        let urlToScan = req.url || '';
        try {
            urlToScan = decodeURIComponent(urlToScan);
            urlToScan = decodeURIComponent(urlToScan); // Double decode
        } catch {}
        urlToScan = SecureUtils.sanitizeString(urlToScan.toLowerCase(), cfg.maxURLLength);
        
        // فحص URL
        for (const [category, patterns] of Object.entries(this.patterns)) {
            for (const pattern of patterns) {
                if (pattern.test(urlToScan)) {
                    const severity = this.getSeverity(category);
                    results.threats.push({ type: category, severity, location: 'url' });
                    results.score += severity;
                    break;
                }
            }
        }
        
        // ✅ تحسين #3: فحص Body بشكل أعمق
        if (req.body) {
            const bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
            const bodyToScan = bodyStr.slice(0, cfg.maxBodySize).toLowerCase();
            
            for (const [category, patterns] of Object.entries(this.patterns)) {
                for (const pattern of patterns) {
                    if (pattern.test(bodyToScan)) {
                        const severity = this.getSeverity(category);
                        results.threats.push({ type: `body_${category}`, severity, location: 'body' });
                        results.score += severity;
                        break;
                    }
                }
            }
        }
        
        // فحص Headers
        const headers = req.headers || {};
        const headersToCheck = ['referer', 'user-agent', 'cookie', 'x-forwarded-for', 'x-forwarded-host'];
        for (const header of headersToCheck) {
            if (headers[header]) {
                const headerValue = String(headers[header]).toLowerCase();
                for (const pattern of this.patterns.xss) {
                    if (pattern.test(headerValue)) {
                        results.threats.push({ type: 'header_xss', severity: 8, location: header });
                        results.score += 8;
                        break;
                    }
                }
            }
        }
        
        // فحص Bot
        const ua = headers['user-agent'] || '';
        if (this.badBots.some(p => p.test(ua))) {
            results.threats.push({ type: 'malicious_bot', severity: 10 });
            results.score += 10;
        }
        
        results.blocked = results.score >= cfg.blockThreshold;
        return results;
    }
    
    getSeverity(category) {
        const severities = { sqlInjection: 10, xss: 8, pathTraversal: 9, commandInjection: 10, xxe: 10, ssrf: 9, lfi: 9 };
        return severities[category] || 5;
    }
}

const waf = new WAFEngine();

// ============================================
// BEHAVIOR ANALYZER - محسّن #5
// ============================================
class BehaviorAnalyzer {
    constructor() {
        // ✅ إصلاح #5: Moving average
        this.baselineRPS = 10;
        this.learningRate = 0.1;
    }
    
    analyze(ip, req) {
        let behavior = storage.get('behaviorPatterns', ip) || { 
            requests: [], endpoints: [], authFailures: 0, 
            firstSeen: Date.now(), avgRPS: this.baselineRPS, 
            errorCount: 0, methods: {}
        };
        
        const now = Date.now();
        const oneMinuteAgo = now - 60000;
        
        behavior.requests = (behavior.requests || []).filter(r => r.timestamp > oneMinuteAgo);
        behavior.requests.push({ timestamp: now, path: req.path, method: req.method, status: 200 });
        
        if (!behavior.endpoints) behavior.endpoints = [];
        if (!behavior.endpoints.includes(req.path)) behavior.endpoints.push(req.path);
        if (behavior.endpoints.length > 100) behavior.endpoints = behavior.endpoints.slice(-100);
        
        // تتبع Methods
        behavior.methods = behavior.methods || {};
        behavior.methods[req.method] = (behavior.methods[req.method] || 0) + 1;
        
        // ✅ حساب Moving Average RPS
        const currentRPS = behavior.requests.length;
        behavior.avgRPS = behavior.avgRPS * (1 - this.learningRate) + currentRPS * this.learningRate;
        
        let anomalyScore = 0;
        
        // مقارنة مع المتوسط بدلاً من threshold ثابت
        if (currentRPS > behavior.avgRPS * 3) anomalyScore += 30;
        else if (currentRPS > behavior.avgRPS * 2) anomalyScore += 15;
        
        if (behavior.endpoints.length > 50) anomalyScore += 20;
        if (behavior.authFailures > 3) anomalyScore += Math.min(behavior.authFailures * 5, 30);
        
        // نسبة الأخطاء
        const errorRatio = behavior.errorCount / Math.max(behavior.requests.length, 1);
        if (errorRatio > 0.5) anomalyScore += 20;
        
        // نسبة غير GET requests
        const totalReqs = Object.values(behavior.methods).reduce((a, b) => a + b, 0);
        const nonGetRatio = (totalReqs - (behavior.methods['GET'] || 0)) / Math.max(totalReqs, 1);
        if (nonGetRatio > 0.7 && totalReqs > 20) anomalyScore += 15;
        
        behavior.anomalyScore = Math.min(100, anomalyScore);
        storage.set('behaviorPatterns', ip, behavior, 600000);
        
        return { 
            anomalyScore: behavior.anomalyScore, 
            requestRate: currentRPS, 
            avgRPS: Math.round(behavior.avgRPS),
            isAnomaly: behavior.anomalyScore > 50 
        };
    }
    
    recordError(ip) {
        let b = storage.get('behaviorPatterns', ip) || { errorCount: 0 };
        b.errorCount = (b.errorCount || 0) + 1;
        storage.set('behaviorPatterns', ip, b, 600000);
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
// BOT DETECTOR - محسّن #6
// ============================================
class BotDetector {
    constructor() {
        this.goodBots = [
            { name: 'Googlebot', pattern: /googlebot/i, verify: '.google.com' },
            { name: 'Bingbot', pattern: /bingbot/i, verify: '.bing.com' },
            { name: 'DuckDuckBot', pattern: /duckduckbot/i },
            { name: 'Slurp', pattern: /slurp/i, verify: '.yahoo.com' }
        ];
        
        this.badBots = waf.badBots; // استخدام نفس القائمة
        
        // ✅ تحسين #6: أنماط سلوك البوت
        this.botBehaviors = {
            noJsFingerprint: true,
            linearRequestPattern: true,
            noMouseMovement: true,
            exactTiming: true
        };
    }
    
    async detect(req, ip) {
        const ua = req.headers?.['user-agent'] || '';
        const result = { isBot: false, botType: null, confidence: 0, action: 'allow', reasons: [] };
        
        // فحص البوتات السيئة
        for (const pattern of this.badBots) {
            if (pattern.test(ua)) {
                return { isBot: true, botType: 'malicious', confidence: 95, action: 'block', reasons: ['Known bad bot'] };
            }
        }
        
        // فحص البوتات الجيدة
        for (const bot of this.goodBots) {
            if (bot.pattern.test(ua)) {
                // ✅ تحسين: التحقق من DNS للبوتات الجيدة
                if (bot.verify) {
                    const verified = await this.verifyBot(ip, bot.verify);
                    if (!verified) {
                        return { isBot: true, botType: 'fake_crawler', confidence: 90, action: 'block', reasons: ['Failed DNS verification'] };
                    }
                }
                return { isBot: true, botType: 'verified_crawler', confidence: 100, action: 'allow', reasons: [`Verified ${bot.name}`] };
            }
        }
        
        // ✅ تحسين #6: تحليل Headers متقدم
        const headers = req.headers || {};
        
        if (!headers['accept-language']) { result.confidence += 15; result.reasons.push('No Accept-Language'); }
        if (!headers['accept-encoding']) { result.confidence += 10; result.reasons.push('No Accept-Encoding'); }
        if (!headers['accept']) { result.confidence += 10; result.reasons.push('No Accept'); }
        if (ua.length < 20) { result.confidence += 20; result.reasons.push('Short UA'); }
        if (ua.length > 500) { result.confidence += 15; result.reasons.push('Oversized UA'); }
        
        // فحص ترتيب Headers
        const headerOrder = Object.keys(headers);
        if (headerOrder.length > 0 && headerOrder[0] !== 'host') {
            result.confidence += 10;
            result.reasons.push('Unusual header order');
        }
        
        // فحص Accept header
        if (headers['accept'] && !headers['accept'].includes('text/html') && !headers['accept'].includes('application/json')) {
            result.confidence += 10;
            result.reasons.push('Unusual Accept header');
        }
        
        // فحص Fingerprint consistency
        const fingerprint = SecureUtils.generateFingerprint(req);
        const fpData = storage.get('fingerprints', ip);
        if (fpData && fpData.fingerprint !== fingerprint) {
            result.confidence += 15;
            result.reasons.push('Fingerprint mismatch');
        }
        storage.set('fingerprints', ip, { fingerprint }, 3600000);
        
        if (result.confidence >= 60) {
            result.isBot = true;
            result.botType = 'suspected';
            result.action = 'challenge';
        } else if (result.confidence >= 40) {
            result.isBot = true;
            result.botType = 'possible';
            result.action = 'monitor';
        }
        
        return result;
    }
    
    async verifyBot(ip, expectedDomain) {
        try {
            const dns = require('dns').promises;
            const hostnames = await dns.reverse(ip);
            return hostnames.some(h => h.endsWith(expectedDomain));
        } catch { return false; }
    }
}

const botDetector = new BotDetector();

// ============================================
// HONEYPOT - محسّن #4
// ============================================
class Honeypot {
    constructor() {
        this.staticTrapPaths = [
            '/admin.php', '/wp-admin', '/wp-login.php', '/phpmyadmin', '/.env', '/.git/config',
            '/config.php', '/backup.sql', '/database.sql', '/.htaccess', '/.htpasswd',
            '/xmlrpc.php', '/wp-config.php', '/administrator', '/.svn', '/.hg',
            '/server-status', '/server-info', '/phpinfo.php', '/info.php', '/test.php',
            '/shell.php', '/cmd.php', '/c99.php', '/r57.php', '/webshell'
        ];
        
        this.trapFields = ['website', 'url', 'homepage', 'fax', 'company_url', 'http', 'link'];
        
        // ✅ إصلاح #4: مصائد ديناميكية لكل session
        this.dynamicTraps = new Set();
        this.generateDynamicTraps();
        setInterval(() => this.generateDynamicTraps(), 3600000);
    }
    
    generateDynamicTraps() {
        this.dynamicTraps.clear();
        const randomPaths = [
            `/admin_${SecureUtils.generateSecureId(4)}`,
            `/backup_${SecureUtils.generateSecureId(4)}.sql`,
            `/config_${SecureUtils.generateSecureId(4)}.php`,
            `/.env_${SecureUtils.generateSecureId(4)}`,
            `/db_${SecureUtils.generateSecureId(4)}`
        ];
        randomPaths.forEach(p => this.dynamicTraps.add(p));
    }
    
    check(req) {
        const path = (req.path || '').toLowerCase();
        
        // فحص المصائد الثابتة
        for (const trap of this.staticTrapPaths) {
            if (path.includes(trap)) return { triggered: true, type: 'path', trap };
        }
        
        // فحص المصائد الديناميكية
        for (const trap of this.dynamicTraps) {
            if (path === trap) return { triggered: true, type: 'dynamic_path', trap };
        }
        
        // فحص حقول النموذج
        if (req.body && typeof req.body === 'object') {
            for (const field of this.trapFields) {
                if (req.body[field] && String(req.body[field]).trim()) {
                    return { triggered: true, type: 'form', trap: field };
                }
            }
        }
        
        return { triggered: false };
    }
    
    getDynamicTraps() {
        return Array.from(this.dynamicTraps);
    }
}

const honeypot = new Honeypot();

// ============================================
// GET CLIENT IP - محسّن #1
// ============================================
const getClientIP = (req) => {
    const connectionIP = (req.connection?.remoteAddress || req.socket?.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');
    
    // ✅ إصلاح #1: تحقق صارم من trusted proxies
    const isTrustedProxy = SECURITY_CONFIG.TRUSTED_PROXIES.some(range => {
        if (range === connectionIP) return true;
        return SecureUtils.isIPInRange(connectionIP, range);
    });
    
    if (isTrustedProxy && req.headers?.['x-forwarded-for']) {
        const ips = req.headers['x-forwarded-for']
            .split(',')
            .map(ip => ip.trim().replace(/^::ffff:/, ''))
            .filter(ip => SecureUtils.isValidIP(ip));
        
        // ✅ أخذ آخر IP غير موثوق (أقرب للـ client الحقيقي)
        for (let i = ips.length - 1; i >= 0; i--) {
            const ip = ips[i];
            const isTrusted = SECURITY_CONFIG.TRUSTED_PROXIES.some(range => 
                ip === range || SecureUtils.isIPInRange(ip, range)
            );
            if (!isTrusted && !SecureUtils.isPrivateIP(ip)) {
                return ip;
            }
        }
        
        // Fallback للأول
        if (ips.length > 0) return ips[0];
    }
    
    return connectionIP;
};

// ============================================
// SECURITY HEADERS - محسّن #8
// ============================================
const addSecurityHeaders = (res, nonce = null) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0'); // Modern browsers don't need this
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=(), usb=()');
    
    // ✅ إصلاح #8: CSP محسّن (بدون unsafe-inline إذا أمكن)
    const cspDirectives = [
        "default-src 'self'",
        nonce ? `script-src 'self' 'nonce-${nonce}'` : "script-src 'self'",
        nonce ? `style-src 'self' 'nonce-${nonce}'` : "style-src 'self'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "upgrade-insecure-requests"
    ];
    res.setHeader('Content-Security-Policy', cspDirectives.join('; '));
    
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    res.setHeader('X-Download-Options', 'noopen');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');
};

// ============================================
// LOG SECURITY EVENT
// ============================================
const logSecurityEvent = async (type, ip, details = {}) => {
    const event = { 
        type, 
        ip: ip ? String(ip).slice(0, 45) : 'unknown', 
        timestamp: new Date().toISOString(), 
        ...details 
    };
    
    // ✅ إصلاح #9: لا نكشف معلومات حساسة في الـ logs
    console.log(`🛡️ [SECURITY] ${type} | IP: ${event.ip.slice(0, 20)}*** | ${JSON.stringify({ ...details, ip: undefined })}`);
    
    if (redisAvailable) {
        try {
            await redisClient.lpush('security:events', JSON.stringify(event));
            await redisClient.ltrim('security:events', 0, 9999);
        } catch {}
    }
    
    if (SECURITY_CONFIG.ALERT_WEBHOOK && ['waf_block', 'ddos_detected', 'brute_force', 'honeypot_triggered'].includes(type)) {
        try {
            const fetch = (await import('node-fetch')).default;
            await fetch(SECURITY_CONFIG.ALERT_WEBHOOK, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(event),
                timeout: 5000
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
                error: 'Access denied', 
                reason: blockData.value.reason,
                remaining_seconds: remaining, 
                appeal_contact: SECURITY_CONFIG.APPEAL_CONTACT, 
                requestId
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
            return setTimeout(() => res.status(404).json({ error: 'Not found' }), 3000 + Math.random() * 2000);
        }
        
        // 4. Bot Detection
        const botResult = await botDetector.detect(req, ip);
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
        if (behavior.isAnomaly && behavior.anomalyScore > SECURITY_CONFIG.ANOMALY_THRESHOLD) {
            logSecurityEvent('anomaly_detected', ip, { score: behavior.anomalyScore, avgRPS: behavior.avgRPS });
        }
        
        // 9. Security Headers
        const nonce = SecureUtils.generateSecureId(16);
        addSecurityHeaders(res, nonce);
        
        // 10. Attach security info
        req.security = { 
            ip, 
            requestId, 
            reputation: ipAnalysis.reputation, 
            anomalyScore: behavior.anomalyScore,
            fingerprint: SecureUtils.generateFingerprint(req),
            nonce
        };
        
        // Track response status for error rate
        res.on('finish', () => {
            if (res.statusCode >= 400) {
                behaviorAnalyzer.recordError(ip);
            }
        });
        
        next();
    } catch (error) {
        console.error('Security middleware error:', error.message);
        next();
    }
};

// ============================================
// BRUTE FORCE PROTECTION - محسّن #7
// ============================================
const bruteForceProtection = async (req, res, next) => {
    const ip = getClientIP(req);
    const cfg = SECURITY_CONFIG.BRUTE_FORCE;
    
    // ✅ إصلاح #7: Rate limit على IP + Username
    const username = req.body?.username || req.body?.email || '';
    const ipKey = ip;
    const userKey = username ? `user:${SecureUtils.secureHash(username)}` : null;
    const combinedKey = username ? `${ip}:${SecureUtils.secureHash(username)}` : null;
    
    let ipAttempts = storage.get('loginAttempts', ipKey) || { count: 0, lockUntil: 0, lockCount: 0 };
    let userAttempts = userKey ? (storage.get('userAttempts', userKey) || { count: 0, lockUntil: 0 }) : null;
    
    // Check IP lock
    if (ipAttempts.lockUntil > Date.now()) {
        const remaining = Math.ceil((ipAttempts.lockUntil - Date.now()) / 1000);
        return res.status(429).json({ error: 'Too many attempts from this IP', remaining_seconds: remaining });
    }
    
    // ✅ Check username lock (حماية إضافية)
    if (userAttempts && userAttempts.lockUntil > Date.now()) {
        const remaining = Math.ceil((userAttempts.lockUntil - Date.now()) / 1000);
        return res.status(429).json({ error: 'Account temporarily locked', remaining_seconds: remaining });
    }
    
    req.recordFailedAttempt = () => {
        ipAttempts.count++;
        behaviorAnalyzer.recordAuthFailure(ip);
        
        if (ipAttempts.count >= cfg.maxAttempts) {
            const lockTime = Math.min(cfg.lockoutTime * Math.pow(cfg.escalationMultiplier, ipAttempts.lockCount), cfg.maxLockoutTime);
            ipAttempts.lockUntil = Date.now() + lockTime;
            ipAttempts.lockCount++;
            ipAttempts.count = 0;
            logSecurityEvent('brute_force', ip, { lockTime, lockCount: ipAttempts.lockCount, username: username ? '***' : null });
        }
        storage.set('loginAttempts', ipKey, ipAttempts, 86400000);
        
        // ✅ Lock username أيضاً
        if (userKey) {
            userAttempts = userAttempts || { count: 0, lockUntil: 0 };
            userAttempts.count++;
            if (userAttempts.count >= cfg.maxAttempts * 2) { // عتبة أعلى للـ username
                userAttempts.lockUntil = Date.now() + cfg.lockoutTime;
                userAttempts.count = 0;
            }
            storage.set('userAttempts', userKey, userAttempts, 86400000);
        }
    };
    
    req.resetFailedAttempts = () => {
        storage.delete('loginAttempts', ipKey);
        if (userKey) storage.delete('userAttempts', userKey);
        behaviorAnalyzer.resetAuthFailures(ip);
    };
    
    req.loginAttempts = { count: ipAttempts.count, remaining: cfg.maxAttempts - ipAttempts.count };
    next();
};

// ============================================
// HELPER FUNCTIONS
// ============================================
function shouldScanPath(path) {
    const sensitive = ['/admin', '/api/', '/login', '/register', '/auth', '/user', '/payment', '/upload', '/download', '/export'];
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
        config: { 
            protectionLevel: SECURITY_CONFIG.PROTECTION_LEVEL, 
            wafEnabled: SECURITY_CONFIG.ENABLE_WAF, 
            rateLimitEnabled: SECURITY_CONFIG.ENABLE_RATE_LIMIT,
            trustedProxies: SECURITY_CONFIG.TRUSTED_PROXIES.length
        },
        honeypot: { staticTraps: honeypot.staticTrapPaths.length, dynamicTraps: honeypot.dynamicTraps.size },
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
    
    cleanup: () => ({ success: true, cleaned: storage.cleanup() }),
    
    getDynamicHoneypots: () => honeypot.getDynamicTraps()
};

// ============================================
// MAINTENANCE
// ============================================
setInterval(() => {
    const cleaned = storage.cleanup();
    const stats = storage.getStats();
    if (cleaned > 0 || stats.totalEntries > 1000) {
        console.log(`🔧 [MAINTENANCE] Cleaned: ${cleaned}, Total: ${stats.totalEntries}`);
    }
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
