// middleware/security.js - SecureArmor v15.0 Advanced Edition
// 🔥 تحسينات Layer 7 + CDN + DDoS Protection المحسنة
'use strict';

const crypto = require('crypto');
const config = require('../config');

// ============================================
// 🔥 ENHANCED SECURE UTILITIES
// ============================================
const SecureUtils = {
    generateSecureId: (length = 32) => crypto.randomBytes(length).toString('hex'),
    
    secureHash: (data, algorithm = 'sha256') => 
        crypto.createHash(algorithm).update(String(data)).digest('hex'),
    
    secureCompare: (a, b) => crypto.timingSafeEqual(
        Buffer.from(String(a)), 
        Buffer.from(String(b))
    ),
    
    sanitizeString: (str, maxLength = 1000) => {
        if (typeof str !== 'string') return '';
        return str
            .normalize('NFKC') // ترميز Unicode موحد
            .replace(/[\x00-\x1f\x7f-\x9f]/g, '')
            .replace(/[\u200B-\u200D\uFEFF]/g, '') // حذف المسافات المخفية
            .slice(0, maxLength)
            .trim();
    },
    
    isValidIP: (ip) => {
        if (!ip || typeof ip !== 'string') return false;
        
        // IPv4 مع CIDR support
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/\d{1,2})?$/;
        
        // IPv6 مع CIDR support
        const ipv6Regex = /^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)(?:\/\d{1,3})?$/;
        
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    },
    
    isIPv6: (ip) => ip && ip.includes(':'),
    
    ipToInt: (ip) => {
        if (!ip || ip.includes(':')) return 0;
        const octets = ip.split('.');
        if (octets.length !== 4) return 0;
        return ((parseInt(octets[0]) << 24) >>> 0) +
               ((parseInt(octets[1]) << 16) >>> 0) +
               ((parseInt(octets[2]) << 8) >>> 0) +
               (parseInt(octets[3]) >>> 0);
    },
    
    isIPInRange: (ip, cidr) => {
        if (!ip) return false;
        if (SecureUtils.isIPv6(ip)) return ip === cidr;
        if (!cidr.includes('/')) return ip === cidr;
        
        try {
            const [range, bits] = cidr.split('/');
            const mask = ~((1 << (32 - parseInt(bits))) - 1) >>> 0;
            return (SecureUtils.ipToInt(ip) & mask) === (SecureUtils.ipToInt(range) & mask);
        } catch { return false; }
    },
    
    isPrivateIP: (ip) => {
        if (!ip) return false;
        if (SecureUtils.isIPv6(ip)) {
            return ip === '::1' || 
                   ip.startsWith('fe80:') || 
                   ip.startsWith('fc00:') || 
                   ip.startsWith('fd') ||
                   ip === '::ffff:127.0.0.1';
        }
        const privateRanges = [
            '10.0.0.0/8', 
            '172.16.0.0/12', 
            '192.168.0.0/16', 
            '127.0.0.0/8',
            '169.254.0.0/16'
        ];
        return privateRanges.some(range => SecureUtils.isIPInRange(ip, range));
    },
    
    generateFingerprint: (req) => {
        const components = [
            req.headers?.['user-agent'] || '',
            req.headers?.['accept-language'] || '',
            req.headers?.['accept-encoding'] || '',
            req.headers?.['accept'] || '',
            req.headers?.['sec-ch-ua'] || '',
            req.headers?.['sec-ch-ua-platform'] || ''
        ];
        return SecureUtils.secureHash(components.join('|')).slice(0, 16);
    },
    
    // 🔥 NEW: تقييم تعقيد الطلب
    computeRequestComplexity: (req) => {
        let complexity = 0;
        
        // حجم الـ Body
        if (req.body) {
            const bodySize = JSON.stringify(req.body).length;
            if (bodySize > 10000) complexity += 2;
            if (bodySize > 50000) complexity += 3;
            if (bodySize > 100000) complexity += 5;
        }
        
        // عدد الـ Headers
        const headerCount = Object.keys(req.headers || {}).length;
        if (headerCount > 20) complexity += 1;
        if (headerCount > 30) complexity += 2;
        
        // طول الـ URL
        const urlLength = req.url?.length || 0;
        if (urlLength > 500) complexity += 2;
        if (urlLength > 1000) complexity += 5;
        
        return complexity;
    }
};

// ============================================
// 🚀 ENHANCED DDOS PROTECTION
// ============================================
class DDoSProtection {
    constructor() {
        this.connections = new Map(); // per IP
        this.globalCount = 0;
        this.burstConnections = new Map(); // للـ Burst Detection
        
        // 🔥 Dynamic thresholds based on traffic
        this.GLOBAL_RPS = process.env.GLOBAL_RPS || 1000;
        this.IP_RPS = process.env.IP_RPS || 20;
        this.BURST_LIMIT = process.env.BURST_LIMIT || 50;
        
        // Auto-adjust thresholds based on server load
        this.autoAdjustThresholds();
        
        // تنظيف أسرع (كل 100ms بدلاً من 1000ms)
        setInterval(() => {
            this.globalCount = Math.max(0, this.globalCount - 100);
            this.cleanConnections();
            this.cleanBurstConnections();
        }, 100);
        
        // تعديل الـ thresholds تلقائياً كل 5 ثوان
        setInterval(() => this.autoAdjustThresholds(), 5000);
    }
    
    autoAdjustThresholds() {
        // تقليل الـ thresholds إذا كان الحمل مرتفعاً
        const memUsage = process.memoryUsage().heapUsed / process.memoryUsage().heapTotal;
        const loadFactor = memUsage > 0.8 ? 0.5 : memUsage > 0.6 ? 0.7 : 1;
        
        this.IP_RPS = Math.floor((process.env.IP_RPS || 20) * loadFactor);
        this.BURST_LIMIT = Math.floor((process.env.BURST_LIMIT || 50) * loadFactor);
    }
    
    cleanConnections() {
        const now = Date.now();
        for (const [ip, data] of this.connections.entries()) {
            // الاحتفاظ بـ timestamps للثانية الأخيرة فقط
            data.timestamps = data.timestamps.filter(t => now - t < 1000);
            if (data.timestamps.length === 0) {
                this.connections.delete(ip);
            }
        }
    }
    
    cleanBurstConnections() {
        const now = Date.now();
        for (const [ip, timestamps] of this.burstConnections.entries()) {
            const recent = timestamps.filter(t => now - t < 100); // 100ms للنافذة
            if (recent.length === 0) {
                this.burstConnections.delete(ip);
            } else {
                this.burstConnections.set(ip, recent);
            }
        }
    }
    
    check(ip) {
        this.globalCount++;
        
        // 🔥 Global rate check
        if (this.globalCount > this.GLOBAL_RPS) {
            return { 
                allowed: false, 
                reason: 'Server under high load', 
                type: 'global_ddos',
                retryAfter: 60 
            };
        }
        
        // 🔥 IP-specific rate checking
        let ipData = this.connections.get(ip);
        const now = Date.now();
        
        if (!ipData) {
            ipData = { count: 0, timestamps: [] };
        }
        
        // إضافة timestamp جديد
        ipData.timestamps.push(now);
        
        // الاحتفاظ بـ 1 ثانية فقط
        ipData.timestamps = ipData.timestamps.filter(t => now - t < 1000);
        ipData.count = ipData.timestamps.length;
        this.connections.set(ip, ipData);
        
        // 🔥 IP RPS check
        if (ipData.count > this.IP_RPS) {
            return { 
                allowed: false, 
                reason: 'Rate exceeded', 
                type: 'ip_ddos',
                retryAfter: 30 
            };
        }
        
        // 🔥 Burst detection (طلبات في آخر 100ms)
        let burstData = this.burstConnections.get(ip) || [];
        burstData.push(now);
        burstData = burstData.filter(t => now - t < 100);
        this.burstConnections.set(ip, burstData);
        
        if (burstData.length > this.BURST_LIMIT) {
            return { 
                allowed: false, 
                reason: 'Burst limit exceeded', 
                type: 'burst_ddos',
                retryAfter: 15 
            };
        }
        
        return { allowed: true };
    }
    
    getStats() {
        return { 
            globalRPS: this.globalCount, 
            connections: this.connections.size,
            burstConnections: this.burstConnections.size,
            thresholds: {
                ipRPS: this.IP_RPS,
                burstLimit: this.BURST_LIMIT,
                globalRPS: this.GLOBAL_RPS
            }
        };
    }
}

// ============================================
// 🛡️ DYNAMIC BLACKLIST MANAGER
// ============================================
class DynamicBlacklist {
    constructor() {
        this.blacklist = new Map(); // IP => { blockedUntil, reason, violations }
        this.violationTracker = new Map(); // IP => violation count
        this.autoUnblockInterval = setInterval(() => this.cleanup(), 30000);
    }
    
    isBlocked(ip) {
        const record = this.blacklist.get(ip);
        if (!record) return false;
        
        if (Date.now() > record.blockedUntil) {
            this.blacklist.delete(ip);
            return false;
        }
        
        return {
            blocked: true,
            reason: record.reason,
            remaining: Math.ceil((record.blockedUntil - Date.now()) / 1000),
            blockedAt: record.blockedAt
        };
    }
    
    addViolation(ip, severity = 1, reason = 'unknown') {
        const current = this.violationTracker.get(ip) || { count: 0, lastViolation: 0 };
        current.count += severity;
        current.lastViolation = Date.now();
        this.violationTracker.set(ip, current);
        
        // 🔥 Dynamic blocking based on violation count
        let blockDuration = 0;
        
        if (current.count >= 10) {
            blockDuration = 3600000; // 1 hour
        } else if (current.count >= 5) {
            blockDuration = 900000; // 15 minutes
        } else if (current.count >= 3) {
            blockDuration = 300000; // 5 minutes
        } else if (current.count >= 2) {
            blockDuration = 60000; // 1 minute
        }
        
        if (blockDuration > 0) {
            this.block(ip, blockDuration, `${reason} (violations: ${current.count})`);
        }
        
        return current.count;
    }
    
    block(ip, duration = 60000, reason = 'Multiple violations') {
        this.blacklist.set(ip, {
            blockedUntil: Date.now() + duration,
            blockedAt: Date.now(),
            reason: reason,
            violations: this.violationTracker.get(ip)?.count || 1
        });
        
        logSecurityEvent('ip_blacklisted', ip, { 
            reason, 
            duration: `${duration/1000}s`,
            violations: this.violationTracker.get(ip)?.count || 1 
        });
        
        return true;
    }
    
    unblock(ip) {
        this.blacklist.delete(ip);
        this.violationTracker.delete(ip);
        logSecurityEvent('ip_unblacklisted', ip, { manual: true });
        return true;
    }
    
    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        
        // تنظيف الـ blacklist
        for (const [ip, record] of this.blacklist.entries()) {
            if (now > record.blockedUntil) {
                this.blacklist.delete(ip);
                cleaned++;
            }
        }
        
        // تنظيف violation tracker (أقدم من 24 ساعة)
        for (const [ip, record] of this.violationTracker.entries()) {
            if (now - record.lastViolation > 86400000) {
                this.violationTracker.delete(ip);
            }
        }
        
        return cleaned;
    }
    
    getStats() {
        return {
            blacklisted: this.blacklist.size,
            trackedIPs: this.violationTracker.size,
            violations: Array.from(this.violationTracker.values())
                .reduce((sum, v) => sum + v.count, 0)
        };
    }
}

// ============================================
// 🔄 REDIS INTEGRATION - Enhanced
// ============================================
let redisClient = null;
let redisAvailable = false;

const initRedis = async () => {
    const redisUrl = config.SECURITY?.REDIS_URL || process.env.REDIS_URL;
    if (!redisUrl) {
        console.log('ℹ️ Redis not configured, using in-memory storage');
        return;
    }
    
    try {
        const Redis = require('ioredis');
        redisClient = new Redis(redisUrl, {
            maxRetriesPerRequest: 3,
            retryStrategy: (times) => {
                const delay = Math.min(times * 100, 3000);
                return delay;
            },
            reconnectOnError: (err) => {
                const targetError = 'READONLY';
                if (err.message.includes(targetError)) return true;
                return false;
            },
            enableOfflineQueue: false,
            password: process.env.REDIS_PASSWORD || undefined,
            tls: process.env.REDIS_TLS === 'true' ? {} : undefined
        });
        
        redisClient.on('connect', () => {
            redisAvailable = true;
            console.log('✅ Redis connected for distributed protection');
        });
        
        redisClient.on('error', (err) => {
            redisAvailable = false;
            console.warn('⚠️ Redis error:', err.message);
        });
        
        await redisClient.connect();
        
        // 🔥 اختبار Redis
        await redisClient.ping();
        console.log('✅ Redis ping successful');
        
    } catch (e) { 
        console.warn('⚠️ Redis not available:', e.message);
        redisAvailable = false;
    }
};

// 🔥 Redis-based Rate Limiter
class RedisRateLimiter {
    constructor(limit, windowMs = 60000) {
        this.limit = limit;
        this.windowMs = windowMs;
    }
    
    async check(ip, endpoint = 'global') {
        if (!redisAvailable || !redisClient) {
            return { allowed: true, remaining: this.limit }; // Fallback
        }
        
        const key = `ratelimit:${endpoint}:${ip}`;
        const now = Date.now();
        const windowStart = now - this.windowMs;
        
        try {
            // استخدام Redis Sorted Set للتتبع
            await redisClient.zremrangebyscore(key, 0, windowStart);
            
            const currentCount = await redisClient.zcard(key);
            
            if (currentCount >= this.limit) {
                const oldest = await redisClient.zrange(key, 0, 0, 'WITHSCORES');
                const waitMs = this.windowMs - (now - parseInt(oldest[1]));
                return { 
                    allowed: false, 
                    remaining: 0,
                    retryAfter: Math.ceil(waitMs / 1000)
                };
            }
            
            // إضافة الطلب الحالي
            await redisClient.zadd(key, now, `${now}:${Math.random()}`);
            await redisClient.expire(key, Math.ceil(this.windowMs / 1000) + 1);
            
            return { 
                allowed: true, 
                remaining: this.limit - currentCount - 1
            };
            
        } catch (error) {
            console.warn('Redis rate limiter failed:', error.message);
            return { allowed: true, remaining: this.limit }; // Fallback to allow
        }
    }
}

// ============================================
// 🌐 CDN & CLOUDFLARE INTEGRATION
// ============================================
const CDNIntegration = {
    // 🔥 Cloudflare IP Ranges (المحدثة)
    CLOUDFLARE_IP_RANGES: [
        '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '104.16.0.0/13', '104.24.0.0/14', '108.162.192.0/18',
        '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15',
        '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
        '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17'
    ],
    
    // 🔥 AWS CloudFront IP Ranges
    CLOUDFRONT_IP_RANGES: [
        '13.32.0.0/15', '13.35.0.0/16', '13.224.0.0/14',
        '52.46.0.0/18', '52.84.0.0/15', '52.124.128.0/17',
        '52.222.128.0/17', '54.182.0.0/16', '54.192.0.0/16',
        '54.230.0.0/16', '54.239.128.0/18', '54.240.128.0/18'
    ],
    
    // 🔥 Fastly IP Ranges
    FASTLY_IP_RANGES: [
        '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24',
        '103.245.222.0/23', '103.245.224.0/24', '104.156.80.0/20',
        '140.248.64.0/18', '140.248.128.0/17', '146.75.0.0/17',
        '151.101.0.0/16', '157.52.64.0/18', '167.82.0.0/17',
        '167.82.128.0/20', '167.82.160.0/20', '167.82.224.0/20',
        '172.111.64.0/18', '185.31.16.0/22', '199.27.72.0/21',
        '199.232.0.0/16'
    ],
    
    isCDNIP: (ip) => {
        if (!SecureUtils.isValidIP(ip)) return false;
        
        // التحقق من جميع نطاقات CDN
        const allRanges = [
            ...CDNIntegration.CLOUDFLARE_IP_RANGES,
            ...CDNIntegration.CLOUDFRONT_IP_RANGES,
            ...CDNIntegration.FASTLY_IP_RANGES
        ];
        
        return allRanges.some(range => SecureUtils.isIPInRange(ip, range));
    },
    
    // 🔥 استخراج IP العميل الحقيقي من خلف CDN
    extractRealIP: (req) => {
        const headers = req.headers || {};
        
        // 1. Cloudflare headers
        if (headers['cf-connecting-ip'] && SecureUtils.isValidIP(headers['cf-connecting-ip'])) {
            return headers['cf-connecting-ip'];
        }
        
        // 2. True-Client-IP (Akamai, Fastly)
        if (headers['true-client-ip'] && SecureUtils.isValidIP(headers['true-client-ip'])) {
            return headers['true-client-ip'];
        }
        
        // 3. X-Forwarded-For مع معالجة ذكية
        if (headers['x-forwarded-for']) {
            const ips = headers['x-forwarded-for']
                .split(',')
                .map(ip => ip.trim())
                .filter(ip => SecureUtils.isValidIP(ip) && !CDNIntegration.isCDNIP(ip));
            
            if (ips.length > 0) return ips[0];
        }
        
        // 4. X-Real-IP
        if (headers['x-real-ip'] && SecureUtils.isValidIP(headers['x-real-ip'])) {
            return headers['x-real-ip'];
        }
        
        // Fallback
        return (req.connection?.remoteAddress || req.socket?.remoteAddress || '127.0.0.1')
            .replace(/^::ffff:/, '');
    },
    
    // 🔥 التحقق مما إذا كان الطلب يمر عبر CDN موثوق
    isRequestViaTrustedCDN: (req) => {
        const clientIP = getClientIP(req); // IP الذي يصل للخادم
        
        if (CDNIntegration.isCDNIP(clientIP)) {
            // التحقق من وجود رؤوس CDN المطلوبة
            const hasCFHeaders = req.headers['cf-ray'] || req.headers['cf-connecting-ip'];
            const hasCloudFrontHeaders = req.headers['via'] && req.headers['via'].includes('CloudFront');
            const hasFastlyHeaders = req.headers['x-served-by'] === 'Fastly';
            
            return hasCFHeaders || hasCloudFrontHeaders || hasFastlyHeaders;
        }
        
        return false;
    },
    
    // 🔥 إضافة رؤوس أمان CDN
    addCDNSecurityHeaders: (res) => {
        // Cloudflare headers
        res.setHeader('CF-Cache-Status', 'DYNAMIC');
        res.setHeader('CF-Ray', SecureUtils.generateSecureId(16));
        
        // CDN caching hints
        res.setHeader('CDN-Cache-Control', 'no-store, no-cache, must-revalidate');
        
        // Request ID for tracing
        res.setHeader('X-CDN-Request-ID', SecureUtils.generateSecureId(16));
    }
};

// ============================================
// 🔧 UPDATED GET CLIENT IP
// ============================================
const getClientIP = (req) => {
    // 🔥 استخدام CDNIntegration لاستخراج IP
    const realIP = CDNIntegration.extractRealIP(req);
    
    // التحقق من صحة IP
    if (SecureUtils.isValidIP(realIP)) {
        return realIP;
    }
    
    // Fallback للطريقة القديمة
    const connectionIP = (req.connection?.remoteAddress || 
                         req.socket?.remoteAddress || 
                         '127.0.0.1').replace(/^::ffff:/, '');
    
    return connectionIP;
};

// ============================================
// 🚦 ENHANCED RATE LIMITING
// ============================================
class EnhancedRateLimiter {
    constructor() {
        this.endpointLimits = {
            // 🔥 Login/Register - حماية شديدة
            '/api/auth/login': { 
                ipRPS: 5, 
                globalRPS: 50,
                capacity: 5, 
                refillRate: 0.3,
                blockDuration: 900000 // 15 دقيقة بعد 5 محاولات فاشلة
            },
            '/api/auth/register': { 
                ipRPS: 3, 
                globalRPS: 30,
                capacity: 3, 
                refillRate: 0.2,
                blockDuration: 1800000 // 30 دقيقة
            },
            '/api/admin/login': { 
                ipRPS: 3, 
                globalRPS: 20,
                capacity: 3, 
                refillRate: 0.1,
                blockDuration: 3600000 // ساعة كاملة
            },
            
            // 🔥 Public API - حدود متوسطة
            '/api/getUser': { 
                ipRPS: 20, 
                globalRPS: 200,
                capacity: 30, 
                refillRate: 5 
            },
            '/api/updateDevice': { 
                ipRPS: 10, 
                globalRPS: 100,
                capacity: 20, 
                refillRate: 2 
            },
            
            // 🔥 Default limits
            'default': { 
                ipRPS: 50, 
                globalRPS: 1000,
                capacity: 100, 
                refillRate: 10 
            }
        };
        
        // 🔥 Redis rate limiters لكل endpoint
        this.redisLimiters = new Map();
        this.initRedisLimiters();
    }
    
    initRedisLimiters() {
        for (const [endpoint, config] of Object.entries(this.endpointLimits)) {
            this.redisLimiters.set(
                endpoint, 
                new RedisRateLimiter(config.capacity, 60000)
            );
        }
    }
    
    getEndpointConfig(path) {
        for (const [endpoint, config] of Object.entries(this.endpointLimits)) {
            if (path.startsWith(endpoint)) {
                return config;
            }
        }
        return this.endpointLimits.default;
    }
    
    async checkRateLimit(req) {
        const ip = getClientIP(req);
        const path = req.path || req.url?.split('?')[0] || '/';
        const config = this.getEndpointConfig(path);
        
        // 🔥 Redis-based rate limiting
        if (redisAvailable) {
            const limiter = this.redisLimiters.get(path) || 
                           this.redisLimiters.get('default') ||
                           new RedisRateLimiter(config.capacity);
            
            const result = await limiter.check(ip, path);
            
            if (!result.allowed) {
                // تسجيل المخالفة
                dynamicBlacklist.addViolation(ip, 1, 'rate_limit_exceeded');
                
                return {
                    allowed: false,
                    reason: 'Rate limit exceeded',
                    retryAfter: result.retryAfter || 60,
                    endpoint: path
                };
            }
            
            return { allowed: true, remaining: result.remaining };
        }
        
        // 🔥 Memory-based fallback
        return { allowed: true, remaining: config.capacity };
    }
    
    // 🔥 Dynamic adjustment based on traffic
    adjustLimitsBasedOnTraffic(currentRPS) {
        const adjustmentFactor = currentRPS > 1000 ? 0.7 : 
                                currentRPS > 500 ? 0.8 : 
                                currentRPS > 100 ? 0.9 : 1;
        
        for (const [endpoint, config] of Object.entries(this.endpointLimits)) {
            if (endpoint !== 'default') {
                config.ipRPS = Math.floor(config.ipRPS * adjustmentFactor);
                config.capacity = Math.floor(config.capacity * adjustmentFactor);
            }
        }
    }
}

// ============================================
// 🛡️ ENHANCED WAF WITH PAYLOAD VALIDATION
// ============================================
class EnhancedWAF extends WAFEngine {
    constructor() {
        super();
        
        // 🔥 Additional patterns
        this.patterns.apiAbuse = [
            /(?:api|v1|v2)\/.*?\.\.\/\.\./gi, // Path traversal in API
            /(?:api|v1|v2)\/.*?select.*?from/gi, // SQLi in API paths
            /(?:api|v1|v2)\/.*?union.*?select/gi
        ];
        
        this.patterns.massAssignment = [
            /(?:__proto__|constructor|prototype)\s*:/gi,
            /"\$[a-zA-Z_]\w*"\s*:/gi, // MongoDB operators
            /"\$[a-zA-Z_]\w*"\s*:\s*\{/gi
        ];
        
        this.patterns.graphql = [
            /__schema/gi,
            /introspection/gi,
            /__type/gi,
            /query\s*\{\s*__/gi
        ];
    }
    
    scan(req) {
        const results = super.scan(req);
        const path = req.path || req.url?.split('?')[0] || '';
        
        // 🔥 Payload size validation
        if (req.body) {
            const bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
            
            // Maximum payload size
            const maxBodySize = SECURITY_CONFIG.WAF?.maxBodySize || 1048576; // 1MB
            
            if (bodyStr.length > maxBodySize) {
                results.threats.push({ 
                    type: 'oversized_payload', 
                    severity: 8, 
                    location: 'body',
                    size: bodyStr.length 
                });
                results.score += 8;
            }
            
            // 🔥 Deep JSON validation
            if (typeof req.body === 'object') {
                this.validateJSONStructure(req.body, results);
            }
            
            // 🔥 GraphQL protection
            if (path.includes('/graphql') || path.includes('/gql')) {
                this.scanGraphQL(req.body, results);
            }
            
            // 🔥 Mass assignment protection
            this.scanMassAssignment(req.body, results);
        }
        
        // 🔥 API abuse detection
        this.scanAPIAbuse(req, results);
        
        results.blocked = results.score >= (SECURITY_CONFIG.WAF?.blockThreshold || 10);
        return results;
    }
    
    validateJSONStructure(obj, results, depth = 0) {
        if (depth > 10) { // منع التعمق المفرط
            results.threats.push({ type: 'deep_json', severity: 5, location: 'body' });
            results.score += 5;
            return;
        }
        
        if (Array.isArray(obj)) {
            if (obj.length > 1000) { // arrays كبيرة جداً
                results.threats.push({ type: 'large_array', severity: 3, location: 'body' });
                results.score += 3;
            }
            
            for (const item of obj.slice(0, 100)) { // تحقق من أول 100 عنصر فقط
                if (typeof item === 'object' && item !== null) {
                    this.validateJSONStructure(item, results, depth + 1);
                }
            }
        } else if (typeof obj === 'object' && obj !== null) {
            const keys = Object.keys(obj);
            
            if (keys.length > 100) { // objects كبيرة جداً
                results.threats.push({ type: 'large_object', severity: 3, location: 'body' });
                results.score += 3;
            }
            
            for (const key of keys) {
                // تحقق من مفاتيح خطيرة
                if (key.toLowerCase().includes('password') || 
                    key.toLowerCase().includes('token') ||
                    key.toLowerCase().includes('secret')) {
                    
                    const value = obj[key];
                    if (typeof value === 'string' && value.length > 1000) {
                        results.threats.push({ 
                            type: 'sensitive_data_leak', 
                            severity: 7, 
                            location: `body.${key}` 
                        });
                        results.score += 7;
                    }
                }
                
                const value = obj[key];
                if (typeof value === 'object' && value !== null) {
                    this.validateJSONStructure(value, results, depth + 1);
                }
            }
        }
    }
    
    scanGraphQL(body, results) {
        const query = body.query || '';
        
        for (const pattern of this.patterns.graphql) {
            if (pattern.test(query)) {
                results.threats.push({ type: 'graphql_introspection', severity: 6, location: 'body' });
                results.score += 6;
                break;
            }
        }
        
        // تحقق من عمق query
        const depth = this.calculateGraphQLDepth(query);
        if (depth > 10) {
            results.threats.push({ type: 'deep_graphql_query', severity: 5, location: 'body' });
            results.score += 5;
        }
    }
    
    calculateGraphQLDepth(query) {
        let depth = 0;
        let maxDepth = 0;
        
        for (const char of query) {
            if (char === '{') {
                depth++;
                maxDepth = Math.max(maxDepth, depth);
            } else if (char === '}') {
                depth--;
            }
        }
        
        return maxDepth;
    }
    
    scanMassAssignment(body, results) {
        const bodyStr = JSON.stringify(body).toLowerCase();
        
        for (const pattern of this.patterns.massAssignment) {
            if (pattern.test(bodyStr)) {
                results.threats.push({ type: 'mass_assignment', severity: 9, location: 'body' });
                results.score += 9;
                break;
            }
        }
    }
    
    scanAPIAbuse(req, results) {
        const path = (req.path || '').toLowerCase();
        const url = (req.url || '').toLowerCase();
        
        for (const pattern of this.patterns.apiAbuse) {
            if (pattern.test(path) || pattern.test(url)) {
                results.threats.push({ type: 'api_abuse', severity: 7, location: 'url' });
                results.score += 7;
                break;
            }
        }
    }
}

// ============================================
// 🔥 ENHANCED SECURITY MIDDLEWARE
// ============================================
const enhancedSecurityMiddleware = async (req, res, next) => {
    const startTime = Date.now();
    const requestId = SecureUtils.generateSecureId(8);
    
    try {
        const path = req.path || req.url?.split('?')[0] || '/';
        
        // Skip static files and exempt paths
        if (SECURITY_CONFIG.STATIC_EXTENSIONS.test(path) || 
            SECURITY_CONFIG.EXEMPT_PATHS.includes(path)) {
            return next();
        }
        
        const ip = getClientIP(req);
        
        // 🔥 CDN Integration - إضافة رؤوس CDN
        if (CDNIntegration.isRequestViaTrustedCDN(req)) {
            CDNIntegration.addCDNSecurityHeaders(res);
            req.isViaCDN = true;
        }
        
        // 🔥 Dynamic Blacklist Check
        const blacklistCheck = dynamicBlacklist.isBlocked(ip);
        if (blacklistCheck && blacklistCheck.blocked) {
            return res.status(429).json({
                error: 'Access temporarily restricted',
                reason: blacklistCheck.reason,
                remaining_seconds: blacklistCheck.remaining,
                appeal_contact: SECURITY_CONFIG.APPEAL_CONTACT,
                requestId
            });
        }
        
        // 🔥 DDoS Protection
        const ddosCheck = ddosProtection.check(ip);
        if (!ddosCheck.allowed) {
            // إضافة انتهاك للـ blacklist
            dynamicBlacklist.addViolation(ip, 2, ddosCheck.type);
            
            logSecurityEvent('ddos_detected', ip, ddosCheck);
            return res.status(503).json({
                error: 'Service temporarily unavailable',
                retry_after: ddosCheck.retryAfter || 30,
                requestId
            });
        }
        
        // 🔥 Enhanced Rate Limiting
        if (SECURITY_CONFIG.ENABLE_RATE_LIMIT) {
            const rateLimitResult = await enhancedRateLimiter.checkRateLimit(req);
            
            if (!rateLimitResult.allowed) {
                res.setHeader('X-RateLimit-Remaining', 0);
                res.setHeader('X-RateLimit-Reset', rateLimitResult.retryAfter || 60);
                
                return res.status(429).json({
                    error: 'Too many requests',
                    retry_after: rateLimitResult.retryAfter || 60,
                    endpoint: rateLimitResult.endpoint,
                    requestId
                });
            }
            
            res.setHeader('X-RateLimit-Remaining', rateLimitResult.remaining || 0);
        }
        
        // 🔥 Request Complexity Analysis
        const complexity = SecureUtils.computeRequestComplexity(req);
        if (complexity > 5) {
            // طلبات معقدة جداً تحتاج لمزيد من الفحص
            req.isComplexRequest = true;
            
            // تسجيل للتحليل
            logSecurityEvent('complex_request', ip, {
                complexity,
                path,
                method: req.method,
                bodySize: req.body ? JSON.stringify(req.body).length : 0
            });
        }
        
        // 🔥 Enhanced WAF Scanning
        if (SECURITY_CONFIG.ENABLE_WAF && shouldScanPath(path)) {
            const wafResult = enhancedWAF.scan(req);
            
            if (wafResult.blocked) {
                // إضافة انتهاك كبير للـ blacklist
                dynamicBlacklist.addViolation(ip, 5, 'waf_violation');
                
                logSecurityEvent('waf_block', ip, {
                    threats: wafResult.threats,
                    score: wafResult.score,
                    path
                });
                
                blockIP(ip, 'WAF violation', 1800000);
                
                return res.status(403).json({
                    error: 'Request blocked by security system',
                    requestId,
                    blocked_at: new Date().toISOString()
                });
            }
            
            // إذا كان هناك تهديدات ولكن لم يتم الحظر
            if (wafResult.score > 3) {
                dynamicBlacklist.addViolation(ip, 1, 'waf_anomaly');
            }
        }
        
        // 🔥 Security Headers with nonce
        const nonce = SecureUtils.generateSecureId(16);
        addSecurityHeaders(res, nonce);
        
        // 🔥 Attach security info
        req.security = {
            ip,
            requestId,
            complexity,
            fingerprint: SecureUtils.generateFingerprint(req),
            nonce,
            isViaCDN: req.isViaCDN || false,
            isComplexRequest: req.isComplexRequest || false,
            processingTime: Date.now() - startTime
        };
        
        // Track response for analysis
        const originalSend = res.send;
        res.send = function(data) {
            const responseTime = Date.now() - startTime;
            
            // تسجيل استجابة طويلة
            if (responseTime > 5000) { // أكثر من 5 ثوان
                logSecurityEvent('slow_response', ip, {
                    path,
                    responseTime,
                    statusCode: res.statusCode
                });
            }
            
            // إضافة header لوقت المعالجة
            res.setHeader('X-Processing-Time', `${responseTime}ms`);
            
            return originalSend.call(this, data);
        };
        
        next();
        
    } catch (error) {
        console.error('Enhanced security middleware error:', error.message);
        
        // Fallback to basic security
        req.security = { ip: getClientIP(req), requestId: SecureUtils.generateSecureId(8) };
        next();
    }
};

// ============================================
// 🎯 INITIALIZATION
// ============================================
// تهيئة المكونات المحسنة
const dynamicBlacklist = new DynamicBlacklist();
const ddosProtection = new DDoSProtection();
const enhancedRateLimiter = new EnhancedRateLimiter();
const enhancedWAF = new EnhancedWAF();

// تهيئة Redis
initRedis();

// ============================================
// 📊 ENHANCED ADMIN FUNCTIONS
// ============================================
const enhancedSecurityAdmin = {
    ...securityAdmin, // الحفاظ على الدوال القديمة
    
    getEnhancedStats: () => ({
        ...securityAdmin.getStats(),
        blacklist: dynamicBlacklist.getStats(),
        ddos: ddosProtection.getStats(),
        rateLimiting: {
            endpoints: Object.keys(enhancedRateLimiter.endpointLimits).length,
            redisEnabled: redisAvailable
        },
        cdn: {
            cloudflareRanges: CDNIntegration.CLOUDFLARE_IP_RANGES.length,
            cloudfrontRanges: CDNIntegration.CLOUDFRONT_IP_RANGES.length,
            fastlyRanges: CDNIntegration.FASTLY_IP_RANGES.length
        }
    }),
    
    getBlacklistDetails: () => {
        const details = [];
        for (const [ip, record] of dynamicBlacklist.blacklist.entries()) {
            details.push({
                ip,
                blockedAt: new Date(record.blockedAt).toISOString(),
                blockedUntil: new Date(record.blockedUntil).toISOString(),
                reason: record.reason,
                violations: record.violations
            });
        }
        return details;
    },
    
    clearBlacklist: () => {
        for (const [ip] of dynamicBlacklist.blacklist.entries()) {
            dynamicBlacklist.unblock(ip);
        }
        return { success: true, cleared: dynamicBlacklist.blacklist.size };
    },
    
    adjustRateLimits: (endpoint, newLimits) => {
        if (enhancedRateLimiter.endpointLimits[endpoint]) {
            enhancedRateLimiter.endpointLimits[endpoint] = {
                ...enhancedRateLimiter.endpointLimits[endpoint],
                ...newLimits
            };
            return { success: true, endpoint, newLimits };
        }
        return { success: false, error: 'Endpoint not found' };
    }
};

// ============================================
// 📈 MAINTENANCE & MONITORING
// ============================================
setInterval(() => {
    const cleaned = storage.cleanup();
    const blacklistCleaned = dynamicBlacklist.cleanup();
    
    if (cleaned > 0 || blacklistCleaned > 0) {
        console.log(`🔧 [MAINTENANCE] Cleaned: ${cleaned} entries, ${blacklistCleaned} from blacklist`);
    }
    
    // 🔥 Auto-adjust rate limits based on traffic
    const stats = ddosProtection.getStats();
    enhancedRateLimiter.adjustLimitsBasedOnTraffic(stats.globalRPS);
    
}, 300000); // كل 5 دقائق

// ============================================
// 📦 EXPORTS
// ============================================
module.exports = {
    securityMiddleware: enhancedSecurityMiddleware,
    bruteForceProtection,
    getClientIP,
    addSecurityHeaders,
    securityAdmin: enhancedSecurityAdmin,
    
    // المكونات المحسنة
    storage,
    ipAnalyzer,
    waf: enhancedWAF,
    behaviorAnalyzer,
    botDetector,
    honeypot,
    ddosProtection,
    rateLimiters,
    
    // المكونات الجديدة
    dynamicBlacklist,
    enhancedRateLimiter,
    CDNIntegration,
    
    // الإعدادات
    SECURITY_CONFIG,
    TRUSTED_APP_ENDPOINTS,
    
    // الأدوات
    utils: {
        blockIP,
        logSecurityEvent,
        SecureUtils,
        isRequestViaCDN: CDNIntegration.isRequestViaTrustedCDN,
        extractRealIP: CDNIntegration.extractRealIP
    }
};
