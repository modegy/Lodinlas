// middleware/security.js - Security Middleware v14.1
const crypto = require('crypto');

class SecurityMiddleware {
    constructor(config) {
        this.config = config.SECURITY || {};
        this.ipCache = new Map();
        this.rateLimitStore = new Map();
        this.blockedIPs = new Set();
        this.bruteForceTracker = new Map();
        
        // تنظيف دوري للذاكرة
        setInterval(() => this.cleanup(), 60000);
    }

    // ═══════════════════════════════════════════
    // MAIN MIDDLEWARE
    // ═══════════════════════════════════════════
    middleware() {
        return async (req, res, next) => {
            try {
                const ip = this.getClientIP(req);
                req.clientIP = ip;

                // فحص IP المحظور
                if (this.isBlocked(ip)) {
                    return this.blockResponse(res, 'IP_BLOCKED');
                }

                // Rate Limiting
                if (this.config.ENABLE_RATE_LIMIT !== false) {
                    const rateLimitResult = this.checkRateLimit(ip, req.path);
                    if (!rateLimitResult.allowed) {
                        return this.blockResponse(res, 'RATE_LIMITED', rateLimitResult.retryAfter);
                    }
                }

                // WAF Protection
                if (this.config.ENABLE_WAF !== false) {
                    const wafResult = this.wafCheck(req);
                    if (!wafResult.safe) {
                        this.recordViolation(ip, wafResult.reason);
                        return this.blockResponse(res, 'WAF_BLOCKED', null, wafResult.reason);
                    }
                }

                // Bot Detection
                if (this.config.ENABLE_BOT_DETECTION !== false) {
                    const botScore = this.detectBot(req);
                    req.botScore = botScore;
                    if (botScore > (this.config.ANOMALY_THRESHOLD || 70)) {
                        this.recordViolation(ip, 'BOT_DETECTED');
                    }
                }

                // إضافة Security Headers
                this.setSecurityHeaders(res);

                next();
            } catch (err) {
                console.error('[Security] Error:', err.message);
                next();
            }
        };
    }

    // ═══════════════════════════════════════════
    // RATE LIMITING (Token Bucket)
    // ═══════════════════════════════════════════
    checkRateLimit(ip, path) {
        const limitType = this.getLimitType(path);
        const limits = this.config.RATE_LIMITS?.[limitType] || { capacity: 100, refill: 10 };
        const key = `${ip}:${limitType}`;
        const now = Date.now();

        let bucket = this.rateLimitStore.get(key);
        if (!bucket) {
            bucket = { tokens: limits.capacity, lastRefill: now };
        }

        // إعادة تعبئة التوكنز
        const elapsed = (now - bucket.lastRefill) / 1000;
        bucket.tokens = Math.min(limits.capacity, bucket.tokens + elapsed * limits.refill);
        bucket.lastRefill = now;

        if (bucket.tokens >= 1) {
            bucket.tokens -= 1;
            this.rateLimitStore.set(key, bucket);
            return { allowed: true };
        }

        this.rateLimitStore.set(key, bucket);
        return { 
            allowed: false, 
            retryAfter: Math.ceil((1 - bucket.tokens) / limits.refill) 
        };
    }

    getLimitType(path) {
        if (path.includes('/auth') || path.includes('/login')) return 'AUTH';
        if (path.includes('/admin')) return 'ADMIN';
        if (path.includes('/api')) return 'API';
        return 'GLOBAL';
    }

    // ═══════════════════════════════════════════
    // WAF (Web Application Firewall)
    // ═══════════════════════════════════════════
    wafCheck(req) {
        const wafConfig = this.config.WAF || {};
        
        // فحص طول URL
        if (req.url.length > (wafConfig.MAX_URL_LENGTH || 2048)) {
            return { safe: false, reason: 'URL_TOO_LONG' };
        }

        // فحص حجم Body
        const contentLength = parseInt(req.headers['content-length'] || 0);
        if (contentLength > (wafConfig.MAX_BODY_SIZE || 1048576)) {
            return { safe: false, reason: 'BODY_TOO_LARGE' };
        }

        // فحص أنماط الهجوم
        const payload = `${req.url}${JSON.stringify(req.query || {})}${JSON.stringify(req.body || {})}`;
        
        const attacks = [
            { pattern: /<script[\s\S]*?>[\s\S]*?<\/script>/gi, name: 'XSS' },
            { pattern: /(\b(union|select|insert|update|delete|drop|create|alter)\b.*\b(from|into|table|database)\b)/gi, name: 'SQL_INJECTION' },
            { pattern: /\.\.\//g, name: 'PATH_TRAVERSAL' },
            { pattern: /(\$\{|\{\{|<%|%>)/g, name: 'TEMPLATE_INJECTION' },
            { pattern: /(eval|exec|system|passthru|shell_exec)\s*\(/gi, name: 'COMMAND_INJECTION' }
        ];

        for (const attack of attacks) {
            if (attack.pattern.test(payload)) {
                return { safe: false, reason: attack.name };
            }
        }

        return { safe: true };
    }

    // ═══════════════════════════════════════════
    // BOT DETECTION
    // ═══════════════════════════════════════════
    detectBot(req) {
        let score = 0;
        const ua = req.headers['user-agent'] || '';

        // لا يوجد User-Agent
        if (!ua) score += 30;

        // User-Agent مشبوه
        const suspiciousUA = /(curl|wget|python|bot|spider|crawler|scraper)/i;
        if (suspiciousUA.test(ua)) score += 25;

        // لا يوجد Accept-Language
        if (!req.headers['accept-language']) score += 15;

        // لا يوجد Accept
        if (!req.headers['accept']) score += 10;

        // Headers غير طبيعية
        if (req.headers['x-forwarded-for']?.split(',').length > 5) score += 20;

        return Math.min(score, 100);
    }

    // ═══════════════════════════════════════════
    // BRUTE FORCE PROTECTION
    // ═══════════════════════════════════════════
    checkBruteForce(ip, endpoint) {
        const config = this.config.BRUTE_FORCE || {};
        const key = `${ip}:${endpoint}`;
        const tracker = this.bruteForceTracker.get(key) || { attempts: 0, lockoutUntil: 0, escalation: 1 };
        const now = Date.now();

        if (tracker.lockoutUntil > now) {
            return { allowed: false, retryAfter: Math.ceil((tracker.lockoutUntil - now) / 1000) };
        }

        return { allowed: true, attempts: tracker.attempts };
    }

    recordFailedAttempt(ip, endpoint) {
        const config = this.config.BRUTE_FORCE || {};
        const key = `${ip}:${endpoint}`;
        const tracker = this.bruteForceTracker.get(key) || { attempts: 0, lockoutUntil: 0, escalation: 1 };
        
        tracker.attempts++;
        
        if (tracker.attempts >= (config.MAX_ATTEMPTS || 5)) {
            const lockoutTime = Math.min(
                (config.LOCKOUT_TIME || 900000) * tracker.escalation,
                config.MAX_LOCKOUT_TIME || 86400000
            );
            tracker.lockoutUntil = Date.now() + lockoutTime;
            tracker.escalation *= (config.ESCALATION_MULTIPLIER || 2);
            tracker.attempts = 0;
        }
        
        this.bruteForceTracker.set(key, tracker);
    }

    resetBruteForce(ip, endpoint) {
        this.bruteForceTracker.delete(`${ip}:${endpoint}`);
    }

    // ═══════════════════════════════════════════
    // UTILITIES
    // ═══════════════════════════════════════════
    getClientIP(req) {
        return req.headers['cf-connecting-ip'] ||
               req.headers['x-real-ip'] ||
               req.headers['x-forwarded-for']?.split(',')[0].trim() ||
               req.socket?.remoteAddress ||
               'unknown';
    }

    isBlocked(ip) {
        return this.blockedIPs.has(ip);
    }

    blockIP(ip, duration) {
        this.blockedIPs.add(ip);
        if (duration) {
            setTimeout(() => this.blockedIPs.delete(ip), duration);
        }
    }

    recordViolation(ip, reason) {
        const cache = this.ipCache.get(ip) || { violations: 0, reasons: [] };
        cache.violations++;
        cache.reasons.push({ reason, time: Date.now() });
        this.ipCache.set(ip, cache);

        if (cache.violations >= (this.config.SOFT_BLOCK_VIOLATIONS || 3)) {
            this.blockIP(ip, this.config.DDOS?.BLOCK_DURATION || 600000);
            console.log(`[Security] IP blocked: ${ip} - Violations: ${cache.violations}`);
        }
    }

    setSecurityHeaders(res) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    }

    blockResponse(res, reason, retryAfter = null, details = null) {
        const status = reason === 'RATE_LIMITED' ? 429 : 403;
        
        if (retryAfter) {
            res.setHeader('Retry-After', retryAfter);
        }

        return res.status(status).json({
            error: true,
            code: reason,
            message: this.getBlockMessage(reason),
            details: details,
            contact: this.config.APPEAL_CONTACT || 'security@yourdomain.com'
        });
    }

    getBlockMessage(reason) {
        const messages = {
            'IP_BLOCKED': 'Your IP has been blocked due to suspicious activity',
            'RATE_LIMITED': 'Too many requests. Please slow down',
            'WAF_BLOCKED': 'Request blocked by security filter',
            'BOT_DETECTED': 'Automated access detected'
        };
        return messages[reason] || 'Access denied';
    }

    cleanup() {
        const now = Date.now();
        const ttl = (this.config.IP_CACHE_TTL || 300) * 1000;

        for (const [key, data] of this.ipCache) {
            if (data.lastUpdate && now - data.lastUpdate > ttl) {
                this.ipCache.delete(key);
            }
        }

        for (const [key, bucket] of this.rateLimitStore) {
            if (now - bucket.lastRefill > 300000) {
                this.rateLimitStore.delete(key);
            }
        }
    }
}

// ═══════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════
let instance = null;

module.exports = {
    init: (config) => {
        instance = new SecurityMiddleware(config);
        return instance;
    },
    getInstance: () => instance,
    SecurityMiddleware
};
