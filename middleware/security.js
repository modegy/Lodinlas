// middleware/security.js - Security Middleware v14.1
'use strict';

const crypto = require('crypto');
const helmet = require('helmet');

class SecurityMiddleware {
    constructor(config) {
        this.config = config.SECURITY || {};
        this.ddosConfig = config.SECURITY?.DDOS || config.DDOS || {};
        this.bruteForceConfig = config.SECURITY?.BRUTE_FORCE || {};
        this.wafConfig = config.SECURITY?.WAF || {};
        
        // Data stores
        this.ipCache = new Map();
        this.rateLimitStore = new Map();
        this.blockedIPs = new Set();
        this.requestCounts = new Map();
        this.loginAttempts = new Map();
        
        // Statistics
        this.stats = {
            totalRequests: 0,
            blockedRequests: 0,
            wafBlocks: 0,
            rateLimitBlocks: 0,
            startTime: Date.now()
        };
        
        // Periodic cleanup
        this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
        
        console.log('🛡️ Security Middleware initialized');
        console.log(`   - Protection Level: ${this.config.PROTECTION_LEVEL || 'balanced'}`);
        console.log(`   - WAF: ${this.config.ENABLE_WAF !== false ? '✅' : '❌'}`);
        console.log(`   - Rate Limiting: ${this.config.ENABLE_RATE_LIMIT !== false ? '✅' : '❌'}`);
        console.log(`   - Bot Detection: ${this.config.ENABLE_BOT_DETECTION !== false ? '✅' : '❌'}`);
    }

    // ═══════════════════════════════════════════════════════════════
    // 🛡️ MAIN MIDDLEWARE
    // ═══════════════════════════════════════════════════════════════
    middleware() {
        return async (req, res, next) => {
            const startTime = Date.now();
            
            try {
                const ip = this.getClientIP(req);
                req.clientIP = ip;
                req.securityContext = { ip, startTime };
                
                this.stats.totalRequests++;

                // 1. Check blocked IP
                if (this.isBlocked(ip)) {
                    this.stats.blockedRequests++;
                    return this.blockResponse(res, 'IP_BLOCKED', null, {
                        reason: 'Your IP has been temporarily blocked',
                        contact: this.config.APPEAL_CONTACT
                    });
                }

                // 2. DDoS Protection
                if (!this.checkDDoS(ip)) {
                    this.stats.blockedRequests++;
                    return this.blockResponse(res, 'DDOS_DETECTED');
                }

                // 3. Rate Limiting
                if (this.config.ENABLE_RATE_LIMIT !== false) {
                    const rateLimitResult = this.checkRateLimit(ip, req.path);
                    if (!rateLimitResult.allowed) {
                        this.stats.rateLimitBlocks++;
                        return this.blockResponse(res, 'RATE_LIMITED', rateLimitResult.retryAfter);
                    }
                    req.securityContext.rateLimit = rateLimitResult;
                }

                // 4. WAF Protection
                if (this.config.ENABLE_WAF !== false) {
                    const wafResult = this.wafCheck(req);
                    if (!wafResult.safe) {
                        this.stats.wafBlocks++;
                        this.recordViolation(ip, `WAF:${wafResult.reason}`);
                        return this.blockResponse(res, 'WAF_BLOCKED', null, {
                            reason: wafResult.reason
                        });
                    }
                }

                // 5. Bot Detection
                if (this.config.ENABLE_BOT_DETECTION !== false) {
                    const botScore = this.detectBot(req);
                    req.securityContext.botScore = botScore;
                    
                    if (botScore > (this.config.ANOMALY_THRESHOLD || 70)) {
                        this.recordViolation(ip, 'HIGH_BOT_SCORE');
                    }
                }

                // 6. Add Security Headers
                this.setSecurityHeaders(res);

                // 7. Log slow requests
                res.on('finish', () => {
                    const duration = Date.now() - startTime;
                    if (duration > 5000) {
                        console.warn(`⚠️ Slow request: ${req.method} ${req.path} - ${duration}ms`);
                    }
                });

                next();
                
            } catch (err) {
                console.error('[Security] Middleware error:', err.message);
                next();
            }
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // 🚫 DDoS PROTECTION
    // ═══════════════════════════════════════════════════════════════
    checkDDoS(ip) {
        const now = Date.now();
        const windowMs = 60000;
        const maxRequests = this.ddosConfig.IP_RPS ? this.ddosConfig.IP_RPS * 60 : 
                           this.ddosConfig.MAX_REQUESTS_PER_MINUTE || 100;
        
        const key = `ddos:${ip}`;
        let data = this.requestCounts.get(key) || { count: 0, windowStart: now };
        
        if (now - data.windowStart > windowMs) {
            data = { count: 0, windowStart: now };
        }
        
        data.count++;
        this.requestCounts.set(key, data);
        
        if (data.count > maxRequests) {
            const blockDuration = this.ddosConfig.BLOCK_DURATION || 600000;
            this.blockIP(ip, blockDuration);
            console.warn(`🚨 DDoS detected from ${ip}: ${data.count} requests/min`);
            return false;
        }
        
        const warningThreshold = this.ddosConfig.WARNING_THRESHOLD || (maxRequests * 0.6);
        if (data.count === Math.floor(warningThreshold)) {
            console.warn(`⚠️ High request rate from ${ip}: ${data.count}/${maxRequests}`);
        }
        
        return true;
    }

    // ═══════════════════════════════════════════════════════════════
    // ⏱️ RATE LIMITING (Token Bucket Algorithm)
    // ═══════════════════════════════════════════════════════════════
    checkRateLimit(ip, path) {
        const limitType = this.getLimitType(path);
        const limits = this.config.RATE_LIMITS?.[limitType] || { capacity: 100, refill: 10 };
        const key = `rate:${ip}:${limitType}`;
        const now = Date.now();

        let bucket = this.rateLimitStore.get(key);
        
        if (!bucket) {
            bucket = { 
                tokens: limits.capacity, 
                lastRefill: now,
                totalRequests: 0
            };
        }

        const elapsedSeconds = (now - bucket.lastRefill) / 1000;
        const refillAmount = elapsedSeconds * limits.refill;
        bucket.tokens = Math.min(limits.capacity, bucket.tokens + refillAmount);
        bucket.lastRefill = now;
        bucket.totalRequests++;

        if (bucket.tokens >= 1) {
            bucket.tokens -= 1;
            this.rateLimitStore.set(key, bucket);
            return { 
                allowed: true, 
                remaining: Math.floor(bucket.tokens),
                limit: limits.capacity,
                type: limitType
            };
        }

        this.rateLimitStore.set(key, bucket);
        const retryAfter = Math.ceil((1 - bucket.tokens) / limits.refill);
        
        return { 
            allowed: false, 
            retryAfter,
            limit: limits.capacity,
            type: limitType
        };
    }

    getLimitType(path) {
        if (path.includes('/auth') || path.includes('/login') || path.includes('/verifyAccount')) {
            return 'AUTH';
        }
        if (path.includes('/admin')) return 'ADMIN';
        if (path.includes('/api')) return 'API';
        return 'GLOBAL';
    }

    // ═══════════════════════════════════════════════════════════════
    // 🔥 WAF (Web Application Firewall)
    // ═══════════════════════════════════════════════════════════════
    wafCheck(req) {
        const currentPath = req.path || req.url?.split('?')[0] || '';
        
        const maxUrlLength = this.wafConfig.MAX_URL_LENGTH || 2048;
        if (req.url && req.url.length > maxUrlLength) {
            return { safe: false, reason: 'URL_TOO_LONG' };
        }

        const contentLength = parseInt(req.headers['content-length'] || 0);
        const maxBodySize = this.wafConfig.MAX_BODY_SIZE || 1048576;
        if (contentLength > maxBodySize) {
            return { safe: false, reason: 'BODY_TOO_LARGE' };
        }

        // URL & Query Check
        const urlToCheck = decodeURIComponent(req.url || '').toLowerCase();
        const queryString = JSON.stringify(req.query || {}).toLowerCase();
        
        const urlAttacks = [
            { pattern: /\.\.[\/\\]/, name: 'PATH_TRAVERSAL' },
            { pattern: /%2e%2e[%2f%5c]/i, name: 'PATH_TRAVERSAL_ENCODED' },
            { pattern: /[;|`]\s*\w+/, name: 'COMMAND_INJECTION' },
            { pattern: /\$\([^)]+\)/, name: 'COMMAND_SUBSTITUTION' },
            { pattern: /%0[ad]/i, name: 'CRLF_INJECTION' },
            { pattern: /\/(\.env|\.git|\.htaccess|wp-config|phpinfo)/i, name: 'SENSITIVE_FILE_ACCESS' },
            { pattern: /\/(etc\/passwd|proc\/self|windows\/system32)/i, name: 'SYSTEM_FILE_ACCESS' },
            { pattern: /^(file|gopher|dict|php|data):\/\//i, name: 'PROTOCOL_ATTACK' }
        ];

        for (const attack of urlAttacks) {
            if (attack.pattern.test(urlToCheck) || attack.pattern.test(queryString)) {
                console.warn(`🚨 WAF [URL]: ${attack.name} | IP: ${req.clientIP || req.ip} | Path: ${currentPath}`);
                return { safe: false, reason: attack.name };
            }
        }

        // Body Check
        const bodyToCheck = this.sanitizeBodyForCheck(req.body);
        
        const bodyAttacks = [
            { pattern: /<script[^>]*>[\s\S]*?<\/script>/gi, name: 'XSS_SCRIPT' },
            { pattern: /javascript\s*:/gi, name: 'XSS_PROTOCOL' },
            { pattern: /on(load|error|click|mouse|focus|blur)\s*=/gi, name: 'XSS_EVENT' },
            { pattern: /'\s*(or|and)\s*'?\d*\s*=\s*'?\d*/gi, name: 'SQL_INJECTION' },
            { pattern: /union\s+(all\s+)?select\s+/gi, name: 'SQL_UNION' },
            { pattern: /;\s*(drop|delete|truncate|update|insert)\s+/gi, name: 'SQL_DESTRUCTIVE' },
            { pattern: /'\s*;\s*--/g, name: 'SQL_COMMENT' },
            { pattern: /\$where\s*:/gi, name: 'NOSQL_WHERE' },
            { pattern: /\{\s*['"]\$[a-z]+['"]\s*:/gi, name: 'NOSQL_OPERATOR' },
            { pattern: /\b(eval|exec|system|passthru|shell_exec|popen)\s*\(/gi, name: 'CODE_EXEC' },
            { pattern: /<!ENTITY\s+/gi, name: 'XXE_ENTITY' },
            { pattern: /<!\[CDATA\[/gi, name: 'XXE_CDATA' },
            { pattern: /\{\{.*\}\}/g, name: 'SSTI_DOUBLE_BRACE' },
            { pattern: /<%.*%>/g, name: 'SSTI_ERB' },
            { pattern: /\${[^}]+}/g, name: 'SSTI_DOLLAR' }
        ];

        for (const attack of bodyAttacks) {
            if (attack.pattern.test(bodyToCheck)) {
                console.warn(`🚨 WAF [BODY]: ${attack.name} | IP: ${req.clientIP || req.ip} | Path: ${currentPath}`);
                return { safe: false, reason: attack.name };
            }
        }

        // Header Check
        const userAgent = (req.headers['user-agent'] || '').toLowerCase();
        const referer = (req.headers['referer'] || '').toLowerCase();
        
        const headerAttacks = [
            { pattern: /<script/gi, name: 'XSS_IN_HEADER' },
            { pattern: /\.\.[\/\\]/g, name: 'PATH_TRAVERSAL_HEADER' }
        ];
        
        const headersToCheck = userAgent + ' ' + referer;
        for (const attack of headerAttacks) {
            if (attack.pattern.test(headersToCheck)) {
                console.warn(`🚨 WAF [HEADER]: ${attack.name} | IP: ${req.clientIP || req.ip}`);
                return { safe: false, reason: attack.name };
            }
        }

        return { safe: true };
    }

    sanitizeBodyForCheck(body) {
        if (!body || typeof body !== 'object') return '';
        
        const sensitiveFields = [
            'password', 'passwd', 'pass', 'pwd',
            'token', 'access_token', 'refresh_token', 'session_token',
            'api_key', 'apikey', 'api_secret', 'secret',
            'credential', 'auth', 'authorization',
            'private_key', 'secret_key'
        ];
        
        const cleanBody = { ...body };
        
        for (const field of sensitiveFields) {
            for (const key of Object.keys(cleanBody)) {
                if (key.toLowerCase().includes(field)) {
                    delete cleanBody[key];
                }
            }
        }
        
        return JSON.stringify(cleanBody).toLowerCase();
    }

    // ═══════════════════════════════════════════════════════════════
    // 🤖 BOT DETECTION
    // ═══════════════════════════════════════════════════════════════
    detectBot(req) {
        let score = 0;
        const ua = req.headers['user-agent'] || '';

        if (!ua) {
            score += 30;
        } else {
            const suspiciousUA = [
                /curl/i, /wget/i, /python/i, /httpie/i,
                /postman/i, /insomnia/i,
                /bot/i, /spider/i, /crawler/i, /scraper/i,
                /headless/i, /phantom/i, /selenium/i
            ];
            
            for (const pattern of suspiciousUA) {
                if (pattern.test(ua)) {
                    score += 20;
                    break;
                }
            }
            
            if (ua.length < 20) score += 15;
        }

        if (!req.headers['accept-language']) score += 15;
        if (!req.headers['accept']) score += 10;
        if (!req.headers['accept-encoding']) score += 5;

        const xff = req.headers['x-forwarded-for'];
        if (xff && xff.split(',').length > 5) {
            score += 20;
        }

        const path = req.path || '';
        const suspiciousPaths = [
            /\.env/i, /\.git/i, /\.htaccess/i,
            /wp-admin/i, /wp-login/i, /phpmyadmin/i,
            /admin\.php/i, /shell/i, /backdoor/i
        ];
        
        for (const pattern of suspiciousPaths) {
            if (pattern.test(path)) {
                score += 25;
                break;
            }
        }

        return Math.min(score, 100);
    }

    // ═══════════════════════════════════════════════════════════════
    // 🔐 BRUTE FORCE PROTECTION
    // ═══════════════════════════════════════════════════════════════
    bruteForceProtection() {
        return (req, res, next) => {
            const ip = this.getClientIP(req);
            const maxAttempts = this.bruteForceConfig.MAX_ATTEMPTS || 5;
            const lockoutDuration = this.bruteForceConfig.LOCKOUT_DURATION || 15 * 60 * 1000;

            if (!this.loginAttempts.has(ip)) {
                this.loginAttempts.set(ip, { count: 0, lastAttempt: Date.now() });
            }

            const attempt = this.loginAttempts.get(ip);

            if (Date.now() - attempt.lastAttempt > lockoutDuration) {
                attempt.count = 0;
            }

            if (attempt.count >= maxAttempts) {
                const remainingTime = Math.ceil((lockoutDuration - (Date.now() - attempt.lastAttempt)) / 1000 / 60);
                return res.status(429).json({
                    success: false,
                    error: `Too many attempts. Try again in ${remainingTime} minutes`
                });
            }

            next();
        };
    }

    recordLoginAttempt(ip, success) {
        const attempt = this.loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
        
        if (success) {
            this.loginAttempts.delete(ip);
        } else {
            attempt.count++;
            attempt.lastAttempt = Date.now();
            this.loginAttempts.set(ip, attempt);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 🔧 UTILITIES
    // ═══════════════════════════════════════════════════════════════
    getClientIP(req) {
        return req.headers['cf-connecting-ip'] ||
               req.headers['x-real-ip'] ||
               req.headers['x-forwarded-for']?.split(',')[0].trim() ||
               req.socket?.remoteAddress ||
               req.ip ||
               'unknown';
    }

    isBlocked(ip) {
        return this.blockedIPs.has(ip);
    }

    blockIP(ip, duration = 600000) {
        this.blockedIPs.add(ip);
        console.warn(`🚫 IP Blocked: ${ip} for ${duration/1000}s`);
        
        if (duration > 0) {
            setTimeout(() => {
                this.blockedIPs.delete(ip);
                console.log(`✅ IP Unblocked: ${ip}`);
            }, duration);
        }
    }

    unblockIP(ip) {
        const deleted = this.blockedIPs.delete(ip);
        if (deleted) {
            console.log(`✅ IP Manually Unblocked: ${ip}`);
        }
        return deleted;
    }

    recordViolation(ip, reason) {
        const cache = this.ipCache.get(ip) || { 
            violations: 0, 
            reasons: [],
            firstSeen: Date.now()
        };
        
        cache.violations++;
        cache.lastViolation = Date.now();
        cache.reasons.push({ reason, time: Date.now() });
        
        if (cache.reasons.length > 10) {
            cache.reasons = cache.reasons.slice(-10);
        }
        
        this.ipCache.set(ip, cache);

        const softBlockViolations = this.config.SOFT_BLOCK_VIOLATIONS || 3;
        if (cache.violations >= softBlockViolations) {
            const blockDuration = this.ddosConfig.BLOCK_DURATION || 600000;
            this.blockIP(ip, blockDuration);
        }
    }

    setSecurityHeaders(res) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('X-Download-Options', 'noopen');
        res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    }

    blockResponse(res, reason, retryAfter = null, details = null) {
        const statusCodes = {
            'IP_BLOCKED': 403,
            'DDOS_DETECTED': 429,
            'RATE_LIMITED': 429,
            'WAF_BLOCKED': 403,
            'BOT_DETECTED': 403
        };
        
        const status = statusCodes[reason] || 403;
        
        if (retryAfter) {
            res.setHeader('Retry-After', retryAfter);
        }

        return res.status(status).json({
            success: false,
            error: true,
            code: reason,
            message: this.getBlockMessage(reason),
            details: details,
            retryAfter: retryAfter,
            timestamp: new Date().toISOString()
        });
    }

    getBlockMessage(reason) {
        const messages = {
            'IP_BLOCKED': 'Your IP has been temporarily blocked due to suspicious activity',
            'DDOS_DETECTED': 'Too many requests detected. Please slow down.',
            'RATE_LIMITED': 'Rate limit exceeded. Please wait before making more requests.',
            'WAF_BLOCKED': 'Request blocked by security filter',
            'BOT_DETECTED': 'Automated access detected and blocked'
        };
        return messages[reason] || 'Access denied';
    }

    cleanup() {
        const now = Date.now();
        const cacheTTL = (this.config.IP_CACHE_TTL || 300) * 1000;
        let cleaned = 0;

        for (const [ip, data] of this.ipCache) {
            if (data.lastViolation && now - data.lastViolation > cacheTTL) {
                this.ipCache.delete(ip);
                cleaned++;
            }
        }

        for (const [key, bucket] of this.rateLimitStore) {
            if (now - bucket.lastRefill > 300000) {
                this.rateLimitStore.delete(key);
                cleaned++;
            }
        }

        for (const [key, data] of this.requestCounts) {
            if (now - data.windowStart > 120000) {
                this.requestCounts.delete(key);
                cleaned++;
            }
        }

        for (const [ip, attempt] of this.loginAttempts) {
            if (now - attempt.lastAttempt > 60 * 60 * 1000) {
                this.loginAttempts.delete(ip);
                cleaned++;
            }
        }

        if (cleaned > 0) {
            console.log(`🧹 Security cleanup: ${cleaned} entries removed`);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 📊 STATS & MONITORING
    // ═══════════════════════════════════════════════════════════════
    getStats() {
        const uptime = Date.now() - this.stats.startTime;
        return {
            ...this.stats,
            uptime: Math.floor(uptime / 1000),
            blockedIPs: this.blockedIPs.size,
            blockedIPsList: Array.from(this.blockedIPs).slice(0, 20),
            cachedIPs: this.ipCache.size,
            activeBuckets: this.rateLimitStore.size,
            blockRate: this.stats.totalRequests > 0 
                ? ((this.stats.blockedRequests / this.stats.totalRequests) * 100).toFixed(2) + '%'
                : '0%'
        };
    }

    destroy() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 📦 HELMET CONFIG
// ═══════════════════════════════════════════════════════════════════
const helmetConfig = helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
});
// ═══════════════════════════════════════════════════════════════════
// 🚦 SIMPLE RATE LIMITER (For compatibility)
// ═══════════════════════════════════════════════════════════════════
const simpleRateLimiter = new Map();

const apiLimiter = (req, res, next) => {
    const ip = req.headers['cf-connecting-ip'] ||
               req.headers['x-real-ip'] ||
               req.headers['x-forwarded-for']?.split(',')[0].trim() ||
               req.socket?.remoteAddress ||
               req.ip ||
               'unknown';
    
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxRequests = 100;
    
    const key = `limiter:${ip}`;
    let data = simpleRateLimiter.get(key) || { count: 0, windowStart: now };
    
    if (now - data.windowStart > windowMs) {
        data = { count: 0, windowStart: now };
    }
    
    data.count++;
    simpleRateLimiter.set(key, data);
    
    if (data.count > maxRequests) {
        return res.status(429).json({
            success: false,
            error: 'Too many requests, please try again later',
            code: 429
        });
    }
    
    next();
};

// Cleanup every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [key, data] of simpleRateLimiter) {
        if (now - data.windowStart > 30 * 60 * 1000) {
            simpleRateLimiter.delete(key);
        }
    }
}, 5 * 60 * 1000);
// ═══════════════════════════════════════════════════════════════════
// 📦 EXPORT
// ═══════════════════════════════════════════════════════════════════
let instance = null;

module.exports = {
    helmetConfig,
    apiLimiter,  // أضف هذا السطر
    init: (config) => {
        if (!instance) {
            instance = new SecurityMiddleware(config);
        }
        return instance;
    },
    getInstance: () => instance,
    SecurityMiddleware
};

