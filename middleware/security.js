'use strict';

const crypto = require('crypto');
const helmet = require('helmet');
const redis = require('redis');

class SecurityMiddleware {
    constructor(config) {
        this.config = config.SECURITY || {};
        this.ddosConfig = this.config.DDOS || {};
        this.bruteForceConfig = this.config.BRUTE_FORCE || {};
        this.wafConfig = this.config.WAF || {};
        
        // Statistics
        this.stats = {
            totalRequests: 0,
            blockedRequests: 0,
            wafBlocks: 0,
            rateLimitBlocks: 0,
            startTime: Date.now()
        };
        
        // Redis client
        this.client = redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
        this.client.on('error', (err) => console.error('Redis Client Error', err));
        
        // Periodic cleanup - increased interval to 5 minutes for better performance
        this.cleanupInterval = setInterval(() => this.cleanup(), 300000);
        
        console.log('🛡️ Security Middleware initialized');
        console.log(`   - Protection Level: ${this.config.PROTECTION_LEVEL || 'balanced'}`);
        console.log(`   - WAF: ${this.config.ENABLE_WAF !== false ? '✅' : '❌'}`);
        console.log(`   - Rate Limiting: ${this.config.ENABLE_RATE_LIMIT !== false ? '✅' : '❌'}`);
        console.log(`   - Bot Detection: ${this.config.ENABLE_BOT_DETECTION !== false ? '✅' : '❌'}`);
    }

    async init() {
        await this.client.connect();
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
                if (await this.isBlocked(ip)) {
                    this.stats.blockedRequests++;
                    return this.blockResponse(res, 'IP_BLOCKED', null, {
                        reason: 'Your IP has been temporarily blocked',
                        contact: this.config.APPEAL_CONTACT
                    });
                }

                // 2. DDoS Protection
                if (!await this.checkDDoS(ip)) {
                    this.stats.blockedRequests++;
                    return this.blockResponse(res, 'DDOS_DETECTED');
                }

                // 3. Rate Limiting
                if (this.config.ENABLE_RATE_LIMIT !== false) {
                    const rateLimitResult = await this.checkRateLimit(ip, req.path);
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
                        await this.recordViolation(ip, `WAF:${wafResult.reason}`);
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
                        await this.recordViolation(ip, 'HIGH_BOT_SCORE');
                    }
                }

                // 6. Add Security Headers (kept for custom headers; helmet handles others)
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
                return this.blockResponse(res, 'INTERNAL_ERROR');
            }
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // 🚫 DDoS PROTECTION
    // ═══════════════════════════════════════════════════════════════
    async checkDDoS(ip) {
        const now = Date.now();
        const windowMs = 60000;
        const maxRequests = this.ddosConfig.IP_RPS ? this.ddosConfig.IP_RPS * 60 : 
                           this.ddosConfig.MAX_REQUESTS_PER_MINUTE || 100;
        
        const key = `ddos:${ip}`;
        let dataStr = await this.client.get(key);
        let data;
        try {
            data = dataStr ? JSON.parse(dataStr) : { count: 0, windowStart: now };
        } catch (e) {
            console.error(`Error parsing DDoS data for ${ip}:`, e);
            data = { count: 0, windowStart: now };
        }
        
        if (now - data.windowStart > windowMs) {
            data = { count: 0, windowStart: now };
        }
        
        data.count++;
        await this.client.set(key, JSON.stringify(data), { EX: 120 }); // TTL 2 min
        
        if (data.count > maxRequests) {
            const blockDuration = this.ddosConfig.BLOCK_DURATION || 600000;
            await this.blockIP(ip, blockDuration);
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
    async checkRateLimit(ip, path) {
        const limitType = this.getLimitType(path);
        const limits = this.config.RATE_LIMITS?.[limitType] || { capacity: 100, refill: 10 };
        const key = `rate:${ip}:${limitType}`;
        const now = Date.now();

        let bucketStr = await this.client.get(key);
        let bucket;
        try {
            bucket = bucketStr ? JSON.parse(bucketStr) : { 
                tokens: limits.capacity, 
                lastRefill: now,
                totalRequests: 0
            };
        } catch (e) {
            console.error(`Error parsing rate limit data for ${ip}:${limitType}:`, e);
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
            await this.client.set(key, JSON.stringify(bucket), { EX: 300 }); // TTL 5 min
            return { 
                allowed: true, 
                remaining: Math.floor(bucket.tokens),
                limit: limits.capacity,
                type: limitType
            };
        }

        await this.client.set(key, JSON.stringify(bucket), { EX: 300 });
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

        const contentLength = parseInt(req.headers['content-length'] || '0', 10);
        const maxBodySize = this.wafConfig.MAX_BODY_SIZE || 1048576;
        if (contentLength > maxBodySize) {
            return { safe: false, reason: 'BODY_TOO_LARGE' };
        }

        // URL & Query Check
        let urlToCheck = '';
        try {
            urlToCheck = decodeURIComponent(req.url || '').toLowerCase();
        } catch (e) {
            console.warn(`⚠️ URL decode error: ${e.message}`);
            return { safe: false, reason: 'INVALID_URL_ENCODING' };
        }
        const queryString = JSON.stringify(req.query || {}).toLowerCase();
        
        const urlAttacks = [
            { pattern: /\.\.[\/\\]/, name: 'PATH_TRAVERSAL' },
            { pattern: /%2e%2e[%2f%5c]/i, name: 'PATH_TRAVERSAL_ENCODED' },
            { pattern: /[;|`]\s*\w+/, name: 'COMMAND_INJECTION' },
            { pattern: /\$\([^)]+\)/, name: 'COMMAND_SUBSTITUTION' },
            { pattern: /%0[ad]/i, name: 'CRLF_INJECTION' },
            { pattern: /\/(\.env|\.git|\.htaccess|wp-config|phpinfo)/i, name: 'SENSITIVE_FILE_ACCESS' },
            { pattern: /\/(etc\/passwd|proc\/self|windows\/system32)/i, name: 'SYSTEM_FILE_ACCESS' },
            { pattern: /^(file|gopher|dict|php|data):\/\//i, name: 'PROTOCOL_ATTACK' },
            { pattern: /%25%35%33%25%34%33%25%34%43/i, name: 'ENCODED_SQLI' }
        ];

        for (const attack of urlAttacks) {
            if (attack.pattern.test(urlToCheck) || attack.pattern.test(queryString)) {
                console.warn(`🚨 WAF [URL]: ${attack.name} | IP: ${crypto.createHash('sha256').update(req.clientIP || req.ip).digest('hex')} | Path: ${currentPath}`);
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
            { pattern: /\${[^}]+}/g, name: 'SSTI_DOLLAR' },
            { pattern: /%27%20or%201%3D1/i, name: 'ENCODED_SQLI' }
        ];

        for (const attack of bodyAttacks) {
            if (attack.pattern.test(bodyToCheck)) {
                console.warn(`🚨 WAF [BODY]: ${attack.name} | IP: ${crypto.createHash('sha256').update(req.clientIP || req.ip).digest('hex')} | Path: ${currentPath}`);
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
                console.warn(`🚨 WAF [HEADER]: ${attack.name} | IP: ${crypto.createHash('sha256').update(req.clientIP || req.ip).digest('hex')}`);
                return { safe: false, reason: attack.name };
            }
        }

        return { safe: true };
    }

    sanitizeBodyForCheck(body) {
        if (!body) return '';
        let bodyStr = '';
        try {
            bodyStr = typeof body === 'object' ? JSON.stringify(body) : body.toString();
        } catch (e) {
            console.warn(`⚠️ Body stringify error: ${e.message}`);
            return '';
        }
        
        const sensitiveFields = [
            'password', 'passwd', 'pass', 'pwd',
            'token', 'access_token', 'refresh_token', 'session_token',
            'api_key', 'apikey', 'api_secret', 'secret',
            'credential', 'auth', 'authorization',
            'private_key', 'secret_key'
        ];
        
        let cleanBody = bodyStr;
        for (const field of sensitiveFields) {
            const regex = new RegExp(`"${field}":"[^"]*"`, 'gi');
            cleanBody = cleanBody.replace(regex, `"${field}":"[REDACTED]"`);
        }
        
        return cleanBody.toLowerCase();
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
        return async (req, res, next) => {
            const ip = this.getClientIP(req);
            const maxAttempts = this.bruteForceConfig.MAX_ATTEMPTS || 5;
            const lockoutDuration = this.bruteForceConfig.LOCKOUT_DURATION || 15 * 60 * 1000;

            const key = `brute:login:${ip}`;
            let attemptStr = await this.client.get(key);
            let attempt;
            try {
                attempt = attemptStr ? JSON.parse(attemptStr) : { count: 0, lastAttempt: Date.now() };
            } catch (e) {
                console.error(`Error parsing brute force data for ${ip}:`, e);
                attempt = { count: 0, lastAttempt: Date.now() };
            }

            if (Date.now() - attempt.lastAttempt > lockoutDuration) {
                attempt.count = 0;
            }

            if (attempt.count >= maxAttempts) {
                const remainingTime = Math.ceil((lockoutDuration - (Date.now() - attempt.lastAttempt)) / 60000);
                return res.status(429).json({
                    success: false,
                    error: `Too many attempts. Try again in ${remainingTime} minutes`
                });
            }

            attempt.lastAttempt = Date.now(); // Update lastAttempt even on check
            await this.client.set(key, JSON.stringify(attempt), { EX: Math.ceil(lockoutDuration / 1000) });

            next();
        };
    }

    async recordLoginAttempt(ip, success) {
        const key = `brute:login:${ip}`;
        let attemptStr = await this.client.get(key);
        let attempt;
        try {
            attempt = attemptStr ? JSON.parse(attemptStr) : { count: 0, lastAttempt: Date.now() };
        } catch (e) {
            console.error(`Error parsing brute force data for ${ip}:`, e);
            attempt = { count: 0, lastAttempt: Date.now() };
        }
        
        if (success) {
            await this.client.del(key);
        } else {
            attempt.count++;
            attempt.lastAttempt = Date.now();
            await this.client.set(key, JSON.stringify(attempt));
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 🔧 UTILITIES
    // ═══════════════════════════════════════════════════════════════
    getClientIP(req) {
        return req.headers['cf-connecting-ip'] ||
               req.headers['x-real-ip'] ||
               req.headers['x-forwarded-for']?.split(',').map(ip => ip.trim())[0] ||
               req.socket?.remoteAddress ||
               req.ip ||
               'unknown';
    }

    async isBlocked(ip) {
        return (await this.client.exists(`block:${ip}`)) === 1;
    }

    async blockIP(ip, duration = 600000) {
        await this.client.set(`block:${ip}`, 'blocked', { EX: Math.ceil(duration / 1000) });
        console.warn(`🚫 IP Blocked: ${crypto.createHash('sha256').update(ip).digest('hex')} for ${duration/1000}s`);
    }

    async unblockIP(ip) {
        const deleted = await this.client.del(`block:${ip}`);
        if (deleted) {
            console.log(`✅ IP Manually Unblocked: ${crypto.createHash('sha256').update(ip).digest('hex')}`);
        }
        return deleted;
    }

    async recordViolation(ip, reason) {
        const key = `violation:${ip}`;
        let cacheStr = await this.client.get(key);
        let cache;
        try {
            cache = cacheStr ? JSON.parse(cacheStr) : { 
                violations: 0, 
                reasons: [],
                firstSeen: Date.now()
            };
        } catch (e) {
            console.error(`Error parsing violation data for ${ip}:`, e);
            cache = { 
                violations: 0, 
                reasons: [],
                firstSeen: Date.now()
            };
        }
        
        cache.violations++;
        cache.lastViolation = Date.now();
        cache.reasons.push({ reason, time: Date.now() });
        
        if (cache.reasons.length > 10) {
            cache.reasons = cache.reasons.slice(-10);
        }
        
        await this.client.set(key, JSON.stringify(cache), { EX: 3600 });

        const softBlockViolations = this.config.SOFT_BLOCK_VIOLATIONS || 3;
        if (cache.violations >= softBlockViolations) {
            const blockDuration = this.ddosConfig.BLOCK_DURATION || 600000;
            await this.blockIP(ip, blockDuration);
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
            'BOT_DETECTED': 403,
            'INTERNAL_ERROR': 500
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
            'BOT_DETECTED': 'Automated access detected and blocked',
            'INTERNAL_ERROR': 'Internal server error. Please try again later.'
        };
        return messages[reason] || 'Access denied';
    }

    async cleanup() {
        const now = Date.now();
        const cacheTTL = (this.config.IP_CACHE_TTL || 300) * 1000;
        let cleaned = 0;

        // Helper function to scan and clean keys
        const scanAndClean = async (pattern, checkFn) => {
            for await (const key of this.client.scanIterator({ MATCH: pattern })) {
                let dataStr = await this.client.get(key);
                let data;
                try {
                    data = dataStr ? JSON.parse(dataStr) : null;
                } catch (e) {
                    await this.client.del(key);
                    cleaned++;
                    continue;
                }
                if (data && checkFn(data, now)) {
                    await this.client.del(key);
                    cleaned++;
                }
            }
        };

        // Cleanup violations
        await scanAndClean('violation:*', (data, now) => data.lastViolation && now - data.lastViolation > cacheTTL);

        // Cleanup rates
        await scanAndClean('rate:*', (data, now) => now - data.lastRefill > 300000);

        // Cleanup ddos
        await scanAndClean('ddos:*', (data, now) => now - data.windowStart > 120000);

        // Cleanup brute
        await scanAndClean('brute:*', (data, now) => now - data.lastAttempt > 60 * 60 * 1000);

        if (cleaned > 0) {
            console.log(`🧹 Security cleanup: ${cleaned} entries removed`);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 📊 STATS & MONITORING
    // ═══════════════════════════════════════════════════════════════
    async getStats() {
        const uptime = Date.now() - this.stats.startTime;
        const blockedIPs = [];
        for await (const key of this.client.scanIterator({ MATCH: 'block:*' })) {
            blockedIPs.push(key);
        }
        return {
            ...this.stats,
            uptime: Math.floor(uptime / 1000),
            blockedIPs: blockedIPs.length,
            blockedIPsList: blockedIPs.slice(0, 20).map(k => crypto.createHash('sha256').update(k.split(':')[1]).digest('hex')),
            blockRate: this.stats.totalRequests > 0 
                ? ((this.stats.blockedRequests / this.stats.totalRequests) * 100).toFixed(2) + '%'
                : '0%'
        };
    }

    destroy() {
        // WARNING: Call this only during graceful shutdown, not while handling requests
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        this.client.quit();
    }
}

// ═══════════════════════════════════════════════════════════════════
// 📦 HELMET CONFIG
// ═══════════════════════════════════════════════════════════════════
const helmetConfig = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // حسب الحاجة
            // أضف directives أخرى
        }
    },
    crossOriginEmbedderPolicy: { policy: 'require-corp' }
});

// ═══════════════════════════════════════════════════════════════════
// 📦 EXPORT
// ═══════════════════════════════════════════════════════════════════
let instance = null;

module.exports = {
    helmetConfig,
    init: async (config) => {
        if (!instance) {
            instance = new SecurityMiddleware(config);
            await instance.init();
        }
        return instance;
    },
    getInstance: () => instance,
    SecurityMiddleware
};
