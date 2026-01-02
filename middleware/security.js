// middleware/security.js
const config = require('../config');

// Storage
const requestTracker = new Map();
const blockedIPs = new Set();
const loginAttempts = new Map();

// Get Client IP
const getClientIP = (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
};

// DDoS Protection
const ddosProtection = (req, res, next) => {
    const ip = getClientIP(req);
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
        if (now - tracker.blockedAt < config.DDOS.BLOCK_DURATION) {
            return res.status(429).json({ 
                error: 'Blocked. Try again later.',
                retry_after: Math.ceil((config.DDOS.BLOCK_DURATION - (now - tracker.blockedAt)) / 1000)
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
    
    if (tracker.count > config.DDOS.WARNING_THRESHOLD && tracker.count <= config.DDOS.MAX_REQUESTS_PER_MINUTE) {
        console.warn(`⚠️ [WARNING] High traffic from: ${ip} (${tracker.count} req/min)`);
    }
    
    if (tracker.count > config.DDOS.MAX_REQUESTS_PER_MINUTE) {
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

// Suspicious Request Filter
const suspiciousRequestFilter = (req, res, next) => {
    const ip = getClientIP(req);
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
    
    // SQL Injection
    if (/union.*select|select.*from|drop.*table|insert.*into/i.test(fullUrl)) {
        blockedIPs.add(ip);
        console.error(`⛔ [SQL INJECTION] from: ${ip}`);
        return res.status(403).end();
    }
    
    // XSS
    if (/<script|javascript:|on\w+\s*=/i.test(fullUrl)) {
        console.error(`⛔ [XSS] from: ${ip}`);
        return res.status(403).end();
    }
    
    next();
};

// Attack Logger
const attackLogger = (req, res, next) => {
    const ip = getClientIP(req);
    const sensitiveEndpoints = ['/api/admin', '/api/sub'];
    
    if (sensitiveEndpoints.some(ep => req.path.startsWith(ep))) {
        console.log(`📋 [AUDIT] ${req.method} ${req.path} | IP: ${ip}`);
    }
    
    next();
};

// Brute Force Protection
const bruteForceProtection = (req, res, next) => {
    const ip = getClientIP(req);
    
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

// Cleanup Functions
const cleanupTrackers = () => {
    const now = Date.now();
    for (const [ip, data] of requestTracker.entries()) {
        if (now - data.firstRequest > 3600000) {
            requestTracker.delete(ip);
        }
    }
    console.log(`📊 [STATS] Tracking: ${requestTracker.size} IPs | Blocked: ${blockedIPs.size}`);
};

const cleanupLoginAttempts = () => {
    const now = Date.now();
    for (const [ip, attempt] of loginAttempts.entries()) {
        if (now - attempt.lastAttempt > 60 * 60 * 1000) {
            loginAttempts.delete(ip);
        }
    }
};

// Start cleanup intervals
setInterval(cleanupTrackers, 3600000);
setInterval(cleanupLoginAttempts, 3600000);

module.exports = {
    ddosProtection,
    suspiciousRequestFilter,
    attackLogger,
    bruteForceProtection,
    blockedIPs,
    requestTracker,
    loginAttempts,
    getClientIP
};
