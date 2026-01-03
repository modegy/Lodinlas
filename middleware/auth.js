// middleware/auth.js
const crypto = require('crypto');
const config = require('../config');
const { firebase, FB_KEY, isFirebaseConnected } = require('../services/firebase');

// Admin Sessions Storage
const adminSessions = new Map();

// Global cache for sub-admin keys
const subAdminCache = new Map();
const failedAttempts = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const FAILED_ATTEMPT_WINDOW = 60 * 60 * 1000; // 1 hour
const MAX_FAILED_ATTEMPTS = 10;

// Retry configuration
const RETRY_CONFIG = {
  maxRetries: 3,
  baseDelay: 2000,
  maxDelay: 8000
};

// Exponential backoff retry helper
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

// Check Firebase connection
const checkFirebaseConnection = async () => {
  try {
    if (!isFirebaseConnected()) {
      throw new Error('Firebase not connected');
    }
    
    // Test connection with a simple read
    const testResponse = await firebase.get(`.json?auth=${FB_KEY}&limitToFirst=1`);
    return true;
  } catch (error) {
    console.error('❌ Firebase connection check failed:', error.message);
    return false;
  }
};

// App Authentication
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
  
  if (apiKey === config.APP_API_KEY) {
    logAuthAttempt(req, true);
    return next();
  }
  
  logAuthAttempt(req, false, 'Invalid API Key');
  res.status(401).json({ 
    success: false, 
    error: 'Invalid API Key', 
    code: 'INVALID_API_KEY'
  });
};

// Admin Authentication
const authAdmin = (req, res, next) => {
  const sessionToken = req.headers['x-session-token'];
  
  if (!sessionToken) {
    logAuthAttempt(req, false, 'Session token missing');
    return res.status(401).json({ 
      success: false, 
      error: 'Session token required', 
      code: 'MISSING_SESSION_TOKEN'
    });
  }
  
  // Validate token format
  if (!/^[a-zA-Z0-9\-_]{20,}$/.test(sessionToken)) {
    logAuthAttempt(req, false, 'Invalid token format');
    return res.status(401).json({ 
      success: false, 
      error: 'Invalid token format', 
      code: 'INVALID_TOKEN_FORMAT'
    });
  }
  
  // Check master token
  if (config.MASTER_ADMIN_TOKEN && sessionToken === config.MASTER_ADMIN_TOKEN) {
    logAuthAttempt(req, true, 'Master token used');
    req.adminUser = 'master_owner';
    req.isMasterAdmin = true;
    return next();
  }
  
  const session = adminSessions.get(sessionToken);
  
  if (!session) {
    logAuthAttempt(req, false, 'Session not found');
    return res.status(401).json({ 
      success: false, 
      error: 'Invalid or expired session', 
      code: 'INVALID_SESSION'
    });
  }
  
  if (Date.now() - session.createdAt > config.SESSION.EXPIRY) {
    adminSessions.delete(sessionToken);
    logAuthAttempt(req, false, 'Session expired');
    return res.status(401).json({ 
      success: false, 
      error: 'Session expired', 
      code: 'SESSION_EXPIRED'
    });
  }
  
  // Update last activity
  session.lastActivity = Date.now();
  adminSessions.set(sessionToken, session);
  
  req.adminUser = session.username;
  req.sessionId = sessionToken;
  next();
};

// Sub Admin Authentication
const authSubAdmin = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    const deviceFingerprint = req.headers['x-device-fingerprint'];
    
    if (!apiKey) {
      logAuthAttempt(req, false, 'API key missing');
      return res.status(401).json({ 
        success: false, 
        error: 'API key required',
        code: 'MISSING_API_KEY'
      });
    }
    
    // Check rate limiting
    if (isRateLimited(apiKey, req.ip)) {
      logAuthAttempt(req, false, 'Rate limited');
      return res.status(429).json({ 
        success: false, 
        error: 'Too many requests. Please try again later.',
        code: 'RATE_LIMITED'
      });
    }
    
    // Check cache first
    const cached = subAdminCache.get(apiKey);
    if (cached && cached.device === deviceFingerprint) {
      if (isKeyValid(cached)) {
        // Update last used
        cached.last_used = Date.now();
        subAdminCache.set(apiKey, cached);
        
        req.subAdminKey = cached;
        req.subAdminKeyId = cached.keyId;
        logAuthAttempt(req, true, 'Cache hit');
        return next();
      } else {
        subAdminCache.delete(apiKey);
      }
    }
    
    // Check Firebase connection
    const isConnected = await checkFirebaseConnection();
    if (!isConnected) {
      logAuthAttempt(req, false, 'Firebase not connected');
      return res.status(503).json({ 
        success: false, 
        error: 'Service temporarily unavailable',
        code: 'SERVICE_UNAVAILABLE'
      });
    }
    
    // Fetch from Firebase with retry
    const operation = async () => {
      const response = await firebase.get(`api_keys.json?auth=${FB_KEY}&orderBy="api_key"&equalTo="${apiKey}"`);
      return response.data || {};
    };
    
    const keys = await retryWithBackoff(() => operation(), 'authSubAdmin');
    
    if (Object.keys(keys).length === 0) {
      recordFailedAttempt(apiKey, req.ip);
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
    const validationError = validateKey(foundKey, deviceFingerprint);
    if (validationError) {
      recordFailedAttempt(apiKey, req.ip);
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
      device: deviceFingerprint,
      last_used: Date.now(),
      cache_time: Date.now(),
      ip: req.ip
    };
    
    // Update cache
    subAdminCache.set(apiKey, keyData);
    
    req.subAdminKey = keyData;
    req.subAdminKeyId = keyId;
    logAuthAttempt(req, true, 'Firebase validation');
    next();
    
  } catch (error) {
    console.error('❌ Auth Sub Admin error:', error.message);
    logAuthAttempt(req, false, `Server error: ${error.message}`);
    
    // If Firebase is down, check if we have a valid cached key
    const apiKey = req.headers['x-api-key'];
    const cached = subAdminCache.get(apiKey);
    
    if (cached && isKeyValid(cached)) {
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

// Key validation helper
const validateKey = (keyData, deviceFingerprint) => {
  if (!keyData.is_active) {
    return 'Key is inactive';
  }
  
  if (keyData.expiry_timestamp) {
    const expiryTime = parseInt(keyData.expiry_timestamp);
    if (isNaN(expiryTime) || expiryTime <= 0) {
      return 'Invalid expiry configuration';
    }
    
    if (Date.now() > expiryTime) {
      return 'Key expired';
    }
  }
  
  if (keyData.bound_device && keyData.bound_device !== deviceFingerprint) {
    return 'Key is bound to another device';
  }
  
  if (keyData.ip_whitelist && keyData.ip_whitelist.length > 0) {
    const clientIp = req?.ip;
    if (clientIp && !keyData.ip_whitelist.includes(clientIp)) {
      return 'IP not authorized';
    }
  }
  
  return null;
};

// Check if cached key is valid
const isKeyValid = (cachedKey) => {
  if (!cachedKey || !cachedKey.is_active) return false;
  
  if (cachedKey.expiry_timestamp && Date.now() > cachedKey.expiry_timestamp) {
    return false;
  }
  
  // Cache validity: 5 minutes
  if (Date.now() - cachedKey.cache_time > CACHE_TTL) {
    return false;
  }
  
  return true;
};

// Rate limiting check
const isRateLimited = (apiKey, ip) => {
  const key = `${apiKey || ip}`;
  const attempts = failedAttempts.get(key) || [];
  const now = Date.now();
  
  // Clean old attempts
  const recentAttempts = attempts.filter(time => now - time < FAILED_ATTEMPT_WINDOW);
  
  if (recentAttempts.length >= MAX_FAILED_ATTEMPTS) {
    return true;
  }
  
  return false;
};

// Record failed attempt
const recordFailedAttempt = (apiKey, ip) => {
  const key = `${apiKey || ip}`;
  const now = Date.now();
  const attempts = failedAttempts.get(key) || [];
  attempts.push(now);
  
  // Keep only recent attempts
  const recentAttempts = attempts.filter(time => now - time < FAILED_ATTEMPT_WINDOW);
  failedAttempts.set(key, recentAttempts);
};

// Permission Check
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
    
    // Check daily limit for add operations
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
    }
    
    next();
  };
};

// Ownership Check
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
    const isConnected = await checkFirebaseConnection();
    if (!isConnected) {
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
    if (req.adminUser === 'master_owner' && req.isMasterAdmin) {
      req.targetUser = user;
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

// Authentication logging
const logAuthAttempt = (req, success, reason = '') => {
  const logEntry = {
    timestamp: new Date().toISOString(),
    ip: req.ip || req.connection.remoteAddress,
    method: req.method,
    path: req.path,
    success,
    reason,
    userAgent: req.get('User-Agent') || 'Unknown',
    apiKeyPrefix: req.headers['x-api-key'] ? '***' + req.headers['x-api-key'].slice(-4) : 'None'
  };
  
  const logLevel = success ? 'INFO' : 'WARN';
  console.log(`[AUTH_${logLevel}] ${JSON.stringify(logEntry)}`);
  
  // Store failed attempts for rate limiting
  if (!success && reason !== 'Cache hit') {
    const key = `${req.ip}-${req.headers['x-api-key']}`;
    recordFailedAttempt(req.headers['x-api-key'], req.ip);
    
    // Check for brute force
    const attempts = failedAttempts.get(key) || [];
    if (attempts.length >= MAX_FAILED_ATTEMPTS) {
      console.warn(`[SECURITY] Brute force detected from ${req.ip}`);
    }
  }
};

// Create admin session
const createAdminSession = (username) => {
  const sessionToken = crypto.randomBytes(32).toString('hex');
  const session = {
    username,
    createdAt: Date.now(),
    lastActivity: Date.now()
  };
  
  adminSessions.set(sessionToken, session);
  return sessionToken;
};

// Invalidate admin session
const invalidateAdminSession = (sessionToken) => {
  return adminSessions.delete(sessionToken);
};

// Session cleanup
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  
  // Clean admin sessions
  for (const [token, session] of adminSessions.entries()) {
    if (now - session.lastActivity > config.SESSION.EXPIRY) {
      adminSessions.delete(token);
      cleaned++;
    }
  }
  
  // Clean sub-admin cache
  for (const [apiKey, keyData] of subAdminCache.entries()) {
    if (now - keyData.cache_time > CACHE_TTL) {
      subAdminCache.delete(apiKey);
      cleaned++;
    }
  }
  
  // Clean failed attempts
  for (const [key, attempts] of failedAttempts.entries()) {
    const recentAttempts = attempts.filter(time => now - time < FAILED_ATTEMPT_WINDOW);
    if (recentAttempts.length === 0) {
      failedAttempts.delete(key);
      cleaned++;
    } else {
      failedAttempts.set(key, recentAttempts);
    }
  }
  
  if (cleaned > 0) {
    console.log(`[CLEANUP] Cleaned ${cleaned} expired entries`);
  }
}, 60 * 1000); // Run every minute

module.exports = {
  authApp,
  authAdmin,
  authSubAdmin,
  checkSubAdminPermission,
  checkUserOwnership,
  adminSessions,
  subAdminCache,
  validateKey,
  logAuthAttempt,
  createAdminSession,
  invalidateAdminSession,
  checkFirebaseConnection
};
