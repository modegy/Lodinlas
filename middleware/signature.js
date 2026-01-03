// middleware/signature.js
const crypto = require('crypto');
const config = require('../config');
const { firebase, FB_KEY } = require('../services/firebase');

// Cache for Sub Admin Keys
const keyCache = new Map();
const usedNonces = new Map();

// Derive signing key from API Key
const deriveSigningKey = (apiKey) => {
    return crypto.createHmac('sha256', config.SIGNING_SALT)
        .update(apiKey)
        .digest('hex');
};

// Get Sub Admin Signing Secret
const getSubAdminSigningSecret = async (clientId, currentPath) => {
    try {
        // 1. Check cache first
        const cachedKey = keyCache.get(clientId);
        if (cachedKey && cachedKey.signing_secret) {
            const cacheAge = Date.now() - cachedKey.cache_time;
            if (cacheAge < 5 * 60 * 1000) { // 5 minutes cache
                console.log(`🔑 [SIGNATURE] Cache hit for ${clientId.substring(0, 8)}...`);
                return cachedKey.signing_secret;
            }
        }

        // 2. For verify-key endpoint: use derived key
        if (currentPath === '/api/sub/verify-key') {
            console.log(`🔑 [SIGNATURE] Using derived key for verify-key`);
            return deriveSigningKey(clientId);
        }

        // 3. Fetch from Firebase
        console.log(`🔍 [SIGNATURE] Fetching from Firebase for ${clientId.substring(0, 8)}...`);
        
        const response = await firebase.get(`api_keys.json?orderBy="api_key"&equalTo="${clientId}"&auth=${FB_KEY}`);
        const keys = response.data || {};
        
        if (Object.keys(keys).length === 0) {
            console.warn(`⚠️ [SIGNATURE] Key not found in Firebase`);
            return deriveSigningKey(clientId);
        }
        
        const keyId = Object.keys(keys)[0];
        const foundKey = keys[keyId];
        
        if (foundKey && foundKey.signing_secret) {
            // Cache the result
            keyCache.set(clientId, {
                ...foundKey,
                keyId,
                cache_time: Date.now()
            });
            return foundKey.signing_secret;
        }
        
        // 4. Fallback: use derived key
        console.warn(`⚠️ [SIGNATURE] Using fallback derived key for ${clientId.substring(0, 8)}...`);
        return deriveSigningKey(clientId);
        
    } catch (error) {
        console.error('❌ [SIGNATURE] Error fetching signing secret:', error.message);
        return deriveSigningKey(clientId);
    }
};

// Verify Signature Middleware
const verifySignature = async (req, res, next) => {
    try {
        console.log('🔐 [SIGNATURE] Verifying:', req.method, req.path);
        
        const path = req.path;
        const needsSignature = config.SIGNED_ENDPOINTS.some(endpoint => {
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

        const signature = req.headers['x-api-signature'];
        const timestamp = req.headers['x-timestamp'];
        const nonce = req.headers['x-nonce'];
        const clientId = req.headers['x-client-id'] || req.headers['x-api-key'];

        if (!signature || !timestamp || !nonce || !clientId) {
            console.log('❌ [SIGNATURE] Missing required headers');
            return res.status(401).json({
                success: false,
                error: 'Missing signature headers',
                code: 401
            });
        }

        // Validate timestamp
        const now = Date.now();
        let requestTime = parseInt(timestamp);
        
        if (isNaN(requestTime)) {
            console.log('❌ [SIGNATURE] Invalid timestamp format');
            return res.status(401).json({
                success: false,
                error: 'Invalid timestamp format',
                code: 401
            });
        }
        
        // Convert seconds to milliseconds if needed
        if (requestTime < 1000000000000) { // Before 2001-09-09
            requestTime = requestTime * 1000;
        }
        
        const timeDiff = Math.abs(now - requestTime);
        const MAX_AGE = 5 * 60 * 1000; // 5 minutes
        
        if (timeDiff > MAX_AGE) {
            console.warn(`❌ [SIGNATURE] Request too old: ${timeDiff}ms`);
            return res.status(401).json({
                success: false,
                error: 'Request too old',
                code: 401
            });
        }

        // Prevent replay attacks
        const nonceKey = `${clientId}:${nonce}:${timestamp}`;
        if (usedNonces.has(nonceKey)) {
            console.warn(`❌ [SIGNATURE] Nonce reused: ${nonce}`);
            return res.status(401).json({
                success: false,
                error: 'Nonce already used',
                code: 401
            });
        }

        // Get secret key
        let secretKey;
        
        if (clientId === config.APP_API_KEY) {
            secretKey = config.APP_SIGNING_SECRET;
        } else if (clientId === config.MASTER_ADMIN_TOKEN) {
            secretKey = config.MASTER_SIGNING_SECRET;
        } else {
            secretKey = await getSubAdminSigningSecret(clientId, path);
        }

        if (!secretKey) {
            console.log('❌ [SIGNATURE] No secret key found');
            return res.status(401).json({
                success: false,
                error: 'Authentication failed',
                code: 401
            });
        }

        // Build string to sign
        let stringToSign = '';
        
        if (req.method === 'GET' || req.method === 'DELETE') {
            stringToSign = `${req.method.toUpperCase()}:${req.path}`;
            
            if (Object.keys(req.query).length > 0) {
                const sortedParams = Object.keys(req.query)
                    .sort()
                    .map(key => {
                        const value = req.query[key];
                        return `${key}=${Array.isArray(value) ? value.join(',') : value}`;
                    })
                    .join('&');
                stringToSign = `${req.method.toUpperCase()}:${req.path}?${sortedParams}`;
            }
        } else {
            const bodyString = req.rawBody || JSON.stringify(req.body || {});
            const bodyHash = crypto.createHash('sha256')
                .update(bodyString)
                .digest('hex');
            stringToSign = `${req.method.toUpperCase()}:${req.path}|${bodyHash}`;
        }
        
        // Add timestamp and nonce
        stringToSign += `|${timestamp}|${nonce}`;
        
        // Add secret key
        stringToSign += `|${secretKey}`;

        // Calculate expected signature
        const expectedSignature = crypto.createHmac('sha256', secretKey)
            .update(stringToSign)
            .digest('base64')
            .replace(/=+$/, '');

        // Use constant-time comparison to prevent timing attacks
        const isValid = crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expectedSignature)
        );

        if (!isValid) {
            console.error(`❌ [SIGNATURE] Invalid signature for ${req.method} ${req.path}`);
            console.error(`   Expected: ${expectedSignature.substring(0, 20)}...`);
            console.error(`   Received: ${signature.substring(0, 20)}...`);
            
            return res.status(401).json({
                success: false,
                error: 'Invalid signature',
                code: 401
            });
        }

        // Store used nonce (expire after MAX_AGE * 2)
        usedNonces.set(nonceKey, now);
        
        console.log(`✅ [SIGNATURE] Valid for ${req.method} ${req.path}`);
        next();

    } catch (error) {
        console.error('❌ [SIGNATURE] Error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Signature verification failed',
            code: 500
        });
    }
};

// Generate signature for outgoing requests
const generateSignature = (method, path, body, timestamp, nonce, clientId, secretKey) => {
    let stringToSign = '';
    
    if (method === 'GET' || method === 'DELETE') {
        stringToSign = `${method.toUpperCase()}:${path}`;
    } else {
        const bodyString = JSON.stringify(body || {});
        const bodyHash = crypto.createHash('sha256')
            .update(bodyString)
            .digest('hex');
        stringToSign = `${method.toUpperCase()}:${path}|${bodyHash}`;
    }
    
    stringToSign += `|${timestamp}|${nonce}|${secretKey}`;
    
    return crypto.createHmac('sha256', secretKey)
        .update(stringToSign)
        .digest('base64')
        .replace(/=+$/, '');
};

// Cleanup caches periodically
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    
    // Clean key cache
    for (const [apiKey, keyData] of keyCache.entries()) {
        if (now - keyData.cache_time > 30 * 60 * 1000) { // 30 minutes
            keyCache.delete(apiKey);
            cleaned++;
        }
    }
    
    // Clean used nonces
    for (const [nonceKey, timestamp] of usedNonces.entries()) {
        if (now - timestamp > 10 * 60 * 1000) { // 10 minutes
            usedNonces.delete(nonceKey);
            cleaned++;
        }
    }
    
    if (cleaned > 0) {
        console.log(`[SIGNATURE_CLEANUP] Cleaned ${cleaned} entries`);
    }
}, 5 * 60 * 1000); // Run every 5 minutes

module.exports = {
    verifySignature,
    deriveSigningKey,
    getSubAdminSigningSecret,
    generateSignature,
    keyCache
};
