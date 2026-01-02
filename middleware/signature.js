// middleware/signature.js
const crypto = require('crypto');
const config = require('../config');
const { firebase, FB_KEY } = require('../services/firebase');

// Cache for Sub Admin Keys
const subAdminKeys = new Map();

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
        const cachedKey = subAdminKeys.get(clientId);
        if (cachedKey && cachedKey.signing_secret) {
            console.log(`🔑 [SIGNATURE] Found in cache: ${clientId.substring(0, 10)}...`);
            return cachedKey.signing_secret;
        }

        // 2. For verify-key: use derived key
        if (currentPath === '/api/sub/verify-key') {
            console.log(`🔑 [SIGNATURE] Using derived key for verify-key`);
            return deriveSigningKey(clientId);
        }

        // 3. Fetch from Firebase
        console.log(`🔍 [SIGNATURE] Fetching from Firebase...`);
        
        const response = await firebase.get(`api_keys.json?auth=${FB_KEY}`);
        const keys = response.data || {};
        
        let foundKey = null;
        for (const key of Object.values(keys)) {
            if (key.api_key === clientId) {
                foundKey = key;
                break;
            }
        }
        
        if (foundKey && foundKey.signing_secret) {
            subAdminKeys.set(clientId, foundKey);
            return foundKey.signing_secret;
        }
        
        // 4. Fallback: use derived key
        console.warn(`⚠️ [SIGNATURE] Using fallback derived key`);
        return deriveSigningKey(clientId);
        
    } catch (error) {
        console.error('❌ [SIGNATURE] Error:', error.message);
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
            console.log('❌ [SIGNATURE] Missing headers');
            return res.status(401).json({
                success: false,
                error: 'Missing signature headers',
                code: 401
            });
        }

        // Validate timestamp
        const now = Date.now();
        let requestTime = parseInt(timestamp);
        if (requestTime < 10000000000) {
            requestTime = requestTime * 1000;
        }
        
        const timeDiff = Math.abs(now - requestTime);
        if (isNaN(requestTime) || timeDiff > 300000) {
            console.warn(`❌ [SIGNATURE] Invalid timestamp: diff ${timeDiff}ms`);
            return res.status(401).json({
                success: false,
                error: 'Request timestamp is invalid or too old',
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
            return res.status(401).json({
                success: false,
                error: 'Authentication failed',
                code: 401
            });
        }

        // Build string to sign
        let stringToSign = '';
        
        if (req.method === 'GET' || req.method === 'DELETE') {
            stringToSign = `${req.method.toUpperCase()}:${req.path}|${timestamp}|${nonce}`;
            
            if (Object.keys(req.query).length > 0) {
                const sortedParams = Object.keys(req.query)
                    .sort()
                    .map(key => `${key}=${req.query[key]}`)
                    .join('&');
                stringToSign = `${req.method.toUpperCase()}:${req.path}?${sortedParams}|${timestamp}|${nonce}`;
            }
        } else {
            const bodyString = req.rawBody || '{}';
            const bodyHash = crypto.createHash('sha256')
                .update(bodyString)
                .digest('hex');
            stringToSign = `${req.method.toUpperCase()}:${req.path}|${bodyHash}|${timestamp}|${nonce}`;
        }

        stringToSign += `|${secretKey}`;

        // Calculate expected signature
        const expectedSignature = crypto.createHmac('sha256', secretKey)
            .update(stringToSign)
            .digest('base64')
            .replace(/=+$/, '');

        if (signature !== expectedSignature) {
            console.error(`❌ [SIGNATURE] Invalid`);
            return res.status(401).json({
                success: false,
                error: 'Invalid signature',
                code: 401
            });
        }

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

// Cleanup cache periodically
setInterval(() => {
    const now = Date.now();
    for (const [apiKey, keyData] of subAdminKeys.entries()) {
        if (now - (keyData.last_used || 0) > 30 * 60 * 1000) {
            subAdminKeys.delete(apiKey);
        }
    }
}, 15 * 60 * 1000);

module.exports = {
    verifySignature,
    deriveSigningKey,
    subAdminKeys
};
