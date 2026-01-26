'use strict';

const express = require('express');
const crypto = require('crypto');
const { body, param, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const redis = require('redis');

const router = express.Router();

// ═══════════════════════════════════════════
// 📦 REDIS
// ═══════════════════════════════════════════
const client = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});

client.connect().catch(err => {
    console.error('Redis connection error:', err.message);
});

// ═══════════════════════════════════════════
// 🔥 FIREBASE ADMIN SDK
// ═══════════════════════════════════════════
const admin = require('firebase-admin');
const db = admin.database();

// ═══════════════════════════════════════════
// 📦 INTERNAL IMPORTS
// ═══════════════════════════════════════════
const { subAdminKeys } = require('../config/constants');
const { authSubAdmin, checkSubAdminPermission } = require('../middleware/auth');
const { verifySignature } = require('../middleware/signature');
const { apiLimiter } = require('../middleware/security');
const { hashPassword, formatDate } = require('../utils/helpers');

// ═══════════════════════════════════════════
// 🔑 VERIFY KEY
// ═══════════════════════════════════════════
router.post(
    '/verify-key',
    verifySignature,
    apiLimiter,
    [
        body('apiKey').isString().isLength({ min: 32, max: 128 }),
        body('deviceFingerprint').isString().isLength({ min: 10, max: 128 })
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ success: false, errors: errors.array() });
            }

            const { apiKey, deviceFingerprint } = req.body;

            // 🛡️ Brute force protection
            const bruteKey = `brute:verify:${apiKey}`;
            const attempts = parseInt(await client.get(bruteKey) || '0', 10);

            if (attempts >= 5) {
                return res.status(429).json({ success: false, error: 'Too many attempts' });
            }

            await client.set(bruteKey, attempts + 1, { EX: 3600 });

            const snapshot = await db.ref('api_keys')
                .orderByChild('api_key')
                .equalTo(apiKey)
                .limitToFirst(1)
                .once('value');

            if (!snapshot.exists()) {
                return res.status(401).json({ success: false, error: 'Invalid API key' });
            }

            const [[keyId, foundKey]] = Object.entries(snapshot.val());

            if (!foundKey.is_active) {
                return res.status(403).json({ success: false, error: 'Key is inactive' });
            }

            if (foundKey.expiry_timestamp && Date.now() > foundKey.expiry_timestamp) {
                return res.status(403).json({ success: false, error: 'Key expired' });
            }

            // 🔐 signing secret
            if (!foundKey.signing_secret) {
                const secret = `SS_${crypto.randomBytes(32).toString('hex')}`;
                await db.ref(`api_keys/${keyId}`).update({
                    signing_secret: secret,
                    last_secret_update: Date.now()
                });
                foundKey.signing_secret = secret;
            }

            // 📱 Device binding
            if (!foundKey.bound_device) {
                await db.ref(`api_keys/${keyId}`).update({
                    bound_device: deviceFingerprint
                });
            } else if (foundKey.bound_device !== deviceFingerprint) {
                return res.status(403).json({
                    success: false,
                    error: 'Key is bound to another device'
                });
            }

            await db.ref(`api_keys/${keyId}`).update({
                usage_count: admin.database.ServerValue.increment(1),
                last_used: Date.now()
            });

            // 🧠 Cache (بدون secrets)
            subAdminKeys.set(apiKey, {
                ...foundKey,
                keyId,
                device: deviceFingerprint,
                last_used: Date.now()
            });

            await client.del(bruteKey);

            return res.json({
                success: true,
                name: foundKey.admin_name,
                permission: foundKey.permission_level || 'view_only',
                key_id: keyId
            });

        } catch (err) {
            console.error('Verify key error:', err.message);
            res.status(500).json({ success: false, error: 'Server error' });
        }
    }
);

// ═══════════════════════════════════════════
// 📊 STATS
// ═══════════════════════════════════════════
router.get(
    '/stats',
    verifySignature,
    authSubAdmin,
    checkSubAdminPermission('view'),
    apiLimiter,
    async (req, res) => {
        try {
            const snapshot = await db.ref('users').once('value');
            const users = snapshot.val() || {};

            let totalUsers = 0;
            let activeUsers = 0;
            let expiredUsers = 0;
            const now = Date.now();

            for (const user of Object.values(users)) {
                if (user.created_by_key === req.subAdminKeyId) {
                    totalUsers++;
                    if (user.is_active !== false) activeUsers++;
                    if (user.subscription_end && user.subscription_end <= now) expiredUsers++;
                }
            }

            res.json({
                success: true,
                stats: { totalUsers, activeUsers, expiredUsers }
            });

        } catch (err) {
            console.error('Stats error:', err.message);
            res.status(500).json({ success: false, error: 'Failed to get stats' });
        }
    }
);

// ═══════════════════════════════════════════
// 👥 CREATE USER
// ═══════════════════════════════════════════
router.post(
    '/users',
    verifySignature,
    authSubAdmin,
    checkSubAdminPermission('add'),
    apiLimiter,
    [
        body('username').isLength({ min: 3, max: 50 }).matches(/^[a-zA-Z0-9_]+$/),
        body('password').isLength({ min: 8, max: 128 })
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ success: false, errors: errors.array() });
            }

            const { username, password, expiryMinutes } = req.body;

            const exists = await db.ref('users')
                .orderByChild('username')
                .equalTo(username)
                .once('value');

            if (exists.exists()) {
                return res.status(400).json({ success: false, error: 'Username taken' });
            }

            const expiryTimestamp = Date.now() + (expiryMinutes * 60 * 1000);

            const userId = uuidv4();
            await db.ref(`users/${userId}`).set({
                username,
                password_hash: await hashPassword(password), // ✅ FIXED
                is_active: true,
                subscription_end: expiryTimestamp,
                max_devices: 1,
                device_id: '',
                created_at: Date.now(),
                last_login: null,
                created_by_key: req.subAdminKeyId,
                created_by: req.subAdminKey.admin_name || 'sub_admin'
            });

            res.json({
                success: true,
                userId,
                expiry_date: formatDate(expiryTimestamp)
            });

        } catch (err) {
            console.error('Create user error:', err.message);
            res.status(500).json({ success: false, error: 'Failed to create user' });
        }
    }
);

module.exports = router;
