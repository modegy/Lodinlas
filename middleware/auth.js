'use strict';

const crypto = require('crypto');
const config = require('../config');
const { firebase, FB_KEY, isFirebaseConnected } = require('../services/firebase');

/* ================================
   HARD REQUIREMENTS
================================ */
if (!config.FINGERPRINT_SECRET) {
  throw new Error('FINGERPRINT_SECRET is mandatory');
}

/* ================================
   CONSTANTS
================================ */
const CACHE_TTL = 5 * 60 * 1000;
const NONCE_TTL = 2 * 60 * 1000;
const CLOCK_SKEW = 30 * 1000;
const GLOBAL_RATE_WINDOW = 5 * 60 * 1000;
const GLOBAL_RATE_LIMIT = 300;

const MAX_CACHE_KEYS = 5000;
const MAX_NONCES = 15000;
const MAX_RATE_KEYS = 15000;

/* ================================
   STORAGE (BOUNDED)
================================ */
const adminSessions = new Map();
const subAdminCache = new Map();
const usedNonces = new Map();
const requestCounter = new Map();

/* ================================
   HELPERS
================================ */
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* Render-safe IP (trust proxy must be enabled in app.js) */
const getIP = req => req.ip || '0.0.0.0';

/* ===== Canonical JSON ===== */
const canonicalize = obj => {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(canonicalize);
  return Object.keys(obj).sort().reduce((r, k) => {
    r[k] = canonicalize(obj[k]);
    return r;
  }, {});
};

const canonicalBody = body =>
  JSON.stringify(canonicalize(body || {}));

/* ===== Timing Safe Compare ===== */
const safeEqual = (a, b) => {
  try {
    const ba = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
};

async function retry(fn, retries = 3) {
  let e;
  for (let i = 0; i < retries; i++) {
    try { return await fn(); }
    catch (err) { e = err; await sleep(300 * (2 ** i)); }
  }
  throw e;
}

/* ================================
   FIREBASE CHECK
================================ */
const checkFirebaseConnection = async () => {
  try {
    if (!isFirebaseConnected()) return false;
    await firebase.get(`.json?auth=${FB_KEY}&limitToFirst=1`);
    return true;
  } catch {
    return false;
  }
};

/* ================================
   APP AUTH
================================ */
const authApp = (req, res, next) => {
  if (req.headers['x-api-key'] !== config.APP_API_KEY) {
    return res.status(401).json({ success: false });
  }
  next();
};

/* ================================
   ADMIN AUTH (MASTER UNTOUCHED)
================================ */
const authAdmin = (req, res, next) => {
  const token = req.headers['x-session-token'];
  if (!token) return res.status(401).json({ success: false });

  /* ❌ DO NOT TOUCH */
  if (config.MASTER_ADMIN_TOKEN && token === config.MASTER_ADMIN_TOKEN) {
    req.adminUser = 'master_owner';
    req.isMasterAdmin = true;
    return next();
  }

  const s = adminSessions.get(token);
  if (!s || Date.now() - s.createdAt > config.SESSION.EXPIRY || s.ip !== req.ip) {
    adminSessions.delete(token);
    return res.status(401).json({ success: false });
  }

  s.lastActivity = Date.now();
  req.adminUser = s.username;
  next();
};

/* ================================
   GLOBAL RATE LIMIT (FIXED)
================================ */
const isRateLimited = req => {
  const k = `${getIP(req)}:${req.headers['x-api-key'] || 'none'}`;
  const now = Date.now();

  const arr = (requestCounter.get(k) || []).filter(t => now - t < GLOBAL_RATE_WINDOW);
  arr.push(now);
  requestCounter.set(k, arr);

  if (requestCounter.size > MAX_RATE_KEYS) {
    const oldest = requestCounter.keys().next().value;
    requestCounter.delete(oldest);
  }

  return arr.length > GLOBAL_RATE_LIMIT;
};

/* ================================
   SUB ADMIN AUTH (RENDER SAFE)
================================ */
const authSubAdmin = async (req, res, next) => {
  try {
    const ip = getIP(req);
    const apiKey = req.headers['x-api-key'];
    const nonce = req.headers['x-nonce'];
    const ts = Number(req.headers['x-timestamp']);
    const sig = req.headers['x-signature'];
    const ua = req.get('user-agent') || '';

    if (!apiKey || !nonce || !ts || !sig)
      return res.status(401).json({ success: false });

    if (isRateLimited(req))
      return res.status(429).json({ success: false });

    if (Math.abs(Date.now() - ts) > NONCE_TTL + CLOCK_SKEW)
      return res.status(401).json({ success: false });

    const fingerprint = crypto
      .createHmac('sha256', config.FINGERPRINT_SECRET)
      .update((req.headers['x-device-fingerprint'] || '') + ua)
      .digest('hex');

    const nonceKey = crypto
      .createHash('sha256')
      .update(apiKey + nonce + fingerprint)
      .digest('hex');

    if (usedNonces.has(nonceKey))
      return res.status(409).json({ success: false });

    usedNonces.set(nonceKey, Date.now());

    if (usedNonces.size > MAX_NONCES) {
      const oldest = usedNonces.keys().next().value;
      usedNonces.delete(oldest);
    }

    const cacheKey = `${apiKey}:${fingerprint}:${ip}`;
    const cached = subAdminCache.get(cacheKey);

    if (cached && isKeyValid(cached)) {
      cached.last_used = Date.now();
      req.subAdminKey = cached;
      req.subAdminKeyId = cached.keyId;
      return next();
    }

    if (!(await checkFirebaseConnection()))
      return res.status(503).json({ success: false });

    const safeKey = encodeURIComponent(apiKey);

    const keys = await retry(async () => {
      const r = await firebase.get(
        `api_keys.json?auth=${FB_KEY}&orderBy="api_key"&equalTo="${safeKey}"`
      );
      return r.data || {};
    });

    if (!Object.keys(keys).length)
      return res.status(401).json({ success: false });

    const keyId = Object.keys(keys)[0];
    const data = keys[keyId];

    if (!validateKey(data, fingerprint, ip))
      return res.status(403).json({ success: false });

    if (!data.secret)
      return res.status(500).json({ success: false });

    const bodyHash = crypto.createHash('sha256')
      .update(canonicalBody(req.body))
      .digest('hex');

    const expected = crypto.createHmac('sha256', data.secret)
      .update(req.method + req.path + ts + nonce + bodyHash)
      .digest('hex');

    if (!safeEqual(sig, expected))
      return res.status(401).json({ success: false });

    const prepared = {
      ...data,
      keyId,
      device: fingerprint,
      ip,
      cache_time: Date.now(),
      last_used: Date.now()
    };

    subAdminCache.set(cacheKey, prepared);

    if (subAdminCache.size > MAX_CACHE_KEYS)
      subAdminCache.delete(subAdminCache.keys().next().value);

    req.subAdminKey = prepared;
    req.subAdminKeyId = keyId;
    next();

  } catch {
    return res.status(401).json({ success: false });
  }
};

/* ================================
   VALIDATION
================================ */
const validateKey = (k, device, ip) => {
  if (!k.is_active) return false;
  if (k.expiry_timestamp && Date.now() > Number(k.expiry_timestamp)) return false;
  if (k.bound_device && k.bound_device !== device) return false;
  if (Array.isArray(k.ip_whitelist) && k.ip_whitelist.length &&
      !k.ip_whitelist.includes(ip)) return false;
  return true;
};

const isKeyValid = k =>
  k &&
  k.is_active &&
  (!k.expiry_timestamp || Date.now() <= k.expiry_timestamp) &&
  Date.now() - k.cache_time <= CACHE_TTL;

/* ================================
   CLEANUP
================================ */
setInterval(() => {
  const now = Date.now();

  for (const [k, v] of usedNonces)
    if (now - v > NONCE_TTL) usedNonces.delete(k);

  for (const [k, v] of subAdminCache)
    if (now - v.cache_time > CACHE_TTL) subAdminCache.delete(k);
}, 60000);

/* ================================
   EXPORTS
================================ */
module.exports = {
  authApp,
  authAdmin,   // MASTER ADMIN untouched ✔
  authSubAdmin,
  adminSessions,
  subAdminCache
};
