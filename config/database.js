const axios = require('axios');
require('dotenv').config();

// ═══════════════════════════════════════════
// التحقق من المتغيرات البيئية
// ═══════════════════════════════════════════
if (!process.env.FIREBASE_URL || !process.env.FIREBASE_KEY) {
    console.error('❌ FIREBASE_URL أو FIREBASE_KEY غير موجود');
    process.exit(1);
}

// ═══════════════════════════════════════════
// Firebase Setup
// ═══════════════════════════════════════════
const firebase = axios.create({
    baseURL: process.env.FIREBASE_URL,
    timeout: 10000,
    headers: { 'Content-Type': 'application/json' }
});

const FB_KEY = process.env.FIREBASE_KEY;
const FB_URL = process.env.FIREBASE_URL;

module.exports = {
    firebase,
    FB_KEY,
    FB_URL
};
