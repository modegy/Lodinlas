// services/firebase.js
const axios = require('axios');
const config = require('../config');

// Validate Firebase config
if (!config.FIREBASE_URL || !config.FIREBASE_KEY) {
    console.error('❌ FIREBASE_URL أو FIREBASE_KEY غير موجود');
    process.exit(1);
}

// Firebase HTTP Client
const firebase = axios.create({ 
    baseURL: config.FIREBASE_URL, 
    timeout: 10000, 
    headers: { 'Content-Type': 'application/json' } 
});

const FB_KEY = config.FIREBASE_KEY;
const FB_URL = config.FIREBASE_URL;

module.exports = {
    firebase,
    FB_KEY,
    FB_URL
};
