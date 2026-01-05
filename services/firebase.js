// ═══════════════════════════════════════════════════════════════════
// 🔥 services/firebase.js - Firebase Service (Fixed)
// ═══════════════════════════════════════════════════════════════════

const axios = require('axios');
const config = require('../config');

// ═══════════════════════════════════════════════════════════════════
// Firebase Configuration
// ═══════════════════════════════════════════════════════════════════
const FIREBASE_URL = config.FIREBASE_URL || process.env.FIREBASE_URL;
const FB_KEY = config.FIREBASE_KEY || process.env.FIREBASE_KEY;

// ✅ Connection Status
let firebaseConnected = false;

if (!FIREBASE_URL) {
    console.error('❌ FIREBASE_URL is not configured!');
}
if (!FB_KEY) {
    console.error('❌ FIREBASE_KEY is not configured!');
}

// ═══════════════════════════════════════════════════════════════════
// Axios Instance
// ═══════════════════════════════════════════════════════════════════
const firebase = axios.create({
    baseURL: FIREBASE_URL,
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    },
    validateStatus: function (status) {
        return status >= 200 && status < 500;
    }
});

// ═══════════════════════════════════════════════════════════════════
// Interceptors
// ═══════════════════════════════════════════════════════════════════
firebase.interceptors.request.use(
    (config) => {
        config.metadata = { startTime: Date.now() };
        return config;
    },
    (error) => {
        console.error('❌ Firebase Request Error:', error.message);
        firebaseConnected = false;
        return Promise.reject(error);
    }
);

firebase.interceptors.response.use(
    (response) => {
        const duration = Date.now() - response.config.metadata.startTime;
        
        // ✅ Connection successful
        firebaseConnected = true;
        
        if (duration > 5000) {
            console.warn(`⚠️ Slow Firebase request: ${response.config.url} took ${duration}ms`);
        }
        
        return response;
    },
    (error) => {
        // ❌ Connection failed
        firebaseConnected = false;
        
        if (error.code === 'ECONNABORTED') {
            console.error('❌ Firebase Timeout Error');
        } else if (error.code === 'ENOTFOUND') {
            console.error('❌ Firebase DNS Error');
        } else if (error.response) {
            console.error(`❌ Firebase Error ${error.response.status}:`, error.response.data);
        } else {
            console.error('❌ Firebase Network Error:', error.message);
        }
        
        return Promise.reject(error);
    }
);

// ═══════════════════════════════════════════════════════════════════
// ✅ Connection Check Function
// ═══════════════════════════════════════════════════════════════════
function isFirebaseConnected() {
    return firebaseConnected;
}

function setFirebaseConnected(status) {
    firebaseConnected = status;
}

// ═══════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════
async function firebaseGet(path) {
    try {
        const url = path.includes('?') 
            ? `${path}&auth=${FB_KEY}` 
            : `${path}?auth=${FB_KEY}`;
        const response = await firebase.get(url);
        return response.data;
    } catch (error) {
        console.error(`Firebase GET error [${path}]:`, error.message);
        throw error;
    }
}

async function firebaseSet(path, data) {
    try {
        const url = path.includes('?') 
            ? `${path}&auth=${FB_KEY}` 
            : `${path}?auth=${FB_KEY}`;
        const response = await firebase.put(url, data);
        return response.data;
    } catch (error) {
        console.error(`Firebase SET error [${path}]:`, error.message);
        throw error;
    }
}

async function firebasePatch(path, data) {
    try {
        const url = path.includes('?') 
            ? `${path}&auth=${FB_KEY}` 
            : `${path}?auth=${FB_KEY}`;
        const response = await firebase.patch(url, data);
        return response.data;
    } catch (error) {
        console.error(`Firebase PATCH error [${path}]:`, error.message);
        throw error;
    }
}

async function firebaseDelete(path) {
    try {
        const url = path.includes('?') 
            ? `${path}&auth=${FB_KEY}` 
            : `${path}?auth=${FB_KEY}`;
        await firebase.delete(url);
        return true;
    } catch (error) {
        console.error(`Firebase DELETE error [${path}]:`, error.message);
        throw error;
    }
}

async function firebasePost(path, data) {
    try {
        const url = path.includes('?') 
            ? `${path}&auth=${FB_KEY}` 
            : `${path}?auth=${FB_KEY}`;
        const response = await firebase.post(url, data);
        return response.data;
    } catch (error) {
        console.error(`Firebase POST error [${path}]:`, error.message);
        throw error;
    }
}

async function testConnection() {
    try {
        const response = await firebase.get(`/.json?auth=${FB_KEY}&shallow=true`);
        firebaseConnected = true;
        console.log('✅ Firebase connection successful');
        return true;
    } catch (error) {
        firebaseConnected = false;
        console.error('❌ Firebase connection failed:', error.message);
        return false;
    }
}

// اختبار الاتصال عند بدء التشغيل
if (FIREBASE_URL && FB_KEY) {
    testConnection();
}

// ═══════════════════════════════════════════════════════════════════
// Exports
// ═══════════════════════════════════════════════════════════════════
module.exports = {
    firebase,
    FB_KEY,
    FIREBASE_URL,
    
    // ✅ Connection status
    isFirebaseConnected,
    setFirebaseConnected,
    
    // Helper functions
    firebaseGet,
    firebaseSet,
    firebasePatch,
    firebaseDelete,
    firebasePost,
    testConnection
};
