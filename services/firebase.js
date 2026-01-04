// ═══════════════════════════════════════════════════════════════════
// 🔥 services/firebase.js - Firebase Service
// ═══════════════════════════════════════════════════════════════════

const axios = require('axios');
const config = require('../config');

// ═══════════════════════════════════════════════════════════════════
// Firebase Configuration
// ═══════════════════════════════════════════════════════════════════
const FIREBASE_URL = config.FIREBASE_URL || process.env.FIREBASE_URL;
const FB_KEY = config.FIREBASE_KEY || process.env.FIREBASE_KEY;

// التحقق من الإعدادات
if (!FIREBASE_URL) {
    console.error('❌ FIREBASE_URL is not configured!');
}
if (!FB_KEY) {
    console.error('❌ FIREBASE_KEY is not configured!');
}

// ═══════════════════════════════════════════════════════════════════
// Axios Instance with Timeout & Error Handling
// ═══════════════════════════════════════════════════════════════════
const firebase = axios.create({
    baseURL: FIREBASE_URL,
    timeout: 30000, // 30 ثانية
    headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    },
    // مهم: لا ترمي خطأ للاستجابات غير 2xx
    validateStatus: function (status) {
        return status >= 200 && status < 500;
    }
});

// ═══════════════════════════════════════════════════════════════════
// Request Interceptor - للتشخيص
// ═══════════════════════════════════════════════════════════════════
firebase.interceptors.request.use(
    (config) => {
        // إضافة timestamp للتشخيص
        config.metadata = { startTime: Date.now() };
        return config;
    },
    (error) => {
        console.error('❌ Firebase Request Error:', error.message);
        return Promise.reject(error);
    }
);

// ═══════════════════════════════════════════════════════════════════
// Response Interceptor - للتشخيص والتعامل مع الأخطاء
// ═══════════════════════════════════════════════════════════════════
firebase.interceptors.response.use(
    (response) => {
        const duration = Date.now() - response.config.metadata.startTime;
        
        // تسجيل الطلبات البطيئة
        if (duration > 5000) {
            console.warn(`⚠️ Slow Firebase request: ${response.config.url} took ${duration}ms`);
        }
        
        return response;
    },
    (error) => {
        // التعامل مع أخطاء الشبكة
        if (error.code === 'ECONNABORTED') {
            console.error('❌ Firebase Timeout Error');
        } else if (error.code === 'ENOTFOUND') {
            console.error('❌ Firebase DNS Error - Check FIREBASE_URL');
        } else if (error.response) {
            console.error(`❌ Firebase Error ${error.response.status}:`, error.response.data);
        } else {
            console.error('❌ Firebase Network Error:', error.message);
        }
        
        return Promise.reject(error);
    }
);

// ═══════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════

/**
 * قراءة بيانات من Firebase
 * @param {string} path - المسار (مثل: users.json)
 */
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

/**
 * كتابة بيانات في Firebase (استبدال كامل)
 * @param {string} path - المسار
 * @param {object} data - البيانات
 */
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

/**
 * تحديث بيانات في Firebase (دمج)
 * @param {string} path - المسار
 * @param {object} data - البيانات للتحديث
 */
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

/**
 * حذف بيانات من Firebase
 * @param {string} path - المسار
 */
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

/**
 * إضافة عنصر جديد (Push)
 * @param {string} path - المسار
 * @param {object} data - البيانات
 */
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

/**
 * اختبار الاتصال بـ Firebase
 */
async function testConnection() {
    try {
        const response = await firebase.get(`/.json?auth=${FB_KEY}&shallow=true`);
        console.log('✅ Firebase connection successful');
        return true;
    } catch (error) {
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
    
    // Helper functions
    firebaseGet,
    firebaseSet,
    firebasePatch,
    firebaseDelete,
    firebasePost,
    testConnection
};
