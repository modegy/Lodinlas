// services/firebase.js - Firebase REST API Service (مُصلح)
const axios = require('axios');
const config = require('../config');

// ═══════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════
const FIREBASE_URL = config.FIREBASE_URL || process.env.FIREBASE_URL;
const FB_KEY = config.FIREBASE_KEY || process.env.FIREBASE_KEY;

if (!FIREBASE_URL) {
    console.error('❌ FIREBASE_URL is not configured!');
}

if (!FB_KEY) {
    console.error('❌ FIREBASE_KEY is not configured!');
}

// ═══════════════════════════════════════════
// AXIOS INSTANCE WITH RETRY
// ═══════════════════════════════════════════
const firebase = axios.create({
    baseURL: FIREBASE_URL,
    timeout: 30000, // 30 ثانية
    headers: {
        'Content-Type': 'application/json'
    }
});

// ═══════════════════════════════════════════
// REQUEST INTERCEPTOR
// ═══════════════════════════════════════════
firebase.interceptors.request.use(
    (config) => {
        // إضافة timestamp للتتبع
        config.metadata = { startTime: Date.now() };
        return config;
    },
    (error) => {
        console.error('Firebase request error:', error.message);
        return Promise.reject(error);
    }
);

// ═══════════════════════════════════════════
// RESPONSE INTERCEPTOR WITH RETRY
// ═══════════════════════════════════════════
firebase.interceptors.response.use(
    (response) => {
        // حساب وقت الاستجابة
        const duration = Date.now() - response.config.metadata.startTime;
        if (duration > 5000) {
            console.warn(`⚠️ Slow Firebase response: ${duration}ms for ${response.config.url}`);
        }
        return response;
    },
    async (error) => {
        const config = error.config;
        
        // إعداد عداد المحاولات
        config.__retryCount = config.__retryCount || 0;
        const maxRetries = 3;
        
        // التحقق من نوع الخطأ
        const isRetryable = 
            error.code === 'ETIMEDOUT' ||
            error.code === 'ECONNRESET' ||
            error.code === 'ECONNABORTED' ||
            error.code === 'ENOTFOUND' ||
            (error.response && error.response.status >= 500);
        
        if (isRetryable && config.__retryCount < maxRetries) {
            config.__retryCount++;
            
            // انتظار تصاعدي قبل إعادة المحاولة
            const delay = Math.pow(2, config.__retryCount) * 1000;
            console.log(`🔄 Retrying Firebase request (${config.__retryCount}/${maxRetries}) after ${delay}ms...`);
            
            await new Promise(resolve => setTimeout(resolve, delay));
            
            return firebase(config);
        }
        
        // تسجيل الخطأ
        const errorMessage = error.response?.data?.error || error.message;
        console.error(`❌ Firebase error: ${errorMessage}`);
        
        return Promise.reject(error);
    }
);

// ═══════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════

/**
 * فحص اتصال Firebase
 */
async function testConnection() {
    try {
        const response = await firebase.get(`/.json?auth=${FB_KEY}&shallow=true`);
        console.log('✅ Firebase connection successful');
        return { success: true, data: response.data };
    } catch (error) {
        console.error('❌ Firebase connection failed:', error.message);
        return { success: false, error: error.message };
    }
}

/**
 * قراءة بيانات مع معالجة الأخطاء
 */
async function getData(path) {
    try {
        const url = path.includes('?') 
            ? `${path}&auth=${FB_KEY}` 
            : `${path}.json?auth=${FB_KEY}`;
        const response = await firebase.get(url);
        return { success: true, data: response.data };
    } catch (error) {
        return { success: false, error: error.message, data: null };
    }
}

/**
 * كتابة بيانات مع معالجة الأخطاء
 */
async function setData(path, data) {
    try {
        const response = await firebase.put(`${path}.json?auth=${FB_KEY}`, data);
        return { success: true, data: response.data };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * تحديث بيانات مع معالجة الأخطاء
 */
async function updateData(path, data) {
    try {
        const response = await firebase.patch(`${path}.json?auth=${FB_KEY}`, data);
        return { success: true, data: response.data };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * حذف بيانات مع معالجة الأخطاء
 */
async function deleteData(path) {
    try {
        await firebase.delete(`${path}.json?auth=${FB_KEY}`);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// ═══════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════
module.exports = {
    firebase,
    FB_KEY,
    FIREBASE_URL,
    
    // Helper functions
    testConnection,
    getData,
    setData,
    updateData,
    deleteData
};
