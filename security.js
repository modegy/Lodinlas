const crypto = require('crypto');
const CryptoJS = require('crypto-js');

// يجب التأكد من تحميل .env في الملف الرئيسي
const HMAC_SECRET_KEY = process.env.HMAC_SECRET_KEY;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// ═══════════════════════════════════════════
// دوال التشفير وفك التشفير (AES-256)
// ═══════════════════════════════════════════

/**
 * فك تشفير البيانات باستخدام AES-256
 * @param {string} encryptedData البيانات المشفرة (Base64)
 * @returns {object|null} البيانات الأصلية ككائن JSON
 */
function decryptData(encryptedData) {
    try {
        const bytes = CryptoJS.AES.decrypt(encryptedData, ENCRYPTION_KEY);
        const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
        if (!decryptedText) return null;
        return JSON.parse(decryptedText);
    } catch (error) {
        console.error("Decryption Error:", error.message);
        return null;
    }
}

/**
 * تشفير البيانات باستخدام AES-256
 * @param {object} data البيانات المراد تشفيرها
 * @returns {string} البيانات المشفرة (Base64)
 */
function encryptData(data) {
    try {
        const jsonString = JSON.stringify(data);
        return CryptoJS.AES.encrypt(jsonString, ENCRYPTION_KEY).toString();
    } catch (error) {
        console.error("Encryption Error:", error.message);
        return null;
    }
}

// ═══════════════════════════════════════════
// دوال HMAC-SHA256
// ═══════════════════════════════════════════

/**
 * إنشاء توقيع HMAC-SHA256
 * @param {string} data البيانات (عادةً جسم الطلب)
 * @param {string} timestamp الطابع الزمني (بالثواني)
 * @returns {string} التوقيع المشفر بـ Base64
 */
function generateHMAC(data, timestamp) {
    // بناء السلسلة للتوقيع كما هو محدد في كود Smali: data|timestamp|SECRET_KEY
    const stringToSign = `${data}|${timestamp}|${HMAC_SECRET_KEY}`;
    
    const hmac = crypto.createHmac('sha256', HMAC_SECRET_KEY);
    hmac.update(stringToSign);
    
    // التوقيع المشفر بـ Base64
    return hmac.digest('base64').trim();
}

// ═══════════════════════════════════════════
// Middlewares
// ═══════════════════════════════════════════

/**
 * Middleware للتحقق من توقيع HMAC-SHA256
 * يجب أن يسبق هذا الـ Middleware أي Middleware يقوم بقراءة جسم الطلب (مثل express.json)
 */
const hmacVerificationMiddleware = (req, res, next) => {
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    
    if (!signature || !timestamp) {
        console.warn("HMAC Warning: Missing signature or timestamp headers.");
        return res.status(401).json({ 
            success: false, 
            error: 'Authentication required: Missing X-Signature or X-Timestamp', 
            code: 401 
        });
    }

    // 1. التحقق من صلاحية الطابع الزمني (مكافحة هجمات إعادة الإرسال - Replay Attacks)
    const now = Math.floor(Date.now() / 1000); // بالثواني
    const timeDiff = Math.abs(now - parseInt(timestamp));
    const MAX_TIME_DIFF = 300; // 5 دقائق كحد أقصى

    if (timeDiff > MAX_TIME_DIFF) {
        console.warn(`HMAC Warning: Timestamp too old/new. Diff: ${timeDiff}s`);
        return res.status(401).json({ 
            success: false, 
            error: 'Authentication failed: Request expired or time skew too large', 
            code: 401 
        });
    }

    // 2. التحقق من التوقيع
    // يجب أن يكون جسم الطلب (req.body) هو البيانات التي تم توقيعها
    // في هذه المرحلة، يجب أن يكون req.body هو النص المشفر (إذا كنا نستخدم التشفير)
    // أو النص الأصلي (إذا كنا لا نستخدم التشفير)
    
    // بما أننا سنستخدم التشفير، فإن req.body سيكون نصاً مشفراً
    const bodyString = JSON.stringify(req.body);
    
    // إزالة الأقواس الخارجية التي يضيفها JSON.stringify إذا كان الجسم فارغاً
    const dataToSign = bodyString === '{}' ? '' : bodyString;
    
    const expectedSignature = generateHMAC(dataToSign, timestamp);
    
    if (expectedSignature !== signature) {
        console.error(`HMAC Error: Invalid signature. Expected: ${expectedSignature}, Received: ${signature}`);
        return res.status(401).json({ 
            success: false, 
            error: 'Authentication failed: Invalid signature', 
            code: 401 
        });
    }
    
    // تخزين البيانات الموقعة للخطوة التالية (فك التشفير)
    req.signedBody = dataToSign;
    
    next();
};

/**
 * Middleware لفك تشفير جسم الطلب
 * يجب أن يسبق هذا الـ Middleware أي Middleware يقوم بقراءة جسم الطلب (مثل express.json)
 */
const decryptBodyMiddleware = (req, res, next) => {
    // نتوقع أن يكون جسم الطلب كائناً يحتوي على حقل واحد هو "payload"
    const { payload } = req.body;
    
    if (!payload) {
        // إذا لم يكن هناك payload، نفترض أن الطلب غير مشفر (قد يكون هذا مقبولاً لبعض المسارات)
        // أو نرفضه إذا كنا نتوقع التشفير دائماً
        // هنا سنفترض أننا نتوقع التشفير دائماً للمسارات التي تستخدم هذا الـ Middleware
        return res.status(400).json({ 
            success: false, 
            error: 'Bad Request: Missing encrypted payload', 
            code: 400 
        });
    }
    
    const decryptedData = decryptData(payload);
    
    if (!decryptedData) {
        return res.status(400).json({ 
            success: false, 
            error: 'Bad Request: Invalid or corrupted payload', 
            code: 400 
        });
    }
    
    // استبدال جسم الطلب بالبيانات المفككة
    req.body = decryptedData;
    
    next();
};

/**
 * Middleware لتشفير استجابة الخادم
 */
const encryptResponseMiddleware = (req, res, next) => {
    const originalJson = res.json;
    
    res.json = function(data) {
        // تشفير البيانات قبل إرسالها
        const encryptedPayload = encryptData(data);
        
        // إرسال البيانات المشفرة في حقل "payload"
        originalJson.call(this, { payload: encryptedPayload });
    };
    
    next();
};

module.exports = {
    hmacVerificationMiddleware,
    decryptBodyMiddleware,
    encryptResponseMiddleware,
    generateHMAC,
    decryptData,
    encryptData
};
