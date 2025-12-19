# 🛡️ Secure Firebase Proxy Server

<div align="center">

![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)
![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-enhanced-red.svg)

**نظام Proxy محمي بـ 9 طبقات أمان متقدمة لحماية Firebase من الهجمات**

[التوثيق](#-المميزات) • [التركيب](#-التركيب-السريع) • [الإعداد](#-الإعداد) • [الـ API](#-api-endpoints)

</div>

---

## 🚀 المميزات

### 🔒 حماية متعددة الطبقات

- ✅ **Helmet Security** - حماية HTTP Headers
- ✅ **Rate Limiting** - 3 مستويات (عام، Login، API)
- ✅ **Anti-Brute Force** - حماية من تخمين كلمات المرور
- ✅ **DDoS Detection** - كشف تلقائي للهجمات
- ✅ **IP Filtering** - Blacklist/Whitelist System
- ✅ **Request Monitoring** - مراقبة وتسجيل الطلبات
- ✅ **Timing Attack Prevention** - مقارنة آمنة
- ✅ **Session Management** - جلسات آمنة 24 ساعة
- ✅ **Auto IP Banning** - حظر تلقائي للمهاجمين

### 📊 إحصائيات الحماية

| النوع | الحد | المدة | العقوبة |
|------|------|-------|---------|
| طلبات عامة | 100 طلب | 15 دقيقة | حظر مؤقت |
| محاولات دخول | 5 محاولات | 15 دقيقة | حظر 15 د |
| API Calls | 200 طلب | 15 دقيقة | حظر مؤقت |
| DDoS Pattern | 30 طلب | 1 دقيقة | حظر دائم |

---

## 📦 التركيب السريع

### المتطلبات
- Node.js >= 16.0.0
- Firebase Realtime Database
- npm أو yarn

### الخطوات

```bash
# 1. استنساخ المشروع
git clone https://github.com/yourusername/secure-firebase-proxy.git
cd secure-firebase-proxy

# 2. تثبيت المكتبات
npm install

# 3. إنشاء ملف الإعدادات
cp .env.example .env

# 4. تعديل الإعدادات
nano .env

# 5. تشغيل الخادم
npm start
```

---

## ⚙️ الإعداد

### 1. إعداد Firebase

احصل على بيانات Firebase:
1. اذهب إلى [Firebase Console](https://console.firebase.google.com)
2. اختر مشروعك
3. اذهب لـ Project Settings → Service Accounts
4. انسخ **Database URL** و **Secret Key**

### 2. إعداد Environment Variables

عدّل ملف `.env`:

```env
# Firebase
FIREBASE_URL=https://your-project.firebaseio.com
FIREBASE_KEY=your-secret-key

# Admin Login (غيّرها!)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=YourStrongPassword123!

# API Keys (غيّرها!)
APP_API_KEY=YourAppSecretKey
ADMIN_API_KEY=YourAdminSecretKey
```

⚠️ **مهم جداً**: غيّر كلمات المرور والـ API Keys الافتراضية!

### 3. إعداد CORS (اختياري)

```env
# للسماح لجميع النطاقات
ALLOWED_ORIGINS=*

# لنطاقات محددة فقط
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

### 4. إعداد IP Filtering (اختياري)

```env
# حظر IPs محددة
IP_BLACKLIST=192.168.1.100,10.0.0.50

# السماح فقط لـ IPs محددة
IP_WHITELIST=192.168.1.10,203.0.113.5
```

---

## 🌐 API Endpoints

### 🔐 Authentication

#### تسجيل دخول Admin
```bash
POST /api/admin/login
Content-Type: application/json

{
  "username": "admin",
  "password": "yourpassword"
}

# Response
{
  "success": true,
  "sessionToken": "abc123...",
  "expiresIn": "24 hours"
}
```

#### التحقق من الجلسة
```bash
GET /api/admin/verify-session
x-session-token: your-session-token

# Response
{
  "success": true,
  "username": "admin",
  "createdAt": 1234567890,
  "lastActivity": 1234567890
}
```

### 📱 App Endpoints

#### الحصول على وقت الخادم
```bash
GET /api/serverTime
x-api-key: your-app-api-key

# Response
{
  "success": true,
  "server_time": 1234567890000,
  "unixtime": 1234567890
}
```

#### التحقق من حساب
```bash
POST /api/verifyAccount
x-api-key: your-app-api-key
Content-Type: application/json

{
  "username": "user1",
  "password": "pass123",
  "deviceId": "device-fingerprint"
}
```

### 👑 Admin Endpoints

**جميع هذه Endpoints تتطلب:**
```bash
x-session-token: your-session-token
```

#### جلب جميع المستخدمين
```bash
GET /api/admin/users
```

#### إضافة مستخدم جديد
```bash
POST /api/admin/users
Content-Type: application/json

{
  "username": "newuser",
  "password": "password123",
  "expiryMinutes": 43200,
  "maxDevices": 1,
  "status": "active"
}
```

#### تمديد مستخدم
```bash
POST /api/admin/users/{userId}/extend
Content-Type: application/json

{
  "minutes": 10080
}
```

#### حذف مستخدم
```bash
DELETE /api/admin/users/{userId}
```

---

## 🔧 Deploy على Render

### خطوة بخطوة

#### 1. رفع على GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/yourusername/your-repo.git
git push -u origin main
```

#### 2. إنشاء Web Service على Render

1. اذهب لـ [Render Dashboard](https://dashboard.render.com)
2. اضغط **New** → **Web Service**
3. اربط GitHub Repository
4. أكمل الإعدادات:

```yaml
Name: secure-firebase-proxy
Environment: Node
Build Command: npm install
Start Command: npm start
```

#### 3. إضافة Environment Variables

في Render Dashboard → Environment:

```
FIREBASE_URL=https://your-project.firebaseio.com
FIREBASE_KEY=your-secret-key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=YourStrongPassword123!
APP_API_KEY=YourAppKey
ADMIN_API_KEY=YourAdminKey
ALLOWED_ORIGINS=*
PORT=10000
NODE_ENV=production
```

#### 4. Deploy!

اضغط **Create Web Service** وانتظر حتى ينتهي الـ Deploy

---

## 🧪 اختبار الحماية

### اختبار Rate Limiting
```bash
# أرسل 101 طلب سريع
for i in {1..101}; do
  curl https://your-app.onrender.com/api/serverTime
done

# المتوقع: حظر بعد 100 طلب
```

### اختبار Brute Force
```bash
# 6 محاولات دخول خاطئة
for i in {1..6}; do
  curl -X POST https://your-app.onrender.com/api/admin/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}'
done

# المتوقع: حظر لمدة 15 دقيقة
```

---

## 📊 مراقبة الخادم

### السجلات (Logs)

في Render Dashboard → Logs:

```
✅ تسجيل دخول ناجح: admin من 1.2.3.4
⚠️ Rate limit exceeded: 5.6.7.8 - /api/login
🚨 DDoS Pattern Detected: 9.10.11.12 - 45 requests/min
```

### Health Check
```bash
GET /api/health

# Response
{
  "status": "healthy",
  "version": "3.0.0-secure",
  "uptime": 3600,
  "security": {
    "helmet": true,
    "rateLimiting": true,
    "bruteForce": true,
    "ddosProtection": true,
    "ipFiltering": true
  }
}
```

---

## 🔐 أفضل الممارسات

### ✅ افعل
- ✅ غيّر جميع كلمات المرور الافتراضية
- ✅ استخدم HTTPS دائماً في الإنتاج
- ✅ فعّل IP Whitelist للحماية القصوى
- ✅ راجع Logs يومياً
- ✅ حدّث المكتبات شهرياً
- ✅ استخدم كلمات مرور قوية (16+ حرف)

### ❌ لا تفعل
- ❌ لا تشارك API Keys أبداً
- ❌ لا تعطل Rate Limiting
- ❌ لا تستخدم HTTP في الإنتاج
- ❌ لا ترفع ملف `.env` على GitHub
- ❌ لا تستخدم كلمات مرور ضعيفة

---

## 🐛 حل المشاكل

### "429 Too Many Requests"
**السبب**: تجاوزت حد الطلبات
**الحل**: انتظر 15 دقيقة أو استخدم API Key صحيح

### "Session غير صالحة"
**السبب**: انتهت الجلسة (24 ساعة)
**الحل**: سجل دخول مرة أخرى

### "CORS Error"
**السبب**: نطاقك غير مسموح
**الحل**: أضف نطاقك لـ `ALLOWED_ORIGINS`

### "Firebase Connection Failed"
**السبب**: بيانات Firebase خاطئة
**الحل**: تحقق من `FIREBASE_URL` و `FIREBASE_KEY`

---

## 📈 خريطة الطريق

- [x] Helmet Security Headers
- [x] Multi-level Rate Limiting
- [x] Brute Force Protection
- [x] DDoS Detection
- [x] IP Filtering
- [ ] Redis Integration
- [ ] WebSocket Support
- [ ] GraphQL API
- [ ] Admin Dashboard (React)
- [ ] Email Notifications
- [ ] Two-Factor Authentication

---

## 🤝 المساهمة

المساهمات مرحب بها! إذا كان لديك اقتراحات:

1. Fork المشروع
2. أنشئ Branch جديد (`git checkout -b feature/amazing`)
3. Commit تغييراتك (`git commit -m 'Add amazing feature'`)
4. Push للـ Branch (`git push origin feature/amazing`)
5. افتح Pull Request

---

## 📄 الترخيص

هذا المشروع مرخص تحت [MIT License](LICENSE)

---## 📞 الدعم

إذا واجهت أي مشكلة:
- 📧 افتح [Issue](https://github.com/modegy/Lodinlas/issues)
- 📖 راجع [التوثيق الكامل](SECURITY.md)
- 💬 انضم إلى [Telegram](https://t.me/mod_egy)
- 💬 Discord Server (قريبًا)

---

<div align="center">

**صُنع بـ ❤️ MOD EGY PRO _ BY MA7MOUD @MOD_EGY**

⭐ إذا أعجبك المشروع، لا تنسَ النجمة!

</div>
