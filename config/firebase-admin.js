// firebaseAdmin.js - Firebase Admin SDK Initialization (Production-Ready 2026)
// ──────────────────────────────────────────────────────────────────────────────

'use strict';

const admin = require('firebase-admin');

// ──────────────────────────────────────────────────────────────────────────────
// 1. تحميل بيانات Service Account من البيئة فقط
// ──────────────────────────────────────────────────────────────────────────────
const serviceAccount = {
  type: 'service_account',
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY
    ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    : undefined,
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI || 'https://accounts.google.com/o/oauth2/auth',
  token_uri: process.env.FIREBASE_TOKEN_URI || 'https://oauth2.googleapis.com/token',
  auth_provider_x509_cert_url:
    process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL ||
    'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN || 'googleapis.com'
};

// ──────────────────────────────────────────────────────────────────────────────
// 2. التحقق من الحقول الإلزامية (أكثر دقة)
// ──────────────────────────────────────────────────────────────────────────────
const requiredFields = ['project_id', 'private_key', 'client_email'];

const missing = requiredFields.filter(field => {
  const value = serviceAccount[field];
  return !value || (typeof value === 'string' && value.trim() === '');
});

if (missing.length > 0) {
  console.error('═'.repeat(70));
  console.error('🚨 FATAL: Missing or empty Firebase credentials in environment:');
  missing.forEach(field => console.error(`   • ${field.toUpperCase()}`));
  console.error('Please check your .env file or deployment secrets.');
  console.error('═'.repeat(70));
  process.exit(1); // إيقاف التطبيق فوراً
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. منع إعادة التهيئة (singleton pattern)
// ──────────────────────────────────────────────────────────────────────────────
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: process.env.FIREBASE_DATABASE_URL,
      // إضافة: دعم storage إذا كنت تستخدمه لاحقاً
      // storageBucket: process.env.FIREBASE_STORAGE_BUCKET
    });

    console.log('🔥 Firebase Admin SDK initialized successfully');
  } catch (error) {
    console.error('═'.repeat(70));
    console.error('💥 Firebase Admin initialization failed:');
    console.error(error.message);
    if (error.stack) console.error(error.stack.split('\n').slice(0, 5).join('\n'));
    console.error('═'.repeat(70));
    process.exit(1);
  }
} else {
  console.log('♻️ Firebase Admin SDK already initialized (singleton)');
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. تصدير الـ instances
// ──────────────────────────────────────────────────────────────────────────────
const db = admin.database();

module.exports = {
  admin,
  db,
  // إضافة اختيارية: إذا كنت تستخدم Firestore أو Storage لاحقاً
  // firestore: admin.firestore(),
  // storage: admin.storage(),
  // auth: admin.auth()
};
