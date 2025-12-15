#!/bin/bash

# ═══════════════════════════════════════════
# 🔒 Fix Security Vulnerabilities Script
# ═══════════════════════════════════════════

echo "🔧 بدء إصلاح الثغرات الأمنية..."
echo "═══════════════════════════════════════════"

# الخطوة 1: حذف الملفات القديمة
echo "📦 الخطوة 1/5: حذف node_modules و package-lock.json..."
rm -rf node_modules
rm -f package-lock.json
echo "✅ تم الحذف"

# الخطوة 2: تنظيف npm cache
echo ""
echo "🧹 الخطوة 2/5: تنظيف npm cache..."
npm cache clean --force
echo "✅ تم التنظيف"

# الخطوة 3: تثبيت المكتبات المحدثة
echo ""
echo "📥 الخطوة 3/5: تثبيت المكتبات الآمنة..."
npm install
echo "✅ تم التثبيت"

# الخطوة 4: فحص الثغرات
echo ""
echo "🔍 الخطوة 4/5: فحص الثغرات..."
npm audit

# الخطوة 5: إصلاح تلقائي
echo ""
echo "🛠️  الخطوة 5/5: إصلاح الثغرات المتبقية..."
npm audit fix --force

echo ""
echo "═══════════════════════════════════════════"
echo "✅ انتهى الإصلاح!"
echo ""
echo "📊 النتيجة النهائية:"
npm audit
echo ""
echo "🚀 الخطوة التالية:"
echo "   git add ."
echo "   git commit -m '🔒 Fix security vulnerabilities'"
echo "   git push origin main"
echo ""