// routes/public.js - Public Routes v14.1
'use strict';

const express = require('express');
const router = express.Router();

// ═══════════════════════════════════════════════════════════════════
// 🏥 HEALTH CHECK
// ═══════════════════════════════════════════════════════════════════
router.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        version: '14.1.0',
        uptime: Math.floor(process.uptime()),
        timestamp: Date.now(),
        security: {
            waf: true,
            ddos: true,
            rateLimit: true,
            botDetection: true
        }
    });
});

// ═══════════════════════════════════════════════════════════════════
// ⏰ SERVER TIME
// ═══════════════════════════════════════════════════════════════════
router.get('/serverTime', (req, res) => {
    res.json({
        success: true,
        server_time: Date.now(),
        formatted: new Date().toISOString()
    });
});

// ═══════════════════════════════════════════════════════════════════
// 🏠 HOME PAGE
// ═══════════════════════════════════════════════════════════════════
const homePageHTML = `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🛡️ Secure API v14.1</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f0f23, #1a1a3e, #0f172a);
      color: #e2e8f0;
      min-height: 100vh;
      padding: 40px 20px;
      text-align: center;
    }
    .container { max-width: 900px; margin: 0 auto; }
    h1 { 
      color: #4cc9f0; 
      margin-bottom: 10px;
      font-size: 2.5rem;
      text-shadow: 0 0 20px rgba(76, 201, 240, 0.3);
    }
    .subtitle {
      color: #94a3b8;
      margin-bottom: 30px;
      font-size: 1.1rem;
    }
    .badge {
      background: linear-gradient(135deg, #10b981, #059669);
      padding: 12px 28px;
      border-radius: 25px;
      display: inline-block;
      margin: 20px 0;
      font-weight: 600;
      box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
    }
    .features {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-top: 40px;
    }
    .feature {
      background: rgba(255, 255, 255, 0.05);
      padding: 20px;
      border-radius: 15px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      transition: transform 0.3s, box-shadow 0.3s;
    }
    .feature:hover {
      transform: translateY(-5px);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    }
    .feature-icon { font-size: 2rem; margin-bottom: 10px; }
    .feature-title { color: #4cc9f0; font-weight: 600; margin-bottom: 5px; }
    .feature-desc { color: #94a3b8; font-size: 0.9rem; }
    .footer {
      margin-top: 50px;
      padding-top: 20px;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
      color: #64748b;
      font-size: 0.85rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Secure Firebase Proxy</h1>
    <p class="subtitle">Enterprise-Grade Security API Server</p>
    <div class="badge">✅ v14.1 - Advanced Security System</div>
    
    <div class="features">
      <div class="feature">
        <div class="feature-icon">🔐</div>
        <div class="feature-title">HMAC-SHA256</div>
        <div class="feature-desc">توقيع رقمي آمن مع مقاومة هجمات التوقيت</div>
      </div>
      <div class="feature">
        <div class="feature-icon">🔥</div>
        <div class="feature-title">WAF Protection</div>
        <div class="feature-desc">حماية من SQL, XSS, NoSQL, XXE, SSTI</div>
      </div>
      <div class="feature">
        <div class="feature-icon">🚫</div>
        <div class="feature-title">DDoS Shield</div>
        <div class="feature-desc">حماية متقدمة ضد هجمات الحرمان من الخدمة</div>
      </div>
      <div class="feature">
        <div class="feature-icon">⏱️</div>
        <div class="feature-title">Token Bucket</div>
        <div class="feature-desc">تحديد معدل الطلبات بخوارزمية متقدمة</div>
      </div>
      <div class="feature">
        <div class="feature-icon">🤖</div>
        <div class="feature-title">Bot Detection</div>
        <div class="feature-desc">كشف وحظر البوتات والطلبات الآلية</div>
      </div>
      <div class="feature">
        <div class="feature-icon">🔄</div>
        <div class="feature-title">Replay Protection</div>
        <div class="feature-desc">منع إعادة استخدام الطلبات (Nonce)</div>
      </div>
    </div>
    
    <div class="footer">
      <p>🔒 Protected by Advanced Security Middleware</p>
      <p>All requests are monitored and logged</p>
    </div>
  </div>
</body>
</html>`;

router.get('/', (req, res) => {
    res.send(homePageHTML);
});

// ═══════════════════════════════════════════════════════════════════
// 📦 EXPORT
// ═══════════════════════════════════════════════════════════════════
module.exports = router;
