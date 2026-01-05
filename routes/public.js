const express = require('express');
const router = express.Router();

const { apiLimiter } = require('../middleware/security');

// ═══════════════════════════════════════════
// 🏥 HEALTH CHECK
// ═══════════════════════════════════════════
router.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        version: '3.3.0',
        uptime: Math.floor(process.uptime()),
        timestamp: Date.now()
    });
});

// ═══════════════════════════════════════════
// ⏰ SERVER TIME
// ═══════════════════════════════════════════
router.get('/serverTime', apiLimiter, (req, res) => {
    res.json({
        success: true,
        server_time: Date.now(),
        formatted: new Date().toISOString()
    });
});

// ═══════════════════════════════════════════
// 🏠 HOME PAGE HTML
// ═══════════════════════════════════════════
const homePageHTML = `<!DOCTYPE html>
<html dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🛡️ Secure API v3.3.0</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, sans-serif;
      background: linear-gradient(135deg, #1a1a2e, #16213e);
      color: #fff;
      min-height: 100vh;
      padding: 40px 20px;
      text-align: center;
    }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { color: #4cc9f0; margin-bottom: 20px; }
    .badge {
      background: linear-gradient(135deg, #10b981, #059669);
      padding: 10px 20px;
      border-radius: 20px;
      display: inline-block;
      margin: 20px 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Secure Firebase Proxy</h1>
    <div class="badge">✅ v3.3.0 - Secure Signature System</div>
    <p style="margin-top: 30px; color: #64748b;">
      🔐 Protected by HMAC-SHA256 Signatures<br>
      🔑 Derived Keys from API Key<br>
      🛡️ DDoS & Rate Limiting Protection
    </p>
  </div>
</body>
</html>`;

router.get('/', (req, res) => {
    res.send(homePageHTML);
});

module.exports = router;
