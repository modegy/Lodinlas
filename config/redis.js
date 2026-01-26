// config/redis.js
'use strict';

const Redis = require('ioredis');

if (!process.env.REDIS_URL) {
  console.error('❌ REDIS_URL is not set');
  process.exit(1);
}

const redis = new Redis(process.env.REDIS_URL, {
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: false
});

redis.on('connect', () => {
  console.log('🟢 Redis connected (Render)');
});

redis.on('ready', () => {
  console.log('⚡ Redis ready');
});

redis.on('error', (err) => {
  console.error('🔴 Redis error:', err.message);
});

redis.on('close', () => {
  console.warn('⚠️ Redis connection closed');
});

module.exports = redis;
