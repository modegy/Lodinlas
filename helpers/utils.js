// helpers/utils.js
const crypto = require('crypto');

// Generate Random Token
const generateToken = () => { 
    return crypto.randomBytes(32).toString('hex'); 
};

// Hash Password (SHA-256)
const hashPassword = (password) => { 
    return crypto.createHash('sha256').update(password).digest('hex'); 
};

// Format Date (DD/MM/YYYY HH:mm)
const formatDate = (timestamp) => {
    if (!timestamp) return null;
    const d = new Date(timestamp);
    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear();
    const hours = String(d.getHours()).padStart(2, '0');
    const mins = String(d.getMinutes()).padStart(2, '0');
    return `${day}/${month}/${year} ${hours}:${mins}`;
};

// Get Client IP
const getClientIP = (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
        || req.headers['x-real-ip'] 
        || req.ip 
        || req.connection.remoteAddress;
};

// Generate API Key
const generateApiKey = () => {
    return `AK_${crypto.randomBytes(16).toString('hex')}`;
};

// Generate Signing Secret
const generateSigningSecret = () => {
    return `SS_${crypto.randomBytes(32).toString('hex')}`;
};

module.exports = {
    generateToken,
    hashPassword,
    formatDate,
    getClientIP,
    generateApiKey,
    generateSigningSecret
};
