const crypto = require('crypto');

const SECRET_KEY = process.env.LICENSE_SECRET_KEY || 'my-super-secret-license-key-2026';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '@Aa7177276';

function decodeBase32(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const charMap = {};
  for (let i = 0; i < alphabet.length; i++) {
    charMap[alphabet[i]] = i;
  }
  
  const cleaned = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const output = [];
  
  for (let i = 0; i < cleaned.length; i++) {
    const c = cleaned[i];
    if (charMap[c] === undefined) continue;
    value = (value << 5) + charMap[c];
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function decryptAndValidateLicense(keyStr, secretKey) {
  try {
    const rawKey = keyStr.replace(/^SND-/i, '').replace(/[^A-Z2-7]/gi, '');
    const encrypted = decodeBase32(rawKey);
    if (encrypted.length !== 32) return { valid: false, message: 'Invalid key length (must be 32 bytes encrypted)' };

    const keyBuffer = crypto.createHash('sha256').update(secretKey).digest(); // 32-byte key
    const decipher = crypto.createDecipheriv('aes-256-ecb', keyBuffer, null);
    decipher.setAutoPadding(false);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    const durationMinutes = decrypted.readUInt32BE(0);
    let userName = decrypted.subarray(4, 20).toString('utf8').replace(/\0/g, '').trim();
    if (!userName) userName = "SN Digital User";

    const hmac = crypto.createHmac('sha256', secretKey).update(decrypted.subarray(0, 20)).digest();
    const expectedChecksum = hmac.subarray(0, 4);
    const actualChecksum = decrypted.subarray(20, 24);

    if (!expectedChecksum.equals(actualChecksum)) {
      return { valid: false, message: 'Cryptographic signature mismatch (incorrect key or secret)' };
    }

    return {
      valid: true,
      user_name: userName,
      duration_minutes: durationMinutes,
      message: 'Verified successfully'
    };
  } catch (e) {
    return { valid: false, message: 'License key decoding failed' };
  }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }

  const { admin_password, license_key } = req.body;

  if (!admin_password || admin_password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Incorrect Admin Password' });
  }

  if (!license_key) {
    return res.status(400).json({ success: false, message: 'License key is required' });
  }

  try {
    const result = decryptAndValidateLicense(license_key, SECRET_KEY);
    return res.status(200).json({ success: true, result });
  } catch(err) {
    console.error('Decrypt Error:', err);
    return res.status(500).json({ success: false, message: 'Server error during decryption' });
  }
};
