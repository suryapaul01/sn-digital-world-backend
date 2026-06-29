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
    if (encrypted.length !== 32) return { valid: false, message: 'Invalid key length' };

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
      return { valid: false, message: 'Invalid license signature' };
    }

    return {
      valid: true,
      user_name: userName,
      duration_minutes: durationMinutes,
      message: 'Signature verified successfully'
    };
  } catch (e) {
    return { valid: false, message: 'License key decoding failed' };
  }
}

async function listKVKeys() {
  const url = process.env.KV_REST_API_URL || process.env.STORAGE_URL || process.env.KV_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.STORAGE_TOKEN || process.env.KV_TOKEN;
  if (!url || !token) return [];

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(['KEYS', 'license_activation:*'])
    });
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data.result) ? data.result : [];
  } catch (e) {
    console.error("KV Keys error:", e);
    return [];
  }
}

async function getKV(key) {
  const url = process.env.KV_REST_API_URL || process.env.STORAGE_URL || process.env.KV_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.STORAGE_TOKEN || process.env.KV_TOKEN;
  if (!url || !token) return null;

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(['GET', key])
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.result;
  } catch (e) {
    console.error("KV Get error:", e);
    return null;
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

  const { admin_password } = req.body;

  if (!admin_password || admin_password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Incorrect Admin Password' });
  }

  try {
    const keys = await listKVKeys();
    const list = [];
    const nowSec = Math.floor(Date.now() / 1000);

    for (const key of keys) {
      const valStr = await getKV(key);
      if (!valStr) continue;

      let state;
      try {
        state = JSON.parse(valStr);
      } catch (e) {
        state = { device_id: valStr, expires_at: null }; // fallback
      }

      const licenseKey = key.replace('license_activation:', '');
      const decoded = decryptAndValidateLicense(licenseKey, SECRET_KEY);

      let status = 'active';
      if (state.revoked || state.status === 'revoked') {
        status = 'revoked';
      } else if (state.expires_at && nowSec > state.expires_at) {
        status = 'expired';
      }

      list.push({
        license_key: licenseKey,
        device_id: state.device_id || 'unknown',
        expires_at: state.expires_at ? new Date(state.expires_at * 1000).toISOString() : 'Never (Lifetime)',
        user_name: decoded.valid ? decoded.user_name : 'Unknown User',
        duration_minutes: decoded.valid ? decoded.duration_minutes : 0,
        status: status
      });
    }

    return res.status(200).json({ success: true, licenses: list });

  } catch(err) {
    console.error('List Error:', err);
    return res.status(500).json({ success: false, message: 'Failed to list active licenses' });
  }
};
