const crypto = require('crypto');

const SECRET_KEY = process.env.LICENSE_SECRET_KEY || 'my-super-secret-license-key-2026';

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
    
    // Extract Username
    let userName = decrypted.subarray(4, 20).toString('utf8').replace(/\0/g, '').trim();
    if (!userName) userName = "SN Digital User";

    // Validate Checksum
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

async function getKV(key) {
  const url = process.env.KV_REST_API_URL || process.env.STORAGE_URL || process.env.KV_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.STORAGE_TOKEN || process.env.KV_TOKEN;
  if (!url || !token) return null;

  try {
    const res = await fetch(`${url}/get/${encodeURIComponent(key)}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.result;
  } catch (e) {
    console.error("KV Get error:", e);
    return null;
  }
}

async function setKV(key, value) {
  const url = process.env.KV_REST_API_URL || process.env.STORAGE_URL || process.env.KV_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.STORAGE_TOKEN || process.env.KV_TOKEN;
  if (!url || !token) return false;

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(['SET', key, value])
    });
    return res.ok;
  } catch (e) {
    console.error("KV Set error:", e);
    return false;
  }
}

module.exports = async (req, res) => {
  // CORS configuration
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, apikey, x-license-key, x-session-id');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ valid: false, message: 'Method Not Allowed' });
  }

  const { license_key, device_id, heartbeat } = req.body;

  if (!license_key) {
    return res.status(400).json({ valid: false, message: 'License key is required.' });
  }

  try {
    // 1. Decrypt and check cryptographic validity
    const decoded = decryptAndValidateLicense(license_key, SECRET_KEY);
    if (!decoded.valid) {
      return res.status(401).json({
        valid: false,
        status: 'invalid',
        message: decoded.message
      });
    }

    // 2. Enforce Single-Device Binding & Activation-based Expiry if KV is linked
    const hasKV = (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN) ||
                  (process.env.STORAGE_URL && process.env.STORAGE_TOKEN) ||
                  (process.env.KV_URL && process.env.KV_TOKEN);

    let remainingSeconds = null;
    let expiresAt = null;

    if (hasKV) {
      const redisKey = `license_activation:${license_key}`;
      const stateStr = await getKV(redisKey);
      const now = Math.floor(Date.now() / 1000);

      if (stateStr) {
        let state;
        try {
          state = JSON.parse(stateStr);
        } catch (e) {
          state = { device_id: stateStr, expires_at: null }; // legacy fallback
        }

        if (state.revoked || state.status === 'revoked') {
          return res.status(401).json({
            valid: false,
            status: 'revoked',
            message: 'This license key has been revoked.'
          });
        }

        if (device_id && state.device_id && state.device_id !== device_id) {
          return res.status(403).json({
            valid: false,
            status: 'bound_conflict',
            message: 'This license key is already activated on another device.'
          });
        }

        if (state.expires_at) {
          if (now > state.expires_at) {
            return res.status(401).json({
              valid: false,
              status: 'expired',
              message: 'Your license key has expired.'
            });
          }
          remainingSeconds = Math.max(0, state.expires_at - now);
          expiresAt = new Date(state.expires_at * 1000).toISOString();
        }
      } else {
        // First activation: bind to this device and compute expires_at from duration
        let expiryTimestamp = null;
        if (decoded.duration_minutes !== 0xffffffff) {
          expiryTimestamp = now + (decoded.duration_minutes * 60);
          remainingSeconds = decoded.duration_minutes * 60;
          expiresAt = new Date(expiryTimestamp * 1000).toISOString();
        }

        const state = {
          device_id: device_id || 'unknown',
          expires_at: expiryTimestamp
        };
        await setKV(redisKey, JSON.stringify(state));
      }
    } else {
      // Fallback if KV is not configured: expiry starts from validation/generation request
      if (decoded.duration_minutes !== 0xffffffff) {
        remainingSeconds = decoded.duration_minutes * 60;
        expiresAt = new Date(Date.now() + decoded.duration_minutes * 60 * 1000).toISOString();
      }
    }

    // 3. Return license info
    return res.status(200).json({
      valid: true,
      session_id: heartbeat ? req.body.session_id : crypto.randomUUID(),
      user_name: decoded.user_name,
      expires_in: remainingSeconds,
      expires_at: expiresAt,
      activated_at: new Date().toISOString(),
      status: 'active',
      message: heartbeat ? 'Heartbeat OK' : 'License activated successfully!'
    });

  } catch (err) {
    console.error('Validation Error:', err);
    return res.status(500).json({
      valid: false,
      status: 'error',
      message: 'Internal server error during validation.'
    });
  }
};
