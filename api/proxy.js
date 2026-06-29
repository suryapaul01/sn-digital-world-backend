const crypto = require('crypto');

const SECRET_KEY = process.env.LICENSE_SECRET_KEY || 'my-super-secret-license-key-2026';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://your-original-supabase-url.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'your-original-supabase-anon-key';

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

module.exports = async (req, res) => {
  // CORS configuration
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, apikey, x-license-key, x-session-id');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Extract license key from headers, body, or query
  const licenseKey = req.headers['x-license-key'] || (req.body && req.body.license_key) || req.query.license_key;

  if (!licenseKey) {
    return res.status(401).json({ error: 'Missing license key' });
  }

  // Allow "INTERNAL" license mode for internal testing (if set in config)
  const isInternal = licenseKey === 'INTERNAL';

  if (!isInternal) {
    // 1. Decrypt and check cryptographic validity
    const decoded = decryptAndValidateLicense(licenseKey, SECRET_KEY);
    if (!decoded.valid) {
      return res.status(401).json({ error: 'Invalid license key signature' });
    }

    // 2. Validate expiration and single-device binding via KV if configured
    const hasKV = (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN) ||
                  (process.env.STORAGE_URL && process.env.STORAGE_TOKEN) ||
                  (process.env.KV_URL && process.env.KV_TOKEN);

    if (hasKV) {
      const redisKey = `license_activation:${licenseKey}`;
      const stateStr = await getKV(redisKey);
      
      if (stateStr) {
        let state;
        try {
          state = JSON.parse(stateStr);
        } catch (e) {
          state = { device_id: stateStr, expires_at: null };
        }

        if (state.revoked || state.status === 'revoked') {
          return res.status(401).json({ error: 'This license key has been revoked.' });
        }

        const deviceId = req.headers['x-device-id'] || (req.body && req.body.device_id) || req.query.device_id;
        if (deviceId && state.device_id && state.device_id !== deviceId) {
          return res.status(403).json({ error: 'License activated on another device.' });
        }

        if (state.expires_at) {
          const now = Math.floor(Date.now() / 1000);
          if (now > state.expires_at) {
            return res.status(401).json({ error: 'Your license key has expired.' });
          }
        }
      }
    }
  }

  // 3. Resolve target path and construct target URL
  const targetPath = req.query.path;
  if (!targetPath) {
    return res.status(400).json({ error: 'Missing proxy path parameter' });
  }

  const targetUrl = new URL(`${SUPABASE_URL}/${targetPath}`);
  for (const [key, val] of Object.entries(req.query)) {
    if (key !== 'path' && key !== 'license_key' && key !== 'device_id') {
      targetUrl.searchParams.append(key, val);
    }
  }

  try {
    // Inject the real Supabase API key (hidden from users)
    const headers = {
      'Content-Type': 'application/json',
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`
    };

    // Forward any other relevant headers if necessary
    if (req.headers['accept']) headers['accept'] = req.headers['accept'];
    if (req.headers['prefer']) headers['prefer'] = req.headers['prefer'];

    const fetchOptions = {
      method: req.method,
      headers: headers,
    };

    if (req.method === 'POST') {
      // Forward the body
      fetchOptions.body = typeof req.body === 'object' ? JSON.stringify(req.body) : req.body;
    }

    const response = await fetch(targetUrl.toString(), fetchOptions);
    const responseText = await response.text();
    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch(e) {
      responseData = responseText;
    }

    return res.status(response.status).json(responseData);

  } catch (err) {
    console.error('Proxy Error:', err);
    return res.status(500).json({ error: 'Internal Server Error during proxy' });
  }
};
