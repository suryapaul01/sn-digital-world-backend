const crypto = require('crypto');
const { resolveAdmin, getLicensePrefix, getKV, listKVKeys } = require('../_helpers');

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

  // Multi-tenant auth
  const adminInfo = await resolveAdmin(admin_password);
  if (!adminInfo) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Incorrect Admin Password' });
  }

  try {
    let allKeys = [];

    if (adminInfo.isSuperAdmin) {
      // Superadmin sees ALL: own keys + all tenant keys
      const superadminKeys = await listKVKeys('license_activation:*');
      const tenantKeys = await listKVKeys('tenant:*:license_activation:*');
      allKeys = [...superadminKeys, ...tenantKeys];
    } else {
      // Tenant admin sees only their own prefixed keys
      const prefix = getLicensePrefix(adminInfo);
      allKeys = await listKVKeys(`${prefix}*`);
    }

    const list = [];
    const nowSec = Math.floor(Date.now() / 1000);

    for (const key of allKeys) {
      const valStr = await getKV(key);
      if (!valStr) continue;

      let state;
      try {
        state = JSON.parse(valStr);
      } catch (e) {
        state = { device_id: valStr, expires_at: null }; // fallback
      }

      // Extract the license key from the KV key
      let licenseKey;
      if (key.startsWith('tenant:')) {
        // tenant:<prefix>:license_activation:<key>
        const parts = key.split(':license_activation:');
        licenseKey = parts[1] || key;
      } else {
        // license_activation:<key>
        licenseKey = key.replace('license_activation:', '');
      }

      const decoded = decryptAndValidateLicense(licenseKey, SECRET_KEY);

      let status = 'active';
      if (state.revoked || state.status === 'revoked') {
        status = 'revoked';
      } else if (state.expires_at && nowSec > state.expires_at) {
        status = 'expired';
      }

      // Determine tenant info for superadmin view
      let tenantName = null;
      if (adminInfo.isSuperAdmin) {
        if (key.startsWith('tenant:')) {
          const prefix = key.split(':')[1];
          tenantName = prefix; // will be shown as tenant prefix
        } else {
          tenantName = 'You (Superadmin)';
        }
      }

      list.push({
        license_key: licenseKey,
        device_id: state.device_id || 'unknown',
        expires_at: state.expires_at ? new Date(state.expires_at * 1000).toISOString() : 'Never (Lifetime)',
        user_name: decoded.valid ? decoded.user_name : 'Unknown User',
        duration_minutes: decoded.valid ? decoded.duration_minutes : 0,
        status: status,
        tenant: tenantName
      });
    }

    return res.status(200).json({ success: true, licenses: list });

  } catch(err) {
    console.error('List Error:', err);
    return res.status(500).json({ success: false, message: 'Failed to list active licenses' });
  }
};
