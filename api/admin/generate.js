const crypto = require('crypto');

const SECRET_KEY = process.env.LICENSE_SECRET_KEY || 'my-super-secret-license-key-2026';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '@Aa7177276';

function encodeBase32(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) + buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

function parseTimeToMinutes(str) {
  if (!str) return 0;
  if (/^\d+$/.test(str)) return parseInt(str);
  
  const matches = str.match(/^(\d+)([mhdyM])$/);
  if (!matches) return 0;
  
  const value = parseInt(matches[1]);
  const unit = matches[2];
  
  switch (unit) {
    case 'm': return value;
    case 'h': return value * 60;
    case 'd': return value * 60 * 24;
    case 'M': return value * 60 * 24 * 30;
    case 'y': return value * 60 * 24 * 365;
    default: return 0;
  }
}

function formatBrandedKey(base32Str) {
  const parts = [];
  for (let i = 0; i < base32Str.length; i += 4) {
    parts.push(base32Str.substring(i, i + 4));
  }
  return 'SND-' + parts.join('-');
}

module.exports = async (req, res) => {
  // CORS configuration
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }

  const { admin_password, user_name, time_limit } = req.body;

  if (!admin_password || admin_password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Incorrect Admin Password' });
  }

  if (!user_name) {
    return res.status(400).json({ success: false, message: 'User Name is required' });
  }

  const timeLimitStr = time_limit || 'lifetime';
  let expiresAtStr = 'Never (Lifetime)';
  let durationMinutes = 0xffffffff;

  if (timeLimitStr !== 'lifetime') {
    const minutes = parseTimeToMinutes(timeLimitStr);
    if (minutes <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid time format' });
    }
    durationMinutes = minutes;
    expiresAtStr = `Valid for ${timeLimitStr} after activation`;
  }

  try {
    // Build a 32-byte plaintext block
    const block = Buffer.alloc(32);
    block.writeUInt32BE(durationMinutes, 0); // Bytes 0-3: Duration in minutes

    // Bytes 4-19: Username (padded/truncated to 16 bytes)
    const nameBuf = Buffer.from(user_name.substring(0, 16), 'utf8');
    nameBuf.copy(block, 4);

    // Bytes 20-23: Checksum (HMAC of duration + username using secretKey)
    const hmac = crypto.createHmac('sha256', SECRET_KEY).update(block.subarray(0, 20)).digest();
    hmac.copy(block, 20, 0, 4);

    // Bytes 24-31: Random Salt
    crypto.randomBytes(8).copy(block, 24);

    // Encrypt block with AES-256-ECB (using key derived from SECRET_KEY)
    const keyBuffer = crypto.createHash('sha256').update(SECRET_KEY).digest(); // 32-byte key
    const cipher = crypto.createCipheriv('aes-256-ecb', keyBuffer, null);
    cipher.setAutoPadding(false);
    const encrypted = Buffer.concat([cipher.update(block), cipher.final()]);

    const base32Str = encodeBase32(encrypted);
    const formattedKey = formatBrandedKey(base32Str);

    return res.status(200).json({
      success: true,
      license_key: formattedKey,
      user_name: user_name,
      time_limit: timeLimitStr,
      expires_at: expiresAtStr
    });

  } catch(err) {
    console.error('Generation Error:', err);
    return res.status(500).json({ success: false, message: 'Failed to generate key' });
  }
};
