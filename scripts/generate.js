const crypto = require('crypto');

const SECRET_KEY = process.env.LICENSE_SECRET_KEY || 'my-super-secret-license-key-2026';

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

function generateLicense(userName, timeLimitStr) {
  const timeLimit = timeLimitStr || 'lifetime';
  let expiresAtStr = 'Never (Lifetime)';
  let durationMinutes = 0xffffffff;

  if (timeLimit !== 'lifetime') {
    const minutes = parseTimeToMinutes(timeLimit);
    if (minutes <= 0) {
      console.error('Error: Invalid time format. Examples: 10m, 4h, 30d, lifetime');
      process.exit(1);
    }
    durationMinutes = minutes;
    expiresAtStr = `Valid for ${timeLimit} after activation`;
  }

  try {
    // Build a 32-byte plaintext block
    const block = Buffer.alloc(32);
    block.writeUInt32BE(durationMinutes, 0); // Bytes 0-3: Duration in minutes

    // Bytes 4-19: Username (padded/truncated to 16 bytes)
    const nameBuf = Buffer.from(userName.substring(0, 16), 'utf8');
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

    console.log('\n=============================================');
    console.log('✅ LICENSE KEY GENERATED SUCCESSFULLY');
    console.log('=============================================');
    console.log(`User Name  : ${userName}`);
    console.log(`Time Limit : ${timeLimit}`);
    console.log(`Expires At : ${expiresAtStr}`);
    console.log('---------------------------------------------');
    console.log('Provide this key to the user:');
    console.log('\n' + formattedKey + '\n');
    console.log('=============================================\n');
  } catch (err) {
    console.error('Generation Error:', err);
    process.exit(1);
  }
}

// Simple CLI parsing
const args = process.argv.slice(2);
let name = 'Premium User';
let time = 'lifetime';

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--name' && args[i+1]) {
    name = args[i+1];
    i++;
  } else if (args[i] === '--time' && args[i+1]) {
    time = args[i+1];
    i++;
  }
}

generateLicense(name, time);
