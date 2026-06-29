const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '@Aa7177276';

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

async function deleteKV(key) {
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
      body: JSON.stringify(['DEL', key])
    });
    return res.ok;
  } catch (e) {
    console.error("KV Delete error:", e);
    return false;
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

  const { admin_password, license_key, action } = req.body;

  if (!admin_password || admin_password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Incorrect Admin Password' });
  }

  if (!license_key) {
    return res.status(400).json({ success: false, message: 'License Key is required' });
  }

  try {
    const redisKey = `license_activation:${license_key}`;
    let success = false;
    let verb = 'revoked';

    if (action === 'delete' || action === 'reset') {
      success = await deleteKV(redisKey);
      verb = 'reset';
    } else {
      const state = {
        revoked: true,
        status: 'revoked',
        revoked_at: new Date().toISOString()
      };
      success = await setKV(redisKey, JSON.stringify(state));
    }

    if (success) {
      return res.status(200).json({ 
        success: true, 
        message: `License registration successfully ${verb}.` 
      });
    } else {
      return res.status(500).json({ 
        success: false, 
        message: `Failed to ${action || 'revoke'} license in database.` 
      });
    }

  } catch(err) {
    console.error('Revoke/Delete Error:', err);
    return res.status(500).json({ success: false, message: 'Server error occurred.' });
  }
};
