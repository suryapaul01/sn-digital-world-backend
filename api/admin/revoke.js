const { resolveAdmin, getLicensePrefix, getKV, setKV, deleteKV, findLicenseKVKey } = require('../_helpers');

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

  // Multi-tenant auth
  const adminInfo = await resolveAdmin(admin_password);
  if (!adminInfo) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Incorrect Admin Password' });
  }

  if (!license_key) {
    return res.status(400).json({ success: false, message: 'License Key is required' });
  }

  try {
    // Find the license key in KV (could be superadmin or any tenant)
    let redisKey;

    if (adminInfo.isSuperAdmin) {
      // Superadmin can operate on any key - find it wherever it is
      const found = await findLicenseKVKey(license_key);
      if (found) {
        redisKey = found.kvKey;
      } else {
        // Key not activated yet, use superadmin prefix
        redisKey = `license_activation:${license_key}`;
      }
    } else {
      // Tenant admin can only operate on their own keys
      const prefix = getLicensePrefix(adminInfo);
      redisKey = `${prefix}${license_key}`;
    }

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
