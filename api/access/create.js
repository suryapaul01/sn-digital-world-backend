const crypto = require('crypto');
const { ADMIN_PASSWORD, getKV, setKV, listKVKeys } = require('../_helpers');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ success: false, message: 'Method Not Allowed' });

  const { superadmin_password, admin_name, admin_password } = req.body;

  // Only superadmin can create admins
  if (!superadmin_password || superadmin_password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Superadmin access required' });
  }

  if (!admin_name || !admin_name.trim()) {
    return res.status(400).json({ success: false, message: 'Admin name is required' });
  }

  if (!admin_password || admin_password.trim().length < 4) {
    return res.status(400).json({ success: false, message: 'Admin password must be at least 4 characters' });
  }

  // Check that the password doesn't collide with superadmin or existing admins
  if (admin_password.trim() === ADMIN_PASSWORD) {
    return res.status(400).json({ success: false, message: 'Password cannot be the same as superadmin password' });
  }

  // Check for duplicate passwords among existing admins
  const existingKeys = await listKVKeys('admin_account:*');
  for (const key of existingKeys) {
    const valStr = await getKV(key);
    if (!valStr) continue;
    try {
      const existing = JSON.parse(valStr);
      if (existing.password === admin_password.trim()) {
        return res.status(400).json({ success: false, message: 'This password is already used by another admin. Choose a unique password.' });
      }
    } catch (e) { continue; }
  }

  try {
    // Generate unique prefix (6 chars hex)
    const prefix = crypto.randomBytes(3).toString('hex');
    const adminId = `admin_${prefix}`;

    const adminData = {
      id: adminId,
      name: admin_name.trim(),
      password: admin_password.trim(),
      prefix: prefix,
      created_at: new Date().toISOString(),
      status: 'active'
    };

    const success = await setKV(`admin_account:${adminId}`, JSON.stringify(adminData));

    if (success) {
      return res.status(200).json({
        success: true,
        message: 'Admin account created successfully',
        admin: {
          id: adminId,
          name: adminData.name,
          prefix: prefix,
          status: 'active',
          created_at: adminData.created_at
        }
      });
    } else {
      return res.status(500).json({ success: false, message: 'Failed to save admin account to database' });
    }
  } catch (err) {
    console.error('Create Admin Error:', err);
    return res.status(500).json({ success: false, message: 'Server error creating admin account' });
  }
};
