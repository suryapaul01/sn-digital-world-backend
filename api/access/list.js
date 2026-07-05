const { ADMIN_PASSWORD, getKV, listKVKeys } = require('../_helpers');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ success: false, message: 'Method Not Allowed' });

  const { superadmin_password } = req.body;

  // Only superadmin can list admins
  if (!superadmin_password || superadmin_password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Superadmin access required' });
  }

  try {
    const adminKeys = await listKVKeys('admin_account:*');
    const admins = [];

    for (const key of adminKeys) {
      const valStr = await getKV(key);
      if (!valStr) continue;

      try {
        const admin = JSON.parse(valStr);

        // Count this admin's license keys
        const licenseKeys = await listKVKeys(`tenant:${admin.prefix}:license_activation:*`);

        admins.push({
          id: admin.id,
          name: admin.name,
          password: admin.password,
          prefix: admin.prefix,
          status: admin.status,
          created_at: admin.created_at,
          total_licenses: licenseKeys.length
        });
      } catch (e) { continue; }
    }

    // Sort by creation date, newest first
    admins.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    return res.status(200).json({ success: true, admins });
  } catch (err) {
    console.error('List Admins Error:', err);
    return res.status(500).json({ success: false, message: 'Failed to list admin accounts' });
  }
};
