const { ADMIN_PASSWORD, getKV, setKV, deleteKV, listKVKeys } = require('../_helpers');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ success: false, message: 'Method Not Allowed' });

  const { superadmin_password, admin_id, action } = req.body;

  // Only superadmin
  if (!superadmin_password || superadmin_password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Superadmin access required' });
  }

  if (!admin_id) {
    return res.status(400).json({ success: false, message: 'Admin ID is required' });
  }

  if (!action || !['disable', 'enable', 'delete'].includes(action)) {
    return res.status(400).json({ success: false, message: 'Invalid action. Use: disable, enable, or delete' });
  }

  try {
    const kvKey = `admin_account:${admin_id}`;
    const valStr = await getKV(kvKey);

    if (!valStr) {
      return res.status(404).json({ success: false, message: 'Admin account not found' });
    }

    const admin = JSON.parse(valStr);

    if (action === 'disable') {
      admin.status = 'disabled';
      const success = await setKV(kvKey, JSON.stringify(admin));
      if (success) {
        return res.status(200).json({ success: true, message: `Admin "${admin.name}" has been disabled. They can no longer log in.` });
      }
    } else if (action === 'enable') {
      admin.status = 'active';
      const success = await setKV(kvKey, JSON.stringify(admin));
      if (success) {
        return res.status(200).json({ success: true, message: `Admin "${admin.name}" has been re-enabled.` });
      }
    } else if (action === 'delete') {
      // Delete the admin account
      const deleted = await deleteKV(kvKey);

      // Also delete all their license keys and reverse mappings
      const licenseKeys = await listKVKeys(`tenant:${admin.prefix}:license_activation:*`);
      for (const lk of licenseKeys) {
        const licenseKey = lk.replace(`tenant:${admin.prefix}:license_activation:`, '');
        await deleteKV(`license_key_tenant:${licenseKey}`); // reverse mapping
        await deleteKV(lk); // the activation record
      }

      if (deleted) {
        return res.status(200).json({
          success: true,
          message: `Admin "${admin.name}" and ${licenseKeys.length} associated license(s) have been deleted.`
        });
      }
    }

    return res.status(500).json({ success: false, message: `Failed to ${action} admin account` });
  } catch (err) {
    console.error('Manage Admin Error:', err);
    return res.status(500).json({ success: false, message: 'Server error managing admin account' });
  }
};
