/**
 * _helpers.js - Shared KV helpers & multi-tenant auth resolver
 * 
 * Prefixed with underscore so Vercel does NOT expose it as an API endpoint.
 * All admin API endpoints require() this file for shared functionality.
 */

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '@Aa7177276';

// ─── KV CRUD ────────────────────────────────────────────────────────────

function _kvCredentials() {
  const url = process.env.KV_REST_API_URL || process.env.STORAGE_URL || process.env.KV_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.STORAGE_TOKEN || process.env.KV_TOKEN;
  return { url, token };
}

async function getKV(key) {
  const { url, token } = _kvCredentials();
  if (!url || !token) return null;

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(['GET', key])
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.result;
  } catch (e) {
    console.error('KV Get error:', e);
    return null;
  }
}

async function setKV(key, value) {
  const { url, token } = _kvCredentials();
  if (!url || !token) return false;

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(['SET', key, value])
    });
    return res.ok;
  } catch (e) {
    console.error('KV Set error:', e);
    return false;
  }
}

async function deleteKV(key) {
  const { url, token } = _kvCredentials();
  if (!url || !token) return false;

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(['DEL', key])
    });
    return res.ok;
  } catch (e) {
    console.error('KV Delete error:', e);
    return false;
  }
}

async function listKVKeys(pattern) {
  const { url, token } = _kvCredentials();
  if (!url || !token) return [];

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(['KEYS', pattern])
    });
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data.result) ? data.result : [];
  } catch (e) {
    console.error('KV Keys error:', e);
    return [];
  }
}

// ─── MULTI-TENANT AUTH ──────────────────────────────────────────────────

/**
 * Resolves a password to either superadmin or a tenant admin.
 * 
 * Returns:
 *   { isSuperAdmin: true, prefix: null, adminId: null, adminName: null }
 *   { isSuperAdmin: false, prefix: 'abc123', adminId: 'admin_abc123', adminName: 'John Shop' }
 *   null  (unauthorized / no match)
 */
async function resolveAdmin(password) {
  if (!password) return null;

  // Check superadmin first
  if (password === ADMIN_PASSWORD) {
    return { isSuperAdmin: true, prefix: null, adminId: null, adminName: 'Super Admin' };
  }

  // Scan tenant admin accounts
  const adminKeys = await listKVKeys('admin_account:*');
  for (const key of adminKeys) {
    const valStr = await getKV(key);
    if (!valStr) continue;

    try {
      const admin = JSON.parse(valStr);
      if (admin.password === password && admin.status === 'active') {
        return {
          isSuperAdmin: false,
          prefix: admin.prefix,
          adminId: admin.id,
          adminName: admin.name
        };
      }
    } catch (e) {
      continue;
    }
  }

  return null; // unauthorized
}

/**
 * Returns the KV key prefix used for storing license activations.
 * - Superadmin: 'license_activation:'
 * - Tenant admin: 'tenant:<prefix>:license_activation:'
 */
function getLicensePrefix(adminInfo) {
  if (adminInfo.isSuperAdmin) return 'license_activation:';
  return `tenant:${adminInfo.prefix}:license_activation:`;
}

/**
 * When generating a key as a tenant admin, store a reverse mapping so
 * validation can efficiently find which tenant a key belongs to.
 * Key: license_key_tenant:<license_key> → Value: <prefix>
 */
async function setLicenseTenant(licenseKey, prefix) {
  if (!prefix) return; // superadmin keys don't need reverse mapping
  await setKV(`license_key_tenant:${licenseKey}`, prefix);
}

/**
 * During validation, look up which tenant a license key belongs to.
 * Returns the prefix string, or null if it's a superadmin key / not found.
 */
async function getLicenseTenant(licenseKey) {
  return await getKV(`license_key_tenant:${licenseKey}`);
}

/**
 * Builds the full KV key for a license activation.
 * Checks: superadmin prefix first, then tenant reverse mapping.
 * Returns { kvKey, prefix } or null if key not found anywhere.
 */
async function findLicenseKVKey(licenseKey) {
  // 1. Check superadmin prefix
  const superadminKey = `license_activation:${licenseKey}`;
  const superadminVal = await getKV(superadminKey);
  if (superadminVal) {
    return { kvKey: superadminKey, prefix: null, value: superadminVal };
  }

  // 2. Check tenant reverse mapping
  const tenantPrefix = await getLicenseTenant(licenseKey);
  if (tenantPrefix) {
    const tenantKey = `tenant:${tenantPrefix}:license_activation:${licenseKey}`;
    const tenantVal = await getKV(tenantKey);
    if (tenantVal) {
      return { kvKey: tenantKey, prefix: tenantPrefix, value: tenantVal };
    }
  }

  return null; // not found
}

module.exports = {
  ADMIN_PASSWORD,
  getKV,
  setKV,
  deleteKV,
  listKVKeys,
  resolveAdmin,
  getLicensePrefix,
  setLicenseTenant,
  getLicenseTenant,
  findLicenseKVKey
};
