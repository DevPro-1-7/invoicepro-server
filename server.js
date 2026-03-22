/**
 * InvoicePro License Server
 * ══════════════════════════
 * Deploy on: Railway / Render / VPS / cPanel Node.js
 * 
 * Endpoints:
 *   POST /api/activate   — activate a license key
 *   POST /api/verify     — verify stored license (heartbeat)
 *   POST /api/deactivate — release a machine slot
 *   GET  /api/health     — server health check
 * 
 * Admin endpoints (protected by ADMIN_TOKEN):
 *   POST /admin/generate — generate a new license key
 *   GET  /admin/keys     — list all keys
 *   POST /admin/revoke   — revoke a key
 *   GET  /admin/stats    — dashboard stats
 */

'use strict';

const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const { v4: uuidv4 } = require('uuid');
const fs      = require('fs');
const path    = require('path');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

// ══════════════════════════════════════════════════════════════
//  CONFIG — set these as environment variables in production
// ══════════════════════════════════════════════════════════════
const CONFIG = {
  // Change this secret — it signs ALL license tokens
  SECRET:       process.env.LICENSE_SECRET || 'IP-SRV-SECRET-change-this-before-deploy-2026',
  // Admin panel password
  ADMIN_TOKEN:  process.env.ADMIN_TOKEN    || 'change-admin-token-2026',
  // Database file path
  DB_PATH:      process.env.DB_PATH        || path.join(__dirname, 'licenses.json'),
  // Port
  PORT:         process.env.PORT           || 3000,
  // Grace period in days after expiry
  GRACE_DAYS:   3,
};

// ══════════════════════════════════════════════════════════════
//  SIMPLE JSON "DATABASE"
//  In production: replace with PostgreSQL or MongoDB
// ══════════════════════════════════════════════════════════════
function loadDB() {
  try {
    if (fs.existsSync(CONFIG.DB_PATH)) {
      return JSON.parse(fs.readFileSync(CONFIG.DB_PATH, 'utf8'));
    }
  } catch { /* */ }
  return { keys: {}, activations: {}, audit: [] };
}

function saveDB(db) {
  fs.writeFileSync(CONFIG.DB_PATH, JSON.stringify(db, null, 2));
}

// ══════════════════════════════════════════════════════════════
//  CRYPTO HELPERS
// ══════════════════════════════════════════════════════════════
function sign(payload) {
  return crypto
    .createHmac('sha256', CONFIG.SECRET)
    .update(JSON.stringify(payload, Object.keys(payload).sort()))
    .digest('hex');
}

function makeToken(payload) {
  const data = { ...payload, iat: Math.floor(Date.now() / 1000) };
  return Buffer.from(JSON.stringify({ ...data, sig: sign(data) })).toString('base64url');
}

function verifyToken(token) {
  try {
    const data = JSON.parse(Buffer.from(token, 'base64url').toString('utf8'));
    const { sig, ...rest } = data;
    return sign(rest) === sig ? data : null;
  } catch { return null; }
}

// ══════════════════════════════════════════════════════════════
//  AUDIT LOG
// ══════════════════════════════════════════════════════════════
function audit(db, event, keyId, machineId, detail = '') {
  db.audit.push({
    ts: new Date().toISOString(),
    event, keyId, machineId, detail,
  });
  // Keep last 1000 entries
  if (db.audit.length > 1000) db.audit.splice(0, db.audit.length - 1000);
}

// ══════════════════════════════════════════════════════════════
//  TIER DEFINITIONS
// ══════════════════════════════════════════════════════════════
const TIERS = {
  trial:        { label: 'تجريبي',   invoicesLimit: 15,      maxMachines: 1 },
  starter:      { label: 'مبتدئ',    invoicesLimit: 200,     maxMachines: 1 },
  professional: { label: 'احترافي',  invoicesLimit: 9999999, maxMachines: 2 },
  enterprise:   { label: 'مؤسسي',    invoicesLimit: 9999999, maxMachines: 5 },
};

// ══════════════════════════════════════════════════════════════
//  ADMIN MIDDLEWARE
// ══════════════════════════════════════════════════════════════
function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (token !== CONFIG.ADMIN_TOKEN)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ══════════════════════════════════════════════════════════════
//  PUBLIC ENDPOINTS
// ══════════════════════════════════════════════════════════════

// Health check
app.get('/api/health', (_, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

// POST /api/activate
app.post('/api/activate', (req, res) => {
  const { licenseKey, machineId, appVersion } = req.body;

  if (!licenseKey || !machineId)
    return res.status(400).json({ ok: false, error: 'بيانات ناقصة' });

  const db  = loadDB();
  const key = db.keys[licenseKey];

  // Key doesn't exist
  if (!key)
    return res.json({ ok: false, error: 'مفتاح الترخيص غير صحيح' });

  // Revoked
  if (key.revoked)
    return res.json({ ok: false, error: 'هذا الترخيص تم إلغاؤه من قبل المطور' });

  // Expired (with grace)
  const expiry    = new Date(key.expiresAt);
  const graceLine = new Date(expiry.getTime() + CONFIG.GRACE_DAYS * 86400_000);
  if (new Date() > graceLine)
    return res.json({ ok: false, error: `انتهت صلاحية الترخيص منذ ${Math.ceil((Date.now() - expiry.getTime()) / 86400_000)} يوم` });

  // Machine slot check
  const activation = db.activations[licenseKey] || { machines: [] };
  const tierCfg    = TIERS[key.tier] || TIERS.starter;
  const alreadyActivated = activation.machines.includes(machineId);

  if (!alreadyActivated) {
    if (activation.machines.length >= tierCfg.maxMachines) {
      return res.json({
        ok: false,
        error: `تم استخدام الحد الأقصى من الأجهزة (${tierCfg.maxMachines}). أرسل لنا طلب تغيير الجهاز.`,
      });
    }
    activation.machines.push(machineId);
    db.activations[licenseKey] = activation;
    key.activationCount = (key.activationCount || 0) + 1;
  }

  // Issue signed server token
  const tokenPayload = {
    keyId:         licenseKey,
    machineId,
    tier:          key.tier,
    expiresAt:     key.expiresAt,
    invoicesLimit: key.invoicesLimit || tierCfg.invoicesLimit,
    features:      key.features || {},
    notes:         key.clientName || '',
  };
  const serverToken = makeToken(tokenPayload);

  audit(db, 'ACTIVATED', licenseKey, machineId, `tier=${key.tier}`);
  saveDB(db);

  const daysLeft = Math.ceil((expiry.getTime() - Date.now()) / 86400_000);

  res.json({
    ok: true,
    serverToken,
    tier:          key.tier,
    tierLabel:     tierCfg.label,
    expiresAt:     key.expiresAt,
    daysLeft:      Math.max(0, daysLeft),
    invoicesLimit: key.invoicesLimit || tierCfg.invoicesLimit,
    features:      key.features || {},
    message:       `✓ تم تفعيل ترخيص ${tierCfg.label} — ${Math.max(0, daysLeft)} يوم متبقٍ`,
  });
});

// POST /api/verify — client calls this on startup to verify stored token
app.post('/api/verify', (req, res) => {
  const { serverToken, machineId } = req.body;
  if (!serverToken || !machineId)
    return res.status(400).json({ ok: false, valid: false });

  const data = verifyToken(serverToken);
  if (!data || data.machineId !== machineId)
    return res.json({ ok: false, valid: false, error: 'توقيع غير صالح' });

  const db  = loadDB();
  const key = db.keys[data.keyId];

  if (!key || key.revoked)
    return res.json({ ok: false, valid: false, error: 'الترخيص ملغى' });

  const graceLine = new Date(new Date(data.expiresAt).getTime() + CONFIG.GRACE_DAYS * 86400_000);
  if (new Date() > graceLine)
    return res.json({ ok: false, valid: false, error: 'انتهت الصلاحية' });

  res.json({ ok: true, valid: true, tier: data.tier, expiresAt: data.expiresAt });
});

// POST /api/deactivate — release machine slot
app.post('/api/deactivate', (req, res) => {
  const { licenseKey, machineId } = req.body;
  if (!licenseKey || !machineId)
    return res.status(400).json({ ok: false });

  const db = loadDB();
  const act = db.activations[licenseKey];
  if (act) {
    act.machines = act.machines.filter(m => m !== machineId);
    audit(db, 'DEACTIVATED', licenseKey, machineId, 'manual');
    saveDB(db);
  }
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  ADMIN ENDPOINTS
// ══════════════════════════════════════════════════════════════

// POST /admin/generate — create a new license key
app.post('/admin/generate', adminAuth, (req, res) => {
  const {
    tier = 'professional',
    durationDays = 365,
    clientName = '',
    clientEmail = '',
    invoicesLimit,
    notes = '',
    maxMachines,
  } = req.body;

  if (!TIERS[tier])
    return res.status(400).json({ error: `tier invalide: ${tier}` });

  const db  = loadDB();
  const key = [
    uuidv4().slice(0,8).toUpperCase(),
    uuidv4().slice(0,8).toUpperCase(),
    uuidv4().slice(0,8).toUpperCase(),
    uuidv4().slice(0,8).toUpperCase(),
  ].join('-');

  db.keys[key] = {
    key,
    tier,
    clientName,
    clientEmail,
    notes,
    createdAt:     new Date().toISOString(),
    expiresAt:     new Date(Date.now() + durationDays * 86400_000).toISOString(),
    revoked:       false,
    activationCount: 0,
    invoicesLimit: invoicesLimit || TIERS[tier].invoicesLimit,
    maxMachines:   maxMachines   || TIERS[tier].maxMachines,
  };

  audit(db, 'KEY_GENERATED', key, '-', `tier=${tier} client=${clientName}`);
  saveDB(db);

  res.json({
    ok:  true,
    key,
    tier,
    expiresAt: db.keys[key].expiresAt,
    message: `مفتاح ${TIERS[tier].label} جاهز`,
  });
});

// GET /admin/keys
app.get('/admin/keys', adminAuth, (_, res) => {
  const db = loadDB();
  const keys = Object.values(db.keys).map(k => ({
    ...k,
    machines: db.activations[k.key]?.machines || [],
  }));
  res.json({ ok: true, count: keys.length, keys });
});

// POST /admin/revoke
app.post('/admin/revoke', adminAuth, (req, res) => {
  const { key } = req.body;
  const db = loadDB();
  if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' });
  db.keys[key].revoked = true;
  audit(db, 'REVOKED', key, '-', 'admin revoke');
  saveDB(db);
  res.json({ ok: true, message: 'تم إلغاء المفتاح' });
});

// POST /admin/unrevoke
app.post('/admin/unrevoke', adminAuth, (req, res) => {
  const { key } = req.body;
  const db = loadDB();
  if (!db.keys[key]) return res.status(404).json({ error: 'Key not found' });
  db.keys[key].revoked = false;
  audit(db, 'UNREVOKED', key, '-', 'admin unrevoke');
  saveDB(db);
  res.json({ ok: true });
});

// POST /admin/reset-machines — clear machine slots for a key
app.post('/admin/reset-machines', adminAuth, (req, res) => {
  const { key } = req.body;
  const db = loadDB();
  if (db.activations[key]) db.activations[key].machines = [];
  audit(db, 'MACHINES_RESET', key, '-', 'admin reset');
  saveDB(db);
  res.json({ ok: true, message: 'تم إعادة تعيين فتحات الأجهزة' });
});

// GET /admin/stats
app.get('/admin/stats', adminAuth, (_, res) => {
  const db   = loadDB();
  const keys = Object.values(db.keys);
  res.json({
    ok:        true,
    total:     keys.length,
    active:    keys.filter(k => !k.revoked && new Date(k.expiresAt) > new Date()).length,
    revoked:   keys.filter(k => k.revoked).length,
    expired:   keys.filter(k => !k.revoked && new Date(k.expiresAt) <= new Date()).length,
    byTier:    Object.fromEntries(Object.keys(TIERS).map(t => [t, keys.filter(k=>k.tier===t).length])),
    lastAudit: db.audit.slice(-20),
  });
});

// GET /admin/audit
app.get('/admin/audit', adminAuth, (_, res) => {
  const db = loadDB();
  res.json({ ok: true, audit: db.audit.slice().reverse().slice(0, 200) });
});

// ══════════════════════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════════════════════
app.listen(CONFIG.PORT, () => {
  console.log(`\n✅ InvoicePro License Server running on port ${CONFIG.PORT}`);
  console.log(`   Health: http://localhost:${CONFIG.PORT}/api/health`);
  console.log(`   Admin:  http://localhost:${CONFIG.PORT}/admin/stats?token=${CONFIG.ADMIN_TOKEN}\n`);
});

module.exports = app;
