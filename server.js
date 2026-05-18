require('dotenv').config();
const express = require('express');
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const db = require('./database');

const app = express();
const PORT           = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const BASE_URL       = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const SESSION_SECRET = process.env.SESSION_SECRET || 'nfcgo-dev-secret-change-in-production';

app.set('view engine', 'ejs');
app.set('views', './views');
app.use(express.static('./public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Rate limiting ────────────────────────────────────────────────────────────
const claimLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos. Espera un minuto e inténtalo de nuevo.' },
});

// ─── Cookie helpers ───────────────────────────────────────────────────────────
const ADMIN_COOKIE     = 'nfcgo_admin';
const VALIDATOR_COOKIE = 'validator_sid';

function parseCookies(header) {
  const cookies = {};
  (header || '').split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx < 0) return;
    const key = part.slice(0, idx).trim();
    try { cookies[key] = decodeURIComponent(part.slice(idx + 1).trim()); }
    catch { cookies[key] = part.slice(idx + 1).trim(); }
  });
  return cookies;
}

// Admin cookie helpers
function requireAdmin(req, res, next) {
  const cookies = parseCookies(req.headers.cookie);
  if (cookies[ADMIN_COOKIE] === ADMIN_PASSWORD) return next();
  res.redirect('/admin/login');
}

function setCookieAdmin(res) {
  res.setHeader(
    'Set-Cookie',
    `${ADMIN_COOKIE}=${encodeURIComponent(ADMIN_PASSWORD)}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
  );
}

function clearCookieAdmin(res) {
  res.setHeader('Set-Cookie', `${ADMIN_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
}

// ─── Validator session helpers ────────────────────────────────────────────────
function signValidatorSession(businessId, slug) {
  const payload = `${businessId}:${slug}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex').slice(0, 16);
  return `${payload}:${sig}`;
}

function parseValidatorSession(cookieVal) {
  if (!cookieVal) return null;
  // Format: "businessId:slug:hmac16"  (slug is a-z0-9- so no ':' conflicts)
  const lastColon = cookieVal.lastIndexOf(':');
  if (lastColon < 0) return null;
  const sig     = cookieVal.slice(lastColon + 1);
  const payload = cookieVal.slice(0, lastColon);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex').slice(0, 16);
  if (sig !== expected) return null;
  const firstColon = payload.indexOf(':');
  if (firstColon < 0) return null;
  const businessId = parseInt(payload.slice(0, firstColon), 10);
  const slug       = payload.slice(firstColon + 1);
  if (isNaN(businessId) || !slug) return null;
  return { businessId, slug };
}

function requireValidator(req, res, next) {
  const cookies = parseCookies(req.headers.cookie);
  const session = parseValidatorSession(cookies[VALIDATOR_COOKIE]);
  if (!session || session.slug !== req.params.slug) {
    return res.redirect(`/v/${req.params.slug}`);
  }
  const business = db
    .prepare(`SELECT * FROM businesses WHERE id = ? AND slug = ?`)
    .get(session.businessId, session.slug);
  if (!business) {
    res.setHeader('Set-Cookie', `${VALIDATOR_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
    return res.redirect(`/v/${req.params.slug}`);
  }
  req.business = business;
  next();
}

// ─── Flash helper (query-param based, no extra deps) ─────────────────────────
function flashFromQuery(req) {
  if (req.query.ok)  return { type: 'success', msg: String(req.query.ok).slice(0, 400) };
  if (req.query.err) return { type: 'error',   msg: String(req.query.err).slice(0, 400) };
  return null;
}

function redirectFlash(res, path, type, msg) {
  const key = type === 'success' ? 'ok' : 'err';
  res.redirect(`${path}?${key}=${encodeURIComponent(msg)}`);
}

// ─── Utilidades ───────────────────────────────────────────────────────────────
function generatePassword(len = 8) {
  // Excluye caracteres confusos: 0/O, 1/I/l
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function csvCell(val) {
  if (val === null || val === undefined) return '""';
  const str  = String(val);
  const safe = /^[=+\-@\t\r]/.test(str) ? `'${str}` : str;
  return `"${safe.replace(/"/g, '""')}"`;
}

// ─── Migración de datos: credenciales para negocios sin ellas ─────────────────
(function migrateValidatorCredentials() {
  const missing = db.prepare(`SELECT * FROM businesses WHERE validator_username IS NULL`).all();
  if (missing.length === 0) return;

  console.log('\n[NFC GO] Generando credenciales de validación para negocios existentes:');
  const update = db.prepare(
    `UPDATE businesses SET validator_username=?, validator_password=? WHERE id=?`
  );
  db.transaction(() => {
    missing.forEach(b => {
      const pass   = generatePassword();
      const hashed = bcrypt.hashSync(pass, 10);
      update.run(b.slug, hashed, b.id);
      console.log(`  → "${b.name}"  usuario: ${b.slug}  contraseña: ${pass}`);
    });
  })();
  console.log('[NFC GO] Guarda estas contraseñas: no se podrán recuperar después.\n');
})();

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC ROUTES
// ════════════════════════════════════════════════════════════════════════════════

app.get('/c/:tag_code', (req, res) => {
  const { tag_code } = req.params;
  const tag = db
    .prepare(
      `SELECT t.*, b.name AS business_name, b.logo_url, b.reward_text, b.slug
       FROM nfc_tags t
       JOIN businesses b ON b.id = t.business_id
       WHERE t.tag_code = ?`
    )
    .get(tag_code);

  if (!tag || tag.status !== 'active') {
    return res.render('landing', {
      state: 'claimed',
      tag: tag || null,
      business: tag
        ? { name: tag.business_name, logo_url: tag.logo_url, reward_text: tag.reward_text }
        : null,
      discount_code: tag?.discount_code || null,
    });
  }

  res.render('landing', {
    state: 'active',
    tag,
    business: { name: tag.business_name, logo_url: tag.logo_url, reward_text: tag.reward_text },
    discount_code: null,
  });
});

app.post('/claim/:tag_code', claimLimiter, (req, res) => {
  const { tag_code } = req.params;

  const claim = db.transaction(() => {
    const tag = db
      .prepare(
        `SELECT t.*, b.name AS business_name, b.logo_url, b.reward_text, b.slug
         FROM nfc_tags t
         JOIN businesses b ON b.id = t.business_id
         WHERE t.tag_code = ?`
      )
      .get(tag_code);

    if (!tag) return { ok: false, error: 'Etiqueta no encontrada.', status: 404 };
    if (tag.status !== 'active')
      return { ok: false, error: 'Este premio ya ha sido reclamado.', status: 409 };

    db.prepare(
      `UPDATE nfc_tags SET status = 'claimed', claimed_at = CURRENT_TIMESTAMP WHERE tag_code = ?`
    ).run(tag_code);

    return {
      ok: true,
      discount_code: tag.discount_code,
      business_name: tag.business_name,
      reward_text: tag.reward_text,
    };
  });

  const result = claim();
  if (!result.ok) return res.status(result.status).json({ error: result.error });
  res.json(result);
});

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATOR PANEL  /v/:slug
// ════════════════════════════════════════════════════════════════════════════════

// Login page
app.get('/v/:slug', (req, res) => {
  const { slug } = req.params;
  const business = db
    .prepare(`SELECT id, name, logo_url, slug FROM businesses WHERE slug = ?`)
    .get(slug);
  if (!business) return res.status(404).send('Negocio no encontrado.');

  // Redirigir si ya hay sesión válida
  const cookies = parseCookies(req.headers.cookie);
  const session = parseValidatorSession(cookies[VALIDATOR_COOKIE]);
  if (session && session.slug === slug && session.businessId === business.id) {
    return res.redirect(`/v/${slug}/dashboard`);
  }

  res.render('validate-login', { business, error: null });
});

// Login submit
app.post('/v/:slug/login', (req, res) => {
  const { slug } = req.params;
  const { username, password } = req.body;

  const business = db
    .prepare(`SELECT * FROM businesses WHERE slug = ? AND validator_username = ?`)
    .get(slug, (username || '').trim());

  const invalid = () =>
    res.render('validate-login', {
      business: business || { name: slug, logo_url: null, slug },
      error: 'Usuario o contraseña incorrectos.',
    });

  if (!business || !business.validator_password) return invalid();

  const valid = bcrypt.compareSync(password || '', business.validator_password);
  if (!valid) return invalid();

  const token = signValidatorSession(business.id, slug);
  res.setHeader(
    'Set-Cookie',
    `${VALIDATOR_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=43200; SameSite=Lax`
  );
  res.redirect(`/v/${slug}/dashboard`);
});

// Dashboard
app.get('/v/:slug/dashboard', requireValidator, (req, res) => {
  const tags = db
    .prepare(
      `SELECT * FROM nfc_tags WHERE business_id = ?
       ORDER BY
         CASE status WHEN 'claimed' THEN 0 WHEN 'redeemed' THEN 1 WHEN 'active' THEN 2 ELSE 3 END,
         discount_code`
    )
    .all(req.business.id);

  const stats = db
    .prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN status='claimed'  THEN 1 ELSE 0 END) AS pending,
         SUM(CASE WHEN status='redeemed' THEN 1 ELSE 0 END) AS redeemed
       FROM nfc_tags WHERE business_id = ?`
    )
    .get(req.business.id);

  res.render('validate-dashboard', {
    business: req.business,
    tags,
    stats,
    flash: flashFromQuery(req),
  });
});

// Validate / redeem a code (JSON API)
app.post('/v/:slug/validate', requireValidator, (req, res) => {
  const code = ((req.body && req.body.code) || '').trim().toUpperCase();
  if (!code) return res.json({ success: false, message: 'Introduce un código.' });

  const tag = db
    .prepare(`SELECT * FROM nfc_tags WHERE business_id = ? AND UPPER(discount_code) = ?`)
    .get(req.business.id, code);

  if (!tag) {
    return res.json({ success: false, message: 'Código no encontrado para este negocio.' });
  }

  if (tag.status === 'redeemed') {
    return res.json({ success: false, message: 'Este código ya fue canjeado anteriormente.' });
  }
  if (tag.status === 'active') {
    return res.json({ success: false, message: 'Este código aún no ha sido reclamado por el cliente.' });
  }
  if (tag.status === 'disabled') {
    return res.json({ success: false, message: 'Este código está desactivado.' });
  }

  // status === 'claimed' → marcar como canjeado
  db.prepare(
    `UPDATE nfc_tags SET status = 'redeemed', redeemed_at = CURRENT_TIMESTAMP WHERE id = ?`
  ).run(tag.id);

  res.json({ success: true, message: `Código ${tag.discount_code} canjeado correctamente.` });
});

// Logout
app.get('/v/:slug/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${VALIDATOR_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
  res.redirect(`/v/${req.params.slug}`);
});

// ════════════════════════════════════════════════════════════════════════════════
// ADMIN: AUTH
// ════════════════════════════════════════════════════════════════════════════════

app.get('/admin/login', (req, res) => {
  res.render('admin-login', { error: null });
});

app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    setCookieAdmin(res);
    return res.redirect('/admin');
  }
  res.render('admin-login', { error: 'Contraseña incorrecta.' });
});

app.get('/admin/logout', (req, res) => {
  clearCookieAdmin(res);
  res.redirect('/admin/login');
});

// ════════════════════════════════════════════════════════════════════════════════
// ADMIN: DASHBOARD
// ════════════════════════════════════════════════════════════════════════════════

app.get('/admin', requireAdmin, (req, res) => {
  const businesses = db
    .prepare(
      `SELECT b.*,
              COUNT(t.id) AS tag_count,
              SUM(CASE WHEN t.status='claimed' THEN 1 ELSE 0 END) AS claimed_count
       FROM businesses b
       LEFT JOIN nfc_tags t ON t.business_id = b.id
       GROUP BY b.id
       ORDER BY b.created_at DESC`
    )
    .all();

  const stats = db
    .prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN status='active'                    THEN 1 ELSE 0 END) AS active,
         SUM(CASE WHEN status='claimed'                   THEN 1 ELSE 0 END) AS claimed,
         SUM(CASE WHEN status IN ('disabled','redeemed')  THEN 1 ELSE 0 END) AS disabled
       FROM nfc_tags`
    )
    .get();

  // Credenciales de negocio recién creado (query param creds_u / creds_p)
  const newCredentials = req.query.creds_u
    ? { username: String(req.query.creds_u).slice(0, 100), password: String(req.query.creds_p || '').slice(0, 50) }
    : null;

  res.render('admin', {
    businesses,
    stats,
    page: 'dashboard',
    flash: flashFromQuery(req),
    newCredentials,
    business: null,
    tags: null,
    baseUrl: BASE_URL,
  });
});

// ════════════════════════════════════════════════════════════════════════════════
// ADMIN: BUSINESSES — CREATE / EDIT / DELETE
// ════════════════════════════════════════════════════════════════════════════════

app.post('/admin/businesses', requireAdmin, (req, res) => {
  const { name, slug, logo_url, reward_text, validator_username, validator_password } = req.body;
  if (!name || !slug || !reward_text) {
    return redirectFlash(res, '/admin', 'error', 'Nombre, slug y texto de recompensa son obligatorios.');
  }

  const cleanSlug  = slug.toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const vUsername  = (validator_username || '').trim() || cleanSlug;
  const plainPass  = (validator_password || '').trim() || generatePassword();
  const hashedPass = bcrypt.hashSync(plainPass, 10);

  try {
    db.prepare(
      `INSERT INTO businesses (name, slug, logo_url, reward_text, validator_username, validator_password)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(name, cleanSlug, logo_url || null, reward_text, vUsername, hashedPass);

    // Mostrar credenciales si fueron autogeneradas (nunca guardamos la contraseña en plano)
    const autoGenerated = !(validator_password || '').trim();
    if (autoGenerated) {
      return res.redirect(
        `/admin?ok=${encodeURIComponent(`Negocio "${name}" creado correctamente`)}&creds_u=${encodeURIComponent(vUsername)}&creds_p=${encodeURIComponent(plainPass)}`
      );
    }
    redirectFlash(res, '/admin', 'success', `Negocio "${name}" creado correctamente`);
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return redirectFlash(res, '/admin', 'error', `El slug "${cleanSlug}" o usuario "${vUsername}" ya existen.`);
    }
    throw e;
  }
});

app.post('/admin/businesses/:id/edit', requireAdmin, (req, res) => {
  const { name, logo_url, reward_text, active, validator_username, validator_password } = req.body;

  const current = db.prepare(`SELECT * FROM businesses WHERE id=?`).get(req.params.id);
  if (!current) return res.redirect('/admin');

  const vUsername = (validator_username || '').trim() || current.validator_username;

  try {
    let info;
    if ((validator_password || '').trim()) {
      const hashed = bcrypt.hashSync(validator_password.trim(), 10);
      info = db.prepare(
        `UPDATE businesses SET name=?, logo_url=?, reward_text=?, active=?, validator_username=?, validator_password=? WHERE id=?`
      ).run(name, logo_url || null, reward_text, active === '1' ? 1 : 0, vUsername, hashed, req.params.id);
    } else {
      info = db.prepare(
        `UPDATE businesses SET name=?, logo_url=?, reward_text=?, active=?, validator_username=? WHERE id=?`
      ).run(name, logo_url || null, reward_text, active === '1' ? 1 : 0, vUsername, req.params.id);
    }

    if (info.changes === 0) return res.redirect('/admin');
    redirectFlash(res, `/admin/businesses/${req.params.id}`, 'success', 'Cambios guardados');
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return redirectFlash(res, `/admin/businesses/${req.params.id}`, 'error', `El usuario "${vUsername}" ya está en uso por otro negocio.`);
    }
    throw e;
  }
});

app.post('/admin/businesses/:id/delete', requireAdmin, (req, res) => {
  const business = db.prepare(`SELECT * FROM businesses WHERE id=?`).get(req.params.id);
  if (!business) return redirectFlash(res, '/admin', 'error', 'Negocio no encontrado.');

  db.transaction(() => {
    db.prepare(`DELETE FROM nfc_tags   WHERE business_id=?`).run(req.params.id);
    db.prepare(`DELETE FROM businesses WHERE id=?`).run(req.params.id);
  })();

  redirectFlash(res, '/admin', 'success', `Negocio "${business.name}" eliminado`);
});

// ════════════════════════════════════════════════════════════════════════════════
// ADMIN: BUSINESS DETAIL
// ════════════════════════════════════════════════════════════════════════════════

app.get('/admin/businesses/:id', requireAdmin, (req, res) => {
  const business = db.prepare(`SELECT * FROM businesses WHERE id=?`).get(req.params.id);
  if (!business) return res.redirect('/admin');

  const tags = db
    .prepare(`SELECT * FROM nfc_tags WHERE business_id=? ORDER BY discount_code`)
    .all(req.params.id);

  const stats = db
    .prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN status='active'                    THEN 1 ELSE 0 END) AS active,
         SUM(CASE WHEN status='claimed'                   THEN 1 ELSE 0 END) AS claimed,
         SUM(CASE WHEN status IN ('disabled','redeemed')  THEN 1 ELSE 0 END) AS disabled
       FROM nfc_tags WHERE business_id=?`
    )
    .get(req.params.id);

  res.render('admin', {
    businesses: null,
    business,
    tags,
    stats,
    page: 'business',
    flash: flashFromQuery(req),
    newCredentials: null,
    baseUrl: BASE_URL,
  });
});

// ─── Generate tags ────────────────────────────────────────────────────────────
app.post('/admin/businesses/:id/generate', requireAdmin, (req, res) => {
  const business = db.prepare(`SELECT * FROM businesses WHERE id=?`).get(req.params.id);
  if (!business) return res.redirect('/admin');

  const count   = Math.min(parseInt(req.body.count,   10) || 30, 200);
  const prefix  = (req.body.prefix || business.slug).replace(/[^A-Z0-9]/gi, '').toUpperCase();
  const startAt = parseInt(req.body.start_at, 10) || 1;

  const insert = db.prepare(
    `INSERT INTO nfc_tags (tag_code, business_id, discount_code) VALUES (?, ?, ?)`
  );
  db.transaction(() => {
    for (let i = 0; i < count; i++) {
      const num = String(startAt + i).padStart(3, '0');
      insert.run(uuidv4(), business.id, `${prefix}-${num}`);
    }
  })();

  redirectFlash(res, `/admin/businesses/${req.params.id}`, 'success', `${count} etiquetas generadas`);
});

// ─── Reset ALL tags of a business ────────────────────────────────────────────
app.post('/admin/businesses/:id/reset-all', requireAdmin, (req, res) => {
  const business = db.prepare(`SELECT * FROM businesses WHERE id=?`).get(req.params.id);
  if (!business) return res.redirect('/admin');

  const result = db.prepare(
    `UPDATE nfc_tags SET status='active', claimed_at=NULL, redeemed_at=NULL WHERE business_id=?`
  ).run(req.params.id);

  redirectFlash(
    res,
    `/admin/businesses/${req.params.id}`,
    'success',
    `${result.changes} etiqueta(s) reseteadas a "disponible"`
  );
});

// ─── Export CSV ───────────────────────────────────────────────────────────────
app.get('/admin/businesses/:id/export.csv', requireAdmin, (req, res) => {
  const business = db.prepare(`SELECT * FROM businesses WHERE id=?`).get(req.params.id);
  if (!business) return res.redirect('/admin');

  const tags = db
    .prepare(`SELECT * FROM nfc_tags WHERE business_id=? ORDER BY discount_code`)
    .all(req.params.id);

  const header = [
    csvCell('Codigo descuento'),
    csvCell('Tag UUID'),
    csvCell('Estado'),
    csvCell('Fecha reclamacion'),
    csvCell('Fecha canje'),
    csvCell('URL NFC'),
  ].join(',');

  const rows = tags.map(t => [
    csvCell(t.discount_code),
    csvCell(t.tag_code),
    csvCell(
      t.status === 'active'    ? 'Disponible' :
      t.status === 'claimed'   ? 'Reclamada'  :
      t.status === 'redeemed'  ? 'Canjeada'   : 'Desactivada'
    ),
    csvCell(t.claimed_at   || ''),
    csvCell(t.redeemed_at  || ''),
    csvCell(`${BASE_URL}/c/${t.tag_code}`),
  ].join(','));

  const csv      = [header, ...rows].join('\r\n');
  const filename = `${business.slug}-etiquetas.csv`;

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Cache-Control', 'no-store');
  res.send('﻿' + csv); // UTF-8 BOM para Excel
});

// ════════════════════════════════════════════════════════════════════════════════
// ADMIN: TAGS — INDIVIDUAL & BULK ACTIONS
// ════════════════════════════════════════════════════════════════════════════════

app.post('/admin/tags/:id/disable', requireAdmin, (req, res) => {
  const tag = db.prepare(`SELECT * FROM nfc_tags WHERE id=?`).get(req.params.id);
  if (!tag) return res.redirect('/admin');
  db.prepare(`UPDATE nfc_tags SET status='disabled' WHERE id=?`).run(req.params.id);
  res.redirect(`/admin/businesses/${tag.business_id}`);
});

app.post('/admin/tags/:id/enable', requireAdmin, (req, res) => {
  const tag = db.prepare(`SELECT * FROM nfc_tags WHERE id=?`).get(req.params.id);
  if (!tag) return res.redirect('/admin');
  db.prepare(`UPDATE nfc_tags SET status='active', claimed_at=NULL, redeemed_at=NULL WHERE id=?`).run(req.params.id);
  res.redirect(`/admin/businesses/${tag.business_id}`);
});

app.post('/admin/businesses/:id/tags/bulk-delete', requireAdmin, (req, res) => {
  const business = db.prepare(`SELECT id FROM businesses WHERE id=?`).get(req.params.id);
  if (!business) return res.status(404).json({ error: 'Negocio no encontrado.' });

  const raw = req.body.ids;
  if (!Array.isArray(raw) || raw.length === 0)
    return res.status(400).json({ error: 'No se seleccionaron etiquetas.' });

  const ids = raw.map(x => parseInt(x, 10)).filter(x => Number.isInteger(x) && x > 0);
  if (ids.length === 0) return res.status(400).json({ error: 'IDs inválidos.' });

  const placeholders = ids.map(() => '?').join(',');
  const result = db.transaction(() =>
    db.prepare(
      `DELETE FROM nfc_tags WHERE id IN (${placeholders}) AND business_id=?`
    ).run(...ids, business.id)
  )();

  res.json({ ok: true, deleted: result.changes });
});

app.post('/admin/businesses/:id/tags/bulk-reset', requireAdmin, (req, res) => {
  const business = db.prepare(`SELECT id FROM businesses WHERE id=?`).get(req.params.id);
  if (!business) return res.status(404).json({ error: 'Negocio no encontrado.' });

  const raw = req.body.ids;
  if (!Array.isArray(raw) || raw.length === 0)
    return res.status(400).json({ error: 'No se seleccionaron etiquetas.' });

  const ids = raw.map(x => parseInt(x, 10)).filter(x => Number.isInteger(x) && x > 0);
  if (ids.length === 0) return res.status(400).json({ error: 'IDs inválidos.' });

  const placeholders = ids.map(() => '?').join(',');
  const result = db.transaction(() =>
    db.prepare(
      `UPDATE nfc_tags SET status='active', claimed_at=NULL, redeemed_at=NULL
       WHERE id IN (${placeholders}) AND business_id=?`
    ).run(...ids, business.id)
  )();

  res.json({ ok: true, reset: result.changes });
});

// ─── Root redirect ────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.redirect('/admin'));

app.listen(PORT, () => {
  console.log(`NFC GO corriendo en ${BASE_URL}`);
});
