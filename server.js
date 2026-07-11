const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
const SESSION_DAYS = 30;

// ── DATABASE ─────────────────────────────────────
let pool = null;
if (process.env.DATABASE_URL) {
  pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  initDB();
}

async function initDB() {
  // Run each statement independently — one failure never rolls back others
  const run = async (sql, label) => {
    try { await pool.query(sql); }
    catch (e) { console.warn(`initDB [${label}]:`, e.message); }
  };

  await run(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`, 'users');

  await run(`CREATE TABLE IF NOT EXISTS sessions (
    token VARCHAR(64) PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
  )`, 'sessions');

  // Create access_tokens with minimal columns; add rest via ALTER
  await run(`CREATE TABLE IF NOT EXISTS access_tokens (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ
  )`, 'access_tokens');

  // Migrate: add any columns that might be missing from old schema
  await run(`ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS user_id INTEGER`, 'at.user_id');
  await run(`ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE`, 'at.active');
  await run(`ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS plan VARCHAR(20)`, 'at.plan');
  await run(`ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS stripe_session_id VARCHAR(200)`, 'at.sid');

  // tracker_state: check if user_id is already the primary key
  let needsReset = true;
  try {
    const r = await pool.query(`
      SELECT kcu.column_name
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON tc.constraint_name = kcu.constraint_name
        AND tc.table_schema = kcu.table_schema
      WHERE tc.table_name = 'tracker_state'
        AND tc.constraint_type = 'PRIMARY KEY'
        AND kcu.column_name = 'user_id'
    `);
    needsReset = r.rows.length === 0;
  } catch { /* table probably doesn't exist yet */ }

  if (needsReset) {
    await run(`DROP TABLE IF EXISTS tracker_state CASCADE`, 'drop tracker_state');
  }
  await run(`CREATE TABLE IF NOT EXISTS tracker_state (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`, 'tracker_state');

  console.log('DB ready');
}

// ── STRIPE ───────────────────────────────────────
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  console.log('Stripe ready');
}

// ── WEBHOOK (raw body — must be before express.json) ──
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) return res.sendStatus(400);
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return res.sendStatus(400);
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    await pool?.query('UPDATE access_tokens SET active = FALSE WHERE stripe_session_id = $1', [sub.id]).catch(() => {});
  }
  if (event.type === 'invoice.paid') {
    const inv = event.data.object;
    if (inv.subscription) {
      const exp = new Date(Date.now() + 35 * 24 * 60 * 60 * 1000);
      await pool?.query(
        'UPDATE access_tokens SET expires_at = $1, active = TRUE WHERE stripe_session_id = $2',
        [exp, inv.subscription]
      ).catch(() => {});
    }
  }

  res.sendStatus(200);
});

// ── MIDDLEWARE ────────────────────────────────────
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ── HELPERS ───────────────────────────────────────
function view(file) {
  return path.join(__dirname, 'views', file);
}
function protected_(file) {
  return path.join(__dirname, 'protected', file);
}

async function getSession(token) {
  if (!pool || !token) return null;
  try {
    const r = await pool.query(
      'SELECT user_id FROM sessions WHERE token = $1 AND expires_at > NOW()',
      [token]
    );
    return r.rows[0] || null;
  } catch { return null; }
}

async function hasAccess(userId) {
  if (!stripe) return true; // no Stripe = open access
  if (!pool || !userId) return false;
  try {
    const r = await pool.query(
      `SELECT id FROM access_tokens
       WHERE user_id = $1 AND active = TRUE
       AND (expires_at IS NULL OR expires_at > NOW())`,
      [userId]
    );
    return r.rows.length > 0;
  } catch { return false; }
}

async function createSession(userId, res) {
  const token = crypto.randomBytes(32).toString('hex');
  const exp = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await pool.query('INSERT INTO sessions (token, user_id, expires_at) VALUES ($1,$2,$3)', [token, userId, exp]);
  res.cookie('session_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000
  });
}

async function requireAuth(req, res, next) {
  const session = await getSession(req.cookies?.session_token);
  if (!session) return res.redirect('/login');
  req.userId = session.user_id;
  next();
}

// ── PAGE ROUTES ───────────────────────────────────

// Root: dispatch based on auth + access
app.get('/', async (req, res) => {
  const session = await getSession(req.cookies?.session_token);
  if (!session) return res.redirect('/login');
  if (await hasAccess(session.user_id)) {
    return res.sendFile(protected_('tracker.html'));
  }
  res.redirect('/pricing');
});

// Login / Register page
app.get('/login', async (req, res) => {
  const session = await getSession(req.cookies?.session_token);
  if (session) {
    return (await hasAccess(session.user_id))
      ? res.redirect('/')
      : res.redirect('/pricing');
  }
  res.sendFile(view('login.html'));
});

// Pricing page (must be logged in, no access yet)
app.get('/pricing', requireAuth, async (req, res) => {
  if (await hasAccess(req.userId)) return res.redirect('/');
  res.sendFile(view('pricing.html'));
});

// Logout
app.get('/logout', async (req, res) => {
  const token = req.cookies?.session_token;
  if (token && pool) {
    await pool.query('DELETE FROM sessions WHERE token = $1', [token]).catch(() => {});
  }
  res.clearCookie('session_token');
  res.redirect('/login');
});

// ── AUTH API ──────────────────────────────────────

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email?.trim() || !password) {
    return res.status(400).json({ error: 'Введи email и пароль' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  }
  if (!pool) return res.status(500).json({ error: 'БД не подключена' });

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const r = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
      [email.toLowerCase().trim(), hash]
    );
    await createSession(r.rows[0].id, res);
    res.json({ ok: true });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Этот email уже зарегистрирован' });
    console.error('register:', e.message);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email?.trim() || !password) {
    return res.status(400).json({ error: 'Введи email и пароль' });
  }
  if (!pool) return res.status(500).json({ error: 'БД не подключена' });

  try {
    const r = await pool.query(
      'SELECT id, password_hash FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );
    if (!r.rows.length) return res.status(401).json({ error: 'Неверный email или пароль' });

    const ok = await bcrypt.compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Неверный email или пароль' });

    await createSession(r.rows[0].id, res);
    res.json({ ok: true });
  } catch (e) {
    console.error('login:', e.message);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ── STRIPE API ────────────────────────────────────

app.post('/api/checkout', requireAuth, async (req, res) => {
  if (!stripe) return res.status(400).json({ error: 'Stripe не настроен' });

  const { plan } = req.body;
  const priceId = plan === 'monthly'
    ? process.env.STRIPE_PRICE_MONTHLY
    : process.env.STRIPE_PRICE_LIFETIME;

  if (!priceId) {
    return res.status(400).json({ error: `Не задан STRIPE_PRICE_${plan === 'monthly' ? 'MONTHLY' : 'LIFETIME'}` });
  }

  const proto = req.headers['x-forwarded-proto'] || 'https';
  const base = process.env.BASE_URL || `${proto}://${req.headers.host}`;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: plan === 'monthly' ? 'subscription' : 'payment',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${base}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${base}/pricing`,
      metadata: { user_id: String(req.userId) },
      allow_promotion_codes: true,
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error('checkout:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// /success serves a page that calls /api/grant-access via AJAX.
// AJAX from same origin always sends cookies — no cross-site cookie issue.
app.get('/success', (req, res) => {
  const sid = (req.query.session_id || '').replace(/[^a-zA-Z0-9_-]/g, '');
  if (!sid) return res.redirect('/login');
  res.send(`<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8"><title>Проверка оплаты</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:Inter,sans-serif;background:#080810;color:#e2e8f0;
       min-height:100vh;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:16px;padding:20px}
  .spin{width:44px;height:44px;border:3px solid rgba(124,58,237,.25);
        border-top-color:#7c3aed;border-radius:50%;animation:s .8s linear infinite}
  @keyframes s{to{transform:rotate(360deg)}}
  #msg{font-size:1rem;color:#94a3b8;text-align:center}
  #err{color:#f87171;font-size:.875rem;text-align:center;display:none;max-width:340px}
  .btn{margin-top:8px;padding:13px 28px;background:#7c3aed;color:#fff;border:none;
       border-radius:10px;cursor:pointer;font-size:1rem;font-weight:600;display:none}
</style></head>
<body>
  <div class="spin" id="spin"></div>
  <p id="msg">Проверяем оплату…</p>
  <p id="err"></p>
  <button class="btn" id="btn" onclick="grant()">Повторить</button>
<script>
const SID = '${sid}';
async function grant() {
  document.getElementById('spin').style.display = 'block';
  document.getElementById('msg').textContent = 'Проверяем оплату…';
  document.getElementById('err').style.display = 'none';
  document.getElementById('btn').style.display = 'none';
  try {
    const r = await fetch('/api/grant-access', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({session_id: SID})
    });
    const d = await r.json();
    if (d.ok) {
      document.getElementById('msg').textContent = 'Готово! Открываем трекер…';
      setTimeout(() => location.href = '/', 600);
    } else if (d.login) {
      document.getElementById('msg').textContent = 'Оплата принята. Войдите в аккаунт.';
      setTimeout(() => location.href = '/login?paid=1', 800);
    } else {
      throw new Error(d.error || 'Неизвестная ошибка');
    }
  } catch(e) {
    document.getElementById('spin').style.display = 'none';
    document.getElementById('err').textContent = 'Ошибка: ' + e.message;
    document.getElementById('err').style.display = 'block';
    document.getElementById('btn').style.display = 'inline-block';
    document.getElementById('msg').textContent = '';
  }
}
grant();
</script>
</body></html>`);
});

app.post('/api/grant-access', async (req, res) => {
  if (!stripe) return res.json({ ok: true });

  const { session_id } = req.body || {};
  if (!session_id) return res.status(400).json({ ok: false, error: 'No session_id' });

  try {
    const ss = await stripe.checkout.sessions.retrieve(session_id);
    const paid = ss.payment_status === 'paid' || ss.mode === 'subscription';
    if (!paid) return res.json({ ok: false, error: `payment_status=${ss.payment_status}` });

    const userId = parseInt(ss.metadata?.user_id, 10);
    if (!userId || isNaN(userId)) {
      return res.json({ ok: false, error: 'No user_id in Stripe metadata' });
    }

    const plan = ss.mode === 'subscription' ? 'monthly' : 'lifetime';
    const subId = ss.subscription || session_id;
    const expiresAt = plan === 'monthly' ? new Date(Date.now() + 35 * 24 * 60 * 60 * 1000) : null;

    if (pool) {
      const ex = await pool.query('SELECT id FROM access_tokens WHERE stripe_session_id = $1', [subId]);
      if (!ex.rows.length) {
        await pool.query(
          `INSERT INTO access_tokens (user_id, stripe_session_id, plan, expires_at, active)
           VALUES ($1,$2,$3,$4,TRUE)`,
          [userId, subId, plan, expiresAt]
        );
        console.log(`Access granted: user=${userId} plan=${plan}`);
      }
    }

    const authSession = await getSession(req.cookies?.session_token);
    if (authSession) return res.json({ ok: true });
    return res.json({ ok: false, login: true });
  } catch (e) {
    console.error('grant-access error:', e.message, e.detail || '');
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ── TRACKER STATE API ─────────────────────────────

app.get('/api/state', requireAuth, async (req, res) => {
  if (!pool) return res.json(null);
  try {
    const r = await pool.query('SELECT data FROM tracker_state WHERE user_id = $1', [req.userId]);
    res.json(r.rows[0]?.data || null);
  } catch (e) {
    console.error('GET state:', e.message);
    res.status(500).json(null);
  }
});

app.post('/api/state', requireAuth, async (req, res) => {
  if (!pool) return res.json({ ok: false });
  try {
    await pool.query(
      `INSERT INTO tracker_state (user_id, data, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (user_id) DO UPDATE SET data = $2, updated_at = NOW()`,
      [req.userId, req.body]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('POST state:', e.message);
    res.status(500).json({ ok: false });
  }
});

// Status check
app.get('/ping', (req, res) => {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const base = process.env.BASE_URL || `${proto}://${req.headers.host}`;
  res.json({
    ok: true,
    version: '2026-07-11-v5',
    base_url: base,
    stripe: !!stripe,
    db: !!pool,
    base_url_env: process.env.BASE_URL || null,
  });
});

// Fallback
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, () => console.log(`Running on port ${PORT}`));
