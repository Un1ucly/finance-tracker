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
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sessions (
        token VARCHAR(64) PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL
      );
      CREATE TABLE IF NOT EXISTS access_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        stripe_session_id VARCHAR(200) UNIQUE,
        plan VARCHAR(20),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ,
        active BOOLEAN DEFAULT TRUE
      );
      CREATE TABLE IF NOT EXISTS tracker_state (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        data JSONB NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log('DB ready');
  } catch (e) {
    console.error('DB init error:', e.message);
  }
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

  const base = process.env.BASE_URL || `http://localhost:${PORT}`;
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

app.get('/success', requireAuth, async (req, res) => {
  if (!stripe) return res.redirect('/');

  const { session_id } = req.query;
  if (!session_id) return res.redirect('/pricing');

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    const paid = session.payment_status === 'paid' || session.mode === 'subscription';
    if (!paid) return res.redirect('/pricing?error=1');

    const plan = session.mode === 'subscription' ? 'monthly' : 'lifetime';
    const subId = session.subscription || session_id;
    const expiresAt = plan === 'monthly' ? new Date(Date.now() + 35 * 24 * 60 * 60 * 1000) : null;

    if (pool) {
      await pool.query(
        `INSERT INTO access_tokens (user_id, stripe_session_id, plan, expires_at)
         VALUES ($1, $2, $3, $4) ON CONFLICT (stripe_session_id) DO NOTHING`,
        [req.userId, subId, plan, expiresAt]
      );
    }
    res.redirect('/');
  } catch (e) {
    console.error('success:', e.message);
    res.redirect('/pricing');
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

// Fallback
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, () => console.log(`Running on port ${PORT}`));
