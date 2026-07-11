const express = require('express');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ── DB ──────────────────────────────────────────
let pool = null;
if (process.env.DATABASE_URL) {
  pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  pool.query(`
    CREATE TABLE IF NOT EXISTS tracker_state (
      id INTEGER PRIMARY KEY DEFAULT 1,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS access_tokens (
      token VARCHAR(64) PRIMARY KEY,
      stripe_session_id VARCHAR(200) UNIQUE,
      plan VARCHAR(20),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ,
      active BOOLEAN DEFAULT TRUE
    );
  `).then(() => console.log('DB ready')).catch(e => console.error('DB init:', e.message));
}

// ── STRIPE ──────────────────────────────────────
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  console.log('Stripe ready');
} else {
  console.warn('STRIPE_SECRET_KEY not set — payment wall disabled');
}

// ── WEBHOOK (raw body, must be before express.json) ──
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) return res.sendStatus(400);

  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error('Webhook signature error:', e.message);
    return res.sendStatus(400);
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    if (pool) {
      await pool.query(
        'UPDATE access_tokens SET active = FALSE WHERE stripe_session_id = $1',
        [sub.id]
      ).catch(e => console.error('webhook DB error:', e.message));
    }
  }

  if (event.type === 'invoice.paid') {
    const inv = event.data.object;
    if (pool && inv.subscription) {
      const newExpiry = new Date(Date.now() + 35 * 24 * 60 * 60 * 1000); // +35 days buffer
      await pool.query(
        'UPDATE access_tokens SET expires_at = $1, active = TRUE WHERE stripe_session_id = $2',
        [newExpiry, inv.subscription]
      ).catch(e => console.error('webhook DB error:', e.message));
    }
  }

  res.sendStatus(200);
});

// ── MIDDLEWARE ───────────────────────────────────
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH HELPER ──────────────────────────────────
async function isValidToken(token) {
  if (!pool || !token) return false;
  try {
    const r = await pool.query(
      'SELECT plan, expires_at FROM access_tokens WHERE token = $1 AND active = TRUE',
      [token]
    );
    if (!r.rows.length) return false;
    const { expires_at } = r.rows[0];
    if (expires_at && new Date() > new Date(expires_at)) return false;
    return true;
  } catch { return false; }
}

// ── ROUTES ───────────────────────────────────────

// Landing / Tracker (depends on auth state)
app.get('/', async (req, res) => {
  // No Stripe configured → serve tracker directly (dev mode)
  if (!stripe) {
    return res.sendFile(path.join(__dirname, 'protected', 'tracker.html'));
  }
  const token = req.cookies?.access_token;
  if (token && await isValidToken(token)) {
    return res.sendFile(path.join(__dirname, 'protected', 'tracker.html'));
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Create Stripe Checkout session
app.post('/api/checkout', async (req, res) => {
  if (!stripe) return res.status(400).json({ error: 'Stripe not configured' });

  const { plan } = req.body;
  const priceId = plan === 'monthly'
    ? process.env.STRIPE_PRICE_MONTHLY
    : process.env.STRIPE_PRICE_LIFETIME;

  if (!priceId) {
    return res.status(400).json({ error: `Price ID not set (STRIPE_PRICE_${plan === 'monthly' ? 'MONTHLY' : 'LIFETIME'})` });
  }

  const base = process.env.BASE_URL || `http://localhost:${PORT}`;

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: plan === 'monthly' ? 'subscription' : 'payment',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${base}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${base}/`,
      allow_promotion_codes: true,
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error('Checkout error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Success redirect after payment
app.get('/success', async (req, res) => {
  if (!stripe) return res.redirect('/');

  const { session_id } = req.query;
  if (!session_id) return res.redirect('/');

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);

    const paid = session.payment_status === 'paid'
      || session.mode === 'subscription';

    if (!paid) return res.redirect('/?denied=1');

    const token = crypto.randomBytes(32).toString('hex');
    const plan = session.mode === 'subscription' ? 'monthly' : 'lifetime';
    const subId = session.subscription || session_id;
    const expiresAt = plan === 'monthly'
      ? new Date(Date.now() + 35 * 24 * 60 * 60 * 1000)
      : null;

    if (pool) {
      await pool.query(
        `INSERT INTO access_tokens (token, stripe_session_id, plan, expires_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (stripe_session_id) DO NOTHING`,
        [token, subId, plan, expiresAt]
      );
    }

    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
    });
    res.redirect('/');
  } catch (e) {
    console.error('Success handler error:', e.message);
    res.redirect('/?denied=1');
  }
});

// Tracker state API (no extra auth — cookie already checked at route level)
app.get('/api/state', async (req, res) => {
  if (!pool) return res.json(null);
  try {
    const r = await pool.query('SELECT data FROM tracker_state WHERE id = 1');
    res.json(r.rows[0]?.data || null);
  } catch (e) {
    console.error('GET /api/state:', e.message);
    res.status(500).json(null);
  }
});

app.post('/api/state', async (req, res) => {
  if (!pool) return res.json({ ok: false });
  try {
    await pool.query(
      `INSERT INTO tracker_state (id, data, updated_at)
       VALUES (1, $1, NOW())
       ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = NOW()`,
      [req.body]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/state:', e.message);
    res.status(500).json({ ok: false });
  }
});

// Fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Running on port ${PORT}`));
