const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let pool = null;

if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  pool.query(`
    CREATE TABLE IF NOT EXISTS tracker_state (
      id INTEGER PRIMARY KEY DEFAULT 1,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `).then(() => console.log('DB ready'))
    .catch(e => console.error('DB init error:', e));
} else {
  console.warn('DATABASE_URL not set — running without sync (localStorage only)');
}

app.get('/api/state', async (req, res) => {
  if (!pool) return res.json(null);
  try {
    const result = await pool.query('SELECT data FROM tracker_state WHERE id = 1');
    res.json(result.rows[0]?.data || null);
  } catch (e) {
    console.error('GET /api/state error:', e.message);
    res.status(500).json(null);
  }
});

app.post('/api/state', async (req, res) => {
  if (!pool) return res.json({ ok: false });
  try {
    await pool.query(`
      INSERT INTO tracker_state (id, data, updated_at)
      VALUES (1, $1, NOW())
      ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = NOW()
    `, [req.body]);
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/state error:', e.message);
    res.status(500).json({ ok: false });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Finance tracker running on port ${PORT}`));
