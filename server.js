import express from 'express'; import cors from 'cors'; import pg from 'pg';
import jwt from 'jsonwebtoken'; import bcrypt from 'bcryptjs';
import path from 'path'; import { fileURLToPath } from 'url';
const { DATABASE_URL, JWT_SECRET, ADMIN_USER, ADMIN_PASS, PORT = 3000 } = process.env;
if (!DATABASE_URL || !JWT_SECRET || !ADMIN_USER || !ADMIN_PASS) throw new Error('Set DATABASE_URL, JWT_SECRET, ADMIN_USER, ADMIN_PASS');
const pool = new pg.Pool({ connectionString: DATABASE_URL, max: 10, ssl: { rejectUnauthorized: false } });
const q = (s, p) => pool.query(s, p).then(r => r.rows);
await q(`CREATE TABLE IF NOT EXISTS polls(id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, active BOOLEAN DEFAULT FALSE);
CREATE TABLE IF NOT EXISTS records(id SERIAL PRIMARY KEY, poll_id INT REFERENCES polls ON DELETE CASCADE, label TEXT NOT NULL, pos INT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS journeys(id SERIAL PRIMARY KEY, poll_id INT REFERENCES polls ON DELETE CASCADE, date DATE NOT NULL, source TEXT, destination TEXT, direction TEXT DEFAULT 'onward', status TEXT DEFAULT 'planned', current_record_id INT REFERENCES records ON DELETE SET NULL);
CREATE TABLE IF NOT EXISTS messages(id SERIAL PRIMARY KEY, sender TEXT NOT NULL, sender_key TEXT NOT NULL, body TEXT NOT NULL, edited BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT now());
ALTER TABLE journeys ADD COLUMN IF NOT EXISTS reached_at TIMESTAMPTZ;
ALTER TABLE records ADD COLUMN IF NOT EXISTS is_pickup BOOLEAN DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS r_poll ON records(poll_id,pos); CREATE INDEX IF NOT EXISTS j_poll ON journeys(poll_id,date);`);

const app = express(); app.use(cors(), express.json({ limit: '2mb' }));
const h = f => (req, res) => f(req, res).catch(e => res.status(e.code === '23505' ? 409 : 500).json({ error: e.code === '23505' ? 'Name or username already exists' : e.message }));
const auth = (req, res, next) => { try { req.user = jwt.verify((req.headers.authorization || '').slice(7) || req.query.token, JWT_SECRET); next(); } catch { res.status(401).json({ error: 'Please sign in' }); } };
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });
const sign = u => jwt.sign(u, JWT_SECRET, { expiresIn: '12h' });

// live updates (SSE)
const clients = new Set();
let ver = 0, cache = null;
const push = (ev, data = {}) => { if (ev === 'state') ver++; clients.forEach(c => c.write(`event: ${ev}\ndata: ${JSON.stringify(data)}\n\n`)); };
app.get('/api/stream', auth, (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' }).flushHeaders();
  clients.add(res); const t = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => { clearInterval(t); clients.delete(res); });
});

app.post('/api/login', h(async (req, res) => {
  const { username = '', password = '' } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) { const u = { role: 'admin', name: 'Admin', key: 'admin' }; return res.json({ token: sign(u), user: u }); }
  const [p] = await q('SELECT * FROM polls WHERE username=$1', [username]);
  if (!p || !(await bcrypt.compare(password, p.password_hash))) return res.status(401).json({ error: 'Wrong username or password' });
  const u = { role: 'poll', pollId: p.id, name: p.name, key: 'p' + p.id }; res.json({ token: sign(u), user: u });
}));

// one shared, versioned snapshot: 50 clients refreshing at once cost one DB round trip
const snapshot = () => {
  if (cache && cache.v === ver) return cache.p;
  const v = ver, p = Promise.all([
    q('SELECT id,name,username,active FROM polls ORDER BY id'), q('SELECT id,poll_id,label,pos,is_pickup FROM records ORDER BY pos,id'),
    q(`SELECT id,poll_id,to_char(date,'YYYY-MM-DD') date,source,destination,direction,status,current_record_id,reached_at FROM journeys ORDER BY date,id`)]);
  cache = { v, p }; p.catch(() => { if (cache?.p === p) cache = null; }); return p;
};
app.get('/api/state', auth, h(async (req, res) => {
  const [polls, records, journeys] = await snapshot(), adm = req.user.role === 'admin';
  res.json({ polls: polls.map(p => ({ ...p, username: adm ? p.username : undefined, records: records.filter(r => r.poll_id === p.id), journeys: journeys.filter(j => j.poll_id === p.id) })) });
}));

// polls CRUD (single or bulk)
app.post('/api/polls', auth, admin, h(async (req, res) => {
  const list = req.body.polls || [req.body]; let n = 0;
  for (const p of list) { if (!p.name || !p.username || !p.password) continue;
    await q('INSERT INTO polls(name,username,password_hash) VALUES($1,$2,$3)', [p.name.trim(), p.username.trim(), await bcrypt.hash(p.password, 10)]); n++; }
  push('state'); res.json({ added: n });
}));
app.put('/api/polls/:id', auth, admin, h(async (req, res) => {
  const { name, username, password, active } = req.body;
  await q('UPDATE polls SET name=COALESCE($2,name),username=COALESCE($3,username),password_hash=COALESCE($4,password_hash),active=COALESCE($5,active) WHERE id=$1',
    [req.params.id, name, username, password ? await bcrypt.hash(password, 10) : null, active]);
  push('state'); res.json({ ok: 1 });
}));
app.delete('/api/polls/:id', auth, admin, h(async (req, res) => { await q('DELETE FROM polls WHERE id=$1', [req.params.id]); push('state'); res.json({ ok: 1 }); }));

// records CRUD (labels[] = bulk)
app.post('/api/polls/:id/records', auth, admin, h(async (req, res) => {
  const labels = (req.body.labels || []).map(l => String(l).trim()).filter(Boolean);
  const [{ m }] = await q('SELECT COALESCE(MAX(pos),0) m FROM records WHERE poll_id=$1', [req.params.id]);
  if (labels.length) await q('INSERT INTO records(poll_id,label,pos) SELECT $1,l,$2+o FROM unnest($3::text[]) WITH ORDINALITY t(l,o)', [req.params.id, m, labels]);
  push('state'); res.json({ added: labels.length });
}));
app.put('/api/records/:id', auth, admin, h(async (req, res) => { await q('UPDATE records SET label=COALESCE($2,label),pos=COALESCE($3,pos),is_pickup=COALESCE($4,is_pickup) WHERE id=$1', [req.params.id, req.body.label, req.body.pos, req.body.is_pickup]); push('state'); res.json({ ok: 1 }); }));
app.delete('/api/records/:id', auth, admin, h(async (req, res) => { await q('DELETE FROM records WHERE id=$1', [req.params.id]); push('state'); res.json({ ok: 1 }); }));

// journeys (controls)
app.post('/api/journeys', auth, admin, h(async (req, res) => {
  const { poll_id, date, source, destination } = req.body;
  await q('INSERT INTO journeys(poll_id,date,source,destination) VALUES($1,$2,$3,$4)', [poll_id, date, source, destination]); push('state'); res.json({ ok: 1 });
}));
app.put('/api/journeys/:id', auth, admin, h(async (req, res) => {
  const { date, source, destination, status } = req.body;
  if (status === 'active') await q(`UPDATE journeys SET status='planned' WHERE status='active' AND poll_id=(SELECT poll_id FROM journeys WHERE id=$1)`, [req.params.id]);
  await q(`UPDATE journeys SET date=COALESCE($2,date),source=COALESCE($3,source),destination=COALESCE($4,destination),status=COALESCE($5,status),
    current_record_id=CASE WHEN $5='active' THEN NULL ELSE current_record_id END WHERE id=$1`, [req.params.id, date, source, destination, status]);
  push('state'); res.json({ ok: 1 });
}));
app.post('/api/journeys/:id/return', auth, admin, h(async (req, res) => {
  const [j] = await q('SELECT * FROM journeys WHERE id=$1', [req.params.id]);
  if (!j || j.status !== 'completed') return res.status(400).json({ error: 'Complete the journey first' });
  await q(`INSERT INTO journeys(poll_id,date,source,destination,direction) VALUES($1,$2,$3,$4,$5)`,
    [j.poll_id, req.body.date || new Date(), j.destination, j.source, j.direction === 'return' ? 'onward' : 'return']);
  push('state'); res.json({ ok: 1 });
}));
app.delete('/api/journeys/:id', auth, admin, h(async (req, res) => { await q('DELETE FROM journeys WHERE id=$1', [req.params.id]); push('state'); res.json({ ok: 1 }); }));

// ticking spots: the journey row is locked, so simultaneous taps are handled one at a time and the earliest wins
app.post('/api/polls/:id/position', auth, h(async (req, res) => {
  const id = +req.params.id;
  if (req.user.role !== 'admin' && req.user.pollId !== id) return res.status(403).json({ error: 'You can only change your own bus' });
  const c = await pool.connect(); let out = [500, { error: 'Failed' }], note = null;
  try {
    await c.query('BEGIN');
    const { rows: [j] } = await c.query(`SELECT * FROM journeys WHERE poll_id=$1 AND status='active' ORDER BY id LIMIT 1 FOR UPDATE`, [id]);
    if (!j) out = [400, { error: 'No active journey. Ask the admin to start one.' }];
    else {
      const { rows: rs } = await c.query('SELECT id,label FROM records WHERE poll_id=$1 ORDER BY pos,id', [id]); if (j.direction === 'return') rs.reverse();
      const cur = rs.findIndex(r => r.id === j.current_record_id), now = cur >= 0 ? rs[cur].label : 'the start';
      let to; // new current record id, or undefined = no change
      if (req.body.undo) {
        if (cur < 0 || req.body.from !== j.current_record_id) out = [409, { error: `Already changed by someone on your bus. Now at ${now}` }];
        else { to = cur > 0 ? rs[cur - 1].id : null; note = `Correction: not yet at ${rs[cur].label}`; }
      } else {
        const i = rs.findIndex(r => r.id === req.body.record_id);
        if (i < 0) out = [400, { error: 'Unknown spot' }];
        else if (i <= cur) out = [200, { ok: 1, same: true }];
        else if (i > cur + 1) out = [409, { error: `Someone on your bus marked a spot first. Now at ${now}` }];
        else { to = rs[i].id; note = 'Reached: ' + rs[i].label; }
      }
      if (to !== undefined) {
        await c.query('UPDATE journeys SET current_record_id=$2,reached_at=now() WHERE id=$1', [j.id, to]);
        await c.query('INSERT INTO messages(sender,sender_key,body) VALUES($1,$2,$3)', [req.user.name, req.user.key, note]); out = [200, { ok: 1 }];
      }
    }
    await c.query('COMMIT');
  } catch (e) { await c.query('ROLLBACK').catch(() => 0); throw e; } finally { c.release(); }
  if (note && out[0] === 200) { push('state'); push('msg', { sender: req.user.name, body: note, reached: true }); }
  res.status(out[0]).json(out[1]);
}));

// messages CRUD
app.get('/api/messages', auth, h(async (req, res) => res.json(await q('SELECT * FROM (SELECT * FROM messages ORDER BY id DESC LIMIT 100) m ORDER BY id'))));
app.post('/api/messages', auth, h(async (req, res) => {
  const body = String(req.body.body || '').trim().slice(0, 1000); if (!body) return res.status(400).json({ error: 'Empty message' });
  await q('INSERT INTO messages(sender,sender_key,body) VALUES($1,$2,$3)', [req.user.name, req.user.key, body]);
  push('msg', { sender: req.user.name, body }); res.json({ ok: 1 });
}));
app.put('/api/messages/:id', auth, h(async (req, res) => { await q('UPDATE messages SET body=$3,edited=true WHERE id=$1 AND sender_key=$2', [req.params.id, req.user.key, String(req.body.body).slice(0, 1000)]); push('msg'); res.json({ ok: 1 }); }));
app.delete('/api/messages', auth, admin, h(async (req, res) => { await q('DELETE FROM messages'); push('msg'); res.json({ ok: 1 }); }));
app.delete('/api/messages/:id', auth, h(async (req, res) => {
  if (req.user.role === 'admin') await q('DELETE FROM messages WHERE id=$1', [req.params.id]); else await q('DELETE FROM messages WHERE id=$1 AND sender_key=$2', [req.params.id, req.user.key]);
  push('msg'); res.json({ ok: 1 });
}));

const dist = path.join(path.dirname(fileURLToPath(import.meta.url)), '../frontend/dist/browser');
app.use(express.static(dist, { maxAge: '1h' })); app.get(/^\/(?!api).*/, (_, res) => res.sendFile(path.join(dist, 'index.html')));
app.listen(PORT, () => console.log('Poll running on :' + PORT));
