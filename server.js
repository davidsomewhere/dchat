const express = require('express'), http = require('http'), crypto = require('crypto');
const { WebSocketServer } = require('ws'), bcrypt = require('bcryptjs');

// Zero setup: data lives in ./data (embedded Postgres). If DATABASE_URL is set, an external Postgres is used instead.
let q, exec;
async function connect() {
  if (process.env.DATABASE_URL) {
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    pool.on('error', e => console.error('pg', e.message));
    q = (s, p) => pool.query(s, p).then(r => r.rows); exec = q;
  } else {
    const { PGlite } = await import('@electric-sql/pglite');
    const db = new PGlite('./data'); await db.waitReady;
    q = (s, p) => db.query(s, p).then(r => r.rows); exec = s => db.exec(s);
  }
}
const rid = n => crypto.randomBytes(n).toString('hex');
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));
app.get('/health', (_, r) => r.send('ok'));

const OWNER = 'davidsomewhere', isOwner = u => u.username.toLowerCase() === OWNER;
const pub = u => ({ owner: isOwner(u), id: u.id, username: u.username, bio: u.bio, pfp: u.pfp, banner: u.banner, theme: u.theme, color: u.color });
const auth = async (req, res, next) => {
  const t = req.get('x-token');
  const r = t && await q('SELECT u.* FROM sessions s JOIN users u ON u.id=s.uid WHERE token=$1', [t]);
  if (!r || !r[0]) return res.status(401).json({ error: 'Please log in again.' });
  if (r[0].banned) return res.status(403).json({ error: 'This account is banned.' });
  req.u = r[0]; next();
};
const hits = {};
const limit = (req, res, next) => { const k = req.ip, n = Date.now(); hits[k] = (hits[k] || []).filter(t => n - t < 60000); if (hits[k].length >= 12) return res.status(429).json({ error: 'Too many tries. Wait a minute.' }); hits[k].push(n); next(); };
app.use(['/api/login', '/api/register'], limit);
const wrap = f => (req, res) => f(req, res).catch(e => { console.error(e); if (e.code === '23505') return res.status(400).json({ error: 'Username is taken.' }); res.status(500).json({ error: 'Server error.' }); });
const isMember = async (uid, sid) => (await q('SELECT 1 FROM members WHERE sid=$1 AND uid=$2', [sid, uid])).length > 0;
const session = async uid => { const t = rid(24); await q('INSERT INTO sessions(token,uid) VALUES($1,$2)', [t, uid]); return t; };

app.post('/api/register', wrap(async (req, res) => {
  const { username, password } = req.body;
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username || '')) return res.status(400).json({ error: 'Username: 3-20 letters, numbers or _.' });
  if ((password || '').length < 6) return res.status(400).json({ error: 'Password needs at least 6 characters.' });
  if ((await q('SELECT 1 FROM users WHERE lower(username)=lower($1)', [username])).length) return res.status(400).json({ error: 'Username is taken.' });
  const [u] = await q('INSERT INTO users(username,pass) VALUES($1,$2) RETURNING *', [username, await bcrypt.hash(password, 10)]);
  res.json({ token: await session(u.id), user: pub(u) });
}));
app.post('/api/login', wrap(async (req, res) => {
  const [u] = await q('SELECT * FROM users WHERE lower(username)=lower($1)', [req.body.username || '']);
  if (!u || !(await bcrypt.compare(req.body.password || '', u.pass))) return res.status(400).json({ error: 'Wrong username or password.' });
  if (u.banned) return res.status(403).json({ error: 'This account is banned.' });
  res.json({ token: await session(u.id), user: pub(u) });
}));
app.get('/api/me', auth, (req, res) => res.json(pub(req.u)));
app.patch('/api/me', auth, wrap(async (req, res) => {
  const b = req.body, u = req.u;
  const [n] = await q('UPDATE users SET bio=$1,pfp=$2,banner=$3,theme=$4,color=$5 WHERE id=$6 RETURNING *',
    [(b.bio ?? u.bio).slice(0, 200), b.pfp ?? u.pfp, b.banner ?? u.banner, b.theme ?? u.theme, b.color ?? u.color, u.id]);
  res.json(pub(n));
}));

const serversFor = async uid => {
  const s = await q('SELECT s.* FROM servers s JOIN members m ON m.sid=s.id WHERE m.uid=$1 ORDER BY s.id', [uid]);
  for (const x of s) x.channels = await q('SELECT id,name FROM channels WHERE sid=$1 ORDER BY id', [x.id]);
  return s;
};
app.get('/api/servers', auth, wrap(async (req, res) => res.json(await serversFor(req.u.id))));
app.post('/api/servers', auth, wrap(async (req, res) => {
  const name = (req.body.name || '').trim().slice(0, 40);
  if (!name) return res.status(400).json({ error: 'Give the server a name.' });
  const [s] = await q('INSERT INTO servers(name,invite,owner,icon) VALUES($1,$2,$3,$4) RETURNING *', [name, rid(4), req.u.id, req.body.icon || null]);
  await q('INSERT INTO members(sid,uid) VALUES($1,$2)', [s.id, req.u.id]);
  await q("INSERT INTO channels(sid,name) VALUES($1,'general')", [s.id]);
  res.json(await serversFor(req.u.id));
}));
app.post('/api/join', auth, wrap(async (req, res) => {
  const [s] = await q('SELECT id FROM servers WHERE invite=$1', [(req.body.invite || '').trim()]);
  if (!s) return res.status(404).json({ error: 'Invite code not found.' });
  await q('INSERT INTO members(sid,uid) VALUES($1,$2) ON CONFLICT DO NOTHING', [s.id, req.u.id]);
  res.json(await serversFor(req.u.id));
}));
app.post('/api/servers/:id/channels', auth, wrap(async (req, res) => {
  const [s] = await q('SELECT * FROM servers WHERE id=$1', [req.params.id]);
  if (!s || s.owner !== req.u.id) return res.status(403).json({ error: 'Only the owner can add channels.' });
  const name = (req.body.name || '').toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, 30);
  if (!name) return res.status(400).json({ error: 'Give the channel a name.' });
  await q('INSERT INTO channels(sid,name) VALUES($1,$2)', [s.id, name]);
  res.json(await serversFor(req.u.id));
}));
app.get('/api/servers/:id/members', auth, wrap(async (req, res) => {
  if (!(await isMember(req.u.id, req.params.id))) return res.status(403).json({ error: 'Not a member.' });
  res.json((await q('SELECT u.* FROM users u JOIN members m ON m.uid=u.id WHERE m.sid=$1', [req.params.id])).map(pub));
}));
app.get('/api/channels/:id/messages', auth, wrap(async (req, res) => {
  const [c] = await q('SELECT sid FROM channels WHERE id=$1', [req.params.id]);
  if (!c || !(await isMember(req.u.id, c.sid))) return res.status(403).json({ error: 'No access.' });
  const rows = await q(`SELECT * FROM (SELECT m.id,m.body,m.file,m.ts,u.username,u.pfp,u.color,(lower(u.username)='davidsomewhere') AS owner FROM messages m JOIN users u ON u.id=m.uid
    WHERE m.cid=$1 ORDER BY m.id DESC LIMIT 100) x ORDER BY id`, [req.params.id]);
  res.json(rows);
}));

// Uploads are stored in Postgres too (survive restarts). 25 MB limit keeps the free DB from filling up.
app.post('/api/upload', auth, express.raw({ type: () => true, limit: '25mb' }), wrap(async (req, res) => {
  const mime = req.get('content-type') || '';
  if (!/^(image|video|audio)\//.test(mime) || !req.body.length) return res.status(400).json({ error: 'Upload an image, video or audio file.' });
  const id = rid(12);
  await q('INSERT INTO files(id,mime,data) VALUES($1,$2,$3)', [id, mime, req.body]);
  res.json({ url: '/media/' + id, mime });
}));
app.get('/media/:id', wrap(async (req, res) => {
  const [f] = await q('SELECT mime,data FROM files WHERE id=$1', [req.params.id]);
  if (!f) return res.sendStatus(404);
  f.data = Buffer.from(f.data);
  const n = f.data.length, h = { 'content-type': f.mime, 'cache-control': 'public, max-age=31536000, immutable', 'accept-ranges': 'bytes' };
  const m = /bytes=(\d*)-(\d*)/.exec(req.get('range') || '');
  if (!m) return res.set(h).send(f.data);
  let a = m[1] ? +m[1] : n - +m[2], b = m[1] && m[2] ? Math.min(+m[2], n - 1) : n - 1;
  if (a > b || a >= n) return res.status(416).set('content-range', 'bytes */' + n).end();
  res.status(206).set({ ...h, 'content-range': `bytes ${a}-${b}/${n}`, 'content-length': b - a + 1 }).send(f.data.subarray(a, b + 1));
}));

// Messages: author or owner can delete
app.delete('/api/messages/:id', auth, wrap(async (req, res) => {
  const [m] = await q('SELECT uid FROM messages WHERE id=$1', [req.params.id]);
  if (!m) return res.json({ ok: 1 });
  if (m.uid !== req.u.id && !isOwner(req.u)) return res.status(403).json({ error: 'Not your message.' });
  await q('DELETE FROM messages WHERE id=$1', [req.params.id]);
  wss.clients.forEach(c => c.readyState === 1 && c.send(JSON.stringify({ del: +req.params.id })));
  res.json({ ok: 1 });
}));

// Owner admin panel
const adm = (req, res, next) => isOwner(req.u) ? next() : res.status(403).json({ error: 'Owner only.' });
app.get('/api/admin', auth, adm, wrap(async (req, res) => {
  const [c] = await q("SELECT (SELECT count(*) FROM users)::int u,(SELECT count(*) FROM servers)::int s,(SELECT count(*) FROM messages)::int m,(SELECT coalesce(sum(length(data)),0)/1048576 FROM files)::int mb");
  const users = (await q('SELECT * FROM users ORDER BY id')).map(u => ({ ...pub(u), banned: u.banned }));
  const servers = await q('SELECT s.id,s.name,(SELECT count(*) FROM members WHERE sid=s.id)::int members FROM servers s ORDER BY id');
  res.json({ stats: { users: c.u, servers: c.s, messages: c.m, mb: c.mb }, users, servers });
}));
const TABLES = ['users', 'servers', 'members', 'channels', 'messages', 'files'];
app.get('/api/admin/backup', auth, adm, wrap(async (req, res) => {
  const out = {};
  for (const t of TABLES) out[t] = await q(t === 'files' ? "SELECT id,mime,'\\x'||encode(data,'hex') AS data FROM files" : `SELECT * FROM ${t}`);
  res.set({ 'content-type': 'application/json', 'content-disposition': 'attachment; filename="d-chat-backup.json"' }).send(JSON.stringify(out));
}));
app.post('/api/admin/restore', auth, adm, express.raw({ type: () => true, limit: '300mb' }), wrap(async (req, res) => {
  const d = JSON.parse(req.body.toString());
  await q('TRUNCATE ' + TABLES.join(',') + ',sessions CASCADE');
  for (const t of TABLES) if (d[t]?.length) await q(`INSERT INTO ${t} SELECT * FROM jsonb_populate_recordset(null::${t}, $1::jsonb)`, [JSON.stringify(d[t])]);
  for (const t of ['users', 'servers', 'channels', 'messages']) await q(`SELECT setval(pg_get_serial_sequence('${t}','id'),(SELECT coalesce(max(id),1) FROM ${t}))`);
  res.json({ ok: 1 });
}));
app.post('/api/admin/users/:id/ban', auth, adm, wrap(async (req, res) => {
  const [u] = await q('UPDATE users SET banned=$1 WHERE id=$2 AND lower(username)<>$3 RETURNING id', [!!req.body.banned, req.params.id, OWNER]);
  if (u && req.body.banned) { await q('DELETE FROM sessions WHERE uid=$1', [u.id]); wss.clients.forEach(c => c.uid === u.id && c.close()); }
  res.json({ ok: 1 });
}));
app.delete('/api/admin/users/:id', auth, adm, wrap(async (req, res) => {
  await q('DELETE FROM users WHERE id=$1 AND lower(username)<>$2', [req.params.id, OWNER]); res.json({ ok: 1 });
}));
app.delete('/api/admin/servers/:id', auth, adm, wrap(async (req, res) => {
  await q('DELETE FROM servers WHERE id=$1', [req.params.id]); res.json({ ok: 1 });
}));

// Live chat
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 1e6 });
wss.on('connection', async (ws, req) => {
  const t = new URL(req.url, 'http://x').searchParams.get('t');
  const [u] = t ? await q('SELECT u.* FROM sessions s JOIN users u ON u.id=s.uid WHERE token=$1', [t]) : [];
  if (!u || u.banned) return ws.close();
  ws.uid = u.id; ws.alive = true;
  ws.on('pong', () => ws.alive = true);
  ws.on('message', async raw => {
    try {
      const m = JSON.parse(raw);
      const body = (m.body || '').slice(0, 2000), file = (m.file || '').slice(0, 100);
      if (!body.trim() && !file) return;
      const [c] = await q('SELECT sid FROM channels WHERE id=$1', [m.cid]);
      if (!c || !(await isMember(u.id, c.sid))) return;
      const [row] = await q('INSERT INTO messages(cid,uid,body,file) VALUES($1,$2,$3,$4) RETURNING id,ts', [m.cid, u.id, body, file || null]);
      const ids = new Set((await q('SELECT uid FROM members WHERE sid=$1', [c.sid])).map(r => r.uid));
      const out = JSON.stringify({ cid: m.cid, id: row.id, ts: row.ts, body, file: file || null, username: u.username, pfp: u.pfp, color: u.color, owner: isOwner(u) });
      wss.clients.forEach(c2 => c2.readyState === 1 && ids.has(c2.uid) && c2.send(out));
    } catch (e) { console.error(e); }
  });
});
setInterval(() => wss.clients.forEach(w => { if (!w.alive) return w.terminate(); w.alive = false; w.ping(); }), 30000);

(async () => {
  await connect();
  await exec(`
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,username TEXT NOT NULL,pass TEXT NOT NULL,bio TEXT DEFAULT '',pfp TEXT,banner TEXT,theme TEXT DEFAULT 'zine',color TEXT DEFAULT '#8b7cff');
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,uid INT REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS servers(id SERIAL PRIMARY KEY,name TEXT,icon TEXT,invite TEXT UNIQUE,owner INT);
CREATE TABLE IF NOT EXISTS members(sid INT REFERENCES servers(id) ON DELETE CASCADE,uid INT REFERENCES users(id) ON DELETE CASCADE,PRIMARY KEY(sid,uid));
CREATE TABLE IF NOT EXISTS channels(id SERIAL PRIMARY KEY,sid INT REFERENCES servers(id) ON DELETE CASCADE,name TEXT);
CREATE TABLE IF NOT EXISTS messages(id SERIAL PRIMARY KEY,cid INT REFERENCES channels(id) ON DELETE CASCADE,uid INT,body TEXT,file TEXT,ts TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,mime TEXT,data BYTEA);
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS users_lu ON users(lower(username));`);
  server.listen(process.env.PORT || 3000, () => console.log('D-Chat running'));
})();
