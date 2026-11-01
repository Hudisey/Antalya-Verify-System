const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS;
if (!ADMIN_PASS) { console.error('ADMIN_PASS ortam değişkeni gerekli'); process.exit(1); }

// ---- basit dosya tabanlı veri (Render free: yeniden başlayınca sıfırlanır) ----
const DATA = path.join(__dirname, 'data.json');
let db = { requests: [], mods: [] };
try { db = JSON.parse(fs.readFileSync(DATA, 'utf8')); } catch {}
const save = () => { try { fs.writeFileSync(DATA, JSON.stringify(db)); } catch {} };

const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const sessions = new Map(); // token -> {role, name}

// ---- yardımcılar ----
const hits = new Map();
function limited(ip, max = 8, windowMs = 3600e3) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < windowMs);
  arr.push(now); hits.set(ip, arr);
  return arr.length > max;
}
async function geocode(lat, lon) {
  try {
    const r = await fetch(
      `https://nominatim.openstreetmap.org/reverse?format=jsonv2&accept-language=tr&zoom=12&lat=${lat}&lon=${lon}`,
      { headers: { 'User-Agent': 'antalya-verify/1.0' }, signal: AbortSignal.timeout(5000) });
    const j = await r.json();
    const a = j.address || {};
    return { place: j.display_name || '', province: a.province || a.state || a.city || '' };
  } catch { return { place: '', province: '' }; }
}

// ---- herkese açık ----
app.get('/healthz', (_, res) => res.send('ok'));

app.post('/api/verify', async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip;
  if (limited(ip)) return res.status(429).json({ error: 'Çok fazla deneme.' });
  const { name, cid, lat, lon, acc } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.length > 40)
    return res.status(400).json({ error: 'Geçerli bir ad yaz.' });
  if (typeof cid !== 'string' || cid.length > 64) return res.status(400).json({ error: 'Hata.' });
  if (![lat, lon].every(Number.isFinite) || Math.abs(lat) > 90 || Math.abs(lon) > 180)
    return res.status(400).json({ error: 'Konum alınamadı.' });

  const old = db.requests.find(r => r.cid === cid);
  if (old) return res.json({ id: old.id, status: old.status }); // bir kere basabilir

  const g = await geocode(lat, lon);
  const rec = {
    id: crypto.randomBytes(16).toString('hex'),
    cid, name: name.trim(), lat, lon,
    acc: Number.isFinite(acc) ? Math.round(acc) : null,
    place: g.place, province: g.province,
    antalya: /antalya/i.test(g.province + ' ' + g.place),
    ip, status: 'pending', time: Date.now(), by: null
  };
  db.requests.push(rec); save();
  res.json({ id: rec.id, status: rec.status });
});

app.get('/api/status/:id', (req, res) => {
  const r = db.requests.find(x => x.id === req.params.id);
  res.json({ status: r ? r.status : 'none' });
});

// ---- giriş ----
app.post('/api/login', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip;
  if (limited('login' + ip, 10, 600e3)) return res.status(429).json({ error: 'Biraz bekle.' });
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Hata' });
  let role = null;
  if (username === ADMIN_USER && password === ADMIN_PASS) role = 'admin';
  else {
    const m = db.mods.find(x => x.username === username);
    if (m && crypto.timingSafeEqual(Buffer.from(hash(password, m.salt)), Buffer.from(m.hash))) role = 'mod';
  }
  if (!role) return res.status(401).json({ error: 'Hatalı giriş' });
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { role, name: username });
  res.json({ token, role, name: username });
});

const auth = (adminOnly) => (req, res, next) => {
  const s = sessions.get((req.headers.authorization || '').replace('Bearer ', ''));
  if (!s || (adminOnly && s.role !== 'admin')) return res.status(401).json({ error: 'yetkisiz' });
  req.user = s; next();
};

// ---- admin + moderatör ----
app.get('/api/requests', auth(false), (req, res) => {
  res.json(db.requests.slice().reverse().map(({ ip, cid, ...r }) => r));
});

app.post('/api/requests/:id/decision', auth(false), (req, res) => {
  const { status } = req.body || {};
  if (!['approved', 'rejected', 'pending'].includes(status)) return res.status(400).json({ error: 'Hata' });
  const r = db.requests.find(x => x.id === req.params.id);
  if (!r) return res.status(404).json({ error: 'Yok' });
  r.status = status; r.by = req.user.name; save();
  res.json({ ok: true });
});

// ---- sadece admin ----
app.delete('/api/requests/:id', auth(true), (req, res) => {
  db.requests = db.requests.filter(x => x.id !== req.params.id); save(); res.json({ ok: true });
});
app.get('/api/mods', auth(true), (_, res) => res.json(db.mods.map(m => m.username)));
app.post('/api/mods', auth(true), (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || !/^[\w.-]{3,20}$/.test(username) || typeof password !== 'string' || password.length < 6)
    return res.status(400).json({ error: 'Kullanıcı adı 3-20 karakter, şifre en az 6 karakter.' });
  if (username === ADMIN_USER || db.mods.some(m => m.username === username))
    return res.status(400).json({ error: 'Bu ad kullanımda.' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.mods.push({ username, salt, hash: hash(password, salt) }); save(); res.json({ ok: true });
});
app.delete('/api/mods/:u', auth(true), (req, res) => {
  db.mods = db.mods.filter(m => m.username !== req.params.u);
  for (const [t, s] of sessions) if (s.name === req.params.u && s.role === 'mod') sessions.delete(t);
  save(); res.json({ ok: true });
});

app.listen(process.env.PORT || 3000, () => console.log('çalışıyor'));
