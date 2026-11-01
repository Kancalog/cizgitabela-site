'use strict';
// Çizgi Stok sunucusu: Node.js (yerleşik sqlite) — dış bağımlılık yok.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PHOTOS = path.join(DATA, 'photos');
const BACKUPS = path.join(DATA, 'backups');
const SETUP_CODE = process.env.SETUP_CODE || '';
const AI_MODEL = process.env.AI_MODEL || 'claude-haiku-5-5';
const PORT = Number(process.env.PORT || 3000);
const SECURE_COOKIE = process.env.INSECURE_COOKIE ? '' : '; Secure';
for (const d of [DATA, PHOTOS, BACKUPS]) fs.mkdirSync(d, { recursive: true });

const db = new DatabaseSync(path.join(DATA, 'stok.db'));
db.exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pass TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user');
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pgroups(id TEXT PRIMARY KEY, name TEXT NOT NULL, prefix TEXT UNIQUE NOT NULL, ord INTEGER NOT NULL DEFAULT 0, next INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY, code TEXT NOT NULL, num INTEGER NOT NULL, name TEXT NOT NULL DEFAULT '', group_id TEXT NOT NULL, stock INTEGER NOT NULL DEFAULT 0, min INTEGER NOT NULL DEFAULT 0, ord INTEGER NOT NULL DEFAULT 0, photo TEXT, price REAL, cost REAL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS moves(id INTEGER PRIMARY KEY AUTOINCREMENT, t INTEGER NOT NULL, day TEXT NOT NULL, pid TEXT, code TEXT, name TEXT, d INTEGER NOT NULL, after INTEGER NOT NULL, kind TEXT NOT NULL, note TEXT DEFAULT '', cost REAL, user TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS moves_day ON moves(day);
CREATE INDEX IF NOT EXISTS moves_pid ON moves(pid);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
`);

/* ---------- veritabanı yardımcıları ---------- */
const stmts = new Map();
const st = sql => { let s = stmts.get(sql); if (!s) { s = db.prepare(sql); stmts.set(sql, s); } return s; };
const get = (sql, ...a) => st(sql).get(...a);
const all = (sql, ...a) => st(sql).all(...a);
const run = (sql, ...a) => st(sql).run(...a);
function tx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { try { db.exec('ROLLBACK'); } catch (_) {} throw e; }
}
const setting = k => { const r = get('SELECT value FROM settings WHERE key=?', k); return r ? r.value : null; };
const setSetting = (k, v) => run('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', k, v);
const newId = () => crypto.randomBytes(10).toString('hex');
const fmt = (pfx, n) => pfx + '-' + String(n).padStart(3, '0');
const dayKey = d => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
const KINDS = new Set(['giris', 'cikis', 'sayim']);

class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const fail = (code, msg) => { throw new HttpError(code, msg); };

/* ---------- şifre ve oturum ---------- */
function hashPass(p) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + crypto.scryptSync(p, salt, 64).toString('hex');
}
function checkPass(p, stored) {
  const [s, h] = String(stored).split(':');
  if (!s || !h) return false;
  const calc = crypto.scryptSync(p, Buffer.from(s, 'hex'), 64);
  const want = Buffer.from(h, 'hex');
  return want.length === calc.length && crypto.timingSafeEqual(calc, want);
}
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
const SESSION_DAYS = 30;
function createSession(res, uid) {
  const token = crypto.randomBytes(32).toString('hex');
  run('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)', token, uid, Date.now() + SESSION_DAYS * 864e5);
  res.setHeader('Set-Cookie', `sid=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${SECURE_COOKIE}`);
}
function cookie(req, name) {
  const m = String(req.headers.cookie || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : null;
}
function currentUser(req) {
  const t = cookie(req, 'sid');
  if (!t || !/^[a-f0-9]{64}$/.test(t)) return null;
  const s = get('SELECT user_id,expires FROM sessions WHERE token=?', t);
  if (!s || s.expires < Date.now()) return null;
  return get('SELECT id,username,name,role FROM users WHERE id=?', s.user_id) || null;
}
const loginFails = new Map();
function ipOf(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }
function checkRate(ip) {
  const r = loginFails.get(ip);
  if (r && r.n >= 10 && r.until > Date.now()) fail(429, 'Çok fazla hatalı deneme. 15 dakika sonra tekrar deneyin.');
}
function noteFail(ip) {
  const r = loginFails.get(ip);
  if (!r || r.until < Date.now()) loginFails.set(ip, { n: 1, until: Date.now() + 15 * 6e4 });
  else r.n++;
}

/* ---------- HTTP yardımcıları ---------- */
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => { size += c.length; if (size > limit) { reject(new HttpError(413, 'Dosya çok büyük.')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req, limit = 1e6) {
  const b = await readBody(req, limit);
  if (!b.length) return {};
  try { return JSON.parse(b.toString('utf8')); } catch (e) { fail(400, 'Geçersiz istek.'); }
}
function send(res, code, obj) {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': b.length, 'Cache-Control': 'no-store' });
  res.end(b);
}
const num = (v, def = null) => (typeof v === 'number' && isFinite(v) ? v : def);
const int = v => { const n = Math.round(Number(v)); return isFinite(n) ? n : null; };
const money = v => (v === null || v === '' || v === undefined ? null : (typeof v === 'number' && isFinite(v) && v >= 0 ? Math.round(v * 100) / 100 : fail(400, 'Fiyat geçersiz.')));
const str = (v, max) => String(v ?? '').trim().slice(0, max);
const photoPath = id => (/^[a-f0-9]{20,40}$/.test(id) ? path.join(PHOTOS, id + '.jpg') : null);

/* ---------- veri işlemleri ---------- */
function productRow(p) {
  return { id: p.id, code: p.code, num: p.num, name: p.name, groupId: p.group_id, stock: p.stock, min: p.min, order: p.ord, photo: p.photo, price: p.price, cost: p.cost, createdAt: p.created_at };
}
function groupRow(g) { return { id: g.id, name: g.name, prefix: g.prefix, order: g.ord, next: g.next }; }
function logMove(m, user) {
  const t = Date.now();
  run('INSERT INTO moves(t,day,pid,code,name,d,after,kind,note,cost,user) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
    t, dayKey(new Date(t)), m.pid, m.code, m.name || '', m.d, m.after, m.kind, m.note || '', m.cost ?? null, user || '');
}
function nextNumber(g) {
  const r = get('SELECT MAX(num) AS m FROM products WHERE group_id=?', g.id);
  return Math.max(g.next || 1, (r.m || 0) + 1);
}
function nextOrder(gid) { const r = get('SELECT MAX(ord) AS m FROM products WHERE group_id=?', gid); return (r.m || 0) + 1; }
function normPrefix(s) {
  return String(s || '').toLocaleUpperCase('tr').replace(/Ç/g, 'C').replace(/Ğ/g, 'G').replace(/İ/g, 'I').replace(/Ö/g, 'O').replace(/Ş/g, 'S').replace(/Ü/g, 'U').replace(/[^A-Z0-9]/g, '').slice(0, 4);
}

async function classify(photoId) {
  const key = setting('ai_key');
  if (!key) fail(400, 'Yapay zeka anahtarı girilmemiş. Ayarlar bölümünden ekleyin.');
  const file = photoPath(photoId);
  if (!file || !fs.existsSync(file)) fail(404, 'Fotoğraf bulunamadı.');
  const groups = all('SELECT id,name FROM pgroups ORDER BY ord');
  if (!groups.length) fail(400, 'Önce bir grup ekleyin.');
  const prompt = `Bu fotoğraf bir tabela ve reklam dükkanındaki bir ürün. Ürünü şu gruplardan tam olarak birine koy: ${groups.map(g => JSON.stringify(g.name)).join(', ')}. Yalnızca şu JSON'u döndür, başka hiçbir şey yazma: {"group":"<listedeki adın birebir aynısı>","name":"<ürünün kısa Türkçe adı, en fazla 5 kelime>"}`;
  let r;
  try {
    r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: AI_MODEL, max_tokens: 200, messages: [{ role: 'user', content: [
        { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: fs.readFileSync(file).toString('base64') } },
        { type: 'text', text: prompt }] }] }),
      signal: AbortSignal.timeout(40000)
    });
  } catch (e) { fail(502, 'Yapay zekaya ulaşılamadı.'); }
  if (!r.ok) {
    const code = r.status;
    fail(502, code === 401 ? 'Yapay zeka anahtarı geçersiz.' : code === 429 ? 'Yapay zeka şu an yoğun, biraz sonra deneyin.' : code === 400 ? 'Yapay zeka isteği reddetti (hesap bakiyesi bitmiş olabilir).' : 'Yapay zeka hata verdi (' + code + ').');
  }
  const j = await r.json();
  const text = (j.content || []).map(c => c.text || '').join('');
  let v = {}; try { v = JSON.parse((text.match(/\{[\s\S]*\}/) || ['{}'])[0]); } catch (_) {}
  const g = groups.find(x => x.name.toLocaleLowerCase('tr') === String(v.group || '').trim().toLocaleLowerCase('tr'));
  return g ? { groupId: g.id, name: str(v.name, 60), matched: true } : { groupId: groups[0].id, name: str(v.name, 60), matched: false };
}

function exportData(withPhotos) {
  const products = all('SELECT * FROM products').map(productRow);
  const out = {
    format: 'cizgi-stok', version: 1, exportedAt: new Date().toISOString(),
    groups: all('SELECT * FROM pgroups ORDER BY ord').map(groupRow),
    products,
    moves: all('SELECT t,pid,code,name,d,after,kind,note,cost,user FROM moves ORDER BY id'),
    settings: { vatIncluded: setting('vat_included') === '1', vatRate: Number(setting('vat_rate') ?? 20) }
  };
  if (withPhotos) {
    out.photos = {};
    for (const p of products) {
      const f = p.photo && photoPath(p.photo);
      if (f && fs.existsSync(f)) out.photos[p.photo] = fs.readFileSync(f).toString('base64');
    }
  }
  return out;
}
function importData(d) {
  if (!d || d.format !== 'cizgi-stok') fail(400, 'Bu dosya Çizgi Stok yedeği değil.');
  if (get('SELECT COUNT(*) AS n FROM products').n > 0) fail(409, 'İçe aktarma yalnızca boş sisteme yapılabilir; sistemde zaten ürün var.');
  const photos = d.photos || {};
  for (const [id, b64] of Object.entries(photos)) { const f = photoPath(id); if (f) fs.writeFileSync(f, Buffer.from(String(b64), 'base64')); }
  return tx(() => {
    run('DELETE FROM pgroups');
    for (const g of d.groups || []) run('INSERT INTO pgroups(id,name,prefix,ord,next) VALUES(?,?,?,?,?)', str(g.id, 40), str(g.name, 60), normPrefix(g.prefix), int(g.order) || 0, int(g.next) || 1);
    for (const p of d.products || []) run('INSERT INTO products(id,code,num,name,group_id,stock,min,ord,photo,price,cost,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
      str(p.id, 40), str(p.code, 20), int(p.num) || 0, str(p.name, 80), str(p.groupId, 40), Math.max(0, int(p.stock) || 0), Math.max(0, int(p.min) || 0), int(p.order) || 0,
      p.photo ? str(p.photo, 40) : null, num(p.price), num(p.cost), int(p.createdAt) || Date.now());
    for (const m of d.moves || []) {
      const t = int(m.t) || Date.now();
      run('INSERT INTO moves(t,day,pid,code,name,d,after,kind,note,cost,user) VALUES(?,?,?,?,?,?,?,?,?,?,?)', t, dayKey(new Date(t)), str(m.pid, 40), str(m.code, 20), str(m.name, 80), int(m.d) || 0, int(m.after) || 0, str(m.kind, 10), str(m.note, 160), num(m.cost), str(m.user, 60));
    }
    if (d.settings) { setSetting('vat_included', d.settings.vatIncluded ? '1' : '0'); setSetting('vat_rate', String(int(d.settings.vatRate) ?? 20)); }
    return { groups: (d.groups || []).length, products: (d.products || []).length, moves: (d.moves || []).length, photos: Object.keys(photos).length };
  });
}

/* ---------- günlük yedek ---------- */
function dailyBackup() {
  try {
    const name = 'stok-' + dayKey(new Date()) + '.db';
    const target = path.join(BACKUPS, name);
    if (!fs.existsSync(target)) db.exec(`VACUUM INTO '${target.replace(/'/g, "''")}'`);
    const files = fs.readdirSync(BACKUPS).filter(f => /^stok-\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort();
    for (const f of files.slice(0, Math.max(0, files.length - 14))) fs.unlinkSync(path.join(BACKUPS, f));
  } catch (e) { console.error('Yedek alınamadı:', e.message); }
}
dailyBackup();
setInterval(dailyBackup, 3600e3).unref();
setInterval(() => run('DELETE FROM sessions WHERE expires<?', Date.now()), 6 * 3600e3).unref();

/* ---------- istek yönlendirme ---------- */
const INDEX = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
const SEC_HEADERS = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' };

async function handle(req, res) {
  for (const [k, v] of Object.entries(SEC_HEADERS)) res.setHeader(k, v);
  const url = new URL(req.url, 'http://x');
  const p = url.pathname, m = req.method;

  if (m === 'GET' && (p === '/' || p === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end(INDEX);
  }
  if (m === 'GET' && p === '/healthz') return send(res, 200, { ok: true });

  const mutating = m !== 'GET' && m !== 'HEAD';
  if (mutating && req.headers['x-stok'] !== '1') fail(403, 'Geçersiz istek.');

  // giriş gerektirmeyenler
  if (m === 'GET' && p === '/api/setup-needed') return send(res, 200, { needed: get('SELECT COUNT(*) AS n FROM users').n === 0 });
  if (m === 'POST' && p === '/api/setup') {
    const ip = ipOf(req); checkRate(ip);
    const b = await readJson(req);
    if (get('SELECT COUNT(*) AS n FROM users').n > 0) fail(409, 'Kurulum zaten yapılmış.');
    if (!SETUP_CODE || !safeEq(str(b.code, 100), SETUP_CODE)) { noteFail(ip); fail(403, 'Kurulum kodu hatalı.'); }
    const username = str(b.username, 40).toLocaleLowerCase('tr'), name = str(b.name, 60), pw = String(b.password || '');
    if (!/^[a-z0-9._-]{3,40}$/.test(username)) fail(400, 'Kullanıcı adı en az 3 karakter olmalı; harf, rakam, nokta ya da tire kullanın.');
    if (pw.length < 8) fail(400, 'Şifre en az 8 karakter olmalı.');
    const r = run('INSERT INTO users(username,name,pass,role) VALUES(?,?,?,?)', username, name || username, hashPass(pw), 'admin');
    createSession(res, Number(r.lastInsertRowid));
    return send(res, 200, { ok: true });
  }
  if (m === 'POST' && p === '/api/login') {
    const ip = ipOf(req); checkRate(ip);
    const b = await readJson(req);
    const u = get('SELECT * FROM users WHERE username=?', str(b.username, 40).toLocaleLowerCase('tr'));
    if (!u || !checkPass(String(b.password || ''), u.pass)) { noteFail(ip); fail(401, 'Kullanıcı adı ya da şifre hatalı.'); }
    loginFails.delete(ip);
    createSession(res, u.id);
    return send(res, 200, { ok: true });
  }

  const me = currentUser(req);
  if (!me) fail(401, 'Oturum açın.');
  const admin = me.role === 'admin';
  const needAdmin = () => { if (!admin) fail(403, 'Bu işlem için yönetici yetkisi gerekir.'); };

  if (m === 'POST' && p === '/api/logout') {
    run('DELETE FROM sessions WHERE token=?', cookie(req, 'sid'));
    res.setHeader('Set-Cookie', `sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${SECURE_COOKIE}`);
    return send(res, 200, { ok: true });
  }
  if (m === 'GET' && p === '/api/me') return send(res, 200, me);

  if (m === 'GET' && p.startsWith('/photos/')) {
    const f = photoPath(p.slice(8).replace(/\.jpg$/, ''));
    if (!f || !fs.existsSync(f)) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Cache-Control': 'private, max-age=31536000, immutable' });
    return fs.createReadStream(f).pipe(res);
  }

  if (m === 'GET' && p === '/api/state') {
    return send(res, 200, {
      me,
      groups: all('SELECT * FROM pgroups ORDER BY ord').map(groupRow),
      products: all('SELECT * FROM products').map(productRow),
      settings: { vatIncluded: setting('vat_included') === '1', vatRate: Number(setting('vat_rate') ?? 20), aiConfigured: !!setting('ai_key') }
    });
  }

  /* gruplar */
  if (m === 'POST' && p === '/api/groups') {
    const b = await readJson(req);
    const name = str(b.name, 60), prefix = normPrefix(b.prefix);
    if (!name || !prefix) fail(400, 'Ad ve kod ön eki gerekli.');
    if (get('SELECT 1 FROM pgroups WHERE prefix=?', prefix)) fail(409, prefix + ' ön eki zaten kullanılıyor.');
    const ord = (get('SELECT MAX(ord) AS m FROM pgroups').m || 0) + 1;
    const id = newId();
    run('INSERT INTO pgroups(id,name,prefix,ord,next) VALUES(?,?,?,?,1)', id, name, prefix, ord);
    return send(res, 200, { id });
  }
  let mm;
  if (m === 'DELETE' && (mm = p.match(/^\/api\/groups\/([\w-]+)$/))) {
    if (get('SELECT 1 FROM products WHERE group_id=?', mm[1])) fail(409, 'Grupta ürün varken grup silinemez.');
    run('DELETE FROM pgroups WHERE id=?', mm[1]);
    return send(res, 200, { ok: true });
  }

  /* fotoğraf */
  if (m === 'POST' && p === '/api/photos') {
    if (!/^image\/jpeg/.test(req.headers['content-type'] || '')) fail(415, 'Fotoğraf JPEG olarak gönderilmeli.');
    const b = await readBody(req, 12e6);
    if (b.length < 100 || b[0] !== 0xff || b[1] !== 0xd8) fail(400, 'Geçerli bir JPEG değil.');
    const id = crypto.randomBytes(16).toString('hex');
    fs.writeFileSync(photoPath(id), b);
    return send(res, 200, { id });
  }
  if (m === 'POST' && p === '/api/classify') {
    const b = await readJson(req);
    return send(res, 200, await classify(str(b.photo, 40)));
  }

  /* ürünler */
  if (m === 'POST' && p === '/api/products') {
    const b = await readJson(req);
    const stock = Math.max(0, int(b.stock) || 0), name = str(b.name, 80), photo = b.photo ? str(b.photo, 40) : null;
    if (photo && !photoPath(photo)) fail(400, 'Fotoğraf geçersiz.');
    const prod = tx(() => {
      const g = get('SELECT * FROM pgroups WHERE id=?', str(b.groupId, 40));
      if (!g) fail(400, 'Grup bulunamadı.');
      const n = nextNumber(g), id = newId(), code = fmt(g.prefix, n);
      run('INSERT INTO products(id,code,num,name,group_id,stock,min,ord,photo,price,cost,created_at) VALUES(?,?,?,?,?,?,0,?,?,NULL,NULL,?)', id, code, n, name, g.id, stock, nextOrder(g.id), photo, Date.now());
      run('UPDATE pgroups SET next=? WHERE id=?', n + 1, g.id);
      if (stock > 0) logMove({ pid: id, code, name, d: stock, after: stock, kind: 'ilk', note: 'Ürün eklendi' }, me.name);
      return get('SELECT * FROM products WHERE id=?', id);
    });
    return send(res, 200, productRow(prod));
  }
  if ((mm = p.match(/^\/api\/products\/([\w-]+)(\/stock|\/reorder)?$/))) {
    const id = mm[1], sub = mm[2] || '';
    if (m === 'PATCH' && !sub) {
      const b = await readJson(req);
      const out = tx(() => {
        const prod = get('SELECT * FROM products WHERE id=?', id); if (!prod) fail(404, 'Ürün bulunamadı.');
        if ('name' in b) run('UPDATE products SET name=? WHERE id=?', str(b.name, 80), id);
        if ('min' in b) run('UPDATE products SET min=? WHERE id=?', Math.max(0, int(b.min) || 0), id);
        if ('price' in b) run('UPDATE products SET price=? WHERE id=?', money(b.price), id);
        if ('groupId' in b && b.groupId !== prod.group_id) {
          const g = get('SELECT * FROM pgroups WHERE id=?', str(b.groupId, 40)); if (!g) fail(400, 'Grup bulunamadı.');
          const n = nextNumber(g);
          run('UPDATE products SET group_id=?,num=?,code=?,ord=? WHERE id=?', g.id, n, fmt(g.prefix, n), nextOrder(g.id), id);
          run('UPDATE pgroups SET next=? WHERE id=?', n + 1, g.id);
        }
        return get('SELECT * FROM products WHERE id=?', id);
      });
      return send(res, 200, productRow(out));
    }
    if (m === 'POST' && sub === '/stock') {
      const b = await readJson(req);
      const out = tx(() => {
        const prod = get('SELECT * FROM products WHERE id=?', id); if (!prod) fail(404, 'Ürün bulunamadı.');
        const v = int(b.value); if (v === null) fail(400, 'Adet geçersiz.');
        const after = b.mode === 'set' ? v : prod.stock + v;
        if (after < 0) fail(400, `Stokta ${prod.stock} adet var; bu kadar çıkış yapılamaz.`);
        const d = after - prod.stock;
        if (d === 0) return prod;
        let kind = KINDS.has(b.kind) ? b.kind : (d > 0 ? 'giris' : 'cikis');
        const cost = kind === 'giris' && b.cost !== undefined && b.cost !== null ? money(b.cost) : null;
        run('UPDATE products SET stock=? WHERE id=?', after, id);
        if (cost !== null) run('UPDATE products SET cost=? WHERE id=?', cost, id);
        logMove({ pid: id, code: prod.code, name: prod.name, d, after, kind, note: str(b.note, 160), cost }, me.name);
        return get('SELECT * FROM products WHERE id=?', id);
      });
      return send(res, 200, productRow(out));
    }
    if (m === 'POST' && sub === '/reorder') {
      const b = await readJson(req);
      tx(() => {
        const prod = get('SELECT * FROM products WHERE id=?', id); if (!prod) fail(404, 'Ürün bulunamadı.');
        const list = all('SELECT id,ord FROM products WHERE group_id=? ORDER BY ord,created_at', prod.group_id);
        const i = list.findIndex(x => x.id === id), j = i + (b.dir < 0 ? -1 : 1);
        if (j < 0 || j >= list.length) return;
        list.forEach((x, k) => { x.ord = k + 1; });
        [list[i].ord, list[j].ord] = [list[j].ord, list[i].ord];
        for (const x of list) run('UPDATE products SET ord=? WHERE id=?', x.ord, x.id);
      });
      return send(res, 200, { ok: true });
    }
    if (m === 'DELETE' && !sub) {
      const prod = tx(() => {
        const prod = get('SELECT * FROM products WHERE id=?', id); if (!prod) fail(404, 'Ürün bulunamadı.');
        logMove({ pid: id, code: prod.code, name: prod.name, d: -prod.stock, after: 0, kind: 'sil', note: 'Ürün silindi' }, me.name);
        run('DELETE FROM products WHERE id=?', id);
        return prod;
      });
      const f = prod.photo && photoPath(prod.photo);
      if (f) fs.rm(f, { force: true }, () => {});
      return send(res, 200, { ok: true });
    }
  }

  /* hareketler */
  if (m === 'GET' && p === '/api/moves') {
    const days = Math.min(366, Math.max(1, int(url.searchParams.get('days')) || 31));
    const since = dayKey(new Date(Date.now() - (days - 1) * 864e5));
    const pid = url.searchParams.get('pid');
    const rows = pid
      ? all('SELECT * FROM moves WHERE pid=? ORDER BY t DESC LIMIT 2000', pid)
      : all('SELECT * FROM moves WHERE day>=? ORDER BY t DESC LIMIT 5000', since);
    return send(res, 200, rows);
  }

  /* ayarlar */
  if (m === 'PUT' && p === '/api/settings') {
    const b = await readJson(req);
    const r = int(b.vatRate); if (r === null || r < 0 || r > 100) fail(400, 'KDV oranı 0–100 arası olmalı.');
    setSetting('vat_included', b.vatIncluded ? '1' : '0'); setSetting('vat_rate', String(r));
    return send(res, 200, { ok: true });
  }
  if (m === 'PUT' && p === '/api/settings/ai') {
    needAdmin();
    const b = await readJson(req);
    const key = str(b.key, 300);
    if (key && !/^sk-ant-[\w-]{20,}$/.test(key)) fail(400, 'Bu bir Anthropic API anahtarına benzemiyor (sk-ant- ile başlamalı).');
    if (key) setSetting('ai_key', key); else run("DELETE FROM settings WHERE key='ai_key'");
    return send(res, 200, { ok: true, aiConfigured: !!key });
  }

  /* kullanıcılar */
  if (p === '/api/users' && m === 'GET') { needAdmin(); return send(res, 200, all('SELECT id,username,name,role FROM users ORDER BY id')); }
  if (p === '/api/users' && m === 'POST') {
    needAdmin();
    const b = await readJson(req);
    const username = str(b.username, 40).toLocaleLowerCase('tr'), pw = String(b.password || '');
    if (!/^[a-z0-9._-]{3,40}$/.test(username)) fail(400, 'Kullanıcı adı en az 3 karakter olmalı; harf, rakam, nokta ya da tire kullanın.');
    if (pw.length < 8) fail(400, 'Şifre en az 8 karakter olmalı.');
    if (get('SELECT 1 FROM users WHERE username=?', username)) fail(409, 'Bu kullanıcı adı zaten var.');
    run('INSERT INTO users(username,name,pass,role) VALUES(?,?,?,?)', username, str(b.name, 60) || username, hashPass(pw), b.role === 'admin' ? 'admin' : 'user');
    return send(res, 200, { ok: true });
  }
  if ((mm = p.match(/^\/api\/users\/(\d+)(\/password)?$/))) {
    const uid = Number(mm[1]);
    if (m === 'PUT' && mm[2]) {
      if (uid !== me.id) needAdmin();
      const b = await readJson(req); const pw = String(b.password || '');
      if (pw.length < 8) fail(400, 'Şifre en az 8 karakter olmalı.');
      run('UPDATE users SET pass=? WHERE id=?', hashPass(pw), uid);
      run('DELETE FROM sessions WHERE user_id=? AND token<>?', uid, cookie(req, 'sid'));
      return send(res, 200, { ok: true });
    }
    if (m === 'DELETE' && !mm[2]) {
      needAdmin();
      if (uid === me.id) fail(400, 'Kendi hesabınızı silemezsiniz.');
      run('DELETE FROM sessions WHERE user_id=?', uid); run('DELETE FROM users WHERE id=?', uid);
      return send(res, 200, { ok: true });
    }
  }

  /* yedek */
  if (m === 'GET' && p === '/api/export') {
    const b = Buffer.from(JSON.stringify(exportData(url.searchParams.get('photos') !== '0')));
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': b.length, 'Cache-Control': 'no-store',
      'Content-Disposition': `attachment; filename="cizgi-stok-yedek-${dayKey(new Date())}.json"` });
    return res.end(b);
  }
  if (m === 'POST' && p === '/api/import') {
    needAdmin();
    const b = await readJson(req, 300e6);
    return send(res, 200, importData(b));
  }

  fail(404, 'Bulunamadı.');
}

http.createServer((req, res) => {
  handle(req, res).catch(e => {
    if (res.headersSent) return res.end();
    if (e instanceof HttpError) return send(res, e.code, { error: e.message });
    console.error(e);
    send(res, 500, { error: 'Sunucu hatası. Tekrar deneyin.' });
  });
}).listen(PORT, () => console.log('Çizgi Stok ' + PORT + ' portunda çalışıyor'));
