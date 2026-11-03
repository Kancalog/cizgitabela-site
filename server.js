'use strict';
// Çizgi İş Takibi sunucusu: Node.js 22 (yerleşik sqlite) — dış bağımlılık yok.
// Giriş/oturum yapısı Çizgi Stok ile aynıdır.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const BACKUPS = path.join(DATA, 'backups');
const SETUP_CODE = process.env.SETUP_CODE || '';
const PORT = Number(process.env.PORT || 3000);
const SECURE_COOKIE = process.env.INSECURE_COOKIE ? '' : '; Secure';
for (const d of [DATA, BACKUPS]) fs.mkdirSync(d, { recursive: true });

const db = new DatabaseSync(path.join(DATA, 'isler.db'));
db.exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pass TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user');
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at INTEGER NOT NULL, created_by TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL DEFAULT '', deleted_at INTEGER);
CREATE TABLE IF NOT EXISTS joblog(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, t INTEGER NOT NULL, user TEXT NOT NULL DEFAULT '', changes TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS joblog_job ON joblog(job_id, t);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS customers(id TEXT PRIMARY KEY, name_key TEXT NOT NULL, data TEXT NOT NULL, created_at INTEGER NOT NULL, created_by TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL DEFAULT '', deleted_at INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS customers_name ON customers(name_key) WHERE deleted_at IS NULL;
CREATE TABLE IF NOT EXISTS custlog(id INTEGER PRIMARY KEY AUTOINCREMENT, cust_id TEXT NOT NULL, t INTEGER NOT NULL, user TEXT NOT NULL DEFAULT '', changes TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS custlog_cust ON custlog(cust_id, t);
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
const newId = () => crypto.randomBytes(10).toString('hex');
const dayKey = d => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');

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
    req.on('data', c => { size += c.length; if (size > limit) { reject(new HttpError(413, 'İstek çok büyük.')); req.destroy(); } else chunks.push(c); });
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
const str = (v, max) => String(v ?? '').trim().slice(0, max);

/* ---------- iş alanları ---------- */
const STAGES = ['ÖLÇÜ ALINACAK', 'FİYAT AŞAMASINDA', 'TASARIM', 'İMALAT', 'MONTAJ', 'BİTTİ', 'TESLİM EDİLDİ'];
const YESNO = new Set(['EVET', 'HAYIR']);
const FIELDS = ['tarih', 'fisNo', 'firma', 'tanim', 'maliyet', 'satis', 'kapora', 'termin', 'donus', 'alindi', 'durum', 'not'];
const MONEY = new Set(['maliyet', 'satis', 'kapora']);
const isDate = v => /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(Date.parse(v + 'T00:00:00Z'));

// Tek alanı doğrula ve sakla biçimine çevir. Boş değer null olur.
function clean(k, v) {
  if (v === undefined || v === null || v === '') return null;
  if (MONEY.has(k)) {
    if (typeof v !== 'number' || !isFinite(v) || v < 0 || v > 1e10) fail(400, 'Tutar geçersiz.');
    return Math.round(v * 100) / 100;
  }
  if (k === 'tarih' || k === 'termin') { const s = str(v, 10); if (!isDate(s)) fail(400, 'Tarih geçersiz.'); return s; }
  if (k === 'donus' || k === 'alindi') { const s = str(v, 10).toLocaleUpperCase('tr'); if (!YESNO.has(s)) fail(400, 'Geçersiz seçim.'); return s; }
  if (k === 'durum') { const s = str(v, 40).toLocaleUpperCase('tr'); if (!STAGES.includes(s)) fail(400, 'Geçersiz durum.'); return s; }
  if (k === 'firma') return str(v, 120).toLocaleUpperCase('tr') || null;
  if (k === 'tanim') return str(v, 300) || null;
  if (k === 'fisNo') return str(v, 40) || null;
  if (k === 'not') return str(v, 1000) || null;
  return null;
}
const same = (k, a, b) => (a ?? null) === (b ?? null);

function jobRow(r) {
  return { id: r.id, ...JSON.parse(r.data), createdAt: r.created_at, createdBy: r.created_by, updatedAt: r.updated_at, updatedBy: r.updated_by };
}
function logChange(jobId, t, user, changes) {
  run('INSERT INTO joblog(job_id,t,user,changes) VALUES(?,?,?,?)', jobId, t, user, JSON.stringify(changes));
}

/* ---------- müşteriler ---------- */
// Kaynak: müşterinin kimden/nereden geldiği. Liste Ayarlar'dan yönetilir.
const DEFAULT_SOURCES = ['FARUK', 'ENVER', 'DÜKKAN', 'İNTERNET'];
const CFIELDS = ['ad', 'yetkili', 'telefon', 'adres', 'kaynak', 'kaynakNot', 'not'];
const nameKey = s => String(s ?? '').trim().replace(/\s+/g, ' ').toLocaleUpperCase('tr');
function getSources() {
  const r = get("SELECT value FROM settings WHERE key='sources'");
  try { const a = r && JSON.parse(r.value); if (Array.isArray(a) && a.length) return a; } catch (_) {}
  return DEFAULT_SOURCES.slice();
}
function cleanSource(v) {
  if (v === undefined || v === null || v === '') return null;
  const s = nameKey(str(v, 40));
  if (!getSources().includes(s)) fail(400, 'Geçersiz müşteri kaynağı.');
  return s;
}
function cleanC(k, v) {
  if (v === undefined || v === null || v === '') return null;
  if (k === 'ad') return nameKey(str(v, 120)) || null;
  if (k === 'kaynak') return cleanSource(v);
  if (k === 'telefon') return str(v, 30) || null;
  if (k === 'yetkili' || k === 'kaynakNot') return str(v, 80) || null;
  if (k === 'adres') return str(v, 300) || null;
  if (k === 'not') return str(v, 1000) || null;
  return null;
}
function custRow(r) {
  return { id: r.id, ...JSON.parse(r.data), createdAt: r.created_at, createdBy: r.created_by, updatedAt: r.updated_at, updatedBy: r.updated_by };
}
function custLog(id, t, user, changes) {
  run('INSERT INTO custlog(cust_id,t,user,changes) VALUES(?,?,?,?)', id, t, user, JSON.stringify(changes));
}
const custByName = name => get('SELECT * FROM customers WHERE name_key=? AND deleted_at IS NULL', nameKey(name));
// tx içinde çağrılır. Firma adıyla müşteriyi bulur; yoksa oluşturur. Müşteri kimliğini döndürür.
function resolveCustomer(firma, kaynak, user, t = Date.now()) {
  const ex = custByName(firma);
  if (ex) return ex.id;
  const id = newId(), data = { ad: nameKey(firma), kaynak: cleanSource(kaynak) };
  run('INSERT INTO customers(id,name_key,data,created_at,created_by,updated_at,updated_by) VALUES(?,?,?,?,?,?,?)', id, data.ad, JSON.stringify(data), t, user, t, user);
  custLog(id, t, user, [{ f: '_new' }]);
  return id;
}
function createCustomer(input, user) {
  const data = {};
  for (const k of CFIELDS) data[k] = cleanC(k, input[k]);
  if (!data.ad) fail(400, 'Müşteri adı gerekli.');
  if (!data.kaynak) fail(400, 'Müşterinin nereden geldiğini seçin.');
  return tx(() => {
    if (custByName(data.ad)) fail(409, 'Bu adla kayıtlı bir müşteri zaten var.');
    const id = newId(), t = Date.now();
    run('INSERT INTO customers(id,name_key,data,created_at,created_by,updated_at,updated_by) VALUES(?,?,?,?,?,?,?)', id, data.ad, JSON.stringify(data), t, user, t, user);
    custLog(id, t, user, [{ f: '_new' }]);
    return custRow(get('SELECT * FROM customers WHERE id=?', id));
  });
}
// Ad değişirse bağlı işlerin firma adı da güncellenir (iş geçmişine yazılır).
function patchCustomer(id, input, user) {
  return tx(() => {
    const r = get('SELECT * FROM customers WHERE id=? AND deleted_at IS NULL', id);
    if (!r) fail(404, 'Müşteri bulunamadı. Başka biri silmiş olabilir.');
    const data = JSON.parse(r.data), changes = [];
    for (const k of CFIELDS) {
      if (!(k in input)) continue;
      const v = cleanC(k, input[k]);
      if ((data[k] ?? null) !== (v ?? null)) { changes.push({ f: k, o: data[k] ?? null, n: v }); data[k] = v; }
    }
    if (!data.ad) fail(400, 'Müşteri adı boş bırakılamaz.');
    if (!changes.length) return custRow(r);
    const t = Date.now();
    if (data.ad !== r.name_key) {
      const other = custByName(data.ad);
      if (other && other.id !== id) { const e = new HttpError(409, 'Bu adla kayıtlı başka bir müşteri var.'); e.extra = { exists: other.id }; throw e; }
      for (const j of all('SELECT * FROM jobs WHERE deleted_at IS NULL')) {
        const jd = JSON.parse(j.data);
        if (jd.musteriId !== id || jd.firma === data.ad) continue;
        logChange(j.id, t, user, [{ f: 'firma', o: jd.firma, n: data.ad }]);
        jd.firma = data.ad;
        run('UPDATE jobs SET data=?,updated_at=?,updated_by=? WHERE id=?', JSON.stringify(jd), t, user, j.id);
      }
    }
    run('UPDATE customers SET name_key=?,data=?,updated_at=?,updated_by=? WHERE id=?', data.ad, JSON.stringify(data), t, user, id);
    custLog(id, t, user, changes);
    return custRow(get('SELECT * FROM customers WHERE id=?', id));
  });
}
// Aynı müşterinin iki kaydını tek kayıtta toplar: işler hedefe taşınır, boş alanlar hedefe tamamlanır.
function mergeCustomer(fromId, intoId, user) {
  if (fromId === intoId) fail(400, 'Müşteri kendisiyle birleştirilemez.');
  return tx(() => {
    const a = get('SELECT * FROM customers WHERE id=? AND deleted_at IS NULL', fromId);
    const b = get('SELECT * FROM customers WHERE id=? AND deleted_at IS NULL', intoId);
    if (!a || !b) fail(404, 'Müşteri bulunamadı.');
    const ad = JSON.parse(a.data), bd = JSON.parse(b.data), t = Date.now(), filled = [];
    for (const k of CFIELDS) if (bd[k] == null && ad[k] != null) { filled.push({ f: k, o: null, n: ad[k] }); bd[k] = ad[k]; }
    let moved = 0;
    for (const j of all('SELECT * FROM jobs WHERE deleted_at IS NULL')) {
      const jd = JSON.parse(j.data);
      if (jd.musteriId !== fromId) continue;
      const ch = [{ f: 'firma', o: jd.firma, n: bd.ad }];
      jd.firma = bd.ad; jd.musteriId = intoId; moved++;
      run('UPDATE jobs SET data=?,updated_at=?,updated_by=? WHERE id=?', JSON.stringify(jd), t, user, j.id);
      if (ch[0].o !== ch[0].n) logChange(j.id, t, user, ch);
    }
    run('UPDATE customers SET data=?,updated_at=?,updated_by=? WHERE id=?', JSON.stringify(bd), t, user, intoId);
    custLog(intoId, t, user, [{ f: '_merge', n: ad.ad }, ...filled]);
    run('UPDATE customers SET deleted_at=? WHERE id=?', t, fromId);
    custLog(fromId, t, user, [{ f: '_merged', n: bd.ad }]);
    return { moved, customer: custRow(get('SELECT * FROM customers WHERE id=?', intoId)) };
  });
}
// Açılışta: müşteriye bağlı olmayan her işi firma adına göre müşteriye bağla (eski kayıtlar için).
// Kaynağı bilinmeyen müşteriler "kaynak belirsiz" olarak açılır; kullanıcı sonra doldurur.
function linkOrphanJobs() {
  return tx(() => {
    let n = 0;
    for (const j of all('SELECT * FROM jobs WHERE deleted_at IS NULL')) {
      const jd = JSON.parse(j.data);
      if (jd.musteriId && get('SELECT 1 FROM customers WHERE id=? AND deleted_at IS NULL', jd.musteriId)) continue;
      if (!jd.firma) continue;
      jd.musteriId = resolveCustomer(jd.firma, null, j.created_by || '', j.created_at);
      run('UPDATE jobs SET data=? WHERE id=?', JSON.stringify(jd), j.id);
      n++;
    }
    return n;
  });
}

function createJob(input, user) {
  const data = {};
  for (const k of FIELDS) data[k] = clean(k, input[k]);
  if (!data.firma || !data.tanim) fail(400, 'Firma ve iş tanımı gerekli.');
  const id = newId(), t = Date.now();
  tx(() => {
    data.musteriId = resolveCustomer(data.firma, input.yeniKaynak, user, t);
    run('INSERT INTO jobs(id,data,created_at,created_by,updated_at,updated_by) VALUES(?,?,?,?,?,?)', id, JSON.stringify(data), t, user, t, user);
    logChange(id, t, user, [{ f: '_new' }]);
  });
  return jobRow(get('SELECT * FROM jobs WHERE id=?', id));
}
// Sadece gönderilen alanlar yazılır: iki kişi aynı işi düzenlerse birbirinin değişikliğini ezmez.
function patchJob(id, input, user) {
  return tx(() => {
    const r = get('SELECT * FROM jobs WHERE id=? AND deleted_at IS NULL', id);
    if (!r) fail(404, 'İş bulunamadı. Başka biri silmiş olabilir.');
    const data = JSON.parse(r.data), changes = [];
    for (const k of FIELDS) {
      if (!(k in input)) continue;
      const v = clean(k, input[k]);
      if (!same(k, data[k], v)) { changes.push({ f: k, o: data[k] ?? null, n: v }); data[k] = v; }
    }
    if (!data.firma || !data.tanim) fail(400, 'Firma ve iş tanımı boş bırakılamaz.');
    if (changes.length) {
      const t = Date.now();
      if (changes.some(c => c.f === 'firma') || !data.musteriId) data.musteriId = resolveCustomer(data.firma, input.yeniKaynak, user, t);
      run('UPDATE jobs SET data=?,updated_at=?,updated_by=? WHERE id=?', JSON.stringify(data), t, user, id);
      logChange(id, t, user, changes);
    }
    return jobRow(get('SELECT * FROM jobs WHERE id=?', id));
  });
}

/* ---------- yedek / içe aktarma ---------- */
function exportData() {
  return {
    format: 'cizgi-is-takip', version: 2, exportedAt: new Date().toISOString(),
    sources: getSources(),
    customers: all('SELECT * FROM customers WHERE deleted_at IS NULL ORDER BY created_at').map(custRow),
    jobs: all('SELECT * FROM jobs WHERE deleted_at IS NULL ORDER BY created_at').map(jobRow),
    log: all('SELECT job_id,t,user,changes FROM joblog ORDER BY id').map(l => ({ jobId: l.job_id, t: l.t, user: l.user, changes: JSON.parse(l.changes) })),
    custLog: all('SELECT cust_id,t,user,changes FROM custlog ORDER BY id').map(l => ({ custId: l.cust_id, t: l.t, user: l.user, changes: JSON.parse(l.changes) }))
  };
}
// Claude'un hazırladığı aktarım dosyası ya da bu uygulamanın yedeği. Yalnızca boş sisteme.
// Kullanıcı adı "__owner__" olan kayıtlar, içe aktaran yöneticinin adıyla yazılır.
function importData(d, me) {
  if (!d || d.format !== 'cizgi-is-takip') fail(400, 'Bu dosya İş Takibi aktarım dosyası değil.');
  if (get('SELECT COUNT(*) AS n FROM jobs').n > 0 || get('SELECT COUNT(*) AS n FROM customers').n > 0) fail(409, 'İçe aktarma yalnızca boş sisteme yapılabilir; sistemde zaten kayıt var.');
  const who = u => (u === '__owner__' || !u ? me.name : str(u, 60));
  const jobs = Array.isArray(d.jobs) ? d.jobs : [], log = Array.isArray(d.log) ? d.log : [];
  const custs = Array.isArray(d.customers) ? d.customers : [], clog = Array.isArray(d.custLog) ? d.custLog : [];
  const res = tx(() => {
    if (Array.isArray(d.sources) && d.sources.length) {
      const s = [...new Set(d.sources.map(x => nameKey(str(x, 40))).filter(Boolean))].slice(0, 30);
      run("INSERT INTO settings(key,value) VALUES('sources',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", JSON.stringify(s));
    }
    const cids = new Set();
    for (const c of custs) {
      const id = str(c.id, 40); if (!/^[\w-]{4,40}$/.test(id) || cids.has(id)) fail(400, 'Aktarım dosyasında geçersiz müşteri kimliği var.');
      const data = {};
      for (const k of CFIELDS) {
        try { data[k] = cleanC(k, c[k]); } catch (e) { fail(400, `${str(c.ad, 40) || id} müşterisinde "${k}" alanı geçersiz.`); }
      }
      if (!data.ad || custByName(data.ad)) fail(400, `Aktarım dosyasında adı boş ya da tekrarlanan müşteri var: ${data.ad || id}`);
      cids.add(id);
      const cr = Number(c.createdAt) || Date.now(), up = Number(c.updatedAt) || cr;
      run('INSERT INTO customers(id,name_key,data,created_at,created_by,updated_at,updated_by) VALUES(?,?,?,?,?,?,?)', id, data.ad, JSON.stringify(data), cr, who(c.createdBy), up, who(c.updatedBy));
    }
    for (const l of clog) {
      if (!cids.has(l.custId) || !Array.isArray(l.changes)) continue;
      custLog(l.custId, Number(l.t) || Date.now(), who(l.user), l.changes.slice(0, 20).map(c => ({ f: str(c.f, 20), o: c.o ?? null, n: c.n ?? null })));
    }
    const ids = new Set();
    for (const j of jobs) {
      const id = str(j.id, 40); if (!/^[\w-]{4,40}$/.test(id) || ids.has(id)) fail(400, 'Aktarım dosyasında geçersiz iş kimliği var.');
      ids.add(id);
      const data = {};
      for (const k of FIELDS) {
        try { data[k] = clean(k, j[k]); }
        catch (e) { fail(400, `${str(j.firma, 40) || id} kaydında "${k}" alanı geçersiz.`); }
      }
      if (typeof j.musteriId === 'string' && cids.has(j.musteriId)) data.musteriId = j.musteriId;
      const c = Number(j.createdAt) || Date.now(), u = Number(j.updatedAt) || c;
      run('INSERT INTO jobs(id,data,created_at,created_by,updated_at,updated_by) VALUES(?,?,?,?,?,?)', id, JSON.stringify(data), c, who(j.createdBy), u, who(j.updatedBy));
    }
    let n = 0;
    for (const l of log) {
      if (!ids.has(l.jobId) || !Array.isArray(l.changes)) continue;
      logChange(l.jobId, Number(l.t) || Date.now(), who(l.user), l.changes.slice(0, 20).map(c => ({ f: str(c.f, 20), o: c.o ?? null, n: c.n ?? null })));
      n++;
    }
    return { jobs: ids.size, log: n, customers: cids.size };
  });
  linkOrphanJobs();
  res.customers =get('SELECT COUNT(*) AS n FROM customers WHERE deleted_at IS NULL').n;
  return res;
}

/* ---------- günlük yedek ---------- */
function dailyBackup() {
  try {
    const target = path.join(BACKUPS, 'isler-' + dayKey(new Date()) + '.db');
    if (!fs.existsSync(target)) db.exec(`VACUUM INTO '${target.replace(/'/g, "''")}'`);
    const files = fs.readdirSync(BACKUPS).filter(f => /^isler-\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort();
    for (const f of files.slice(0, Math.max(0, files.length - 14))) fs.unlinkSync(path.join(BACKUPS, f));
  } catch (e) { console.error('Yedek alınamadı:', e.message); }
}
dailyBackup();
try { const n = linkOrphanJobs(); if (n) console.log(n + ' iş müşteri kayıtlarına bağlandı'); } catch (e) { console.error('Müşteri bağlama hatası:', e.message); }
setInterval(dailyBackup, 3600e3).unref();
setInterval(() => run('DELETE FROM sessions WHERE expires<?', Date.now()), 6 * 3600e3).unref();

/* ---------- WhatsApp günlük özet (Meta WhatsApp Cloud API) ---------- */
// Ayarlar ortam değişkenlerinden gelir; anahtar koda ya da veritabanına yazılmaz.
const WA = {
  token: process.env.WA_TOKEN || '', phoneId: process.env.WA_PHONE_ID || '', to: (d => d.length === 11 && d[0] === '0' ? '9' + d : d.length === 10 && d[0] === '5' ? '90' + d : d)((process.env.WA_TO || '').replace(/\D/g, '')),
  template: process.env.WA_TEMPLATE || 'gunluk_ozet', lang: process.env.WA_LANG || 'tr',
  hour: Number(process.env.WA_HOUR || 19), ver: process.env.WA_API_VERSION || 'v23.0', base: process.env.WA_API_BASE || 'https://graph.facebook.com'
};
const waReady = () => !!(WA.token && WA.phoneId && WA.to);
const setting = k => { const r = get('SELECT value FROM settings WHERE key=?', k); return r ? r.value : null; };
const setSetting = (k, v) => run('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', k, v);
const srcTitleTR = s => s.toLocaleLowerCase('tr').replace(/(^|\s)\S/g, c => c.toLocaleUpperCase('tr'));
// Uygulamadaki "Günlük" ve "İşler" sekmesiyle aynı tanımlar.
function dailySummary(day = dayKey(new Date())) {
  const jobs = all('SELECT * FROM jobs WHERE deleted_at IS NULL').map(jobRow);
  const custs = new Map(all('SELECT * FROM customers WHERE deleted_at IS NULL').map(r => [r.id, JSON.parse(r.data)]));
  const jday = j => j.tarih || dayKey(new Date(j.createdAt));
  const done = j => j.durum === 'TESLİM EDİLDİ';
  const tomorrow = dayKey(new Date(Date.now() + 864e5));
  const today = jobs.filter(j => jday(j) === day);
  const bySrc = new Map();
  for (const j of today) { const c = custs.get(j.musteriId); const k = c && c.kaynak ? srcTitleTR(c.kaynak) : 'Belirsiz'; bySrc.set(k, (bySrc.get(k) || 0) + 1); }
  return {
    day, n: today.length,
    sources: [...bySrc].sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(', ') || 'yok',
    won: today.filter(j => j.alindi === 'EVET').length,
    waiting: jobs.filter(j => !done(j) && j.alindi !== 'HAYIR' && j.donus !== 'EVET').length,
    late: jobs.filter(j => !done(j) && j.alindi !== 'HAYIR' && j.termin && j.termin < day).length,
    dueTomorrow: jobs.filter(j => !done(j) && j.alindi !== 'HAYIR' && j.termin === tomorrow).length
  };
}
// Şablon gövdesi (Meta'da onaylatılacak, 7 değişken):
// Çizgi günlük özet ({{1}}): Bugün {{2}} iş girdi. Kaynaklar: {{3}}. Alınan: {{4}}. Dönüş bekleyen: {{5}}. Geciken: {{6}}. Yarın termini olan: {{7}}.
async function sendWhatsApp(s) {
  if (!waReady()) fail(400, 'WhatsApp ayarları sunucuda eksik.');
  const tpl = WA.template === 'hello_world'
    ? { name: 'hello_world', language: { code: 'en_US' } } // yalnızca bağlantıyı denemek için
    : { name: WA.template, language: { code: WA.lang }, components: [{ type: 'body', parameters:
        [s.day.split('-').reverse().join('.'), s.n, s.sources, s.won, s.waiting, s.late, s.dueTomorrow].map(v => ({ type: 'text', text: String(v) })) }] };
  let r, j = null;
  try {
    r = await fetch(`${WA.base}/${WA.ver}/${encodeURIComponent(WA.phoneId)}/messages`, {
      method: 'POST', headers: { Authorization: 'Bearer ' + WA.token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ messaging_product: 'whatsapp', to: WA.to, type: 'template', template: tpl }),
      signal: AbortSignal.timeout(15000)
    });
    j = await r.json().catch(() => null);
  } catch (e) { setSetting('wa_error', 'Meta sunucusuna ulaşılamadı: ' + e.message); fail(502, 'Meta sunucusuna ulaşılamadı.'); }
  if (!r.ok) {
    const msg = (j && j.error && (j.error.error_user_msg || j.error.message)) || ('HTTP ' + r.status);
    setSetting('wa_error', dayKey(new Date()) + ' · ' + msg);
    fail(502, 'WhatsApp gönderilemedi: ' + msg);
  }
  setSetting('wa_error', '');
  setSetting('wa_last', String(Date.now()));
  return { ok: true };
}
// Her dakika bakar: saat geldiyse ve bugün gönderilmediyse gönderir. Sunucu geç açılırsa o gün yine bir kez gönderir.
let waBusy = false;
async function waTick() {
  if (!waReady() || waBusy) return;
  const now = new Date(), today = dayKey(now);
  if (now.getHours() < WA.hour || setting('wa_day') === today) return;
  if (setting('wa_fail_day') === today && Number(setting('wa_fails') || 0) >= 3) return; // günde en fazla 3 deneme
  waBusy = true;
  try { await sendWhatsApp(dailySummary(today)); setSetting('wa_day', today); console.log('WhatsApp özeti gönderildi'); }
  catch (e) {
    const n = setting('wa_fail_day') === today ? Number(setting('wa_fails') || 0) + 1 : 1;
    setSetting('wa_fail_day', today); setSetting('wa_fails', String(n));
    console.error('WhatsApp özeti gönderilemedi:', e.message);
  } finally { waBusy = false; }
}
setInterval(() => { waTick().catch(() => {}); }, 60e3).unref();

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
  if (mutating && req.headers['x-is'] !== '1') fail(403, 'Geçersiz istek.');

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

  if (m === 'GET' && p === '/api/state') {
    return send(res, 200, { me, stages: STAGES, sources: getSources(),
      customers: all('SELECT * FROM customers WHERE deleted_at IS NULL').map(custRow),
      jobs: all('SELECT * FROM jobs WHERE deleted_at IS NULL').map(jobRow) });
  }

  /* müşteriler */
  let mm0;
  if (m === 'POST' && p === '/api/customers') return send(res, 200, createCustomer(await readJson(req), me.name));
  if ((mm0 = p.match(/^\/api\/customers\/([\w-]{4,40})(\/log|\/merge)?$/))) {
    const id = mm0[1];
    if (m === 'GET' && mm0[2] === '/log') {
      return send(res, 200, all('SELECT t,user,changes FROM custlog WHERE cust_id=? ORDER BY t DESC, id DESC LIMIT 200', id).map(l => ({ t: l.t, user: l.user, changes: JSON.parse(l.changes) })));
    }
    if (m === 'POST' && mm0[2] === '/merge') {
      const b = await readJson(req);
      return send(res, 200, mergeCustomer(id, str(b.into, 40), me.name));
    }
    if (m === 'PATCH' && !mm0[2]) return send(res, 200, patchCustomer(id, await readJson(req), me.name));
    if (m === 'DELETE' && !mm0[2]) {
      needAdmin();
      tx(() => {
        if (!get('SELECT 1 FROM customers WHERE id=? AND deleted_at IS NULL', id)) fail(404, 'Müşteri bulunamadı.');
        if (all('SELECT data FROM jobs WHERE deleted_at IS NULL').some(j => JSON.parse(j.data).musteriId === id)) fail(409, 'Bu müşteriye bağlı işler var; önce işleri silin ya da müşteriyi başka bir kayıtla birleştirin.');
        const t = Date.now();
        run('UPDATE customers SET deleted_at=? WHERE id=?', t, id);
        custLog(id, t, me.name, [{ f: '_del' }]);
      });
      return send(res, 200, { ok: true });
    }
  }
  if (m === 'GET' && p === '/api/wa') {
    needAdmin();
    const s = dailySummary();
    return send(res, 200, { ready: waReady(), to: WA.to ? '+' + WA.to.slice(0, 4) + '•••' + WA.to.slice(-4) : null, hour: WA.hour, template: WA.template,
      last: Number(setting('wa_last')) || null, error: setting('wa_error') || null,
      preview: `Çizgi günlük özet (${s.day.split('-').reverse().join('.')}): Bugün ${s.n} iş girdi. Kaynaklar: ${s.sources}. Alınan: ${s.won}. Dönüş bekleyen: ${s.waiting}. Geciken: ${s.late}. Yarın termini olan: ${s.dueTomorrow}.` });
  }
  if (m === 'POST' && p === '/api/wa/test') { needAdmin(); return send(res, 200, await sendWhatsApp(dailySummary())); }
  if (m === 'PUT' && p === '/api/sources') {
    needAdmin();
    const b = await readJson(req);
    if (!Array.isArray(b.sources)) fail(400, 'Geçersiz liste.');
    const list = [...new Set(b.sources.map(x => nameKey(str(x, 40))).filter(Boolean))];
    if (!list.length) fail(400, 'En az bir kaynak olmalı.');
    if (list.length > 30) fail(400, 'En fazla 30 kaynak olabilir.');
    const used = new Set(all('SELECT data FROM customers WHERE deleted_at IS NULL').map(c => JSON.parse(c.data).kaynak).filter(Boolean));
    const missing = [...used].filter(s => !list.includes(s));
    if (missing.length) fail(409, `${missing.join(', ')} kaynağına bağlı müşteriler var; önce o müşterilerin kaynağını değiştirin.`);
    run("INSERT INTO settings(key,value) VALUES('sources',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", JSON.stringify(list));
    return send(res, 200, { sources: list });
  }

  /* işler */
  if (m === 'POST' && p === '/api/jobs') return send(res, 200, createJob(await readJson(req), me.name));
  let mm;
  if ((mm = p.match(/^\/api\/jobs\/([\w-]{4,40})(\/log)?$/))) {
    const id = mm[1];
    if (m === 'GET' && mm[2]) {
      return send(res, 200, all('SELECT t,user,changes FROM joblog WHERE job_id=? ORDER BY t DESC, id DESC LIMIT 200', id).map(l => ({ t: l.t, user: l.user, changes: JSON.parse(l.changes) })));
    }
    if (m === 'PATCH' && !mm[2]) return send(res, 200, patchJob(id, await readJson(req), me.name));
    if (m === 'DELETE' && !mm[2]) {
      needAdmin();
      tx(() => {
        if (!get('SELECT 1 FROM jobs WHERE id=? AND deleted_at IS NULL', id)) fail(404, 'İş bulunamadı.');
        const t = Date.now();
        run('UPDATE jobs SET deleted_at=? WHERE id=?', t, id);
        logChange(id, t, me.name, [{ f: '_del' }]);
      });
      return send(res, 200, { ok: true });
    }
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
    const b = Buffer.from(JSON.stringify(exportData()));
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': b.length, 'Cache-Control': 'no-store',
      'Content-Disposition': `attachment; filename="is-takip-yedek-${dayKey(new Date())}.json"` });
    return res.end(b);
  }
  if (m === 'POST' && p === '/api/import') {
    needAdmin();
    return send(res, 200, importData(await readJson(req, 50e6), me));
  }

  fail(404, 'Bulunamadı.');
}

http.createServer((req, res) => {
  handle(req, res).catch(e => {
    if (res.headersSent) return res.end();
    if (e instanceof HttpError) return send(res, e.code, { error: e.message, ...(e.extra || {}) });
    console.error(e);
    send(res, 500, { error: 'Sunucu hatası. Tekrar deneyin.' });
  });
}).listen(PORT, () => console.log('Çizgi İş Takibi ' + PORT + ' portunda çalışıyor'));
