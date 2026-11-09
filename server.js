'use strict';
// Bağımlılık yok. Kayıtlar DATA_DIR/db.json dosyasında. Tek kullanıcı, tek şifre.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const PASS = process.env.PANEL_PASSWORD;
if (!PASS) { console.error('PANEL_PASSWORD ortam değişkeni gerekli'); process.exit(1); }
const SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update('siparis|' + PASS).digest('hex');
const DIR = process.env.DATA_DIR || '/data';
const FILE = path.join(DIR, 'db.json');
const INDEX = fs.readFileSync(path.join(__dirname, 'index.html'));

fs.mkdirSync(DIR, { recursive: true });
let db = { orders: {}, settings: {} };
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); }
catch (e) { if (e.code !== 'ENOENT') throw e; } // bozuk dosyanın üzerine yazma, başlatmayı durdur
db.orders = db.orders || {};
db.settings = db.settings || {};

function save() {
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, FILE);
}

const sha = s => crypto.createHash('sha256').update(s).digest();
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const mkToken = () => { const exp = Date.now() + 30 * 864e5; return exp + '.' + sign(String(exp)); };
function okToken(t) {
  if (!t) return false;
  const [exp, sig] = t.split('.');
  if (!sig || !(+exp > Date.now())) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function cookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}

const tries = new Map(); // ip -> {n, t}; 15 dakikada en fazla 10 deneme
function limited(ip) {
  const now = Date.now(), r = tries.get(ip);
  if (!r || now - r.t > 15 * 60e3) { tries.set(ip, { n: 0, t: now }); return false; }
  return r.n >= 10;
}

const HEAD = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store'
};
function send(res, code, data, type, extra) {
  res.writeHead(code, Object.assign({ 'Content-Type': type || 'text/plain; charset=utf-8' }, HEAD, extra || {}));
  res.end(data);
}
const json = (res, code, obj, extra) => send(res, code, JSON.stringify(obj), 'application/json; charset=utf-8', extra);
const redirect = (res, to, extra) => send(res, 303, '', 'text/plain', Object.assign({ Location: to }, extra || {}));

function readBody(req, max = 1e6) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', d => {
      n += d.length;
      if (n > max) { reject(Object.assign(new Error('big'), { status: 413 })); req.destroy(); }
      else chunks.push(d);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
async function readJSON(req) {
  if (!/^application\/json/i.test(req.headers['content-type'] || '')) throw Object.assign(new Error('type'), { status: 415 });
  let v;
  try { v = JSON.parse(await readBody(req)); } catch (e) { throw Object.assign(new Error('json'), { status: 400 }); }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw Object.assign(new Error('obj'), { status: 400 });
  return v;
}

const LOGIN = bad => `<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sipariş Takip · Giriş</title>
<style>
:root{--bg:#eceff2;--s:#fff;--ink:#17212b;--line:#d6dce2;--a:#1d5a85;--bad:#b0301c;color-scheme:light dark}
@media(prefers-color-scheme:dark){:root{--bg:#0f151a;--s:#172029;--ink:#e6ebef;--line:#2b3743;--a:#6db1e2;--bad:#f08c78}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,'Segoe UI',Arial,sans-serif;padding:16px}
form{background:var(--s);border:1px solid var(--line);border-radius:8px;padding:24px;width:100%;max-width:340px;display:grid;gap:12px}
h1{margin:0;font-size:18px}
input,button{font:inherit;padding:9px 10px;border-radius:6px;border:1px solid var(--line);background:var(--s);color:var(--ink)}
button{background:var(--a);border-color:var(--a);color:#fff;font-weight:600;cursor:pointer}
p{margin:0;color:var(--bad)}
</style></head><body><form method="post" action="/login"><h1>Sipariş Takip</h1>
<input type="password" name="p" placeholder="Şifre" autocomplete="current-password" autofocus required>
${bad ? '<p>Şifre yanlış.</p>' : ''}<button>Giriş</button></form></body></html>`;

const ID = /^[A-Za-z0-9_-]{1,64}$/;

const server = http.createServer(async (req, res) => {
  try {
    const p = new URL(req.url, 'http://x').pathname, m = req.method;
    if (p === '/health') return send(res, 200, 'ok');

    if (p === '/login') {
      if (m === 'GET') return send(res, 200, LOGIN(false), 'text/html; charset=utf-8');
      if (m === 'POST') {
        const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
        if (limited(ip)) return send(res, 429, 'Çok fazla deneme. 15 dakika sonra tekrar deneyin.');
        const given = new URLSearchParams(await readBody(req, 4096)).get('p') || '';
        if (crypto.timingSafeEqual(sha(given), sha(PASS))) {
          tries.delete(ip);
          const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
          return redirect(res, '/', { 'Set-Cookie': 'sid=' + mkToken() + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000' + secure });
        }
        tries.get(ip).n++;
        return send(res, 401, LOGIN(true), 'text/html; charset=utf-8');
      }
    }
    if (p === '/logout') return redirect(res, '/login', { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });

    const authed = okToken(cookie(req, 'sid'));
    if (p === '/' || p === '/index.html') {
      if (!authed) return redirect(res, '/login');
      return send(res, 200, INDEX, 'text/html; charset=utf-8');
    }
    if (!p.startsWith('/api/')) return send(res, 404, 'Bulunamadı');
    if (!authed) return json(res, 401, { error: 'auth' });

    if (p === '/api/orders' && m === 'GET') return json(res, 200, Object.keys(db.orders).map(id => Object.assign({}, db.orders[id], { id })));
    if (p === '/api/settings' && m === 'GET') return json(res, 200, db.settings);
    if (p === '/api/settings' && m === 'PUT') {
      const b = await readJSON(req);
      db.settings = { firmaAdi: String(b.firmaAdi || '').slice(0, 200), iletisim: String(b.iletisim || '').slice(0, 500) };
      save();
      return json(res, 200, { ok: true });
    }
    if (p === '/api/export' && m === 'GET') {
      const name = 'siparis-yedek-' + new Date().toISOString().slice(0, 10) + '.json';
      return json(res, 200, db, { 'Content-Disposition': 'attachment; filename="' + name + '"' });
    }
    const mm = p.match(/^\/api\/orders\/([^/]+)$/);
    if (mm) {
      const id = decodeURIComponent(mm[1]);
      if (!ID.test(id)) return json(res, 400, { error: 'id' });
      if (m === 'PUT') {
        const b = await readJSON(req);
        delete b.id;
        db.orders[id] = b;
        save();
        return json(res, 200, { ok: true });
      }
      if (m === 'PATCH') {
        if (!db.orders[id]) return json(res, 404, { error: 'yok' });
        const b = await readJSON(req);
        if (Array.isArray(b.log)) db.orders[id].log = b.log; // sayfa yalnızca günlüğü yamalar
        save();
        return json(res, 200, { ok: true });
      }
      if (m === 'DELETE') {
        delete db.orders[id];
        save();
        return json(res, 200, { ok: true });
      }
    }
    return json(res, 404, { error: 'yok' });
  } catch (e) {
    if (!res.headersSent) json(res, e.status || 500, { error: e.status ? e.message : 'sunucu' });
    if (!e.status) console.error(e);
  }
});
server.listen(PORT, () => console.log('Sipariş Takip dinliyor: ' + PORT));
