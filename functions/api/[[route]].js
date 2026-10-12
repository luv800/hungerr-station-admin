// Cloudflare Pages Function: serves every /api/* route.
// Needs: D1 binding named "DB" and a secret named ADMIN_PASSWORD.
const STATUSES = ['New', 'Preparing', 'Completed', 'Cancelled'];
const PAYS = ['cash', 'paytm', 'gpay', 'phonepe'];
const enc = new TextEncoder();

const json = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
});
const str = (v, n) => (typeof v === 'string' ? v.trim().slice(0, n) : '');
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const sha = async s => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const same = (a, b) => { let d = a.length ^ b.length; for (let i = 0; i < a.length; i++) d |= a[i] ^ (b[i] || 0); return d === 0; };

// Login tokens are stateless: "expiry.HMAC(expiry)", signed with the admin password.
const sign = async (env, text) => {
  const key = await crypto.subtle.importKey('raw', enc.encode(env.ADMIN_PASSWORD), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(text)));
};
const makeToken = async env => { const exp = String(Date.now() + 12 * 3600e3); return exp + '.' + await sign(env, exp); };
async function isAdmin(env, req) {
  const [exp, sig] = (req.headers.get('Authorization') || '').replace(/^Bearer /, '').split('.');
  if (!env.ADMIN_PASSWORD || !exp || !sig || !(Number(exp) > Date.now())) return false;
  return same(enc.encode(sig), enc.encode(await sign(env, exp)));
}

async function body(req) {
  if (Number(req.headers.get('Content-Length') || 0) > 65536) throw new Error('too big');
  try { return JSON.parse(await req.text()) || {}; } catch { return {}; }
}
function cleanCustomer(b) {
  const c = {
    phone: str(b.phone, 10), name: str(b.name, 60),
    gender: ['Male', 'Female'].includes(b.gender) ? b.gender : '',
    dob: /^\d{4}-\d{2}-\d{2}$/.test(b.dob) ? b.dob : '',
    branch: /^[a-z0-9_-]{1,30}$/.test(b.branch) ? b.branch : ''
  };
  return /^[6-9]\d{9}$/.test(c.phone) && c.name.length >= 2 ? c : null;
}
// New mobile number  -> a new customer row.
// Existing number    -> the stored row is kept exactly as it is: nothing already saved is overwritten and no duplicate is made.
//                       Only fields that are still blank (gender / DOB / branch) are filled in if the customer gives them later.
const upsertCustomer = (env, c, now) => env.DB.prepare(
  `INSERT INTO customers (phone,name,gender,dob,branch,created_at,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?6)
   ON CONFLICT(phone) DO UPDATE SET
     gender=COALESCE(NULLIF(gender,''),NULLIF(?3,''),gender),
     dob=COALESCE(NULLIF(dob,''),NULLIF(?4,''),dob),
     branch=COALESCE(NULLIF(branch,''),NULLIF(?5,''),branch),
     last_seen=?6`
).bind(c.phone, c.name, c.gender, c.dob, c.branch, now);

// Live refresh: one counter that goes up on every change. The admin panel checks this single row every
// couple of seconds and only downloads the full data when the number has changed.
let metaReady = false;
async function ensureMeta(env) {
  if (metaReady) return;
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS push_subs (endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL, ts INTEGER NOT NULL)').run();
  metaReady = true;
}
const bump = env => env.DB.prepare("INSERT INTO meta (k,v) VALUES ('v',1) ON CONFLICT(k) DO UPDATE SET v=v+1");

// ---- Web Push: alerts on the admin's phone even when the panel is closed ----
// Needs two secrets (made once with:  npx web-push generate-vapid-keys):  VAPID_PUBLIC  and  VAPID_PRIVATE
const b64u = {
  enc: b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: s => Uint8Array.from(atob(String(s).replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
};
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
async function vapidJwt(env, aud) {
  const pub = b64u.dec(env.VAPID_PUBLIC);
  const key = await crypto.subtle.importKey('jwk',
    { kty: 'EC', crv: 'P-256', x: b64u.enc(pub.slice(1, 33)), y: b64u.enc(pub.slice(33, 65)), d: env.VAPID_PRIVATE, ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const h = b64u.enc(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const c = b64u.enc(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || 'https://hungerrstation.pages.dev' })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(h + '.' + c));
  return h + '.' + c + '.' + b64u.enc(sig);
}
async function encryptPush(sub, text) {   // RFC 8291 (aes128gcm)
  const ua = b64u.dec(sub.p256dh), authSecret = b64u.dec(sub.auth);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, eph.privateKey, 256));
  const hk = async (salt, ikm, info, len) => new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info }, await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']), len * 8));
  const ikm = await hk(authSecret, secret, cat(enc.encode('WebPush: info\0'), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hk(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hk(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, cat(enc.encode(text), new Uint8Array([2]))));
  return cat(salt, new Uint8Array([0, 0, 16, 0, 65]), asPub, ct);
}
async function pushAll(env, payload) {
  if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE) return;
  try {
    const subs = (await env.DB.prepare('SELECT endpoint,p256dh,auth FROM push_subs').all()).results, text = JSON.stringify(payload);
    await Promise.all(subs.map(async s => {
      try {
        const jwt = await vapidJwt(env, new URL(s.endpoint).origin);
        const r = await fetch(s.endpoint, {
          method: 'POST',
          headers: { 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'high',
                     Authorization: 'vapid t=' + jwt + ', k=' + env.VAPID_PUBLIC },
          body: await encryptPush(s, text)
        });
        if (r.status === 404 || r.status === 410) await env.DB.prepare('DELETE FROM push_subs WHERE endpoint=?').bind(s.endpoint).run();   // phone uninstalled / revoked
      } catch (e) {}
    }));
  } catch (e) {}
}
// ---- end Web Push ----

export async function onRequest({ request: req, env, params, waitUntil }) {
  const path = '/' + [].concat(params.route || []).join('/'), m = req.method;
  try {
    if (!env.DB) return json({ error: 'Database not connected (bind D1 as "DB")' }, 500);
    await ensureMeta(env);

    // ---- public: called by the customer site ----
    if (m === 'POST' && path === '/customers') {
      const c = cleanCustomer(await body(req));
      if (!c) return json({ error: 'Invalid details' }, 400);
      const [before] = await env.DB.batch([
        env.DB.prepare('SELECT 1 AS x FROM customers WHERE phone=?').bind(c.phone),   // runs before the upsert below
        upsertCustomer(env, c, new Date().toISOString()),
        bump(env)
      ]);
      return json({ ok: true, existing: before.results.length > 0 });
    }
    if (m === 'POST' && path === '/orders') {
      const b = await body(req), c = cleanCustomer(b), cid = str(b.cid, 60);
      const items = Array.isArray(b.items) ? b.items.slice(0, 50).map(i => ({
        id: str(i && i.id, 20), name: str(i && i.name, 160), price: Math.round(Number(i && i.price))
      })) : [];
      if (!c || !cid || !items.length || items.some(i => !i.name || !(i.price >= 0 && i.price <= 100000)))
        return json({ error: 'Invalid order' }, 400);
      const now = new Date().toISOString(), subtotal = items.reduce((a, i) => a + i.price, 0), t = Math.round(Number(b.total));
      const res = await env.DB.batch([
        upsertCustomer(env, c, now),
        env.DB.prepare('INSERT OR IGNORE INTO orders (cid,ts,status,phone,name,branch,mode,pay,subtotal,total,items) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
          .bind(cid, now, 'New', c.phone, c.name, c.branch, b.mode === 'delivery' ? 'delivery' : 'dining',
                PAYS.includes(b.pay) ? b.pay : 'cash', subtotal, t >= 0 && t <= 1e6 ? t : subtotal, JSON.stringify(items)),
        bump(env)
      ]);
      const r = await env.DB.prepare('SELECT seq FROM orders WHERE cid=?').bind(cid).first();   // same cid = same order, no duplicates
      if (res[1].meta.changes > 0 && waitUntil)   // only a genuinely new order alerts the admin (retries of the same order do not)
        waitUntil(pushAll(env, { kind: 'new', tag: 'new-' + r.seq, title: 'New order HS-' + (1000 + r.seq),
          body: c.name + ' \u00B7 \u20B9' + (t >= 0 && t <= 1e6 ? t : subtotal) + ' \u00B7 ' + items.length + ' item' + (items.length > 1 ? 's' : '') + ' \u00B7 ' + (b.mode === 'delivery' ? 'Delivery' : 'Dining / Takeaway') }));
      return json({ ok: true, id: 'HS-' + (1000 + r.seq) });
    }

    // Customer site asks "what is the status of my orders?". Only the order number and status come back (no names, items or phone numbers),
    // and an order can only be looked up by its long private id (cid) that only that customer's browser knows.
    if (m === 'POST' && path === '/orders/status') {
      const b = await body(req);
      const cids = (Array.isArray(b.cids) ? b.cids : []).slice(0, 20).map(x => str(x, 60)).filter(Boolean);
      if (!cids.length) return json({ orders: [] });
      const r = await env.DB.prepare(`SELECT cid, seq, status FROM orders WHERE cid IN (${cids.map(() => '?').join(',')})`).bind(...cids).all();
      return json({ orders: r.results.map(x => ({ cid: x.cid, id: 'HS-' + (1000 + x.seq), status: x.status })) });
    }

    // ---- admin ----
    if (m === 'POST' && path === '/admin/login') {
      if (!env.ADMIN_PASSWORD) return json({ error: 'Set the ADMIN_PASSWORD secret and redeploy' }, 503);
      const ip = req.headers.get('CF-Connecting-IP') || 'unknown', since = Date.now() - 15 * 60e3;
      const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM attempts WHERE ip=? AND ts>?').bind(ip, since).first();
      if (n.n >= 10) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);
      const given = (await body(req)).password;
      if (!same(await sha(typeof given === 'string' ? given.slice(0, 200) : ''), await sha(env.ADMIN_PASSWORD))) {
        await env.DB.batch([env.DB.prepare('INSERT INTO attempts (ip,ts) VALUES (?,?)').bind(ip, Date.now()),
                            env.DB.prepare('DELETE FROM attempts WHERE ts<?').bind(since)]);
        return json({ error: 'Wrong password' }, 401);
      }
      return json({ token: await makeToken(env) });
    }
    if (path.startsWith('/admin/')) {
      if (!(await isAdmin(env, req))) return json({ error: 'Unauthorized' }, 401);
      if (m === 'GET' && path === '/admin/push-key') return json({ key: env.VAPID_PUBLIC && env.VAPID_PRIVATE ? env.VAPID_PUBLIC : '' });
      if (m === 'POST' && path === '/admin/push/subscribe') {
        const b = await body(req), k = b.keys || {};
        if (typeof b.endpoint !== 'string' || !/^https:\/\//.test(b.endpoint) || b.endpoint.length > 600 || typeof k.p256dh !== 'string' || typeof k.auth !== 'string')
          return json({ error: 'Invalid subscription' }, 400);
        await env.DB.prepare('INSERT INTO push_subs (endpoint,p256dh,auth,ts) VALUES (?1,?2,?3,?4) ON CONFLICT(endpoint) DO UPDATE SET p256dh=?2,auth=?3,ts=?4')
          .bind(b.endpoint, k.p256dh.slice(0, 200), k.auth.slice(0, 100), Date.now()).run();
        return json({ ok: true });
      }
      if (m === 'POST' && path === '/admin/push/unsubscribe') {
        await env.DB.prepare('DELETE FROM push_subs WHERE endpoint=?').bind(str((await body(req)).endpoint, 600)).run();
        return json({ ok: true });
      }
      if (m === 'GET' && path === '/admin/ping') {
        const r = await env.DB.prepare("SELECT v FROM meta WHERE k='v'").first();
        return json({ v: r ? r.v : 0 });
      }
      if (m === 'GET' && path === '/admin/data') {
        const o = await env.DB.prepare('SELECT * FROM orders ORDER BY seq DESC LIMIT 2000').all();
        const c = await env.DB.prepare('SELECT * FROM customers ORDER BY last_seen DESC LIMIT 5000').all();
        return json({
          orders: o.results.map(r => ({ id: 'HS-' + (1000 + r.seq), ts: r.ts, status: r.status, phone: r.phone, name: r.name,
            branch: r.branch, mode: r.mode, pay: r.pay, subtotal: r.subtotal, total: r.total, items: JSON.parse(r.items) })),
          customers: c.results.map(r => ({ phone: r.phone, name: r.name, gender: r.gender, dob: r.dob, branch: r.branch,
            createdAt: r.created_at, lastSeen: r.last_seen }))
        });
      }
      const st = path.match(/^\/admin\/orders\/HS-(\d+)\/status$/);
      if (m === 'PATCH' && st) {
        const s = (await body(req)).status;
        if (!STATUSES.includes(s)) return json({ error: 'Invalid request' }, 400);
        const [r] = await env.DB.batch([
          env.DB.prepare('UPDATE orders SET status=? WHERE seq=?').bind(s, Number(st[1]) - 1000),
          bump(env)
        ]);
        if (!r.meta.changes) return json({ error: 'Order not found' }, 404);
        if (waitUntil) {
          const o = await env.DB.prepare('SELECT name,total FROM orders WHERE seq=?').bind(Number(st[1]) - 1000).first();
          if (o) waitUntil(pushAll(env, { kind: 'status', tag: 'st-' + st[1], title: 'Order HS-' + st[1] + ' \u2192 ' + s, body: o.name + ' \u00B7 \u20B9' + o.total }));
        }
        return json({ ok: true });
      }
    }
    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ error: 'Server error' }, 500);
  }
}
