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
const upsertCustomer = (env, c, now) => env.DB.prepare(
  `INSERT INTO customers (phone,name,gender,dob,branch,created_at,last_seen) VALUES (?1,?2,?3,?4,?5,?6,?6)
   ON CONFLICT(phone) DO UPDATE SET name=?2, gender=COALESCE(NULLIF(?3,''),gender),
   dob=COALESCE(NULLIF(?4,''),dob), branch=COALESCE(NULLIF(?5,''),branch), last_seen=?6`
).bind(c.phone, c.name, c.gender, c.dob, c.branch, now);

export async function onRequest({ request: req, env, params }) {
  const path = '/' + [].concat(params.route || []).join('/'), m = req.method;
  try {
    if (!env.DB) return json({ error: 'Database not connected (bind D1 as "DB")' }, 500);

    // ---- public: called by the customer site ----
    if (m === 'POST' && path === '/customers') {
      const c = cleanCustomer(await body(req));
      if (!c) return json({ error: 'Invalid details' }, 400);
      await upsertCustomer(env, c, new Date().toISOString()).run();
      return json({ ok: true });
    }
    if (m === 'POST' && path === '/orders') {
      const b = await body(req), c = cleanCustomer(b), cid = str(b.cid, 60);
      const items = Array.isArray(b.items) ? b.items.slice(0, 50).map(i => ({
        id: str(i && i.id, 20), name: str(i && i.name, 160), price: Math.round(Number(i && i.price))
      })) : [];
      if (!c || !cid || !items.length || items.some(i => !i.name || !(i.price >= 0 && i.price <= 100000)))
        return json({ error: 'Invalid order' }, 400);
      const now = new Date().toISOString(), subtotal = items.reduce((a, i) => a + i.price, 0), t = Math.round(Number(b.total));
      await env.DB.batch([
        upsertCustomer(env, c, now),
        env.DB.prepare('INSERT OR IGNORE INTO orders (cid,ts,status,phone,name,branch,mode,pay,subtotal,total,items) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
          .bind(cid, now, 'New', c.phone, c.name, c.branch, b.mode === 'delivery' ? 'delivery' : 'dining',
                PAYS.includes(b.pay) ? b.pay : 'cash', subtotal, t >= 0 && t <= 1e6 ? t : subtotal, JSON.stringify(items))
      ]);
      const r = await env.DB.prepare('SELECT seq FROM orders WHERE cid=?').bind(cid).first();   // same cid = same order, no duplicates
      return json({ ok: true, id: 'HS-' + (1000 + r.seq) });
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
        const r = await env.DB.prepare('UPDATE orders SET status=? WHERE seq=?').bind(s, Number(st[1]) - 1000).run();
        return r.meta.changes ? json({ ok: true }) : json({ error: 'Order not found' }, 404);
      }
    }
    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ error: 'Server error' }, 500);
  }
}
