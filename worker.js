// Wellen-Desk Server (Cloudflare Worker)
// Verbindet deine App sicher mit Bybit. Die API-Schlüssel liegen NUR hier (als verschlüsselte Secrets),
// nie auf dem Handy. Auszahlungen sind technisch ausgeschlossen (nur freigegebene Pfade).
//
// Benötigte Einstellungen in Cloudflare (Settings → Variables and Secrets):
//   APP_PASSWORD       (Secret)  dein App-Passwort für den Live-Zugang
//   TOKEN_SECRET       (Secret)  langer Zufallstext (erzeugt die App für dich)
//   BYBIT_DEMO_KEY     (Secret)  API-Key aus dem Bybit-Demo-Handel
//   BYBIT_DEMO_SECRET  (Secret)  API-Secret aus dem Bybit-Demo-Handel
//   BYBIT_KEY          (Secret)  echter API-Key (erst später)
//   BYBIT_SECRET       (Secret)  echtes API-Secret (erst später)
//   ALLOWED_ORIGIN     (Text)    https://w4cf2z7k76-ai.github.io

const VERSION = '1.0';
const HOSTS = { demo: 'https://api-demo.bybit.com', live: 'https://api.bybit.com' };
const RECV = '10000';

// Nur diese Bybit-Funktionen sind erlaubt – KEINE Auszahlungen, KEINE Überweisungen.
const ALLOW = {
  'GET /v5/account/wallet-balance': 1,
  'GET /v5/account/info': 1,
  'GET /v5/position/list': 1,
  'GET /v5/order/realtime': 1,
  'GET /v5/order/history': 1,
  'GET /v5/execution/list': 1,
  'GET /v5/position/closed-pnl': 1,
  'GET /v5/market/instruments-info': 1,
  'GET /v5/market/tickers': 1,
  'GET /v5/user/query-api': 1,
  'POST /v5/order/create': 1,
  'POST /v5/order/amend': 1,
  'POST /v5/order/cancel': 1,
  'POST /v5/order/cancel-all': 1,
  'POST /v5/position/set-leverage': 1,
  'POST /v5/position/trading-stop': 1,
  'POST /v5/position/switch-isolated': 1,
  'POST /v5/account/set-margin-mode': 1,
};

const enc = new TextEncoder();
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
async function hmac(secret, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
function safeEq(a, b) { // Vergleich ohne Zeit-Leck
  a = String(a || ''); b = String(b || '');
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}
function cors(env, req) {
  const o = req.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  const ok = allowed.includes(o) || o.startsWith('http://localhost') || o.startsWith('http://127.0.0.1');
  return {
    'Access-Control-Allow-Origin': ok ? o : (allowed[0] || 'null'),
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}
const json = (h, obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...h, 'Content-Type': 'application/json' } });

async function makeToken(env, hours) {
  const exp = Date.now() + hours * 3600e3;
  const body = `v1.${exp}`;
  return `${body}.${await hmac(env.TOKEN_SECRET, body)}`;
}
async function checkToken(env, tok) {
  if (!tok || !env.TOKEN_SECRET) return false;
  const p = tok.split('.');
  if (p.length !== 3 || p[0] !== 'v1') return false;
  const exp = +p[1];
  if (!(exp > Date.now())) return false;
  return safeEq(p[2], await hmac(env.TOKEN_SECRET, `${p[0]}.${p[1]}`));
}

async function bybit(env, which, method, path, params) {
  const key = which === 'live' ? env.BYBIT_KEY : env.BYBIT_DEMO_KEY;
  const sec = which === 'live' ? env.BYBIT_SECRET : env.BYBIT_DEMO_SECRET;
  if (!key || !sec) return { status: 400, body: { error: 'nokey', msg: `Kein ${which === 'live' ? 'Live' : 'Demo'}-Schlüssel auf dem Server eingetragen` } };
  const ts = String(Date.now());
  let url = HOSTS[which] + path, payload = '', init = { method, headers: {} };
  if (method === 'GET') {
    const q = new URLSearchParams();
    Object.keys(params || {}).forEach(k => { if (params[k] !== undefined && params[k] !== null && params[k] !== '') q.append(k, String(params[k])); });
    payload = q.toString();
    if (payload) url += '?' + payload;
  } else {
    payload = JSON.stringify(params || {});
    init.body = payload;
    init.headers['Content-Type'] = 'application/json';
  }
  const sign = await hmac(sec, ts + key + RECV + payload);
  Object.assign(init.headers, { 'X-BAPI-API-KEY': key, 'X-BAPI-TIMESTAMP': ts, 'X-BAPI-RECV-WINDOW': RECV, 'X-BAPI-SIGN': sign });
  let r, txt;
  try { r = await fetch(url, init); txt = await r.text(); }
  catch (e) { return { status: 502, body: { error: 'network', msg: 'Bybit nicht erreichbar: ' + e.message } }; }
  let body;
  try { body = JSON.parse(txt); } catch (_) { body = { error: 'http', msg: `Bybit antwortet mit HTTP ${r.status}` + (r.status === 403 ? ' (Zugriff aus diesem Land/Rechenzentrum gesperrt?)' : ''), raw: txt.slice(0, 200) }; }
  return { status: 200, body };
}

export default {
  async fetch(req, env) {
    const h = cors(env, req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: h });
    const url = new URL(req.url);
    try {
      if (url.pathname === '/' || url.pathname === '/ping')
        return json(h, { ok: true, app: 'wellen-desk', version: VERSION, colo: (req.cf && req.cf.colo) || null, country: (req.cf && req.cf.country) || null });

      if (url.pathname === '/login' && req.method === 'POST') {
        if (!env.APP_PASSWORD || !env.TOKEN_SECRET) return json(h, { error: 'setup', msg: 'APP_PASSWORD und TOKEN_SECRET fehlen in Cloudflare' }, 500);
        const b = await req.json().catch(() => ({}));
        if (!safeEq(b.password, env.APP_PASSWORD)) { await new Promise(r => setTimeout(r, 1200)); return json(h, { error: 'auth', msg: 'Falsches Passwort' }, 401); }
        return json(h, { ok: true, token: await makeToken(env, 12), hours: 12, demo: !!(env.BYBIT_DEMO_KEY && env.BYBIT_DEMO_SECRET), live: !!(env.BYBIT_KEY && env.BYBIT_SECRET) });
      }

      // Ab hier nur mit gültigem Token
      const tok = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
      if (!(await checkToken(env, tok))) return json(h, { error: 'auth', msg: 'Anmeldung abgelaufen – bitte neu entsperren' }, 401);

      if (url.pathname === '/status')
        return json(h, { ok: true, version: VERSION, demo: !!(env.BYBIT_DEMO_KEY && env.BYBIT_DEMO_SECRET), live: !!(env.BYBIT_KEY && env.BYBIT_SECRET), colo: (req.cf && req.cf.colo) || null });

      if (url.pathname === '/bybit' && req.method === 'POST') {
        const b = await req.json().catch(() => ({}));
        const which = b.env === 'live' ? 'live' : 'demo';
        const method = b.method === 'POST' ? 'POST' : 'GET';
        const path = String(b.path || '');
        if (!ALLOW[`${method} ${path}`]) return json(h, { error: 'forbidden', msg: `Nicht erlaubt: ${method} ${path}` }, 403);
        const r = await bybit(env, which, method, path, b.params || {});
        return json(h, r.body, r.status);
      }
      return json(h, { error: 'notfound' }, 404);
    } catch (e) {
      return json(h, { error: 'server', msg: String(e && e.message || e) }, 500);
    }
  },
};
