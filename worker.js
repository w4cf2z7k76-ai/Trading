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
//   ANTHROPIC_API_KEY  (Secret)  für die Claude-Analyse in der App (console.anthropic.com)
//   ALLOWED_ORIGIN     (Text)    https://w4cf2z7k76-ai.github.io

const VERSION = '2.5';
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


// ================= Web-Push (RFC 8291 aes128gcm + VAPID) =================
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ub64u = s => { s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0), o = new Uint8Array(n); let i = 0; a.forEach(x => { o.set(x, i); i += x.length; }); return o; };
async function hmacRaw(key, data) { const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC', k, data)); }
function vapidJwk(env) { try { const j = JSON.parse(env.VAPID_JWK || ''); return j && j.d && j.x && j.y ? j : null; } catch (_) { return null; } }
const vapidPub = j => cat(new Uint8Array([4]), ub64u(j.x), ub64u(j.y));
async function vapidAuth(env, endpoint) {
  const j = vapidJwk(env), aud = new URL(endpoint).origin;
  const hdr = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const pl = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'mailto:wellen-desk@users.noreply.github.com' })));
  const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: j.x, y: j.y, d: j.d, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(hdr + '.' + pl));
  return `vapid t=${hdr}.${pl}.${b64u(sig)}, k=${b64u(vapidPub(j))}`;
}
async function encryptPush(sub, payload) {
  const ua = ub64u(sub.keys.p256dh), auth = ub64u(sub.keys.auth);
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, kp.privateKey, 256));
  const prkKey = await hmacRaw(auth, ecdh);
  const ikm = (await hmacRaw(prkKey, cat(enc.encode('WebPush: info\0'), ua, asPub, new Uint8Array([1])))).slice(0, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmacRaw(salt, ikm);
  const cek = (await hmacRaw(prk, cat(enc.encode('Content-Encoding: aes128gcm\0'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmacRaw(prk, cat(enc.encode('Content-Encoding: nonce\0'), new Uint8Array([1])))).slice(0, 12);
  const k = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, k, cat(enc.encode(payload), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]);
  return cat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}
async function sendPush(env, sub, msg) {
  const body = await encryptPush(sub, JSON.stringify(msg));
  const r = await fetch(sub.endpoint, { method: 'POST', body, headers: { 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'high', Authorization: await vapidAuth(env, sub.endpoint) } });
  let txt = ''; try { txt = (await r.text()).slice(0, 160); } catch (_) {}
  return { status: r.status, txt };
}
async function pushAll(env, msg, skipAlive) {
  const KV = env.WDESK; const subs = (await KV.get('subs', 'json')) || []; if (!subs.length) return { sent: 0 };
  const alive = skipAlive ? ((await KV.get('alive', 'json')) || {}) : {}; const keep = [], res = []; let sent = 0, gone = false;
  for (const s of subs) {
    const host = (() => { try { return new URL(s.endpoint).host; } catch (_) { return '?'; } })();
    if (skipAlive && alive[s.dev] && Date.now() - alive[s.dev] < 4 * 60e3) { keep.push(s); res.push({ name: s.name, host, skip: 'App offen' }); continue; } // App ist offen → meldet selbst
    try { const r = await sendPush(env, s, msg); res.push({ name: s.name, host, status: r.status, txt: r.txt }); if (r.status === 404 || r.status === 410) { gone = true; continue; } if (r.status < 300) sent++; }
    catch (e) { res.push({ name: s.name, host, err: String(e && e.message || e) }); }
    keep.push(s);
  }
  if (gone) await KV.put('subs', JSON.stringify(keep));
  return { sent, res };
}
// Kurse für die Wachliste (Hoch/Tief der letzten 2 Minuten), Binance mit Bybit als Ersatz
const okxId = sym => sym.replace(/USDT$/, '-USDT');
const deNum = v => { try { return new Intl.NumberFormat('de-DE', { maximumFractionDigits: v < 10 ? 4 : v < 1000 ? 2 : 1 }).format(v); } catch (_) { return String(v); } };
async function hiLo(sym) {
  const fromK = (k, src) => (Array.isArray(k) && k.length ? { h: Math.max(...k.map(x => +x[2])), l: Math.min(...k.map(x => +x[3])), c: +k[0][4] > 0 ? +k[0][4] : +k[k.length - 1][4], src } : null);
  const alt = { XAUUSDT: 'PAXGUSDT', EURUSDUSDT: 'EURUSDT' }[sym] || sym; // Ersatz-Codes für Börsen ohne TradFi
  const tries = [
    ['bybit', async () => { const r = await fetch(`https://api.bybit.com/v5/market/kline?category=linear&symbol=${sym}&interval=1&limit=2`); if (!r.ok) return null; const j = await r.json(); return fromK(j && j.result && j.result.list, 'bybit'); }],
    ['binance-vision', async () => { const r = await fetch(`https://data-api.binance.vision/api/v3/klines?symbol=${alt}&interval=1m&limit=2`); if (!r.ok) return null; const k = await r.json(); return fromK(k.slice().reverse(), 'binance-vision'); }],
    ['binance', async () => { const r = await fetch(`https://api.binance.com/api/v3/klines?symbol=${alt}&interval=1m&limit=2`); if (!r.ok) return null; const k = await r.json(); return fromK(k.slice().reverse(), 'binance'); }],
    ['okx', async () => { const r = await fetch(`https://www.okx.com/api/v5/market/candles?instId=${okxId(alt)}&bar=1m&limit=2`); if (!r.ok) return null; const j = await r.json(); return fromK(j && j.data, 'okx'); }],
  ];
  const errs = [];
  for (const [n, f] of tries) { try { const v = await f(); if (v && isFinite(v.h) && isFinite(v.l)) return v; errs.push(n); } catch (_) { errs.push(n); } }
  return { err: 'keine Quelle erreichbar (' + errs.join(', ') + ')' };
}
async function watchRun(env) {
  const KV = env.WDESK; if (!KV || !vapidJwk(env)) return { skip: 'setup' };
  const w = await KV.get('watch', 'json'); if (!w || !w.items || !w.items.length) return { skip: 'empty' };
  const sent = (await KV.get('sent', 'json')) || {}; const syms = [...new Set(w.items.filter(x => !sent[x.id]).map(x => x.sym))].slice(0, 12); if (!syms.length) return { skip: 'done' };
  const px = {}; await Promise.all(syms.map(async s => { px[s] = await hiLo(s); }));
  const hits = w.items.filter(x => !sent[x.id] && px[x.sym] && !px[x.sym].err && (x.cond === 'above' ? px[x.sym].h >= x.p : px[x.sym].l <= x.p));
  if (!hits.length) return { hits: 0 };
  for (const x of hits.slice(0, 5)) { sent[x.id] = Date.now(); const c = px[x.sym].c; await pushAll(env, { title: x.title, body: (x.body ? x.body + ' · ' : '') + 'Kurs ' + deNum(c), tag: x.id, nav: x.nav || null }, true); }
  const cut = Date.now() - 14 * 864e5; for (const k in sent) if (sent[k] < cut) delete sent[k];
  await KV.put('sent', JSON.stringify(sent));
  return { hits: hits.length };
}

// ================= ☁️ Bots auf dem Server =================
// Solange keine App offen ist, rechnet der Server die Bots jede Minute weiter.
// Der Rechen-Code unten (zwischen den Markierungen) wird beim Bauen UNVERÄNDERT aus der App (index.html) übernommen.
function makeEngine(ctx) {
  const SY = { ro: false };
  const S = { sym: null, tf: '15m', bars: [], tfms: 9e5, tfData: {}, custom: null, src: 'binance', full: false, bg: true };
  const AC = ctx.acct; AC.pos = AC.pos || []; AC.ord = AC.ord || []; AC.hist = AC.hist || []; AC.bots = AC.bots || [];
  let uid = Math.max(Date.now(), ...AC.pos.map(p => +p.id || 0), ...AC.hist.map(p => +p.id || 0));
  const toast = () => {}, shotLater = () => {}, alCheck = () => {}, divNotify = () => {}, saveAcct = () => {}, renderAcct = () => {}, renderPanel = () => {};
  const notify = (kind, title, body, nav) => ctx.notify(kind, title, body, nav, S.sym);
  const svHold = o => !!(ctx.hold && ctx.hold(o));
  // Live-Analyse: Zeichnungen landen im gespeicherten Stand, nicht auf einem Bildschirm
  const store = (k, v) => { if (v === undefined) return jp(ctx.data[k]); ctx.data[k] = JSON.stringify(v); };
  const save = () => {}, req = () => {}, renderSheet = () => {}, $ = () => null, laIsOpen = () => false;
  // Server führt nur Bots und deren Positionen – deine Hand-Trades bleiben bei der App
  const mine = o => o.key === pkey() && !o.replay && (AC.bots.includes(o) || o.bot != null);
  // ---- ab hier: Code aus der App ----
  const TFMS={'15m':9e5,'1h':36e5,'4h':144e5,'1D':864e5};
  const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));
  function fmt(p){if(p==null||!isFinite(p))return '–';const a=Math.abs(p);const d=a>=1000?1:a>=10?2:a>=2?3:a>=0.1?4:6;return p.toLocaleString('de-DE',{minimumFractionDigits:d,maximumFractionDigits:d})}
  const pct=v=>(v*100).toFixed(1).replace('.',',')+' %';
  const ff=v=>String(v).replace('.',',');
  const retr=(a,b,f)=>b-(b-a)*f;
  function analyze(d){
 const P=d.pts.map(q=>q.p),n=P.length;const R={lines:[],zones:[],checks:[],stats:[],valid:true};
 const L=(p,label,color,dash,x0)=>R.lines.push({p,label,color,dash,x0:x0||0});
 const Z=(a,b,color,x0,label)=>R.zones.push({a,b,color,x0:x0||0,label});
 switch(d.type){
 case 'hline':if(n)L(P[0],'Linie','#58a6ff',0,0);break;
 case 'fib':if(n<2)break;
  [0,.236,.382,.5,.618,.786,1].forEach(f=>L(retr(P[0],P[1],f),ff(f),f===.618||f===.5?'#f0b90b':'#8b949e',0,0));
  Z(retr(P[0],P[1],.618),retr(P[0],P[1],.65),'rgba(240,185,11,.16)',0,'Golden Pocket');
  R.stats.push(['Bewegung',fmt(P[1]-P[0])+' ('+pct((P[1]-P[0])/P[0])+')']);break;
 case 'ext':if(n<3)break;
  [.618,1,1.272,1.6,1.809,2,2.618].forEach(f=>L(P[2]+(P[1]-P[0])*f,ff(f),f<=1.272?'#f5e663':'#7bc96f',0,2));break;
 case 'ew':case 'diag':{
  if(n<2)break;const dir=Math.sign(P[1]-P[0])||1,w1=P[1]-P[0];
  if(n===2){[.382,.5,.618,.786].forEach(f=>L(retr(P[0],P[1],f),'W2 '+ff(f),'#58a6ff',1,1));Z(retr(P[0],P[1],.5),retr(P[0],P[1],.618),'rgba(88,166,255,.13)',1,'Zielzone W2');L(P[0],'W2 ungültig','#ef5350',1,1)}
  if(n===3){[1,1.618,2.618].forEach(f=>L(P[2]+w1*f,'W3 '+ff(f)+'×W1',f===1.618?'#f0b90b':'#26a69a',1,2));Z(P[2]+w1*1.618,P[2]+w1*1,'rgba(38,166,154,.1)',2,'Ziel W3')}
  if(n===4){[.236,.382,.5].forEach(f=>L(retr(P[2],P[3],f),'W4 '+ff(f),'#58a6ff',1,3));Z(retr(P[2],P[3],.236),retr(P[2],P[3],.382),'rgba(88,166,255,.13)',3,'Zielzone W4');if(d.type==='ew')L(P[1],'W4 ungültig (Hoch W1)','#ef5350',1,3)}
  if(n===5){[.618,1,1.618].forEach(f=>L(P[4]+w1*f,'W5 '+ff(f)+'×W1','#26a69a',1,4));L(P[4]+(P[3]-P[0])*.618,'W5 0,618×(0→3)','#f0b90b',1,4)}
  if(n===6){[.382,.5,.618].forEach(f=>L(retr(P[0],P[5],f),'Korrektur '+ff(f),'#d2a8ff',1,5));Z(retr(P[0],P[5],.382),retr(P[0],P[5],.618),'rgba(210,168,255,.1)',5,'ABC-Zielzone')}
  if(n>=3)R.checks.push({t:'Welle 2 läuft nicht über den Start (0) hinaus',ok:dir*(P[2]-P[0])>0});
  if(n>=4)R.checks.push({t:'Welle 3 übersteigt das Ende von Welle 1',ok:dir*(P[3]-P[1])>0});
  if(n>=5){if(d.type==='diag')R.checks.push({t:'Welle 4 überschneidet Welle 1 (typisch Diagonale)',ok:dir*(P[4]-P[1])<=0,soft:true});
   else R.checks.push({t:'Welle 4 dringt nicht in Welle 1 ein',ok:dir*(P[4]-P[1])>0})}
  if(n>=6){const a=Math.abs(w1),b=Math.abs(P[3]-P[2]),c=Math.abs(P[5]-P[4]);
   R.checks.push({t:'Welle 3 ist nicht die kürzeste',ok:!(b<a&&b<c)});
   if(d.type==='diag'){const w2=Math.abs(P[1]-P[2]),w4=Math.abs(P[3]-P[4]);const cv=b<a&&c<b&&w4<w2;R.checks.push({t:cv?'Linien laufen zusammen (kontrahierend)':'Linien laufen nicht zusammen',ok:cv,soft:true});R.pattern=(cv?'Diagonale':'Diagonale?')+' – endend (W5/C) o. führend (W1/A)'}
   const ex=dir*(P[5]-P[3])>0;R.checks.push({t:ex?'Welle 5 übersteigt Welle 3':'Welle 5 verkürzt (Truncation)',ok:ex,soft:true});
   R.stats.push(['Trend',dir>0?'Aufwärts':'Abwärts'],['W2-Retracement',pct((P[1]-P[2])/w1)],['W3 / W1',ff((b/a).toFixed(3))],['W4-Retracement',pct((P[3]-P[4])/(P[3]-P[2]))],['W5 / W1',ff((c/a).toFixed(3))])}
  break;}
 case 'abc':{
  if(n<2)break;const a=P[1]-P[0],dir=Math.sign(a)||1;
  if(n===2){[.382,.5,.618,.786,1].forEach(f=>L(retr(P[0],P[1],f),'B '+ff(f),f===.618?'#f0b90b':'#58a6ff',1,1));Z(retr(P[0],P[1],.382),retr(P[0],P[1],.618),'rgba(88,166,255,.1)',1,'B hier → Zigzag');Z(retr(P[0],P[1],.618),retr(P[0],P[1],1),'rgba(210,168,255,.08)',1,'B hier → Flat')}
  if(n>=3){const rb=(P[1]-P[2])/a;
   const fl=rb<=.618?[.618,1,1.272,1.618]:rb<=1?[.618,1,1.382,1.618]:[1,1.618,2.618];
   fl.forEach(f=>L(P[2]+a*f,'C '+ff(f)+'×A',f===1?'#f0b90b':'#d2a8ff',1,2));
   R.stats.push(['B-Retracement',pct(rb)]);
   if(n===3)R.pattern=rb<=.618?'→ Zigzag erwartet':rb<=1?'→ Flat erwartet':rb<=1.618?'→ Irregular/Running Flat':'B zu weit (>161,8 %)';
   if(n>=4){const rc=Math.abs(P[3]-P[2])/Math.abs(a),cEnd=dir*(P[3]-P[1])/Math.abs(a),cb=rb?rc/Math.abs(rb):0;let pat;
    if(rb<=.618){pat='Zigzag (5-3-5)';R.checks.push({t:'B retraced max. 61,8 % von A',ok:rb>0});R.checks.push({t:'C schließt jenseits von A',ok:cEnd>0,soft:true})}
    else if(rb<=1){pat=cEnd<0?'Verkürztes Flat (3-3-5)':cEnd<=.1?'Normales Flat (3-3-5)':'Erweitertes Flat (3-3-5)';
     R.checks.push({t:'B retraced mind. 61,8 % von A',ok:true});R.checks.push({t:'C max. 161,8 % von A',ok:rc<=1.618});R.checks.push({t:'C erreicht mind. 61,8 % von B',ok:cb>=.618})}
    else if(rb<=1.618){if(cEnd>0){pat='Irregular Flat (3-3-5)';R.checks.push({t:'B überschießt Start max. 61,8 %',ok:true});R.checks.push({t:'C max. 261,8 % von A',ok:rc<=2.618})}
     else{pat='Running Flat (3-3-5)';R.checks.push({t:'B überschießt Start max. 61,8 %',ok:true});R.checks.push({t:'C erreicht mind. 61,8 % von B',ok:cb>=.618})}}
    else{pat='Keine Standard-Korrektur';R.checks.push({t:'B überschießt Start um mehr als 61,8 %',ok:false})}
    R.pattern=pat;R.stats.unshift(['Muster',pat]);R.stats.push(['C / A',ff(rc.toFixed(3))])}}
  break;}
 case 'tri':{
  if(n<2)break;const dir=Math.sign(P[1]-P[0])||1,I=d.pts.map(q=>q.i);
  if(n>=4)R.checks.push({t:'C übersteigt A nicht',ok:dir*(P[3]-P[1])<0});
  if(n>=5)R.checks.push({t:'D übersteigt B nicht',ok:dir*(P[4]-P[2])>0});
  if(n===5){L(P[4]+(P[3]-P[2])*.618,'E ≈ 0,618×C','#ffa657',1,4);L(P[4]+(P[3]-P[2])*.8,'E ≈ 0,8×C','#ffa657',1,4)}
  if(n>=5){const sAC=(P[3]-P[1])/((I[3]-I[1])||1),sBD=(P[4]-P[2])/((I[4]-I[2])||1);
   const ac=i=>P[1]+sAC*(i-I[1]),bd=i=>P[2]+sBD*(i-I[2]);const conv=Math.abs(ac(I[4])-bd(I[4]))<Math.abs(ac(I[1])-bd(I[1]));
   const h=Math.abs(P[1]-P[2])||1,len=(I[4]-I[1])||1;const up=dir>0?sAC:sBD,lo=dir>0?sBD:sAC;const nu=up*len/h,nl=lo*len/h;
   let pat=!conv?'Sich ausdehnendes Dreieck (sehr selten)':Math.abs(nu)<.15&&nl>.15?'Aufsteigendes Dreieck':Math.abs(nl)<.15&&nu<-.15?'Abfallendes Dreieck':'Symmetrisches Dreieck';
   R.pattern=pat+' (3-3-3-3-3)';R.stats.push(['Muster',R.pattern],['Breite (A–B)',fmt(h)])}
  if(n>=6){R.checks.push({t:'E übersteigt C nicht (E muss die Linie nicht erreichen)',ok:dir*(P[5]-P[3])<0,soft:true});
   L(P[5]-dir*Math.abs(P[1]-P[2]),'Ausbruchsziel (Thrust)','#ffa657',0,5)}
  break;}
 case 'sk':{
  if(n<2)break;const dir=Math.sign(P[1]-P[0])||1,a=P[1]-P[0];
  const z1=retr(P[0],P[1],.5),z2=retr(P[0],P[1],.667);
  Z(z1,z2,'rgba(88,166,255,.2)',1,'Golden Zone');
  [[.5,'GKL 0,5'],[.559,'GKL 0,559'],[.618,'GKL 0,618'],[.667,'GKL 0,667']].forEach(([f,l])=>L(retr(P[0],P[1],f),l,'#58a6ff',0,1));
  L(P[0],'Invalidierung (0)','#ef5350',1,0);
  const entry=retr(P[0],P[1],.618),sl=P[0];
  R.stats.push(['Richtung',dir>0?'Long (aufwärts)':'Short (abwärts)'],['Golden Zone',fmt(Math.min(z1,z2))+' – '+fmt(Math.max(z1,z2))]);
  if(n>=3){const r=(P[1]-P[2])/a;const F=[1,1.272,1.6,1.809,2];const T=F.map(f=>P[2]+a*f);
   T.forEach((t,k)=>L(t,ff(F[k]),k<2?'#f5e663':'#7bc96f',0,2));
   Z(T[0],T[1],'rgba(245,230,99,.07)',2,'Ziel C');Z(T[2],T[4],'rgba(123,201,111,.08)',2,'Extension-Zone');
   const inZ=r>=.5&&r<=.667;
   R.checks.push({t:'B in der Golden Zone (Retracement '+pct(r)+')',ok:inZ,soft:!inZ&&r>=.382&&r<=.786});
   R.checks.push({t:'B hält oberhalb/unterhalb von Punkt 0',ok:dir*(P[2]-P[0])>0});
   const bi=Math.round(d.pts[2].i);let act=-1;for(let i=Math.max(0,bi+1);i<S.bars.length;i++){if(dir*(S.bars[i].c-P[1])>0){act=i;break}}
   R.checks.push({t:act>=0?'Aktiviert: Schlusskurs jenseits von A':'Noch nicht aktiviert (kein Schluss jenseits A)',ok:act>=0,soft:act<0});
   const risk=Math.abs(entry-sl);
   R.stats.push(['Einstieg (GKL 0,618)',fmt(entry)],['Stop (Punkt 0)',fmt(sl)]);
   T.forEach((t,k)=>R.stats.push(['CRV bis C '+ff(F[k]),ff((Math.abs(t-entry)/risk).toFixed(2))+' R']))}
  break;}
 }
 R.valid=R.checks.filter(c=>!c.soft).every(c=>c.ok);
 return R;
}
  function zigzag(B,dev){
 if(B.length<3)return[];const piv=[];let trend=0,hi={i:0,p:B[0].h},lo={i:0,p:B[0].l},cand=null;
 for(let i=1;i<B.length;i++){const b=B[i];
  if(trend===0){if(b.h>hi.p)hi={i,p:b.h};if(b.l<lo.p)lo={i,p:b.l};
   if((hi.p-lo.p)/lo.p>dev){if(hi.i>lo.i){piv.push({...lo,t:-1,c:i});trend=1;cand={...hi}}else{piv.push({...hi,t:1,c:i});trend=-1;cand={...lo}}}continue}
  if(trend===1){if(b.h>=cand.p)cand={i,p:b.h};else if((cand.p-b.l)/cand.p>dev){piv.push({...cand,t:1,c:i});trend=-1;cand={i,p:b.l}}}
  else{if(b.l<=cand.p)cand={i,p:b.l};else if((b.h-cand.p)/cand.p>dev){piv.push({...cand,t:-1,c:i});trend=1;cand={i,p:b.h}}}
 }
 if(cand)piv.push({...cand,t:trend,prov:true});return piv;
}
  const DEVS=[.005,.01,.02,.03,.05,.08,.12,.2];
  function nearestDev(v){return DEVS.reduce((a,b)=>Math.abs(b-v)<Math.abs(a-v)?b:a)}
  function ewaBase(B){const n=Math.min(150,B.length);let s=0;for(let i=B.length-n;i<B.length;i++)s+=(B[i].h-B[i].l)/B[i].c;return s/n}
  function ewaLevels(B){if(!S.devAuto&&S.dev)return[S.dev];const b=ewaBase(B);return[2.5,4,6,9,13].map(m=>clamp(b*m,.003,.35))}
  const HTFF={'1m':5,'3m':5,'5m':3,'15m':4,'30m':2,'1h':4,'2h':2,'4h':6,'6h':4,'12h':2,'1D':7,'1d':7,'3D':2,'1W':4,'1w':4};
  function ewaHtf(B){const f=HTFF[S.tf]||4;return htfTrend(B,f)}
  function ewaVol(B,a,b){let s=0,n=0;for(let i=Math.min(a,b)+1;i<=Math.max(a,b);i++){s+=B[i].v||0;n++}return n?s/n:0}
  function ewaGrade(B,P,I,RS,htf){const n=P.length,d=Math.sign(P[1]-P[0])||1,q=P.map(v=>d*v),g=[];const G=(t,ok,w)=>g.push({t,ok:!!ok,w});
 const w1=q[1]-q[0];
 if(n>=3){const r2=(q[1]-q[2])/w1;G(`Welle 2 korrigiert ${pct(r2)} (ideal 50–61,8 %)`,r2>=.45&&r2<=.7,15)}
 if(n>=4){const r3=(q[3]-q[2])/w1;G(`Welle 3 = ${ff(r3.toFixed(2))}× Welle 1 (ideal ≈ 1,618)`,r3>=1.38&&r3<=2.8,20);
  const v3=ewaVol(B,I[2],I[3]),v1=ewaVol(B,I[0],I[1]);if(v1>0&&v3>0)G('Volumen in Welle 3 höher als in Welle 1',v3>v1,12)}
 if(n>=5){const r4=(q[3]-q[4])/(q[3]-q[2]),r2=(q[1]-q[2])/w1;G(`Welle 4 korrigiert ${pct(r4)} (ideal 23,6–50 %)`,r4>=.2&&r4<=.52,15);
  G('Wechsel: Welle 2 und 4 unterschiedlich tief',Math.abs(r2-r4)>=.15||Math.abs((I[2]-I[1])-(I[4]-I[3]))>=Math.max(I[2]-I[1],I[4]-I[3])*.5,8)}
 if(n>=6){const r5=(q[5]-q[4])/w1,alt=(q[5]-q[4])/(q[3]-q[0]);G(`Welle 5 = ${ff(r5.toFixed(2))}× Welle 1 (ideal 0,618–1,618)`,(r5>=.55&&r5<=1.7)||(alt>=.55&&alt<=.7),10);
  if(RS&&isFinite(RS[I[3]])&&isFinite(RS[I[5]]))G('RSI-Divergenz am Ende von Welle 5',d>0?RS[I[5]]<RS[I[3]]:RS[I[5]]>RS[I[3]],10);
  const v5=ewaVol(B,I[4],I[5]),v3=ewaVol(B,I[2],I[3]);if(v5>0&&v3>0)G('Volumen in Welle 5 schwächer als in Welle 3',v5<v3,8)}
 // Richtung der nächsten erwarteten Bewegung vs. höhere Zeiteinheit
 const nextDir=n===6?-d:(n%2===1?d:-d);if(htf)G(`Höhere Zeiteinheit zeigt ${htf>0?'aufwärts':'abwärts'}${htf===nextDir?' – passt':' – Gegenwind'}`,htf===nextDir,10);
 const tw=g.reduce((s,x)=>s+x.w,0),sc=tw?Math.round(g.reduce((s,x)=>s+(x.ok?x.w:0),0)/tw*100):0;return{score:sc,g}}
  function ewaRules(P,full){const d=Math.sign(P[1]-P[0])||1,q=P.map(v=>d*v),n=q.length;
 if(n>=3&&!(q[2]>q[0]&&q[2]<q[1]))return false;if(n>=4&&!(q[3]>q[1]))return false;if(n>=5&&!(q[4]<q[3]&&q[4]>q[1]))return false;
 if(n>=6){if(!(q[5]>q[4]))return false;const a=q[1]-q[0],b=q[3]-q[2],c=q[5]-q[4];if(b<a&&b<c)return false}return true}
  const EWA_ST={3:'Welle 3 erwartet',4:'Welle 3 läuft · danach Welle 4',5:'in Welle 4/5 · Welle 5 erwartet',6:'Impuls 1–5 fertig · Korrektur erwartet'};
  function ewaFind(B){const lv=ewaLevels(B),RS=rsiA(B.map(b=>b.c),14),htf=ewaHtf(B),C=[];
 lv.forEach((dev,li)=>{const z=zigzag(B,dev);if(z.length<3)return;const L=z.length-1;
  // Impuls-Zählungen (vollständig oder laufend), letzter Punkt = jüngster Pivot
  for(const n of [6,5,4,3]){for(const end of n===6?[L,L-1]:[L]){const st=end-n+1;if(st<0)continue;const pts=z.slice(st,end+1);const P=pts.map(x=>x.p),I=pts.map(x=>x.i);
    if(!ewaRules(P))continue;{const px=B[B.length-1].c,d0=Math.sign(P[1]-P[0])||1;if(n<=3?d0*(px-P[0])<0:n<=5?d0*(px-P[1])<0:false)continue}const G=ewaGrade(B,P,I,RS,htf);const age=B.length-1-I[I.length-1];
    // Folge-ABC nach fertigem Impuls
    if(n===6&&end<L){const nx=z.slice(end,L+1);if(nx.length>=3){const ab=[pts[5],...nx.slice(1,4)].map(x=>({i:x.i,p:x.p}));const A=analyze({type:'abc',pts:ab});
      if(A.checks.every(c=>c.ok||c.soft))C.push({type:'abc',pts:ab,imp:pts.map(x=>({i:x.i,p:x.p})),score:Math.round(G.score*.9),g:G.g,dev,li,status:ab.length>=4?'ABC-Korrektur '+(A.pattern||''):'Korrektur läuft · Welle C erwartet',rank:G.score+30-li*2})}}
    C.push({type:'ew',pts:pts.map(x=>({i:x.i,p:x.p})),score:G.score,g:G.g,dev,li,status:EWA_ST[n],rank:G.score*(.55+.1*Math.min(4,G.g.length))+(n-3)*4-(age>40?10:0)-(end<L?8:0)})}}
  // Dreieck A–E
  if(z.length>=6){const pts=z.slice(L-5).map(x=>({i:x.i,p:x.p}));const A=analyze({type:'tri',pts});if(A.checks.length&&A.checks.every(c=>c.ok)&&!/ausdehn/i.test(A.pattern||''))C.push({type:'tri',pts,score:70,g:[{t:A.pattern||'Dreieck',ok:true,w:1}],dev,li,status:(A.pattern||'Dreieck')+' · Ausbruch erwartet',rank:78})}
 });
 C.sort((a,b)=>b.rank-a.rank);const good=C.filter(c=>c.score>=35);const best=good[0]||C[0]||null;if(best&&best.score<35)best.status+=' (schwach)';
 const sig=c=>c.type+':'+c.pts.map(p=>p.i).join(',');const alt=best?(good.length?good:C).find(c=>sig(c)!==sig(best)&&(c.status!==best.status||Math.abs(c.pts[0].i-best.pts[0].i)>3)):null;
 return{best,alt,htf,levels:lv}}
  function skFind(B){const lv=ewaLevels(B),htf=ewaHtf(B),C=[],atr=(()=>{let s=0;for(let i=B.length-14;i<B.length;i++)s+=B[i].h-B[i].l;return s/14})();
 lv.forEach((dev,li)=>{const z=zigzag(B,dev);for(let k=z.length-1;k>=Math.max(2,z.length-2);k--){const o=z[k-2],a=z[k-1],b=z[k],imp=a.p-o.p,d=Math.sign(imp);if(!d)continue;const r=(a.p-b.p)/imp;if(r<.382||r>.786)continue;
  const g=[];const G=(t,ok,w)=>g.push({t,ok:!!ok,w});G(`Rücksetzer ${pct(r)} (ideal Golden Zone 50–66,7 %)`,r>=.5&&r<=.667,30);
  G('Impuls kräftig (≥ 3× ATR)',Math.abs(imp)>=atr*3,20);const vi=ewaVol(B,o.i,a.i),vb=ewaVol(B,a.i,b.i);if(vi>0&&vb>0)G('Rücksetzer mit weniger Volumen',vb<vi,20);
  if(htf)G(`Höhere Zeiteinheit ${htf===d?'passt':'dagegen'}`,htf===d,20);const px=B[B.length-1].c;G('Kurs noch über/unter Punkt 0',d*(px-o.p)>0,10);
  const tw=g.reduce((s,x)=>s+x.w,0),sc=Math.round(g.reduce((s,x)=>s+(x.ok?x.w:0),0)/tw*100);C.push({pts:[o,a,b].map(x=>({i:x.i,p:x.p})),score:sc,g,dev,rank:sc-(z.length-1-k)*15-li})}});
 C.sort((a,b)=>b.rank-a.rank);return C[0]||null}
  function rsiA(cl,n){const o=new Array(cl.length).fill(NaN);let g=0,l=0;for(let i=1;i<cl.length;i++){const d=cl[i]-cl[i-1],u=Math.max(d,0),w=Math.max(-d,0);if(i<=n){g+=u;l+=w;if(i===n){g/=n;l/=n;o[i]=l===0?100:100-100/(1+g/l)}}else{g=(g*(n-1)+u)/n;l=(l*(n-1)+w)/n;o[i]=l===0?100:100-100/(1+g/l)}}return o}
  const fR=v=>(v>=0?'+':'')+ff(v.toFixed(2))+' R';
  const fin=Number.isFinite;
  const pkey=()=>S.custom?'csv:'+S.custom:S.src+':'+S.sym;
  const lastP=()=>S.bars[S.bars.length-1].c;
  const nowT=()=>S.full?S.bars[S.bars.length-1].t:Date.now();
  const isRp=()=>!!S.full;
  const pmode=p=>p.mode||'fut';
  const TYPN={market:'Market',limit:'Limit',stop:'Stop-Order',trail:'Trailing-Einstieg'};
  function money(v){return (v<0?'-':'')+'$'+Math.abs(v).toLocaleString('de-DE',{minimumFractionDigits:2,maximumFractionDigits:2})}
  function used(){let u=0;AC.pos.forEach(p=>{u+=pmode(p)==='spot'?p.entry*p.qty:p.entry*p.qty/(p.lev||1)});AC.bots.forEach(b=>{if(b.state!=='stopped'&&b.state!=='done')u+=b.inv});return u}
  const avail=()=>AC.bal-used();
  const liqPrice=(dir,entry,lev)=>entry*(1-dir*(1/lev-.005));
  function sizeOf(o,price){
 if(o.mode==='spot'){const notional=Math.max(0,Math.min(fin(o.stake)&&o.stake>0?o.stake:AC.bal*o.amtPct/100,avail()));const qty=notional/price;return{qty,margin:notional,notional,risk$:fin(o.sl)?qty*Math.abs(price-o.sl):notional}}
 const dist=Math.abs(price-o.sl);if(fin(o.stake)&&o.stake>0){const notional=o.stake*o.lev,qty=notional/price;return{qty,margin:o.stake,notional,risk$:qty*dist}}
 const qty=AC.bal*o.riskPct/100/dist,notional=qty*price;return{qty,margin:notional/o.lev,notional,risk$:qty*dist}}
  function openPos(o,price){
 if(o.mode!=='spot'&&!fin(o.sl))return null;
 if(fin(o.sl)&&o.dir*(price-o.sl)<=0)return null;
 const z=sizeOf(o,price);if(!(z.qty>0))return null;
 if(z.margin>avail()+1e-6){toast(o.mode==='spot'?'Nicht genug Guthaben':'Nicht genug Margin – Hebel erhöhen oder Risiko senken');return null}
 const fee=price*z.qty*AC.fee;AC.bal-=fee;const lev=o.mode==='spot'?1:o.lev;
 const p={id:++uid,key:o.key,label:o.label,mode:o.mode,lev,liq:o.mode==='spot'?null:liqPrice(o.dir,price,lev),dir:o.dir,entry:price,qty0:z.qty,qty:z.qty,
  sl:fin(o.sl)?o.sl:null,sl0:fin(o.sl)?o.sl:null,tps:o.tps.map(t=>({...t,hit:false})),be:o.be,trail:o.trail||0,ttp:o.ttp||0,csl:!!o.csl,ext:price,t0:nowT(),real:-fee,risk$:z.risk$,replay:o.replay,exits:[],tf:o.tf||curTf(),strat:o.strat||null};
 AC.pos.push(p);shotLater(p,'a');return p}
  function closePart(p,px,q,why){if(SY.ro)return;q=Math.min(q,p.qty);if(q<=0)return;const fee=px*q*AC.fee,pnl=(px-p.entry)*p.dir*q-fee;AC.bal+=pnl;p.real+=pnl;p.qty-=q;p.exits.push({px,q,why});
 if(p.qty<=p.qty0*1e-6)finishPos(p,why)}
  function finishPos(p,why){AC.pos=AC.pos.filter(x=>x!==p);const qx=p.exits.reduce((s,e)=>s+e.q,0)||1,avg=p.exits.reduce((s,e)=>s+e.px*e.q,0)/qx,r=p.real/(p.risk$||1);
 AC.hist.push({key:p.key,label:p.label,mode:pmode(p),lev:p.lev||1,dir:p.dir,entry:p.entry,exit:avg,pnl:p.real,R:r,t0:p.t0,t1:nowT(),why,replay:!!p.replay,bot:p.bot||null,wave:p.wave||null,id:p.id,tf:p.btf||p.tf||null,strat:p.bot?'Elliott-Bot':(p.strat||null),note:''});shotLater(p,'b');
 toast(`${p.dir>0?'Long':'Short'} geschlossen (${why}): ${money(p.real)} · ${fR(r)}`);if(!p.replay)notify(p.bot?'bot':'trade',`${p.real>=0?'✅':'❌'} ${p.label} ${p.dir>0?'Long':'Short'} geschlossen`,`${why} · ${money(p.real)} · ${fR(r)}`,{tab:p.bot?'bots':pmode(p),pid:p.id})}
  function whySL(p){if(p.sl===p.sl0)return'Stop';if(p.sl===p.entry)return'Break-even';return p.dir*(p.sl-p.entry)>0?'Trailing-Stop':'Stop'}
  function onPrice(h,l,c,closed){if(SY.ro)return;let ch=false;const fresh=new Set();if(fin(c))AC.pos.forEach(p=>{if(mine(p))p.lpx=c});try{alCheck(h,l,c);if(closed&&!S.bg)setTimeout(divNotify,50)}catch(_){}
 AC.ord.filter(mine).forEach(o=>{const d=o.dir;let fp=null;
  if(o.type==='limit'){if(d>0?l<=o.price:h>=o.price)fp=o.price}
  else if(o.type==='stop'){if(d>0?h>=o.price:l<=o.price)fp=o.price}
  else if(o.type==='trail'){
   if(!o.act){if(!fin(o.price)||(d>0?l<=o.price:h>=o.price)){o.act=true;o.ext=d>0?l:h;ch=true}}
   else{o.ext=d>0?Math.min(o.ext,l):Math.max(o.ext,h);const trg=o.ext*(1+d*o.tpct/100);if(d>0?h>=trg:l<=trg)fp=trg}}
  if(fp!=null){AC.ord=AC.ord.filter(x=>x!==o);ch=true;const p=openPos(o,fp);
   if(p){fresh.add(p.id);toast(`${TYPN[o.type]} ${p.dir>0?'Long':'Short'} ausgeführt @ ${fmt(fp)}`);notify('trade',`📥 ${p.label}: ${TYPN[o.type]} ausgeführt`,`${p.dir>0?'Long':'Short'} @ ${fmt(fp)}`,{tab:pmode(p)});if(p.sl!=null&&!p.csl&&(p.dir>0?l<=p.sl:h>=p.sl))closePart(p,p.sl,p.qty,'Stop')}
   else toast(`${TYPN[o.type]} verworfen – Stop/Guthaben passt beim Auslösen nicht`)}});
 AC.pos.filter(p=>mine(p)&&!svHold(p)).forEach(p=>{if(fresh.has(p.id))return;const d=p.dir;
  if(p.sl!=null){const hit=p.csl?(closed&&(d>0?c<=p.sl:c>=p.sl)):(d>0?l<=p.sl:h>=p.sl);if(hit){closePart(p,p.csl?c:p.sl,p.qty,whySL(p)+(p.csl?' (Kerzenschluss)':''));ch=true;return}}
  if(p.liq!=null&&(d>0?l<=p.liq:h>=p.liq)){closePart(p,p.liq,p.qty,'Liquidation');ch=true;return}
  if(p.ttOn){p.ttExt=d>0?Math.max(p.ttExt,h):Math.min(p.ttExt,l);const trg=p.ttExt*(1-d*p.ttp/100);if(d>0?l<=trg:h>=trg){closePart(p,trg,p.qty,'Trailing-TP');ch=true;return}}
  p.tps.forEach((t,k)=>{if(t.hit||!AC.pos.includes(p))return;if(d>0?h>=t.p:l<=t.p){t.hit=true;ch=true;const last=p.tps.every(x=>x.hit);
    if(last&&p.ttp>0){p.ttOn=true;p.ttExt=t.p;toast('Letztes Ziel erreicht – Trailing-TP läuft weiter')}
    else{closePart(p,t.p,last?p.qty:p.qty0*t.pct/100,'TP '+(k+1));if(!last)notify(p.bot?'bot':'trade',`🎯 ${p.label}: Ziel ${k+1} erreicht`,`@ ${fmt(t.p)} · ${t.pct} % geschlossen`,{tab:p.bot?'bots':pmode(p)})}
    if(k===0&&p.be&&AC.pos.includes(p))p.sl=p.sl==null?p.entry:(d>0?Math.max(p.sl,p.entry):Math.min(p.sl,p.entry))}});
  if(AC.pos.includes(p)&&p.trail>0){p.ext=d>0?Math.max(p.ext,h):Math.min(p.ext,l);const ns=p.ext*(1-d*p.trail/100);if(p.sl==null||d*(ns-p.sl)>0){p.sl=ns;ch=true}}});
 if(botTick(h,l,c))ch=true;
 if(closed&&eBotTick(true))ch=true;
 if(ch){saveAcct();renderAcct();renderPanel()}}
  function botSell(bt,px){const pnl=(px-bt.buyP)*bt.qty-px*bt.qty*AC.fee;AC.bal+=pnl;bt.pnl+=pnl;bt.qty=0}
  function botTick(h,l,c){if(SY.ro)return;let ch=false;
 AC.bots.filter(b=>mine(b)&&!svHold(b)).forEach(bt=>{if(bt.state==='stopped'||bt.state==='done'||bt.type==='elliott')return;
  if(bt.type==='channel'){
   if(bt.state==='wait'){if(l<=bt.low){bt.qty=bt.inv/bt.low;bt.buyP=bt.low;const f=bt.low*bt.qty*AC.fee;AC.bal-=f;bt.pnl-=f;bt.state='hold';bt.just=true;ch=true;notify('bot','📥 '+bt.label+' Channel-Bot',`Gekauft @ ${fmt(bt.low)}`)}}
   else if(bt.state==='hold'){if(bt.just)bt.just=false;
    else if(bt.stop&&l<=bt.stop){botSell(bt,bt.stop);bt.state='stopped';ch=true;toast('Channel-Bot: Stop ausgelöst – Bot beendet');notify('bot','🛑 '+bt.label+' Channel-Bot','Stop ausgelöst – Bot beendet')}
    else if(h>=bt.high){botSell(bt,bt.high);bt.cyc++;bt.state=bt.auto?'wait':'done';ch=true;toast(`Channel-Bot: Zyklus ${bt.cyc} abgeschlossen`);notify('bot','✅ '+bt.label+' Channel-Bot',`Zyklus ${bt.cyc} verkauft @ ${fmt(bt.high)} · gesamt ${money(bt.pnl)}`)}}}
  else{const Lv=bt.levels;
   bt.slots.forEach((s,i)=>{if(s.held&&!s.just&&h>=Lv[i+1]){const px=Lv[i+1],pnl=(px-s.buyP)*s.qty-px*s.qty*AC.fee;AC.bal+=pnl;bt.pnl+=pnl;s.held=false;bt.cyc++;ch=true}});
   bt.slots.forEach(s=>s.just=false);
   if(bt.stop&&l<=bt.stop){bt.slots.forEach(s=>{if(s.held){const pnl=(bt.stop-s.buyP)*s.qty-bt.stop*s.qty*AC.fee;AC.bal+=pnl;bt.pnl+=pnl;s.held=false}});bt.state='stopped';ch=true;toast('Grid-Bot: Stop ausgelöst – Bot beendet');notify('bot','🛑 '+bt.label+' Grid-Bot','Stop ausgelöst – Bot beendet');return}
   bt.slots.forEach((s,i)=>{const L=Lv[i];if(!s.armed&&h>=Lv[i+1])s.armed=true;
    if(!s.held&&s.armed&&l<=L){s.held=true;s.just=true;s.qty=bt.inv/bt.slots.length/L;s.buyP=L;const f=L*s.qty*AC.fee;AC.bal-=f;bt.pnl-=f;ch=true}})}});
 return ch}
  const curTf=()=>S.custom?'csv':S.tf;
  const tfName=tf=>tf==='csv'?'CSV':tf;
  const WNAME={'1':'Welle 1','3':'Welle 3','5':'Welle 5',A:'Welle A',C:'Welle C'};
  function impOK(q){const w1=q[1]-q[0],w3=q[3]-q[2],w5=q[5]-q[4];return q[1]>q[0]&&q[2]<q[1]&&q[2]>q[0]&&q[3]>q[1]&&q[4]<q[3]&&q[4]>q[1]&&q[5]>q[4]&&q[5]>q[3]&&!(w3<w1&&w3<w5)}
  function eMatch(z,cfg){const n=z.length;if(n<3)return null;const last=z[n-1],res=[];
 for(const s of [1,-1]){const P=len=>{const a=[];for(let k=len;k>=1;k--)a.push(s*z[n-k].p);return a};const hi=s*last.t===1;
  if(hi){
   if(n>=8){const q=P(8);if(impOK(q.slice(0,6))&&q[6]<q[5]&&q[7]>q[6]&&q[7]<q[5]){const rb=(q[7]-q[6])/(q[5]-q[6]);if(rb>=.382&&rb<=.886)res.push({len:8,wave:'C',side:-s,stop:s*q[7],tp:s*(q[7]-(q[5]-q[6])),names:['0','1','2','3','4','5','A','B']})}}
   if(n>=6){const q=P(6);if(impOK(q))res.push({len:6,wave:'A',side:-s,stop:s*q[5],tp:s*(q[5]-.382*(q[5]-q[0])),names:['0','1','2','3','4','5']})}}
  else{
   if(n>=5){const q=P(5),w3=q[3]-q[2];if(q[1]>q[0]&&q[2]>q[0]&&q[2]<q[1]&&q[3]>q[1]&&q[4]<q[3]&&q[4]>q[1]&&w3>=q[1]-q[0]&&(q[3]-q[4])/w3<=.618)res.push({len:5,wave:'5',side:s,stop:s*q[4],tp:s*(q[4]+(q[1]-q[0])),names:['0','1','2','3','4']})}
   if(n>=4){const q=P(4);if(q[1]<q[0]&&q[2]>q[1]&&q[2]<q[0]&&q[3]<q[1]){const rb=(q[2]-q[1])/(q[0]-q[1]),rc=(q[2]-q[3])/(q[0]-q[1]);if(rb>=.382&&rb<=.886&&rc>=.618&&rc<=1.618)res.push({len:4,wave:'1',side:s,stop:s*q[3],tp:s*(q[3]+.618*(q[0]-q[3])),names:['5','A','B','C']})}}
   {const q=P(3);if(q[1]>q[0]&&q[2]<q[1]&&q[2]>q[0]){const r=(q[1]-q[2])/(q[1]-q[0]);if(r>=.382&&r<=.786)res.push({len:3,wave:'3',side:s,stop:s*q[2],tp:s*(q[2]+1.618*(q[1]-q[0])),names:['0','1','2']})}}}}
 const ok=res.filter(m=>cfg.waves[m.wave]&&(cfg.dir==='both'||(cfg.dir==='long')===(m.side>0)));if(!ok.length)return null;
 ok.sort((a,b)=>b.len-a.len);return ok[0]}
  function htfTrend(B,f){const a=[];for(let i=B.length-1;i>=0;i-=f)a.unshift(B[i].c);if(a.length<5)return 0;const k=2/(Math.min(20,a.length)+1);let e=a[0];a.forEach(v=>e=v*k+e*(1-k));return a[a.length-1]>=e?1:-1}
  function aggBars(B,src,dst){if(!B.length||dst<src||dst%src)return null;if(dst===src)return B;const out=[];let cur=null;
 for(const b of B){const k=Math.floor(b.t/dst)*dst;if(!cur||cur.t!==k){cur={t:k,o:b.o,h:b.h,l:b.l,c:b.c,v:b.v||0};out.push(cur)}else{cur.h=Math.max(cur.h,b.h);cur.l=Math.min(cur.l,b.l);cur.c=b.c;cur.v+=b.v||0}}
 if((B[B.length-1].t+src)%dst!==0)out.pop();return out}
  function tfBars(tf){if(tf===curTf())return S.bars;
 if(S.src==='binance'&&!S.full&&tf!=='csv'){const c=S.tfData[tf];return c&&c.sym===S.sym?c.bars.slice(0,-1):null}
 return tf==='csv'?null:aggBars(S.bars,S.tfms,TFMS[tf])}
  const devOf=B=>{const n=Math.min(150,B.length);let s=0;for(let i=B.length-n;i<B.length;i++)s+=(B[i].h-B[i].l)/B[i].c;return nearestDev(s/n*4)};
  function eMig(bt){if(!bt.tfs){bt.tfs=[bt.tf||curTf()];bt.st={}}bt.st=bt.st||{}}
  function eBotTick(onClose){let ch=false;
 AC.bots.filter(bt=>bt.type==='elliott'&&bt.state==='run'&&mine(bt)&&!svHold(bt)).forEach(bt=>{eMig(bt);
  bt.tfs.forEach(tf=>{const live=S.src==='binance'&&!S.full&&tf!==curTf();if(!onClose&&!live)return;
   const B=tfBars(tf);if(!B||B.length<30)return;const st=bt.st[tf]||(bt.st[tf]={});const dev=bt.dev||st.dev||(st.dev=devOf(B));
   const z=zigzag(B,dev).filter(p=>!p.prov);if(z.length<3)return;const lp=z[z.length-1],lt=B[lp.i].t;if(st.lastT===lt)return;const first=st.lastT==null;st.lastT=lt;ch=true;
   if(first&&bt.skipFirst)return;
   const m=eMatch(z,bt);if(!m)return;st.match={pts:z.slice(-m.len).map(q=>({t:B[q.i].t,p:q.p})),names:m.names,wave:m.wave,side:m.side};
   const tg=`${tfName(tf)}: ${WNAME[m.wave]} ${m.side>0?'Long':'Short'}`;
   if(bt.htf&&htfTrend(B,4)!==m.side){st.last=tg+' – gefiltert (Trend höhere ZE)';return}
   AC.pos.filter(p=>p.bot===bt.id&&p.btf===tf&&p.dir!==m.side).forEach(p=>closePart(p,lastP(),p.qty,'Signalwechsel'));
   if(AC.pos.some(p=>p.bot===bt.id&&p.btf===tf)){st.last=tg+' – Position läuft bereits';return}
   const px=lastP(),sl=m.stop*(1-m.side*.0015);if(m.side*(px-sl)<=0){st.last=tg+' – verworfen (Kurs schon hinter Stop)';return}
   const dist=Math.abs(px-sl)/px,lev=Math.max(1,Math.min(bt.lev,Math.floor(.9/(dist+.006))));
   const tps=bt.tp&&m.side*(m.tp-px)>0?[{p:m.tp,pct:50},{p:px+m.side*Math.abs(m.tp-px)*6,pct:50}]:[];
   const p=openPos({key:pkey(),label:(S.custom||S.sym)+' 🤖'+tfName(tf),mode:'fut',dir:m.side,sl,tps,be:true,trail:dev*100,ttp:0,csl:false,riskPct:bt.riskUsd>0&&AC.bal>0?bt.riskUsd/AC.bal*100:bt.risk,lev,replay:isRp()},px);
   if(p){p.bot=bt.id;p.btf=tf;p.wave=m.wave;bt.trades++;st.last=`${tg} eröffnet @ ${fmt(px)}`;toast('🤖 '+st.last);notify('bot','🤖 '+(S.custom||S.sym)+' Elliott-Bot',st.last)}else st.last=tg+' – abgelehnt (Margin)'})});
 return ch}
  const BGF=['sym','tf','bars','tfms','tfData','custom','src','full'];
  function laCtx(e,B,fn){const sv={};const F=[...BGF,'devAuto','dev','bg'];F.forEach(k=>sv[k]=S[k]);
 Object.assign(S,{sym:e.sym,tf:e.tf,bars:B,tfms:TFMS[e.tf]||S.tfms,tfData:{},custom:null,src:e.src,full:false,bg:true,devAuto:e.devAuto,dev:e.dev});try{return fn()}finally{F.forEach(k=>S[k]=sv[k])}}
  function autoCompute(B,o){const out=[],found=[];const R=o.ew?ewaFind(B):null;
 const put=(c,alt)=>{const d={type:c.type,auto:true,pts:c.pts.map(q=>({i:q.i,p:q.p})),q:c.score,g:c.g,st:c.status,lvl:c.dev};if(alt)d.alt=true;out.push(d);
  if(c.imp&&!alt)out.push({type:'ew',auto:true,pts:c.imp.map(q=>({i:q.i,p:q.p})),q:c.score,g:c.g,st:'Impuls 1–5 (fertig)',lvl:c.dev,sub:true})};
 if(R&&R.best){put(R.best,false);found.push(`${R.best.status} (${R.best.score} %)`);if(R.alt){put(R.alt,true);found.push(`Alternative: ${R.alt.status} (${R.alt.score} %)`)}}
 let k=null;if(o.sk){k=skFind(B);if(k){out.push({type:'sk',auto:true,pts:k.pts.map(q=>({i:q.i,p:q.p})),q:k.score,g:k.g,st:'SK-Setup',lvl:k.dev});found.push(`SK ${k.score} %`)}}
 return{draws:out,found,R,k}}
  function laConf(o,c,B){if(o.inv==null)return o;const k=c.pts.map(q=>q.p).lastIndexOf(o.inv);if(k<0)return o;const i=c.pts[k].i,dv=c.dev>0?c.dev:.01;let ok=false;
 for(let j=i+1;j<B.length;j++){if(o.invUp?B[j].l<=o.inv*(1-dv):B[j].h>=o.inv*(1+dv)){ok=true;break}}
 if(!ok){o.inv=null;o.invWait=true}return o}
  function laInfo(c,B,kind){return laConf(laInfo0(c,B,kind),c,B)}
  function laInfo0(c,B,kind){const P=c.pts.map(q=>q.p),T=c.pts.map(q=>B[q.i]?B[q.i].t:null),n=P.length,o={type:kind==='sk'?'sk':c.type,st:kind==='sk'?'SK-Setup':c.status,q:c.score,t0:T[0],n,inv:null,invUp:false,tgt:null,tgtUp:false,tl:''};
 if(kind==='sk'){const d=Math.sign(P[1]-P[0]);o.inv=P[0];o.invUp=d<0;o.tgt=P[2]+(P[1]-P[0]);o.tgtUp=d>0;o.tl='SK-Ziel';return o}
 const d=Math.sign(P[1]-P[0])||1,w1=Math.abs(P[1]-P[0]);
 if(c.type==='ew'){if(n<=3){o.inv=P[0];o.invUp=d<0;o.tgt=P[2]+d*w1*1.618;o.tgtUp=d>0;o.tl='Ziel Welle 3'}
  else if(n<=5){o.inv=P[1];o.invUp=d<0;if(n===5){o.tgt=P[4]+d*w1;o.tgtUp=d>0;o.tl='Ziel Welle 5'}}
  else{o.inv=P[5];o.invUp=d>0;o.tgt=retr(P[0],P[5],.382);o.tgtUp=d<0;o.tl='Korrekturziel 38,2 %'}}
 else if(c.type==='abc'){const dA=Math.sign(P[1]-P[0]);if(n>=4){o.inv=P[3];o.invUp=dA>0}else if(n===3){o.tgt=P[2]+dA*Math.abs(P[1]-P[0]);o.tgtUp=dA>0;o.tl='Ziel Welle C'}}
 return o}
  function laNew(R,k,B){return{cur:R&&R.best?laInfo(R.best,B):{none:true},skc:k?laInfo(k,B,'sk'):null}}
  function laApply(e,B,draws){draws.forEach(d=>d.pts.forEach(q=>{q.t=B[q.i]?B[q.i].t:null}));
 const merge=arr=>{const hid=new Set(arr.filter(d=>d.auto&&d.hidden).map(d=>d.type+(d.alt?'*':'')));draws.forEach(d=>{if(hid.has(d.type+(d.alt?'*':'')))d.hidden=true});return arr.filter(d=>!d.auto).concat(draws)};
 if(laIsOpen(e)){S.drawings=merge(S.drawings);save();req();if($('#sheet')&&$('#sheet').classList.contains('open'))renderSheet()}
 else{const k='wdesk_'+(e.src==='binance'?'live_':'')+e.sym+'_'+e.tf;store(k,merge(store(k)||[]))}}
  function laProc(e,B,msgs){const L=B.length-1;if(L<60)return;const nm=`${e.sym.replace(/\/USDT?$/,'')} ${e.tf}`,add=(title,body)=>{msgs.push({e,title:`🔴 ${nm}: ${title}`,body,short:`${nm} – ${title}`});e.hist.unshift({t:Date.now(),m:title+(body?' · '+body:'')});if(e.hist.length>30)e.hist.length=30};
 let hi=-Infinity,lo=Infinity;for(let i=L;i>=0&&(i===L||B[i].t>=(e.chkT||B[L].t));i--){const b=B[i];if(b.t===e.chkT&&e.bH!=null){if(b.h>e.bH)hi=Math.max(hi,b.h);if(b.l<e.bL)lo=Math.min(lo,b.l)}else{hi=Math.max(hi,b.h);lo=Math.min(lo,b.l)}}e.chkT=B[L].t;e.bH=B[L].h;e.bL=B[L].l;
 const closedT=B[L-1].t;let rerun=e.lastT!==closedT;
 const chk=(c,lab)=>{if(!c||c.none)return;if(!c.dead&&c.inv!=null&&(c.invUp?hi>c.inv:lo<c.inv)){c.dead=true;rerun=true;add(`${lab} ungültig`,`${c.st} – Marke ${fmt(c.inv)} gebrochen`)}
  if(!c.hit&&!c.dead&&c.tgt!=null&&(c.tgtUp?hi>=c.tgt:lo<=c.tgt)){c.hit=true;add(`${c.tl} erreicht`,`${fmt(c.tgt)} · ${c.st}`)}};
 chk(e.cur,'Zählung');chk(e.skc,'SK-Setup');e.ts=Date.now();if(!rerun)return;
 const res=laCtx(e,B,()=>autoCompute(B,{ew:e.ew,sk:e.sk})),nw=laNew(res.R,res.k,B);e.lastT=closedT;
 if(e.ew){const o=e.cur,n=nw.cur;
  const weak=!n.none&&n.q<35;
  if(n.none||weak){if(o&&!o.none&&(o.dead||o.q>=35))add('keine starke Zählung mehr','Analyse läuft weiter')}
  else if(!o||o.none||o.q<35)add('neue Zählung',`${n.st} · ${n.q} %`);
  else if(o.type===n.type&&o.t0===n.t0){if(o.st!==n.st)add(n.st,`${n.q} %${n.tgt!=null?' · '+n.tl+' '+fmt(n.tgt):''}`);if(o.hit)n.hit=true}
  else add(o.dead?'neue Zählung':'Zählung gewechselt',`${n.st} · ${n.q} %${o.dead?'':' (vorher: '+o.st+')'}`);
  e.cur=n}
 if(e.sk){const o=e.skc,n=nw.skc;if(n&&n.q>=50&&(!o||o.t0!==n.t0))add('neues SK-Setup',`${n.q} % · Ziel ${fmt(n.tgt)}`);if(n&&o&&o.t0===n.t0&&o.hit)n.hit=true;e.skc=n}
 laApply(e,B,res.draws)}
  // ---- Ende Code aus der App ----
  return { S, AC, onPrice, eBotTick, TFMS, laProc };
}
const jp = v => { try { return typeof v === 'string' ? JSON.parse(v) : (v || null); } catch (_) { return null; } };
const ITV = { '1m': ['1', '1m', '1m'], '15m': ['15', '15m', '15m'], '1h': ['60', '1h', '1H'], '4h': ['240', '4h', '4H'], '1D': ['D', '1d', '1Dutc'] };
// Kerzen (aufsteigend, {t,o,h,l,c,v}); gleiche Quelle wie die App, mit Ersatzquellen
// Kursdaten ebenfalls über den Europa-Baustein (Fallback: direkt)
let KENV = null;
async function kFetch(url) { if (KENV && KENV.BYEU) { try { const x = await bxFetch(KENV, url, {}); return new Response(x.txt, { status: x.status }); } catch (_) {} } return fetch(url); }
async function klines(sym, tf, limit, pref) {
  const [by, bn, ok] = ITV[tf]; const alt = { XAUUSDT: 'PAXGUSDT', EURUSDUSDT: 'EURUSDT' }[sym] || sym;
  const row = k => ({ t: +k[0], o: +k[1], h: +k[2], l: +k[3], c: +k[4], v: +k[5] });
  const tries = {
    bybit: async () => { const r = await kFetch(`https://api.bybit.com/v5/market/kline?category=linear&symbol=${sym}&interval=${by}&limit=${Math.min(limit, 1000)}`); if (!r.ok) return null; const j = await r.json(); const l = j && j.result && j.result.list; return Array.isArray(l) && l.length ? l.map(row).reverse() : null; },
    'binance-vision': async () => { const r = await kFetch(`https://data-api.binance.vision/api/v3/klines?symbol=${alt}&interval=${bn}&limit=${Math.min(limit, 1000)}`); if (!r.ok) return null; const k = await r.json(); return Array.isArray(k) && k.length ? k.map(row) : null; },
    binance: async () => { const r = await kFetch(`https://api.binance.com/api/v3/klines?symbol=${alt}&interval=${bn}&limit=${Math.min(limit, 1000)}`); if (!r.ok) return null; const k = await r.json(); return Array.isArray(k) && k.length ? k.map(row) : null; },
    okx: async () => { const r = await kFetch(`https://www.okx.com/api/v5/market/candles?instId=${okxId(alt)}&bar=${ok}&limit=${Math.min(limit, 300)}`); if (!r.ok) return null; const j = await r.json(); return j && Array.isArray(j.data) && j.data.length ? j.data.map(row).reverse() : null; },
  };
  const order = pref === 'binance' ? ['binance-vision', 'binance', 'bybit', 'okx'] : ['bybit', 'binance-vision', 'binance', 'okx'];
  for (const n of order) { try { const b = await tries[n](); if (b && b.length && b.every(x => isFinite(x.c))) return { bars: b, src: n }; } catch (_) {} }
  return { err: 'keine Kursquelle erreichbar' };
}
const ENG_WRITE = 15 * 60e3; // Zwischenstände spätestens alle 15 Min. speichern (KV-Schreiblimit schonen)
// opt: { now, dry, force }
async function engRun(env, opt = {}) {
  const KV = env.WDESK; if (!KV) return { skip: 'nokv' };
  const now = opt.now || Date.now(), t0run = Date.now();
  const head = await KV.get('head', 'json'); if (!head || !head.v) return { skip: 'nosync' };
  const eng = (await KV.get('eng', 'json')) || {};
  if (!opt.dry && !opt.force) {
    const alive = (await KV.get('alive', 'json')) || {};
    if (Object.values(alive).some(t => t && now - t < 4 * 60e3)) return { skip: 'app offen' };
    if (head.dev !== 'server' && now - head.t < 90e3) return { skip: 'frisch' };
  }
  const snap = await KV.get('snap', 'json'); if (!snap || !snap.data) return { skip: 'nosync' };
  if (snap.v !== head.v) return { skip: 'stand' };
  const cfg = jp(snap.data.wdesk_srv) || { on: true }; if (cfg.on === false) return { skip: 'aus', w: eng.w || null };
  const hadAcct = !!snap.data.wdesk_acct, acct = jp(snap.data.wdesk_acct) || { bal: 0, pos: [], ord: [], hist: [], bots: [] };
  const map = jp(snap.data.wdesk_srvmap) || {}, pref = String(jp(snap.data.wdesk_xsrc) || snap.data.wdesk_xsrc || 'bybit').includes('binance') ? 'binance' : 'bybit';
  const symOfK = k => k && k.startsWith('binance:') ? k.slice(8) : null;
  const actBot = b => !b.replay && b.ex !== 'bybit' && b.state !== 'stopped' && b.state !== 'done' && ['elliott', 'grid', 'channel'].includes(b.type);
  const syms = [...new Set([...(acct.bots || []).filter(actBot).map(b => symOfK(b.key)), ...(acct.pos || []).filter(p => !p.replay && p.bot != null).map(p => symOfK(p.key))].filter(y => y && map[y]))].slice(0, 12);
  const LAs = jp(snap.data.wdesk_la) || [], laAct = LAs.filter(e => e.src === 'binance' && map[e.sym]).slice(0, 10);
  if (!syms.length && !laAct.length) return { skip: 'nobots', w: eng.w || null };
  const data = { ...snap.data };
  // Fortschritt der Live-Analysen (welche Kerze schon gezählt ist) liegt im kleinen eng-Eintrag
  if (eng.v === head.v && eng.la) LAs.forEach(e => { const g = eng.la[e.id]; if (g) Object.assign(e, g); });
  const laCur = () => JSON.stringify(LAs.map(e => [e.id, e.cur, e.skc])), laCurBefore = laCur();
  // Fortschritt gilt nur für denselben Stand; hat die App inzwischen gespeichert, ab ihrem Zeitpunkt weiterrechnen
  const same = eng.v === head.v, prog = same ? (eng.t || {}) : {}, seen = same ? (eng.b || {}) : {};
  const before = JSON.stringify(acct, (k, v) => k === 'lpx' ? undefined : v);
  const events = [];
  const bxIds = new Set((acct.bots || []).filter(b => b.ex === 'bybit').map(b => b.id));
  const E = makeEngine({ acct, data, hold: o => o.ex === 'bybit' || (o.bot != null && bxIds.has(o.bot)), notify: (kind, title, body, nav, sym) => events.push({ kind, title, body: body || '', nav: Object.assign({ sym, tf: null, tab: kind === 'bot' ? 'bots' : 'chart' }, nav || {}) }) });
  const out = [], nprog = { ...prog }, nseen = JSON.parse(JSON.stringify(seen));
  const nowC = Math.floor(now / 60e3) * 60e3; // Beginn der laufenden Minute
  for (const y of syms) {
    const code = map[y], info = { sym: y, bots: acct.bots.filter(b => actBot(b) && symOfK(b.key) === y).length, pos: acct.pos.filter(p => !p.replay && p.bot != null && symOfK(p.key) === y).length };
    try {
      let from = prog[y] != null ? prog[y] : (head.dev === 'server' ? nowC - 2 * 60e3 : Math.floor(head.t / 60e3) * 60e3);
      from = Math.max(from, nowC - 999 * 60e3);
      const need = Math.max(2, Math.ceil((nowC - from) / 60e3) + 1);
      const m1 = await klines(code, '1m', Math.min(1000, need + 1), pref); if (m1.err) { info.err = m1.err; out.push(info); continue; }
      const nb = m1.bars.filter(b => b.t > from && b.t + 60e3 <= now); info.src = m1.src;
      const last = m1.bars.filter(b => b.t + 60e3 <= now).pop(); info.px = last ? last.c : m1.bars[m1.bars.length - 1].c;
      const ebots = acct.bots.filter(b => actBot(b) && b.type === 'elliott' && symOfK(b.key) === y);
      const tfs = new Set(); ebots.forEach(b => (b.tfs || [b.tf]).forEach(t => { if (t && t !== 'csv') tfs.add(t); }));
      // 15m-Kerzen: Kontext der App im Hintergrund (Zeiteinheit 15m)
      let b15 = null;
      if (tfs.has('15m') && nb.some(b => (b.t + 60e3) % 9e5 === 0)) { const r = await klines(code, '15m', 1000, pref); if (!r.err) b15 = r.bars; }
      E.S.sym = y; E.S.tfData = {};
      for (const b of nb) {
        const k = Math.floor(b.t / 9e5) * 9e5; let bars;
        if (b15) { const i = b15.findIndex(x => x.t === k); bars = i >= 0 ? b15.slice(0, i + 1) : [...b15]; const lb = bars[bars.length - 1]; bars[bars.length - 1] = { ...lb, c: b.c }; }
        else bars = [{ t: k, o: b.o, h: b.h, l: b.l, c: b.c, v: b.v }];
        E.S.bars = bars;
        E.onPrice(b.h, b.l, b.c, (b.t + 60e3) % 9e5 === 0);
      }
      if (last) { const lb = E.S.bars[E.S.bars.length - 1]; if (!b15 || !nb.length) E.S.bars = [{ t: Math.floor(last.t / 9e5) * 9e5, o: last.o, h: last.h, l: last.l, c: last.c, v: last.v }]; else if (lb) lb.c = last.c; }
      // höhere Zeiteinheiten: nur neu laden, wenn dort eine Kerze fertig geworden ist
      const sn = nseen[y] || (nseen[y] = {});
      for (const tf of tfs) {
        if (tf === '15m') continue; const ms = E.TFMS[tf]; if (!ms) continue; const per = Math.floor(now / ms) * ms;
        if (sn[tf] === per) continue;
        const r = await klines(code, tf, 1000, pref); if (r.err) continue;
        E.S.tfData[tf] = { bars: r.bars, ts: now, sym: y };
        if (r.bars[r.bars.length - 1].t >= per) sn[tf] = per; // fertige Kerze ist da
      }
      if (Object.keys(E.S.tfData).length) E.eBotTick(false);
      if (nb.length) nprog[y] = nb[nb.length - 1].t;
    } catch (e) { info.err = String(e && e.message || e); }
    out.push(info);
  }
  // ---- Live-Analysen ----
  // Wie in der App: nach jedem Kerzenschluss neu zählen, und jede Minute prüfen,
  // ob eine Marke gebrochen oder ein Ziel erreicht wurde (dafür reichen die letzten Kerzen).
  const laOut = []; let budget = 4;
  const order = laAct.map((e, i) => ({ e, i }));
  for (const { e, i } of order) {
    const info = { sym: e.sym, tf: e.tf };
    try {
      const ms = E.TFMS[e.tf]; if (!ms) continue;
      const since = e.chkT || 0, n = Math.min(1000, Math.max(3, Math.ceil((now - since) / ms) + 2));
      const tl = await klines(map[e.sym], e.tf, n, pref); if (tl.err) { info.err = tl.err; laOut.push(info); continue; }
      const T = tl.bars; let hi = -Infinity, lo = Infinity;
      for (const b of T) { if (b.t < since) continue; if (b.t === e.chkT && e.bH != null) { if (b.h > e.bH) hi = Math.max(hi, b.h); if (b.l < e.bL) lo = Math.min(lo, b.l); } else { hi = Math.max(hi, b.h); lo = Math.min(lo, b.l); } }
      const trig = ['cur', 'skc'].some(f => { const c = e[f]; return c && !c.none && ((!c.dead && c.inv != null && (c.invUp ? hi > c.inv : lo < c.inv)) || (!c.hit && !c.dead && c.tgt != null && (c.tgtUp ? hi >= c.tgt : lo <= c.tgt))); });
      const closedT = T.length >= 2 ? T[T.length - 2].t : null;
      const due = closedT != null && e.lastT !== closedT;
      if ((trig || due) && budget > 0) {
        const full = await klines(map[e.sym], e.tf, 1000, pref);
        if (!full.err && full.bars.length > 60) {
          budget--; const msgs = [];
          E.laProc(e, full.bars, msgs);
          msgs.forEach(m => events.push({ kind: 'live', title: m.title, body: m.body || '', nav: { sym: e.sym, tf: e.tf, tab: 'chart' } }));
          info.ran = true;
        }
      }
      const c = e.cur || {}; info.st = c.none ? 'keine Zählung' : (c.st ? `${c.dead ? 'ungültig: ' : ''}${c.st} · ${c.q} %` : 'wartet'); info.src = tl.src;
    } catch (er) { info.err = String(er && er.message || er); }
    laOut.push(info);
  }
  if (laOut.some(x => x.ran)) data.wdesk_la = JSON.stringify(LAs);
  const after = JSON.stringify(acct, (k, v) => k === 'lpx' ? undefined : v);
  const changed = after !== before, important = events.length > 0 || laCur() !== laCurBefore;
  const laRan = laOut.some(x => x.ran), laProg = {};
  LAs.forEach(e => { if (e.lastT != null) laProg[e.id] = { lastT: e.lastT, chkT: e.chkT, bH: e.bH, bL: e.bL }; });
  const ms = Date.now() - t0run;
  const res = { syms: out, la: laOut, events: events.map(e => e.title + ' · ' + e.body), changed, ms, w: eng.w || null, last: eng.r || null };
  if (opt.dry) return res;
  if ((changed || important) && (important || !eng.w || now - eng.w >= ENG_WRITE)) {
    // neuen Stand speichern → die App lädt ihn beim nächsten Öffnen
    if (hadAcct || changed) data.wdesk_acct = after;
    if (events.length) {
      const inb = jp(data.wdesk_inbox) || [];
      events.forEach((e, i) => inb.unshift({ id: (now + i).toString(36) + 'srv', t: now, kind: e.kind, title: e.title, body: e.body + ' · ☁️ Server', nav: e.nav, read: false }));
      if (inb.length > 150) inb.length = 150; data.wdesk_inbox = JSON.stringify(inb);
    }
    const v = head.v + 1;
    await KV.put('snap', JSON.stringify({ v, data }));
    await KV.put('head', JSON.stringify({ v, t: now, dev: 'server', name: 'Server ☁️', lead: head.lead }));
    const r = events.length ? events[events.length - 1].title : 'Zwischenstand';
    await KV.put('eng', JSON.stringify({ v, t: nprog, b: nseen, w: now, r, la: laProg }));
    res.saved = v;
    for (const e of events.slice(0, 6)) await pushAll(env, { title: e.title, body: e.body, tag: (e.kind === 'live' ? 'la-' : 'bot-') + now + '-' + Math.random().toString(36).slice(2, 6), nav: { sym: e.nav.sym, tf: e.nav.tf || null, tab: e.nav.tab } }, false);
    { const lv = events.find(e => e.kind === 'live' && e.nav && map[e.nav.sym]); if (lv) { try { await aiAuto(env, { sym: lv.nav.sym, code: map[lv.nav.sym], tf: lv.nav.tf, title: lv.title, body: lv.body }); } catch (_) {} } }
  } else {
    const per = !changed && (!eng.w || now - eng.w >= ENG_WRITE || eng.v !== head.v);
    if (per || laRan) {
      // offene Bot-Änderungen (noch nicht gespeichert) → deren Fortschritt NICHT vorrücken, damit nichts verloren geht
      const base = eng.v === head.v ? { ...eng } : { v: head.v, t: {}, b: {}, w: null, r: null };
      if (!changed) { base.t = nprog; base.b = nseen; }
      if (per) base.w = now;
      base.la = laProg; base.v = head.v;
      await KV.put('eng', JSON.stringify(base));
    }
  }
  return res;
}

// ================= 🟠 Bots handeln über Bybit Demo =================
// Bybit ist maßgeblich: Stop und Ziele liegen als Orders an der Börse. Der Server eröffnet nach den Signalen
// der Elliott-Bots (gleicher Code wie in der App), zieht den Stop nach (Einstand, Nachzieh-Stop) und bucht
// Ergebnisse so, wie Bybit sie abrechnet. Nur das Demo-Konto – echtes Geld kommt erst in einem eigenen Schritt.
const BX_LEV_MAX = 20, BX_POS_MAX = 3, BX_FEE = 0.00055;
const bxNum = (v, d) => { const x = parseFloat(v); return isFinite(x) ? x : d; };
const bxDec = s => Math.max(0, (String(s).split('.')[1] || '').replace(/0+$/, '').length);
const bxFloor = (x, s) => +(Math.floor(x / s + 1e-9) * s).toFixed(bxDec(s) + 2);
const bxRnd = (x, s, dir) => +((dir > 0 ? Math.ceil(x / s - 1e-9) : dir < 0 ? Math.floor(x / s + 1e-9) : Math.round(x / s)) * s).toFixed(bxDec(s) + 2);
const bxS = (x, s) => x.toFixed(bxDec(s));
const bxMoney = v => (v < 0 ? '-' : '+') + '$' + new Intl.NumberFormat('de-DE', { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(Math.abs(v));
async function bxCall(env, method, path, params) {
  const r = await bybit(env, 'demo', method, path, params); const b = r.body || {};
  if (r.status !== 200 || b.retCode !== 0) { const e = new Error((b.retMsg || b.msg || b.error || 'Fehler') + (b.retCode != null ? ` (${b.retCode})` : '')); e.code = b.retCode; throw e; }
  return b.result || {};
}
const BXI = {};
async function bxInstr(env, code) {
  if (BXI[code]) return BXI[code];
  const r = await bxCall(env, 'GET', '/v5/market/instruments-info', { category: 'linear', symbol: code }); const x = (r.list || [])[0];
  if (!x) throw new Error('Symbol bei Bybit unbekannt: ' + code);
  return (BXI[code] = { step: bxNum(x.lotSizeFilter.qtyStep, .001), min: bxNum(x.lotSizeFilter.minOrderQty, .001), tick: bxNum(x.priceFilter.tickSize, .1), maxLev: bxNum(x.leverageFilter && x.leverageFilter.maxLeverage, 25) });
}
// Gegen Überschneidungen: Was per Hand storniert/entfernt wurde, merkt sich der Server 15 Min.
// Ein gleichzeitig laufender Abgleich darf es beim Speichern nicht wieder zurückschreiben.
async function bxDead(KV, add) {
  const now = Date.now(); let d = (await KV.get('bxdel', 'json')) || {};
  for (const k in d) if (now - d[k] > 15 * 60e3) delete d[k];
  if (add && add.length) { add.forEach(id => { d[id] = now; }); await KV.put('bxdel', JSON.stringify(d)); }
  return d;
}
async function bxSave(KV, bx) { const d = await bxDead(KV); if (Object.keys(d).length) bx.pos = bx.pos.filter(q => !(q.id != null && d[q.id])); await KV.put('bx', JSON.stringify(bx)); }
async function bxLoad(KV) {
  const bx = (await KV.get('bx', 'json')) || {}; bx.bots = bx.bots || {}; bx.pos = bx.pos || []; bx.hist = bx.hist || []; bx.err = bx.err || [];
  const c = (await KV.get('bxcfg', 'json')) || {}; c.bots = c.bots || {}; c.map = c.map || {};
  return { bx, cfg: c };
}
const bxPaused = (bx, cfg, id) => { const s = bx.bots[id], c = cfg.bots[id]; return !!(s && s.paused && !(c && c.resumeT > s.pausedT)); };
async function bxPush(env, title, body, sym) { try { await pushAll(env, { title, body, tag: 'bx-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6), nav: { sym, tab: 'bots' } }, false); } catch (_) {} }
function bxPause(bx, id, why, now) { const s = bx.bots[id] || (bx.bots[id] = {}); s.paused = why; s.pausedT = now; }
// Position bei Bybit schließen (Orders weg, Rest per Market reduce-only)
async function bxClose(env, p, x, why) {
  p.closing = p.closing || why;
  try { await bxCall(env, 'POST', '/v5/order/cancel-all', { category: 'linear', symbol: p.code }); } catch (_) {}
  const sz = bxNum(x && x.size, 0); if (sz <= 0) return;
  await bxCall(env, 'POST', '/v5/order/create', { category: 'linear', symbol: p.code, side: p.dir > 0 ? 'Sell' : 'Buy', orderType: 'Market', qty: String(x.size), reduceOnly: true, positionIdx: 0 });
}
// geschlossene Position so buchen, wie Bybit abgerechnet hat
async function bxBook(env, bx, p, now, ev) {
  let L = [];
  try { const r = await bxCall(env, 'GET', '/v5/position/closed-pnl', { category: 'linear', symbol: p.code, startTime: String(p.t0 - 60e3), limit: '50' }); const done = new Set(bx.booked || []); L = (r.list || []).filter(x => +x.createdTime >= p.t0 - 60e3 && !done.has(x.orderId + ':' + x.createdTime)); } catch (_) {}
  p.bookTry = (p.bookTry || 0) + 1;
  if (!L.length && p.bookTry < 5) return false; // Abrechnung noch nicht da → nächste Minute
  const q = L.reduce((s, x) => s + bxNum(x.closedSize, 0), 0), pnl = L.reduce((s, x) => s + bxNum(x.closedPnl, 0), 0);
  const exit = q > 0 ? L.reduce((s, x) => s + bxNum(x.avgExitPrice, 0) * bxNum(x.closedSize, 0), 0) / q : (p.lastPx || p.entry);
  // Grund aus den Ausführungen: Ausstieg auf einem Ziel-Preis = Ziel, sonst Stop
  const tpP = p.tps.filter(t => !t.skip && !t.small).map(t => t.pb || t.p), onTP = x => tpP.some(tp => Math.abs(bxNum(x.avgExitPrice, 0) - tp) <= Math.max(p.tick || 0, tp * 4e-4));
  const nT = L.filter(onTP).length, rest = L.length - nT, beSL = p.sl != null && p.dir * (p.sl - p.entry) >= -1.5 * (p.tick || 0);
  const stopWhy = p.slMoved ? 'Nachzieh-Stop' : beSL ? 'Einstand' : 'Stop';
  const why = p.closing || (L.length && !rest ? (nT >= tpP.length && tpP.length > 1 ? 'Ziele erreicht' : 'Ziel erreicht') : nT || (p.hits || 0) ? 'Ziel 1 + ' + stopWhy : stopWhy);
  const h = { id: p.id, bot: p.kind === 'hand' ? null : p.bot, hand: p.kind === 'hand', mode: 'fut', label: p.label, sym: p.sym, dir: p.dir, entry: p.entry, exit, qty: p.qty0b, pnl, R: p.risk$ ? pnl / p.risk$ : null, why, tf: p.btf || null, wave: p.wave || null, strat: p.strat || null, t0: p.t0, t1: now, ex: 'bybit', lev: p.levB };
  bx.hist.unshift(h); if (bx.hist.length > 100) bx.hist.length = 100;
  bx.booked = [...L.map(x => x.orderId + ':' + x.createdTime), ...(bx.booked || [])].slice(0, 200); // nie doppelt buchen
  if (p.kind !== 'hand') { const s = bx.bots[p.bot] || (bx.bots[p.bot] = {}); s.trades = (s.trades || 0) + 1; s.pnl = (s.pnl || 0) + pnl; }
  bx.pos = bx.pos.filter(x => x !== p);
  ev.push({ title: `🟠 Bybit Demo: ${p.label} ${p.dir > 0 ? 'Long' : 'Short'} geschlossen`, body: `${why} · ${bxMoney(pnl)} · Ausstieg ${deNum(exit)}`, sym: p.sym });
  return true;
}
// neue Position aus dem Bot-Signal bei Bybit eröffnen
async function bxOpen(env, p, code, now) {
  const ins = await bxInstr(env, code);
  const qty = bxFloor(p.qty, ins.step); if (!(qty >= ins.min)) throw new Error(`Menge ${qty} unter Bybit-Minimum ${ins.min} – Risiko erhöhen`);
  const lev = Math.max(1, Math.min(Math.floor(p.lev), BX_LEV_MAX, Math.floor(ins.maxLev)));
  try { await bxCall(env, 'POST', '/v5/position/set-leverage', { category: 'linear', symbol: code, buyLeverage: String(lev), sellLeverage: String(lev) }); } catch (e) { if (e.code !== 110043) throw e; }
  const sl = bxRnd(p.sl, ins.tick, -p.dir);
  const r = await bxCall(env, 'POST', '/v5/order/create', { category: 'linear', symbol: code, side: p.dir > 0 ? 'Buy' : 'Sell', orderType: 'Market', qty: bxS(qty, ins.step), stopLoss: bxS(sl, ins.tick), slTriggerBy: 'LastPrice', tpslMode: 'Full', positionIdx: 0, orderLinkId: 'wd' + p.id });
  Object.assign(p, { ex: 'bybit', code, qty0b: qty, step: ins.step, tick: ins.tick, min: ins.min, levB: lev, oid: r.orderId, filled: false, t0: now, sl, hits: 0 });
  try { const pl = await bxCall(env, 'GET', '/v5/position/list', { category: 'linear', symbol: code }); const x = (pl.list || []).find(y => bxNum(y.size, 0) > 0); if (x) { p.entry = bxNum(x.avgPrice, p.entry); p.filled = true; } } catch (_) {}
  // Ziele als Limit-Orders, die die Position nur verkleinern
  let left = qty; const errs = [];
  for (let k = 0; k < p.tps.length; k++) {
    const t = p.tps[k], last = k === p.tps.length - 1, q = last ? +left.toFixed(bxDec(ins.step) + 2) : bxFloor(qty * t.pct / 100, ins.step);
    if (!(q >= ins.min)) { t.skip = true; continue; }
    left -= q; t.q = q; t.pb = bxRnd(t.p, ins.tick, 0);
    try { await bxCall(env, 'POST', '/v5/order/create', { category: 'linear', symbol: code, side: p.dir > 0 ? 'Sell' : 'Buy', orderType: 'Limit', qty: bxS(q, ins.step), price: bxS(t.pb, ins.tick), reduceOnly: true, timeInForce: 'GTC', positionIdx: 0, orderLinkId: 'wd' + p.id + 't' + k }); }
    catch (e) { errs.push(`Ziel ${k + 1}: ${e.message}`); }
  }
  return errs;
}
// Stop nachziehen: Einstand nach Ziel 1, Nachzieh-Stop im Abstand der Wellen-Größe (wie in der App)
async function bxManage(env, p, x, now, pref) {
  const sz = bxNum(x.size, 0), d = p.dir, done = 1 - sz / p.qty0b;
  let cum = 0, hits = 0; for (const t of p.tps) { if (t.skip || !(t.q > 0)) continue; cum += t.q; if (p.qty0b - sz - (p.partQ || 0) >= cum - p.step / 2) hits++; }
  if (hits > (p.hits || 0)) p.hits = hits;
  if (p.manual) return null; // von Hand übernommen: Stop/Ziele nicht mehr automatisch verschieben
  const cur = bxNum(x.stopLoss, 0); let want = cur > 0 ? cur : p.sl, why = null;
  if (p.hits >= 1 && p.be && d * (p.entry - want) > 0) { want = p.entry; why = 'be'; }
  let last = null;
  if (p.trail > 0) {
    const age = now - p.t0, tf = age < 950 * 60e3 ? '1m' : '15m', ms = tf === '1m' ? 60e3 : 9e5;
    const k = await klines(p.code, tf, Math.min(1000, Math.ceil(age / ms) + 2), pref);
    if (!k.err) {
      const B = k.bars.filter(b => b.t >= Math.floor(p.t0 / ms) * ms + (tf === '1m' ? 60e3 : 0)); let ext = p.entry;
      B.forEach(b => { ext = d > 0 ? Math.max(ext, b.h) : Math.min(ext, b.l); }); last = k.bars[k.bars.length - 1].c; p.lastPx = last;
      const ns = ext * (1 - d * p.trail / 100); if (d * (ns - want) > 0) { want = ns; why = 'trail'; }
    }
  }
  want = bxRnd(want, p.tick, -d);
  if (why && (cur <= 0 || d * (want - cur) >= p.tick * .999)) {
    if (last != null && d * (last - want) <= 0) { await bxClose(env, p, x, why === 'be' ? 'Einstand' : 'Nachzieh-Stop'); return 'closed'; }
    try { await bxCall(env, 'POST', '/v5/position/trading-stop', { category: 'linear', symbol: p.code, stopLoss: bxS(want, p.tick), slTriggerBy: 'LastPrice', tpslMode: 'Full', positionIdx: 0 }); }
    catch (e) { // Kurs schon (fast) am neuen Stop → wie in der App sofort schließen, sonst nächste Minute erneut
      if (last != null && d * (last - want) <= Math.abs(want) * .002) { await bxClose(env, p, x, why === 'be' ? 'Einstand' : 'Nachzieh-Stop'); return 'closed'; } throw e; }
    p.sl = want; if (why === 'trail') p.slMoved = true; return why;
  }
  return null;
}
// ---- ✋ Hand-Orders aus der App an Bybit Demo (Futures + Spot) ----
// Futures: Stop liegt als Positions-Stop bei Bybit, Ziele als Limit-Orders (nur verkleinernd).
// Spot: Ziele als Limit-Verkäufe bei Bybit; den Stop überwacht der Server jede Minute (Spot kennt keinen Positions-Stop).
const BXIS = {};
async function bxInstrSpot(env, code) {
  if (BXIS[code]) return BXIS[code];
  const r = await bxCall(env, 'GET', '/v5/market/instruments-info', { category: 'spot', symbol: code }); const x = (r.list || [])[0];
  if (!x) throw new Error('Diesen Spot-Markt gibt es bei Bybit nicht: ' + code);
  const lf = x.lotSizeFilter || {};
  return (BXIS[code] = { step: bxNum(lf.basePrecision, .000001), min: bxNum(lf.minOrderQty, 0), minAmt: bxNum(lf.minOrderAmt, 1), tick: bxNum(x.priceFilter && x.priceFilter.tickSize, .01), base: x.baseCoin || code.replace(/USDT$/, '') });
}
// Ziele (nur noch offene) neu legen; Futures reduce-only, Spot normale Limit-Verkäufe
async function bxPlaceTPs(env, p, size) {
  const open = p.tps.filter(t => !t.hit && !t.skip), sum = open.reduce((s, t) => s + t.pct, 0) || 1; let left = size; const errs = [];
  p.tpv = (p.tpv || 0) + 1;
  for (let k = 0; k < open.length; k++) {
    const t = open[k], last = k === open.length - 1, q = last ? +left.toFixed(bxDec(p.step) + 2) : bxFloor(size * t.pct / sum, p.step);
    t.pb = bxRnd(t.p, p.tick, 0);
    if (!(q > 0) || q < (p.min || 0) || (p.mode === 'spot' && q * t.pb < (p.minAmt || 0))) { t.small = true; t.q = 0; continue; }
    t.q = q; t.small = false;
    left -= q;
    const body = { category: p.mode === 'spot' ? 'spot' : 'linear', symbol: p.code, side: p.dir > 0 ? 'Sell' : 'Buy', orderType: 'Limit', qty: bxS(q, p.step), price: bxS(t.pb, p.tick), timeInForce: 'GTC', orderLinkId: 'wh' + p.id + 'v' + p.tpv + 't' + p.tps.indexOf(t) };
    if (p.mode !== 'spot') { body.reduceOnly = true; body.positionIdx = 0; }
    try { const r = await bxCall(env, 'POST', '/v5/order/create', body); t.oid = r.orderId; } catch (e) { errs.push(`Ziel ${p.tps.indexOf(t) + 1}: ${e.message}`); }
  }
  return errs;
}
async function bxCancelTPs(env, p) {
  for (const t of p.tps) if (t.oid && !t.hit) { try { await bxCall(env, 'POST', '/v5/order/cancel', { category: p.mode === 'spot' ? 'spot' : 'linear', symbol: p.code, orderId: t.oid }); } catch (_) {} t.oid = null; }
}
// Stornieren nur als erledigt melden, wenn Bybit es bestätigt (oder die Order dort gar nicht mehr offen ist)
async function bxCancelSafe(env, cat, p) {
  try { await bxCall(env, 'POST', '/v5/order/cancel', { category: cat, symbol: p.code, orderLinkId: 'wh' + p.id }); return true; }
  catch (e) {
    const o = await bxOrderStatus(env, cat, p.code, 'wh' + p.id), st = o && o.orderStatus;
    if (!o || /Cancel|Reject|Deactivat/.test(st || '')) return true;
    if (/Filled/.test(st || '')) throw new Error('Die Order wurde gerade bei Bybit ausgeführt – sie erscheint gleich als offene Position (dann Schließen/Verkaufen)');
    throw new Error('Bybit hat das Stornieren abgelehnt: ' + (e.message || e) + ' – Order ist noch offen, bitte nochmal versuchen');
  }
}
async function bxOrderStatus(env, cat, code, link) {
  for (const path of ['/v5/order/realtime', '/v5/order/history']) {
    try { const r = await bxCall(env, 'GET', path, { category: cat, symbol: code, orderLinkId: link }); const o = (r.list || [])[0]; if (o) return o; } catch (_) {}
  }
  return null;
}
// Spot: was wurde seit dem Kauf gekauft/verkauft (Gebühr beim Kauf geht in Coins ab)
async function bxSpotFills(env, p) {
  const r = await bxCall(env, 'GET', '/v5/execution/list', { category: 'spot', symbol: p.code, startTime: String(p.t0 - 60e3), limit: '100' });
  let bq = 0, bv = 0, bfee = 0, sq = 0, sv = 0, sfee = 0, tq = 0;
  (r.list || []).forEach(x => { const q = bxNum(x.execQty, 0), px = bxNum(x.execPrice, 0), f = bxNum(x.execFee, 0);
    if (x.side === 'Buy' && (x.orderLinkId === 'wh' + p.id || x.orderId === p.oid)) { bq += q; bv += q * px; if ((x.feeCurrency || p.base) === p.base) bfee += f; else bv += f; }
    else if (x.side === 'Sell' && String(x.orderLinkId || '').startsWith('wh' + p.id)) { if (/v\d+t\d+$/.test(x.orderLinkId)) tq += q; sq += q; sv += q * px; sfee += (x.feeCurrency && x.feeCurrency !== 'USDT') ? f * px : f; } });
  return { bq, bv, bfee, net: Math.max(0, bq - bfee), sq, sv, sfee, tq };
}
async function bxSpotRun(env, bx, p, now, ev, log) {
  if (!p.filled) {
    const o = await bxOrderStatus(env, 'spot', p.code, 'wh' + p.id);
    const st = o && o.orderStatus;
    if (st === 'Filled' || st === 'PartiallyFilledCanceled') { const f = await bxSpotFills(env, p); if (!(f.net > 0)) return; p.filled = true; p.t0f = now; p.entry = f.bq ? f.bv / f.bq : p.entry; p.qtyNet = bxFloor(f.net, p.step); p.risk$ = Math.abs(p.entry - (p.sl || p.entry)) * p.qtyNet || p.risk$;
      ev.push({ title: `🟠 Bybit Demo: ${p.base} gekauft (Spot)`, body: `${deNum(p.qtyNet)} ${p.base} @ ${deNum(p.entry)}${p.sl ? ' · Stop ' + deNum(p.sl) + ' (Server)' : ''}`, sym: p.sym });
      (await bxPlaceTPs(env, p, p.qtyNet)).forEach(m => log(`${p.label}: ${m}`)); return; }
    if (st === 'Cancelled' || st === 'Rejected' || st === 'Deactivated' || (!o && now - p.t0 > 30 * 60e3)) { bx.pos = bx.pos.filter(q => q !== p); ev.push({ title: `🟠 Bybit Demo: Spot-Kauf ${p.base} storniert`, body: st || 'nicht gefunden', sym: p.sym }); }
    return;
  }
  const f = await bxSpotFills(env, p), rem = bxFloor(Math.max(0, p.qtyNet - f.sq), p.step);
  // Ziele erreicht?
  let cum = 0, hits = 0;
  for (const t of p.tps) { if (!(t.q > 0)) continue; cum += t.q; if (f.tq + (p.tqBase || 0) >= cum - p.step / 2) { t.hit = true; hits++; } }
  if (hits > (p.hits || 0)) { p.hits = hits; if (rem > 0) ev.push({ title: `🟠 Bybit Demo: ${p.base} Ziel ${hits} erreicht`, body: `Rest ${deNum(rem)} ${p.base}${p.be ? ' · Stop auf Einstand' : ''}`, sym: p.sym }); }
  const dust = rem < Math.max(p.min || 0, p.step) || rem * (p.lastPx || p.entry) < (p.minAmt || 1);
  if (dust || p.sold) { // fertig → buchen
    const pnl = f.sv - f.sfee - (p.entry * (f.bq || p.qtyNet)) + (f.bq ? 0 : 0), exit = f.sq ? f.sv / f.sq : (p.lastPx || p.entry);
    const why = p.closing || (p.hits >= p.tps.filter(t => !t.skip).length && p.tps.length ? 'Ziele erreicht' : p.hits ? 'Ziel 1 + Rest verkauft' : 'Verkauft');
    bx.hist.unshift({ id: p.id, hand: true, mode: 'spot', label: p.label, sym: p.sym, dir: 1, entry: p.entry, exit, qty: p.qtyNet, pnl, R: p.risk$ ? pnl / p.risk$ : null, why, t0: p.t0, t1: now, ex: 'bybit' }); if (bx.hist.length > 100) bx.hist.length = 100;
    bx.pos = bx.pos.filter(q => q !== p); await bxCancelTPs(env, p);
    ev.push({ title: `🟠 Bybit Demo: ${p.base} (Spot) abgeschlossen`, body: `${why} · ${bxMoney(pnl)} · Ø Verkauf ${deNum(exit)}`, sym: p.sym });
    return;
  }
  // Stop (Server): Einstand nach Ziel 1, Nachzieh-Stop, Kurs prüfen
  const k = await klines(p.code, '1m', Math.min(1000, Math.ceil((now - (p.t0f || p.t0)) / 60e3) + 2), 'bybit');
  if (k.err) return;
  const B = k.bars.filter(b => b.t >= Math.floor((p.t0f || p.t0) / 60e3) * 60e3 + 60e3), last = k.bars[k.bars.length - 1].c; p.lastPx = last;
  let sl = p.sl; if (p.hits >= 1 && p.be && sl != null && p.entry > sl) sl = p.entry;
  if (p.trail > 0) { let ext = p.entry; B.forEach(b => { ext = Math.max(ext, b.h); }); const ns = ext * (1 - p.trail / 100); if (sl == null || ns > sl) sl = ns; }
  if (sl != null && sl !== p.sl) p.sl = sl;
  const low = Math.min(last, ...B.filter(b => b.t + 60e3 <= now && b.t >= now - 3 * 60e3).map(b => b.l));
  if (p.sl != null && low <= p.sl) { p.closing = p.hits ? (p.be && p.sl >= p.entry ? 'Einstand' : 'Nachzieh-Stop') : 'Stop'; await bxSpotSell(env, p, rem); }
}
async function bxSpotSell(env, p, q) {
  await bxCancelTPs(env, p);
  const f = await bxSpotFills(env, p), rem = bxFloor(Math.max(0, p.qtyNet - f.sq), p.step), qq = Math.min(bxFloor(q, p.step), rem);
  if (!(qq > 0)) { p.sold = true; return; }
  p.sv = (p.sv || 0) + 1;
  await bxCall(env, 'POST', '/v5/order/create', { category: 'spot', symbol: p.code, side: 'Sell', orderType: 'Market', qty: bxS(qq, p.step), marketUnit: 'baseCoin', orderLinkId: 'wh' + p.id + 's' + p.sv });
  if (qq >= rem - p.step / 2) p.sold = true; else await bxPlaceTPs(env, p, rem - qq);
}
async function bxHand(env, b, opt = {}) {
  const KV = env.WDESK; if (!KV) throw new Error('Speicher (KV) fehlt');
  if (!(env.BYBIT_DEMO_KEY && env.BYBIT_DEMO_SECRET)) throw new Error('Kein Bybit-Demo-Schlüssel auf dem Server');
  const { bx } = await bxLoad(KV), now = opt.now || Date.now(), ev = [], res = { ok: true };
  const find = () => bx.pos.find(q => q.id === +b.id || (b.code && q.code === b.code && (q.mode || 'fut') === (b.mode || 'fut')));
  const op = b.op;
  if (op === 'open') { const cfg0 = await KV.get('bxcfg', 'json') || {}; if (bxLocked(cfg0, now)) throw new Error(`Tagesverlust-Grenze erreicht (−${String(cfg0.lock.loss).replace('.', ',')} %) – neue Orders erst ab Mitternacht wieder möglich`); }
  if (op === 'open') {
    const code = String(b.code || ''), mode = b.mode === 'spot' ? 'spot' : 'fut', dir = mode === 'spot' ? 1 : (+b.dir < 0 ? -1 : 1);
    if (!/^[A-Z0-9]{3,24}$/.test(code)) throw new Error('Symbol fehlt');
    if (!['market', 'limit', 'stop'].includes(b.type)) throw new Error('Diese Order-Art geht bei Bybit (noch) nicht – Market, Limit oder Stop-Order wählen');
    const id = now, sl0 = +b.sl, tps = (b.tps || []).filter(t => isFinite(+t.p) && +t.pct > 0).slice(0, 3).map(t => ({ p: +t.p, pct: +t.pct }));
    const p = { kind: 'hand', mode, id, sym: b.sym, code, label: (b.sym || code) + (mode === 'spot' ? ' Spot' : ''), dir, tps, be: !!b.be, trail: Math.max(0, +b.trail || 0), t0: now, type: b.type, hits: 0, risk$: +b.risk || 0, strat: b.strat || null };
    if (mode === 'fut') {
      if (bx.pos.some(q => q.code === code && q.mode !== 'spot')) throw new Error('Auf diesem Paar läuft schon eine Bybit-Position oder Order (Bot oder Hand) – erst schließen/stornieren');
      const pl = await bxCall(env, 'GET', '/v5/position/list', { category: 'linear', symbol: code }); if ((pl.list || []).some(x => bxNum(x.size, 0) > 0)) throw new Error('Bei Bybit ist auf diesem Paar schon eine Position offen');
      if (!isFinite(sl0)) throw new Error('Stop-Loss fehlt');
      const ins = await bxInstr(env, code), qty = bxFloor(+b.qty, ins.step); if (!(qty >= ins.min)) throw new Error(`Menge ${qty} unter Bybit-Minimum ${ins.min}`);
      const lev = Math.max(1, Math.min(Math.floor(+b.lev || 1), BX_LEV_MAX, Math.floor(ins.maxLev)));
      try { await bxCall(env, 'POST', '/v5/position/set-leverage', { category: 'linear', symbol: code, buyLeverage: String(lev), sellLeverage: String(lev) }); } catch (e) { if (e.code !== 110043) throw e; }
      const sl = bxRnd(sl0, ins.tick, -dir), body = { category: 'linear', symbol: code, side: dir > 0 ? 'Buy' : 'Sell', orderType: 'Market', qty: bxS(qty, ins.step), stopLoss: bxS(sl, ins.tick), slTriggerBy: 'LastPrice', tpslMode: 'Full', positionIdx: 0, orderLinkId: 'wh' + id };
      if (b.type === 'limit') { body.orderType = 'Limit'; body.price = bxS(bxRnd(+b.price, ins.tick, 0), ins.tick); body.timeInForce = 'GTC'; }
      if (b.type === 'stop') { body.triggerPrice = bxS(bxRnd(+b.price, ins.tick, 0), ins.tick); body.triggerDirection = dir > 0 ? 1 : 2; body.triggerBy = 'LastPrice'; }
      const r = await bxCall(env, 'POST', '/v5/order/create', body);
      Object.assign(p, { oid: r.orderId, qty0b: qty, step: ins.step, tick: ins.tick, min: ins.min, levB: lev, lev, sl, entry: +b.price || null, filled: false });
      if (b.type === 'market') {
        try { const pl2 = await bxCall(env, 'GET', '/v5/position/list', { category: 'linear', symbol: code }); const x = (pl2.list || []).find(y => bxNum(y.size, 0) > 0); if (x) { p.entry = bxNum(x.avgPrice, p.entry); p.filled = true; p.t0 = now; } } catch (_) {}
        if (p.filled) res.warn = await bxPlaceTPs(env, p, qty);
      }
      bx.pos.push(p); res.pos = p;
      ev.push({ title: `🟠 Bybit Demo: ${p.label} ${dir > 0 ? 'Long' : 'Short'} ${p.filled ? 'eröffnet' : b.type === 'limit' ? '– Limit-Order liegt' : '– Stop-Order liegt'}`, body: `${p.filled ? '@ ' + deNum(p.entry) : 'bei ' + deNum(+b.price)} · ${qty} Stk. · ${lev}× · Stop ${deNum(sl)}`, sym: p.sym });
    } else {
      if (bx.pos.some(q => q.code === code && q.mode === 'spot')) throw new Error('Für diesen Coin läuft schon ein Spot-Trade – erst verkaufen/stornieren');
      const ins = await bxInstrSpot(env, code), qty = bxFloor(+b.qty, ins.step);
      const ref = b.type === 'market' ? +b.ref : +b.price; if (!(qty > 0) || qty < ins.min || qty * ref < ins.minAmt) throw new Error(`Menge zu klein für Bybit (min. ${ins.min} ${ins.base} bzw. ${ins.minAmt} USDT)`);
      const body = { category: 'spot', symbol: code, side: 'Buy', orderType: 'Market', qty: bxS(qty, ins.step), marketUnit: 'baseCoin', orderLinkId: 'wh' + id };
      if (b.type === 'limit') { body.orderType = 'Limit'; body.price = bxS(bxRnd(+b.price, ins.tick, 0), ins.tick); body.timeInForce = 'GTC'; delete body.marketUnit; }
      if (b.type === 'stop') { body.orderFilter = 'StopOrder'; body.triggerPrice = bxS(bxRnd(+b.price, ins.tick, 0), ins.tick); }
      const r = await bxCall(env, 'POST', '/v5/order/create', body);
      Object.assign(p, { oid: r.orderId, step: ins.step, tick: ins.tick, min: ins.min, minAmt: ins.minAmt, base: ins.base, sl: isFinite(sl0) ? sl0 : null, entry: ref, filled: false, qtyAsk: qty });
      bx.pos.push(p); res.pos = p;
      if (b.type === 'market') { const log = m => res.warn = [...(res.warn || []), m]; await bxSpotRun(env, bx, p, now, ev, log); }
      if (!p.filled) ev.push({ title: `🟠 Bybit Demo: Spot-Kauf ${ins.base} ${b.type === 'market' ? 'gesendet' : 'liegt'}`, body: `${qty} ${ins.base}${b.type !== 'market' ? ' bei ' + deNum(+b.price) : ''}`, sym: p.sym });
    }
  } else {
    const p = find(); if (!p) throw new Error('Position/Order nicht gefunden – evtl. schon geschlossen');
    if (p.mode === 'spot') {
      if (op === 'cancel' && !p.filled) { await bxCancelSafe(env, 'spot', p); bx.pos = bx.pos.filter(q => q !== p); await bxDead(KV, [p.id]); ev.push({ title: `🟠 Bybit Demo: Spot-Kauf ${p.base} storniert`, body: 'von dir', sym: p.sym }); }
      else if (op === 'close' || op === 'part') { if (!p.filled) throw new Error('Kauf ist noch nicht ausgeführt – stornieren'); const f = await bxSpotFills(env, p), rem = Math.max(0, p.qtyNet - f.sq); p.closing = op === 'close' ? 'Von Hand verkauft' : null; await bxSpotSell(env, p, op === 'close' ? rem : rem * Math.min(1, Math.max(.05, +b.pct || .5))); await bxSpotRun(env, bx, p, now, ev, () => {}); }
      else if (op === 'sl') { p.sl = isFinite(+b.price) ? +b.price : null; }
      else if (op === 'be') { if (!p.filled) throw new Error('Noch nicht gekauft'); p.sl = p.entry; }
      else if (op === 'tp') { if (!p.filled) throw new Error('Noch nicht gekauft'); await bxCancelTPs(env, p); p.tps = (b.tps || []).filter(t => isFinite(+t.p) && +t.pct > 0).slice(0, 3).map(t => ({ p: +t.p, pct: +t.pct })); const f = await bxSpotFills(env, p); const rem = bxFloor(Math.max(0, p.qtyNet - f.sq), p.step); p.hits = 0; p.tqBase = -f.tq; res.warn = await bxPlaceTPs(env, p, rem); }
      else throw new Error('Unbekannte Aktion');
    } else {
      const pl = await bxCall(env, 'GET', '/v5/position/list', { category: 'linear', symbol: p.code }); const x = (pl.list || []).find(y => bxNum(y.size, 0) > 0);
      const takeover = () => { if (p.kind !== 'hand' && !p.manual) { p.manual = true; ev.push({ title: `✋ Bybit Demo: ${p.label} von dir übernommen`, body: 'Stop und Ziele dieser Bot-Position steuerst ab jetzt du – der Bot handelt neue Signale normal weiter', sym: p.sym }); } };
      if (op === 'cancel' && !p.filled) { await bxCancelSafe(env, 'linear', p); bx.pos = bx.pos.filter(q => q !== p); await bxDead(KV, [p.id]); ev.push({ title: `🟠 Bybit Demo: Order ${p.label} storniert`, body: 'von dir', sym: p.sym }); }
      else if (op === 'close') { if (!x) throw new Error('Keine offene Position bei Bybit'); await bxClose(env, p, x, 'Von Hand geschlossen'); try { if (await bxBook(env, bx, p, now, ev)) { try { await bxCall(env, 'POST', '/v5/order/cancel-all', { category: 'linear', symbol: p.code }); } catch (_) {} } } catch (_) {} }
      else if (op === 'part') { if (!x) throw new Error('Keine offene Position bei Bybit'); const q = bxFloor(bxNum(x.size, 0) * Math.min(1, Math.max(.05, +b.pct || .5)), p.step); if (!(q >= p.min)) throw new Error('Teil zu klein'); await bxCall(env, 'POST', '/v5/order/create', { category: 'linear', symbol: p.code, side: p.dir > 0 ? 'Sell' : 'Buy', orderType: 'Market', qty: bxS(q, p.step), reduceOnly: true, positionIdx: 0 }); ev.push({ title: `🟠 Bybit Demo: ${p.label} teilweise geschlossen`, body: `${q} Stk. verkauft`, sym: p.sym }); p.partQ = (p.partQ || 0) + q; }
      else if (op === 'sl' || op === 'be') { if (!x) throw new Error('Keine offene Position bei Bybit'); takeover(); const want = bxRnd(op === 'be' ? bxNum(x.avgPrice, p.entry) : +b.price, p.tick, -p.dir); await bxCall(env, 'POST', '/v5/position/trading-stop', { category: 'linear', symbol: p.code, stopLoss: bxS(want, p.tick), slTriggerBy: 'LastPrice', tpslMode: 'Full', positionIdx: 0 }); p.sl = want; }
      else if (op === 'tp') { if (!x) throw new Error('Keine offene Position bei Bybit'); takeover(); await bxCancelTPs(env, p); p.tps = (b.tps || []).filter(t => isFinite(+t.p) && +t.pct > 0).slice(0, 3).map(t => ({ p: +t.p, pct: +t.pct })); p.qty0b = bxNum(x.size, 0); p.hits = 0; p.hitsSeen = 0; p.partQ = 0; res.warn = await bxPlaceTPs(env, p, bxNum(x.size, 0)); }
      else throw new Error('Unbekannte Aktion');
    }
  }
  bx.w = now; await bxSave(KV, bx);
  for (const e of ev.slice(0, 3)) await bxPush(env, e.title, e.body, e.sym);
  res.events = ev.map(e => e.title + ' · ' + e.body);
  return res;
}

const bxDay = t => new Intl.DateTimeFormat('sv-SE', { timeZone: 'Europe/Berlin' }).format(new Date(t));
const bxLim = cfg => cfg.dayLim == null ? 3 : cfg.dayLim;
const bxLocked = (cfg, now) => !!(cfg.lock && cfg.lock.d === bxDay(now));
async function bxRun(env, opt = {}) {
  const KV = env.WDESK; if (!KV) return { skip: 'nokv' };
  if (!(env.BYBIT_DEMO_KEY && env.BYBIT_DEMO_SECRET)) return { skip: 'nokey' };
  const now = opt.now || Date.now(), t0run = Date.now();
  const { bx, cfg } = await bxLoad(KV);
  const run = Object.values(cfg.bots).filter(b => b.state === 'run' && b.type === 'elliott');
  if (!run.length && !bx.pos.length) return { skip: 'nobots' };
  // flüchtige Werte (letzter Kurs, nachgezogener Stop – den kennt Bybit selbst) lösen kein Speichern aus
  const sig = () => JSON.stringify(bx, (k, v) => (k === 'lastPx' || k === 'sl' || k === 'w') ? undefined : v);
  const before = sig(), ev = [], res = { pos: [], ent: [] };
  const log = m => { bx.err.unshift({ t: now, m }); if (bx.err.length > 20) bx.err.length = 20; };
  let wal, pl;
  try { wal = await bxCall(env, 'GET', '/v5/account/wallet-balance', { accountType: 'UNIFIED' }); pl = await bxCall(env, 'GET', '/v5/position/list', { category: 'linear', settleCoin: 'USDT', limit: '200' }); }
  catch (e) {
    // Cloudflare lässt Hintergrund-Läufe auch in Ländern laufen, die Bybit sperrt (403) → einzelne Aussetzer sind normal.
    // Sparsam speichern (KV-Limit): Fehlerstand höchstens alle 30 Min., Warnung + Push erst nach 45 Min. ohne Verbindung.
    res.err = e.message; const is403 = /HTTP 403/.test(e.message); let dirty = false;
    if (!bx.failT || now - bx.failT > 30 * 60e3) { bx.failT = now; bx.failMsg = e.message; dirty = true; }
    if (!is403 && bx.lastErr !== e.message) { bx.lastErr = e.message; log('Bybit: ' + e.message); dirty = true; }
    if (bx.okT && now - bx.okT > 45 * 60e3 && !bx.failPushed) { bx.failPushed = true; dirty = true; await bxPush(env, '⚠️ Server erreicht Bybit nicht', `Seit ${Math.round((now - bx.okT) / 60e3)} Min. keine Verbindung (${is403 ? 'Rechenzentrum von Bybit gesperrt' : e.message}). Stop und Ziele liegen weiter bei Bybit.`, null); }
    if (dirty) await bxSave(KV, bx);
    return res;
  }
  if (bx.lastErr) bx.lastErr = null;
  if (bx.failPushed) { bx.failPushed = false; await bxPush(env, '✅ Server erreicht Bybit wieder', 'Die Bybit-Bots laufen weiter.', null); }
  if (!bx.okT || now - bx.okT > 30 * 60e3) bx.okT = now;
  const acc = (wal.list || [])[0] || {}, equity = bxNum(acc.totalEquity, 0); res.equity = equity;
  // Tagesverlust-Grenze: Startguthaben je Tag (Berliner Zeit) merken, bei Überschreiten alles sperren bis Mitternacht
  { const dk = bxDay(now); let cdirty = false;
    if (!bx.day || bx.day.d !== dk) {
      if (cfg.lock && cfg.lock.d !== dk) { cfg.lock = null; Object.values(cfg.bots).forEach(o => { o.resumeT = now; }); cdirty = true; ev.push({ title: '✅ Neuer Handelstag', body: 'Tagesverlust-Grenze zurückgesetzt · Bybit-Bots laufen wieder', sym: null }); }
      bx.day = { d: dk, eq0: equity };
    }
    const lim = bxLim(cfg), loss = bx.day.eq0 > 0 ? (bx.day.eq0 - equity) / bx.day.eq0 * 100 : 0; res.dayLoss = loss;
    if (lim > 0 && !cfg.lock && cfg.lockSkip !== dk && loss >= lim) {
      cfg.lock = { t: now, d: dk, loss: +loss.toFixed(2), eq0: bx.day.eq0, eq: equity }; cfg.kill = now; cdirty = true;
      ev.push({ title: `🛑 Tagesverlust-Grenze erreicht (−${loss.toFixed(1).replace('.', ',')} %)`, body: `${bxMoney(equity - bx.day.eq0)} heute · Bybit-Bots gestoppt und Bot-Positionen geschlossen · keine neuen Handorders bis Mitternacht`, sym: null });
    }
    if (cdirty) await KV.put('bxcfg', JSON.stringify(cfg)); }
  const bpos = {}; (pl.list || []).forEach(x => { if (bxNum(x.size, 0) > 0) bpos[x.symbol] = x; });
  const pref = 'bybit';
  // 1) laufende Positionen: ausgeführt? geschlossen? Stop nachziehen? Bot gestoppt / Not-Aus?
  for (const p of [...bx.pos]) {
    if (p.mode === 'spot') { try { await bxSpotRun(env, bx, p, now, ev, log); } catch (e) { log(`${p.label}: ${e.message}`); } continue; }
    const x = bpos[p.code], sz = x ? bxNum(x.size, 0) : 0, c = cfg.bots[p.bot], hand = p.kind === 'hand';
    try {
      if (!p.filled && hand) { // Limit-/Stop-Order von Hand: warten, bis Bybit füllt oder storniert
        if (sz > 0) { p.filled = true; p.entry = bxNum(x.avgPrice, p.entry); p.t0 = now; ev.push({ title: `🟠 Bybit Demo: ${p.label} ${p.dir > 0 ? 'Long' : 'Short'} ausgeführt`, body: `@ ${deNum(p.entry)} · Stop ${deNum(p.sl)}`, sym: p.sym }); (await bxPlaceTPs(env, p, sz)).forEach(m => log(`${p.label}: ${m}`)); }
        else { const o = await bxOrderStatus(env, 'linear', p.code, 'wh' + p.id); const st = o && o.orderStatus; if (st === 'Cancelled' || st === 'Rejected' || st === 'Deactivated') { bx.pos = bx.pos.filter(q => q !== p); ev.push({ title: `🟠 Bybit Demo: Order ${p.label} storniert`, body: st, sym: p.sym }); } }
        continue;
      }
      if (!p.filled) {
        if (sz > 0) { p.filled = true; p.entry = bxNum(x.avgPrice, p.entry); }
        else { if (now - p.t0 > 3 * 60e3) { bx.pos = bx.pos.filter(q => q !== p); log(`${p.label}: Einstieg wurde bei Bybit nicht ausgeführt`); } continue; }
      }
      if (sz <= 0) { if (await bxBook(env, bx, p, now, ev)) { try { await bxCall(env, 'POST', '/v5/order/cancel-all', { category: 'linear', symbol: p.code }); } catch (_) {} } continue; }
      const kill = !hand && cfg.kill && cfg.kill > p.t0;
      if ((!hand && (!c || c.state !== 'run')) || kill || p.close) { await bxClose(env, p, x, p.close || (kill ? 'Not-Aus' : 'Bot gestoppt')); continue; }
      const m = await bxManage(env, p, x, now, pref);
      if (m === 'be') { p.hitsSeen = p.hits; ev.push({ title: `🟠 Bybit Demo: ${p.label}`, body: `Ziel 1 erreicht · Stop auf Einstand ${deNum(p.sl)}`, sym: p.sym }); }
      else if (hand && (p.hits || 0) > (p.hitsSeen || 0)) { p.hitsSeen = p.hits; ev.push({ title: `🟠 Bybit Demo: ${p.label} Ziel ${p.hits} erreicht`, body: `Rest ${deNum(sz)} Stk. läuft weiter`, sym: p.sym }); }
      res.pos.push({ sym: p.sym, dir: p.dir, size: sz, upnl: bxNum(x.unrealisedPnl, 0) });
    } catch (e) { log(`${p.label}: ${e.message}`); }
  }
  // 2) neue Signale der Bybit-Bots (Code aus der App, nur kurz nach Kerzenschluss der jeweiligen Zeiteinheit)
  const syms = [...new Set(run.map(b => b.key.slice(8)))];
  for (const y of syms) {
    const code = cfg.map[y]; if (!code) continue;
    const bots = run.filter(b => b.key.slice(8) === y && !bxPaused(bx, cfg, b.id) && !(cfg.kill && !(cfg.bots[b.id].resumeT > cfg.kill)));
    if (!bots.length) continue;
    const TFM = { '15m': 9e5, '1h': 36e5, '4h': 144e5, '1D': 864e5 }, need = new Set();
    // Prüffenster nach Kerzenschluss: ganze 15m-Kerze bzw. 30 Min. – fällt ein Lauf aus (403), klappt es im nächsten (st.lastT verhindert Doppel-Einstiege)
    bots.forEach(b => (b.tfs || []).forEach(tf => { const ms = TFM[tf]; if (!ms) return; const st = (bx.bots[b.id] || {}).st || {}; if (!st[tf] || !st[tf].lastT || now - Math.floor(now / ms) * ms < Math.min(ms, 30 * 60e3)) need.add(tf); }));
    if (!need.size) continue;
    try {
      const m1 = await klines(code, '1m', 3, pref); if (m1.err) throw new Error(m1.err);
      const lb = m1.bars.filter(b => b.t + 60e3 <= now).pop() || m1.bars[m1.bars.length - 1];
      const tfData = {}; for (const tf of need) { const r = await klines(code, tf, 1000, pref); if (!r.err) tfData[tf] = { bars: r.bars, ts: now, sym: y }; }
      const copies = bots.map(b => ({ ...JSON.parse(JSON.stringify(b)), st: JSON.parse(JSON.stringify((bx.bots[b.id] || {}).st || {})) }));
      const acct = { bal: equity, fee: BX_FEE, pos: [...bx.pos], ord: [], hist: [], bots: copies };
      const E = makeEngine({ acct, data: {}, notify: () => {} });
      E.S.sym = y; E.S.tf = '1m'; E.S.bars = [{ ...lb }]; E.S.tfData = tfData;
      const ids = new Set(acct.pos.map(p => p.id));
      E.eBotTick(false);
      copies.forEach(b => { const s = bx.bots[b.id] || (bx.bots[b.id] = {}); s.st = b.st; });
      // Signalwechsel: Bot hat eine Position geschlossen
      for (const p of bx.pos.filter(p => p.sym === y && !acct.pos.includes(p))) {
        p.close = 'Signalwechsel';
        try { await bxClose(env, p, bpos[p.code], 'Signalwechsel'); if (await bxBook(env, bx, p, now, ev)) delete bpos[p.code]; } catch (e) { log(`${p.label}: Schließen fehlgeschlagen – ${e.message}`); }
      }
      for (const np of acct.pos.filter(p => !ids.has(p.id))) {
        const bt = copies.find(b => b.id === np.bot), st = bt && bt.st[np.btf], tg = st && st.last ? st.last.replace(/ eröffnet @.*/, '') : (np.label);
        np.sym = y;
        if (bpos[code] || bx.pos.some(p => p.code === code && p.mode !== 'spot' && !p.close)) { if (st) st.last = tg + ' – übersprungen (Bybit: schon eine Position auf dem Paar)'; continue; }
        if (bx.pos.filter(p => !p.close && p.mode !== 'spot').length >= BX_POS_MAX) { if (st) st.last = tg + ` – übersprungen (max. ${BX_POS_MAX} Bybit-Positionen)`; continue; }
        try {
          const errs = await bxOpen(env, np, code, now); bx.pos.push(np); res.ent.push(y);
          if (st) st.last = `${tg} eröffnet @ ${deNum(np.entry)} (Bybit)`;
          ev.push({ title: `🟠 Bybit Demo: ${np.label} ${np.dir > 0 ? 'Long' : 'Short'} eröffnet`, body: `@ ${deNum(np.entry)} · ${np.qty0b} Stk. · Hebel ${np.levB}× · Stop ${deNum(np.sl)}${np.tps.length ? ' · Ziel ' + deNum(np.tps[0].p) : ''}`, sym: y });
          errs.forEach(m => log(`${np.label}: ${m}`));
        } catch (e) {
          bxPause(bx, np.bot, e.message, now); if (st) st.last = tg + ' – Order fehlgeschlagen';
          log(`${np.label}: Order fehlgeschlagen – ${e.message}`);
          ev.push({ title: `⚠️ Bybit Demo: Order fehlgeschlagen`, body: `${np.label}: ${e.message} · Bot pausiert`, sym: y });
        }
      }
    } catch (e) { log(`${y}: ${e.message}`); }
  }
  // Positionen, die gerade geschlossen werden sollen (Signalwechsel), sofort schließen
  for (const p of bx.pos.filter(p => p.close && !p.closing)) { try { await bxClose(env, p, bpos[p.code], p.close); } catch (e) { log(`${p.label}: Schließen fehlgeschlagen – ${e.message}`); } }
  res.ms = Date.now() - t0run; res.events = ev.map(e => e.title + ' · ' + e.body);
  if (sig() !== before) { bx.w = now; await bxSave(KV, bx); }
  for (const e of ev.slice(0, 6)) await bxPush(env, e.title, e.body, e.sym);
  return res;
}

// ================= 🧠 Claude-Analyse =================
// Die App schickt Kerzen, ihre Auto-Analyse und auf Wunsch ein Chart-Bild; der Server fragt Claude.
// Der Anthropic-Schlüssel liegt nur hier (Secret ANTHROPIC_API_KEY). Claude handelt nie selbst.
const AI_MODELS = { fast: 'claude-haiku-5-5', std: 'claude-sonnet-5-5', deep: 'claude-opus-5-5' };
const AI_SYS = `Du bist ein erfahrener Chartanalyst für Krypto- und TradFi-Perpetuals. Deine Werkzeuge: Elliott-Wellen, Fibonacci und das SK-System (Korrektur-Setup aus den Punkten 0–A–B: Einstieg in der Zone um 0,618 der Bewegung 0–A, Stop hinter 0, Ziele 1,0 / 1,272 / 1,6 der Bewegung 0–A ab B).
Du bekommst die letzten Kerzen, die automatische Analyse der App (beste Zählung, Alternative, SK-Setup, Ungültig-Marken, Trend der höheren Zeiteinheit, RSI), Funding/Open Interest und offene Positionen – manchmal auch ein Bild des Charts mit den Zeichnungen des Nutzers.
Bilde dir ein eigenes Urteil; die Auto-Analyse ist ein Hinweis, kein Befehl. Sei ehrlich über Unsicherheit. Wenn kein sauberes Setup da ist, sag „Abwarten“ und warum. Keine Gewinnversprechen.
Antworte auf Deutsch und ausschließlich über das Werkzeug „analyse“ (Zahlen als Zahlen, ohne Tausenderpunkte). Höchstens 3 Szenarien; Stop und Ziele müssen zur Richtung passen. Fasse dich knapp: je Feld wenige Sätze. Bei einer Nachfrage des Nutzers beantworte sie im Feld „kurz“ ausführlicher und passe den Rest an.`;
const AI_TOOL = { name: 'analyse', description: 'Strukturierte Chartanalyse für die App', input_schema: { type: 'object', properties: {
  kurz: { type: 'string', description: '2–3 Sätze Gesamteinschätzung (bei einer Nachfrage: die Antwort darauf)' },
  welle: { type: 'string', description: 'welche Welle wahrscheinlich läuft und warum' },
  alternative: { type: 'string', description: 'wichtigste Alternativzählung und woran man sie erkennt' },
  szenarien: { type: 'array', maxItems: 3, items: { type: 'object', properties: {
    name: { type: 'string' }, richtung: { type: 'string', enum: ['long', 'short', 'abwarten'] }, wahrscheinlichkeit: { type: 'number' },
    einstieg: { type: ['number', 'null'] }, stop: { type: ['number', 'null'] }, ziele: { type: 'array', items: { type: 'number' } }, ungueltig: { type: ['number', 'null'] },
    begruendung: { type: 'string', description: '1–3 Sätze' } }, required: ['name', 'richtung', 'begruendung'] } },
  risiken: { type: 'array', items: { type: 'string' } },
  fazit: { type: 'string', description: 'ein Satz: was würdest du jetzt tun' } }, required: ['kurz', 'welle', 'szenarien', 'fazit'] } };
// Notfall: Antwort kam als Text (evtl. abgeschnitten) – so viel wie möglich herauslesen
function aiParseText(t) {
  const x = String(t || '').replace(/```(?:json)?/gi, '').trim();
  try { const a = x.indexOf('{'), b = x.lastIndexOf('}'); if (a >= 0 && b > a) { const o = JSON.parse(x.slice(a, b + 1)); if (o && (o.kurz || o.szenarien)) return o; } } catch (_) {}
  const f = k => { const m = x.match(new RegExp('"' + k + '"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)')); try { return m ? JSON.parse('"' + m[1] + '"') : null; } catch (_) { return m ? m[1] : null; } };
  const o = { kurz: f('kurz'), welle: f('welle'), alternative: f('alternative'), fazit: f('fazit'), szenarien: [], risiken: [] };
  if (o.kurz || o.welle) return o;
  return { kurz: x.startsWith('{') ? '' : x.slice(0, 4000), szenarien: [], risiken: [] };
}
const aiDay = () => new Date().toISOString().slice(0, 10);
async function aiLoad(KV) { const a = (await KV.get('ai', 'json')) || {}; if (a.day !== aiDay()) { a.day = aiDay(); a.n = 0; } a.limit = a.limit || 20; a.hist = a.hist || []; return a; }
// 🧠 Claude automatisch: kurze Einschätzung nach einem Signal (Schalter + eigenes Tageslimit, je Paar/Zeiteinheit höchstens 1× pro Stunde)
async function aiAuto(env, ev) {
  const KV = env.WDESK; if (!KV || !env.ANTHROPIC_API_KEY || !ev || !ev.sym || !ev.code) return null;
  const a = await aiLoad(KV), au = a.auto || {}; if (!au.on) return null;
  if (au.day !== aiDay()) { au.day = aiDay(); au.n = 0; au.last = {}; }
  au.last = au.last || {}; const k = ev.sym + '|' + (ev.tf || ''), now = Date.now();
  if ((au.n || 0) >= (au.max || 5) || (au.last[k] && now - au.last[k] < 60 * 60e3) || a.n >= a.limit) return null;
  au.n = (au.n || 0) + 1; au.last[k] = now; a.auto = au; await KV.put('ai', JSON.stringify(a));
  let kl = null; try { kl = await klines(ev.code, ev.tf || '1h', 150, 'bybit'); } catch (_) {}
  const bars = kl && kl.bars ? kl.bars : [];
  const ctx = { ereignis: ev.title + (ev.body ? ' · ' + ev.body : ''), kurs: bars.length ? bars[bars.length - 1].c : null, kerzen: bars.map(b => [b.t, b.o, b.h, b.l, b.c]) };
  const r = await aiRun(env, { sym: ev.sym, tf: ev.tf || '1h', model: au.model || 'fast', ctx, auto: ev.title,
    q: `Automatische Kurz-Einschätzung nach diesem Signal der App: „${ev.title}${ev.body ? ' · ' + ev.body : ''}“. Schreib in „kurz“ höchstens 2 Sätze: Ist das Signal tragfähig, und worauf sollte man jetzt achten? Szenarien knapp halten.` });
  if (r && r.ok) {
    const sz = (r.res.szenarien || [])[0], dir = sz && sz.richtung ? ' · ' + sz.richtung + (sz.wahrscheinlichkeit != null ? ' ' + sz.wahrscheinlichkeit + ' %' : '') : '';
    const body = String(r.res.kurz || r.res.welle || '').replace(/\s+/g, ' ').slice(0, 220) + dir;
    await pushAll(env, { title: `🧠 Claude: ${ev.sym.replace(/\/USDT?$/, '')} ${ev.tf || ''}`.trim(), body, tag: 'ai-' + now, nav: { sym: ev.sym, tf: ev.tf || null, tab: 'chart' } }, false);
  }
  return r;
}
async function aiRun(env, b) {
  if (!env.ANTHROPIC_API_KEY) return { error: 'nokey', msg: 'Auf dem Server ist noch kein ANTHROPIC_API_KEY eingetragen' };
  const KV = env.WDESK, a = KV ? await aiLoad(KV) : { n: 0, limit: 20, hist: [] };
  if (a.n >= a.limit) return { error: 'limit', msg: `Tageslimit erreicht (${a.n}/${a.limit}) – morgen wieder oder Limit erhöhen` };
  const model = AI_MODELS[b.model] || AI_MODELS.std;
  const content = [];
  if (b.img && /^data:image\/(jpeg|png);base64,/.test(b.img) && b.img.length < 1.5e6) { const m = b.img.match(/^data:(image\/(?:jpeg|png));base64,(.*)$/); content.push({ type: 'image', source: { type: 'base64', media_type: m[1], data: m[2] } }); }
  let txt = `Paar: ${b.sym} · Zeiteinheit: ${b.tf}\nDaten der App (JSON):\n${JSON.stringify(b.ctx || {}).slice(0, 60000)}`;
  if (b.prev) txt += `\n\nDeine letzte Analyse dazu:\n${JSON.stringify(b.prev).slice(0, 6000)}`;
  txt += b.q ? `\n\nFrage des Nutzers: ${String(b.q).slice(0, 1000)}` : '\n\nBitte analysiere den Chart.';
  content.push({ type: 'text', text: txt });
  let r, j;
  try {
    r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }, body: JSON.stringify({ model, max_tokens: 6000, system: AI_SYS, tools: [AI_TOOL], tool_choice: { type: 'tool', name: 'analyse' }, messages: [{ role: 'user', content }] }) });
    j = await r.json();
  } catch (e) { return { error: 'network', msg: 'Claude nicht erreichbar: ' + (e.message || e) }; }
  if (!r.ok || !j || j.type === 'error') { const m = j && j.error ? j.error.message : 'HTTP ' + r.status; return { error: 'api', msg: (r.status === 401 ? 'Schlüssel ungültig – ' : r.status === 429 ? 'Zu viele Anfragen – ' : /credit|balance/i.test(m) ? 'Kein Guthaben im Anthropic-Konto – ' : '') + m }; }
  const tu = (j.content || []).find(c => c.type === 'tool_use' && c.input);
  let res = tu ? tu.input : aiParseText((j.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n'));
  if (!Array.isArray(res.szenarien)) res.szenarien = []; if (!Array.isArray(res.risiken)) res.risiken = [];
  if (j.stop_reason === 'max_tokens') res.cut = true;
  if (!res.kurz && !res.welle && !res.szenarien.length) return { error: 'leer', msg: 'Claude hat keine lesbare Antwort geliefert – bitte nochmal versuchen' };
  const usage = j.usage || {};
  a.n++; const h = { t: Date.now(), sym: b.sym, tf: b.tf, model: b.model || 'std', q: b.auto ? '⚡ Auto: ' + String(b.auto).slice(0, 120) : (b.q || null), auto: !!b.auto, res, px: b.ctx && b.ctx.kurs, usage: { in: usage.input_tokens || 0, out: usage.output_tokens || 0 } };
  a.hist.unshift(h); if (a.hist.length > 20) a.hist.length = 20;
  if (KV) await KV.put('ai', JSON.stringify(a));
  return { ok: true, res, usage: h.usage, model, n: a.n, limit: a.limit, t: h.t };
}

// Bybit sperrt manche Cloudflare-Standorte (HTTP 403). Darum laufen alle
// Bybit-Aufrufe über einen kleinen Baustein, der fest in Westeuropa steht.
async function bxFetch(env, url, init) {
  if (env.BYEU) {
    try {
      const stub = env.BYEU.get(env.BYEU.idFromName('eu1'), { locationHint: 'weur' });
      const r = await stub.fetch('https://eu/proxy', { method: 'POST', body: JSON.stringify({ url, init }) });
      const j = await r.json();
      if (j && j.ok) { BXVIA.eu = j.colo || 'eu'; return { status: j.status, txt: j.txt }; }
    } catch (_) {}
  }
  BXVIA.eu = null;
  const r = await fetch(url, init); return { status: r.status, txt: await r.text() };
}
const BXVIA = { eu: null };
export class BybitEU {
  constructor(state, env) { this.state = state; this.colo = null; }
  async fetch(req) {
    try {
      const { url, init } = await req.json();
      if (!/^https:\/\/(api(-demo)?\.bybit\.com|data-api\.binance\.vision|api\.binance\.com|www\.okx\.com)\//.test(url)) return Response.json({ ok: false, error: 'url' });
      const r = await fetch(url, init); const txt = await r.text();
      if (!this.colo) { try { const t = await (await fetch('https://www.cloudflare.com/cdn-cgi/trace')).text(); this.colo = (t.match(/colo=(\w+)/) || [])[1] || 'eu'; } catch (_) { this.colo = 'eu'; } }
      return Response.json({ ok: true, status: r.status, txt, colo: this.colo });
    } catch (e) { return Response.json({ ok: false, error: String(e && e.message || e) }); }
  }
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
  try { const x = await bxFetch(env, url, init); r = { status: x.status }; txt = x.txt; }
  catch (e) { return { status: 502, body: { error: 'network', msg: 'Bybit nicht erreichbar: ' + e.message } }; }
  let body;
  try { body = JSON.parse(txt); } catch (_) { body = { error: 'http', msg: `Bybit antwortet mit HTTP ${r.status}` + (r.status === 403 ? ' (Zugriff aus diesem Land/Rechenzentrum gesperrt?)' : ''), raw: txt.slice(0, 200) }; }
  return { status: 200, body };
}

// 📈 Wochenbericht als Mitteilung: sonntags ab 18 Uhr (deutsche Zeit), auch wenn die App zu ist
async function repRun(env, opt = {}) {
  const KV = env.WDESK; if (!KV) return null; const now = opt.now || Date.now();
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Berlin', weekday: 'short', hour: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(now)).map(x => [x.type, x.value]));
  if (p.weekday !== 'Sun' || +p.hour < 18) return null;
  const wk = bxDay(now); const last = await KV.get('repn'); if (last === wk) return null;
  await KV.put('repn', wk);
  const snap = await KV.get('snap', 'json'); const acct = snap && snap.data ? jp(snap.data.wdesk_acct) : null;
  const L = (acct && Array.isArray(acct.hist) ? acct.hist : []).filter(t => !t.replay && t.t1 >= now - 7 * 864e5);
  if (!L.length) return { n: 0 };
  const part = (A, nm) => { if (!A.length) return null; const w = A.filter(t => t.R > 0).length, pnl = A.reduce((a, t) => a + (t.pnl || 0), 0), sR = A.reduce((a, t) => a + (t.R || 0), 0);
    return `${nm}: ${A.length} Trade${A.length > 1 ? 's' : ''} · ${Math.round(w / A.length * 100)} % Treffer · ${bxMoney(pnl)} (${sR >= 0 ? '+' : ''}${sR.toFixed(1).replace('.', ',')} R)`; };
  const body = [part(L.filter(t => t.ex !== 'bybit'), 'Spielgeld'), part(L.filter(t => t.ex === 'bybit'), '🟠 Bybit')].filter(Boolean).join(' · ') + ' – antippen für Details';
  await pushAll(env, { title: '📈 Dein Wochenbericht', body, tag: 'rep-' + wk, nav: { act: 'rep' } }, false);
  return { n: L.length };
}

export default {
  async scheduled(event, env, ctx) { KENV = env; ctx.waitUntil(Promise.all([watchRun(env).catch(() => null), engRun(env).catch(() => null), bxRun(env).catch(() => null), repRun(env).catch(() => null)])); },
  async fetch(req, env) {
    KENV = env;
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
        return json(h, { ok: true, token: await makeToken(env, 720), hours: 720, demo: !!(env.BYBIT_DEMO_KEY && env.BYBIT_DEMO_SECRET), live: !!(env.BYBIT_KEY && env.BYBIT_SECRET) });
      }

      // Ab hier nur mit gültigem Token
      const tok = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
      if (!(await checkToken(env, tok))) return json(h, { error: 'auth', msg: 'Anmeldung abgelaufen – bitte neu entsperren' }, 401);

      // ---- Geräte-Abgleich (Cloudflare KV, Binding-Name WDESK) ----
      if (url.pathname.startsWith('/sync')) {
        const KV = env.WDESK;
        if (!KV) return json(h, { error: 'nokv', msg: 'Speicher fehlt: in Cloudflare unter Bindings einen KV-Namespace mit dem Namen WDESK verbinden' }, 400);
        const head = (await KV.get('head', 'json')) || { v: 0, t: 0, dev: null, name: null, lead: null };
        if (url.pathname === '/sync/head') return json(h, head);
        if (url.pathname === '/sync' && req.method === 'GET') {
          const snap = (await KV.get('snap', 'json')) || { v: 0, data: null };
          return json(h, { head, data: snap.data, v: snap.v });
        }
        const b = await req.json().catch(() => ({}));
        if (url.pathname === '/sync/lead' && req.method === 'POST') {
          head.lead = { id: String(b.dev || ''), name: String(b.name || ''), t: Date.now() };
          await KV.put('head', JSON.stringify(head));
          return json(h, head);
        }
        if (url.pathname === '/sync' && req.method === 'POST') {
          if (b.base !== head.v && !b.force) return json(h, { error: 'conflict', msg: 'Neuerer Stand auf dem Server', head }, 409);
          if (!b.data || typeof b.data !== 'object') return json(h, { error: 'bad', msg: 'Keine Daten' }, 400);
          const v = head.v + 1, t = Date.now();
          await KV.put('snap', JSON.stringify({ v, data: b.data }));
          const nh = { v, t, dev: String(b.dev || ''), name: String(b.name || ''), lead: b.force ? { id: String(b.dev || ''), name: String(b.name || ''), t } : head.lead };
          await KV.put('head', JSON.stringify(nh));
          return json(h, nh);
        }
        return json(h, { error: 'notfound' }, 404);
      }

      // ---- Push vom Server ----
      if (url.pathname.startsWith('/push') || url.pathname === '/watch') {
        const KV = env.WDESK;
        if (!KV) return json(h, { error: 'nokv', msg: 'Speicher fehlt: KV-Namespace WDESK verbinden' }, 400);
        const j = vapidJwk(env);
        if (url.pathname === '/push/key') return j ? json(h, { pub: b64u(vapidPub(j)) }) : json(h, { error: 'novapid', msg: 'VAPID_JWK fehlt in Cloudflare' }, 400);
        if (url.pathname === '/watch' && req.method === 'GET') return json(h, { sent: (await KV.get('sent', 'json')) || {}, watch: (await KV.get('watch', 'json')) || null });
        const b = await req.json().catch(() => ({}));
        if (url.pathname === '/push/sub') {
          if (!b.sub || !b.sub.endpoint || !b.sub.keys) return json(h, { error: 'bad', msg: 'Ungültiges Abo' }, 400);
          const subs = ((await KV.get('subs', 'json')) || []).filter(s => s.endpoint !== b.sub.endpoint && s.dev !== b.dev);
          subs.push({ endpoint: b.sub.endpoint, keys: b.sub.keys, dev: String(b.dev || ''), name: String(b.name || ''), t: Date.now() });
          await KV.put('subs', JSON.stringify(subs.slice(-6)));
          return json(h, { ok: true, n: subs.length });
        }
        if (url.pathname === '/push/unsub') { const subs = ((await KV.get('subs', 'json')) || []).filter(s => s.dev !== b.dev); await KV.put('subs', JSON.stringify(subs)); return json(h, { ok: true }); }
        if (url.pathname === '/push/test') { if (!j) return json(h, { error: 'novapid', msg: 'VAPID_JWK fehlt in Cloudflare' }, 400); return json(h, await pushAll(env, { title: '📲 Wellen-Desk', body: 'Push vom Server funktioniert ✅', tag: 'test' }, false)); }
        if (url.pathname === '/push/alive') { const a = (await KV.get('alive', 'json')) || {}; a[String(b.dev || '')] = b.on === false ? 0 : Date.now(); await KV.put('alive', JSON.stringify(a)); return json(h, { ok: true }); }
        if (url.pathname === '/watch' && req.method === 'POST') { const items = Array.isArray(b.items) ? b.items.slice(0, 200) : []; await KV.put('watch', JSON.stringify({ t: Date.now(), dev: String(b.dev || ''), items })); return json(h, { ok: true, n: items.length }); }
        if (url.pathname === '/push/run') return json(h, await watchRun(env));
        if (url.pathname === '/push/diag') {
          const subs = (await KV.get('subs', 'json')) || [], w = (await KV.get('watch', 'json')) || { items: [] }, sent = (await KV.get('sent', 'json')) || {}, alive = (await KV.get('alive', 'json')) || {};
          const open = (w.items || []).filter(x => !sent[x.id]), syms = [...new Set(open.map(x => x.sym))].slice(0, 12), px = {};
          await Promise.all(syms.map(async s2 => { px[s2] = await hiLo(s2); }));
          return json(h, { version: VERSION, colo: (req.cf && req.cf.colo) || null, country: (req.cf && req.cf.country) || null, vapid: !!j,
            subs: subs.map(s2 => ({ name: s2.name, dev: s2.dev, host: (() => { try { return new URL(s2.endpoint).host; } catch (_) { return '?'; } })(), t: s2.t })),
            alive, watch: { t: w.t || null, n: (w.items || []).length, open: open.length }, sent: Object.keys(sent).length,
            prices: px, wouldHit: open.filter(x => px[x.sym] && !px[x.sym].err && (x.cond === 'above' ? px[x.sym].h >= x.p : px[x.sym].l <= x.p)).map(x => x.title) });
        }
        return json(h, { error: 'notfound' }, 404);
      }

      // ---- 🧠 Claude-Analyse ----
      if (url.pathname === '/ai/run' && req.method === 'POST') { const b = await req.json().catch(() => ({})); const r = await aiRun(env, b); return json(h, r, r.error ? 400 : 200); }
      if (url.pathname === '/ai/auto' && req.method === 'POST') { const b = await req.json().catch(() => ({})); const r = await aiAuto(env, b); return json(h, r || { ok: false, skip: true }); }
      if (url.pathname === '/ai/state' && req.method === 'POST') {
        const b = await req.json().catch(() => ({})); const KV = env.WDESK; const a = KV ? await aiLoad(KV) : { n: 0, limit: 20, hist: [] };
        if (b.limit != null && KV) { a.limit = Math.max(1, Math.min(200, Math.round(+b.limit) || 20)); await KV.put('ai', JSON.stringify(a)); }
        if (b.auto && KV) { const au = a.auto || {}; if (b.auto.on != null) au.on = !!b.auto.on; if (b.auto.max != null) au.max = Math.max(1, Math.min(30, Math.round(+b.auto.max) || 5)); if (b.auto.model && AI_MODELS[b.auto.model]) au.model = b.auto.model; a.auto = au; await KV.put('ai', JSON.stringify(a)); }
        const au = a.auto || {}; return json(h, { ok: true, key: !!env.ANTHROPIC_API_KEY, n: a.n, limit: a.limit, hist: a.hist, auto: { on: !!au.on, max: au.max || 5, model: au.model || 'fast', n: au.day === aiDay() ? au.n || 0 : 0 } });
      }

      // ---- 🟠 Bybit-Demo-Bots ----
      if (url.pathname.startsWith('/bx/') && req.method === 'POST') {
        const KV = env.WDESK; if (!KV) return json(h, { error: 'nokv', msg: 'Speicher (KV) fehlt' }, 400);
        const b = await req.json().catch(() => ({})), op = url.pathname.slice(4);
        const cfg = (await KV.get('bxcfg', 'json')) || { bots: {}, map: {} }; cfg.bots = cfg.bots || {}; cfg.map = cfg.map || {};
        const saveCfg = () => KV.put('bxcfg', JSON.stringify(cfg));
        if (op === 'cfg') { // App meldet ihre Bybit-Bots (ohne Rechenstand)
          const nb = {}; (b.bots || []).forEach(x => { if (x && x.id != null && x.ex === 'bybit') { const o = cfg.bots[x.id] || {}; nb[x.id] = { id: x.id, type: x.type, key: x.key, label: x.label, ex: 'bybit', state: x.state, tfs: x.tfs, waves: x.waves, dir: x.dir, risk: x.risk, riskUsd: x.riskUsd || 0, lev: x.lev, tp: x.tp, htf: x.htf, dev: x.dev || 0, skipFirst: x.skipFirst, trades: 0, pnl: 0, inv: 0, cyc: 0, t0: x.t0, resumeT: o.resumeT || 0 }; } });
          Object.values(cfg.bots).forEach(o => { if (!nb[o.id]) nb[o.id] = { ...o, state: 'stopped' }; });
          cfg.bots = nb; Object.assign(cfg.map, b.map || {}); await saveCfg();
        } else if (op === 'stop') { const o = cfg.bots[b.id]; if (o) { o.state = 'stopped'; await saveCfg(); } }
        else if (op === 'resume') { const o = cfg.bots[b.id]; if (o) { o.resumeT = Date.now(); await saveCfg(); } }
        else if (op === 'kill') { cfg.kill = Date.now(); await saveCfg(); }
        else if (op === 'unkill') { const t = Date.now(); Object.values(cfg.bots).forEach(o => { o.resumeT = t; }); if (cfg.lock) { cfg.lockSkip = cfg.lock.d; cfg.lock = null; } await saveCfg(); }
        else if (op === 'daylim') { const v = +b.pct; cfg.dayLim = isFinite(v) ? Math.max(0, Math.min(50, v)) : 3; await saveCfg(); }
        else if (op === 'hand') { try { const r = await bxHand(env, b); const { bx } = await bxLoad(KV); return json(h, { ...r, hist: bx.hist.slice(0, 100) }); } catch (e) { return json(h, { error: 'bybit', msg: e.message }, 400); } }
        else if (op !== 'state') return json(h, { error: 'notfound' }, 404);
        let ran = null; if (op !== 'state' && op !== 'resume' && op !== 'hand') ran = await bxRun(env).catch(e => ({ err: String(e.message || e) }));
        const cfgN = ran ? ((await KV.get('bxcfg', 'json')) || cfg) : cfg;
        const { bx } = await bxLoad(KV); { const d = await bxDead(KV); bx.pos = bx.pos.filter(q => !(q.id != null && d[q.id])); } const out = { ok: true, key: !!(env.BYBIT_DEMO_KEY && env.BYBIT_DEMO_SECRET), ran, kill: cfgN.kill || 0, bots: {}, pos: [], hist: bx.hist.slice(0, 100), err: bx.err.filter(e => !/HTTP 403/.test(e.m)).slice(0, 10), w: bx.w || null, via: BXVIA.eu, day: { eq0: bx.day && bx.day.d === bxDay(Date.now()) ? bx.day.eq0 : null, lim: bxLim(cfgN), lock: bxLocked(cfgN, Date.now()) ? cfgN.lock : null },
          conn: { okT: bx.okT || null, failT: bx.failT || null, failMsg: bx.failMsg || null, down: !!bx.failPushed },
          hand: bx.pos.filter(p => p.kind === 'hand').map(p => ({ id: p.id, mode: p.mode, sym: p.sym, code: p.code, label: p.label, base: p.base, dir: p.dir, type: p.type, filled: !!p.filled, entry: p.entry, sl: p.sl, tps: p.tps.map(t => ({ p: t.pb || t.p, pct: t.pct, hit: !!t.hit })), hits: p.hits || 0, qty: p.qtyNet || p.qty0b || p.qtyAsk, lev: p.levB || null, be: p.be, trail: p.trail, lastPx: p.lastPx || null, t0: p.t0 })) };
        Object.keys(bx.bots).forEach(id => { out.bots[id] = { ...bx.bots[id], paused: bxPaused(bx, cfg, id) ? bx.bots[id].paused : null }; });
        if (out.key) {
          try {
            const wal = await bxCall(env, 'GET', '/v5/account/wallet-balance', { accountType: 'UNIFIED' }); const a = (wal.list || [])[0] || {}; out.equity = bxNum(a.totalEquity, null); out.avail = bxNum(a.totalAvailableBalance, null);
            const pl = await bxCall(env, 'GET', '/v5/position/list', { category: 'linear', settleCoin: 'USDT', limit: '200' }); const L = (pl.list || []).filter(x => bxNum(x.size, 0) > 0);
            out.pos = L.map(x => { const p = bx.pos.find(q => q.code === x.symbol && q.mode !== 'spot'); return { code: x.symbol, sym: p ? p.sym : x.symbol, bot: p ? p.bot : null, label: p ? p.label : x.symbol + ' (nicht aus der App)', hand: !!(p && p.kind === 'hand'), manual: !!(p && p.manual), id: p ? p.id : null, dir: x.side === 'Buy' ? 1 : -1, size: bxNum(x.size, 0), entry: bxNum(x.avgPrice, 0), mark: bxNum(x.markPrice, 0), sl: bxNum(x.stopLoss, 0) || null, upnl: bxNum(x.unrealisedPnl, 0), lev: bxNum(x.leverage, 0), tps: p ? p.tps.filter(t => !t.skip).map(t => t.pb || t.p) : [], hits: p ? p.hits || 0 : 0, wave: p ? p.wave : null, tf: p ? p.btf : null }; });
          } catch (e) { out.bybitErr = e.message; }
        }
        return json(h, out);
      }

      // ---- ☁️ Server-Bots ----
      if (url.pathname === '/eng/run' && req.method === 'POST') { const b = await req.json().catch(() => ({})); return json(h, await engRun(env, { dry: b.dry !== false })); }
      if (url.pathname === '/eng') return json(h, (env.WDESK && await env.WDESK.get('eng', 'json')) || {});

      if (url.pathname === '/status')
        return json(h, { ok: true, version: VERSION, demo: !!(env.BYBIT_DEMO_KEY && env.BYBIT_DEMO_SECRET), live: !!(env.BYBIT_KEY && env.BYBIT_SECRET), colo: (req.cf && req.cf.colo) || null, eu: !!env.BYEU });

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
