// Wellen-Desk Service Worker: App offline verfügbar, Kursdaten immer live
const CACHE = 'wellen-desk-v75';
const SHELL = ['./', './index.html', './manifest.json', './icon-192.png', './icon-512.png', './icon-maskable.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL))); self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE && k !== 'wd-diag').map(k => caches.delete(k))))); self.clients.claim(); });
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin || e.request.method !== 'GET') return; // Binance & Co. nie cachen
  if (u.pathname.endsWith('/calendar.json')) return; // Kalender immer frisch, nicht cachen
  e.respondWith(fetch(e.request).then(r => { const c = r.clone(); caches.open(CACHE).then(x => x.put(e.request, c)); return r; })
    .catch(() => caches.match(e.request).then(r => r || caches.match('./index.html'))));
});
// Tippen auf eine Meldung öffnet die App
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const nav = (e.notification.data && e.notification.data.nav) || null;
  const msg = nav ? { type: 'wd-nav', nav, title: e.notification.title || '', t: Date.now() } : null;
  // Ziel merken, falls die App erst startet oder neu lädt
  const keep = msg ? caches.open('wd-diag').then(c => c.put('./__nav', new Response(JSON.stringify(msg)))).catch(() => {}) : Promise.resolve();
  e.waitUntil(keep.then(() => self.clients.matchAll({ type: 'window', includeUncontrolled: true })).then(cs => {
    for (const c of cs) if ('focus' in c) { if (msg) { try { c.postMessage(msg); } catch (_) {} } return c.focus(); }
    return self.clients.openWindow('./' + (msg ? '#nav=' + encodeURIComponent(JSON.stringify(nav)) : ''));
  }));
});
// Push vom eigenen Server (auch wenn die App geschlossen ist)
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { title: 'Wellen-Desk', body: e.data ? e.data.text() : '' }; }
  const show = self.registration.showNotification(d.title || 'Wellen-Desk', { body: d.body || '', tag: d.tag || undefined, icon: 'icon-192.png', badge: 'icon-192.png', data: { nav: d.nav || null } });
  // Für die Diagnose merken: wann kam zuletzt ein Push an?
  const log = caches.open('wd-diag').then(c => c.put('./__lastpush', new Response(JSON.stringify({ t: Date.now(), title: d.title || '' })))).catch(() => {});
  e.waitUntil(Promise.all([show, log]));
});
