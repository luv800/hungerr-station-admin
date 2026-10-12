// Service worker: keeps the admin panel installable and shows order alerts even when the panel is closed.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => { if (e.request.method === 'GET') e.respondWith(fetch(e.request)); });   // live data is never cached

self.addEventListener('push', e => {
  let d = {}; try { d = e.data.json(); } catch (_) {}
  e.waitUntil(self.registration.showNotification(d.title || 'Hungerr Station', {
    body: d.body || 'Order update', icon: '/icons/admin-192.png', badge: '/icons/admin-192.png',
    tag: d.tag || undefined, renotify: !!d.tag, vibrate: [200, 100, 200, 100, 200],
    requireInteraction: d.kind === 'new', data: { url: '/admin' }
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(l => {
    const c = l.find(x => x.url.includes('/admin'));
    return c ? c.focus() : self.clients.openWindow('/admin');
  }));
});
