/* Service worker: keeps the app shell available offline and caches encrypted content files.
   Content files (c/*.bin) are named by a keyed hash of their contents, so they never change and are
   served cache-first. Shell files are network-first so a new version is picked up when online. */
const VERSION = '6da2f54feb';
const SHELL = 'sq-shell-' + VERSION;
const CONTENT = 'sq-content';
const SHELL_FILES = [
  './', 'index.html', 'app.js?v=' + VERSION, 'styles.css?v=' + VERSION, 'manifest.webmanifest', 'config.json',
  'icons/icon-192.png', 'icons/icon-512.png', 'icons/apple-touch-icon.png',
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(SHELL).then(c => c.addAll(SHELL_FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k.startsWith('sq-shell-') && k !== SHELL).map(k => caches.delete(k))))
      .then(() => self.clients.claim()));
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (/\/c\/[0-9a-f]+\.bin$/.test(url.pathname)) {
    event.respondWith(caches.open(CONTENT).then(async cache => {
      const hit = await cache.match(req);
      if (hit) return hit;
      const res = await fetch(req);
      if (res.ok) cache.put(req, res.clone());
      return res;
    }));
    return;
  }

  event.respondWith(
    fetch(req)
      .then(res => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(SHELL).then(c => c.put(req, copy));
        }
        return res;
      })
      .catch(async () => {
        // offline or a failed update: same file, else the cached copy from the previous version
        const hit = await caches.match(req) || await caches.match(req, {ignoreSearch: true});
        if (hit) return hit;
        if (req.mode === 'navigate') return caches.match('index.html');
        return Response.error();
      }));
});
