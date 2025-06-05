// sw.js
const cacheName = 'recipes-cache-v1';
const assetsToCache = [
  '/',
  '/static/manifest.json'
  // Add other assets (CSS, JS, images) as needed
];

self.addEventListener('install', event => {
  console.log('Service Worker installing.');
  event.waitUntil(
    caches.open(cacheName)
      .then(cache => {
        console.log('Caching assets');
        return cache.addAll(assetsToCache);
      })
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Return cached asset if available; otherwise fetch from network.
        return response || fetch(event.request);
      })
  );
});
