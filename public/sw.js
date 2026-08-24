const CACHE_NAME = "privchat-public-v2";
const PUBLIC_ASSETS = ["/manifest.webmanifest", "/favicon.svg", "/og.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(PUBLIC_ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))),
    ),
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== self.location.origin) return;

  // Söhbət, admin, sənəd və dinamik cavablar cihaz keşinə heç vaxt yazılmır.
  if (
    event.request.mode === "navigate" ||
    event.request.destination === "document" ||
    url.pathname.startsWith("/chat") ||
    url.pathname.startsWith("/admin") ||
    url.searchParams.has("_rsc")
  ) {
    return;
  }

  const isImmutableAsset = url.pathname.startsWith("/_next/static/");
  const isPublicAsset = PUBLIC_ASSETS.includes(url.pathname);
  if (!isImmutableAsset && !isPublicAsset) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((response) => {
        if (response.ok && response.type === "basic") {
          const copy = response.clone();
          event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy)));
        }
        return response;
      });
    }),
  );
});
