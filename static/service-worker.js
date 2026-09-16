const CACHE_NAME = "trainer-app-v51";
const APP_SHELL = [
  "/manifest.webmanifest?v=4",
  "/static/images/settings.png?v=2",
  "/static/images/coach.png?v=2",
  "/static/images/social/instagram.png",
  "/static/images/social/facebook.png",
  "/static/images/social/viber.png",
  "/static/offline.html"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)).catch(() => Promise.resolve())
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  const acceptsHtml = req.headers.get("accept") && req.headers.get("accept").includes("text/html");

  if (req.mode === "navigate" || acceptsHtml) {
    event.respondWith(
      fetch(req, { cache: "no-store" }).catch(() => caches.match("/static/offline.html"))
    );
    return;
  }

  if (url.origin !== self.location.origin) {
    event.respondWith(fetch(req));
    return;
  }

  if (url.pathname.startsWith("/static/") || url.pathname === "/manifest.webmanifest") {
    event.respondWith(
      caches.match(req).then((cached) => {
        if (cached) return cached;
        return fetch(req).then((res) => {
          const clone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, clone)).catch(() => {});
          return res;
        });
      })
    );
    return;
  }

  event.respondWith(
    fetch(req).catch(() => caches.match(req))
  );
});
