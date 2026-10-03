// EventSolutions App — service worker.
// The page is fetched from the network first, so a new version is picked up at
// once – but when the network is slow (over 2 s) the saved copy opens right away
// and the fresh one is saved for the next start.
// Libraries from the CDN are left to the browser's own cache (going through this
// worker they failed to load on some phones: the vote page stayed on „Kraunama…“).
// Data (Supabase) is never cached here.
const CACHE = 'es-app-v202';
const SHELL = ['./', './index.html', './manifest.webmanifest', './icons/icon-192.png', './icons/icon-512.png', './icons/apple-touch-icon.png', './icons/badge-96.png'];

self.addEventListener('install', e=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL)).then(()=>self.skipWaiting()));
});
self.addEventListener('activate', e=>{
  e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});
self.addEventListener('fetch', e=>{
  const req = e.request;
  if(req.method!=='GET') return;
  const url = new URL(req.url);
  if(url.origin!==self.location.origin) return;           // Supabase, CDN, fonts: straight to the network
  if(/\.(apk|exe|part\d+)$|\/EventSolutions-Setup\.json$/i.test(url.pathname)) return;   // app downloads: never cached (and never stored as index.html)
  // other pages (the voting page …): from the network, the saved copy only offline
  if(req.mode==='navigate' && !/\/(index\.html)?$/.test(url.pathname)){
    e.respondWith(fetch(req).then(res=>{ if(res.ok){ const copy = res.clone(); caches.open(CACHE).then(c=>c.put(url.pathname, copy)); } return res; }).catch(()=>caches.match(url.pathname)));
    return;
  }
  if(req.mode==='navigate'){
    const net = fetch(req).then(res=>{
      if(res.ok){ const copy = res.clone(); caches.open(CACHE).then(c=>c.put('./index.html', copy)); }
      return res;
    });
    e.waitUntil(net.catch(()=>{}));
    e.respondWith(caches.match('./index.html').then(saved=>{
      if(!saved) return net;
      return Promise.race([net.catch(()=>saved), new Promise(r=>setTimeout(()=>r(saved), 2000))]);
    }));
    return;
  }
  e.respondWith(caches.match(req).then(hit=>hit || fetch(req).then(res=>{
    if(res.ok){ const copy = res.clone(); caches.open(CACHE).then(c=>c.put(req, copy)); }
    return res;
  })));
});

// Pranešimai (push). Kai programa atidaryta ir matoma, pranešimą parodo pati
// programa, todėl čia jo nekartojame. iPhone reikalauja kiekvieną push
// parodyti, tad ten rodome visada.
const IOS = /iPhone|iPad|iPod/.test(self.navigator.userAgent||'');
// the small icon in the phone's status bar must be a white silhouette on transparent (otherwise a white square);
// on a phone the notification shows only the app icon, no big picture on the right
const PHONE = /android|iphone|ipad|ipod/i.test(self.navigator.userAgent || '');
const NOTE_ICONS = PHONE ? { badge: 'icons/badge-96.png' } : { icon: 'icons/icon-192.png', badge: 'icons/badge-96.png' };
self.addEventListener('push', e=>{
  let d = {};
  try{ d = e.data ? e.data.json() : {}; }catch(_){ d = {body: e.data ? e.data.text() : ''}; }
  const title = d.title || 'EventSolutions App';
  e.waitUntil(self.clients.matchAll({type:'window', includeUncontrolled:true}).then(list=>{
    if(d.kind!=='dial' && !IOS && list.some(c=>c.visibilityState==='visible')) return;
    const call = d.kind==='call' && d.call_id;
    // „skambinti šiam žmogui“ iš kompiuterio: rodoma net programai esant atidarytai
    if(d.kind==='dial') return self.registration.showNotification(title, {
      body: d.body || '', tag: 'dial', renotify: true, requireInteraction: true,
      ...NOTE_ICONS, vibrate: [300, 150, 300],
      data: {url: d.url || './', kind: 'dial'}, actions: [{action: 'dial', title: '📞 Skambinti'}]
    });
    return self.registration.showNotification(title, Object.assign({
      body: d.body || '', tag: d.tag || 'es', renotify: true,
      ...NOTE_ICONS,
      data: {url: d.url || './', kind: d.kind || '', meet: d.meet || '', call: d.call_id || ''}
    }, call ? {
      // vaizdo skambutis: skamba, kol atsakysi (Priimti -> iškart Google Meet)
      requireInteraction: true, vibrate: [400, 200, 400, 200, 400, 200, 400],
      actions: [{action: 'accept', title: '✅ Priimti'}, {action: 'decline', title: '❌ Atmesti'}]
    } : {}));
  }));
});
self.addEventListener('notificationclick', e=>{
  e.notification.close();
  const nd = e.notification.data || {};
  if(nd.kind==='call' && nd.call && (e.action==='accept' || e.action==='decline')){
    const status = e.action==='accept' ? 'accepted' : 'declined';
    e.waitUntil(self.clients.matchAll({type:'window', includeUncontrolled:true}).then(list=>{
      const c = list.find(x=>x.url.startsWith(self.registration.scope));
      if(status==='declined'){ if(c) c.postMessage({type:'call-answer', call:nd.call, status}); return; }
      // Google Meet: straight into the meeting
      if(/^https:\/\/meet\.google\.com\//.test(nd.meet)){ if(c) c.postMessage({type:'call-answer', call:nd.call, status}); return self.clients.openWindow(nd.meet); }
      // Daily: the call opens inside the app
      if(c){ c.postMessage({type:'call-join', call:nd.call}); return c.focus(); }
      return self.clients.openWindow(new URL('./?call='+encodeURIComponent(nd.call)+'&join=1', self.registration.scope).href);
    }));
    return;
  }
  if(nd.kind==='dial'){
    // the app opens with a big „Skambinti“ button (one tap starts the call)
    const u = new URL(nd.url || './', self.registration.scope), phone = u.searchParams.get('dial'), who = u.searchParams.get('who') || '';
    e.waitUntil(self.clients.matchAll({type:'window', includeUncontrolled:true}).then(list=>{
      const c = list.find(x=>x.url.startsWith(self.registration.scope));
      if(c){ c.postMessage({type:'dial', phone, who}); return c.focus(); }
      return self.clients.openWindow(u.href);
    }));
    return;
  }
  const url = new URL((e.notification.data && e.notification.data.url) || './', self.registration.scope).href;
  const sp = new URL(url).searchParams, chat = sp.get('chat'), thread = sp.get('thread'), meeting = sp.get('meeting'), call = sp.get('call');
  e.waitUntil(self.clients.matchAll({type:'window', includeUncontrolled:true}).then(list=>{
    const c = list.find(x=>x.url.startsWith(self.registration.scope));
    if(c){ if(chat) c.postMessage({type:'open-chat', chat, thread}); if(meeting) c.postMessage({type:'open-meeting', id:meeting}); if(call) c.postMessage({type:'open-call', call});
      if(['task','gear','event','invoice','feedback','leave','admin'].some(k=>sp.get(k))) c.postMessage({type:'open-url', url});
      return c.focus(); }
    return self.clients.openWindow(url);
  }));
});
