'use strict';
// What the page sees of the desktop app: window.esDesktop (only on the app's own site)
const { contextBridge, ipcRenderer } = require('electron');

const argOf = (k) => { const a = process.argv.find((x) => x.startsWith(`--${k}=`)); return a ? a.slice(k.length + 3) : ''; };
const ORIGIN = argOf('es-origin') || 'https://app.eventsolutions.lt';

if (location.origin === ORIGIN) {
  contextBridge.exposeInMainWorld('esDesktop', {
    version: Number(argOf('es-ver')) || 3,        // DESK_VERSION in main.js
    platform: process.platform,
    arch: process.arch,
    notify: (n) => ipcRenderer.send('es:notify', n),
    onOpen: (cb) => ipcRenderer.on('es:open', (_e, url) => { try { cb(String(url)); } catch {} }),
    // download the newest installer, install it silently and restart
    update: () => ipcRenderer.invoke('es:update'),
    // the app window was minimized / hidden (false) or shown again (true)
    onWindow: (cb) => ipcRenderer.on('es:window', (_e, shown) => { try { cb(!!shown); } catch {} }),
    // screen sharing: the page shows the choice and answers with the id (or null = cancel)
    onPickScreen: (cb) => (ipcRenderer.send('es:pick-ready'), ipcRenderer.on('es:pick-screen', async (_e, r) => {
      let id = null;
      try { id = await cb(r.sources); } catch {}
      ipcRenderer.send('es:picked', { reqId: r.reqId, id: typeof id === 'string' ? id : null });
    })),
    onUpdateProgress: (cb) => ipcRenderer.on('es:update-progress', (_e, p) => { try { cb({ got: Number(p.got) || 0, size: Number(p.size) || 0 }); } catch {} }),
  });
}
