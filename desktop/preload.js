'use strict';
// What the page sees of the desktop app: window.esDesktop (only on the app's own site)
const { contextBridge, ipcRenderer } = require('electron');

const arg = process.argv.find((a) => a.startsWith('--es-origin='));
const ORIGIN = arg ? arg.slice('--es-origin='.length) : 'https://app.eventsolutions.lt';

if (location.origin === ORIGIN) {
  contextBridge.exposeInMainWorld('esDesktop', {
    version: 1,                                   // bump together with DESK_LATEST in index.html
    platform: process.platform,
    notify: (n) => ipcRenderer.send('es:notify', n),
    onOpen: (cb) => ipcRenderer.on('es:open', (_e, url) => { try { cb(String(url)); } catch {} }),
  });
}
