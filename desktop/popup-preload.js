'use strict';
// the notification popup (popup.html) tells the app: clicked, closed, mouse over / away
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('pop', {
  send: (what) => { if (['open', 'close', 'hover', 'leave'].includes(what)) ipcRenderer.send('es:pop', what); },
});
