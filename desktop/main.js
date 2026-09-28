'use strict';
// Event Solutions for Windows: app.eventsolutions.lt in its own window.
//  * closing the window only hides it: the app keeps running next to the clock
//    (tray) and shows Windows notifications (chat, tasks, events …)
//  * starts together with Windows, hidden (can be switched off in the tray menu)
//  * links to other sites open in the normal browser
// Notifications: Web Push does not work inside Electron, so push-notify also
// writes each notification to public.desktop_inbox; the page listens to it
// (Realtime) and hands it over here through preload.js (window.esDesktop).
const { app, BrowserWindow, Tray, Menu, Notification, shell, ipcMain, nativeImage, session, screen, desktopCapturer } = require('electron');
const path = require('path');
const fs = require('fs');

// ES_URL: another address for testing (only when run with `npm start`, never in the installed app)
const HOME = (!app.isPackaged && process.env.ES_URL) || 'https://app.eventsolutions.lt/';
const ORIGIN = new URL(HOME).origin;
const APP_ID = 'lt.eventsolutions.app';
const ICON = path.join(__dirname, 'icons', 'icon.png');
const TRAY_ICON = path.join(__dirname, 'icons', 'tray.png');
// sites whose frames may use the camera and microphone (video calls)
const MEDIA_OK = [/^https:\/\/([a-z0-9-]+\.)*daily\.co$/];

let win = null, tray = null, quitting = false;
const notes = new Set();                       // keeps notifications alive until clicked or closed
const startHidden = process.argv.includes('--hidden');
const settingsFile = () => path.join(app.getPath('userData'), 'desktop.json');
let settings = {};
function readSettings() { try { settings = JSON.parse(fs.readFileSync(settingsFile(), 'utf8')) || {}; } catch { settings = {}; } }
function writeSettings() { try { fs.writeFileSync(settingsFile(), JSON.stringify(settings)); } catch {} }

function originOf(u) { try { return new URL(u).origin; } catch { return ''; } }
function sameOrigin(u) { return originOf(u) === ORIGIN; }
function openOutside(u) {
  try { if (['https:', 'http:', 'mailto:', 'tel:'].includes(new URL(u).protocol)) shell.openExternal(u); } catch {}
}

function showWin() {
  if (!win) return createWindow(true);
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
}

// the saved position, if it is still on one of the screens
function savedBounds() {
  const b = settings.bounds;
  if (!b || !(b.width > 300 && b.height > 300)) return { width: 1280, height: 820 };
  const on = screen.getAllDisplays().some((d) => {
    const a = d.workArea;
    return b.x < a.x + a.width - 80 && b.x + b.width > a.x + 80 && b.y >= a.y - 10 && b.y < a.y + a.height - 80;
  });
  return on ? b : { width: b.width, height: b.height };
}
function saveBounds() {
  if (!win || win.isDestroyed() || win.isFullScreen()) return;
  settings.bounds = win.getNormalBounds();
  settings.maximized = win.isMaximized();
  writeSettings();
}

function guard(wc) {
  wc.on('will-navigate', (e, url) => { if (!sameOrigin(url)) { e.preventDefault(); openOutside(url); } });
  wc.setWindowOpenHandler(({ url, features }) => {
    // print previews and reports (about:blank) and pages of the app itself
    if (!url || url === 'about:blank' || sameOrigin(url)) {
      return { action: 'allow', overrideBrowserWindowOptions: { autoHideMenuBar: true, icon: ICON, width: 1000, height: 800 } };
    }
    // a popup the app places next to itself (e.g. the road-toll site)
    if (/popup/.test(features || '') && /^https:/.test(url)) {
      return { action: 'allow', overrideBrowserWindowOptions: { autoHideMenuBar: true, icon: ICON } };
    }
    openOutside(url);
    return { action: 'deny' };
  });
  wc.on('did-create-window', (child) => {
    child.setMenuBarVisibility(false);
    child.webContents.setWindowOpenHandler(({ url }) => { openOutside(url); return { action: 'deny' }; });
  });
}

function keys(wc) {
  wc.on('before-input-event', (e, i) => {
    if (i.type !== 'keyDown') return;
    const k = (i.key || '').toLowerCase(), c = i.control || i.meta;
    let done = true;
    if (k === 'f5' || (c && k === 'r')) wc.reload();
    else if (c && i.shift && k === 'i') wc.toggleDevTools();
    else if (c && (k === '=' || k === '+')) wc.setZoomLevel(Math.min(wc.getZoomLevel() + 0.5, 4));
    else if (c && k === '-') wc.setZoomLevel(Math.max(wc.getZoomLevel() - 0.5, -3));
    else if (c && k === '0') wc.setZoomLevel(0);
    else if (k === 'f11') win.setFullScreen(!win.isFullScreen());
    else done = false;
    if (done) e.preventDefault();
  });
}

function createWindow(show) {
  win = new BrowserWindow({
    ...savedBounds(),
    minWidth: 360, minHeight: 480, show: false, backgroundColor: '#111111',
    title: 'Event Solutions', icon: ICON, autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true, nodeIntegration: false, spellcheck: true,
      additionalArguments: ['--es-origin=' + ORIGIN],
    },
  });
  win.removeMenu();
  if (settings.maximized) win.maximize();
  guard(win.webContents);
  keys(win.webContents);
  win.once('ready-to-show', () => { if (show || !startHidden) win.show(); });
  win.webContents.on('render-process-gone', () => { setTimeout(() => { if (win && !win.isDestroyed()) win.reload(); }, 1000); });
  win.on('focus', () => win.flashFrame(false));
  win.on('close', (e) => {
    saveBounds();
    if (quitting) return;
    e.preventDefault();
    win.hide();
    if (!settings.trayTip) {
      settings.trayTip = true;
      writeSettings();
      notify({ title: 'Event Solutions veikia fone', body: 'Pranešimai bus rodomi ir toliau. Visiškai uždaryti: dešiniu pelės mygtuku ant ikonos šalia laikrodžio → Išeiti.' });
    }
  });
  win.loadURL(HOME);
}

function autoStartOn() { return app.getLoginItemSettings({ args: ['--hidden'] }).openAtLogin; }
function setAutoStart(on) {
  app.setLoginItemSettings({ openAtLogin: !!on, args: ['--hidden'] });
  settings.autoStart = !!on;
  writeSettings();
}

function buildTray() {
  tray = new Tray(nativeImage.createFromPath(TRAY_ICON));
  tray.setToolTip('Event Solutions');
  const menu = () => Menu.buildFromTemplate([
    { label: 'Atidaryti Event Solutions', click: showWin },
    { type: 'separator' },
    { label: 'Paleisti kartu su Windows', type: 'checkbox', checked: autoStartOn(), click: (m) => { setAutoStart(m.checked); tray.setContextMenu(menu()); } },
    { label: 'Pranešimų garsas', type: 'checkbox', checked: soundOn(), click: (m) => { settings.sound = m.checked; writeSettings(); tray.setContextMenu(menu()); } },
    { label: 'Išbandyti pranešimą', click: () => notify({ title: 'Event Solutions', body: soundOn() ? 'Pranešimai veikia – turėjai išgirsti garsą.' : 'Pranešimai veikia (garsas išjungtas).' }, '') },
    { label: 'Perkrauti', click: () => { showWin(); win.webContents.reloadIgnoringCache(); } },
    { type: 'separator' },
    { label: 'Išeiti', click: () => { quitting = true; app.quit(); } },
  ]);
  tray.setContextMenu(menu());
  tray.on('click', showWin);
}

const xml = (s) => String(s).replace(/[<>&"']/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' })[c]);
function soundOn() { return settings.sound !== false; }
// Windows toast with its own sound: messages, tasks … get the "message" sound,
// a video call rings until answered. The icon must be a real file (not inside app.asar).
function toastXml(title, body, call) {
  const icon = ICON.replace(/app\.asar([\\/])/, 'app.asar.unpacked$1');
  const audio = !soundOn() ? '<audio silent="true"/>'
    : call ? '<audio src="ms-winsoundevent:Notification.Looping.Call" loop="true"/>'
    : '<audio src="ms-winsoundevent:Notification.IM"/>';
  return `<toast activationType="foreground" launch="es"${call ? ' scenario="incomingCall"' : ''}>`
    + '<visual><binding template="ToastGeneric">'
    + `<text>${xml(title)}</text>${body ? `<text>${xml(body)}</text>` : ''}`
    + (fs.existsSync(icon) ? `<image placement="appLogoOverride" src="${xml(icon)}"/>` : '')
    + '</binding></visual>'
    + (call ? '<actions><action content="Atsiliepti" arguments="es" activationType="foreground"/><action content="Atmesti" arguments="dismiss" activationType="system"/></actions>' : '')
    + `${audio}</toast>`;
}
function notify(n, url) {
  const call = n.kind === 'call';
  const title = String(n.title || 'Event Solutions').slice(0, 120), body = String(n.body || '').slice(0, 300);
  const opts = { title, body, icon: ICON, silent: !soundOn(), timeoutType: call ? 'never' : 'default', urgency: call ? 'critical' : 'normal' };
  if (process.platform === 'win32') opts.toastXml = toastXml(title, body, call);
  const note = new Notification(opts);
  notes.add(note);
  const drop = () => notes.delete(note);
  note.on('click', () => {
    drop();
    showWin();
    if (url && win) win.webContents.send('es:open', url);
  });
  note.on('close', drop);
  note.on('failed', drop);
  note.show();
}

ipcMain.on('es:notify', (e, n) => {
  if (!win || e.sender !== win.webContents || !sameOrigin(e.senderFrame ? e.senderFrame.url : '')) return;
  if (!n || typeof n !== 'object') return;
  // shown always, also with the window open (the page skips a chat you are reading)
  const url = typeof n.url === 'string' ? n.url.slice(0, 500) : './';
  notify(n, url);
  if (!win.isFocused()) win.flashFrame(true);
});

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.setAppUserModelId(APP_ID);
  // look like the ordinary Chrome to the sites (video calls check the browser)
  app.userAgentFallback = app.userAgentFallback.replace(/ Electron\/\S+/, '').replace(/ eventsolutions-desktop\/\S+/i, '');

  app.on('second-instance', showWin);
  app.on('before-quit', () => { quitting = true; saveBounds(); });
  app.on('window-all-closed', () => {});          // keeps running in the tray

  app.whenReady().then(() => {
    readSettings();
    const s = session.defaultSession;
    s.setPermissionRequestHandler((wc, permission, cb, details) => {
      const o = originOf(details.requestingUrl || wc.getURL());
      if (permission === 'openExternal') return cb(true);
      if (['media', 'display-capture'].includes(permission)) return cb(o === ORIGIN || MEDIA_OK.some((r) => r.test(o)));
      cb(o === ORIGIN && ['notifications', 'clipboard-read', 'clipboard-sanitized-write', 'fullscreen', 'pointerLock'].includes(permission));
    });
    // screen sharing in a video call: the whole main screen
    s.setDisplayMediaRequestHandler((req, cb) => {
      desktopCapturer.getSources({ types: ['screen'] }).then((src) => cb(src[0] ? { video: src[0] } : {})).catch(() => cb({}));
    });
    if (app.isPackaged && settings.autoStart === undefined) setAutoStart(true);
    buildTray();
    createWindow(false);
  });
}
