'use strict';
// Event Solutions for Windows and Mac: app.eventsolutions.lt in its own window.
//  * closing the window only hides it: the app keeps running next to the clock
//    (Windows tray / Mac menu bar) and shows notifications with sound
//  * starts together with the computer, hidden (can be switched off in the tray menu)
//  * links to other sites open in the normal browser
//  * updates itself: "Atnaujinti" in the app downloads and installs the new version
// Notifications: Web Push does not work inside Electron, so push-notify also
// writes each notification to public.desktop_inbox; the page listens to it
// (Realtime) and hands it over here through preload.js (window.esDesktop).
const { app, BrowserWindow, Tray, Menu, shell, ipcMain, nativeImage, session, screen, desktopCapturer, net, systemPreferences } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { spawn } = require('child_process');

// the version of this program; EventSolutions-Setup.json / EventSolutions-Mac-<arch>.json
// in Supabase Storage (bucket "desktop") say which is the newest
const DESK_VERSION = 5;
const MAC = process.platform === 'darwin';
// what this computer downloads when it updates itself
const PKG = MAC ? { manifest: `EventSolutions-Mac-${process.arch}.json`, file: `EventSolutions-Mac-${process.arch}.zip` }
  : { manifest: 'EventSolutions-Setup.json', file: 'EventSolutions-Setup.exe' };

// ES_URL: another address for testing (only when run with `npm start`, never in the installed app)
const HOME = (!app.isPackaged && process.env.ES_URL) || 'https://app.eventsolutions.lt/';
const ORIGIN = new URL(HOME).origin;
const APP_ID = 'lt.eventsolutions.app';
const ICON = path.join(__dirname, 'icons', 'icon.png');
const TRAY_ICON = path.join(__dirname, 'icons', 'tray.png');
// sites whose frames may use the camera and microphone (video calls)
const MEDIA_OK = [/^https:\/\/([a-z0-9-]+\.)*daily\.co$/];

let win = null, tray = null, quitting = false;
let startHidden = process.argv.includes('--hidden');
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
    // AltGr (Ctrl+Alt on Windows) types letters and signs on the Lithuanian keyboard: never a shortcut
    const k = (i.key || '').toLowerCase(), c = (i.control || i.meta) && !i.alt;
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
      // hidden next to the clock the page must stay live (chat connection, notifications)
      backgroundThrottling: false,
      additionalArguments: ['--es-origin=' + ORIGIN, '--es-ver=' + DESK_VERSION],
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

function autoStartOn() { return app.getLoginItemSettings(MAC ? {} : { args: ['--hidden'] }).openAtLogin; }
function setAutoStart(on) {
  app.setLoginItemSettings(MAC ? { openAtLogin: !!on, openAsHidden: true } : { openAtLogin: !!on, args: ['--hidden'] });
  settings.autoStart = !!on;
  writeSettings();
}

function buildTray() {
  let img = nativeImage.createFromPath(TRAY_ICON);
  if (MAC) img = img.resize({ width: 18, height: 18 });   // the Mac menu bar is small
  tray = new Tray(img);
  tray.setToolTip('Event Solutions');
  const menu = () => Menu.buildFromTemplate([
    { label: 'Atidaryti Event Solutions', click: showWin },
    { type: 'separator' },
    { label: MAC ? 'Paleisti kartu su kompiuteriu' : 'Paleisti kartu su Windows', type: 'checkbox', checked: autoStartOn(), click: (m) => { setAutoStart(m.checked); tray.setContextMenu(menu()); } },
    { label: 'Pranešimų garsas', type: 'checkbox', checked: soundOn(), click: (m) => { settings.sound = m.checked; writeSettings(); tray.setContextMenu(menu()); } },
    { label: 'Išbandyti pranešimą', click: () => notify({ title: 'Event Solutions', body: soundOn() ? 'Pranešimai veikia – turėjai išgirsti garsą.' : 'Pranešimai veikia (garsas išjungtas).' }, '') },
    { label: 'Perkrauti', click: () => { showWin(); win.webContents.reloadIgnoringCache(); } },
    { type: 'separator' },
    { label: 'Išeiti', click: () => { quitting = true; app.quit(); } },
  ]);
  tray.setContextMenu(menu());
  tray.on('click', showWin);
}

function soundOn() { return settings.sound !== false; }

/* ---------- notifications: our own popups ----------
   Windows' own toasts are silently dropped for an unsigned app in many setups,
   so the app shows its own small window in the bottom-right corner (above other
   windows, without taking the focus) with its own sound. Up to 4 are stacked;
   a message closes after 10 s, a video call rings until clicked or closed. */
const POP_W = 380, POP_H = 104, POP_GAP = 10, POP_MAX = 4;
const pops = [];                                // { win, url, call }
function popLayout() {
  const a = screen.getPrimaryDisplay().workArea;
  pops.forEach((p, i) => {
    if (p.win.isDestroyed()) return;
    const y = MAC ? a.y + 8 + (POP_H + POP_GAP) * i : a.y + a.height - (POP_H + POP_GAP) * (i + 1) - 4;
    p.win.setBounds({ x: a.x + a.width - POP_W - 14, y, width: POP_W, height: POP_H });
  });
}
function popClose(p) {
  const i = pops.indexOf(p);
  if (i >= 0) pops.splice(i, 1);
  clearTimeout(p.timer);
  if (!p.win.isDestroyed()) p.win.destroy();
  popLayout();
}
function notify(n, url) {
  const call = n.kind === 'call';
  while (pops.length >= POP_MAX) popClose(pops[pops.length - 1]);
  const w = new BrowserWindow({
    width: POP_W, height: POP_H, show: false, frame: false, resizable: false, movable: false, minimizable: false, maximizable: false,
    fullscreenable: false, skipTaskbar: true, alwaysOnTop: true, focusable: false, backgroundColor: '#1b1b1d', title: 'Event Solutions',
    webPreferences: { preload: path.join(__dirname, 'popup-preload.js'), contextIsolation: true, sandbox: true, autoplayPolicy: 'no-user-gesture-required' },
  });
  w.setAlwaysOnTop(true, 'screen-saver');
  w.removeMenu();
  const p = { win: w, url: url || '', call };
  pops.unshift(p);
  popLayout();
  w.loadFile(path.join(__dirname, 'popup.html'), { query: {
    t: String(n.title || 'Event Solutions').slice(0, 120), b: String(n.body || '').slice(0, 300),
    call: call ? '1' : '', sound: soundOn() ? '1' : '',
  } });
  w.once('ready-to-show', () => { if (!w.isDestroyed()) w.showInactive(); });
  w.on('closed', () => popClose(p));
  p.timer = setTimeout(() => popClose(p), call ? 60000 : 10000);
  if (win && !win.isDestroyed() && !win.isFocused()) { if (MAC) { if (call && app.dock) app.dock.bounce('critical'); } else win.flashFrame(true); }
}
ipcMain.on('es:pop', (e, what) => {
  const p = pops.find((x) => !x.win.isDestroyed() && x.win.webContents === e.sender);
  if (!p) return;
  if (what === 'open') {
    showWin();
    if (p.url && win) win.webContents.send('es:open', p.url);
  } else if (what === 'hover') {
    clearTimeout(p.timer);                        // stays while the mouse is over it
  } else if (what === 'leave') {
    clearTimeout(p.timer);
    p.timer = setTimeout(() => popClose(p), p.call ? 60000 : 5000);
    return;
  }
  if (what !== 'hover') popClose(p);
});

ipcMain.on('es:notify', (e, n) => {
  if (!win || e.sender !== win.webContents || !sameOrigin(e.senderFrame ? e.senderFrame.url : '')) return;
  if (!n || typeof n !== 'object') return;
  // shown always, also with the window open (the page skips a chat you are reading)
  notify(n, typeof n.url === 'string' ? n.url.slice(0, 500) : './');
});

/* ---------- updates ----------
   Supabase Storage (bucket "desktop", reached through the site's _redirects) has
   the manifest (version, size, sha256, parts) and the program in parts of 24 MB.
   "Atnaujinti" in the app: the parts are downloaded here, checked and joined into
   a file in TEMP. Windows: the installer runs silently (/S), closes this app and
   starts the new one. Mac: the new .app is unpacked and put in place of this one
   by a small script once this app has quit, then opened. */
let updating = false;
const partRe = new RegExp('^' + PKG.file.replace(/\./g, '\\.') + '\\.part\\d+$');
async function download(progress) {
  const at = (f) => new URL(f, HOME).href;
  const html = (r) => /text\/html/i.test(r.headers.get('content-type') || '');
  const mr = await net.fetch(at(PKG.manifest), { cache: 'no-store' });
  if (!mr.ok || html(mr)) throw new Error('missing');
  const m = await mr.json();
  if (!m || !Array.isArray(m.parts) || !m.parts.length || !(m.size > 0) || !/^[0-9a-f]{64}$/.test(m.sha256 || '')) throw new Error('missing');
  const file = path.join(app.getPath('temp'), `${Number(m.version) || 0}-${PKG.file}`);
  const fh = await fs.promises.open(file, 'w');
  const hash = crypto.createHash('sha256');
  let got = 0, last = 0;
  try {
    for (const part of m.parts) {
      if (!partRe.test(part)) throw new Error('missing');
      const r = await net.fetch(at(part), { cache: 'no-store' });
      if (!r.ok || html(r)) throw new Error('missing');
      for await (const chunk of r.body) {
        const buf = Buffer.from(chunk);
        hash.update(buf);
        await fh.write(buf);
        got += buf.length;
        if (Date.now() - last > 150) { last = Date.now(); progress(got, m.size); }
      }
    }
  } finally { await fh.close(); }
  progress(got, m.size);
  if (got !== m.size || hash.digest('hex') !== m.sha256) { fs.rmSync(file, { force: true }); throw new Error('broken'); }
  return file;
}
function run(cmd, args) {
  return new Promise((res, rej) => {
    const c = spawn(cmd, args, { stdio: 'ignore' });
    c.on('error', rej);
    c.on('exit', (code) => (code === 0 ? res() : rej(new Error(cmd + ' ' + code))));
  });
}
async function installMac(zip) {
  // /Applications/Event Solutions.app/Contents/MacOS/Event Solutions -> the .app
  const appDir = path.resolve(process.execPath, '..', '..', '..');
  if (!/\.app$/.test(appDir)) throw new Error('Programa paleista ne iš .app');
  // started straight from Downloads (macOS runs such a copy from a read-only place)
  if (/AppTranslocation/.test(appDir)) throw new Error('translocated');
  const dir = path.join(app.getPath('temp'), 'es-update-' + Date.now());
  fs.mkdirSync(dir, { recursive: true });
  await run('/usr/bin/ditto', ['-x', '-k', zip, dir]);
  const fresh = fs.readdirSync(dir).find((f) => f.endsWith('.app'));
  if (!fresh) throw new Error('broken');
  const q = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
  const script = path.join(dir, 'install.sh');
  fs.writeFileSync(script, [
    '#!/bin/sh',
    `while kill -0 ${process.pid} 2>/dev/null; do sleep 0.3; done`,
    `rm -rf ${q(appDir)} && /usr/bin/ditto ${q(path.join(dir, fresh))} ${q(appDir)}`,
    `/usr/bin/xattr -dr com.apple.quarantine ${q(appDir)} 2>/dev/null`,
    `/usr/bin/open ${q(appDir)}`,
    `rm -rf ${q(dir)} ${q(zip)}`,
  ].join('\n'), { mode: 0o755 });
  const child = spawn('/bin/sh', [script], { detached: true, stdio: 'ignore' });
  child.on('error', () => {});
  child.unref();
}
async function update(progress) {
  if (updating) return { ok: false, error: 'busy' };
  updating = true;
  try {
    const file = await download(progress);
    if (MAC) await installMac(file);
    else {
      const child = spawn(file, ['/S'], { detached: true, stdio: 'ignore' });
      child.on('error', () => {});
      child.unref();
    }
    setTimeout(() => { quitting = true; app.quit(); }, 400);
    return { ok: true };
  } catch (err) {
    updating = false;
    return { ok: false, error: err && err.message || String(err) };
  }
}
ipcMain.handle('es:update', (e) => {
  if (!win || e.sender !== win.webContents) return { ok: false, error: 'denied' };
  return update((got, size) => { if (win && !win.isDestroyed()) win.webContents.send('es:update-progress', { got, size }); });
});

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  if (!MAC) app.setAppUserModelId(APP_ID);
  // look like the ordinary Chrome to the sites (video calls check the browser)
  app.userAgentFallback = app.userAgentFallback.replace(/ Electron\/\S+/, '').replace(/ eventsolutions-desktop\/\S+/i, '');

  app.on('second-instance', showWin);
  app.on('activate', showWin);                    // Mac: a click on the Dock icon
  app.on('before-quit', () => { quitting = true; saveBounds(); });
  app.on('window-all-closed', () => {});          // keeps running in the tray

  app.whenReady().then(() => {
    readSettings();
    if (MAC) {
      // started at login: only the menu bar icon
      try { if (app.getLoginItemSettings().wasOpenedAsHidden) startHidden = true; } catch {}
      // the Mac menu: without it copy / paste (⌘C, ⌘V) and ⌘Q do not work
      Menu.setApplicationMenu(Menu.buildFromTemplate([
        { role: 'appMenu', label: 'Event Solutions' },
        { role: 'editMenu', label: 'Taisyti' },
        { label: 'Rodinys', submenu: [{ role: 'reload', label: 'Perkrauti' }, { role: 'togglefullscreen', label: 'Visas ekranas' }, { type: 'separator' }, { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }] },
        { role: 'windowMenu', label: 'Langas' },
      ]));
    }
    const s = session.defaultSession;
    s.setPermissionRequestHandler((wc, permission, cb, details) => {
      const o = originOf(details.requestingUrl || wc.getURL());
      if (permission === 'openExternal') return cb(true);
      if (['media', 'display-capture'].includes(permission)) {
        const ok = o === ORIGIN || MEDIA_OK.some((r) => r.test(o));
        // Mac asks the person once for the camera and microphone
        if (ok && MAC && permission === 'media' && systemPreferences.askForMediaAccess) {
          const kinds = (details.mediaTypes || []).map((t) => (t === 'video' ? 'camera' : 'microphone'));
          return Promise.all(kinds.map((k) => systemPreferences.askForMediaAccess(k))).then((r) => cb(r.every(Boolean)), () => cb(false));
        }
        return cb(ok);
      }
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
