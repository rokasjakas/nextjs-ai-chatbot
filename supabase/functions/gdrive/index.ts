// Supabase Edge Function: gdrive
//
// Every event (Renginiai, not „Sandėlio darbai“) gets a folder in the company's shared Google Drive:
//   „2026-11-05 Festivalis Ruduo“ with Darbiniai planai, Video failai, Raideriai, Erdvės foto, Papildomi failai.
// Access: members from Office up (by their e-mail) can edit; the people a letter of the event was sent to can view.
// Slack: a file put in the event's Slack channel → the bot asks under it „Kur dėti?“ with buttons; the one pressed
// moves the file into that folder of the event's Drive folder, and the bot's message says where it went.
//
// From the app (signed-in member, Authorization: Bearer <session>):
//   POST {action:"status"}                   is Google Drive connected (the shared drive's name) – Admin
//   POST {action:"ensure", event_id}         make / rename the event's folder, give Office and up access → {url, subs}
//   POST {action:"share", event_id, emails}  the letter's recipients may view the folder → {url, shared, failed}
// From Slack (x-slack-signature, checked with SLACK_SIGNING_SECRET): Event Subscriptions (file_shared) and
// Interactivity (the buttons) – both Request URLs are this function's address.
// Google – one of two ways:
//   a) a Gmail account signed in once (Admin → Google Drive → „Prisijungti su Google“): GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
//      (an OAuth „Web application“ client; redirect URI = this function's address + ?oauth=1). Scope drive.file – the app
//      sees only what it made itself; the folders go into „Renginiai (Event Solutions)“ it makes in that Drive.
//   b) a Workspace service account: GOOGLE_SA_JSON (its JSON key) and GDRIVE_ROOT_ID (a shared drive's id).
// Slack: SLACK_BOT_TOKEN (scopes also files:read), SLACK_SIGNING_SECRET.
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are given by Supabase.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const E = (n: string) => Deno.env.get(n) ?? "";
class UserError extends Error {}
const enc = encodeURIComponent;
const SUBS: [string, string][] = [["plans", "Darbiniai planai"], ["video", "Video failai"], ["riders", "Raideriai"], ["venue", "Erdvės foto"], ["extra", "Papildomi failai"]];
const FOLDER = "application/vnd.google-apps.folder";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" } });
}
async function db<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const key = E("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${E("SUPABASE_URL")}/rest/v1/${path}`, {
    ...init,
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json", ...(init.headers as Record<string, string> ?? {}) },
  });
  const t = await res.text();
  if (!res.ok) {
    if (/event_drive|drive_uploads|does not exist|schema cache/i.test(t)) throw new UserError("Drive dar neparuoštas – paleisk supabase/sql/event_drive.sql.");
    throw new Error(`Database ${res.status}: ${t.slice(0, 300)}`);
  }
  return (t ? JSON.parse(t) : null) as T;
}

// ---- Google: a service account's token (JWT signed with its key) ----
let TOK: { t: string; exp: number } | null = null;
const b64u = (b: Uint8Array | string) => {
  const s = typeof b === "string" ? btoa(unescape(encodeURIComponent(b))) : btoa(String.fromCharCode(...b));
  return s.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
};
type Auth = { refresh_token: string | null; email: string | null; root_id: string | null };
let AUTH: Auth | null = null;
async function auth(): Promise<Auth | null> {
  if (AUTH) return AUTH;
  const r = await db<Auth[]>("gdrive_auth?select=refresh_token,email,root_id&id=eq.1").catch(() => []);
  return AUTH = (r[0] && r[0].refresh_token) ? r[0] : null;
}
// a Gmail signed in (Admin → „Prisijungti su Google“) wins; otherwise the service account, if there is one
const oauthMode = async () => !!(await auth()) || !E("GOOGLE_SA_JSON");
const redirectUri = () => `${E("SUPABASE_URL")}/functions/v1/gdrive?oauth=1`;
async function gToken(): Promise<string> {
  if (TOK && TOK.exp > Date.now() + 60_000) return TOK.t;
  if (await oauthMode()) {
    const a = await auth();
    if (!a) throw new UserError("Google Drive neprijungtas: Admin → Google Drive → „Prisijungti su Google“.");
    const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: E("GOOGLE_CLIENT_ID"), client_secret: E("GOOGLE_CLIENT_SECRET"), refresh_token: a.refresh_token!, grant_type: "refresh_token" }) });
    const d = await r.json() as { access_token?: string; expires_in?: number; error?: string; error_description?: string };
    if (!d.access_token) throw new UserError("Google prisijungimas nebegalioja (" + (d.error_description || d.error || r.status) + ") – Admin → Google Drive → „Prisijungti su Google“ iš naujo.");
    TOK = { t: d.access_token, exp: Date.now() + (d.expires_in ?? 3600) * 1000 };
    return TOK.t;
  }
  const raw = E("GOOGLE_SA_JSON");
  let sa: { client_email?: string; private_key?: string };
  try { sa = JSON.parse(raw); } catch { throw new UserError("GOOGLE_SA_JSON – ne JSON (įklijuok visą rakto failo turinį)."); }
  if (!sa.client_email || !sa.private_key) throw new UserError("GOOGLE_SA_JSON be client_email / private_key.");
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64u(JSON.stringify({ iss: sa.client_email, scope: "https://www.googleapis.com/auth/drive", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const der = Uint8Array.from(atob(sa.private_key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(head + "." + claim)));
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: head + "." + claim + "." + b64u(sig) }) });
  const d = await r.json() as { access_token?: string; expires_in?: number; error_description?: string; error?: string };
  if (!d.access_token) throw new UserError("Google atmetė raktą: " + (d.error_description || d.error || r.status));
  TOK = { t: d.access_token, exp: Date.now() + (d.expires_in ?? 3600) * 1000 };
  return TOK.t;
}
async function g<T = Record<string, unknown>>(path: string, init: RequestInit = {}, base = "https://www.googleapis.com/drive/v3/"): Promise<T> {
  const r = await fetch(base + path + (path.includes("?") ? "&" : "?") + "supportsAllDrives=true", {
    ...init, headers: { Authorization: "Bearer " + await gToken(), "Content-Type": "application/json", ...(init.headers as Record<string, string> ?? {}) } });
  const t = await r.text();
  if (!r.ok) {
    let m = t.slice(0, 300); try { m = (JSON.parse(t).error || {}).message || m; } catch { /* text */ }
    if (r.status === 404 && /File not found/i.test(m)) throw new UserError("Google Drive: aplankas nerastas – patikrink GDRIVE_ROOT_ID ir ar paslaugos paskyra pridėta prie bendro Drive (Content manager).");
    throw new UserError("Google Drive: " + m);
  }
  return (t ? JSON.parse(t) : {}) as T;
}
// where the event folders go: the shared drive (service account), or the app's own folder in the Gmail Drive (made the first time)
let ROOT = "";
async function root(): Promise<string> {
  if (ROOT) return ROOT;
  if (!(await oauthMode())) { const r = E("GDRIVE_ROOT_ID"); if (!r) throw new UserError("Nėra GDRIVE_ROOT_ID (bendro Drive id) – Supabase → Edge Functions → Secrets."); return ROOT = r; }
  const a = await auth(); if (!a) throw new UserError("Google Drive neprijungtas.");
  if (a.root_id) { try { const f = await g<{ trashed?: boolean }>(`files/${a.root_id}?fields=id,trashed`); if (!f.trashed) return ROOT = a.root_id; } catch { /* gone – made again */ } }
  const id = await mkFolder("Renginiai (Event Solutions)", "root");
  await db("gdrive_auth?id=eq.1", { method: "PATCH", body: JSON.stringify({ root_id: id }) });
  AUTH = { ...a, root_id: id };
  return ROOT = id;
}
// the sign-in link's state: who asked and until when, signed (so nobody else's code can be put in)
async function hmac(s: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(E("SUPABASE_SERVICE_ROLE_KEY")), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(s))));
}
async function oauthStart(who: string): Promise<string> {
  if (!E("GOOGLE_CLIENT_ID") || !E("GOOGLE_CLIENT_SECRET")) throw new UserError("Nėra GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET (Supabase → Edge Functions → Secrets).");
  const st = b64u(JSON.stringify({ w: who, x: Date.now() + 15 * 60_000 })), state = st + "." + await hmac(st);
  return "https://accounts.google.com/o/oauth2/v2/auth?" + new URLSearchParams({ client_id: E("GOOGLE_CLIENT_ID"), redirect_uri: redirectUri(), response_type: "code",
    scope: "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.email", access_type: "offline", prompt: "consent", include_granted_scopes: "true", state });
}
const page = (title: string, text: string) => new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<body style="font-family:system-ui,sans-serif;background:#111;color:#eee;display:grid;place-items:center;min-height:90vh;margin:0"><div style="max-width:420px;padding:24px;text-align:center"><h2>${title}</h2><p>${text}</p>
<p><a style="color:#6AB0F3" href="https://app.eventsolutions.lt/?admin=1">Grįžti į programėlę</a></p></div>`, { headers: { "Content-Type": "text/html; charset=utf-8" } });
async function oauthBack(u: URL): Promise<Response> {
  const code = u.searchParams.get("code"), state = u.searchParams.get("state") || "", err = u.searchParams.get("error");
  if (err) return page("Neprijungta", "Google: " + err.replace(/[<>&]/g, ""));
  const [st, sig] = state.split(".");
  if (!code || !st || !sig || sig !== await hmac(st)) return page("Neprijungta", "Netinkama nuoroda – bandyk dar kartą iš Admin.");
  let s: { w?: string; x?: number } = {}; try { s = JSON.parse(decodeURIComponent(escape(atob(st.replace(/-/g, "+").replace(/_/g, "/"))))); } catch { /* bad */ }
  if (!s.x || s.x < Date.now()) return page("Neprijungta", "Nuoroda pasibaigė – bandyk dar kartą iš Admin.");
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code, client_id: E("GOOGLE_CLIENT_ID"), client_secret: E("GOOGLE_CLIENT_SECRET"), redirect_uri: redirectUri(), grant_type: "authorization_code" }) });
  const d = await r.json() as { access_token?: string; refresh_token?: string; error_description?: string; error?: string };
  if (!d.refresh_token) return page("Neprijungta", "Google negrąžino ilgalaikio rakto (" + String(d.error_description || d.error || "be refresh_token").replace(/[<>&]/g, "") + ").");
  let email = ""; try { const me = await (await fetch("https://www.googleapis.com/oauth2/v2/userinfo", { headers: { Authorization: "Bearer " + d.access_token } })).json(); email = String(me.email || ""); } catch { /* none */ }
  const [old] = await db<{ email: string | null; root_id: string | null }[]>("gdrive_auth?select=email,root_id&id=eq.1").catch(() => []);
  await db("gdrive_auth?on_conflict=id", { method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify({ id: 1, refresh_token: d.refresh_token, email, connected_by: s.w || "", connected_at: new Date().toISOString(), root_id: old && old.email === email ? old.root_id : null }) });
  return page("✓ Google Drive prijungtas", `Paskyra <b>${email.replace(/[<>&]/g, "")}</b>. Renginių aplankai bus kuriami aplanke „Renginiai (Event Solutions)“. Gali uždaryti šį langą.`);
}
const folderUrl = (id: string) => `https://drive.google.com/drive/folders/${id}`;
async function mkFolder(name: string, parent: string): Promise<string> {
  const f = await g<{ id: string }>("files?fields=id", { method: "POST", body: JSON.stringify({ name, mimeType: FOLDER, parents: [parent] }) });
  return f.id;
}
async function findFolder(name: string, parent: string): Promise<string | null> {
  const q = `name = '${name.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}' and '${parent}' in parents and mimeType = '${FOLDER}' and trashed = false`;
  const r = await g<{ files: { id: string }[] }>(`files?q=${enc(q)}&fields=files(id)&includeItemsFromAllDrives=true&corpora=allDrives`);
  return r.files?.[0]?.id ?? null;
}
// one person may open the folder (writer / reader); an address without a Google account needs Google's own invitation e-mail
async function grant(folder: string, email: string, role: "writer" | "reader"): Promise<string | null> {
  const body = JSON.stringify({ type: "user", role, emailAddress: email });
  try { await g(`files/${folder}/permissions?sendNotificationEmail=false`, { method: "POST", body }); return null; }
  catch (e) {
    const m = (e as Error).message;
    if (/notif|Google account|invalid sharing/i.test(m)) {
      try { await g(`files/${folder}/permissions?sendNotificationEmail=true&emailMessage=${enc("Renginio failai – Event Solutions")}`, { method: "POST", body }); return null; }
      catch (e2) { return (e2 as Error).message; }
    }
    return m;
  }
}

// ---- the event and its folder ----
type Ev = { id: string; kind?: string; name?: string; date?: string; deletedAt?: string; handoverId?: string };
type Row = { event_id: string; folder_id: string; url: string; name: string; subs: Record<string, { id: string; url: string }>; shared: string[] };
async function loadEvent(id: string): Promise<Ev | null> {
  const r = await db<{ id: string; data: Ev }[]>(`events?select=id,data&id=eq.${enc(id)}`);
  return r[0] ? { ...r[0].data, id: r[0].id } : null;
}
const folderName = (ev: Ev) => `${String(ev.date || "").slice(0, 10)} ${String(ev.name || "Renginys").replace(/[\\/]+/g, "-").trim()}`.trim().slice(0, 200);
async function officeEmails(): Promise<string[]> {
  const r = await db<{ email: string }[]>("profiles?select=email&role=in.(admin,pm,office)");
  return [...new Set(r.map((x) => String(x.email || "").trim().toLowerCase()).filter((x) => /@/.test(x)))];
}
async function ensure(ev: Ev): Promise<Row> {
  if (ev.kind === "work" || ev.handoverId) throw new UserError("Sandėlio darbams ir išdavimams Drive aplanko nėra.");
  const [had] = await db<Row[]>(`event_drive?select=*&event_id=eq.${enc(ev.id)}`);
  const name = folderName(ev);
  let row: Row;
  if (had) {
    row = had;
    if (had.name !== name) { await g(`files/${had.folder_id}`, { method: "PATCH", body: JSON.stringify({ name }) }); row.name = name; }
  } else {
    const id = (await findFolder(name, await root())) ?? await mkFolder(name, await root());
    row = { event_id: ev.id, folder_id: id, url: folderUrl(id), name, subs: {}, shared: [] };
  }
  for (const [k, label] of SUBS) {
    if (row.subs[k]?.id) continue;
    const id = (await findFolder(label, row.folder_id)) ?? await mkFolder(label, row.folder_id);
    row.subs[k] = { id, url: folderUrl(id) };
  }
  // Office and up – may edit
  const want = (await officeEmails()).filter((e) => !row.shared.includes(e)), errs: string[] = [];
  for (const e of want) { const err = await grant(row.folder_id, e, "writer"); if (err) errs.push(e + ": " + err); else row.shared.push(e); }
  await db("event_drive?on_conflict=event_id", { method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify({ ...row, last_error: errs.length ? errs.join("; ").slice(0, 500) : null, updated_at: new Date().toISOString() }) });
  return row;
}
async function share(ev: Ev, emails: string[]) {
  const row = await ensure(ev), failed: string[] = [], added: string[] = [];
  for (const e0 of emails) {
    const e = String(e0 || "").trim().toLowerCase(); if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) || row.shared.includes(e)) continue;
    const err = await grant(row.folder_id, e, "reader"); if (err) failed.push(e); else { added.push(e); row.shared.push(e); }
  }
  if (added.length) await db(`event_drive?event_id=eq.${enc(ev.id)}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ shared: row.shared, updated_at: new Date().toISOString() }) });
  return { url: row.url, shared: added.length, failed };
}

// ---- Slack ----
async function slack(method: string, args: Record<string, unknown>, form = false): Promise<Record<string, unknown>> {
  const token = E("SLACK_BOT_TOKEN"); if (!token) throw new UserError("Nėra SLACK_BOT_TOKEN.");
  const r = await fetch(`https://slack.com/api/${method}`, form
    ? { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(args as Record<string, string>) }
    : { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json; charset=utf-8" }, body: JSON.stringify(args) });
  return await r.json();
}
async function slackSigned(req: Request, body: string): Promise<boolean> {
  const secret = E("SLACK_SIGNING_SECRET"), ts = req.headers.get("x-slack-request-timestamp") ?? "", sig = req.headers.get("x-slack-signature") ?? "";
  if (!secret || !ts || Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`v0:${ts}:${body}`)));
  const want = "v0=" + [...mac].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (want.length !== sig.length) return false;
  let d = 0; for (let i = 0; i < want.length; i++) d |= want.charCodeAt(i) ^ sig.charCodeAt(i);
  return d === 0;
}
const later = (p: Promise<unknown>) => { const w = (globalThis as { EdgeRuntime?: { waitUntil(p: Promise<unknown>): void } }).EdgeRuntime; p.catch((e) => console.error("gdrive bg", (e as Error).message)); if (w) w.waitUntil(p); };
async function driveOn(): Promise<boolean> {
  const r = await db<{ value: { on?: boolean } }[]>("app_config?select=value&key=eq.gdrive").catch(() => []);
  return !!(r[0]?.value?.on);
}
// a file came into an event's channel: „Kur dėti?“ with a button for each folder
async function onFileShared(ev0: { file_id?: string; channel_id?: string; user_id?: string }) {
  if (!ev0.file_id || !ev0.channel_id || !(await driveOn())) return;
  const [ch] = await db<{ event_id: string }[]>(`slack_channels?select=event_id&channel_id=eq.${enc(ev0.channel_id)}`);
  if (!ch) return;
  const info = await slack("files.info", { file: ev0.file_id }, true) as { ok: boolean; file?: { name?: string; title?: string; user?: string; shares?: { public?: Record<string, { ts: string }[]>; private?: Record<string, { ts: string }[]> } } };
  if (!info.ok || !info.file) return;
  const a = await slack("auth.test", {}, true) as { user_id?: string };
  if (info.file.user && info.file.user === a.user_id) return;   // the bot's own file
  const sh = info.file.shares || {}, ts = (sh.public?.[ev0.channel_id] || sh.private?.[ev0.channel_id] || [])[0]?.ts;
  const name = String(info.file.name || info.file.title || "failas");
  const ins = await db<{ id: string }[]>("drive_uploads?on_conflict=slack_file,event_id", { method: "POST", headers: { Prefer: "resolution=ignore-duplicates,return=representation" },
    body: JSON.stringify({ event_id: ch.event_id, slack_file: ev0.file_id, slack_ts: ts ?? null, name }) });
  if (!ins.length) return;   // asked already
  const blocks = [
    { type: "section", text: { type: "mrkdwn", text: `📁 *Kur dėti „${name.replace(/[<>&*]/g, "")}“ renginio Google Drive?*` } },
    { type: "actions", elements: SUBS.map(([k, label]) => ({ type: "button", text: { type: "plain_text", text: label }, action_id: "gd_" + k, value: JSON.stringify({ u: ins[0].id, k }) }))
      .concat([{ type: "button", text: { type: "plain_text", text: "Nedėti" }, action_id: "gd_skip", value: JSON.stringify({ u: ins[0].id, k: "skip" }) }]) },
  ];
  await slack("chat.postMessage", { channel: ev0.channel_id, ...(ts ? { thread_ts: ts } : {}), text: `Kur dėti „${name}“ renginio Google Drive?`, blocks });
}
// a button pressed: the file from Slack straight into that Drive folder (streamed, not kept in memory)
async function onButton(p: { user?: { name?: string; username?: string }; channel?: { id: string }; message?: { ts: string }; actions?: { value: string }[]; response_url?: string }) {
  let v: { u?: string; k?: string } = {}; try { v = JSON.parse(p.actions?.[0]?.value || "{}"); } catch { /* bad */ }
  const say = async (text: string) => { if (p.response_url) await fetch(p.response_url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ replace_original: true, text }) }); };
  const [u] = await db<{ id: string; event_id: string; slack_file: string; name: string; drive_url: string | null }[]>(`drive_uploads?select=*&id=eq.${enc(v.u || "")}`);
  if (!u) { await say("Šis failas nebežinomas."); return; }
  const who = p.user?.name || p.user?.username || "";
  if (v.k === "skip") { await db(`drive_uploads?id=eq.${enc(u.id)}`, { method: "PATCH", body: JSON.stringify({ category: "skip", by_name: who, done_at: new Date().toISOString() }) }); await say(`„${u.name}“ – į Drive nedėta.`); return; }
  const sub = SUBS.find(([k]) => k === v.k); if (!sub) return;
  if (u.drive_url) { await say(`„${u.name}“ jau įkeltas: ${u.drive_url}`); return; }
  await say(`⏳ Keliama „${u.name}“ į ${sub[1]}…`);
  try {
    const ev = await loadEvent(u.event_id); if (!ev) throw new UserError("renginys nerastas");
    const row = await ensure(ev), parent = row.subs[sub[0]].id;
    const info = await slack("files.info", { file: u.slack_file }, true) as { ok: boolean; error?: string; file?: { url_private_download?: string; mimetype?: string; size?: number; name?: string } };
    if (!info.ok || !info.file?.url_private_download) throw new UserError("Slack failo negauna (" + (info.error || "nėra nuorodos") + ") – bot'ui reikia files:read teisės.");
    const src = await fetch(info.file.url_private_download, { headers: { Authorization: "Bearer " + E("SLACK_BOT_TOKEN") } });
    if (!src.ok || !src.body) throw new UserError("Slack failo atsisiųsti nepavyko (" + src.status + ")");
    const type = info.file.mimetype || "application/octet-stream";
    const start = await fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true&fields=id,webViewLink", {
      method: "POST", headers: { Authorization: "Bearer " + await gToken(), "Content-Type": "application/json; charset=UTF-8", "X-Upload-Content-Type": type, ...(info.file.size ? { "X-Upload-Content-Length": String(info.file.size) } : {}) },
      body: JSON.stringify({ name: info.file.name || u.name, parents: [parent] }) });
    const loc = start.headers.get("location"); if (!start.ok || !loc) throw new UserError("Google Drive įkėlimo pradėti nepavyko (" + start.status + ")");
    const up = await fetch(loc, { method: "PUT", headers: { "Content-Type": type, ...(info.file.size ? { "Content-Length": String(info.file.size) } : {}) }, body: src.body });
    const f = await up.json() as { id?: string; webViewLink?: string; error?: { message?: string } };
    if (!up.ok || !f.id) throw new UserError("Google Drive: " + (f.error?.message || up.status));
    await db(`drive_uploads?id=eq.${enc(u.id)}`, { method: "PATCH", body: JSON.stringify({ category: sub[0], drive_id: f.id, drive_url: f.webViewLink, by_name: who, error: null, done_at: new Date().toISOString() }) });
    await say(`✅ „${u.name}“ įkeltas į *${sub[1]}*${who ? " (" + who + ")" : ""} · <${row.subs[sub[0]].url}|atidaryti aplanką>`);
  } catch (e) {
    const m = (e as Error).message;
    await db(`drive_uploads?id=eq.${enc(u.id)}`, { method: "PATCH", body: JSON.stringify({ error: m.slice(0, 400) }) }).catch(() => {});
    await say(`⚠️ „${u.name}“ įkelti nepavyko: ${m}`);
  }
}

// who calls from the app: a signed-in member (role, may edit Renginiai)
async function caller(req: Request): Promise<{ id: string; role: string; level: string; edit: boolean } | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const res = await fetch(`${E("SUPABASE_URL")}/auth/v1/user`, { headers: { apikey: E("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` } });
  if (!res.ok) return null;
  const user = await res.json() as { id?: string };
  if (!user?.id) return null;
  const [p] = await db<{ role: string; level: string | null }[]>(`profiles?select=role,level&id=eq.${enc(user.id)}`);
  if (!p || ["pending", "blocked"].includes(p.role)) return null;
  let edit = p.role === "admin" || p.level === "super";
  if (!edit) { const [x] = await db<{ can_edit: boolean }[]>(`role_permissions?select=can_edit&section=eq.events&role=eq.${enc(p.role)}`); edit = !!(x && x.can_edit); }
  return { id: user.id, role: p.role, level: p.level || "", edit };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method === "GET") { const u = new URL(req.url); if (u.searchParams.has("oauth")) { try { return await oauthBack(u); } catch (e) { return page("Neprijungta", String((e as Error).message).replace(/[<>&]/g, "")); } } }
  if (req.method !== "POST") return json({ error: "POST" }, 405);
  const body = await req.text();
  try {
    // ---- Slack (Event Subscriptions and Interactivity point here) ----
    if (req.headers.get("x-slack-signature")) {
      if (!(await slackSigned(req, body))) return new Response("bad signature", { status: 401 });
      if (req.headers.get("x-slack-retry-num")) return new Response("ok");   // answered the first time already
      const ct = req.headers.get("content-type") || "";
      if (/x-www-form-urlencoded/.test(ct)) {
        const p = JSON.parse(new URLSearchParams(body).get("payload") || "{}");
        if (p.type === "block_actions" && String(p.actions?.[0]?.action_id || "").startsWith("gd_")) later(onButton(p));
        return new Response("");
      }
      const b = JSON.parse(body || "{}");
      if (b.type === "url_verification") return new Response(String(b.challenge || ""), { headers: { "Content-Type": "text/plain" } });
      if (b.type === "event_callback" && b.event?.type === "file_shared") later(onFileShared(b.event));
      return new Response("ok");
    }
    // ---- the app ----
    let b: { action?: string; event_id?: string; emails?: string[] } = {};
    try { b = JSON.parse(body || "{}"); } catch { /* empty */ }
    const who = await caller(req);
    if (!who) return json({ error: "Prisijunk iš naujo." }, 401);
    const action = String(b.action || "");
    if (action === "status") {
      if (!(who.role === "admin" || who.level === "super")) return json({ error: "Tik administratoriams." }, 403);
      const om = await oauthMode(), a = om ? await auth() : null;
      const out: Record<string, unknown> = { mode: om ? "oauth" : "sa", client: !!(E("GOOGLE_CLIENT_ID") && E("GOOGLE_CLIENT_SECRET")), email: a?.email || "", redirect: redirectUri(),
        sa: !!E("GOOGLE_SA_JSON"), root: !!E("GDRIVE_ROOT_ID"), slack: !!E("SLACK_SIGNING_SECRET"), on: await driveOn() };
      try { await gToken(); out.token = true; const f = await g<{ name?: string; driveId?: string }>(`files/${await root()}?fields=name,driveId`); out.name = f.name; out.shared_drive = !!f.driveId; }
      catch (e) { out.error = (e as Error).message; }
      const [n] = await db<{ count: number }[]>("event_drive?select=count").catch(() => [{ count: 0 }]); out.folders = n?.count ?? 0;
      return json(out);
    }
    if (action === "oauth_start") {
      if (!(who.role === "admin" || who.level === "super")) return json({ error: "Tik administratoriams." }, 403);
      return json({ ok: true, url: await oauthStart(who.id) });
    }
    if (action === "ensure" || action === "share") {
      if (!who.edit) return json({ error: "Aplanką kuria tie, kas redaguoja Renginius." }, 403);
      if (!(await driveOn())) return json({ ok: true, skipped: "išjungta" });
      const ev = await loadEvent(String(b.event_id || ""));
      if (!ev) return json({ error: "Renginys nerastas (dar neišsaugotas?)." }, 404);
      if (ev.deletedAt) return json({ error: "Renginys ištrintas." }, 400);
      if (action === "ensure") { const r = await ensure(ev); return json({ ok: true, url: r.url, subs: r.subs, name: r.name }); }
      return json({ ok: true, ...(await share(ev, Array.isArray(b.emails) ? b.emails.slice(0, 120) : [])) });
    }
    return json({ error: "Nežinomas veiksmas." }, 400);
  } catch (e) {
    if (e instanceof UserError) return json({ error: e.message }, 400);
    console.error("gdrive", (e as Error).message);
    return json({ error: "Klaida: " + (e as Error).message }, 500);
  }
});
