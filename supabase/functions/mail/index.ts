// Supabase Edge Function: mail
//
// Lets a team member read and answer their own @eventsolutions.lt mailbox
// (hosting IMAP/SMTP, e.g. Serveriai.lt) on the app's "El. paštas" page.
// The mailbox password is stored encrypted (AES-GCM, key = MAIL_SECRET) and
// never leaves this function.
//
// POST, Authorization: Bearer <user token>, body {"action": ...}
//   status                               -> { connected, email, unseen }
//   connect   {email, password}          -> checks the login, then saves it
//   disconnect
//   folders                              -> all folders with unread counts
//   list      {folder, page}             folder: "inbox" | "sent" | "trash" | "drafts" | "junk" | "archive" | a folder path
//   read      {folder, uid, peek}        -> full message (marks it read, unless peek)
//   flag      {folder, uid, flagged}     -> star / unstar
//   move      {folder, uid, to}          -> moves to another folder
//   attachment{folder, uid, index}       -> { filename, contentType, base64 } (index = body part, e.g. "2")
//   search    {q, from, to, subject, since, before, unseen, attachments, folder:"inbox"|"sent"|"all"}
//   send      {to, cc, subject, text, html?, sig?, quoted, inReplyTo, references, attachments:[{filename,contentType,base64}]}
//   seen      {folder, uid, seen}
//   delete    {folder, uid}              -> moves to Trash
//   settings / settings_save {settings:{sig, auto:{on,from,to,subject,text}}}
//   sync      {folder}                   -> brings public.mail_index up to date (the app reads the list from there)
//             and keeps the newest letters' text in public.mail_bodies (sql/mail_bodies.sql): the app opens
//             them from the database at once, without waiting for the mail server
//   (the signature is built from the profile: name, job title, phone)
// POST with header x-cron-secret: <CRON_SECRET> (every 10 min from pg_cron)
//   sends the automatic replies ("out of office") for everyone who has it on
//   body {"action":"sync_all"} (every minute): refreshes everyone's letter list
//
// Secrets: MAIL_SECRET (any long random text), optional MAIL_IMAP_HOST
// (default koala.serveriai.lt), MAIL_IMAP_PORT (993), MAIL_SMTP_HOST
// (same as IMAP), MAIL_SMTP_PORT (465). Supabase blocks ports 25 and 587,
// so SMTP must be 465 (SSL).

import { ImapFlow } from "npm:imapflow@1.0.171";
import nodemailer from "npm:nodemailer@6.9.16";
import MailComposer from "npm:nodemailer@6.9.16/lib/mail-composer/index.js";
import { Buffer } from "node:buffer";
import { LOGO_PNG_BASE64 } from "./logo.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const APPROVED = ["admin", "pm", "office", "tech", "freelance", "runner"];
// the app shows a warning when the deployed function is older than it expects
const VERSION = 30;
const PAGE = 25;
const MAX_SEND_BYTES = 15 * 1024 * 1024;

class UserError extends Error {}

function json(body: unknown, status = 200): Response {
  if (body && typeof body === "object" && !Array.isArray(body)) body = { v: VERSION, ...(body as Record<string, unknown>) };
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}
function env(name: string, fallback?: string): string {
  const v = Deno.env.get(name) || fallback;
  if (!v) throw new Error(`${name} is not configured`);
  return v;
}
async function db<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${env("SUPABASE_URL")}/rest/v1/${path}`, {
    ...init,
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`Database ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const text = await res.text();
  return (text ? JSON.parse(text) : null) as T;
}

type Person = { first_name: string | null; last_name: string | null; full_name: string | null; job_title?: string | null; phone?: string | null };
type Me = { id: string; role: string; name: string; person: Person };
// who is asking and their mailbox are kept for a minute, so opening letters
// one after another does not ask the database every time
const meCache = new Map<string, { me: Me; exp: number }>();
async function caller(req: Request): Promise<Me | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const hit = meCache.get(token);
  if (hit && hit.exp > Date.now()) return hit.me;
  const me = await callerFresh(token);
  if (me) {
    if (meCache.size > 200) meCache.clear();
    meCache.set(token, { me, exp: Date.now() + 60_000 });
  }
  return me;
}
async function callerFresh(token: string): Promise<Me | null> {
  const res = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, {
    headers: { apikey: env("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    console.error(`Sign-in token refused: auth ${res.status} ${(await res.text()).slice(0, 200)}`);
    return null;
  }
  const u = await res.json();
  if (!u?.id) return null;
  const [p] = await db<(Person & { role: string })[]>(`profiles?select=*&id=eq.${u.id}`);
  if (!p || !APPROVED.includes(p.role)) throw new UserError("Tavo paskyra dar nepatvirtinta arba užblokuota.");
  if (p.role !== "admin") {
    // Admin → „Ką gali kiekvienas lygis“ → El. paštas
    const [perm] = await db<{ can_view: boolean; can_edit: boolean }[]>(
      `role_permissions?select=can_view,can_edit&role=eq.${p.role}&section=eq.mail`,
    );
    if (!perm || !(perm.can_view || perm.can_edit)) throw new UserError("Tavo lygiui el. paštas išjungtas (Admin skiltyje).");
  }
  return { id: u.id, role: p.role, name: personName(p), person: p };
}

// ---------- password encryption ----------
async function aesKey(): Promise<CryptoKey> {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(env("MAIL_SECRET")));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
export async function seal(plain: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(), new TextEncoder().encode(plain)));
  return Buffer.concat([iv, ct]).toString("base64");
}
export async function unseal(sealed: string): Promise<string> {
  const b = Buffer.from(sealed, "base64");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.subarray(0, 12) }, await aesKey(), b.subarray(12));
  return new TextDecoder().decode(pt);
}

// ---------- IMAP / SMTP ----------
// reader: where letters are read from, when not the company mail server (e.g. Gmail that the
// server forwards to); sending always goes from the company mailbox
type Account = { email: string; password: string; host?: string; reader?: Account };
const GMAIL_IMAP = "imap.gmail.com";
const readerOf = (a: Account): Account => a.reader ?? a;
const insecure = () => Deno.env.get("MAIL_TLS_INSECURE") === "1"; // tests only
// the last lines of the talk with the mail server, printed to the function
// log when a letter does not open (passwords are never logged by imapflow;
// login lines are dropped anyway)
type Trail = string[];
function trailLogger(trail: Trail) {
  const t0 = Date.now();
  const add = (o: { src?: string; msg?: string }) => {
    const m = String(o?.msg ?? "");
    if (!m || o?.src === "c" || /LOGIN|AUTHENTICATE/i.test(m)) return;   // "c" = the login continuation
    trail.push(`+${Date.now() - t0}ms ${o.src ?? "-"} ${m.slice(0, 160)}`);
    if (trail.length > 14) trail.shift();
  };
  return { debug: add, info: add, warn: add, error: add, trace: () => {} };
}
const trails = new WeakMap<ImapFlow, Trail>();
function imapClient(a: Account) {
  const trail: Trail = [];
  const c = new ImapFlow({
    host: a.host || env("MAIL_IMAP_HOST", "koala.serveriai.lt"),
    port: Number(env("MAIL_IMAP_PORT", "993")),
    secure: true,
    auth: { user: a.email, pass: a.password },
    tls: { rejectUnauthorized: !insecure() },
    connectionTimeout: 15000,
    greetingTimeout: 10000,
    logger: trailLogger(trail),
  });
  trails.set(c, trail);
  return c;
}
// The connection to the mail server is kept open for a minute after use:
// while the function stays warm, the next letter opens without logging in
// again (that was most of the waiting).
type Pooled = { c: ImapFlow; ready: Promise<void>; timer?: ReturnType<typeof setTimeout>; used: number; busy?: boolean; boxes?: { at: number; list: Box[] } };
type Box = { path: string; name: string; delimiter: string; specialUse?: string; flags?: Set<string>; status?: { messages?: number; unseen?: number } };
const pool = new Map<string, Pooled>();
const IDLE_MS = 60_000;
const poolKey = (a: Account) => (a.host || "") + "\u0000" + a.email + "\u0000" + a.password;
function connectError(e: unknown): UserError {
  const err = e as { authenticationFailed?: boolean };
  return new UserError(err?.authenticationFailed ? "Neteisingas el. paštas arba slaptažodis." : "Nepavyko prisijungti prie pašto serverio.");
}
function drop(k: string, p: Pooled) {
  if (pool.get(k) === p) pool.delete(k);
  clearTimeout(p.timer);
  try { p.c.close(); } catch { /* already closed */ }
}
async function connectNew(a: Account): Promise<ImapFlow> {
  const c = imapClient(a);
  c.on("error", () => {});
  try {
    await withTimeout(c.connect(), 12_000, "connect");
  } catch (e) {
    try { c.close(); } catch { /* ignore */ }
    throw e instanceof OpTimeout ? slow("prisijungimas") : connectError(e);
  }
  return c;
}
class OpTimeout extends Error {}
// "the mail server did not answer in time" — the step that hung is shown too
type Trace = { s: string; c?: ImapFlow; info?: string };
function slow(step: string): UserError {
  const e = new UserError(`Pašto serveris per ilgai neatsako (${step}). Pabandyk dar kartą.`);
  (e as UserError & { transient?: boolean }).transient = true;
  return e;
}
const isTransient = (e: unknown) => !(e instanceof UserError) || !!(e as { transient?: boolean }).transient;
function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let t: ReturnType<typeof setTimeout>;
  return Promise.race([p, new Promise<T>((_, rej) => { t = setTimeout(() => rej(new OpTimeout(what + " timeout")), ms); })]).finally(() => clearTimeout(t));
}
// the kept connection is used only when it is free and answers a quick NOOP;
// otherwise this request gets its own connection (one stuck command must not
// hold up everything else)
async function pooled(a: Account, tr: Trace, fresh = false): Promise<{ c: ImapFlow; p?: Pooled }> {
  const k = poolKey(a);
  const p = fresh ? undefined : pool.get(k);
  if (fresh) { tr.s = "prisijungimas"; return { c: await connectNew(a) }; }
  if (p && !p.busy && p.c.usable) {
    p.busy = true;
    clearTimeout(p.timer);
    if (Date.now() - p.used < 5_000) return { c: p.c, p };
    tr.s = "ryšio patikra";
    const ok = await withTimeout(p.c.noop().then(() => true, () => false), 3000, "noop").catch(() => false);
    if (ok) return { c: p.c, p };
    drop(k, p);
  } else if (p && !p.c.usable) drop(k, p);
  tr.s = "prisijungimas";
  const c = await connectNew(a);
  if (!pool.has(k)) {
    const np: Pooled = { c, ready: Promise.resolve(), used: Date.now(), busy: true };
    pool.set(k, np);
    c.on("close", () => { if (pool.get(k) === np) pool.delete(k); });
    return { c, p: np };
  }
  return { c };                                     // a one-off connection, closed after use
}
const OP_MS = Number(Deno.env.get("MAIL_OP_MS") || 15_000);
async function withImap<T>(a: Account, fn: (c: ImapFlow) => Promise<T>, retry = true, ms = OP_MS, tr: Trace = { s: "" }, fresh = false): Promise<T> {
  const k = poolKey(a);
  const once = async () => {
    const { c, p } = await pooled(a, tr, fresh);
    tr.s = "komanda";
    try {
      return await withTimeout(fn(c), ms, "imap");
    } catch (e) {
      if (!(e instanceof UserError)) { if (p) drop(k, p); else try { c.close(); } catch { /* ignore */ } }   // a broken connection is not reused
      throw e;
    } finally {
      if (p && pool.get(k) === p) {
        p.busy = false;
        p.used = Date.now();
        clearTimeout(p.timer);
        p.timer = setTimeout(() => {
          if (pool.get(k) !== p || p.busy) return;
          pool.delete(k);
          p.c.logout().catch(() => p.c.close());
        }, IDLE_MS);
        try { Deno.unrefTimer(p.timer as unknown as number); } catch { /* older runtime */ }
      } else if (!p) c.logout().catch(() => c.close());
    }
  };
  try {
    return await once();
  } catch (e) {
    if (e instanceof UserError || !retry) {
      if (e instanceof OpTimeout) throw slow(tr.s);
      throw e;
    }
    console.error("imap retry after:", (e as Error).message, "at", tr.s);
    try {
      return await once();
    } catch (e2) {
      if (e2 instanceof UserError) throw e2;
      console.error("imap failed again:", (e2 as Error).message, "at", tr.s);
      throw slow(tr.s);
    }
  }
}
// every folder of the mailbox (kept for a minute per connection)
async function boxes(c: ImapFlow, fresh = false): Promise<Box[]> {
  const p = [...pool.values()].find((x) => x.c === c);
  if (!fresh && p?.boxes && Date.now() - p.boxes.at < 60_000) return p.boxes.list;
  const list = (await c.list()) as unknown as Box[];
  if (p) p.boxes = { at: Date.now(), list };
  return list;
}
const SPECIAL: Record<string, { use: string; re: RegExp; name: string; create: boolean }> = {
  sent:    { use: "\\Sent",    re: /^(inbox[./])?(sent|išsiųsti|sent items|sent messages)$/i, name: "Sent", create: true },
  trash:   { use: "\\Trash",   re: /^(inbox[./])?(trash|deleted|deleted items|šiukšl\S*)$/i, name: "Trash", create: true },
  drafts:  { use: "\\Drafts",  re: /^(inbox[./])?(drafts|juodraščiai)$/i, name: "Drafts", create: false },
  junk:    { use: "\\Junk",    re: /^(inbox[./])?(junk|junk e-mail|spam|brukalas)$/i, name: "Junk", create: false },
  archive: { use: "\\Archive", re: /^(inbox[./])?(archive|archyvas)$/i, name: "Archive", create: true },
  // Gmail's own: Starred, All Mail, Important
  starred: { use: "\\Flagged", re: /^\[gmail\]\/(starred|pažymėti žvaigždute)$/i, name: "Starred", create: false },
  all:     { use: "\\All",     re: /^\[gmail\]\/(all mail|visi laiškai)$/i, name: "All", create: false },
  important: { use: "\\Important", re: /^\[gmail\]\/(important|svarbūs)$/i, name: "Important", create: false },
};
export function specialOf(b: { path: string; specialUse?: string }): string {
  if (b.path.toUpperCase() === "INBOX") return "inbox";
  for (const [k, v] of Object.entries(SPECIAL)) if (b.specialUse === v.use) return k;
  for (const [k, v] of Object.entries(SPECIAL)) if (v.re.test(b.path)) return k;
  return "";
}
async function folderPath(c: ImapFlow, folder: string): Promise<string> {
  if (folder === "inbox" || folder.toUpperCase() === "INBOX") return "INBOX";
  const list = await boxes(c);
  const sp = SPECIAL[folder];
  if (sp) {
    const hit = list.find((m) => m.specialUse === sp.use) ?? list.find((m) => sp.re.test(m.path));
    if (hit) return hit.path;
    if (!sp.create) throw new UserError("Tokio aplanko nėra.");
    // create it the way most hosting servers (Dovecot) name it
    const sep = list.find((m) => m.path.toUpperCase() !== "INBOX")?.delimiter ?? ".";
    const path = list.some((m) => m.path.toUpperCase().startsWith("INBOX" + sep)) ? `INBOX${sep}${sp.name}` : sp.name;
    await c.mailboxCreate(path).catch(() => {});
    await boxes(c, true);
    return path;
  }
  // any other existing folder, by its path
  const hit = list.find((m) => m.path === folder);
  if (!hit || hit.flags?.has("\\Noselect")) throw new UserError("Tokio aplanko nėra.");
  return hit.path;
}
async function folders(a: Account, only = "all") {
  return await withImap(a, async (c) => {
    const list = (await c.list({ statusQuery: { messages: true, unseen: true } })) as unknown as Box[];
    // only the work (or only the personal) letters shown: the counts are of those letters
    if (only !== "all") {
      const t0 = Date.now();
      for (const b of list) {
        if (b.flags?.has("\\Noselect") || b.flags?.has("\\NonExistent") || Date.now() - t0 > 20_000) continue;
        const key = specialOf(b) || b.path;
        try {
          const lock = await c.getMailboxLock(b.path);
          try {
            const w = await workUids(c, key), keep = (u: number) => only === "work" ? w.has(u) : !w.has(u);
            const unseen = (((await c.search({ seen: false }, { uid: true })) || []) as number[]).filter(keep).length;
            const total = only === "work" ? w.size : Math.max(0, (b.status?.messages ?? 0) - w.size);
            b.status = { messages: total, unseen };
          } finally { lock.release(); }
        } catch { /* a folder that cannot be opened keeps its own numbers */ }
      }
    }
    const p = [...pool.values()].find((x) => x.c === c); if (p) p.boxes = { at: Date.now(), list };
    const order = ["starred", "important", "sent", "drafts", "all", "junk", "trash", "archive"];
    // two folders of one kind (e.g. „Junk“ and „Spam“): only the one the app opens is shown as that kind,
    // the other keeps its own name (it was listed twice as „Brukalas“)
    const pick: Record<string, string> = {};
    for (const [k, sp] of Object.entries(SPECIAL)) { const hit = list.find((m) => m.specialUse === sp.use) ?? list.find((m) => sp.re.test(m.path)); if (hit) pick[k] = hit.path; }
    const rows = list
      .filter((b) => !b.flags?.has("\\Noselect") && !b.flags?.has("\\NonExistent"))
      .map((b) => {
        let special = specialOf(b);
        if (special && special !== "inbox" && pick[special] && pick[special] !== b.path) special = "";
        const segs = b.path.split(b.delimiter || "/").length;
        return { path: b.path, name: special === "inbox" ? "INBOX" : b.name, special, level: special ? 0 : Math.max(0, segs - 1), unseen: b.status?.unseen ?? 0, total: b.status?.messages ?? 0 };
      });
    // INBOX, its own sub-folders, then Drafts / Sent / Junk / Trash / Archive, then the rest
    const rank = (x: { path: string; special: string }) =>
      x.special === "inbox" ? 0 : !x.special && /^inbox[./]/i.test(x.path) ? 1 : x.special ? 2 + order.indexOf(x.special) : 20;
    return rows.sort((x, y) => rank(x) - rank(y) || x.path.localeCompare(y.path, "lt"));
  });
}

type Addr = { name?: string; address?: string };
const addr = (l?: Addr[]) => (l ?? []).map((x) => ({ name: x.name || "", address: x.address || "" }));

async function list(a: Account, folder: string, page: number) {
  return await withImap(a, async (c) => {
    const path = await folderPath(c, folder);
    const lock = await c.getMailboxLock(path);
    try {
      const total = (c.mailbox && c.mailbox.exists) || 0;
      const end = total - page * PAGE, start = Math.max(1, end - PAGE + 1);
      const items: unknown[] = [];
      if (end >= 1) {
        for await (const m of c.fetch(`${start}:${end}`, { uid: true, envelope: true, flags: true, bodyStructure: true, internalDate: true, size: true })) {
          items.push({
            uid: m.uid, folder,
            date: (m.envelope?.date ?? m.internalDate)?.toISOString?.() ?? null,
            subject: m.envelope?.subject || "",
            from: addr(m.envelope?.from),
            to: addr(m.envelope?.to),
            seen: m.flags?.has("\\Seen") ?? false,
            answered: m.flags?.has("\\Answered") ?? false,
            flagged: m.flags?.has("\\Flagged") ?? false,
            attachments: hasAttachments(m.bodyStructure as Node),
            size: m.size,
          });
        }
      }
      items.reverse();
      const unseen = folder === "inbox" ? ((await c.status("INBOX", { unseen: true })).unseen ?? 0) : undefined;
      return { total, page, pages: Math.max(1, Math.ceil(total / PAGE)), items, unseen };
    } finally {
      lock.release();
    }
  });
}

// ---------- the letter list kept in the database (public.mail_index, sql/mail_index.sql) ----------
// The app reads the list straight from the database (instant, sorted by
// date); this keeps it in step with the mail server: new letters are added,
// gone ones removed, read / star flags updated. It runs every minute from
// pg_cron for everyone and when someone opens a folder.
// First run: the last ~60 days and the newest letters by number come first,
// the older ones follow in the next runs (SYNC_BATCH per run).
const SYNC_BATCH = 500, SYNC_MS = 25_000;
type SyncState = { uidvalidity: string | null; modseq: string | null; synced_at?: string };
type IdxRow = { user_id: string; folder: string; uid: number; date: string | null; subject: string; from_addr: unknown; to_addr: unknown; seen: boolean; answered: boolean; flagged: boolean; attachments: boolean; size: number | null; updated_at: string; acct?: string; cat?: string; snippet?: string };
const enc = encodeURIComponent;
async function dbAllUids(user: string, folder: string): Promise<number[]> {
  const out: number[] = [];
  for (let off = 0; ; off += 1000) {
    const part = await db<{ uid: number }[]>(`mail_index?select=uid&user_id=eq.${user}&folder=eq.${enc(folder)}&order=uid.asc&limit=1000&offset=${off}`);
    part.forEach((r) => out.push(Number(r.uid)));
    if (part.length < 1000) break;
  }
  return out;
}
async function idxUpsert(rows: Partial<IdxRow>[]) {
  for (let i = 0; i < rows.length; i += 300) {
    await db("mail_index?on_conflict=user_id,folder,uid", {
      method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" }, body: JSON.stringify(rows.slice(i, i + 300)),
    });
  }
}
async function idxDelete(user: string, folder: string, uids: number[]) {
  for (let i = 0; i < uids.length; i += 300) {
    await db(`mail_index?user_id=eq.${user}&folder=eq.${enc(folder)}&uid=in.(${uids.slice(i, i + 300).join(",")})`, { method: "DELETE", headers: { Prefer: "return=minimal" } });
  }
}
// the app's own changes (read, star, move, delete) show at once, without waiting for the next sync
async function idxPatch(user: string, folder: string, uid: number, patch: Partial<IdxRow>) {
  try { await db(`mail_index?user_id=eq.${user}&folder=eq.${enc(folder)}&uid=eq.${uid}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ ...patch, updated_at: new Date().toISOString() }) }); }
  catch (e) { console.error("mail_index patch", (e as Error).message); }
}
async function idxGone(user: string, folder: string, uid: number) {
  try { await idxDelete(user, folder, [uid]); } catch (e) { console.error("mail_index delete", (e as Error).message); }
  await bodyDelete(user, folder, [uid]);
}
// ---------- the newest letters' text kept in the database (public.mail_bodies) ----------
// Opening a letter then needs no mail server at all; letters not kept there are read live as before.
const BODY_MAX_JSON = 1_500_000, BODY_PER_RUN = 15, BODY_MS = 12_000, BODY_KEEP = 60;
let bodiesOk = true;     // the table may not exist yet (sql/mail_bodies.sql not run): then nothing is kept
const bodySkip = new Map<string, number>();   // letters whose text could not be kept: not tried again for a while
// the first words of a letter, shown in the list after the subject (as Gmail does)
let snipOk = true;
export function snippetOf(d: { text?: string; html?: string }): string {
  let t = String(d?.text || "");
  if (!t.trim() && d?.html) {
    t = String(d.html).slice(0, 200_000).replace(/<(style|script|head|title)\b[\s\S]*?<\/\1\s*>/gi, " ").replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/&quot;/gi, '"').replace(/&#39;/gi, "'").replace(/&[a-z0-9#]+;/gi, " ");
  }
  return t.replace(/^>.*$/gm, " ").replace(/\s+/g, " ").trim().slice(0, 200);
}
async function snipSave(user: string, folder: string, uid: number, data: unknown) {
  if (!snipOk) return;
  const snippet = snippetOf(data as { text?: string; html?: string }); if (!snippet) return;
  try { await db(`mail_index?user_id=eq.${user}&folder=eq.${enc(folder)}&uid=eq.${uid}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ snippet }) }); }
  catch (e) { if (/snippet/.test((e as Error).message)) snipOk = false; }
}
async function bodySave(user: string, folder: string, uid: number, data: unknown) {
  snipSave(user, folder, uid, data).catch(() => {});
  if (!bodiesOk) return;
  const json = JSON.stringify(data);
  if (json.length > BODY_MAX_JSON) return;
  try {
    await db("mail_bodies?on_conflict=user_id,folder,uid", {
      method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify({ user_id: user, folder, uid, data, fetched_at: new Date().toISOString() }),
    });
  } catch (e) { if (/mail_bodies|relation|schema cache/i.test((e as Error).message)) bodiesOk = false; console.error("mail_bodies save", (e as Error).message); }
}
async function bodyDelete(user: string, folder: string, uids: number[]) {
  if (!bodiesOk || !uids.length) return;
  try { for (let i = 0; i < uids.length; i += 300) await db(`mail_bodies?user_id=eq.${user}&folder=eq.${enc(folder)}&uid=in.(${uids.slice(i, i + 300).join(",")})`, { method: "DELETE", headers: { Prefer: "return=minimal" } }); }
  catch (e) { console.error("mail_bodies delete", (e as Error).message); }
}
// after a sync, on the same connection: the newest letters whose text is not kept yet
async function bodyPrefetch(c: ImapFlow, user: string, folder: string, present: number[], big = false, quick = false) {
  if (!bodiesOk || !present.length) return 0;
  const t0 = Date.now();
  // Gmail answers fast: many more letters are kept ready (they open at once)
  const KEEP = big ? 400 : BODY_KEEP, PER_RUN = quick ? 5 : big ? 60 : BODY_PER_RUN, MS = quick ? 5_000 : big ? 25_000 : BODY_MS;
  const newest = present.slice().sort((x, y) => y - x).slice(0, KEEP);
  let have: { uid: number }[] = [];
  try { have = await db<{ uid: number }[]>(`mail_bodies?select=uid&user_id=eq.${user}&folder=eq.${enc(folder)}&limit=2000`); }
  catch (e) { if (/mail_bodies|relation|schema cache/i.test((e as Error).message)) bodiesOk = false; return 0; }
  const hset = new Set(have.map((r) => Number(r.uid)));
  // the ones that dropped out of the newest are let go (the database keeps only the newest letters)
  const keep = new Set(newest);
  await bodyDelete(user, folder, [...hset].filter((u) => !keep.has(u)));
  let done = 0, failed = 0;
  for (const uid of newest) {
    if (done >= PER_RUN || Date.now() - t0 > MS) break;
    if (hset.has(uid)) continue;
    if ((bodySkip.get(`${user}/${folder}/${uid}`) ?? 0) > Date.now()) continue;
    try { await bodySave(user, folder, uid, await readOn(c, folder, uid, true, true, { s: "" })); done++; failed = 0; }
    catch (e) {
      // one letter that fails (a big newsletter) no longer stops the others: it is tried again only after an hour;
      // two failures in a row mean the connection itself is in trouble – the rest on the next run
      console.error(`mail_bodies ${folder}/${uid}`, (e as Error).message);
      bodySkip.set(`${user}/${folder}/${uid}`, Date.now() + 3600_000);
      if (++failed >= 2) break;
    }
  }
  return done;
}
// work or personal: a letter to (or, in Sent / Drafts, from) a …@eventsolutions.lt address is a work letter
let acctOk = true;     // mail_index.acct may not exist yet (sql/mail_acct.sql not run)
function acctOf(folder: string, e?: { from?: Addr[]; to?: Addr[]; cc?: Addr[] }): string {
  const dom = "@" + (Deno.env.get("MAIL_WORK_DOMAIN") || "eventsolutions.lt").toLowerCase();
  const list = folder === "sent" || folder === "drafts" ? (e?.from ?? []) : [...(e?.to ?? []), ...(e?.cc ?? [])];
  return list.some((x) => String(x.address || "").toLowerCase().endsWith(dom)) ? "work" : "personal";
}
function idxRow(user: string, folder: string, m: { uid: number; envelope?: { date?: Date; subject?: string; from?: Addr[]; to?: Addr[]; cc?: Addr[] }; internalDate?: Date | string; flags?: Set<string>; bodyStructure?: unknown; size?: number }): Partial<IdxRow> {
  const d = m.envelope?.date ?? (m.internalDate ? new Date(m.internalDate as string) : null);
  return {
    ...(acctOk ? { acct: acctOf(folder, m.envelope) } : {}),
    user_id: user, folder, uid: m.uid,
    date: d && !isNaN(+d) ? new Date(d).toISOString() : null,
    subject: (m.envelope?.subject || "").slice(0, 998),
    from_addr: addr(m.envelope?.from), to_addr: addr(m.envelope?.to),
    seen: m.flags?.has("\\Seen") ?? false, answered: m.flags?.has("\\Answered") ?? false, flagged: m.flags?.has("\\Flagged") ?? false,
    attachments: hasAttachments(m.bodyStructure as Node), size: m.size ?? null, updated_at: new Date().toISOString(),
  };
}
// Gmail's own tabs (Primary, Promotions, Social, Updates, Forums): which tab each inbox letter is in
const GM_CATS = ["social", "promotions", "updates", "forums"];
let catOk = true;     // mail_index.cat may not exist yet (sql/mail_gmail.sql not run)
async function gmCats(c: ImapFlow, uids: number[]): Promise<Map<number, string>> {
  const out = new Map<number, string>(uids.map((u) => [u, "primary"]));
  for (let i = 0; i < uids.length; i += 300) {
    const set = uids.slice(i, i + 300).join(",");
    for (const cat of GM_CATS) {
      const hit = ((await c.search({ uid: set, gmraw: "category:" + cat }, { uid: true }).catch(() => [])) || []) as number[];
      for (const u of hit) out.set(u, cat);
    }
  }
  return out;
}
// a new letter to a work address (…@eventsolutions.lt): a notification on the phone and the computer
const WORK_DOMAIN = (Deno.env.get("MAIL_WORK_DOMAIN") || "eventsolutions.lt").toLowerCase();
// a new work letter while the automatic reply is on: answered right away (not at the next minute), and no notification
async function autoReplyNow(user: string) {
  const [row] = await db<{ user_id: string; email: string; secret: string; reader?: Reader | null; settings: Settings; state: { auto?: AutoState } | null }[]>(
    `mail_accounts?select=user_id,email,secret,reader,settings,state&user_id=eq.${user}`);
  if (row && autoActive(row.settings?.auto)) return await autoReplyFor(row);
  return 0;
}
async function notifyNew(user: string, items: { uid: number; from: string; subject: string }[]) {
  if (!items.length) return;
  const secret = Deno.env.get("CRON_SECRET"); if (!secret) return;
  await fetch(env("SUPABASE_URL") + "/functions/v1/push-notify", {
    method: "POST", headers: { "Content-Type": "application/json", "x-cron-secret": secret },
    body: JSON.stringify({ mode: "mail-new", user_id: user, items: items.slice(-5) }),
  }).catch((e) => console.error("mail notify", e?.message));
}
// „Kokius laiškus rodyti“ (Nustatymai, kept in the profile): with Gmail only the work or only the personal letters are kept
async function acctPref(user: string): Promise<string> {
  try { const [p] = await db<{ notify_prefs: { mlAcct?: string } | null }[]>(`profiles?select=notify_prefs&id=eq.${user}`); const v = p?.notify_prefs?.mlAcct; return v === "work" || v === "personal" ? v : "all"; }
  catch { return "all"; }
}
async function syncFolder(user: string, a: Account, folder: string, quick = false) {
  const t0 = Date.now();
  let wantAuto = false;
  const only = a.host === GMAIL_IMAP ? await acctPref(user) : "all";
  const gmTabs = a.host === GMAIL_IMAP && folder === "inbox" && catOk;
  const [st] = await db<SyncState[]>(`mail_sync?select=uidvalidity,modseq,synced_at&user_id=eq.${user}&folder=eq.${enc(folder)}`);
  return await withImap(a, async (c) => {
    const path = await folderPath(c, folder);
    let present: number[] = [];
    const res = await (async () => {
    const lock = await c.getMailboxLock(path);
    try {
      const mb = c.mailbox as unknown as { exists?: number; uidValidity?: bigint; highestModseq?: bigint };
      const validity = mb.uidValidity != null ? String(mb.uidValidity) : null;
      let known: number[] = [];
      if (st && st.uidvalidity && validity && st.uidvalidity !== validity) {
        await db(`mail_index?user_id=eq.${user}&folder=eq.${enc(folder)}`, { method: "DELETE", headers: { Prefer: "return=minimal" } });   // the folder was re-created: start over
      } else known = await dbAllUids(user, folder);
      // a kept connection may still hold the folder's old state: ask the server for the current one
      present = ((await c.search({ all: true }, { uid: true })) || []) as number[];
      if (only !== "all") {
        // the work letters: to / copy (in Sent: from) …@eventsolutions.lt – asked from Gmail, not read one by one
        const work = await workUids(c, folder);
        present = present.filter((u) => only === "work" ? work.has(u) : !work.has(u));
      }
      const now = await c.status(path, { highestModseq: true }).catch(() => null) as { highestModseq?: bigint } | null;
      const modseq = now?.highestModseq ?? mb.highestModseq;
      const pset = new Set(present), kset = new Set(known);
      const removed = known.filter((u) => !pset.has(u));
      if (removed.length) { await idxDelete(user, folder, removed); await bodyDelete(user, folder, removed); }
      // what to add now: recent letters first, then the newest by number, then older ones in later runs
      const fresh = present.filter((u) => !kset.has(u));
      let take: number[] = [];
      if (fresh.length) {
        const since = new Date(Date.now() - 60 * 86400_000);
        const recent = new Set(((await c.search({ since }, { uid: true })) || []) as number[]);
        const byNew = fresh.slice().sort((x, y) => y - x);
        take = byNew.filter((u) => recent.has(u)).slice(0, SYNC_BATCH);
        for (const u of byNew) { if (take.length >= SYNC_BATCH) break; if (!recent.has(u)) take.push(u); }
      }
      let added = 0;
      // only letters that really just came (not the first listing of a mailbox)
      const watch = folder === "inbox" && !!st?.synced_at && (!validity || st.uidvalidity === validity);
      const news: { uid: number; from: string; subject: string }[] = [];
      for (let i = 0; i < take.length && Date.now() - t0 < SYNC_MS; i += 150) {
        const rows: Partial<IdxRow>[] = [];
        for await (const m of c.fetch(take.slice(i, i + 150).join(","), { uid: true, envelope: true, flags: true, bodyStructure: true, internalDate: true, size: true }, { uid: true })) {
          rows.push(idxRow(user, folder, m as never));
          const mm = m as { uid: number; flags?: Set<string>; internalDate?: Date; envelope?: { subject?: string; from?: Addr[]; to?: Addr[]; cc?: Addr[] } };
          const got = mm.internalDate ? new Date(mm.internalDate).getTime() : 0;
          const work = [...(mm.envelope?.to ?? []), ...(mm.envelope?.cc ?? [])].some((x) => String(x.address || "").toLowerCase().endsWith("@" + WORK_DOMAIN));
          if (watch && work && !mm.flags?.has("\\Seen") && Date.now() - got < 30 * 60_000) {
            const f = mm.envelope?.from?.[0];
            news.push({ uid: mm.uid, from: (f?.name || f?.address || "").slice(0, 80), subject: (mm.envelope?.subject || "(be temos)").slice(0, 140) });
          }
        }
        if (gmTabs) { const cats = await gmCats(c, rows.map((r) => r.uid!)); rows.forEach((r) => { (r as Record<string, unknown>).cat = cats.get(r.uid!) || "primary"; }); }
        try { await idxUpsert(rows); }
        catch (e) {
          const msg = (e as Error).message;
          if (/acct/.test(msg)) acctOk = false; else if (gmTabs && /cat/.test(msg)) catOk = false; else throw e;
          rows.forEach((r) => { if (!acctOk) delete (r as Record<string, unknown>).acct; if (!catOk) delete (r as Record<string, unknown>).cat; });
          await idxUpsert(rows);
        }
        added += rows.length;
      }
      // read / answered / star changes of the letters already listed
      let changed = 0;
      const stillKnown = known.filter((u) => pset.has(u));
      if (stillKnown.length && Date.now() - t0 < SYNC_MS) {
        const flagRows = new Map<number, Partial<IdxRow>>();
        const push = (m: { uid: number; flags?: Set<string> }) => { if (kset.has(m.uid)) flagRows.set(m.uid, { user_id: user, folder, uid: m.uid, seen: m.flags?.has("\\Seen") ?? false, answered: m.flags?.has("\\Answered") ?? false, flagged: m.flags?.has("\\Flagged") ?? false }); };
        const tracked = modseq != null && st?.modseq && validity === st.uidvalidity;
        // the server tells what changed since the last run (CONDSTORE) …
        if (tracked && String(modseq) !== st!.modseq) {
          for await (const m of c.fetch("1:*", { uid: true, flags: true }, { uid: true, changedSince: BigInt(st!.modseq!) })) push(m as never);
        }
        // … and the newest letters are always checked as well (400 without change tracking)
        const last = stillKnown.slice(tracked ? -150 : -400);
        for await (const m of c.fetch(last.join(","), { uid: true, flags: true }, { uid: true })) push(m as never);
        // only the rows that really differ are written
        const cur = await db<{ uid: number; seen: boolean; answered: boolean; flagged: boolean }[]>(
          `mail_index?select=uid,seen,answered,flagged&user_id=eq.${user}&folder=eq.${enc(folder)}&uid=in.(${[...flagRows.keys()].slice(0, 900).join(",") || 0})&limit=1000`);
        const was = new Map(cur.map((r) => [Number(r.uid), r]));
        const diff = [...flagRows.values()].filter((r) => { const w = was.get(r.uid!); return !w || w.seen !== r.seen || w.answered !== r.answered || w.flagged !== r.flagged; });
        if (diff.length) { await idxUpsert(diff); changed = diff.length; }
      }
      // letters listed before „work / personal“ was kept: up to a thousand each run (only the addresses are read)
      if (acctOk && !quick && Date.now() - t0 < SYNC_MS) {
        try {
          const todo = (await db<{ uid: number }[]>(`mail_index?select=uid&user_id=eq.${user}&folder=eq.${enc(folder)}&acct=is.null&order=uid.desc&limit=1000`)).map((r) => Number(r.uid)).filter((u) => pset.has(u));
          const rows: Partial<IdxRow>[] = [];
          for (let i = 0; i < todo.length && Date.now() - t0 < SYNC_MS; i += 250) {
            for await (const m of c.fetch(todo.slice(i, i + 250).join(","), { uid: true, envelope: true }, { uid: true })) {
              const mm = m as { uid: number; envelope?: { from?: Addr[]; to?: Addr[]; cc?: Addr[] } };
              rows.push({ user_id: user, folder, uid: mm.uid, acct: acctOf(folder, mm.envelope) } as Partial<IdxRow>);
            }
          }
          if (rows.length) await idxUpsert(rows);
        } catch (e) { if (/acct/.test((e as Error).message)) acctOk = false; else console.error("acct backfill", (e as Error).message); }
      }
      // letters listed before the tabs were known: a few hundred each run
      if (gmTabs && catOk && !quick && Date.now() - t0 < SYNC_MS) {
        try {
          const todo = (await db<{ uid: number }[]>(`mail_index?select=uid&user_id=eq.${user}&folder=eq.inbox&cat=is.null&order=uid.desc&limit=300`)).map((r) => Number(r.uid)).filter((u) => pset.has(u));
          if (todo.length) { const cats = await gmCats(c, todo); await idxUpsert(todo.map((u) => ({ user_id: user, folder, uid: u, cat: cats.get(u) || "primary" } as Partial<IdxRow>))); }
        } catch (e) { if (/cat/.test((e as Error).message)) catOk = false; else console.error("gmail tabs", (e as Error).message); }
      }
      if (news.length) {
        if (autoActive((await settingsOf(user)).auto)) wantAuto = true;    // away: an automatic reply instead of a notification
        else await notifyNew(user, news);
      }
      const unseen = (((await c.search({ seen: false }, { uid: true })) || []) as number[]).filter((u) => pset.has(u)).length;
      const remaining = fresh.length - added;
      await db("mail_sync?on_conflict=user_id,folder", {
        method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify({ user_id: user, folder, uidvalidity: validity, modseq: modseq != null ? String(modseq) : null, total: present.length, unseen, remaining, synced_at: new Date().toISOString() }),
      });
      return { total: present.length, unseen, added, removed: removed.length, changed, remaining, ms: Date.now() - t0 };
    } finally {
      lock.release();
    }
    })();
    // the quick check (every 15 s): only the few newest letters are made ready
    (res as Record<string, unknown>).bodies = await bodyPrefetch(c, user, folder, present, a.host === GMAIL_IMAP, quick).catch(() => 0);
    return res;
  }, true, 60_000).then(async (res) => {
    if (wantAuto) { try { (res as Record<string, unknown>).autoSent = await autoReplyNow(user); } catch (e) { console.error("auto reply now", (e as Error).message); } }
    return res;
  });
}
// ---------- the company mailbox (RainLoop, koala.serveriai.lt) → Gmail ----------
// When letters are read from Gmail but the company server does not forward them, every NEW letter that comes
// to the company Inbox is copied into the Gmail Inbox (unread, with its own date) – then it shows in the app,
// gives a notification and is answered by the auto reply like any other. Only letters that arrive after it
// was switched on; each run copies up to 10 (≤ 25 MB), the rest go in the next runs. The server's own forwarding
// may work only sometimes: a letter already in Gmail (same Message-ID) is not copied again, and a new one waits a
// minute first, so a forwarded copy can come.
type MirrorState = { uidValidity?: string; lastUid?: number; copied?: number; busy?: string; removed?: number;
  recent?: Record<string, number>;   // Message-IDs copied in the last hours: a later forwarded copy of one is deleted
  last?: { at: string; n: number; skipped?: number; waiting?: number; removed?: number; err?: string } };
const MIRROR_WAIT_MS = Number(Deno.env.get("MAIL_MIRROR_WAIT_MS") ?? 60_000);
type MirrorRow = { user_id: string; email: string; secret: string; reader?: Reader | null; settings?: Settings | null; state?: { mirror?: MirrorState } | null };
async function mirrorSave(user: string, mirror: MirrorState) {
  const [cur] = await db<{ state: Record<string, unknown> | null }[]>(`mail_accounts?select=state&user_id=eq.${user}`);
  await db(`mail_accounts?user_id=eq.${user}`, { method: "PATCH", body: JSON.stringify({ state: { ...(cur?.state ?? {}), mirror } }) });
}
type MirrorMsg = { uid: number; source: Buffer; flags: string[]; date?: Date; mid?: string };
// letters into the Gmail Inbox, unless Gmail already has them (the server did forward them) – looked up by the
// Message-ID in „All Mail“; each handled letter is reported (copied or already there)
async function toGmail(dst: Account, msgs: MirrorMsg[], done: (m: MirrorMsg) => void = () => {}) {
  let n = 0, skipped = 0;
  const mids: string[] = [];
  await withImap(dst, async (g) => {
    const gm = !!(g.capabilities as unknown as Map<string, unknown>)?.has?.("X-GM-EXT-1");
    const allBox = (await boxes(g)).find((b) => b.specialUse === "\\All")?.path || "INBOX";
    const lock = await g.getMailboxLock(allBox);
    try {
      for (const m of msgs) {
        let there = false;
        if (m.mid) {
          const q = gm ? { gmraw: "rfc822msgid:" + m.mid.replace(/^<|>$/g, "") } : { header: { "message-id": m.mid } };
          there = ((await g.search(q as never, { uid: true })) || []).length > 0;
        }
        // with the letter's own receive time; a server that refuses that date format gets it without one
        if (!there) { await g.append("INBOX", m.source, m.flags, m.date).catch(() => g.append("INBOX", m.source, m.flags)); n++; if (m.mid) mids.push(m.mid); }
        else skipped++;
        done(m);
      }
    } finally { lock.release(); }
  }, false, 90_000);
  return { n, skipped, mids };
}
// one letter, two copies in Gmail (we copied it, then the server's forwarding brought it too, or the other way):
// the one that came first stays, the later one goes to the Trash (and so out of the app's list)
const RECENT_MS = 6 * 3600e3;
async function dedupeGmail(dst: Account, recent: Record<string, number>): Promise<number> {
  const mids = Object.keys(recent).filter((k) => Date.now() - recent[k] < RECENT_MS);
  if (!mids.length) return 0;
  let removed = 0;
  await withImap(dst, async (g) => {
    const gm = !!(g.capabilities as unknown as Map<string, unknown>)?.has?.("X-GM-EXT-1");
    const list = await boxes(g);
    const allBox = list.find((b) => b.specialUse === "\\All")?.path || "INBOX";
    const trash = list.find((b) => b.specialUse === "\\Trash")?.path;
    const lock = await g.getMailboxLock(allBox);
    try {
      for (const mid of mids) {
        const q = gm ? { gmraw: "rfc822msgid:" + mid.replace(/^<|>$/g, "") } : { header: { "message-id": mid } };
        const uids = ((await g.search(q as never, { uid: true })) || []).sort((x, y) => x - y);
        if (uids.length < 2) continue;
        const later = uids.slice(1).join(",");     // the lowest UID came first
        if (trash) await g.messageMove(later, trash, { uid: true }); else await g.messageDelete(later, { uid: true });
        removed += uids.length - 1;
      }
    } finally { lock.release(); }
  }, false, 60_000);
  return removed;
}
const keepRecent = (r: Record<string, number> | undefined, add: string[]) => {
  const out: Record<string, number> = {};
  for (const [k, t] of Object.entries(r ?? {})) if (Date.now() - t < RECENT_MS) out[k] = t;
  for (const k of add) out[k] = Date.now();
  return Object.fromEntries(Object.entries(out).sort((a, b) => b[1] - a[1]).slice(0, 200));
};
// the company Inbox's letters (sources) by UID, at most 25 MB
async function companyMsgs(c: ImapFlow, uids: number[]): Promise<MirrorMsg[]> {
  const sizes = new Map<number, number>();
  for await (const m of c.fetch(uids.join(","), { uid: true, size: true }, { uid: true })) sizes.set(m.uid, m.size || 0);
  const take: number[] = []; let bytes = 0;
  for (const u of uids) { const z = sizes.get(u) || 0; if (take.length && bytes + z > 25e6) break; take.push(u); bytes += z; }
  const out: MirrorMsg[] = [];
  for await (const m of c.fetch(take.join(","), { uid: true, source: true, flags: true, internalDate: true, envelope: true }, { uid: true })) {
    if (m.source) out.push({ uid: m.uid, source: m.source as Buffer, flags: [...(m.flags ?? [])].filter((f) => f !== "\\Recent"), date: m.internalDate as Date | undefined, mid: m.envelope?.messageId || undefined });
  }
  return out.sort((x, y) => x.uid - y.uid);
}
// „Perkelti paskutinių N val. laiškus“: the letters the forwarding lost before the copying was on (Gmail's own skipped)
async function mirrorBack(row: MirrorRow, hours: number) {
  const a = await accountOf(row), src: Account = { email: a.email, password: a.password };
  const from = Date.now() - hours * 3600e3;
  let more = 0;
  const msgs = await withImap(src, async (c) => {
    const lock = await c.getMailboxLock("INBOX");
    try {
      const since = new Date(from - 24 * 3600e3);   // SEARCH SINCE is by day; the exact time is checked below
      const uids = ((await c.search({ since }, { uid: true })) || []).sort((x, y) => x - y);
      if (!uids.length) return [] as MirrorMsg[];
      const dates = new Map<number, number>();
      for await (const m of c.fetch(uids.join(","), { uid: true, internalDate: true }, { uid: true })) dates.set(m.uid, new Date(m.internalDate as Date).getTime());
      const want = uids.filter((u) => (dates.get(u) || 0) >= from);
      more = Math.max(0, want.length - 30);
      return want.length ? await companyMsgs(c, want.slice(0, 30)) : [] as MirrorMsg[];
    } finally { lock.release(); }
  }, true, 120_000);
  const r = msgs.length ? await toGmail(a.reader!, msgs) : { n: 0, skipped: 0, mids: [] as string[] };
  if (r.mids.length) {
    const [cur] = await db<{ state: { mirror?: MirrorState } | null }[]>(`mail_accounts?select=state&user_id=eq.${row.user_id}`);
    const m = cur?.state?.mirror ?? {};
    await mirrorSave(row.user_id, { ...m, recent: keepRecent(m.recent, r.mids), copied: (m.copied ?? 0) + r.n });
  }
  return { copied: r.n, skipped: r.skipped, checked: msgs.length, more };
}
async function mirrorFor(row: MirrorRow, force = false) {
  if (!row.reader?.email || (!force && !row.settings?.mirror?.on)) return null;
  // one run at a time for a mailbox (the 15-second check and the minute check can meet): a 2-minute lock
  const now = new Date().toISOString();
  const locked = await db<{ state: { mirror?: MirrorState } | null }[]>(
    `mail_accounts?user_id=eq.${row.user_id}&or=(state->mirror->>busy.is.null,state->mirror->>busy.lt.${now})`,
    { method: "PATCH", headers: { Prefer: "return=representation" },
      body: JSON.stringify({ state: { ...(row.state ?? {}), mirror: { ...(row.state?.mirror ?? {}), busy: new Date(Date.now() + 120_000).toISOString() } } }) });
  if (!locked.length) return { busy: true };
  const st: MirrorState = { ...(locked[0].state?.mirror ?? {}) };
  delete st.busy;
  const a = await accountOf(row), src: Account = { email: a.email, password: a.password }, dst = a.reader!;
  let n = 0, waiting = 0, skipped = 0, removed = 0, err = "";
  try {
    // 1) the company Inbox: which letters are new (the first run only notes where „now“ is)
    type Msg = MirrorMsg;
    const msgs = await withImap(src, async (c) => {
      const lock = await c.getMailboxLock("INBOX");
      try {
        // (a kept connection's uidNext is not refreshed when letters come – the UIDs are searched every time)
        const uv = String((c.mailbox as unknown as { uidValidity: bigint }).uidValidity);
        if (st.uidValidity !== uv || st.lastUid === undefined) {
          const all = (await c.search({ all: true }, { uid: true })) || [];
          st.uidValidity = uv; st.lastUid = all.length ? Math.max(...all) : 0;
          return [] as Msg[];
        }
        const found = ((await c.search({ uid: `${st.lastUid + 1}:*` }, { uid: true })) || []).filter((u) => u > st.lastUid!).sort((x, y) => x - y);
        if (!found.length) return [] as Msg[];
        const out = await companyMsgs(c, found.slice(0, 10));
        waiting = found.length - out.length;
        // a just-arrived letter gets a minute to come to Gmail by the server's own forwarding first
        const young = out.findIndex((m) => m.date && Date.now() - new Date(m.date).getTime() < MIRROR_WAIT_MS);
        if (young >= 0) { waiting += out.length - young; out.length = young; }
        return out;
      } finally { lock.release(); }
    }, true, 90_000);
    // 2) into the Gmail Inbox, in order; the position moves only past what was really handled
    if (msgs.length) {
      const r = await toGmail(dst, msgs, (m) => { st.lastUid = m.uid; });
      n += r.n; skipped += r.skipped;
      st.recent = keepRecent(st.recent, r.mids);
    }
    // a forwarded copy of a letter copied earlier: the later of the two is deleted
    if (Object.keys(st.recent ?? {}).length) { removed = await dedupeGmail(dst, st.recent!).catch((e) => { console.error("dedupe", (e as Error).message); return 0; }); st.recent = keepRecent(st.recent, []); }
  } catch (e) {
    err = e instanceof UserError ? e.message : (e as Error).message || "klaida";
    console.error("mirror", row.email, err);
  }
  st.copied = (st.copied ?? 0) + n;
  st.removed = (st.removed ?? 0) + removed;
  st.last = { at: new Date().toISOString(), n, ...(skipped ? { skipped } : {}), ...(waiting ? { waiting } : {}), ...(removed ? { removed } : {}), ...(err ? { err: err.slice(0, 300) } : {}) };
  await mirrorSave(row.user_id, st);
  return { copied: n, skipped, waiting, removed, err: err || undefined };
}

// ---------- the invoice mailbox (saskaitos@eventsolutions.lt) → „Sąskaitos“ ----------
// Every new letter to the invoice mailbox becomes an invoice: its attachments are the invoice's files, the
// total is found in a PDF's text, the sender is the supplier, and the kind comes from Admin+'s keyword rules
// (the first rule whose words are found wins; none – the default kind). The same letter is never imported
// twice (invoices.mail_id = its Message-ID). Checked every 15 s with the mail sync (up to 3 letters a run; 8 a minute).
type InboxRule = { kw?: string; where?: string; kind?: string; supplier?: string };
type InboxRow = { id: number; email: string | null; host: string | null; secret: string | null; active: boolean; rules: InboxRule[]; default_kind: string;
  state: { uidValidity?: string; lastUid?: number; busy?: string; total?: number; last?: { at: string; n: number; skipped?: number; err?: string; items?: { subject: string; kind: string; rule?: number }[] } } };
const INV_KINDS_OK = ["freelance", "service", "rent", "purchase", "other"];
const foldLt = (t: string) => String(t || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
type InboxLetter = { uid: number; mid: string; date: Date | null; subject: string; from: { name: string; address: string }; text: string;
  files: { name: string; type: string; data: Buffer }[]; skippedFiles: string[] };
// which rule fits a letter (index), or -1
export function inboxRule(rules: InboxRule[], l: { subject: string; from: { name: string; address: string }; text: string; files: { name: string }[] }): number {
  const fields: Record<string, string> = {
    from: foldLt(l.from.name + " " + l.from.address), subject: foldLt(l.subject), text: foldLt(l.text).slice(0, 200_000),
    file: foldLt(l.files.map((f) => f.name).join(" ")),
  };
  fields.any = [fields.from, fields.subject, fields.text, fields.file].join("\n");
  for (const [i, r] of rules.entries()) {
    const words = String(r.kw || "").split(/[,;\n]+/).map((w) => foldLt(w).trim()).filter(Boolean);
    if (!words.length) continue;
    const hay = fields[r.where || "any"] ?? fields.any;
    if (words.some((w) => hay.includes(w))) return i;
  }
  return -1;
}
const htmlToText = (h: string) => h.replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<br\s*\/?>|<\/(p|div|tr|li|h\d)>/gi, "\n").replace(/<[^>]+>/g, " ")
  .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n").trim();
// one letter of the invoice mailbox: the text (for the rules) and the attachments (≤ 15 MB each, ≤ 30 MB in all)
async function inboxLetter(c: ImapFlow, uid: number): Promise<InboxLetter | null> {
  const msg = await c.fetchOne(String(uid), { uid: true, envelope: true, bodyStructure: true, internalDate: true }, { uid: true });
  if (!msg || !msg.envelope) return null;
  const all = leaves(msg.bodyStructure as Node);
  const isBody = (l: Leaf) => l.disposition !== "attachment" && !l.filename;
  const htmlPart = all.find((l) => l.type === "text/html" && isBody(l)), textPart = all.find((l) => l.type === "text/plain" && isBody(l));
  let text = "";
  if (textPart && textPart.size < 400_000) text = decodeText(await partBuffer(c, uid, textPart.part, 400_000), textPart.charset);
  else if (htmlPart && htmlPart.size < 1_000_000) text = htmlToText(decodeText(await partBuffer(c, uid, htmlPart.part, 1_000_000), htmlPart.charset));
  const files: InboxLetter["files"] = [], skippedFiles: string[] = [];
  let budget = 30e6;
  for (const l of all) {
    if (l === htmlPart || l === textPart) continue;
    const named = l.disposition === "attachment" || !!l.filename;
    if (!named) continue;
    if (l.cid && l.type.startsWith("image/") && l.size < 60_000 && l.disposition !== "attachment") continue;   // logos inside the letter
    const name = (l.filename || "priedas." + (l.type.split("/")[1] || "bin")).replace(/[\\/\u0000-\u001f]+/g, "_").slice(-120);
    if (l.size > 15e6 * 1.37 || l.size > budget * 1.37) { skippedFiles.push(name); continue; }
    const data = await partBuffer(c, uid, l.part, 16e6);
    budget -= data.length;
    files.push({ name, type: l.type || "application/octet-stream", data });
  }
  const e = msg.envelope, f = (e.from ?? [])[0] ?? {};
  return { uid, mid: e.messageId || "", date: (e.date ?? msg.internalDate) as Date | null, subject: e.subject || "", from: { name: f.name || "", address: (f.address || "").toLowerCase() }, text, files, skippedFiles };
}
// the invoice's number: after „Nr.“ / „No“, or a series code like LVA0390087, ES-0123, AB 0012
export const numberOf = (t: string) => {
  const s = String(t || "").replace(/_/g, " ");
  return (s.match(/\b(?:nr|no|numeris)\.?\s*[:#]?\s*([A-Z0-9][A-Z0-9\-\/]{2,30})/i) || [])[1]
    || (s.match(/\b([A-Z]{1,6}[- ]?\d{3,}[A-Z0-9\-\/]*)\b/) || [])[1]?.replace(" ", "-") || null;
};
async function inboxOwner(): Promise<string> {
  const o = await db<{ id: string }[]>("profiles?select=id&role=eq.admin&level=in.(plus,super)&order=created_at&limit=1");
  const id = o[0]?.id || (await db<{ id: string }[]>("profiles?select=id&role=eq.admin&order=created_at&limit=1"))[0]?.id;
  if (!id) throw new Error("no admin");
  return id;
}
// a letter → an invoice (false when it was imported before)
async function inboxImport(row: InboxRow, l: InboxLetter, owner: string): Promise<{ kind: string; rule: number } | false> {
  const mailId = l.mid || `uid:${row.email}:${row.state.uidValidity}:${l.uid}`;
  const had = await db<{ id: string }[]>(`invoices?select=id&mail_id=eq.${encodeURIComponent(mailId)}&limit=1`);
  if (had.length) return false;
  const ri = inboxRule(row.rules || [], l), rule = ri >= 0 ? row.rules[ri] : null;
  const kind = INV_KINDS_OK.includes(String(rule?.kind)) ? String(rule!.kind) : (INV_KINDS_OK.includes(row.default_kind) ? row.default_kind : "other");
  const id = crypto.randomUUID(), key = env("SUPABASE_SERVICE_ROLE_KEY"), base = env("SUPABASE_URL");
  const files: { path: string; name: string; type: string; size: number }[] = [];
  const up = async (name: string, type: string, data: Uint8Array) => {
    const path = `${owner}/mail/${id}/${files.length + 1}-${name.replace(/[^\w.\-]+/g, "_").slice(-80)}`;
    const r = await fetch(`${base}/storage/v1/object/invoice-files/${path}`, { method: "POST", headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": type, "x-upsert": "true" }, body: data });
    if (!r.ok) throw new Error("upload " + r.status + " " + (await r.text()).slice(0, 160));
    files.push({ path, name, type, size: data.length });
  };
  for (const f of l.files) await up(f.name, f.type, new Uint8Array(f.data));
  // no attachment (a link or the text itself): the letter is kept as a text file
  if (!l.files.length) await up("laiskas.txt", "text/plain", new TextEncoder().encode(`Nuo: ${l.from.name} <${l.from.address}>\nTema: ${l.subject}\nData: ${l.date ? new Date(l.date).toISOString() : ""}\n\n${l.text}`.slice(0, 500_000)));
  // the total is not read here (a PDF's parsing would run out of the function's CPU time): the app reads it
  // from the PDF when Admin+ opens „Sąskaitos“ and fills it in
  const amount: number | null = null;
  const number = numberOf(l.subject) || l.files.map((f) => numberOf(f.name.replace(/\.[a-z0-9]+$/i, ""))).find(Boolean) || null;
  const day = l.date ? new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Vilnius" }).format(new Date(l.date)) : null;
  const note = ["📧 " + (l.subject || "(be temos)"), l.skippedFiles.length ? "Per dideli priedai (neįkelti): " + l.skippedFiles.join(", ") : ""].filter(Boolean).join("\n").slice(0, 1000);
  try {
    await db("invoices", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify({
      id, created_by: owner, kind, supplier: (rule?.supplier || l.from.name || l.from.address || "").slice(0, 200) || null, number, amount, invoice_date: day, note, files,
      source: "email", ext_email: l.from.address || null, ext_name: l.from.name || null, mail_id: mailId, uploader_seen: true,
    }) });
  } catch (e) {
    await fetch(`${base}/storage/v1/object/invoice-files`, { method: "DELETE", headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify({ prefixes: files.map((f) => f.path) }) }).catch(() => {});
    if (/duplicate key|invoices_mail_id/i.test((e as Error).message)) return false;   // imported by a parallel run
    throw e;
  }
  const cs = Deno.env.get("CRON_SECRET");
  if (cs) await fetch(`${base}/functions/v1/push-notify`, { method: "POST", headers: { "Content-Type": "application/json", "x-cron-secret": cs }, body: JSON.stringify({ mode: "invoice-email", invoice_id: id }) }).catch(() => {});
  return { kind, rule: ri };
}
async function inboxRow(): Promise<InboxRow | null> {
  const [r] = await db<InboxRow[]>("invoice_inbox?select=*&id=eq.1").catch(() => [] as InboxRow[]);
  return r ?? null;
}
// one run: new letters (since=days: the letters of the last days, those not imported yet)
async function runInvoiceInbox(force = false, sinceDays = 0, max = 8) {
  const row = await inboxRow();
  if (!row || !row.email || !row.secret || (!row.active && !force)) return null;
  const now = new Date().toISOString();
  const locked = await db<InboxRow[]>(`invoice_inbox?id=eq.1&or=(state->>busy.is.null,state->>busy.lt.${now})`,
    { method: "PATCH", headers: { Prefer: "return=representation" }, body: JSON.stringify({ state: { ...row.state, busy: new Date(Date.now() + 100_000).toISOString() } }) });
  if (!locked.length) return { busy: true };
  const st: InboxRow["state"] & { trying?: number; failed?: number[] } = { ...locked[0].state }; delete st.busy;
  row.state = st;
  // the last run stopped inside a letter (it never finished): that letter is skipped, so it can't stop every run
  if (!sinceDays && st.trying && st.lastUid !== undefined && st.trying > st.lastUid) {
    st.lastUid = st.trying; st.failed = [...(st.failed ?? []), st.trying].slice(-20);
  }
  delete st.trying;
  const keep = (extra: Record<string, unknown> = {}) => db("invoice_inbox?id=eq.1", { method: "PATCH", body: JSON.stringify({ state: { ...st, ...extra, busy: new Date(Date.now() + 100_000).toISOString() } }) }).catch(() => {});
  const a: Account = { email: row.email, password: await unseal(row.secret), host: row.host || undefined };
  let n = 0, skipped = 0, err = "", more = 0;
  const items: { subject: string; kind: string; rule?: number }[] = [];
  try {
    const owner = await inboxOwner();
    await withImap(a, async (c) => {
      const lock = await c.getMailboxLock("INBOX");
      try {
        const uv = String((c.mailbox as unknown as { uidValidity: bigint }).uidValidity);
        let uids: number[];
        if (sinceDays > 0) {
          uids = ((await c.search({ since: new Date(Date.now() - sinceDays * 864e5) }, { uid: true })) || []).sort((x, y) => x - y);
        } else {
          if (st.uidValidity !== uv || st.lastUid === undefined) {   // the first run only notes where „now“ is
            const allU = (await c.search({ all: true }, { uid: true })) || [];
            st.uidValidity = uv; st.lastUid = allU.length ? Math.max(...allU) : 0;
            return;
          }
          uids = ((await c.search({ uid: `${st.lastUid + 1}:*` }, { uid: true })) || []).filter((u) => u > st.lastUid!).sort((x, y) => x - y);
        }
        st.uidValidity = uv;
        const take = uids.slice(0, sinceDays > 0 ? 25 : max);
        more = uids.length - take.length;
        for (const uid of take) {
          if (!sinceDays) await keep({ trying: uid });
          const l = await inboxLetter(c, uid);
          if (l) {
            const r = await inboxImport(row, l, owner);
            if (r) { n++; items.push({ subject: l.subject.slice(0, 120), kind: r.kind, ...(r.rule >= 0 ? { rule: r.rule } : {}) }); } else skipped++;
          }
          if (!sinceDays) { st.lastUid = uid; await keep(); }
        }
      } finally { lock.release(); }
    }, true, 80_000);
  } catch (e) {
    err = e instanceof UserError ? e.message : (e as Error).message || "klaida";
    console.error("invoice inbox", err);
  }
  st.total = (st.total ?? 0) + n;
  st.last = { at: new Date().toISOString(), n, ...(skipped ? { skipped } : {}), ...(err ? { err: err.slice(0, 300) } : {}), ...(items.length ? { items } : (st.last?.items ? { items: st.last.items } : {})) };
  await db("invoice_inbox?id=eq.1", { method: "PATCH", body: JSON.stringify({ state: st }) });
  return { imported: n, skipped, more, err: err || undefined };
}
// „Peržiūra“: how the last letters would be sorted with these rules (nothing is imported)
async function inboxPreview(row: InboxRow, rules: InboxRule[]) {
  const a: Account = { email: row.email!, password: await unseal(row.secret!), host: row.host || undefined };
  return await withImap(a, async (c) => {
    const lock = await c.getMailboxLock("INBOX");
    try {
      const allU = ((await c.search({ all: true }, { uid: true })) || []).sort((x, y) => y - x).slice(0, 15);
      const out = [];
      for (const uid of allU) {
        const msg = await c.fetchOne(String(uid), { uid: true, envelope: true, bodyStructure: true }, { uid: true });
        if (!msg || !msg.envelope) continue;
        const lv = leaves(msg.bodyStructure as Node);
        const tp = lv.find((l) => l.type === "text/plain" && l.disposition !== "attachment" && !l.filename && l.size < 200_000);
        const text = tp ? decodeText(await partBuffer(c, uid, tp.part, 200_000), tp.charset) : "";
        const f = (msg.envelope.from ?? [])[0] ?? {};
        const l = { subject: msg.envelope.subject || "", from: { name: f.name || "", address: f.address || "" }, text, files: lv.filter((x) => x.disposition === "attachment" || x.filename).map((x) => ({ name: x.filename || "" })) };
        const ri = inboxRule(rules, l);
        out.push({ date: (msg.envelope.date as Date | undefined)?.toISOString?.() ?? null, subject: l.subject, from: l.from.name || l.from.address, files: l.files.map((x) => x.name).filter(Boolean), rule: ri, kind: ri >= 0 ? rules[ri].kind : row.default_kind });
      }
      return out;
    } finally { lock.release(); }
  }, true, 90_000);
}
export function cleanRules(v: unknown): InboxRule[] {
  return (Array.isArray(v) ? v : []).slice(0, 60).map((r) => ({
    kw: String((r as InboxRule)?.kw ?? "").slice(0, 500),
    where: ["any", "from", "subject", "text", "file"].includes(String((r as InboxRule)?.where)) ? String((r as InboxRule).where) : "any",
    kind: INV_KINDS_OK.includes(String((r as InboxRule)?.kind)) ? String((r as InboxRule).kind) : "other",
    supplier: String((r as InboxRule)?.supplier ?? "").slice(0, 200),
  })).filter((r) => r.kw.trim());
}
async function isPlusUser(uid: string) {
  const [p] = await db<{ role: string; level: string | null }[]>(`profiles?select=role,level&id=eq.${uid}`);
  return !!p && p.role === "admin" && ["plus", "super"].includes(String(p.level));
}
async function inboxAction(me: Me, action: string, body: Record<string, unknown>) {
  if (!(await isPlusUser(me.id))) throw new UserError("Sąskaitų dėžutę tvarko tik Admin+.");
  let row = await inboxRow().catch(() => null);
  if (action === "inv_inbox_get") {
    return { email: row?.email ?? "", host: row?.host ?? "", active: !!row?.active, hasPassword: !!row?.secret, rules: row?.rules ?? [], default_kind: row?.default_kind ?? "other", last: row?.state?.last ?? null, total: row?.state?.total ?? 0 };
  }
  if (action === "inv_inbox_save") {
    const email = String(body.email ?? "").trim().toLowerCase(), password = String(body.password ?? ""), host = String(body.host ?? "").trim().toLowerCase();
    if (!emailRe.test(email)) throw new UserError("Įrašyk sąskaitų dėžutės el. paštą.");
    if (host && !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) throw new UserError("Neteisingas serverio adresas.");
    const secret = password ? await seal(password) : (row?.email === email ? row?.secret : null);
    if (!secret) throw new UserError("Įrašyk dėžutės slaptažodį.");
    if (password || row?.email !== email || (row?.host || "") !== host) {
      try { await withImap({ email, password: password || await unseal(secret), host: host || undefined }, async () => null, false); }
      catch (e) { throw e instanceof UserError && /Neteisingas/.test(e.message) ? new UserError("Prie dėžutės neprisijungta: patikrink el. paštą ir slaptažodį.") : e; }
    }
    const active = body.active === true, default_kind = INV_KINDS_OK.includes(String(body.default_kind)) ? String(body.default_kind) : "other";
    const changed = row?.email !== email;
    await db("invoice_inbox?on_conflict=id", { method: "POST", headers: { Prefer: "resolution=merge-duplicates" }, body: JSON.stringify({
      id: 1, email, host: host || null, secret, active, rules: cleanRules(body.rules), default_kind, updated_at: new Date().toISOString(),
      ...(changed || !row ? { state: {} } : {}),
    }) });
    row = await inboxRow();
    // switched on for the first time: where „now“ is gets noted at once (only later letters are imported)
    if (active && row && row.state?.lastUid === undefined) await runInvoiceInbox(true).catch(() => null);
    return { ok: true };
  }
  if (!row?.email || !row.secret) throw new UserError("Pirmiausia išsaugok dėžutės prisijungimą.");
  if (action === "inv_inbox_now") return { ok: true, ...(await runInvoiceInbox(true)) };
  if (action === "inv_inbox_back") return { ok: true, ...(await runInvoiceInbox(true, Math.min(60, Math.max(1, Number(body.days) || 7)))) };
  if (action === "inv_inbox_preview") return { ok: true, letters: await inboxPreview(row, cleanRules(body.rules ?? row.rules)) };
  throw new UserError("Nežinomas veiksmas.");
}

// pg_cron, every minute: Inbox for everyone (Sent every 5 min), one after another
async function runSyncAll(quick = false) {
  const rows = await db<MirrorRow[]>("mail_accounts?select=user_id,email,secret,reader,settings,state");
  const t0 = Date.now(), done: Record<string, unknown> = {};
  const sent = !quick && new Date().getMinutes() % 5 === 0;
  for (const r of rows) {
    if (Date.now() - t0 > (quick ? 12_000 : 100_000)) break;
    try {
      // the company mailbox first: new letters copied into Gmail are seen by this same check
      if (r.reader && r.settings?.mirror?.on) await mirrorFor(r).catch((e) => console.error("mirror", (e as Error).message));
      const a = readerOf(await accountOf(r));
      done[r.email] = await syncFolder(r.user_id, a, "inbox", quick);
      if (sent) await syncFolder(r.user_id, a, "sent").catch(() => null);
    } catch (e) {
      done[r.email] = { error: (e as Error).message };
    }
  }
  // automatic replies („out of office“) – every minute now, right after the letters are checked
  let auto: unknown = null, inbox: unknown = null;
  if (!quick) { try { auto = await runAutoReplies(); } catch (e) { auto = { error: (e as Error).message }; } }
  // the invoice mailbox (saskaitos@) → „Sąskaitos“
  // (every 15 s too, in its own call of this function – a slow letter does not hold up the mail sync)
  const cs = Deno.env.get("CRON_SECRET");
  if (cs) {
    await fetch(`${env("SUPABASE_URL")}/functions/v1/mail`, { method: "POST", signal: AbortSignal.timeout(2500),
      headers: { "Content-Type": "application/json", "x-cron-secret": cs }, body: JSON.stringify({ action: "invoice_inbox", quick }) }).catch(() => null);
    inbox = "started";
  }
  return { synced: Object.keys(done).length, ms: Date.now() - t0, auto, inbox };
}

// ---------- reading a message: only the parts that are needed ----------
// (the whole message with attachments can be many MB — parsing it all would
// run out of the function's CPU time, so we walk the structure instead)
type Node = {
  part?: string; type: string; parameters?: Record<string, string>; disposition?: string; encoding?: string;
  dispositionParameters?: Record<string, string>; size?: number; id?: string; childNodes?: Node[];
};
type Leaf = { part: string; type: string; size: number; filename: string; disposition: string; cid: string; encoding: string; charset: string };
export function leaves(root: Node | undefined): Leaf[] {
  const out: Leaf[] = [];
  const walk = (n: Node | undefined) => {
    if (!n) return;
    if (n.childNodes && n.childNodes.length) { n.childNodes.forEach(walk); return; }
    if (n.type?.startsWith("multipart/")) return;
    out.push({
      part: n.part || "1", type: (n.type || "text/plain").toLowerCase(), size: n.size || 0,
      filename: n.dispositionParameters?.filename || n.parameters?.name || "",
      disposition: (n.disposition || "").toLowerCase(), cid: (n.id || "").replace(/^<|>$/g, ""),
      encoding: (n.encoding || "").toLowerCase(), charset: (n.parameters?.charset || "").toLowerCase(),
    });
  };
  walk(root);
  return out;
}
const MAX_TEXT = 1_500_000, MAX_INLINE = 400_000, MAX_INLINE_TOTAL = 2_000_000;
async function partBuffer(c: ImapFlow, uid: number, part: string, maxBytes: number): Promise<Buffer> {
  const { content } = await c.download(String(uid), part, { uid: true, maxBytes });
  const chunks: Buffer[] = [];
  for await (const ch of content) chunks.push(Buffer.from(ch));
  return Buffer.concat(chunks);
}
function hasAttachments(node: Node | undefined): boolean {
  // pictures embedded in the text (e.g. the signature logo) are not attachments
  return leaves(node).some((l) => l.disposition === "attachment" || (!!l.filename && !l.type.startsWith("text/") && !(l.cid && l.type.startsWith("image/"))));
}

// a body part as fetched from the server (still base64 / quoted-printable)
export function decodeTransfer(buf: Buffer, enc: string): Buffer {
  if (enc === "base64") return Buffer.from(buf.toString("latin1").replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
  if (enc === "quoted-printable") {
    const src = buf.toString("latin1").replace(/=\r?\n/g, "");
    const out: number[] = [];
    for (let i = 0; i < src.length; i++) {
      const ch = src.charCodeAt(i);
      if (ch === 61 && /^[0-9A-Fa-f]{2}$/.test(src.slice(i + 1, i + 3))) { out.push(parseInt(src.slice(i + 1, i + 3), 16)); i += 2; }
      else out.push(ch & 0xff);
    }
    return Buffer.from(out);
  }
  return buf;
}
export function decodeText(buf: Buffer, charset: string): string {
  const cs = (charset || "utf-8").replace(/^utf8$/, "utf-8").replace(/^(x-)?(windows|cp)-?(\d+)$/, "windows-$3");
  try { return new TextDecoder(cs).decode(buf); } catch { return new TextDecoder("utf-8").decode(buf); }
}
// First the quick way (kept connection, all parts in one request). If that
// does not answer in time, once more on a fresh connection, part by part —
// the way that always worked with this mail server, only slower.
async function read(a: Account, folder: string, uid: number, peek = false) {
  const t0 = Date.now(), tr: Trace = { s: "" };
  let how = "fast";
  try {
    try {
      return await withImap(a, (c) => readOn(c, folder, uid, peek, true, tr), false, READ_FAST_MS, tr);
    } catch (e) {
      if (!isTransient(e)) throw e;
      console.error(`read ${folder}/${uid} quick way failed at "${tr.s}": ${(e as Error).message} | ${tr.info ?? ""}\n${(tr.c && trails.get(tr.c) || []).join("\n")}`);
      how = "plain";
      return await withImap(a, (c) => readOn(c, folder, uid, peek, false, tr), false, 25_000, tr, true);
    }
  } catch (e) {
    how += " FAILED at " + tr.s;
    console.error(`read ${folder}/${uid} plain way failed | ${tr.info ?? ""}\n${(tr.c && trails.get(tr.c) || []).join("\n")}`);
    throw e;
  } finally {
    console.log(`read ${folder}/${uid}${peek ? " peek" : ""} ${how} ${Date.now() - t0} ms | ${tr.info ?? ""}`);
  }
}
const READ_FAST_MS = Number(Deno.env.get("MAIL_READ_FAST_MS") || 10_000);
async function readOn(c: ImapFlow, folder: string, uid: number, peek: boolean, fast: boolean, tr: Trace) {
  {
    tr.c = c;
    tr.s = "aplankas";
    const path = await folderPath(c, folder);
    const lock = await c.getMailboxLock(path);
    try {
      tr.s = "antraštė";
      const msg = await c.fetchOne(String(uid), { uid: true, envelope: true, flags: true, bodyStructure: true, internalDate: true, size: true, headers: ["references"] }, { uid: true });
      if (!msg || !msg.envelope) throw new UserError("Laiškas nerastas (gal jau ištrintas).");
      const all = leaves(msg.bodyStructure as Node);
      tr.info = `size ${msg.size} parts ${all.map((l) => `${l.part}:${l.type}:${l.size}:${l.encoding}`).join(" ").slice(0, 300)}`;
      const isBody = (l: Leaf) => l.disposition !== "attachment" && !l.filename;
      const htmlPart = all.find((l) => l.type === "text/html" && isBody(l));
      const textPart = all.find((l) => l.type === "text/plain" && isBody(l));
      const texts = [htmlPart, textPart && (!htmlPart || textPart.size < 200_000) ? textPart : undefined].filter(Boolean) as Leaf[];
      // small pictures that may be shown inside the text (cid:)
      let budget = MAX_INLINE_TOTAL;
      const inline = htmlPart ? all.filter((l) => { if (!l.cid || !l.type.startsWith("image/") || l.size > MAX_INLINE || l.size > budget) return false; budget -= l.size; return true; }) : [];
      // everything that fits comes in ONE request to the mail server; the "read" mark goes at the same time
      const small = [...texts.filter((l) => l.size <= MAX_TEXT), ...inline];
      tr.s = "tekstas";
      const got = fast && small.length ? await c.fetchOne(String(uid), { uid: true, bodyParts: small.map((l) => l.part) }, { uid: true }) : null;
      tr.s = "žyma";
      if (!peek && !msg.flags?.has("\\Seen")) await c.messageFlagsAdd(String(uid), ["\\Seen"], { uid: true }).catch(() => false);
      const parts = (got && (got as { bodyParts?: Map<string, Buffer> }).bodyParts) || new Map<string, Buffer>();
      const partOf = async (l: Leaf): Promise<Buffer> => {
        const raw = parts.get(l.part) ?? parts.get(l.part.toLowerCase());
        if (raw) return decodeTransfer(Buffer.from(raw), l.encoding);
        tr.s = "dalis " + l.part;
        return await partBuffer(c, uid, l.part, MAX_TEXT);        // big ones / the plain way (already decoded)
      };
      let html = "", text = "";
      if (htmlPart) html = decodeText(await partOf(htmlPart), htmlPart.charset);
      if (texts.includes(textPart as Leaf)) text = decodeText(await partOf(textPart as Leaf), (textPart as Leaf).charset);
      const used = new Set<string>();
      if (html) {
        for (const l of all) {
          if (!l.cid || !l.type.startsWith("image/") || !html.includes("cid:" + l.cid)) continue;
          used.add(l.part);
          if (!inline.includes(l)) continue;
          const b64 = (await partOf(l)).toString("base64");
          html = html.split("cid:" + l.cid).join(`data:${l.type};base64,${b64}`);
        }
      }
      const refHeader = msg.headers ? msg.headers.toString().replace(/\r?\n\s+/g, " ") : "";
      const references = (refHeader.match(/<[^>\s]+>/g) || []).slice(-20);
      const env = msg.envelope;
      return {
        uid, folder,
        messageId: env.messageId || "",
        references,
        flagged: msg.flags?.has("\\Flagged") ?? false,
        date: (env.date ?? msg.internalDate)?.toISOString?.() ?? null,
        subject: env.subject || "",
        from: addr(env.from), to: addr(env.to), cc: addr(env.cc), replyTo: addr(env.replyTo),
        text, html,
        attachments: all
          .filter((l) => l !== htmlPart && l !== textPart && !used.has(l.part) && (l.disposition === "attachment" || l.filename || !l.type.startsWith("text/")))
          .map((l) => ({ index: l.part, filename: l.filename || "priedas." + (l.type.split("/")[1] || "bin"), contentType: l.type, size: Math.round(l.size * (l.type.startsWith("text/") ? 1 : 0.74)) })),
      };
    } finally {
      lock.release();
    }
  }
}

async function attachment(a: Account, folder: string, uid: number, part: string) {
  if (!/^[0-9]+(\.[0-9]+)*$/.test(part)) throw new UserError("Priedas nerastas.");
  return await withImap(a, async (c) => {
    const lock = await c.getMailboxLock(await folderPath(c, folder));
    try {
      const msg = await c.fetchOne(String(uid), { uid: true, bodyStructure: true }, { uid: true });
      const l = leaves(msg?.bodyStructure as Node).find((x) => x.part === part);
      if (!l) throw new UserError("Priedas nerastas.");
      if (l.size > 30 * 1024 * 1024) throw new UserError("Priedas per didelis atsisiųsti per programėlę — atidaryk Roundcube.");
      const buf = await partBuffer(c, uid, part, 40 * 1024 * 1024);
      return { filename: l.filename || "priedas", contentType: l.type, base64: buf.toString("base64") };
    } finally {
      lock.release();
    }
  }, true, 100_000);
}

// ---------- search ----------
type SearchBody = { q?: string; from?: string; to?: string; subject?: string; since?: string; before?: string; unseen?: boolean; attachments?: boolean; folder?: string };
// the work letters of the open folder (to / copy …@eventsolutions.lt; in Sent / Drafts: from)
async function workUids(c: ImapFlow, folder: string): Promise<Set<number>> {
  const dom = (Deno.env.get("MAIL_WORK_DOMAIN") || "eventsolutions.lt").toLowerCase();
  const q = folder === "sent" || folder === "drafts" ? { from: dom } : { or: [{ to: dom }, { cc: dom }] };
  return new Set(((await c.search(q as never, { uid: true })) || []) as number[]);
}
async function search(a: Account, b: SearchBody, only = "all") {
  const crit: Record<string, unknown> = {};
  const q = String(b.q ?? "").trim().slice(0, 200);
  if (q) crit.or = [{ from: q }, { to: q }, { subject: q }, { body: q }];
  if (b.from) crit.from = String(b.from).trim().slice(0, 200);
  if (b.to) crit.to = String(b.to).trim().slice(0, 200);
  if (b.subject) crit.subject = String(b.subject).trim().slice(0, 200);
  const d = (s?: string) => (s && /^\d{4}-\d{2}-\d{2}$/.test(s) ? new Date(s + "T00:00:00Z") : null);
  const since = d(b.since), before = d(b.before);
  // by the letter's own date (Date header), the "before" day included; the
  // server's search is only a wide first pass, the exact check is below
  if (since) crit.sentSince = new Date(since.getTime() - 24 * 3600e3);
  if (before) crit.sentBefore = new Date(before.getTime() + 2 * 24 * 3600e3);
  const dayOf = (iso: string) => new Intl.DateTimeFormat("en-CA", { timeZone: TZ }).format(new Date(iso));
  const inRange = (iso: unknown) => {
    if (!since && !before) return true;
    if (!iso) return false;
    const day = dayOf(String(iso));
    return (!b.since || day >= b.since) && (!b.before || day <= b.before);
  };
  if (b.unseen) crit.seen = false;
  if (!Object.keys(crit).length) crit.all = true;
  const folders = b.folder && b.folder !== "all" ? [b.folder] : ["inbox", "sent"];
  return await withImap(a, async (c) => {
    const items: Record<string, unknown>[] = [];
    let total = 0;
    for (const f of folders) {
      const lock = await c.getMailboxLock(await folderPath(c, f));
      try {
        let uids = ((await c.search(crit, { uid: true })) || []) as number[];
        if (only !== "all") { const w = await workUids(c, f); uids = uids.filter((u) => only === "work" ? w.has(u) : !w.has(u)); }
        total += uids.length;
        const last = uids.sort((x, y) => x - y).slice(-60);
        if (!last.length) continue;
        for await (const m of c.fetch(last.join(","), { uid: true, envelope: true, flags: true, bodyStructure: true, internalDate: true, size: true }, { uid: true })) {
          const att = hasAttachments(m.bodyStructure as Node);
          if (b.attachments && !att) continue;
          if (!inRange((m.envelope?.date ?? m.internalDate)?.toISOString?.())) continue;
          items.push({
            uid: m.uid, folder: f,
            date: (m.envelope?.date ?? m.internalDate)?.toISOString?.() ?? null,
            subject: m.envelope?.subject || "", from: addr(m.envelope?.from), to: addr(m.envelope?.to),
            seen: m.flags?.has("\\Seen") ?? false, answered: m.flags?.has("\\Answered") ?? false,
            attachments: att, size: m.size,
          });
        }
      } finally {
        lock.release();
      }
    }
    items.sort((x, y) => String(y.date).localeCompare(String(x.date)));
    return { items: items.slice(0, 100), total, more: total > items.length };
  }, true, 40_000);
}

async function flag(a: Account, folder: string, uid: number, seen: boolean) {
  return await withImap(a, async (c) => {
    const lock = await c.getMailboxLock(await folderPath(c, folder));
    try {
      if (seen) await c.messageFlagsAdd(String(uid), ["\\Seen"], { uid: true });
      else await c.messageFlagsRemove(String(uid), ["\\Seen"], { uid: true });
      return { ok: true };
    } finally {
      lock.release();
    }
  }, false);
}

async function star(a: Account, folder: string, uid: number, on: boolean) {
  return await withImap(a, async (c) => {
    const lock = await c.getMailboxLock(await folderPath(c, folder));
    try {
      if (on) await c.messageFlagsAdd(String(uid), ["\\Flagged"], { uid: true });
      else await c.messageFlagsRemove(String(uid), ["\\Flagged"], { uid: true });
      return { ok: true };
    } finally {
      lock.release();
    }
  }, false);
}
async function move(a: Account, folder: string, uid: number, to: string) {
  return await withImap(a, async (c) => {
    const target = await folderPath(c, to);
    const lock = await c.getMailboxLock(await folderPath(c, folder));
    try {
      if (lock.path === target) return { ok: true };
      await c.messageMove(String(uid), target, { uid: true });
      return { ok: true };
    } finally {
      lock.release();
    }
  }, false);
}
async function remove(a: Account, folder: string, uid: number) {
  return await withImap(a, async (c) => {
    const trash = await folderPath(c, "trash");
    const lock = await c.getMailboxLock(await folderPath(c, folder));
    try {
      if (lock.path === trash) { await c.messageDelete(String(uid), { uid: true }); return { ok: true, gone: true }; }
      await c.messageMove(String(uid), trash, { uid: true });
      return { ok: true };
    } finally {
      lock.release();
    }
  }, false);
}

const emailRe = /^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/;
export function parseRecipients(v: unknown): string[] {
  const parts = String(v ?? "").split(/[,;\n]+/).map((s) => s.trim()).filter(Boolean)
    .map((s) => (s.match(/<([^>]+)>/)?.[1] ?? s).trim());
  for (const p of parts) if (!emailRe.test(p)) throw new UserError(`Netinkamas adresas: ${p}`);
  return parts;
}

async function smtpSend(a: Account, rcpt: string[], raw: Buffer) {
  const tx = nodemailer.createTransport({
    host: a.host === GMAIL_IMAP ? "smtp.gmail.com" : env("MAIL_SMTP_HOST", env("MAIL_IMAP_HOST", "koala.serveriai.lt")),
    port: Number(env("MAIL_SMTP_PORT", "465")),
    secure: true,
    auth: { user: a.email, pass: a.password },
    tls: { rejectUnauthorized: !insecure() },
    connectionTimeout: 15000,
  });
  const info = await tx.sendMail({ envelope: { from: a.email, to: rcpt }, raw });
  const rejected = (info.rejected ?? []).map(String);
  if (rejected.length) throw Object.assign(new Error("Serveris atmetė gavėjus: " + rejected.join(", ")), { response: info.response });
  return { response: String(info.response ?? ""), accepted: (info.accepted ?? []).map(String) };
}

// ---------- signature (built from the profile) ----------
const COMPANY = {
  address: ["Terminalo g. 8, Kuprioniškės,", "13279 Vilniaus r. sav"],
  web: "www.eventsolutions.lt",
};
const LOGO_CID = "es-logo@eventsolutions.lt";
const personName = (p?: Person | null) => [p?.first_name, p?.last_name].filter(Boolean).join(" ") || p?.full_name || "";
const escHtml = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
export function sigText(p: Person): string {
  return ["-- ", personName(p), p.job_title || "", "",
    p.phone ? "T. " + p.phone : "", "A. " + COMPANY.address.join(" "), "W. " + COMPANY.web].filter((x, i) => x || i === 3).join("\n");
}
export function sigHtml(p: Person): string {
  const f = "font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#000;";
  const row = (k: string, v: string) =>
    `<tr><td style="${f}padding:0 14px 2px 0;vertical-align:top;">${k}</td><td style="${f}padding:0 0 2px;vertical-align:top;">${v}</td></tr>`;
  const tel = (p.phone || "").replace(/[^\d+]/g, "");
  return `<table cellpadding="0" cellspacing="0" border="0" style="margin-top:22px;border-collapse:collapse;"><tr>
<td style="padding:0 18px 0 0;border-right:1px solid #000;vertical-align:middle;"><img src="cid:${LOGO_CID}" width="120" alt="Event Solutions" style="display:block;border:0;"></td>
<td style="padding:0 0 0 18px;vertical-align:top;">
<div style="${f}font-size:15px;font-weight:bold;">${escHtml(personName(p))}</div>
${p.job_title ? `<div style="${f}color:#555;">${escHtml(p.job_title)}</div>` : ""}
<table cellpadding="0" cellspacing="0" border="0" style="margin-top:14px;border-collapse:collapse;">
${p.phone ? row("T.", `<a href="tel:${escHtml(tel)}" style="color:#1a55c4;">${escHtml(p.phone)}</a>`) : ""}
${row("A.", COMPANY.address.map(escHtml).join("<br>"))}
${row("W.", `<a href="https://${COMPANY.web}" style="color:#000;">${COMPANY.web}</a>`)}
</table></td></tr></table>`;
}
// the personal signature (letters from the Gmail address): own text, or name and phone
export function psigText(p: Person, own?: string): string {
  return "-- \n" + (own && own.trim() ? own.trim() : [personName(p), p.phone ? "T. " + p.phone : ""].filter(Boolean).join("\n"));
}
export function psigHtml(p: Person, own?: string): string {
  const f = "font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#000;";
  if (own && own.trim()) return `<div style="${f}margin-top:22px;">${escHtml(own.trim()).replace(/\r?\n/g, "<br>")}</div>`;
  const tel = (p.phone || "").replace(/[^\d+]/g, "");
  return `<div style="${f}margin-top:22px;"><b>${escHtml(personName(p))}</b>${p.phone ? `<br><a href="tel:${escHtml(tel)}" style="color:#1a55c4;">${escHtml(p.phone)}</a>` : ""}</div>`;
}
type SigKind = "work" | "personal" | "none";
const logoAttachment = () => ({ filename: "eventsolutions.png", content: Buffer.from(LOGO_PNG_BASE64, "base64"), contentType: "image/png", cid: LOGO_CID, contentDisposition: "inline" as const });
// plain text -> simple HTML; "> " lines become a quote block
export function textToHtml(text: string): string {
  const out: string[] = [];
  let quote: string[] = [];
  const flush = () => {
    if (quote.length) out.push(`<blockquote style="margin:8px 0 0;padding:0 0 0 10px;border-left:2px solid #ccc;color:#555;">${quote.join("<br>")}</blockquote>`);
    quote = [];
  };
  for (const line of text.split(/\r?\n/)) {
    if (/^>/.test(line)) quote.push(escHtml(line.replace(/^> ?/, "")));
    else { flush(); out.push(escHtml(line)); }
  }
  flush();
  return out.join("<br>").replace(/<br>(<blockquote)/g, "$1").replace(/(<\/blockquote>)<br>/g, "$1");
}
export function composeBody(text: string, quoted: string, p: Person | null, html = "", kind: SigKind = "work", own = "") {
  const wrap = (h: string) => `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#000;">${h}</div>`;
  const st = !p || kind === "none" ? "" : kind === "personal" ? psigText(p, own) : sigText(p);
  const sh = !p || kind === "none" ? "" : kind === "personal" ? psigHtml(p, own) : sigHtml(p);
  return {
    text: text + (st ? "\n\n" + st : "") + (quoted ? "\n\n" + quoted : ""),
    html: wrap((html ? cleanHtml(html) : textToHtml(text)) + sh + (quoted ? "<br><br>" + textToHtml(quoted) : "")),
  };
}
// a letter built in the app (the event letter): formatted HTML. Scripts,
// frames, forms and event handlers are removed — only formatting stays.
export function cleanHtml(h: string): string {
  return String(h).slice(0, 400_000)
    .replace(/<(script|style|iframe|object|embed|form|button|textarea|select)\b[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/<\/?(script|style|iframe|object|embed|form|input|button|textarea|select|meta|link|base)\b[^>]*>/gi, "")
    .replace(/\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    .replace(/(href|src)\s*=\s*("|')\s*(javascript|vbscript|data):[^"']*\2/gi, '$1="#"');
}

type SendBody = {
  to?: string; cc?: string; subject?: string; text?: string; quoted?: string; html?: string; sig?: boolean; from?: "work" | "personal";
  inReplyTo?: string; references?: string[]; replyUid?: number; replyFolder?: string;
  attachments?: { filename: string; contentType?: string; base64: string }[];
};
async function send(me: Me, a: Account, b: SendBody) {
  const to = parseRecipients(b.to), cc = parseRecipients(b.cc);
  if (!to.length) throw new UserError("Įrašyk gavėją.");
  if (to.length + cc.length > 100) throw new UserError("Per daug gavėjų (iki 100).");
  const atts = (b.attachments ?? []).slice(0, 10).map((x) => ({
    filename: String(x.filename || "priedas").slice(0, 200),
    contentType: x.contentType || "application/octet-stream",
    content: Buffer.from(String(x.base64 || ""), "base64"),
  }));
  if (atts.reduce((n, x) => n + x.content.length, 0) > MAX_SEND_BYTES) throw new UserError("Priedai per dideli (iki 15 MB).");
  // from which address: the work one (company mail server) or the personal Gmail (Gmail's own server)
  const personal = b.from === "personal" && !!a.reader && (await acctPref(me.id)) !== "work";
  const fromAcc: Account = personal ? a.reader! : a;
  const st = await settingsOf(me.id);
  // which signature: the event letter always the work one (b.sig); otherwise as set for that address
  const kind: SigKind = b.sig === true ? "work" : st.sig === false ? "none" : (st.sigFor?.[personal ? "personal" : "work"] ?? (personal ? "personal" : "work"));
  const body = composeBody(String(b.text ?? ""), String(b.quoted ?? ""), kind === "none" ? null : me.person, typeof b.html === "string" ? b.html : "", kind, st.psig || "");
  const withSig = kind === "work";
  const mail = {
    from: me.name ? { name: me.name, address: fromAcc.email } : fromAcc.email,
    to, cc: cc.length ? cc : undefined,
    subject: String(b.subject ?? "").slice(0, 500),
    text: body.text,
    html: body.html,
    inReplyTo: b.inReplyTo || undefined,
    references: b.references?.length ? b.references.slice(-20) : b.inReplyTo || undefined,
    attachments: withSig ? [...atts, logoAttachment()] : atts,
  };
  const raw: Buffer = await new MailComposer(mail).compile().build();
  let server: { response: string; accepted: string[] };
  try {
    server = await smtpSend(fromAcc, [...to, ...cc], raw);
    console.log("sent", fromAcc.email, "->", server.accepted.join(","), server.response);
  } catch (e) {
    console.error("smtp", (e as Error).message);
    throw new UserError("Laiško išsiųsti nepavyko: " + ((e as { response?: string }).response || (e as Error).message).slice(0, 200));
  }
  // a copy in "Sent" and the original marked as answered; the mail is already
  // out, so problems here are not reported as a failure
  // (read through Gmail: the copy also goes to the company mailbox's "Sent")
  // (sent through Gmail's server: Gmail keeps the copy itself)
  if (a.reader && !personal) withImap(a, async (c) => { await c.append(await folderPath(c, "sent"), raw, ["\\Seen"]); }, false).catch((e) => console.error("append company", e?.message));
  await withImap(readerOf(a), async (c) => {
    if (!personal) await c.append(await folderPath(c, "sent"), raw, ["\\Seen"]).catch((e: Error) => console.error("append", e?.message));
    if (b.replyUid && b.replyFolder) {
      const lock = await c.getMailboxLock(await folderPath(c, b.replyFolder));
      try {
        await c.messageFlagsAdd(String(b.replyUid), ["\\Answered"], { uid: true });
      } finally {
        lock.release();
      }
    }
  }, false).catch((e) => console.error("after send", e?.message));
  return { ok: true, accepted: server.accepted, server: server.response.slice(0, 200) };
}

// ---------- account storage ----------
type Reader = { email: string; host: string; secret: string };
async function accountOf(row: { email: string; secret: string; reader?: Reader | null }): Promise<Account> {
  const a: Account = { email: row.email, password: await unseal(row.secret) };
  if (row.reader?.email && row.reader?.secret) a.reader = { email: row.reader.email, host: row.reader.host || GMAIL_IMAP, password: await unseal(row.reader.secret) };
  return a;
}
// letters of another mailbox: what the app keeps about the old one (list, texts) is cleared
async function clearIndex(uid: string) {
  for (const t of ["mail_index", "mail_sync", "mail_bodies"]) await db(`${t}?user_id=eq.${uid}`, { method: "DELETE" }).catch(() => null);
  const [row] = await db<{ state: Record<string, unknown> | null }[]>(`mail_accounts?select=state&user_id=eq.${uid}`);
  if (row) await db(`mail_accounts?user_id=eq.${uid}`, { method: "PATCH", body: JSON.stringify({ state: { ...(row.state ?? {}), auto: {} } }) });
}
const accCache = new Map<string, { a: Account | null; exp: number }>();
async function account(uid: string): Promise<Account | null> {
  const hit = accCache.get(uid);
  if (hit && hit.exp > Date.now()) return hit.a;
  const [row] = await db<{ email: string; secret: string; reader?: Reader | null }[]>(`mail_accounts?select=email,secret,reader&user_id=eq.${uid}`);
  const a = row ? await accountOf(row) : null;
  accCache.set(uid, { a, exp: Date.now() + 60_000 });
  return a;
}

// ---------- settings: signature and automatic reply ----------
type Settings = {
  sig?: boolean; // add the signature (default on)
  psig?: string; // the personal signature's own text (empty: name and phone)
  sigFor?: { work?: SigKind; personal?: SigKind }; // which signature letters from each address carry
  auto?: { on?: boolean; from?: string; to?: string; subject?: string; text?: string; since?: string };
  mirror?: { on?: boolean; since?: string }; // new company-mailbox letters copied into Gmail (set by „mirror_save“)
};
const dateRe = /^\d{4}-\d{2}-\d{2}$/;
export function cleanSettings(v: unknown, prev: Settings = {}): Settings {
  const i = (v ?? {}) as Settings, a = i.auto ?? {};
  const on = a.on === true;
  const text = String(a.text ?? "").slice(0, 5000);
  if (on && !text.trim()) throw new UserError("Įrašyk automatinio atsakymo tekstą.");
  const from = dateRe.test(String(a.from ?? "")) ? String(a.from) : "";
  const to = dateRe.test(String(a.to ?? "")) ? String(a.to) : "";
  if (from && to && to < from) throw new UserError("Pabaigos data ankstesnė už pradžią.");
  const sk = (v: unknown, d: SigKind): SigKind => (["work", "personal", "none"].includes(String(v)) ? String(v) as SigKind : d);
  return {
    ...(prev.mirror ? { mirror: prev.mirror } : {}),   // changed only by „mirror_save“
    sig: i.sig !== false,
    psig: String(i.psig ?? "").slice(0, 2000),
    sigFor: { work: sk(i.sigFor?.work, "work"), personal: sk(i.sigFor?.personal, "personal") },
    auto: {
      on, from, to, text,
      subject: String(a.subject ?? "").slice(0, 300),
      // replies only to mail that arrives after it was switched on
      since: on ? (prev.auto?.on && prev.auto.since ? prev.auto.since : new Date().toISOString()) : undefined,
    },
  };
}
async function settingsOf(uid: string): Promise<Settings> {
  const [row] = await db<{ settings: Settings | null }[]>(`mail_accounts?select=settings&user_id=eq.${uid}`);
  return row?.settings ?? {};
}

const TZ = "Europe/Vilnius";
const todayVilnius = (now = new Date()) => new Intl.DateTimeFormat("en-CA", { timeZone: TZ }).format(now);
export function autoActive(a: Settings["auto"], now = new Date()): boolean {
  if (!a?.on || !a.text) return false;
  const d = todayVilnius(now);
  return (!a.from || d >= a.from) && (!a.to || d <= a.to);
}
// start of the reply window: switched on, or the start date (Vilnius midnight)
function autoStart(a: NonNullable<Settings["auto"]>): number {
  const since = a.since ? Date.parse(a.since) : Date.now();
  if (!a.from) return since;
  const [y, m, d] = a.from.split("-").map(Number);
  const guess = Date.UTC(y, m - 1, d); // midnight in Vilnius is 21:00 or 22:00 UTC the day before
  const off = new Date(guess).toLocaleString("en-US", { timeZone: TZ, hour: "2-digit", hour12: false });
  return Math.max(since, guess - Number(off) * 3600e3);
}
// never answer robots, mailing lists or other automatic replies
export function autoSkip(from: string, own: string, headers: string): boolean {
  const f = from.toLowerCase();
  if (!f || f === own.toLowerCase()) return true;
  if (/^(no-?reply|do-?not-?reply|mailer-daemon|postmaster|bounce|notifications?)([+.@-]|$)/.test(f)) return true;
  const h = headers.toLowerCase();
  if (/^auto-submitted:\s*(?!no\b)\S/m.test(h)) return true;
  if (/^precedence:\s*(bulk|junk|list|auto_reply)/m.test(h)) return true;
  if (/^(list-id|list-unsubscribe|x-autoreply|x-autorespond|feedback-id):/m.test(h)) return true;
  if (/^x-auto-response-suppress:.*\b(all|oof|autoreply)\b/m.test(h)) return true;
  return false;
}
type AutoState = { uidValidity?: string; lastUid?: number; replied?: Record<string, number>;
  last?: { at: string; checked: number; sent: string[]; skipped: { from: string; why: string }[]; err?: string } };
const REPLY_EVERY = 4 * 24 * 3600e3; // the same sender gets the auto reply once per 4 days

async function autoReplyFor(row: { user_id: string; email: string; secret: string; reader?: Reader | null; settings: Settings; state: { auto?: AutoState } | null }) {
  const a = await accountOf(row);
  const auto = row.settings.auto!;
  // one run at a time for a mailbox (the instant reply and the minute check could meet): a 90-second lock
  const now = new Date().toISOString();
  const locked = await db<{ state: { auto?: AutoState } | null }[]>(
    `mail_accounts?user_id=eq.${row.user_id}&or=(state->auto->>busy.is.null,state->auto->>busy.lt.${now})`,
    { method: "PATCH", headers: { Prefer: "return=representation" },
      body: JSON.stringify({ state: { ...(row.state ?? {}), auto: { ...(row.state?.auto ?? {}), busy: new Date(Date.now() + 90_000).toISOString() } } }) });
  if (!locked.length) return 0;
  row.state = locked[0].state;
  const st: AutoState & { busy?: string } = { ...(row.state?.auto ?? {}) };
  delete st.busy;
  const replied: Record<string, number> = {};
  for (const [k, t] of Object.entries(st.replied ?? {})) if (Date.now() - t < REPLY_EVERY) replied[k] = t;
  const [p] = await db<Person[]>(`profiles?select=*&id=eq.${row.user_id}`);
  const fromName = personName(p);
  const out: { to: string; subject: string; messageId: string; references: string[] }[] = [];
  // what this run did – shown in Nustatymai, so it is clear why a letter got no reply
  const diag: NonNullable<AutoState["last"]> = { at: new Date().toISOString(), checked: 0, sent: [], skipped: [] };
  const skip = (from: string, why: string) => { if (diag.skipped.length < 10) diag.skipped.push({ from: from.slice(0, 120), why }); };
  await withImap(readerOf(a), async (c) => {
    const lock = await c.getMailboxLock("INBOX");
    try {
      const mb = c.mailbox as { uidValidity: bigint; uidNext: number };
      const validity = String(mb.uidValidity);
      const fresh = st.uidValidity !== validity || !st.lastUid;
      const start = autoStart(auto);
      let uids: number[];
      if (fresh) {
        // first run in this window: everything that came after it began
        const since = new Date(start - 24 * 3600e3);
        uids = ((await c.search({ since }, { uid: true })) || []) as number[];
      } else {
        uids = (((await c.search({ uid: `${st.lastUid! + 1}:*` }, { uid: true })) || []) as number[]).filter((u) => u > st.lastUid!);
      }
      let last = fresh ? mb.uidNext - 1 : st.lastUid!;
      if (uids.length) {
        for await (const m of c.fetch(uids.slice(-100).join(","), {
          uid: true, envelope: true, internalDate: true,
          headers: ["auto-submitted", "precedence", "list-id", "list-unsubscribe", "x-autoreply", "x-autorespond", "x-auto-response-suppress", "feedback-id"],
        }, { uid: true })) {
          last = Math.max(last, m.uid);
          const got = (m.internalDate as Date | undefined)?.getTime?.() ?? 0;
          if (got < start) continue;
          diag.checked++;
          const who = m.envelope?.replyTo?.[0]?.address || m.envelope?.from?.[0]?.address || "";
          if (autoSkip(who, a.email, m.headers ? m.headers.toString() : "")) { skip(who, "automatinis laiškas, naujienlaiškis arba tavo paties adresas"); continue; }
          // read through Gmail: only letters that came to the work address get the work auto reply (not personal mail)
          if (a.reader) {
            const dom = "@" + (Deno.env.get("MAIL_WORK_DOMAIN") || "eventsolutions.lt").toLowerCase();
            const env = m.envelope as { to?: Addr[]; cc?: Addr[] } | undefined;
            if (![...(env?.to ?? []), ...(env?.cc ?? [])].some((x) => String(x.address || "").toLowerCase().endsWith(dom))) { skip(who, "laiškas ne į darbo adresą"); continue; }
          }
          const key = who.toLowerCase();
          if (replied[key]) { skip(who, "šiam siuntėjui jau atsakyta per paskutines 4 d."); continue; }
          if (out.some((x) => x.to === key) || out.length >= 30) continue;
          const orig = m.envelope?.subject || "";
          out.push({
            to: key,
            subject: auto.subject?.trim() || ("Automatinis atsakymas: " + orig).trim(),
            messageId: m.envelope?.messageId || "",
            references: m.envelope?.messageId ? [m.envelope.messageId] : [],
          });
        }
      }
      st.uidValidity = validity;
      st.lastUid = last;
    } finally {
      lock.release();
    }
  });
  let sent = 0;
  const withSig = row.settings.sig !== false && !!p;
  const body = composeBody(auto.text!, "", withSig ? p : null);
  for (const r of out) {
    try {
      const mail = {
        from: fromName ? { name: fromName, address: a.email } : a.email,
        to: r.to, subject: r.subject,
        text: body.text, html: body.html,
        attachments: withSig ? [logoAttachment()] : [],
        inReplyTo: r.messageId || undefined, references: r.references.length ? r.references : undefined,
        headers: { "Auto-Submitted": "auto-replied", "X-Auto-Response-Suppress": "All", Precedence: "auto_reply" },
      };
      await smtpSend(a, [r.to], await new MailComposer(mail).compile().build());
      replied[r.to] = Date.now();
      sent++; diag.sent.push(r.to);
    } catch (e) {
      console.error("auto reply", row.email, (e as Error).message);
      diag.err = "Išsiųsti nepavyko: " + (e as Error).message.slice(0, 200);
    }
  }
  st.replied = replied;
  if (diag.checked || diag.err) st.last = diag;
  await db(`mail_accounts?user_id=eq.${row.user_id}`, { method: "PATCH", body: JSON.stringify({ state: { ...(row.state ?? {}), auto: st } }) });
  return sent;
}

async function runAutoReplies() {
  const rows = await db<{ user_id: string; email: string; secret: string; reader?: Reader | null; settings: Settings; state: { auto?: AutoState } | null }[]>(
    "mail_accounts?select=user_id,email,secret,reader,settings,state&settings->auto->>on=eq.true",
  );
  let sent = 0, checked = 0;
  for (const row of rows) {
    if (!autoActive(row.settings.auto)) {
      // outside the dates: forget the position, so the next window starts clean
      if (row.state?.auto?.lastUid) {
        await db(`mail_accounts?user_id=eq.${row.user_id}`, { method: "PATCH", body: JSON.stringify({ state: { ...(row.state ?? {}), auto: {} } }) });
      }
      continue;
    }
    checked++;
    try {
      sent += await autoReplyFor(row);
    } catch (e) {
      console.error("auto reply", row.email, (e as Error).message);
    }
  }
  return { checked, sent };
}

async function handle(me: Me, body: Record<string, unknown>) {
  const action = String(body.action ?? "");
  if (action === "connect") {
    const email = String(body.email ?? "").trim().toLowerCase(), password = String(body.password ?? "");
    if (!emailRe.test(email) || !password) throw new UserError("Įrašyk el. paštą ir slaptažodį.");
    const a = { email, password };
    await withImap(a, async () => null); // wrong password -> UserError
    accCache.delete(me.id);
    await db("mail_accounts?on_conflict=user_id", {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates" },
      body: JSON.stringify({ user_id: me.id, email, secret: await seal(password), updated_at: new Date().toISOString() }),
    });
    return { connected: true, email };
  }
  if (action === "disconnect") {
    await db(`mail_accounts?user_id=eq.${me.id}`, { method: "DELETE" });
    accCache.delete(me.id);
    return { connected: false };
  }
  if (action.startsWith("inv_inbox_")) return await inboxAction(me, action, body);
  const a0 = await account(me.id);
  if (!a0) return { connected: false };
  // „Gauti per Gmail“: letters read from Gmail (the company server forwards to it), sent as before
  if (action === "connect_reader") {
    const email = String(body.email ?? "").trim().toLowerCase(), password = String(body.password ?? "").replace(/\s+/g, "");
    if (!emailRe.test(email) || !password) throw new UserError("Įrašyk Gmail adresą ir programos slaptažodį.");
    const host = GMAIL_IMAP;
    try { await withImap({ email, password, host }, async () => null, false); }
    catch (e) { throw e instanceof UserError && /Neteisingas/.test(e.message) ? new UserError("Gmail neprisijungė: patikrink adresą ir programos slaptažodį (16 raidžių, iš myaccount.google.com/apppasswords).") : e; }
    await db(`mail_accounts?user_id=eq.${me.id}`, { method: "PATCH", body: JSON.stringify({ reader: { email, host, secret: await seal(password) }, updated_at: new Date().toISOString() }) });
    accCache.delete(me.id);
    await clearIndex(me.id);
    return { ok: true, reader: email };
  }
  if (action === "disconnect_reader") {
    await db(`mail_accounts?user_id=eq.${me.id}`, { method: "PATCH", body: JSON.stringify({ reader: null }) });
    accCache.delete(me.id);
    await clearIndex(me.id);
    return { ok: true, reader: null };
  }
  const a = readerOf(a0);            // reading: Gmail when connected, otherwise the company mailbox
  if (action === "settings") {
    return {
      connected: true, email: a0.email, reader: a0.reader?.email ?? null, settings: await settingsOf(me.id),
      companyHost: a0.host || env("MAIL_IMAP_HOST", "koala.serveriai.lt"),
      psignature: psigHtml(me.person, (await settingsOf(me.id)).psig || ""),
      ...(await (async () => {
        const stt = (await db<{ state: { auto?: AutoState; mirror?: MirrorState } | null }[]>(`mail_accounts?select=state&user_id=eq.${me.id}`))[0]?.state;
        return { autoLast: stt?.auto?.last ?? null, mirror: { last: stt?.mirror?.last ?? null, copied: stt?.mirror?.copied ?? 0, removed: stt?.mirror?.removed ?? 0 } };
      })()),
      signature: sigHtml(me.person).replace(`cid:${LOGO_CID}`, "data:image/png;base64," + LOGO_PNG_BASE64),
    };
  }
  // RainLoop → Gmail: switch on/off, or check now
  if (action === "mirror_back") {
    if (!a0.reader) throw new UserError("Pirmiausia prijunk Gmail.");
    const hours = Math.min(168, Math.max(1, Number(body.hours) || 1));
    const [row] = await db<MirrorRow[]>(`mail_accounts?select=user_id,email,secret,reader,settings,state&user_id=eq.${me.id}`);
    return { ok: true, hours, ...(await mirrorBack(row, hours)) };
  }
  if (action === "mirror_save" || action === "mirror_now") {
    if (!a0.reader) throw new UserError("Pirmiausia prijunk Gmail.");
    const prev = await settingsOf(me.id);
    if (action === "mirror_save") {
      const on = body.on === true;
      const settings = { ...prev, mirror: { on, since: on ? (prev.mirror?.on && prev.mirror.since ? prev.mirror.since : new Date().toISOString()) : undefined } };
      await db(`mail_accounts?user_id=eq.${me.id}`, { method: "PATCH", body: JSON.stringify({ settings }) });
      if (!on) { await mirrorSave(me.id, {}); return { ok: true, on }; }   // switched off: the position is forgotten (on again = from then)
    }
    const [row] = await db<MirrorRow[]>(`mail_accounts?select=user_id,email,secret,reader,settings,state&user_id=eq.${me.id}`);
    const r = await mirrorFor(row, true);
    const stt = (await db<{ state: { mirror?: MirrorState } | null }[]>(`mail_accounts?select=state&user_id=eq.${me.id}`))[0]?.state?.mirror;
    return { ok: true, on: !!row.settings?.mirror?.on, result: r, last: stt?.last ?? null, copied: stt?.copied ?? 0, removed: stt?.removed ?? 0 };
  }
  if (action === "settings_save") {
    const settings = cleanSettings(body.settings, await settingsOf(me.id));
    await db(`mail_accounts?user_id=eq.${me.id}`, { method: "PATCH", body: JSON.stringify({ settings }) });
    return { ok: true, settings };
  }
  const folder = String(body.folder ?? "inbox"), uid = Number(body.uid);
  const needUid = () => { if (!Number.isInteger(uid) || uid <= 0) throw new UserError("Nežinomas laiškas."); };
  switch (action) {
    case "status":
      return await withImap(a, async (c) => ({ connected: true, email: a0.email, reader: a0.reader?.email ?? null, unseen: (await c.status("INBOX", { unseen: true })).unseen ?? 0 }))
        .catch((e) => ({ connected: true, email: a0.email, reader: a0.reader?.email ?? null, error: e instanceof UserError ? e.message : "Paštas nepasiekiamas." }));
    case "list": {
      const st = await settingsOf(me.id);
      return { connected: true, email: a0.email, reader: a0.reader?.email ?? null, autoOn: autoActive(st.auto), sig: st.sig !== false, ...(await list(a, folder, Math.max(0, Number(body.page) || 0))) };
    }
    case "sync": {
      const st = await settingsOf(me.id);
      if (folder === "inbox" && a0.reader && st.mirror?.on) {
        const [row] = await db<MirrorRow[]>(`mail_accounts?select=user_id,email,secret,reader,settings,state&user_id=eq.${me.id}`);
        if (row) await withTimeout(mirrorFor(row), 25_000, "mirror").catch((e) => console.error("mirror on sync", (e as Error).message));
      }
      return { connected: true, email: a0.email, reader: a0.reader?.email ?? null, only: a0.reader ? await acctPref(me.id) : "all", autoOn: autoActive(st.auto), sig: st.sig !== false, ...(await syncFolder(me.id, a, folder)) };
    }
    case "read": {
      needUid();
      const r = await read(a, folder, uid, body.peek === true);
      if (body.peek !== true) idxPatch(me.id, folder, uid, { seen: true });
      bodySave(me.id, folder, uid, r).catch(() => {});
      return r;
    }
    case "folders":
      return { connected: true, folders: await folders(a, a0.reader ? await acctPref(me.id) : "all") };
    case "flag": {
      needUid();
      const r = await star(a, folder, uid, body.flagged !== false);
      await idxPatch(me.id, folder, uid, { flagged: body.flagged !== false });
      return r;
    }
    case "move": {
      needUid();
      const r = await move(a, folder, uid, String(body.to ?? ""));
      await idxGone(me.id, folder, uid);
      return r;
    }
    case "attachment":
      needUid();
      return await attachment(a, folder, uid, String(body.index ?? ""));
    case "seen": {
      needUid();
      const r = await flag(a, folder, uid, body.seen !== false);
      await idxPatch(me.id, folder, uid, { seen: body.seen !== false });
      return r;
    }
    case "delete": {
      needUid();
      const r = await remove(a, folder, uid);
      await idxGone(me.id, folder, uid);
      return r;
    }
    case "search":
      return { connected: true, ...(await search(a, body as SearchBody, a0.reader ? await acctPref(me.id) : "all")) };
    case "send":
      return await send(me, a0, body as SendBody);
  }
  throw new UserError("Nežinomas veiksmas.");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  try {
    if (req.headers.get("x-cron-secret")) {
      const secret = Deno.env.get("CRON_SECRET");
      if (!secret || req.headers.get("x-cron-secret") !== secret) return json({ error: "Unauthorized" }, 401);
      const cb = await req.clone().json().catch(() => ({}));
      if ((cb as { action?: string }).action === "sync_all") return json(await runSyncAll((cb as { quick?: boolean }).quick === true));
      if ((cb as { action?: string }).action === "invoice_inbox") return json(await runInvoiceInbox(false, 0, (cb as { quick?: boolean }).quick === true ? 3 : 8) ?? { off: true });
      // (the old 10-minute job – sql/mail_auto.sql switches it off: the replies now go with the minute sync)
      return json(await runAutoReplies());
    }
    const me = await caller(req);
    if (!me) return json({ error: "Programėlės sesija pasibaigė — perkrauk puslapį arba atsijunk ir prisijunk iš naujo." }, 401);
    const body = await req.json().catch(() => ({}));
    return json(await handle(me, body));
  } catch (err) {
    if (err instanceof UserError) return json({ error: err.message }, 400);
    console.error(err instanceof Error ? err.stack || err.message : err);
    return json({ error: "Pašto klaida. Pabandyk dar kartą." }, 500);
  }
});
