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
//   list      {folder:"inbox"|"sent", page}
//   read      {folder, uid}              -> full message (marks it read)
//   attachment{folder, uid, index}       -> { filename, contentType, base64 }
//   send      {to, cc, subject, text, quoted, inReplyTo, references, attachments:[{filename,contentType,base64}]}
//   seen      {folder, uid, seen}
//   delete    {folder, uid}              -> moves to Trash
//   settings / settings_save {settings:{sig, auto:{on,from,to,subject,text}}}
//   (the signature is built from the profile: name, job title, phone)
// POST with header x-cron-secret: <CRON_SECRET> (every 10 min from pg_cron)
//   sends the automatic replies ("out of office") for everyone who has it on
//
// Secrets: MAIL_SECRET (any long random text), optional MAIL_IMAP_HOST
// (default koala.serveriai.lt), MAIL_IMAP_PORT (993), MAIL_SMTP_HOST
// (same as IMAP), MAIL_SMTP_PORT (465). Supabase blocks ports 25 and 587,
// so SMTP must be 465 (SSL).

import { ImapFlow } from "npm:imapflow@1.0.171";
import nodemailer from "npm:nodemailer@6.9.16";
import MailComposer from "npm:nodemailer@6.9.16/lib/mail-composer/index.js";
import { simpleParser } from "npm:mailparser@3.7.2";
import { Buffer } from "node:buffer";
import { LOGO_PNG_BASE64 } from "./logo.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const APPROVED = ["admin", "office", "tech", "freelance", "runner"];
// the app shows a warning when the deployed function is older than it expects
const VERSION = 3;
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
async function caller(req: Request): Promise<Me | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const res = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, {
    headers: { apikey: env("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  const u = await res.json();
  if (!u?.id) return null;
  const [p] = await db<(Person & { role: string })[]>(`profiles?select=*&id=eq.${u.id}`);
  if (!p || !APPROVED.includes(p.role)) return null;
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
type Account = { email: string; password: string };
const insecure = () => Deno.env.get("MAIL_TLS_INSECURE") === "1"; // tests only
function imapClient(a: Account) {
  return new ImapFlow({
    host: env("MAIL_IMAP_HOST", "koala.serveriai.lt"),
    port: Number(env("MAIL_IMAP_PORT", "993")),
    secure: true,
    auth: { user: a.email, pass: a.password },
    logger: false,
    tls: { rejectUnauthorized: !insecure() },
    connectionTimeout: 15000,
    greetingTimeout: 10000,
  });
}
async function withImap<T>(a: Account, fn: (c: ImapFlow) => Promise<T>): Promise<T> {
  const c = imapClient(a);
  c.on("error", () => {});
  try {
    await c.connect();
  } catch (e) {
    const err = e as { authenticationFailed?: boolean; code?: string };
    if (err.authenticationFailed) throw new UserError("Neteisingas el. paštas arba slaptažodis.");
    throw new UserError("Nepavyko prisijungti prie pašto serverio.");
  }
  try {
    return await fn(c);
  } finally {
    await c.logout().catch(() => c.close());
  }
}
async function folderPath(c: ImapFlow, folder: string): Promise<string> {
  if (folder === "inbox") return "INBOX";
  const use = folder === "sent" ? "\\Sent" : folder === "trash" ? "\\Trash" : "";
  if (!use) throw new UserError("Nežinomas aplankas.");
  const list = await c.list();
  const hit = list.find((m) => m.specialUse === use) ??
    list.find((m) => (folder === "sent" ? /^(inbox[./])?(sent|išsiųsti)/i : /^(inbox[./])?(trash|deleted|šiukšl)/i).test(m.path));
  if (hit) return hit.path;
  // create it the way most hosting servers (Dovecot) name it
  const name = folder === "sent" ? "Sent" : "Trash";
  const sep = list.find((m) => m.path.toUpperCase() !== "INBOX")?.delimiter ?? ".";
  const path = list.some((m) => m.path.toUpperCase().startsWith("INBOX" + sep)) ? `INBOX${sep}${name}` : name;
  await c.mailboxCreate(path).catch(() => {});
  return path;
}

type Addr = { name?: string; address?: string };
const addr = (l?: Addr[]) => (l ?? []).map((x) => ({ name: x.name || "", address: x.address || "" }));

function hasAttachments(node: { disposition?: string; childNodes?: unknown[]; type?: string } | undefined): boolean {
  if (!node) return false;
  if (node.disposition === "attachment") return true;
  return ((node.childNodes ?? []) as typeof node[]).some(hasAttachments);
}

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
            uid: m.uid,
            date: (m.envelope?.date ?? m.internalDate)?.toISOString?.() ?? null,
            subject: m.envelope?.subject || "",
            from: addr(m.envelope?.from),
            to: addr(m.envelope?.to),
            seen: m.flags?.has("\\Seen") ?? false,
            answered: m.flags?.has("\\Answered") ?? false,
            attachments: hasAttachments(m.bodyStructure as never),
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

async function fetchParsed(c: ImapFlow, uid: number) {
  const msg = await c.fetchOne(String(uid), { source: true, flags: true }, { uid: true });
  if (!msg || !msg.source) throw new UserError("Laiškas nerastas (gal jau ištrintas).");
  return { msg, parsed: await simpleParser(msg.source) };
}
const addrText = (a: unknown) => {
  const v = (a as { value?: Addr[] } | undefined)?.value ?? [];
  return addr(v);
};

async function read(a: Account, folder: string, uid: number) {
  return await withImap(a, async (c) => {
    const path = await folderPath(c, folder);
    const lock = await c.getMailboxLock(path);
    try {
      const { msg, parsed } = await fetchParsed(c, uid);
      if (!msg.flags?.has("\\Seen")) await c.messageFlagsAdd(String(uid), ["\\Seen"], { uid: true });
      const refs = parsed.references ? ([] as string[]).concat(parsed.references) : [];
      return {
        uid,
        messageId: parsed.messageId || "",
        references: refs,
        date: parsed.date?.toISOString() ?? null,
        subject: parsed.subject || "",
        from: addrText(parsed.from),
        to: addrText(parsed.to),
        cc: addrText(parsed.cc),
        replyTo: addrText(parsed.replyTo),
        text: parsed.text || "",
        html: typeof parsed.html === "string" ? parsed.html : "",
        attachments: parsed.attachments
          .map((x, index) => ({ index, filename: x.filename || "priedas", contentType: x.contentType, size: x.size, inline: x.related || x.contentDisposition === "inline" }))
          .filter((x) => !x.inline || !x.contentType.startsWith("image/")),
      };
    } finally {
      lock.release();
    }
  });
}

async function attachment(a: Account, folder: string, uid: number, index: number) {
  return await withImap(a, async (c) => {
    const lock = await c.getMailboxLock(await folderPath(c, folder));
    try {
      const { parsed } = await fetchParsed(c, uid);
      const x = parsed.attachments[index];
      if (!x) throw new UserError("Priedas nerastas.");
      return { filename: x.filename || "priedas", contentType: x.contentType, base64: Buffer.from(x.content).toString("base64") };
    } finally {
      lock.release();
    }
  });
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
  });
}

async function remove(a: Account, folder: string, uid: number) {
  return await withImap(a, async (c) => {
    const trash = await folderPath(c, "trash");
    const lock = await c.getMailboxLock(await folderPath(c, folder));
    try {
      await c.messageMove(String(uid), trash, { uid: true });
      return { ok: true };
    } finally {
      lock.release();
    }
  });
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
    host: env("MAIL_SMTP_HOST", env("MAIL_IMAP_HOST", "koala.serveriai.lt")),
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
export function composeBody(text: string, quoted: string, p: Person | null) {
  const wrap = (h: string) => `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#000;">${h}</div>`;
  return {
    text: text + (p ? "\n\n" + sigText(p) : "") + (quoted ? "\n\n" + quoted : ""),
    html: wrap(textToHtml(text) + (p ? sigHtml(p) : "") + (quoted ? "<br><br>" + textToHtml(quoted) : "")),
  };
}

type SendBody = {
  to?: string; cc?: string; subject?: string; text?: string; quoted?: string;
  inReplyTo?: string; references?: string[]; replyUid?: number; replyFolder?: string;
  attachments?: { filename: string; contentType?: string; base64: string }[];
};
async function send(me: Me, a: Account, b: SendBody) {
  const to = parseRecipients(b.to), cc = parseRecipients(b.cc);
  if (!to.length) throw new UserError("Įrašyk gavėją.");
  if (to.length + cc.length > 50) throw new UserError("Per daug gavėjų (iki 50).");
  const atts = (b.attachments ?? []).slice(0, 10).map((x) => ({
    filename: String(x.filename || "priedas").slice(0, 200),
    contentType: x.contentType || "application/octet-stream",
    content: Buffer.from(String(x.base64 || ""), "base64"),
  }));
  if (atts.reduce((n, x) => n + x.content.length, 0) > MAX_SEND_BYTES) throw new UserError("Priedai per dideli (iki 15 MB).");
  const withSig = (await settingsOf(me.id)).sig !== false;
  const body = composeBody(String(b.text ?? ""), String(b.quoted ?? ""), withSig ? me.person : null);
  const mail = {
    from: me.name ? { name: me.name, address: a.email } : a.email,
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
    server = await smtpSend(a, [...to, ...cc], raw);
    console.log("sent", a.email, "->", server.accepted.join(","), server.response);
  } catch (e) {
    console.error("smtp", (e as Error).message);
    throw new UserError("Laiško išsiųsti nepavyko: " + ((e as { response?: string }).response || (e as Error).message).slice(0, 200));
  }
  // a copy in "Sent" and the original marked as answered; the mail is already
  // out, so problems here are not reported as a failure
  await withImap(a, async (c) => {
    await c.append(await folderPath(c, "sent"), raw, ["\\Seen"]).catch((e) => console.error("append", e?.message));
    if (b.replyUid && b.replyFolder) {
      const lock = await c.getMailboxLock(await folderPath(c, b.replyFolder));
      try {
        await c.messageFlagsAdd(String(b.replyUid), ["\\Answered"], { uid: true });
      } finally {
        lock.release();
      }
    }
  }).catch((e) => console.error("after send", e?.message));
  return { ok: true, accepted: server.accepted, server: server.response.slice(0, 200) };
}

// ---------- account storage ----------
async function account(uid: string): Promise<Account | null> {
  const [row] = await db<{ email: string; secret: string }[]>(`mail_accounts?select=email,secret&user_id=eq.${uid}`);
  if (!row) return null;
  return { email: row.email, password: await unseal(row.secret) };
}

// ---------- settings: signature and automatic reply ----------
type Settings = {
  sig?: boolean; // add the signature (default on)
  auto?: { on?: boolean; from?: string; to?: string; subject?: string; text?: string; since?: string };
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
  return {
    sig: i.sig !== false,
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
type AutoState = { uidValidity?: string; lastUid?: number; replied?: Record<string, number> };
const REPLY_EVERY = 4 * 24 * 3600e3; // the same sender gets the auto reply once per 4 days

async function autoReplyFor(row: { user_id: string; email: string; secret: string; settings: Settings; state: { auto?: AutoState } | null }) {
  const a = { email: row.email, password: await unseal(row.secret) };
  const auto = row.settings.auto!;
  const st: AutoState = { ...(row.state?.auto ?? {}) };
  const replied: Record<string, number> = {};
  for (const [k, t] of Object.entries(st.replied ?? {})) if (Date.now() - t < REPLY_EVERY) replied[k] = t;
  const [p] = await db<Person[]>(`profiles?select=*&id=eq.${row.user_id}`);
  const fromName = personName(p);
  const out: { to: string; subject: string; messageId: string; references: string[] }[] = [];
  await withImap(a, async (c) => {
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
          const who = m.envelope?.replyTo?.[0]?.address || m.envelope?.from?.[0]?.address || "";
          if (autoSkip(who, a.email, m.headers ? m.headers.toString() : "")) continue;
          const key = who.toLowerCase();
          if (replied[key] || out.some((x) => x.to === key) || out.length >= 30) continue;
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
      sent++;
    } catch (e) {
      console.error("auto reply", row.email, (e as Error).message);
    }
  }
  st.replied = replied;
  await db(`mail_accounts?user_id=eq.${row.user_id}`, { method: "PATCH", body: JSON.stringify({ state: { ...(row.state ?? {}), auto: st } }) });
  return sent;
}

async function runAutoReplies() {
  const rows = await db<{ user_id: string; email: string; secret: string; settings: Settings; state: { auto?: AutoState } | null }[]>(
    "mail_accounts?select=user_id,email,secret,settings,state&settings->auto->>on=eq.true",
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
    await db("mail_accounts?on_conflict=user_id", {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates" },
      body: JSON.stringify({ user_id: me.id, email, secret: await seal(password), updated_at: new Date().toISOString() }),
    });
    return { connected: true, email };
  }
  if (action === "disconnect") {
    await db(`mail_accounts?user_id=eq.${me.id}`, { method: "DELETE" });
    return { connected: false };
  }
  const a = await account(me.id);
  if (!a) return { connected: false };
  if (action === "settings") {
    return {
      connected: true, email: a.email, settings: await settingsOf(me.id),
      signature: sigHtml(me.person).replace(`cid:${LOGO_CID}`, "data:image/png;base64," + LOGO_PNG_BASE64),
    };
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
      return await withImap(a, async (c) => ({ connected: true, email: a.email, unseen: (await c.status("INBOX", { unseen: true })).unseen ?? 0 }))
        .catch((e) => ({ connected: true, email: a.email, error: e instanceof UserError ? e.message : "Paštas nepasiekiamas." }));
    case "list": {
      const st = await settingsOf(me.id);
      return { connected: true, email: a.email, autoOn: autoActive(st.auto), sig: st.sig !== false, ...(await list(a, folder, Math.max(0, Number(body.page) || 0))) };
    }
    case "read":
      needUid();
      return await read(a, folder, uid);
    case "attachment":
      needUid();
      return await attachment(a, folder, uid, Number(body.index) || 0);
    case "seen":
      needUid();
      return await flag(a, folder, uid, body.seen !== false);
    case "delete":
      needUid();
      return await remove(a, folder, uid);
    case "send":
      return await send(me, a, body as SendBody);
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
      return json(await runAutoReplies());
    }
    const me = await caller(req);
    if (!me) return json({ error: "Reikia prisijungti." }, 401);
    const body = await req.json().catch(() => ({}));
    return json(await handle(me, body));
  } catch (err) {
    if (err instanceof UserError) return json({ error: err.message }, 400);
    console.error(err instanceof Error ? err.stack || err.message : err);
    return json({ error: "Pašto klaida. Pabandyk dar kartą." }, 500);
  }
});
