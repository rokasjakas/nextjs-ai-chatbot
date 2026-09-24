// Supabase Edge Function: mail
//
// Lets a team member read and answer their own @eventsolutions.lt mailbox
// (hosting IMAP/SMTP, e.g. Serveriai.lt) from the profile page.
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
//   send      {to, cc, subject, text, inReplyTo, references, attachments:[{filename,contentType,base64}]}
//   seen      {folder, uid, seen}
//   delete    {folder, uid}              -> moves to Trash
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

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const APPROVED = ["admin", "office", "tech", "freelance", "runner"];
const PAGE = 25;
const MAX_SEND_BYTES = 15 * 1024 * 1024;

class UserError extends Error {}

function json(body: unknown, status = 200): Response {
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

type Me = { id: string; role: string; name: string };
async function caller(req: Request): Promise<Me | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const res = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, {
    headers: { apikey: env("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  const u = await res.json();
  if (!u?.id) return null;
  const [p] = await db<{ role: string; first_name: string | null; last_name: string | null; full_name: string | null }[]>(
    `profiles?select=role,first_name,last_name,full_name&id=eq.${u.id}`,
  );
  if (!p || !APPROVED.includes(p.role)) return null;
  return { id: u.id, role: p.role, name: [p.first_name, p.last_name].filter(Boolean).join(" ") || p.full_name || "" };
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

type SendBody = {
  to?: string; cc?: string; subject?: string; text?: string;
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
  const mail = {
    from: me.name ? { name: me.name, address: a.email } : a.email,
    to, cc: cc.length ? cc : undefined,
    subject: String(b.subject ?? "").slice(0, 500),
    text: String(b.text ?? ""),
    inReplyTo: b.inReplyTo || undefined,
    references: b.references?.length ? b.references.slice(-20) : b.inReplyTo || undefined,
    attachments: atts,
  };
  const raw: Buffer = await new MailComposer(mail).compile().build();
  const tx = nodemailer.createTransport({
    host: env("MAIL_SMTP_HOST", env("MAIL_IMAP_HOST", "koala.serveriai.lt")),
    port: Number(env("MAIL_SMTP_PORT", "465")),
    secure: true,
    auth: { user: a.email, pass: a.password },
    tls: { rejectUnauthorized: !insecure() },
    connectionTimeout: 15000,
  });
  try {
    await tx.sendMail({ envelope: { from: a.email, to: [...to, ...cc] }, raw });
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
  return { ok: true };
}

// ---------- account storage ----------
async function account(uid: string): Promise<Account | null> {
  const [row] = await db<{ email: string; secret: string }[]>(`mail_accounts?select=email,secret&user_id=eq.${uid}`);
  if (!row) return null;
  return { email: row.email, password: await unseal(row.secret) };
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
  const folder = String(body.folder ?? "inbox"), uid = Number(body.uid);
  const needUid = () => { if (!Number.isInteger(uid) || uid <= 0) throw new UserError("Nežinomas laiškas."); };
  switch (action) {
    case "status":
      return await withImap(a, async (c) => ({ connected: true, email: a.email, unseen: (await c.status("INBOX", { unseen: true })).unseen ?? 0 }))
        .catch((e) => ({ connected: true, email: a.email, error: e instanceof UserError ? e.message : "Paštas nepasiekiamas." }));
    case "list":
      return { connected: true, email: a.email, ...(await list(a, folder, Math.max(0, Number(body.page) || 0))) };
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
