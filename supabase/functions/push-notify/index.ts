// Supabase Edge Function: push-notify
//
// Sends Web Push notifications (phone / computer, also when the app is
// closed) about chat activity.
//
// GET  (no auth)                         -> { publicKey } for subscribing
// POST {"kind":"message","message_id"}   Authorization: Bearer <user token>
//      The sender calls this right after sending; everyone else in the
//      conversation who has notifications on for that kind of chat and is
//      not in quiet hours gets one.
// POST {"kind":"reaction","message_id","emoji"}  -> the message's author
// POST {"kind":"call","call_id"}        Video call from its starter: every other
//      member of the conversation gets a ringing notification with
//      "Priimti" / "Atmesti" (muted chats ring too; quiet hours do not).
// POST {"kind":"test"}                   -> the caller's own devices
// POST {"kind":"meeting","meeting_id","mode":"new"|"update"|"cancel"}
//      Calendar invitation from its creator: invited members get a push
//      notification, invited e-mail addresses get an e-mail with an .ics
//      file. "new" reaches only people not invited before, "update" and
//      "cancel" reach everyone; "cancel" also deletes the meeting.
//
// Secrets: VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY (from `npx web-push
// generate-vapid-keys`), VAPID_SUBJECT (optional, mailto: address).
// E-mail invitations use RESEND_API_KEY and REMINDER_FROM (same as the
// vehicle reminders); APP_URL (optional, default https://app.eventsolutions.lt).
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.

import * as webpush from "jsr:@negrel/webpush@0.3.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const APPROVED = ["admin", "pm", "office", "tech", "freelance", "runner"];
const TZ = "Europe/Vilnius";

type Profile = {
  id: string;
  role: string;
  first_name: string | null;
  last_name: string | null;
  full_name: string | null;
  nickname: string | null;
  email: string;
  notify_prefs: Prefs | null;
};
type Prefs = {
  enabled?: boolean;
  general?: boolean;
  direct?: boolean;
  group?: boolean;
  reactions?: boolean;
  meetings?: boolean;
  mentions?: boolean;
  threads?: boolean;
  calls?: boolean;
  muted?: string[];
  quiet?: { on?: boolean; from?: string; to?: string };
};
type Sub = { endpoint: string; user_id: string; p256dh: string; auth: string };
type Payload = { title: string; body: string; tag: string; url: string; kind?: string; call_id?: string; meet?: string; provider?: string };

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}
function env(name: string): string {
  const v = Deno.env.get(name);
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
const inList = (ids: string[]) => `(${ids.map((i) => `"${i}"`).join(",")})`;

async function caller(req: Request): Promise<string | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const res = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, {
    headers: { apikey: env("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  const u = await res.json();
  return u?.id ?? null;
}

function name(p?: Profile): string {
  if (!p) return "Narys";
  return p.nickname || [p.first_name, p.last_name].filter(Boolean).join(" ") || p.full_name ||
    p.email.split("@")[0];
}

// quiet hours in Vilnius time, also across midnight (22:00–07:00)
export function inQuietHours(q: Prefs["quiet"], now = new Date()): boolean {
  if (!q?.on || !q.from || !q.to) return false;
  const hm = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit", minute: "2-digit", hour12: false })
    .format(now);
  const cur = hm === "24:00" ? "00:00" : hm;
  return q.from <= q.to ? cur >= q.from && cur < q.to : cur >= q.from || cur < q.to;
}
export function wants(p: Prefs | null, kind: "general" | "direct" | "group" | "reactions" | "meetings" | "threads", convId: string): boolean {
  const pr = p ?? {};
  if (pr.enabled === false) return false;
  if (pr[kind] === false) return false;
  if ((pr.muted ?? []).includes(convId)) return false;
  return !inQuietHours(pr.quiet);
}

// the keys from `npx web-push generate-vapid-keys` (raw, base64url) as JWK
function b64uToBytes(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
function bytesToB64u(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
let appServer: webpush.ApplicationServer | null = null;
async function server(): Promise<webpush.ApplicationServer> {
  if (appServer) return appServer;
  const pub = b64uToBytes(env("VAPID_PUBLIC_KEY"));
  const x = bytesToB64u(pub.slice(1, 33)), y = bytesToB64u(pub.slice(33, 65));
  const d = env("VAPID_PRIVATE_KEY").trim();
  const vapidKeys = await webpush.importVapidKeys({
    publicKey: { kty: "EC", crv: "P-256", x, y, ext: true },
    privateKey: { kty: "EC", crv: "P-256", x, y, d, ext: true },
  });
  appServer = await webpush.ApplicationServer.new({
    contactInformation: Deno.env.get("VAPID_SUBJECT") || "mailto:info@eventsolutions.lt",
    vapidKeys,
  });
  return appServer;
}

async function sendTo(userIds: string[], payload: Payload, ttl = 86400): Promise<{ sent: number; gone: number }> {
  if (!userIds.length) return { sent: 0, gone: 0 };
  const subs = await db<Sub[]>(`push_subscriptions?select=*&user_id=in.${inList(userIds)}`);
  const as = await server();
  let sent = 0, gone = 0;
  await Promise.all(subs.map(async (s) => {
    try {
      await as.subscribe({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } })
        .pushTextMessage(JSON.stringify(payload), { ttl, urgency: ttl < 600 ? webpush.Urgency.High : webpush.Urgency.Normal, topic: payload.tag.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 32) || undefined });
      sent++;
    } catch (e) {
      const status = (e as { response?: Response }).response?.status;
      if (status === 404 || status === 410) {
        gone++;
        await db(`push_subscriptions?endpoint=eq.${encodeURIComponent(s.endpoint)}`, { method: "DELETE" });
      } else console.error("push failed", status ?? e);
    }
  }));
  return { sent, gone };
}

async function chatUsers(): Promise<Profile[]> {
  const [profiles, perms] = await Promise.all([
    db<Profile[]>(`profiles?select=id,role,first_name,last_name,full_name,nickname,email,notify_prefs&role=in.(${APPROVED.join(",")})`),
    db<{ role: string; can_view: boolean; can_edit: boolean }[]>("role_permissions?select=role,can_view,can_edit&section=eq.chat"),
  ]);
  const hasRows = perms.length > 0;
  const ok = new Set(perms.filter((p) => p.can_view || p.can_edit).map((p) => p.role));
  return profiles.filter((p) => p.role === "admin" || !hasRows || ok.has(p.role));
}

function preview(m: { body: string; attachments: unknown[] }): string {
  const t = (m.body || "").trim();
  if (t) return t.length > 140 ? t.slice(0, 137) + "…" : t;
  const att = (m.attachments ?? []) as { type?: string; name?: string }[];
  const file = att.find((a) => a.type === "file");
  if (file) return "📎 " + (file.name || "Failas");
  return att.length ? "📷 Nuotrauka" : "";
}

type Msg = { id: string; conversation_id: string; sender_id: string; body: string; attachments: unknown[]; deleted_at: string | null; parent_id?: string | null; also_channel?: boolean };
const MENTION_RE = /<@([0-9a-f-]{36})>/g;
export function mentionIds(body: string): string[] {
  return [...new Set([...String(body || "").matchAll(MENTION_RE)].map((x) => x[1]))];
}
// <@id> -> @Vardas for the notification text
function withNames(body: string, byId: Map<string, Profile>): string {
  return String(body || "").replace(MENTION_RE, (_, id) => "@" + name(byId.get(id)));
}
async function onMessage(uid: string, messageId: string) {
  const [m] = await db<Msg[]>(`messages?select=*&id=eq.${encodeURIComponent(messageId)}`);
  if (!m || m.sender_id !== uid || m.deleted_at) return { sent: 0, skipped: "not your message" };
  const [c] = await db<{ id: string; kind: "general" | "direct" | "group" | "channel"; title: string | null; is_private?: boolean }[]>(
    `conversations?select=*&id=eq.${m.conversation_id}`,
  );
  if (!c) return { sent: 0 };
  const users = await chatUsers();
  const byId = new Map(users.map((u) => [u.id, u]));
  const members = c.kind === "general" ? users.map((u) => u.id)
    : (await db<{ user_id: string }[]>(`conversation_members?select=user_id&conversation_id=eq.${c.id}`)).map((x) => x.user_id);
  // only members of the conversation are told (#bendras: everyone; a channel,
  // also a public one, or a group: the people in it)
  const canSee = (id: string) => byId.has(id) && members.includes(id);
  const thread = !!m.parent_id && !m.also_channel;
  let recipients: string[];
  if (thread) {
    // a reply in a thread: the thread's author and everyone who replied
    const rows = await db<{ sender_id: string }[]>(
      `messages?select=sender_id&or=(id.eq.${m.parent_id},parent_id.eq.${m.parent_id})`,
    );
    recipients = [...new Set(rows.map((r) => r.sender_id))];
  } else recipients = c.kind === "general" ? users.map((u) => u.id) : members;
  const mentioned = mentionIds(m.body).filter((id) => id !== uid && canSee(id));
  const pref = thread ? "threads" : c.kind === "channel" ? "group" : c.kind;
  const to = recipients.filter((id) => id !== uid && canSee(id) && !mentioned.includes(id) && wants(byId.get(id)!.notify_prefs, pref as never, c.id));
  const sender = byId.get(uid);
  const text = preview({ ...m, body: withNames(m.body, byId) });
  const where = c.kind === "direct" ? "" : c.kind === "general" ? "Bendras chatas" : "#" + (c.title || "kanalas");
  const url = `./?chat=${c.id}${m.parent_id ? "&thread=" + m.parent_id : ""}`;
  const payload: Payload = c.kind === "direct" && !thread
    ? { title: name(sender), body: text, tag: c.id, url }
    : { title: thread ? `Gija · ${where || name(sender)}` : where, body: `${name(sender)}: ${text}`, tag: thread ? "t-" + m.parent_id : c.id, url };
  const a = await sendTo(to, payload);
  // @mentions reach the person even in a muted chat
  const mto = mentioned.filter((id) => wantsMention(byId.get(id)!.notify_prefs));
  const b = await sendTo(mto, { title: `${name(sender)} paminėjo tave${where ? " · " + where : ""}`, body: text, tag: "m-" + m.id, url });
  return { sent: a.sent + b.sent, gone: a.gone + b.gone, mentioned: mto.length };
}
export function wantsMention(p: Prefs | null): boolean {
  const pr = p ?? {};
  if (pr.enabled === false || pr.mentions === false) return false;
  return !inQuietHours(pr.quiet);
}

export function wantsCall(p: Prefs | null): boolean {
  const pr = p ?? {};
  if (pr.enabled === false || pr.calls === false) return false;
  return !inQuietHours(pr.quiet);
}
async function onCall(uid: string, callId: string) {
  const [call] = await db<{ id: string; conversation_id: string; created_by: string; meet_url: string; provider?: string; created_at: string; ended_at: string | null }[]>(
    `calls?select=*&id=eq.${encodeURIComponent(callId)}`,
  );
  if (!call || call.created_by !== uid || call.ended_at) return { sent: 0, skipped: "not your call" };
  if (Date.now() - new Date(call.created_at).getTime() > 5 * 60e3) return { sent: 0, skipped: "too old" };
  const [c] = await db<{ id: string; kind: string; title: string | null }[]>(`conversations?select=id,kind,title&id=eq.${call.conversation_id}`);
  if (!c) return { sent: 0 };
  const users = await chatUsers();
  const byId = new Map(users.map((u) => [u.id, u]));
  const members = c.kind === "general" ? users.map((u) => u.id)
    : (await db<{ user_id: string }[]>(`conversation_members?select=user_id&conversation_id=eq.${c.id}`)).map((x) => x.user_id);
  const to = members.filter((id) => id !== uid && byId.has(id) && wantsCall(byId.get(id)!.notify_prefs));
  const where = c.kind === "direct" ? "" : c.kind === "general" ? "#bendras" : (c.kind === "group" && !c.title) ? "grupėje" : "#" + (c.title || "kanalas");
  const r = await sendTo(to, {
    title: `📹 ${name(byId.get(uid))} skambina`,
    body: (where ? where + " · " : "") + (call.provider === "daily" ? "Vaizdo skambutis. Priimti ar atmesti?" : "Vaizdo skambutis (Google Meet). Priimti ar atmesti?"),
    tag: "call-" + call.id, url: `./?call=${call.id}`, kind: "call", call_id: call.id,
    // Google Meet opens straight away; a Daily call opens inside the app
    provider: call.provider === "daily" ? "daily" : "meet", meet: call.provider === "daily" ? undefined : call.meet_url,
  }, 90);
  return { ...r, members: to.length };
}

async function onReaction(uid: string, messageId: string, emoji: string) {
  const rows = await db<unknown[]>(
    `message_reactions?select=message_id&message_id=eq.${encodeURIComponent(messageId)}&user_id=eq.${uid}&emoji=eq.${encodeURIComponent(emoji)}`,
  );
  if (!rows.length) return { sent: 0, skipped: "no such reaction" };
  const [m] = await db<{ conversation_id: string; sender_id: string; body: string; attachments: unknown[] }[]>(
    `messages?select=conversation_id,sender_id,body,attachments&id=eq.${encodeURIComponent(messageId)}`,
  );
  if (!m || m.sender_id === uid) return { sent: 0 };
  const users = await chatUsers();
  const author = users.find((u) => u.id === m.sender_id);
  if (!author || !wants(author.notify_prefs, "reactions", m.conversation_id)) return { sent: 0, skipped: "off" };
  const who = users.find((u) => u.id === uid);
  return await sendTo([author.id], {
    title: `${name(who)} sureagavo ${emoji}`,
    body: preview({ ...m, body: withNames(m.body, new Map(users.map((u) => [u.id, u]))) }) || "į tavo žinutę",
    tag: `rx-${messageId}`,
    url: `./?chat=${m.conversation_id}`,
  });
}


// ---------- calendar invitations ----------
type Meeting = {
  id: string; title: string; meet_date: string; start_time: string | null; end_time: string | null;
  location: string; description: string; attendees: string[]; emails: string[];
  notified: { users?: string[]; emails?: string[]; seq?: number } | null; created_by: string;
};
const LT_MONTHS = ["sausio", "vasario", "kovo", "balandžio", "gegužės", "birželio", "liepos", "rugpjūčio", "rugsėjo", "spalio", "lapkričio", "gruodžio"];
const LT_DAYS = ["sekmadienis", "pirmadienis", "antradienis", "trečiadienis", "ketvirtadienis", "penktadienis", "šeštadienis"];
const hm = (t: string | null) => (t ? t.slice(0, 5) : "");
export function meetingWhen(m: Pick<Meeting, "meet_date" | "start_time" | "end_time">): string {
  const [y, mo, d] = m.meet_date.split("-").map(Number);
  const wd = LT_DAYS[new Date(Date.UTC(y, mo - 1, d)).getUTCDay()];
  const date = `${y} m. ${LT_MONTHS[mo - 1]} ${d} d., ${wd}`;
  const time = m.start_time ? `${hm(m.start_time)}${m.end_time ? "–" + hm(m.end_time) : ""}` : "visą dieną";
  return `${date} · ${time}`;
}
// Vilnius wall clock -> UTC
export function vilniusToUtc(date: string, time: string): Date {
  const [y, mo, d] = date.split("-").map(Number), [h, mi] = time.split(":").map(Number);
  const guess = Date.UTC(y, mo - 1, d, h, mi);
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false })
    .formatToParts(new Date(guess)).reduce((o, p) => ({ ...o, [p.type]: p.value }), {} as Record<string, string>);
  const asVilnius = Date.UTC(+parts.year, +parts.month - 1, +parts.day, +parts.hour % 24, +parts.minute);
  return new Date(guess - (asVilnius - guess));
}
const icsDate = (d: Date) => d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
const icsText = (t: string) => t.replace(/\\/g, "\\\\").replace(/;/g, "\;").replace(/,/g, "\\,").replace(/\r?\n/g, "\\n");
function icsFold(line: string): string {
  const out: string[] = [];
  let cur = "";
  for (const ch of line) {
    if (new TextEncoder().encode(cur + ch).length > 73) { out.push(cur); cur = " " + ch; } else cur += ch;
  }
  out.push(cur);
  return out.join("\r\n");
}
export function meetingIcs(m: Meeting, organizer: { name: string; email: string }, cancel: boolean, seq: number): string {
  let start: string, end: string;
  if (m.start_time) {
    const s = vilniusToUtc(m.meet_date, hm(m.start_time));
    const e = m.end_time && m.end_time > m.start_time ? vilniusToUtc(m.meet_date, hm(m.end_time)) : new Date(s.getTime() + 3600e3);
    start = "DTSTART:" + icsDate(s); end = "DTEND:" + icsDate(e);
  } else {
    const [y, mo, d] = m.meet_date.split("-").map(Number);
    const next = new Date(Date.UTC(y, mo - 1, d + 1)).toISOString().slice(0, 10).replace(/-/g, "");
    start = "DTSTART;VALUE=DATE:" + m.meet_date.replace(/-/g, ""); end = "DTEND;VALUE=DATE:" + next;
  }
  return [
    "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Event Solutions//EventSolutions App//LT", "CALSCALE:GREGORIAN",
    "METHOD:" + (cancel ? "CANCEL" : "PUBLISH"),
    "BEGIN:VEVENT", `UID:${m.id}@eventsolutions.lt`, "SEQUENCE:" + seq, "DTSTAMP:" + icsDate(new Date()), start, end,
    "SUMMARY:" + icsText(m.title), m.location ? "LOCATION:" + icsText(m.location) : "",
    m.description ? "DESCRIPTION:" + icsText(m.description) : "",
    organizer.email ? `ORGANIZER;CN=${icsText(organizer.name || organizer.email)}:mailto:${organizer.email}` : "",
    "STATUS:" + (cancel ? "CANCELLED" : "CONFIRMED"), "END:VEVENT", "END:VCALENDAR", "",
  ].filter((l, i, a) => l !== "" || i === a.length - 1).map(icsFold).join("\r\n");
}
const escHtml = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
export function meetingEmailHtml(m: Meeting, organizer: string, people: string[], mode: string): string {
  const head = mode === "cancel" ? "Susitikimas atšauktas" : mode === "update" ? "Susitikimas pakeistas" : "Kvietimas";
  const row = (k: string, v: string) => v ? `<tr><td style="padding:4px 14px 4px 0;color:#666;vertical-align:top;white-space:nowrap;">${k}</td><td style="padding:4px 0;">${v}</td></tr>` : "";
  return `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#111;max-width:560px;">
<div style="font-size:12px;letter-spacing:.5px;text-transform:uppercase;color:${mode === "cancel" ? "#c62828" : "#e04e6c"};font-weight:bold;">${head}</div>
<h2 style="margin:6px 0 14px;font-size:22px;${mode === "cancel" ? "text-decoration:line-through;" : ""}">${escHtml(m.title)}</h2>
<table cellpadding="0" cellspacing="0" style="font-size:14px;border-collapse:collapse;">
${row("Kada", escHtml(meetingWhen(m)))}
${row("Kur", escHtml(m.location || ""))}
${row("Organizatorius", escHtml(organizer))}
${row("Dalyviai", escHtml(people.join(", ")))}
</table>
${m.description ? `<div style="margin-top:14px;padding:12px 14px;background:#f5f5f7;border-radius:8px;white-space:pre-wrap;">${escHtml(m.description)}</div>` : ""}
<p style="margin-top:18px;font-size:12px;color:#888;">${mode === "cancel" ? "" : "Pridėk į savo kalendorių — atidaryk prisegtą failą „kvietimas.ics“. "}Išsiųsta per EventSolutions App.</p>
</div>`;
}
function b64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
async function resendMail(to: string, subject: string, html: string, replyTo: string, ics: string) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env("RESEND_API_KEY")}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: Deno.env.get("REMINDER_FROM") || Deno.env.get("ACCESS_FROM") || "Event Solutions <onboarding@resend.dev>",
      to: [to], subject, html, reply_to: replyTo || undefined,
      attachments: [{ filename: "kvietimas.ics", content: b64(new TextEncoder().encode(ics)), content_type: "text/calendar; charset=utf-8" }],
    }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${(await res.text()).slice(0, 200)}`);
}

async function onMeeting(uid: string, id: string, mode: string) {
  const [m] = await db<Meeting[]>(`meetings?select=*&id=eq.${encodeURIComponent(id)}`);
  if (!m || m.created_by !== uid) return { sent: 0, skipped: "not your meeting" };
  const profiles = await db<Profile[]>(`profiles?select=id,role,first_name,last_name,full_name,nickname,email,notify_prefs&role=in.(${APPROVED.join(",")})`);
  const byId = new Map(profiles.map((p) => [p.id, p]));
  const me = byId.get(uid);
  const organizer = name(me);
  const notified = m.notified ?? {};
  const all = mode !== "new";
  const users = (m.attendees ?? []).filter((u) => u !== uid && byId.has(u) && (all || !(notified.users ?? []).includes(u)));
  const emails = (m.emails ?? []).map((e) => e.trim().toLowerCase()).filter((e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e))
    .filter((e) => all || !(notified.emails ?? []).includes(e));
  const when = meetingWhen(m);
  // app notification for members
  const verb = mode === "cancel" ? "atšaukė" : mode === "update" ? "pakeitė" : "pakvietė";
  const push = await sendTo(
    users.filter((u) => wants(byId.get(u)!.notify_prefs, "meetings", "meeting")),
    {
      title: (mode === "cancel" ? "❌ " : "📅 ") + m.title,
      body: `${when}${m.location ? " · " + m.location : ""}\n${organizer} ${verb}`,
      tag: "meet-" + m.id,
      url: mode === "cancel" ? "./" : `./?meeting=${m.id}`,
    },
  );
  // e-mail for the others
  const seq = (notified.seq ?? 0) + (all ? 1 : 0);
  const people = [organizer, ...(m.attendees ?? []).filter((u) => u !== uid).map((u) => name(byId.get(u))), ...(m.emails ?? [])];
  let mailed = 0;
  const failed: string[] = [];
  if (emails.length) {
    const html = meetingEmailHtml(m, organizer, people, mode);
    const ics = meetingIcs(m, { name: organizer, email: me?.email ?? "" }, mode === "cancel", seq);
    const subject = (mode === "cancel" ? "Atšaukta: " : mode === "update" ? "Pakeista: " : "Kvietimas: ") + m.title + " · " + when;
    for (const e of emails) {
      try {
        await resendMail(e, subject, html, me?.email ?? "", ics);
        mailed++;
      } catch (err) {
        console.error("invite mail", e, (err as Error).message);
        failed.push(e);
      }
    }
  }
  if (mode === "cancel") {
    await db(`meetings?id=eq.${m.id}`, { method: "DELETE" });
  } else {
    const okEmails = emails.filter((e) => !failed.includes(e));
    await db(`meetings?id=eq.${m.id}`, {
      method: "PATCH",
      body: JSON.stringify({ notified: {
        users: [...new Set([...(notified.users ?? []), ...users])],
        emails: [...new Set([...(notified.emails ?? []), ...okEmails])],
        seq,
      } }),
    });
  }
  return { members: users.length, pushed: push.sent, mailed, failed };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    if (req.method === "GET") return json({ publicKey: env("VAPID_PUBLIC_KEY") });
    if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
    const uid = await caller(req);
    if (!uid) return json({ error: "Reikia prisijungti." }, 401);
    const body = await req.json().catch(() => ({}));
    if (body.kind === "message") return json(await onMessage(uid, String(body.message_id ?? "")));
    if (body.kind === "call") return json(await onCall(uid, String(body.call_id ?? "")));
    if (body.kind === "reaction") return json(await onReaction(uid, String(body.message_id ?? ""), String(body.emoji ?? "").slice(0, 16)));
    if (body.kind === "meeting") {
      const mode = ["new", "update", "cancel"].includes(body.mode) ? body.mode : "new";
      return json(await onMeeting(uid, String(body.meeting_id ?? ""), mode));
    }
    if (body.kind === "test") {
      return json(await sendTo([uid], { title: "EventSolutions App", body: "Pranešimai veikia 🎉", tag: "test", url: "./" }));
    }
    return json({ error: "Unknown kind" }, 400);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    return json({ error: "Nepavyko išsiųsti pranešimų." }, 500);
  }
});
