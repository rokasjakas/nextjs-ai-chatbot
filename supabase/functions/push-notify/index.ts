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
// POST {"kind":"dial","phone","name"}    -> the caller's own devices: "call this
//      person" — tapping it on the phone starts the call (Žmonės → Bookingas)
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

import { p256 } from "npm:@noble/curves@1.4.0/p256";
import { sha256 } from "npm:@noble/hashes@1.4.0/sha256";
import { hkdf } from "npm:@noble/hashes@1.4.0/hkdf";
import { gcm } from "npm:@noble/ciphers@0.5.3/aes";


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
type Sub = { endpoint: string; user_id: string; p256dh: string; auth: string; user_agent?: string | null };
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
// The public key is worked out from the private key, so the pair always
// matches: a VAPID_PUBLIC_KEY that belongs to another key pair made every
// push fail with 403 (Google rejects the signature). Devices subscribed with
// the wrong key renew themselves in the app.
let vapidPublic = "";
const PUSH_FN_VERSION = 10;
let vapidD: Uint8Array | null = null;
// The public key is worked out from the private key, so the pair always
// matches. Signing and encryption use @noble (plain JavaScript): the Supabase
// runtime's own ECDSA produced signatures Google and Mozilla rejected
// ("invalid JWT" / "InvalidSignature") and that did not even verify there.
// the private key as `web-push generate-vapid-keys` prints it (base64url, 32
// bytes); also accepted: quoted, standard base64, a JWK, or a PEM / PKCS#8 file
export function parsePrivateKey(raw: string): Uint8Array {
  let t = String(raw ?? "").trim().replace(/^["']+|["']+$/g, "").trim();
  if (t.startsWith("{")) { try { t = String(JSON.parse(t).d ?? ""); } catch { /* not JSON */ } }
  let bytes: Uint8Array;
  try {
    bytes = b64uToBytes(t.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
  } catch {
    throw new Error("VAPID_PRIVATE_KEY netinkamas: ne base64 tekstas (" + t.length + " simb.)");
  }
  if (bytes.length === 33 && bytes[0] === 0) bytes = bytes.slice(1);
  if (bytes.length > 33) {                               // PKCS#8 / SEC1 DER: 04 20 <32 bytes>
    for (let i = 0; i + 34 <= bytes.length; i++) if (bytes[i] === 0x04 && bytes[i + 1] === 0x20) { bytes = bytes.slice(i + 2, i + 34); break; }
  }
  // a key whose first byte(s) were 0 is sometimes written without them
  // (31 bytes): it is the same key, put the zeros back
  if (bytes.length >= 28 && bytes.length < 32) { const full = new Uint8Array(32); full.set(bytes, 32 - bytes.length); bytes = full; }
  if (bytes.length !== 32) throw new Error("VAPID_PRIVATE_KEY netinkamas: " + bytes.length + " baitų (turi būti 32) — tikriausiai įrašytas ne tas raktas");
  return bytes;
}
function vapidKeyPair() {
  if (vapidD) return;
  const d = parsePrivateKey(env("VAPID_PRIVATE_KEY"));
  p256.getPublicKey(d, false);                         // throws if it is not a P-256 key
  vapidD = d;
  vapidPublic = bytesToB64u(p256.getPublicKey(d, false));
  if (vapidPublic !== env("VAPID_PUBLIC_KEY").trim()) console.warn("VAPID_PUBLIC_KEY does not belong to VAPID_PRIVATE_KEY — using the public key worked out from the private key");
}
async function publicKey(): Promise<string> {
  vapidKeyPair();
  return vapidPublic;
}
const vapidTokens = new Map<string, { t: string; exp: number }>();
function vapidHeader(endpoint: string): string {
  vapidKeyPair();
  const aud = new URL(endpoint).origin, now = Math.floor(Date.now() / 1000);
  const hit = vapidTokens.get(aud);
  if (hit && hit.exp - now > 3600) return `vapid t=${hit.t}, k=${vapidPublic}`;
  const enc = new TextEncoder();
  const b64json = (o: unknown) => bytesToB64u(enc.encode(JSON.stringify(o)));
  const exp = now + 12 * 3600;
  const data = b64json({ typ: "JWT", alg: "ES256" }) + "." + b64json({ aud, exp, sub: Deno.env.get("VAPID_SUBJECT") || "mailto:info@eventsolutions.lt" });
  const hash = sha256(enc.encode(data));
  const sig = p256.sign(hash, vapidD!).toCompactRawBytes();
  if (!p256.verify(sig, hash, b64uToBytes(vapidPublic))) throw new Error("VAPID signature does not verify");
  const t = data + "." + bytesToB64u(sig);
  vapidTokens.set(aud, { t, exp });
  return `vapid t=${t}, k=${vapidPublic}`;
}
// aes128gcm body for one device (RFC 8291)
export function encryptPush(p256dh: string, authSecret: string, text: string): Uint8Array {
  const enc = new TextEncoder();
  const uaPub = b64uToBytes(p256dh), auth = b64uToBytes(authSecret);
  const eph = p256.utils.randomPrivateKey();
  const asPub = p256.getPublicKey(eph, false);
  const shared = p256.getSharedSecret(eph, uaPub).slice(1, 33);
  const ikm = hkdf(sha256, shared, auth, new Uint8Array([...enc.encode("WebPush: info\0"), ...uaPub, ...asPub]), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = hkdf(sha256, ikm, salt, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = hkdf(sha256, ikm, salt, enc.encode("Content-Encoding: nonce\0"), 12);
  const ct = gcm(cek, nonce).encrypt(new Uint8Array([...enc.encode(text), 2]));
  const head = new Uint8Array(21 + asPub.length);
  head.set(salt, 0); new DataView(head.buffer).setUint32(16, 4096); head[20] = asPub.length; head.set(asPub, 21);
  return new Uint8Array([...head, ...ct]);
}
class PushError extends Error { constructor(public status: number, public body: string) { super("push " + status); } }
async function pushOne(s: Sub, payload: Payload, ttl: number) {
  const body = encryptPush(s.p256dh, s.auth, JSON.stringify(payload));
  const topic = payload.tag.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 32);
  const res = await fetch(s.endpoint, {
    method: "POST",
    headers: {
      Authorization: vapidHeader(s.endpoint), TTL: String(ttl), "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream", Urgency: ttl < 600 ? "high" : "normal", ...(topic ? { Topic: topic } : {}),
    },
    body: body as unknown as BodyInit,
  });
  if (!res.ok) throw new PushError(res.status, (await res.text().catch(() => "")).replace(/\s+/g, " ").trim().slice(0, 200));
  await res.body?.cancel().catch(() => {});
}

async function sendTo(userIds: string[], payload: Payload, ttl = 86400, except = ""): Promise<{ sent: number; gone: number; devices?: number; failed?: string[] }> {
  if (!userIds.length) return { sent: 0, gone: 0 };
  let subs = await db<Sub[]>(`push_subscriptions?select=*&user_id=in.${inList(userIds)}`);
  const devices = subs.length;
  if (except) subs = subs.filter((s) => s.endpoint !== except);
  let sent = 0, gone = 0;
  const failed: string[] = [];
  await Promise.all(subs.map(async (s) => {
    try {
      await pushOne(s, payload, ttl);
      sent++;
    } catch (e) {
      const status = e instanceof PushError ? e.status : 0;
      const note = (e instanceof PushError ? `${e.status} ${e.body}`.trim() : (e as Error)?.message || String(e)).slice(0, 220);
      if (status === 404 || status === 410) {                 // the device is gone
        gone++;
        await db(`push_subscriptions?endpoint=eq.${encodeURIComponent(s.endpoint)}`, { method: "DELETE" });
      } else {
        console.error("push failed", note);
        failed.push(note);
      }
    }
  }));
  return { sent, gone, devices, ...(failed.length ? { failed } : {}) };
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


// ---------- tasks (public.tasks): new / done notices and reminders ----------
export type Remind = { before?: number[]; at?: string[]; push?: boolean; email?: boolean; overdue?: boolean };
export type Task = {
  id: string; title: string; note: string; due_at: string | null; created_by: string; assignees: string[];
  lead: string | null; remind: Remind | null; done: Record<string, string> | null; sent: Record<string, string> | null;
};
export type Moment = { key: string; at: number; kind: "before" | "at" | "overdue"; n: number };

// who has to do it: the chosen members, or the author for an own task
export function taskPeople(t: Task): string[] { return t.assignees?.length ? t.assignees : [t.created_by]; }
export function taskOpen(t: Task): string[] { const d = t.done ?? {}; return taskPeople(t).filter((u) => !d[u]); }
export function taskMoments(t: Task): Moment[] {
  const r = t.remind ?? {}, out: Moment[] = [];
  const due = t.due_at ? Date.parse(t.due_at) : NaN;
  if (!isNaN(due)) {
    for (const m of r.before ?? []) if (Number.isFinite(m) && m >= 0) out.push({ key: "b" + m, at: due - m * 60000, kind: "before", n: m });
    if (r.overdue) for (let d = 1; d <= 14; d++) out.push({ key: "o" + d, at: due + d * 86400000, kind: "overdue", n: d });
  }
  for (const iso of r.at ?? []) { const a = Date.parse(iso); if (!isNaN(a)) out.push({ key: "a" + iso, at: a, kind: "at", n: 0 }); }
  return out;
}
// reminders whose time came within the last hour and were not sent yet
export function dueMoments(t: Task, now: number, windowMs = 3600000): Moment[] {
  const sent = t.sent ?? {};
  return taskMoments(t).filter((m) => m.at <= now && m.at > now - windowMs && !sent[m.key]);
}
function whenLt(iso: string | null): string {
  if (!iso) return "";
  return new Intl.DateTimeFormat("lt-LT", { timeZone: TZ, month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(iso));
}
function before(min: number): string {
  if (min >= 1440 && min % 1440 === 0) return `${min / 1440} d.`;
  if (min >= 60 && min % 60 === 0) return `${min / 60} val.`;
  return `${min} min.`;
}
export function reminderText(t: Task, m: Moment): { title: string; body: string } {
  const due = t.due_at ? whenLt(t.due_at) : "";
  const body = m.kind === "overdue" ? `Vėluoja ${m.n} d. · terminas buvo ${due}`
    : m.kind === "before" ? (m.n === 0 ? `Terminas dabar (${due})` : `Terminas po ${before(m.n)} · ${due}`)
    : due ? `Priminimas · terminas ${due}` : "Priminimas";
  return { title: "⏰ " + t.title.slice(0, 120), body };
}
function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}
async function mailTo(to: string[], subject: string, html: string): Promise<string> {
  const key = Deno.env.get("RESEND_API_KEY");
  if (!key || !to.length) return key ? "" : "RESEND_API_KEY nenustatytas";
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: Deno.env.get("REMINDER_FROM") || "Event Solutions <onboarding@resend.dev>", to, subject, html }),
  });
  return res.ok ? "" : `Resend ${res.status}: ${(await res.text()).slice(0, 200)}`;
}
async function taskReminders() {
  const now = Date.now();
  const since = new Date(now - 15 * 86400000).toISOString();
  const tasks = await db<Task[]>(`tasks?select=*&or=(due_at.is.null,due_at.gte.${since})`);
  const out: unknown[] = [];
  for (const t of tasks) {
    const moments = dueMoments(t, now);
    if (!moments.length) continue;
    const open = taskOpen(t);
    const sent = { ...(t.sent ?? {}) };
    for (const m of moments) sent[m.key] = new Date(now).toISOString();
    if (open.length) {
      const m = moments[moments.length - 1];                  // one notice even if several came due together
      const who = new Set(open);
      if (t.lead && (m.kind === "overdue" || (m.kind === "before" && m.n === 0))) who.add(t.lead);   // the one responsible hears it too
      const ids = [...who];
      const { title, body } = reminderText(t, m);
      const r = t.remind ?? {};
      let pushed = 0, mailErr = "";
      if (r.push !== false) pushed = (await sendTo(ids, { title, body, tag: "task-" + t.id, url: `./?task=${t.id}`, kind: "task" }, 3600)).sent;
      if (r.email) {
        const ps = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&id=in.${inList(ids)}`);
        const html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;line-height:1.5;">
          <p><b>${esc(t.title)}</b></p><p>${esc(body)}</p>${t.note ? `<p style="white-space:pre-wrap;color:#555;">${esc(t.note)}</p>` : ""}
          <p style="color:#777;font-size:12px;margin-top:18px;">EventSolutions App · užduoties priminimas. Kai atliksi – pažymėk užduotį programėlėje.</p></div>`;
        mailErr = await mailTo(ps.map((p) => p.email).filter(Boolean), "Priminimas: " + t.title.slice(0, 120), html);
      }
      out.push({ task: t.id, key: m.key, to: ids.length, pushed, ...(mailErr ? { mailErr } : {}) });
    }
    await db(`tasks?id=eq.${t.id}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ sent }) });
  }
  return { fn: PUSH_FN_VERSION, checked: tasks.length, sent: out };
}
async function onTask(uid: string, taskId: string, ev: string) {
  const [t] = await db<Task[]>(`tasks?select=*&id=eq.${encodeURIComponent(taskId)}`);
  if (!t) return { error: "Užduotis nerasta" };
  const involved = t.created_by === uid || (t.assignees ?? []).includes(uid) || t.lead === uid;
  if (!involved) return { error: "Ši užduotis ne tau" };
  const users = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&id=eq.${uid}`);
  const me = name(users[0]);
  let ids: string[], title: string, body: string;
  if (ev === "new") {
    if (t.created_by !== uid) return { error: "Tik užduoties autorius" };
    ids = [...new Set([...(t.assignees ?? []), ...(t.lead ? [t.lead] : [])])].filter((u) => u !== uid);
    title = "📋 Nauja užduotis: " + t.title.slice(0, 100);
    body = `${me} paskyrė${t.due_at ? " · iki " + whenLt(t.due_at) : ""}${t.lead === ids[0] && ids.length === 1 ? " (tu atsakingas)" : ""}`;
  } else {
    ids = [...new Set([t.created_by, ...(t.lead ? [t.lead] : [])])].filter((u) => u !== uid);
    const left = taskOpen(t).length;
    title = (ev === "done" ? "✓ " : "↺ ") + t.title.slice(0, 100);
    body = ev === "done" ? `${me} atliko${left ? ` · liko ${left}` : " · visi atliko"}` : `${me} atšaukė „atlikta“`;
  }
  if (!ids.length) return { sent: 0 };
  return await sendTo(ids, { title, body, tag: "task-" + t.id, url: `./?task=${t.id}`, kind: "task" });
}

// Sąskaitos: a new one goes to Admin+, the decision to its uploader, a reply
// from the e-mail to Admin+; „Priminti vėliau“ comes back at the chosen time
type Invoice = { id: string; created_by: string; kind: string; supplier: string | null; number: string | null; amount: number | null; status: string; decision_note: string | null; remind_at: string | null; reminded_at: string | null; responses: { who?: string; kind: string; text?: string }[] };
const INV_KIND: Record<string, string> = { freelance: "Freelance", service: "Paslaugų", rent: "Nuomos" };
const INV_STATUS: Record<string, string> = { approved: "✅ Sąskaita patvirtinta", rejected: "✖ Sąskaita netvirtinta", later: "⏰ Sąskaita atidėta vėlesniam laikui", sent: "📤 Sąskaita patvirtinta ir išsiųsta", paid: "💶 Sąskaita apmokėta", queued: "🗂 Sąskaita suvesta apmokėjimui" };
async function plusIds(): Promise<string[]> {
  return (await db<{ id: string }[]>(`profiles?select=id&role=eq.admin&level=in.(plus,super)`)).map((p) => p.id);
}
const invTitle = (v: Invoice) => [INV_KIND[v.kind] || "", v.supplier || "", v.number ? "nr. " + v.number : "", v.amount != null ? Number(v.amount).toFixed(2).replace(".", ",") + " €" : ""].filter(Boolean).join(" · ");
async function onInvoice(uid: string, id: string, ev: string) {
  const [v] = await db<Invoice[]>(`invoices?select=*&id=eq.${encodeURIComponent(id)}`);
  if (!v) return { error: "Sąskaita nerasta" };
  const plus = await plusIds();
  if (ev === "new") {
    if (v.created_by !== uid) return { error: "Tik įkėlęs asmuo" };
    const [me] = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&id=eq.${uid}`);
    return await sendTo(plus.filter((u) => u !== uid), { title: "🧾 Nauja sąskaita: " + invTitle(v), body: "Įkėlė " + name(me), tag: "inv-" + v.id, url: `./?invoice=${v.id}`, kind: "invoice" });
  }
  if (!plus.includes(uid)) return { error: "Tik Admin+" };
  if (v.created_by === uid || !INV_STATUS[v.status]) return { sent: 0 };
  return await sendTo([v.created_by], { title: INV_STATUS[v.status], body: invTitle(v) + (v.decision_note ? " · " + v.decision_note.slice(0, 120) : ""), tag: "inv-" + v.id, url: `./?invoice=${v.id}`, kind: "invoice" });
}
// a reply given in the e-mail (called by invoice-respond with the cron secret)
async function onInvoiceReply(id: string) {
  const [v] = await db<Invoice[]>(`invoices?select=*&id=eq.${encodeURIComponent(id)}`);
  if (!v) return { error: "Sąskaita nerasta" };
  const r = (v.responses || [])[v.responses.length - 1]; if (!r) return { sent: 0 };
  const what = r.kind === "paid" ? "💶 Apmokėta" : r.kind === "queued" ? "🗂 Suvesta apmokėjimui" : "💬 Atsakymas";
  return await sendTo(await plusIds(), { title: what + ": " + invTitle(v), body: (r.who ? r.who + ": " : "") + (r.text || ""), tag: "inv-" + v.id, url: `./?invoice=${v.id}`, kind: "invoice" });
}
async function invoiceReminders() {
  const now = new Date().toISOString();
  const due = await db<Invoice[]>(`invoices?select=*&status=eq.later&remind_at=lte.${encodeURIComponent(now)}&reminded_at=is.null`);
  if (!due.length) return { invoices: 0 };
  const plus = await plusIds();
  for (const v of due) {
    await sendTo(plus, { title: "⏰ Priminimas: sąskaita", body: invTitle(v) + (v.decision_note ? " · " + v.decision_note.slice(0, 120) : ""), tag: "inv-" + v.id, url: `./?invoice=${v.id}`, kind: "invoice" });
    await db(`invoices?id=eq.${v.id}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ reminded_at: now }) });
  }
  return { invoices: due.length };
}

// Klaidos / pasiūlymai: a new one goes to the admins, an answer to its author
type Feedback = { id: string; created_by: string; kind: string; text: string; status: string; admin_note: string | null };
const FB_STATUS: Record<string, string> = {
  fixed: "✅ Klaida ištaisyta", accepted: "✅ Pasiūlymas priimtas ir pridėtas", rejected: "✖ Pasiūlymas atmestas", progress: "🔧 Jau taisoma",
};
async function onFeedback(uid: string, id: string, ev: string) {
  const [f] = await db<Feedback[]>(`feedback?select=id,created_by,kind,text,status,admin_note&id=eq.${encodeURIComponent(id)}`);
  if (!f) return { error: "Įrašas nerastas" };
  const users = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&role=eq.admin`);
  const short = f.text.replace(/\s+/g, " ").slice(0, 120);
  if (ev === "new") {
    if (f.created_by !== uid) return { error: "Tik autorius" };
    const [me] = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&id=eq.${uid}`);
    const ids = users.map((u) => u.id).filter((u) => u !== uid);
    return await sendTo(ids, { title: (f.kind === "bug" ? "🐞 Nauja klaida: " : "💡 Naujas pasiūlymas: ") + short, body: name(me), tag: "fb-" + f.id, url: `./?feedback=${f.id}`, kind: "feedback" });
  }
  if (!users.some((u) => u.id === uid)) return { error: "Tik administratorius" };
  if (!FB_STATUS[f.status] || f.created_by === uid) return { sent: 0 };
  return await sendTo([f.created_by], {
    title: FB_STATUS[f.status], body: (f.admin_note ? f.admin_note.slice(0, 140) + " · " : "") + "„" + short + "“",
    tag: "fb-" + f.id, url: `./?feedback=${f.id}`, kind: "feedback",
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    if (req.method === "GET") return json({ publicKey: await publicKey() });
    if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
    const body = await req.json().catch(() => ({}));
    // every 5 minutes from pg_cron: task reminders
    if (body?.mode === "cron") {
      const secret = Deno.env.get("CRON_SECRET");
      if (!secret || req.headers.get("x-cron-secret") !== secret) return json({ error: "Unauthorized" }, 401);
      const tr = await taskReminders();
      let ir: unknown = null;
      try { ir = await invoiceReminders(); } catch (e) { ir = { error: String(e) }; }   // before invoices.sql the table is missing
      return json({ ...tr, inv: ir });
    }
    if (body?.mode === "invoice-reply") {
      const secret = Deno.env.get("CRON_SECRET");
      if (!secret || req.headers.get("x-cron-secret") !== secret) return json({ error: "Unauthorized" }, 401);
      return json(await onInvoiceReply(String(body.invoice_id ?? "")));
    }
    const uid = await caller(req);
    if (!uid) return json({ error: "Reikia prisijungti." }, 401);
    if (body.kind === "task") return json(await onTask(uid, String(body.task_id ?? ""), ["new", "done", "undone"].includes(body.event) ? body.event : "new"));
    if (body.kind === "invoice") return json(await onInvoice(uid, String(body.invoice_id ?? ""), body.event === "new" ? "new" : "decided"));
    if (body.kind === "feedback") return json(await onFeedback(uid, String(body.feedback_id ?? ""), body.event === "new" ? "new" : "resolved"));
    if (body.kind === "message") return json(await onMessage(uid, String(body.message_id ?? "")));
    if (body.kind === "call") return json(await onCall(uid, String(body.call_id ?? "")));
    if (body.kind === "reaction") return json(await onReaction(uid, String(body.message_id ?? ""), String(body.emoji ?? "").slice(0, 16)));
    if (body.kind === "meeting") {
      const mode = ["new", "update", "cancel"].includes(body.mode) ? body.mode : "new";
      return json(await onMeeting(uid, String(body.meeting_id ?? ""), mode));
    }
    if (body.kind === "dial") {
      const phone = String(body.phone ?? "").trim();
      if (!/^\+?[\d\s()-]{5,24}$/.test(phone)) return json({ error: "Neteisingas numeris." }, 400);
      const who = String(body.name ?? "").replace(/[\r\n]+/g, " ").trim().slice(0, 80);
      return json(await sendTo([uid], {
        title: "📞 Skambinti: " + (who || phone), body: phone + " — paspausk ir telefonas skambins", tag: "dial",
        url: `./?dial=${encodeURIComponent(phone)}&who=${encodeURIComponent(who)}`, kind: "dial",
      // every other device of the caller (the one that asked is left out) —
      // not guessed from the browser name, which phones sometimes hide
      }, 120, String(body.except ?? "")));
    }
    if (body.kind === "test") {
      const r = await sendTo([uid], { title: "EventSolutions App", body: "Pranešimai veikia 🎉", tag: "test", url: "./" });
      // what the server sees (for the "Išbandyti" diagnosis in the app)
      const all = await db<{ user_id: string }[]>("push_subscriptions?select=user_id").catch(() => null);
      let keyErr = "";
      try { await publicKey(); } catch (e) { keyErr = (e as Error).message; }
      return json({ ...r, uid, total: all ? all.length : -1, fn: PUSH_FN_VERSION, keyMatch: !keyErr && vapidPublic === env("VAPID_PUBLIC_KEY").trim(), keyErr, subject: Deno.env.get("VAPID_SUBJECT") || "(numatytas)" });
    }
    return json({ error: "Unknown kind" }, 400);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    // the reason goes back to the app (the "Išbandyti" diagnosis shows it)
    return json({ error: "Nepavyko išsiųsti pranešimų: " + (err instanceof Error ? err.message : String(err)).slice(0, 200), fn: PUSH_FN_VERSION }, 500);
  }
});
