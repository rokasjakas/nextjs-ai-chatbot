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
// pg_cron "cron" mode (every 5 min) also reminds every hour of an open Team Tracker shift (tracker.sql)
// POST {"kind":"mail-test"} -> Admin: a test e-mail to the caller, with Resend's answer
// POST {"kind":"tracker-pin","member_id"} -> Team Tracker „Pamiršau PIN“: a 1-hour link to the member's account e-mail
// POST {"kind":"event","event_id","users":[…]}  people just written into an
//      event's crew: each one who really is in it now is told (Renginiai)
// POST {"mode":"new-user","user_id"}  header x-cron-secret (from user-access):
//      someone registered – every admin gets a notification
// POST {"kind":"leave","leave_id","event":"new"|"decided"|"cancelled"}  Prašymai:
//      new / cancelled -> office + Admin+, decided -> the one who asked
// Topics can be switched off in Profilis → Pranešimai (tasks, events, gear …).
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
// iPhone app (TestFlight, ios_devices.sql): APNS_KEY_ID, APNS_TEAM_ID, APNS_KEY_P8
// (Apple Developer → Keys → Apple Push Notifications service, the .p8 text),
// APNS_BUNDLE_ID (optional, default lt.eventsolutions.app).
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.

import { p256 } from "npm:@noble/curves@1.4.0/p256";
import { sha256 } from "npm:@noble/hashes@1.4.0/sha256";
import { hkdf } from "npm:@noble/hashes@1.4.0/hkdf";
import { gcm } from "npm:@noble/ciphers@0.5.3/aes";
import { hmac } from "npm:@noble/hashes@1.4.0/hmac";


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
  tasks?: boolean;
  events?: boolean;
  gear?: boolean;
  leave?: boolean;
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
    signal: AbortSignal.timeout(12000),
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
export function wants(p: Prefs | null, kind: "general" | "direct" | "group" | "reactions" | "meetings" | "threads" | "tasks" | "events" | "gear" | "leave" | "other", convId: string): boolean {
  const pr = p ?? {};
  if (pr.enabled === false) return false;
  if (kind !== "other" && pr[kind] === false) return false;
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
const PUSH_FN_VERSION = 18;
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
      "Content-Type": "application/octet-stream", Urgency: payload.kind === "reaction" ? "normal" : "high", ...(topic ? { Topic: topic } : {}),
    },
    body: body as unknown as BodyInit,
  });
  if (!res.ok) throw new PushError(res.status, (await res.text().catch(() => "")).replace(/\s+/g, " ").trim().slice(0, 200));
  await res.body?.cancel().catch(() => {});
}

// every notice about a member is also kept for the home card „Pranešimai“ (user_notifications.sql);
// not the test, the „call this person“ and the hourly Team Tracker reminders
async function logNotes(userIds: string[], p: Payload) {
  if (p.tag === "test" || ["dial", "tracker"].includes(p.kind ?? "")) return;
  const now = new Date().toISOString();
  const rows = [...new Set(userIds)].map((u) => ({ user_id: u, tag: p.tag || "n-" + now, kind: p.kind ?? null, title: (p.title || "").slice(0, 300), body: (p.body || "").slice(0, 600), url: p.url || "./", created_at: now, read_at: null }));
  await db(`user_notifications?on_conflict=user_id,tag`, { method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" }, body: JSON.stringify(rows) });
}
async function sendTo(userIds: string[], payload: Payload, ttl = 86400, except = ""): Promise<{ sent: number; gone: number; devices?: number; stale?: number; failed?: string[] }> {
  if (!userIds.length) return { sent: 0, gone: 0 };
  try { await logNotes(userIds, payload); } catch (e) { console.error("notes", (e as Error).message); }   // before user_notifications.sql the table is missing
  let subs = await db<Sub[]>(`push_subscriptions?select=*&user_id=in.${inList(userIds)}`);
  const devices = subs.length;
  if (except) subs = subs.filter((s) => s.endpoint !== except);
  let sent = 0, gone = 0, staleN = 0;
  const failed: string[] = [];
  await Promise.all(subs.map(async (s) => {
    try {
      await pushOne(s, payload, ttl);
      sent++;
    } catch (e) {
      const status = e instanceof PushError ? e.status : 0;
      const note = (e instanceof PushError ? `${e.status} ${e.body}`.trim() : (e as Error)?.message || String(e)).slice(0, 220);
      // the device is gone, or it was subscribed with another (old) server key – it can never get a push again:
      // forget it; the app on that device subscribes anew by itself when opened
      const stale = (status === 401 || status === 403) && /VAPID public key mismatch|UnauthorizedRegistration|does not correspond to the sender|InvalidCredentials/i.test(note);
      if (status === 404 || status === 410 || stale) {
        gone++;
        if (stale) staleN++;
        await db(`push_subscriptions?endpoint=eq.${encodeURIComponent(s.endpoint)}`, { method: "DELETE" });
      } else {
        console.error("push failed", note);
        failed.push(note);
      }
    }
  }));
  const desktop = payload.kind === "dial" ? 0 : await toDesktop(userIds, payload);
  const ios = await toIos(userIds, payload, ttl);
  return { sent, gone, devices, ...(staleN ? { stale: staleN } : {}), ...(desktop ? { desktop } : {}), ...(ios ? { ios } : {}), ...(failed.length ? { failed } : {}) };
}

// ---------- iPhone app: Apple Push Notification service (APNs) ----------
const apnsOn = () => !!(Deno.env.get("APNS_KEY_ID") && Deno.env.get("APNS_TEAM_ID") && Deno.env.get("APNS_KEY_P8"));
let apnsJwt: { token: string; at: number } | null = null;
// Apple wants a token signed with the .p8 key (ES256), renewed at most every 20–60 min
async function apnsToken(): Promise<string> {
  if (apnsJwt && Date.now() - apnsJwt.at < 40 * 60e3) return apnsJwt.token;
  const pem = env("APNS_KEY_P8").replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const key = await crypto.subtle.importKey("pkcs8", b64ToBytes(pem), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const part = (o: unknown) => bytesToB64u(new TextEncoder().encode(JSON.stringify(o)));
  const now = Math.floor(Date.now() / 1000);
  const head = part({ alg: "ES256", kid: env("APNS_KEY_ID") }) + "." + part({ iss: env("APNS_TEAM_ID"), iat: now });
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(head)));
  apnsJwt = { token: head + "." + bytesToB64u(sig), at: Date.now() };
  return apnsJwt.token;
}
function b64ToBytes(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
export function apnsBody(payload: Payload) {
  const call = payload.kind === "call";
  return {
    aps: {
      alert: { title: payload.title, body: payload.body },
      sound: "default",
      "thread-id": payload.tag.slice(0, 64),
      // a call or "call this person" comes through even in Focus mode
      "interruption-level": call || payload.kind === "dial" ? "time-sensitive" : "active",
    },
    url: payload.url,
    kind: payload.kind ?? "",
  };
}
async function toIos(userIds: string[], payload: Payload, ttl: number): Promise<number> {
  if (!apnsOn() || !userIds.length) return 0;
  try {
    const devs = await db<{ token: string }[]>(`ios_devices?select=token&user_id=in.${inList(userIds)}`);
    if (!devs.length) return 0;
    const jwt = await apnsToken();
    const host = Deno.env.get("APNS_HOST") || "api.push.apple.com";
    const body = JSON.stringify(apnsBody(payload));
    let sent = 0;
    await Promise.all(devs.map(async (d) => {
      const res = await fetch(`https://${host}/3/device/${d.token}`, {
        method: "POST",
        headers: {
          authorization: `bearer ${jwt}`, "apns-topic": Deno.env.get("APNS_BUNDLE_ID") || "lt.eventsolutions.app",
          "apns-push-type": "alert", "apns-priority": payload.kind === "reaction" ? "5" : "10",
          "apns-expiration": String(Math.floor(Date.now() / 1000) + ttl), "apns-collapse-id": payload.tag.slice(0, 64),
        },
        body,
      }).catch((e) => { console.error("apns", (e as Error).message); return null; });
      if (!res) return;
      if (res.ok) { sent++; await res.body?.cancel().catch(() => {}); return; }
      const why = await res.text().catch(() => "");
      // the app was removed or the token is from another build
      if (res.status === 410 || /BadDeviceToken|Unregistered|DeviceTokenNotForTopic/.test(why)) {
        await db(`ios_devices?token=eq.${d.token}`, { method: "DELETE" }).catch(() => {});
      } else console.error("apns", res.status, why.slice(0, 200));
    }));
    return sent;
  } catch (e) {
    console.error("ios push", (e as Error)?.message || String(e));
    return 0;
  }
}

// The Windows app (desktop/) has no Web Push: it listens to desktop_inbox
// (desktop_inbox.sql). Only people who opened it in the last 45 days get rows.
async function toDesktop(userIds: string[], payload: Payload): Promise<number> {
  try {
    const since = new Date(Date.now() - 45 * 86400000).toISOString();
    const on = await db<{ user_id: string }[]>(`desktop_clients?select=user_id&user_id=in.${inList(userIds)}&last_seen=gte.${since}`);
    if (!on.length) return 0;
    const rows = on.map((c) => ({ user_id: c.user_id, title: payload.title, body: payload.body, tag: payload.tag, url: payload.url, kind: payload.kind ?? null }));
    await db("desktop_inbox", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify(rows) });
    if (Math.random() < 0.05) {
      await db(`desktop_inbox?created_at=lt.${new Date(Date.now() - 3 * 86400000).toISOString()}`, { method: "DELETE" });
    }
    return rows.length;
  } catch (e) {
    // the table is missing (SQL not run yet) or the database is busy: phones still get theirs
    console.error("desktop inbox", (e as Error)?.message || String(e));
    return 0;
  }
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
async function onMailNew(userId: string, items: { uid?: number; from?: string; subject?: string }[]) {
  if (!/^[0-9a-f-]{36}$/.test(userId) || !items.length) return { sent: 0 };
  const [p] = await db<Profile[]>(`profiles?select=id,role,first_name,last_name,full_name,nickname,email,notify_prefs&id=eq.${userId}`);
  if (!p || !APPROVED.includes(p.role)) return { sent: 0 };
  const pr = (p.notify_prefs ?? {}) as Prefs & { mail?: boolean };
  if (pr.mail === false || !wants(p.notify_prefs, "other", "")) return { sent: 0, skipped: "off" };
  let sent = 0;
  for (const it of items.slice(-5)) {
    const uid = Number(it.uid) || 0;
    // two checks running at once may both see the same new letter: told only once
    const seen = await db<{ id: string }[]>(`user_notifications?select=id&user_id=eq.${userId}&tag=eq.mail-${uid}&created_at=gt.${new Date(Date.now() - 6 * 3600e3).toISOString()}&limit=1`).catch(() => []);
    if (seen.length) continue;
    const r = await sendTo([userId], { title: "✉️ " + String(it.from || "Naujas laiškas").slice(0, 80), body: String(it.subject || "").slice(0, 140),
      tag: "mail-" + uid, url: "./?mail=" + uid, kind: "mail" });
    sent += r.sent;
  }
  return { sent };
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
  const [call] = await db<{ id: string; conversation_id: string; created_by: string; meet_url: string; provider?: string; media?: string; created_at: string; ended_at: string | null }[]>(
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
  const audio = call.media === "audio";
  const what = audio ? "Garso skambutis" : "Vaizdo skambutis";
  // a one-to-one call rings; in a channel or group the members are only told
  // that a call is going on – they join from the channel when they want
  if (c.kind !== "direct") {
    const where = c.kind === "general" ? "#bendras" : (c.kind === "group" && !c.title) ? "Grupėje" : "#" + (c.title || "kanalas");
    const r = await sendTo(to, {
      title: `${audio ? "🎧" : "📹"} Vyksta pokalbis · ${where}`,
      body: `${name(byId.get(uid))} pradėjo ${audio ? "garso" : "vaizdo"} pokalbį. Užeik į kanalą ir spausk „Prisijungti“.`,
      tag: "callinfo-" + call.id, url: `./?chat=${c.id}`, kind: "callinfo",
    }, 3600);
    return { ...r, members: to.length };
  }
  const r = await sendTo(to, {
    title: `${audio ? "📞" : "📹"} ${name(byId.get(uid))} skambina`,
    body: call.provider === "daily" ? `${what}. Priimti ar atmesti?` : `${what} (Google Meet). Priimti ar atmesti?`,
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
  online?: boolean; conversation_id?: string | null; notes?: string; summary_sent_at?: string | null;
};
type Guest = { id: string; meeting_id: string; email: string; name: string | null; token: string; status: string };
const APP = () => (Deno.env.get("APP_URL") || "https://app.eventsolutions.lt").replace(/\/$/, "");
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
// the guest's own buttons: answer, and (online meeting) the meeting page with chat, files and the call
export function guestLinksHtml(token: string, online: boolean): string {
  const u = (q: string) => `${APP()}/?svecias=${encodeURIComponent(token)}${q}`;
  const btn = (href: string, text: string, bg: string, fg = "#fff") =>
    `<a href="${escHtml(href)}" style="display:inline-block;margin:0 8px 8px 0;padding:11px 18px;border-radius:10px;background:${bg};color:${fg};font-weight:bold;text-decoration:none;font-size:14px;">${text}</a>`;
  return `<div style="margin-top:18px;">${btn(u("&ats=taip"), "✅ Dalyvausiu", "#2E8C77")}${btn(u("&ats=ne"), "❌ Nedalyvausiu", "#f1f1f3", "#111")}</div>`
    + (online ? `<div style="margin-top:6px;padding:14px;border-radius:10px;background:#111;color:#fff;">
<div style="font-weight:bold;margin-bottom:4px;">💬 Susitikimo puslapis</div>
<div style="font-size:13px;color:#ccc;margin-bottom:10px;">Pokalbis su organizatoriais, failų įkėlimas ir vaizdo skambutis – be jokios registracijos.</div>
${btn(u(""), "Atidaryti susitikimą", "#E5486C")}</div>` : `<div style="font-size:12px;color:#888;">Arba <a href="${escHtml(u(""))}" style="color:#E5486C;">atidaryk susitikimo puslapį</a>.</div>`);
}
export function meetingEmailHtml(m: Meeting, organizer: string, people: string[], mode: string, guestToken = ""): string {
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
${mode !== "cancel" && guestToken ? guestLinksHtml(guestToken, !!m.online) : ""}
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
  // every invited e-mail gets its own link (answer, meeting page); an online meeting also gets its chat
  const tokens = mode === "cancel" ? new Map<string, string>() : await meetingGuests(m).catch((e) => { console.error("guests", (e as Error).message); return new Map<string, string>(); });
  if (m.online && mode !== "cancel") await meetingRoom(m).catch((e) => console.error("meeting room", (e as Error).message));
  if (emails.length) {
    const ics = meetingIcs(m, { name: organizer, email: me?.email ?? "" }, mode === "cancel", seq);
    const subject = (mode === "cancel" ? "Atšaukta: " : mode === "update" ? "Pakeista: " : "Kvietimas: ") + m.title + " · " + when;
    for (const e of emails) {
      try {
        const html = meetingEmailHtml(m, organizer, people, mode, tokens.get(e) || "");
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


// ---------- meetings with people from outside (guest_meetings.sql) ----------
const validEmail = (e: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
// a row (and a secret link) for every invited e-mail -> e-mail: token
async function meetingGuests(m: Meeting): Promise<Map<string, string>> {
  const emails = [...new Set((m.emails ?? []).map((e) => e.trim().toLowerCase()).filter(validEmail))];
  if (emails.length) {
    await db("meeting_guests?on_conflict=meeting_id,email", {
      method: "POST", headers: { Prefer: "resolution=ignore-duplicates,return=minimal" },
      body: JSON.stringify(emails.map((email) => ({ meeting_id: m.id, email }))),
    });
  }
  // someone taken off the list: their link stops working
  await db(`meeting_guests?meeting_id=eq.${m.id}` + (emails.length ? `&email=not.in.${inList(emails)}` : ""), { method: "DELETE" });
  const rows = await db<Guest[]>(`meeting_guests?select=email,token&meeting_id=eq.${m.id}`);
  return new Map(rows.map((r) => [r.email, r.token]));
}
// the meeting's chat: a group "🤝 <title>" of the organizer and the invited members
async function meetingRoom(m: Meeting): Promise<string> {
  const title = ("🤝 " + m.title).slice(0, 80);
  let cid = m.conversation_id || "";
  if (!cid) {
    const [c] = await db<{ id: string }[]>("conversations", {
      method: "POST", headers: { Prefer: "return=representation" },
      body: JSON.stringify({ kind: "group", title, created_by: m.created_by }),
    });
    cid = c.id;
    await db(`meetings?id=eq.${m.id}`, { method: "PATCH", body: JSON.stringify({ conversation_id: cid }) });
  } else {
    await db(`conversations?id=eq.${cid}`, { method: "PATCH", body: JSON.stringify({ title }) });
  }
  const have = new Set((await db<{ user_id: string }[]>(`conversation_members?select=user_id&conversation_id=eq.${cid}`)).map((x) => x.user_id));
  const add = [...new Set([m.created_by, ...(m.attendees ?? [])])].filter((u) => !have.has(u));
  if (add.length) await db("conversation_members", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify(add.map((user_id) => ({ conversation_id: cid, user_id }))) });
  return cid;
}
// a guest answered: the organizer is told
async function onGuestRsvp(guestId: string) {
  const [g] = await db<Guest[]>(`meeting_guests?select=*&id=eq.${encodeURIComponent(guestId)}`);
  if (!g || !["yes", "no"].includes(g.status)) return { sent: 0 };
  const [m] = await db<Meeting[]>(`meetings?select=*&id=eq.${g.meeting_id}`);
  if (!m) return { sent: 0 };
  const who = g.name || g.email;
  return await sendTo([m.created_by], {
    title: (g.status === "yes" ? "✅ " + who + " dalyvaus" : "❌ " + who + " nedalyvaus"),
    body: m.title + " · " + meetingWhen(m), tag: "rsvp-" + g.id, url: `./?meeting=${m.id}`, kind: "meeting",
  });
}
// a guest wrote in the meeting's chat: its members are told
async function onGuestMessage(messageId: string) {
  const [msg] = await db<(Msg & { guest_name: string | null; guest_id: string | null })[]>(`messages?select=*&id=eq.${encodeURIComponent(messageId)}`);
  if (!msg || !msg.guest_id) return { sent: 0 };
  const [c] = await db<{ id: string; title: string | null }[]>(`conversations?select=id,title&id=eq.${msg.conversation_id}`);
  const members = (await db<{ user_id: string }[]>(`conversation_members?select=user_id&conversation_id=eq.${msg.conversation_id}`)).map((x) => x.user_id);
  const users = await chatUsers();
  const byId = new Map(users.map((u) => [u.id, u]));
  const to = members.filter((u) => byId.has(u) && wants(byId.get(u)!.notify_prefs, "group", msg.conversation_id));
  return await sendTo(to, {
    title: `💬 ${msg.guest_name || "Svečias"} (svečias) · ${c?.title || "susitikimas"}`,
    body: preview(msg), tag: "m-" + msg.conversation_id, url: `./?chat=${msg.conversation_id}`, kind: "message",
  });
}
// a guest opened the meeting's call: its members are told (the organizer too)
async function onGuestCall(callId: string, guestId: string) {
  const [call] = await db<{ id: string; conversation_id: string; media?: string; ended_at: string | null }[]>(`calls?select=id,conversation_id,media,ended_at&id=eq.${encodeURIComponent(callId)}`);
  const [g] = await db<Guest[]>(`meeting_guests?select=*&id=eq.${encodeURIComponent(guestId)}`);
  if (!call || call.ended_at || !g) return { sent: 0 };
  const [c] = await db<{ id: string; title: string | null }[]>(`conversations?select=id,title&id=eq.${call.conversation_id}`);
  const members = (await db<{ user_id: string }[]>(`conversation_members?select=user_id&conversation_id=eq.${call.conversation_id}`)).map((x) => x.user_id);
  const users = await chatUsers();
  const byId = new Map(users.map((u) => [u.id, u]));
  const to = members.filter((u) => byId.has(u) && wantsCall(byId.get(u)!.notify_prefs));
  const audio = call.media === "audio";
  return await sendTo(to, {
    title: `${audio ? "🎧" : "📹"} ${g.name || g.email} (svečias) laukia skambutyje`,
    body: `${c?.title || "Susitikimas"} · užeik į pokalbį ir spausk „Prisijungti“.`,
    tag: "callinfo-" + call.id, url: `./?chat=${call.conversation_id}`, kind: "callinfo",
  }, 3600);
}
// ---- files in the summary: a link that works for 7 days (Cloudflare R2, or Supabase Storage for older ones)
const r2On = () => !!(Deno.env.get("R2_ACCOUNT_ID") && Deno.env.get("R2_ACCESS_KEY_ID") && Deno.env.get("R2_SECRET_ACCESS_KEY") && Deno.env.get("R2_BUCKET"));
const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const rfc3986 = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
function r2Presign(method: string, key: string, expires: number, query: Record<string, string> = {}): string {
  const host = `${env("R2_ACCOUNT_ID")}.r2.cloudflarestorage.com`, enc = new TextEncoder();
  const full = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, ""), day = full.slice(0, 8);
  const scope = `${day}/auto/s3/aws4_request`;
  const uri = "/" + rfc3986(env("R2_BUCKET")) + "/" + key.split("/").map(rfc3986).join("/");
  const q: Record<string, string> = { "X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": `${env("R2_ACCESS_KEY_ID")}/${scope}`, "X-Amz-Date": full, "X-Amz-Expires": String(expires), "X-Amz-SignedHeaders": "host", ...query };
  const qs = Object.keys(q).sort().map((k) => rfc3986(k) + "=" + rfc3986(q[k])).join("&");
  const canonical = [method, uri, qs, "host:" + host + "\n", "host", "UNSIGNED-PAYLOAD"].join("\n");
  const sts = ["AWS4-HMAC-SHA256", full, scope, hexOf(sha256(enc.encode(canonical)))].join("\n");
  let k = hmac(sha256, enc.encode("AWS4" + env("R2_SECRET_ACCESS_KEY")), enc.encode(day));
  for (const part of ["auto", "s3", "aws4_request"]) k = hmac(sha256, k, enc.encode(part));
  return `https://${host}${uri}?${qs}&X-Amz-Signature=${hexOf(hmac(sha256, k, enc.encode(sts)))}`;
}
async function fileLink(path: string, name: string): Promise<string> {
  const week = 7 * 86400;
  if (r2On()) {
    const head = await fetch(r2Presign("HEAD", "chat-files/" + path, 60), { method: "HEAD" }).catch(() => null);
    if (head && head.ok) return r2Presign("GET", "chat-files/" + path, week, { "response-content-disposition": `attachment; filename*=UTF-8''${rfc3986(name)}` });
  }
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${env("SUPABASE_URL")}/storage/v1/object/sign/chat-files/${path.split("/").map(encodeURIComponent).join("/")}`, {
    method: "POST", headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify({ expiresIn: week }),
  }).catch(() => null);
  const j = res && res.ok ? await res.json().catch(() => null) : null;
  return j?.signedURL ? `${env("SUPABASE_URL")}/storage/v1${j.signedURL}&download=${encodeURIComponent(name)}` : "";
}
export function meetingSummaryHtml(m: Meeting, organizer: string, people: string[], notes: string, files: { name: string; url: string; by: string }[], chat: { who: string; at: string; text: string }[]): string {
  const sec = (t: string, body: string) => `<h3 style="margin:22px 0 8px;font-size:15px;">${t}</h3>${body}`;
  return `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#111;max-width:620px;">
<div style="font-size:12px;letter-spacing:.5px;text-transform:uppercase;color:#e04e6c;font-weight:bold;">Susitikimo santrauka</div>
<h2 style="margin:6px 0 10px;font-size:22px;">${escHtml(m.title)}</h2>
<div style="color:#555;">${escHtml(meetingWhen(m))}${m.location ? " · " + escHtml(m.location) : ""} · organizatorius ${escHtml(organizer)}</div>
<div style="color:#555;margin-top:4px;">Dalyviai: ${escHtml(people.join(", "))}</div>
${sec("📝 Užrašai", notes.trim() ? `<div style="padding:12px 14px;background:#f5f5f7;border-radius:8px;white-space:pre-wrap;">${escHtml(notes)}</div>` : `<div style="color:#888;">Užrašų nebuvo.</div>`)}
${files.length ? sec("📎 Failai", files.map((f) => `<div style="margin:4px 0;">${f.url ? `<a href="${escHtml(f.url)}" style="color:#E5486C;">${escHtml(f.name)}</a>` : escHtml(f.name)} <span style="color:#888;">· ${escHtml(f.by)}</span></div>`).join("") + `<div style="font-size:12px;color:#888;margin-top:6px;">Nuorodos galioja 7 dienas.</div>`) : ""}
${chat.length ? sec("💬 Pokalbis", chat.map((c) => `<div style="margin:6px 0;"><b>${escHtml(c.who)}</b> <span style="color:#888;font-size:12px;">${escHtml(c.at)}</span><div style="white-space:pre-wrap;">${escHtml(c.text)}</div></div>`).join("")) : ""}
<p style="margin-top:22px;font-size:12px;color:#888;">Išsiųsta per EventSolutions App.</p></div>`;
}
// the call is over (everybody left): notes, files and the chat to everybody invited, once
async function onMeetingSummary(meetingId: string) {
  const claimed = await db<Meeting[]>(`meetings?id=eq.${encodeURIComponent(meetingId)}&summary_sent_at=is.null`, {
    method: "PATCH", headers: { Prefer: "return=representation" }, body: JSON.stringify({ summary_sent_at: new Date().toISOString() }),
  });
  const m = claimed[0];
  if (!m) return { sent: 0, skipped: "already sent" };
  const profiles = await db<Profile[]>(`profiles?select=id,role,first_name,last_name,full_name,nickname,email,notify_prefs&role=in.(${APPROVED.join(",")})`);
  const byId = new Map(profiles.map((p) => [p.id, p]));
  const organizer = name(byId.get(m.created_by));
  const guests = await db<Guest[]>(`meeting_guests?select=*&meeting_id=eq.${m.id}`);
  const gName = (g: Guest) => g.name || g.email;
  const people = [organizer, ...(m.attendees ?? []).filter((u) => u !== m.created_by).map((u) => name(byId.get(u))), ...guests.map(gName)];
  type M = { body: string; attachments: { type?: string; path?: string; name?: string }[]; created_at: string; sender_id: string; guest_name: string | null; deleted_at: string | null };
  const msgs = m.conversation_id ? await db<M[]>(`messages?select=body,attachments,created_at,sender_id,guest_name,deleted_at&conversation_id=eq.${m.conversation_id}&deleted_at=is.null&order=created_at.asc&limit=400`) : [];
  const who = (x: M) => x.guest_name ? x.guest_name + " (svečias)" : name(byId.get(x.sender_id));
  const at = (iso: string) => new Intl.DateTimeFormat("lt-LT", { timeZone: TZ, hour: "2-digit", minute: "2-digit" }).format(new Date(iso));
  const files: { name: string; url: string; by: string }[] = [];
  for (const x of msgs) for (const a of x.attachments ?? []) if (a.path) files.push({ name: a.name || a.path.split("/").pop() || "failas", url: await fileLink(a.path, a.name || "failas").catch(() => ""), by: who(x) });
  const chat = msgs.filter((x) => (x.body || "").trim() && !/skambutis: https:/.test(x.body)).map((x) => ({ who: who(x), at: at(x.created_at), text: withNames(x.body, byId) }));
  const html = meetingSummaryHtml(m, organizer, people, m.notes || "", files, chat);
  const to = [...new Set([
    ...[m.created_by, ...(m.attendees ?? [])].map((u) => byId.get(u)?.email || "").filter(validEmail),
    ...guests.map((g) => g.email).filter(validEmail),
  ].map((e) => e.toLowerCase()))];
  let mailed = 0;
  for (const e of to) if (!(await mailTo([e], "Santrauka: " + m.title, html))) mailed++;
  return { mailed, to: to.length, files: files.length };
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
    signal: AbortSignal.timeout(12000),
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
      const ids = await wantIds([...who], "tasks");
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
// Team Tracker: every hour of an open shift the app account that started it is reminded that the tracker runs
const TT_KIND: Record<string, string> = { warehouse: "Sandėlis", driving: "Vairavimas", standby: "Budėjimas", setup: "Montažas", teardown: "Demontažas", operator: "Operatorius", break: "Pertrauka" };
type OpenShift = { id: string; member_id: string; started_by: string | null; started_at: string; reminded_at: string | null; tracker_members: { name: string } | null; time_entries: { kind: string; ended_at: string | null }[] };
async function trackerReminders() {
  const now = Date.now();
  const open = await db<OpenShift[]>(`time_shifts?select=id,member_id,started_by,started_at,reminded_at,tracker_members(name),time_entries(kind,ended_at)&ended_at=is.null`);
  const out: unknown[] = [];
  for (const s of open) {
    const from = Date.parse(s.reminded_at ?? s.started_at);
    if (!s.started_by || now - from < 59 * 60000) continue;
    const mins = Math.floor((now - Date.parse(s.started_at)) / 60000);
    const cur = s.time_entries.find((e) => !e.ended_at);
    const body = `${s.tracker_members?.name ?? ""}: dirbama ${Math.floor(mins / 60)} val. ${mins % 60} min.${cur ? " Dabar – " + (TT_KIND[cur.kind] ?? cur.kind) + "." : ""} Nepamiršk baigti darbo.`;
    const r = await sendTo([s.started_by], { title: "Team Tracker aktyvus", body, tag: "tracker-" + s.id, url: "./?tracker=1", kind: "tracker" }, 3600);
    await db(`time_shifts?id=eq.${s.id}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ reminded_at: new Date(now).toISOString() }) });
    out.push({ shift: s.id, sent: r.sent });
  }
  return { open: open.length, sent: out };
}
// Team Tracker „Pamiršau PIN“: a one-time link (1 hour) to the e-mail of the member's own account
async function onTrackerPin(memberId: string) {
  if (!/^[0-9a-f-]{36}$/i.test(memberId)) return { error: "Nėra nario." };
  let step = "duomenų bazė (tracker_members)";
  try {
    return await trackerPinSteps(memberId, (s) => { step = s; });
  } catch (e) {
    const m = e instanceof Error ? e.message : String(e);
    return { error: `Sustojo ties: ${step}. ${/timed? ?out|TimeoutError|aborted/i.test(m) ? "Neatsakė per 12 s." : m.slice(0, 200)}` };
  }
}
async function trackerPinSteps(memberId: string, at: (s: string) => void) {
  const [m] = await db<{ id: string; name: string; user_id: string | null; reset_sent_at: string | null }[]>(`tracker_members?select=id,name,user_id,reset_sent_at&id=eq.${memberId}`);
  if (!m) return { error: "Tokio nario nėra." };
  if (!m.user_id) return { error: "Šis narys nesusietas su paskyra – PIN pakeisti gali administratorius (ištrinti ir užregistruoti iš naujo)." };
  if (m.reset_sent_at && Date.now() - Date.parse(m.reset_sent_at) < 2 * 60000) return { error: "Nuoroda ką tik išsiųsta – patikrink el. paštą (ir šlamšto aplanką)." };
  at("duomenų bazė (profiles)");
  const [p] = await db<{ email: string }[]>(`profiles?select=email&id=eq.${m.user_id}`);
  if (!p?.email) return { error: "Paskyra neturi el. pašto." };
  at("duomenų bazė (tracker_pin_resets – ar paleistas tracker.sql?)");
  const raw = crypto.getRandomValues(new Uint8Array(24));
  const token = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
  const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)))].map((b) => b.toString(16).padStart(2, "0")).join("");
  await db(`tracker_pin_resets`, { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ token_hash: hash, member_id: m.id, expires_at: new Date(Date.now() + 3600000).toISOString() }) });
  const link = `${APP()}/?ttpin=${token}`;
  const html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;line-height:1.5;">
    <p>Sveiki, ${esc(m.name)},</p><p>gavome prašymą pakeisti tavo <b>Team Tracker</b> PIN kodą.</p>
    <p><a href="${link}" style="display:inline-block;background:#50AD97;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:bold;">Pakeisti PIN kodą</a></p>
    <p style="color:#555;">Nuoroda galioja 1 valandą ir veikia vieną kartą. Jei PIN keisti neprašei – tiesiog ignoruok šį laišką.</p>
    <p style="color:#777;font-size:12px;margin-top:18px;">EventSolutions App · Team Tracker</p></div>`;
  at("laiško siuntimas (Resend)");
  const err = await mailTo([p.email], "Team Tracker: PIN kodo keitimas", html);
  if (err) return { error: "Laiško išsiųsti nepavyko: " + err };
  await db(`tracker_members?id=eq.${m.id}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ reset_sent_at: new Date().toISOString() }) });
  const [u, d] = p.email.split("@");
  return { ok: true, to: (u.length > 2 ? u.slice(0, 2) + "•••" : u[0] + "•••") + "@" + d };
}
// Admin → „Laiškų patikra“: a test e-mail to the caller, with Resend's exact answer
async function onMailTest(uid: string) {
  const [p] = await db<{ email: string; role: string }[]>(`profiles?select=email,role&id=eq.${uid}`);
  if (!p || p.role !== "admin") return { error: "Tik administratoriui." };
  const key = Deno.env.get("RESEND_API_KEY") ?? "", from = Deno.env.get("REMINDER_FROM") || "Event Solutions <onboarding@resend.dev>";
  const out: Record<string, unknown> = { to: p.email, from, key: key ? "nustatytas (" + key.slice(0, 5) + "…)" : "NENUSTATYTAS", fn: PUSH_FN_VERSION };
  if (!key) return { ...out, ok: false, error: "Supabase → Edge Functions → Secrets: nėra RESEND_API_KEY." };
  const res = await fetch("https://api.resend.com/emails", {
    signal: AbortSignal.timeout(12000),
    method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to: [p.email], subject: "EventSolutions App: laiškų patikra", html: `<div style="font-family:Arial,sans-serif;font-size:14px;">✓ Laiškai iš programėlės veikia (${new Date().toISOString()}).</div>` }),
  });
  const text = (await res.text()).slice(0, 400);
  return { ...out, ok: res.ok, status: res.status, resend: text };
}
// the people who want notifications about a topic (Profilis → Pranešimai)
async function wantIds(ids: string[], kind: "tasks" | "events" | "gear" | "leave" | "other"): Promise<string[]> {
  if (!ids.length) return [];
  const ps = await db<Profile[]>(`profiles?select=id,notify_prefs&id=in.${inList(ids)}`);
  return ps.filter((p) => wants(p.notify_prefs, kind, kind)).map((p) => p.id);
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
  ids = await wantIds(ids, "tasks");
  if (!ids.length) return { sent: 0 };
  return await sendTo(ids, { title, body, tag: "task-" + t.id, url: `./?task=${t.id}`, kind: "task" });
}

// Sąskaitos: a new one goes to Admin+, the decision to its uploader, a reply
// from the e-mail to Admin+; „Priminti vėliau“ comes back at the chosen time
type Invoice = { id: string; created_by: string; kind: string; supplier: string | null; number: string | null; amount: number | null; status: string; decision_note: string | null; remind_at: string | null; reminded_at: string | null; responses: { who?: string; kind: string; text?: string }[] };
const INV_KIND: Record<string, string> = { freelance: "Freelance", service: "Paslaugų", rent: "Nuomos", purchase: "Pirkinių" };
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
    return await sendTo(await wantIds(plus.filter((u) => u !== uid), "other"), { title: "🧾 Nauja sąskaita: " + invTitle(v), body: "Įkėlė " + name(me), tag: "inv-" + v.id, url: `./?invoice=${v.id}`, kind: "invoice" });
  }
  if (!plus.includes(uid)) return { error: "Tik Admin+" };
  if (v.created_by === uid || !INV_STATUS[v.status]) return { sent: 0 };
  return await sendTo(await wantIds([v.created_by], "other"), { title: INV_STATUS[v.status], body: invTitle(v) + (v.decision_note ? " · " + v.decision_note.slice(0, 120) : ""), tag: "inv-" + v.id, url: `./?invoice=${v.id}`, kind: "invoice" });
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
// „kviečia pažaisti“: a colleague who is not in the app gets a notification; the invite itself comes when they open it
async function onGameInvite(uid: string, to: string[], game: string, room: string) {
  const ids = [...new Set(to.map(String).filter((x) => /^[0-9a-f-]{36}$/i.test(x) && x !== uid))].slice(0, 11);
  if (!ids.length || !room) return { sent: 0 };
  const [me] = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&id=eq.${uid}`);
  if (!me || me.role === "pending") return { error: "Tik patvirtinti nariai" };
  return await sendTo(ids, { title: "🎮 " + name(me) + " kviečia pažaisti", body: game + " – atidaryk programą ir priimk kvietimą", tag: "game-" + room, url: `./?game=${encodeURIComponent(room)}`, kind: "game" }, 600);
}
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

// „Įranga“: sugadinta / dingusi įranga (public.gear_issues, sql/gear.sql)
type GearIssue = { id: string; kind: string; item_name: string; qty: number; state: string; place: string | null; assignee: string | null; members: string[] | null; created_by: string;
  wo_status: string | null; wo_approver: string | null; wo_requested_by: string | null; wo_requested_name: string | null; wo_note: string | null; wo_decision_note: string | null };
async function onGear(uid: string, id: string, ev: string) {
  const [g] = await db<GearIssue[]>(`gear_issues?select=id,kind,item_name,qty,state,place,assignee,members,created_by,wo_status,wo_approver,wo_requested_by,wo_requested_name,wo_note,wo_decision_note&id=eq.${encodeURIComponent(id)}`);
  if (!g) return { error: "Įrašas nerastas" };
  const people = new Set<string>([...(g.members ?? []), ...(g.assignee ? [g.assignee] : []), g.created_by]);
  const what0 = `${g.item_name}${g.qty > 1 ? " × " + g.qty : ""}`;
  // write-off approval: the request goes to every Admin+ (push + e-mail), the answer back to the requester
  if (ev === "wo_request") {
    if (g.wo_status !== "pending" || g.wo_requested_by !== uid) return { error: "Prašymo nėra" };
    const url = `./?gear=${g.id}`;
    const plus = await wantIds((await plusIds()).filter((u) => u !== uid), "gear");
    if (!plus.length) return { sent: 0 };
    const r = await sendTo(plus, { title: "Patvirtinti nurašymą: " + what0, body: (g.wo_requested_name || "") + (g.wo_note ? " · " + g.wo_note.slice(0, 120) : ""), tag: "gear-wo-" + g.id, url, kind: "gear" });
    const aps = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&id=in.${inList(plus)}`);
    const link = (Deno.env.get("APP_URL") || "https://app.eventsolutions.lt").replace(/\/$/, "") + "/?gear=" + g.id;
    const html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;line-height:1.5;">
      <p><b>Prašoma patvirtinti įrangos nurašymą</b></p>
      <p>${esc(what0)}${g.kind === "lost" ? " (dingęs daiktas)" : g.state === "broken" ? " (sugadintas, negalima naudoti)" : " (pažeistas)"}</p>
      <p>Prašo: ${esc(g.wo_requested_name || "")}${g.wo_note ? `<br>Priežastis: ${esc(g.wo_note)}` : ""}</p>
      <p><a href="${esc(link)}" style="display:inline-block;padding:10px 16px;background:#F35E7D;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;">Atidaryti ir patvirtinti</a></p>
      <p style="color:#777;font-size:12px;margin-top:18px;">EventSolutions App · prašymas išsiųstas visiems Admin+ nariams; kol vienas nepatvirtins, daiktas nenurašomas.</p></div>`;
    const mailErr = await mailTo(aps.map((p) => p.email).filter(Boolean), "Patvirtinti nurašymą: " + what0.slice(0, 120), html);
    return { ...r, ...(mailErr ? { mailErr } : {}) };
  }
  if (ev === "wo_approved" || ev === "wo_rejected") {
    if (g.wo_approver !== uid) return { error: "Tik patvirtinęs narys" };
    const to = await wantIds([...new Set([g.wo_requested_by, g.created_by, g.assignee].filter((x): x is string => !!x && x !== uid))], "gear");
    return await sendTo(to, { title: (ev === "wo_approved" ? "Nurašymas patvirtintas: " : "Nurašymas atmestas: ") + what0, body: g.wo_decision_note ? g.wo_decision_note.slice(0, 140) : "", tag: "gear-wo-" + g.id, url: `./?gear=${g.id}`, kind: "gear" });
  }
  if (!people.has(uid)) return { error: "Tik įrašo dalyviai" };
  people.delete(uid);
  const [me] = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&id=eq.${uid}`);
  const what = `${g.item_name}${g.qty > 1 ? " × " + g.qty : ""}`;
  const title = ev === "fixed" ? "Sutaisyta: " + what
    : ev === "found" ? "Rasta: " + what
    : g.kind === "lost" ? "Dingo: " + what
    : (g.state === "broken" ? "Sugadinta: " : "Pažeista: ") + what;
  const body = (g.kind === "lost" && g.place && ev === "new" ? "Galimai: " + g.place + " · " : "") + name(me);
  return await sendTo(await wantIds([...people], "gear"), { title, body, tag: "gear-" + g.id, url: `./?gear=${g.id}`, kind: "gear" });
}

// Transportas: removing a vehicle from the fleet needs an Admin+ approval – the request goes to every
// other Admin+ (push + e-mail), the answer back to the one who asked
type VehicleRm = { id: string; vehicle_id: string; vehicle_name: string; plate: string | null; reason: string; status: string; requested_by: string; requested_name: string | null; decided_by: string | null; decision_note: string | null };
async function onVehicleRm(uid: string, id: string, ev: string) {
  const [r] = await db<VehicleRm[]>(`vehicle_removals?select=id,vehicle_id,vehicle_name,plate,reason,status,requested_by,requested_name,decided_by,decision_note&id=eq.${encodeURIComponent(id)}`);
  if (!r) return { error: "Prašymas nerastas" };
  const what = r.vehicle_name + (r.plate ? " (" + r.plate + ")" : "");
  const url = `./?vehicle=${encodeURIComponent(r.vehicle_id)}`;
  if (ev === "request") {
    if (r.status !== "pending" || r.requested_by !== uid) return { error: "Prašymo nėra" };
    const plus = await wantIds((await plusIds()).filter((u) => u !== uid), "other");
    if (!plus.length) return { sent: 0 };
    const res = await sendTo(plus, { title: "🚐 Patvirtinti automobilio pašalinimą: " + what, body: (r.requested_name || "") + (r.reason ? " · " + r.reason.slice(0, 120) : ""), tag: "veh-rm-" + r.id, url, kind: "fleet" });
    const aps = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&id=in.${inList(plus)}`);
    const link = (Deno.env.get("APP_URL") || "https://app.eventsolutions.lt").replace(/\/$/, "") + "/?vehicle=" + encodeURIComponent(r.vehicle_id);
    const html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;line-height:1.5;">
      <p><b>Prašoma patvirtinti automobilio pašalinimą iš parko</b></p>
      <p>${esc(what)}</p>
      <p>Prašo: ${esc(r.requested_name || "")}${r.reason ? `<br>Priežastis: ${esc(r.reason)}` : ""}</p>
      <p><a href="${esc(link)}" style="display:inline-block;padding:10px 16px;background:#F35E7D;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;">Atidaryti ir patvirtinti</a></p>
      <p style="color:#777;font-size:12px;margin-top:18px;">EventSolutions App · prašymas išsiųstas visiems Admin+ nariams; kol vienas nepatvirtins, automobilis lieka parke.</p></div>`;
    const mailErr = await mailTo(aps.map((p) => p.email).filter(Boolean), "Patvirtinti automobilio pašalinimą: " + what.slice(0, 120), html);
    return { ...res, ...(mailErr ? { mailErr } : {}) };
  }
  if (r.decided_by !== uid || !["approved", "rejected", "done"].includes(r.status) || r.requested_by === uid) return { error: "Tik patvirtinęs narys" };
  const ok = r.status !== "rejected";
  return await sendTo(await wantIds([r.requested_by], "other"), { title: (ok ? "Pašalinimas patvirtintas: " : "Pašalinimas atmestas: ") + what, body: r.decision_note ? r.decision_note.slice(0, 140) : "", tag: "veh-rm-" + r.id, url, kind: "fleet" });
}

// Naujas narys: someone registered and waits for access – every admin (Admin, Admin+, Super Admin)
async function onNewUser(id: string) {
  const [u] = await db<(Profile & { created_at: string })[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs,created_at&id=eq.${encodeURIComponent(id)}`);
  if (!u || u.role !== "pending") return { sent: 0, skipped: "not pending" };
  if (Date.now() - new Date(u.created_at).getTime() > 24 * 3600 * 1000) return { sent: 0, skipped: "old" };
  const admins = (await db<{ id: string }[]>(`profiles?select=id&role=eq.admin`)).map((a) => a.id);
  const to = await wantIds(admins, "other");
  return await sendTo(to, {
    title: "Naujas narys laukia patvirtinimo",
    body: `${[u.first_name, u.last_name].filter(Boolean).join(" ") || u.full_name || u.email} (${u.email}) – suteik prieigą skiltyje Admin`,
    tag: "newuser-" + u.id, url: "./?admin=pending", kind: "admin",
  });
}

// Prašymai (laisvos dienos / atostogos): a new or cancelled one goes to the
// office members and Admin+, the decision back to the one who asked
type Leave = { id: string; user_id: string; user_name: string | null; kind: string; days: string[] | null; date_from: string; date_to: string; reason: string; status: string; decision_note: string | null; decided_by: string | null; decided_by_name: string | null };
async function onLeave(uid: string, id: string, ev: string) {
  const [r] = await db<Leave[]>(`leave_requests?select=*&id=eq.${encodeURIComponent(id)}`);
  if (!r) return { error: "Prašymas nerastas" };
  const day = (s: string) => String(s).slice(5, 10).replace("-", ".");
  const when = r.kind === "dayoff" && (r.days || []).length ? (r.days || []).map(day).join(", ") : day(r.date_from) + (r.date_to !== r.date_from ? "–" + day(r.date_to) : "");
  const what = r.kind === "dayoff" ? "Laisvos dienos" : "Atostogos";
  const url = `./?leave=${r.id}`;
  if (ev === "new" || ev === "cancelled") {
    if (r.user_id !== uid) return { error: "Tik prašymą pateikęs narys" };
    if (ev === "new" && r.status !== "pending") return { sent: 0 };
    if (ev === "cancelled" && r.status !== "cancelled") return { sent: 0 };
    const staff = (await db<{ id: string }[]>(`profiles?select=id&or=(role.eq.office,and(role.eq.admin,level.in.(plus,super)))`)).map((p) => p.id).filter((x) => x !== uid);
    const to = await wantIds(staff, "leave");
    return await sendTo(to, {
      title: (ev === "new" ? "Naujas prašymas: " : "Atšauktas prašymas: ") + what.toLowerCase() + " · " + (r.user_name || ""),
      body: when + (ev === "new" && r.reason ? " · " + r.reason.slice(0, 120) : ""), tag: "leave-" + r.id, url, kind: "leave",
    });
  }
  // decided
  if (r.decided_by !== uid || !["approved", "rejected"].includes(r.status)) return { error: "Tik sprendimą priėmęs narys" };
  const to = await wantIds([r.user_id], "leave");
  return await sendTo(to, {
    title: `${what} ${r.status === "approved" ? "patvirtintos" : "nepatvirtintos"}: ${when}`,
    body: (r.decided_by_name || "") + (r.decision_note ? " · " + r.decision_note.slice(0, 120) : ""), tag: "leave-" + r.id, url, kind: "leave",
  });
}

// Renginiai: a member written into an event's crew (or as its manager) is told.
// The app sends the people it added; the server checks the caller may edit
// events and that each of them really is in that event now (by name).
const normName = (s: string) => String(s || "").toLowerCase()
  .replace(/[ąčęėįšųūž]/g, (c) => ({ "ą": "a", "č": "c", "ę": "e", "ė": "e", "į": "i", "š": "s", "ų": "u", "ū": "u", "ž": "z" })[c]!)
  .replace(/[^a-z0-9 ]/g, " ").replace(/\s+/g, " ").trim();
type EvCrew = { title?: string; note?: string; entries?: { pos?: string; person?: string }[] };
type EvData = { name?: string; title?: string; kind?: string; date?: string; dateEnd?: string; venue?: string; location?: string; manager?: string; crew?: EvCrew[] };
async function canEditEvents(uid: string): Promise<boolean> {
  const [me] = await db<{ role: string }[]>(`profiles?select=role&id=eq.${uid}`);
  if (!me) return false;
  if (me.role === "admin") return true;
  const [rp] = await db<{ can_edit: boolean }[]>(`role_permissions?select=can_edit&role=eq.${encodeURIComponent(me.role)}&section=eq.events`);
  return !!rp?.can_edit;
}
async function onEvent(uid: string, id: string, users: string[]) {
  if (!(await canEditEvents(uid))) return { error: "Tik tas, kas redaguoja renginius" };
  const [row] = await db<{ id: string; data: EvData }[]>(`events?select=id,data&id=eq.${encodeURIComponent(id)}`);
  if (!row) return { error: "Renginys nerastas" };
  const d = row.data || {};
  // who is written in, and where
  const where = new Map<string, string[]>();
  (d.crew || []).forEach((g) => (g.entries || []).forEach((e) => {
    const k = normName(e.person || ""); if (!k) return;
    const w = [g.title, e.pos].filter(Boolean).join(" · ");
    where.set(k, [...(where.get(k) || []), ...(w ? [w] : [])]);
  }));
  if (d.manager) where.set(normName(d.manager), [...(where.get(normName(d.manager)) || []), "Vadovas"]);
  const want = [...new Set(users.map(String))].filter((u) => u && u !== uid).slice(0, 200);
  if (!want.length) return { sent: 0 };
  const ps = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&id=in.${inList(want)}&role=in.(${APPROVED.join(",")})`);
  const [me] = await db<Profile[]>(`profiles?select=id,email,first_name,last_name,full_name,nickname,role,notify_prefs&id=eq.${uid}`);
  const evName = d.kind === "work" ? (d.title || "Sandėlio darbai") : (d.name || "Renginys");
  const day = (s?: string) => s ? s.slice(5, 10).replace("-", ".") : "";
  const when = d.date ? day(d.date) + (d.dateEnd && d.dateEnd !== d.date ? "–" + day(d.dateEnd) : "") : "";
  let sent = 0, skipped = 0;
  for (const p of ps) {
    const full = normName([p.first_name, p.last_name].filter(Boolean).join(" ") || p.full_name || "");
    const hit = where.get(full) || (p.nickname ? where.get(normName(p.nickname)) : undefined);
    if (!hit) { skipped++; continue; }                  // not in this event
    if (!wants(p.notify_prefs, "events", "events")) { skipped++; continue; }
    const r = await sendTo([p.id], {
      title: "Įrašytas į renginį: " + evName,
      body: [when, d.venue || d.location, [...new Set(hit)].join(", "), "įrašė " + name(me)].filter(Boolean).join(" · "),
      tag: "ev-" + row.id, url: `./?event=${encodeURIComponent(row.id)}`, kind: "event",
    });
    sent += r.sent;
  }
  return { sent, skipped };
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
      let ir: unknown = null, tt: unknown = null;
      try { ir = await invoiceReminders(); } catch (e) { ir = { error: String(e) }; }   // before invoices.sql the table is missing
      try { tt = await trackerReminders(); } catch (e) { tt = { error: String(e) }; }   // before tracker.sql the tables are missing
      if (new Date().getUTCMinutes() < 5) await db(`user_notifications?created_at=lt.${new Date(Date.now() - 30 * 86400000).toISOString()}`, { method: "DELETE" }).catch(() => {});
      return json({ ...tr, inv: ir, tracker: tt });
    }
    // a new member signed up (called by user-access with the cron secret): every admin is told
    if (body?.mode === "new-user") {
      const secret = Deno.env.get("CRON_SECRET");
      if (!secret || req.headers.get("x-cron-secret") !== secret) return json({ error: "Unauthorized" }, 401);
      return json(await onNewUser(String(body.user_id ?? "")));
    }
    // meetings with guests (called by the "guest" function with the cron secret)
    if (["guest-rsvp", "guest-message", "guest-call", "meeting-summary"].includes(body?.mode)) {
      const secret = Deno.env.get("CRON_SECRET");
      if (!secret || req.headers.get("x-cron-secret") !== secret) return json({ error: "Unauthorized" }, 401);
      if (body.mode === "guest-rsvp") return json(await onGuestRsvp(String(body.guest_id ?? "")));
      if (body.mode === "guest-message") return json(await onGuestMessage(String(body.message_id ?? "")));
      if (body.mode === "guest-call") return json(await onGuestCall(String(body.call_id ?? ""), String(body.guest_id ?? "")));
      return json(await onMeetingSummary(String(body.meeting_id ?? "")));
    }
    // new work letters (called by the "mail" function with the cron secret): only the mailbox's owner
    if (body?.mode === "mail-new") {
      const secret = Deno.env.get("CRON_SECRET");
      if (!secret || req.headers.get("x-cron-secret") !== secret) return json({ error: "Unauthorized" }, 401);
      return json(await onMailNew(String(body.user_id ?? ""), Array.isArray(body.items) ? body.items : []));
    }
        if (body?.mode === "invoice-reply") {
      const secret = Deno.env.get("CRON_SECRET");
      if (!secret || req.headers.get("x-cron-secret") !== secret) return json({ error: "Unauthorized" }, 401);
      return json(await onInvoiceReply(String(body.invoice_id ?? "")));
    }
    const uid = await caller(req);
    if (!uid) return json({ error: "Reikia prisijungti." }, 401);
    if (body.kind === "game") return json(await onGameInvite(uid, Array.isArray(body.to) ? body.to : [], String(body.game ?? "Žaidimas").slice(0, 60), String(body.room ?? "").slice(0, 40)));
    if (body.kind === "mail-test") return json(await onMailTest(uid));
    if (body.kind === "tracker-pin") return json(await onTrackerPin(String(body.member_id ?? "")));
    if (body.kind === "task") return json(await onTask(uid, String(body.task_id ?? ""), ["new", "done", "undone"].includes(body.event) ? body.event : "new"));
    if (body.kind === "invoice") return json(await onInvoice(uid, String(body.invoice_id ?? ""), body.event === "new" ? "new" : "decided"));
    if (body.kind === "feedback") return json(await onFeedback(uid, String(body.feedback_id ?? ""), body.event === "new" ? "new" : "resolved"));
    if (body.kind === "leave") return json(await onLeave(uid, String(body.leave_id ?? ""), ["new", "decided", "cancelled"].includes(body.event) ? body.event : "new"));
    if (body.kind === "event") return json(await onEvent(uid, String(body.event_id ?? ""), Array.isArray(body.users) ? body.users : []));
    if (body.kind === "vehicle_rm") return json(await onVehicleRm(uid, String(body.removal_id ?? ""), body.event === "request" ? "request" : "decided"));
    if (body.kind === "gear") return json(await onGear(uid, String(body.gear_id ?? ""), ["new", "fixed", "found", "wo_request", "wo_approved", "wo_rejected"].includes(body.event) ? body.event : "new"));
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
