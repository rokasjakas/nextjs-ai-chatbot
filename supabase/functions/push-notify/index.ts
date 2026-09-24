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
// POST {"kind":"test"}                   -> the caller's own devices
//
// Secrets: VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY (from `npx web-push
// generate-vapid-keys`), VAPID_SUBJECT (optional, mailto: address).
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.

import * as webpush from "jsr:@negrel/webpush@0.3.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const APPROVED = ["admin", "office", "tech", "freelance", "runner"];
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
  muted?: string[];
  quiet?: { on?: boolean; from?: string; to?: string };
};
type Sub = { endpoint: string; user_id: string; p256dh: string; auth: string };
type Payload = { title: string; body: string; tag: string; url: string };

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
export function wants(p: Prefs | null, kind: "general" | "direct" | "group" | "reactions", convId: string): boolean {
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

async function sendTo(userIds: string[], payload: Payload): Promise<{ sent: number; gone: number }> {
  if (!userIds.length) return { sent: 0, gone: 0 };
  const subs = await db<Sub[]>(`push_subscriptions?select=*&user_id=in.${inList(userIds)}`);
  const as = await server();
  let sent = 0, gone = 0;
  await Promise.all(subs.map(async (s) => {
    try {
      await as.subscribe({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } })
        .pushTextMessage(JSON.stringify(payload), { ttl: 86400, topic: payload.tag.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 32) || undefined });
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

async function onMessage(uid: string, messageId: string) {
  const [m] = await db<{ id: string; conversation_id: string; sender_id: string; body: string; attachments: unknown[]; deleted_at: string | null }[]>(
    `messages?select=*&id=eq.${encodeURIComponent(messageId)}`,
  );
  if (!m || m.sender_id !== uid || m.deleted_at) return { sent: 0, skipped: "not your message" };
  const [c] = await db<{ id: string; kind: "general" | "direct" | "group"; title: string | null }[]>(
    `conversations?select=id,kind,title&id=eq.${m.conversation_id}`,
  );
  if (!c) return { sent: 0 };
  const users = await chatUsers();
  const byId = new Map(users.map((u) => [u.id, u]));
  let recipients: Profile[];
  if (c.kind === "general") recipients = users;
  else {
    const members = await db<{ user_id: string }[]>(`conversation_members?select=user_id&conversation_id=eq.${c.id}`);
    recipients = members.map((x) => byId.get(x.user_id)).filter(Boolean) as Profile[];
  }
  const sender = byId.get(uid);
  const to = recipients.filter((r) => r.id !== uid && wants(r.notify_prefs, c.kind, c.id)).map((r) => r.id);
  const text = preview(m);
  const payload: Payload = c.kind === "direct"
    ? { title: name(sender), body: text, tag: c.id, url: `./?chat=${c.id}` }
    : { title: c.kind === "general" ? "Bendras chatas" : (c.title || "Grupė"), body: `${name(sender)}: ${text}`, tag: c.id, url: `./?chat=${c.id}` };
  return await sendTo(to, payload);
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
    body: preview(m) || "į tavo žinutę",
    tag: `rx-${messageId}`,
    url: `./?chat=${m.conversation_id}`,
  });
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
    if (body.kind === "reaction") return json(await onReaction(uid, String(body.message_id ?? ""), String(body.emoji ?? "").slice(0, 16)));
    if (body.kind === "test") {
      return json(await sendTo([uid], { title: "EventSolutions App", body: "Pranešimai veikia 🎉", tag: "test", url: "./" }));
    }
    return json({ error: "Unknown kind" }, 400);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    return json({ error: "Nepavyko išsiųsti pranešimų." }, 500);
  }
});
