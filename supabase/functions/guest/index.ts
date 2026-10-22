// Supabase Edge Function: guest
//
// The page of a person from outside who was invited to a meeting by e-mail
// (app …/?svecias=<key>). The key from the invitation is the only pass: it
// opens this one meeting and nothing else, and stops working 7 days after the
// meeting (or when the person is taken off the list / the meeting is cancelled).
//
// POST { token, action:"info" }                      -> meeting, the guest, notes, whether a call is on
// POST { token, action:"rsvp", answer:"yes"|"no", name? }   the organizer is told
// POST { token, action:"name", name }
// Online meeting only (its chat "🤝 <title>"):
// POST { token, action:"messages", since? }          -> { messages }
// POST { token, action:"send", body, attachments? }  members are told
// POST { token, action:"put", name, type, size }     -> { url, type, path }   upload with PUT
// POST { token, action:"url", path, download? }      -> { url }  a file of this meeting's chat
// POST { token, action:"notes", notes }              shared notes (go out with the summary)
// POST { token, action:"call" }                      -> { url, token, call_id, media }  joins the call
//      going on (or starts one; the members are told)
//
// Deploy WITHOUT the JWT check (guests have no login):
//   supabase functions deploy guest --no-verify-jwt
// Secrets: DAILY_API_KEY, CRON_SECRET (to ask push-notify), R2_* (files, as in "files");
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.
import { sha256 } from "npm:@noble/hashes@1.4.0/sha256";
import { hmac } from "npm:@noble/hashes@1.4.0/hmac";

export const VERSION = 1;
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" } });
class UserError extends Error {}
function env(name: string): string {
  const v = (Deno.env.get(name) ?? "").trim();
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
// ask push-notify to tell the members (never fails the guest's action)
async function notify(body: Record<string, unknown>) {
  try {
    const res = await fetch(`${env("SUPABASE_URL")}/functions/v1/push-notify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-cron-secret": env("CRON_SECRET"), Authorization: `Bearer ${env("SUPABASE_SERVICE_ROLE_KEY")}` },
      body: JSON.stringify(body),
    });
    await res.body?.cancel().catch(() => {});
  } catch (e) { console.error("notify", (e as Error).message); }
}

type Guest = { id: string; meeting_id: string; email: string; name: string | null; token: string; status: string; responded_at: string | null };
type Meeting = {
  id: string; title: string; meet_date: string; start_time: string | null; end_time: string | null; location: string; description: string;
  attendees: string[] | null; created_by: string; online: boolean; conversation_id: string | null; notes: string; summary_sent_at: string | null;
};
type Profile = { id: string; first_name: string | null; last_name: string | null; nickname: string | null; full_name?: string | null; email: string | null };
type Call = { id: string; conversation_id: string; created_by: string; meet_url: string; provider: string; room: string | null; media?: string; created_at: string; ended_at: string | null };
const pname = (p?: Profile) => !p ? "Narys" : [p.first_name, p.last_name].filter(Boolean).join(" ") || p.nickname || p.full_name || (p.email ?? "").split("@")[0] || "Narys";
export const guestName = (g: Pick<Guest, "name" | "email">) => (g.name || "").trim() || g.email.split("@")[0];
export const cleanName = (s: unknown) => String(s ?? "").replace(/[<>\u0000-\u001f]/g, "").replace(/\s+/g, " ").trim().slice(0, 60);
const DAY = 86400e3;
// the link works until a week after the meeting
export function expired(meetDate: string, now = Date.now()): boolean {
  const t = Date.parse(meetDate + "T23:59:59Z");
  return !isNaN(t) && now > t + 7 * DAY;
}

async function load(token: string): Promise<{ g: Guest; m: Meeting }> {
  if (!/^[0-9a-f]{64}$/.test(token)) throw new UserError("Nuoroda neteisinga.");
  const [g] = await db<Guest[]>(`meeting_guests?select=*&token=eq.${token}`);
  if (!g) throw new UserError("Nuoroda nebegalioja – susitikimas atšauktas arba tavęs nebėra kviestųjų sąraše.");
  const [m] = await db<Meeting[]>(`meetings?select=*&id=eq.${g.meeting_id}`);
  if (!m) throw new UserError("Susitikimas atšauktas.");
  if (expired(m.meet_date)) throw new UserError("Nuoroda nebegalioja – susitikimas jau praėjo.");
  return { g, m };
}
function room(m: Meeting): string {
  if (!m.online || !m.conversation_id) throw new UserError("Šis susitikimas vyksta ne internetu.");
  return m.conversation_id;
}

// ---------- files (the chat's bucket: Cloudflare R2, or Supabase Storage) ----------
const r2On = () => !!(Deno.env.get("R2_ACCOUNT_ID") && Deno.env.get("R2_ACCESS_KEY_ID") && Deno.env.get("R2_SECRET_ACCESS_KEY") && Deno.env.get("R2_BUCKET"));
const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const rfc3986 = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
export function r2Presign(method: string, key: string, expires: number, query: Record<string, string> = {}, headers: Record<string, string> = {}, date = new Date()): string {
  const host = `${env("R2_ACCOUNT_ID")}.r2.cloudflarestorage.com`, enc = new TextEncoder();
  const full = date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, ""), day = full.slice(0, 8);
  const scope = `${day}/auto/s3/aws4_request`;
  const uri = "/" + rfc3986(env("R2_BUCKET")) + "/" + key.split("/").map(rfc3986).join("/");
  const hs: Record<string, string> = { host };
  for (const [k, v] of Object.entries(headers)) hs[k.toLowerCase()] = v;
  const names = Object.keys(hs).sort();
  const q: Record<string, string> = { "X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": `${env("R2_ACCESS_KEY_ID")}/${scope}`, "X-Amz-Date": full, "X-Amz-Expires": String(expires), "X-Amz-SignedHeaders": names.join(";"), ...query };
  const qs = Object.keys(q).sort().map((k) => rfc3986(k) + "=" + rfc3986(q[k])).join("&");
  const canonical = [method, uri, qs, names.map((n) => n + ":" + hs[n].trim()).join("\n") + "\n", names.join(";"), "UNSIGNED-PAYLOAD"].join("\n");
  const sts = ["AWS4-HMAC-SHA256", full, scope, hexOf(sha256(enc.encode(canonical)))].join("\n");
  let k = hmac(sha256, enc.encode("AWS4" + env("R2_SECRET_ACCESS_KEY")), enc.encode(day));
  for (const part of ["auto", "s3", "aws4_request"]) k = hmac(sha256, k, enc.encode(part));
  return `https://${host}${uri}?${qs}&X-Amz-Signature=${hexOf(hmac(sha256, k, enc.encode(sts)))}`;
}
async function storage(path: string, body: unknown): Promise<Record<string, string> | null> {
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${env("SUPABASE_URL")}/storage/v1/${path}`, {
    method: "POST", headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body),
  }).catch(() => null);
  return res && res.ok ? await res.json().catch(() => null) : null;
}
const encKey = (p: string) => p.split("/").map(encodeURIComponent).join("/");
async function fileUrl(path: string, download: string | null): Promise<string> {
  if (r2On()) {
    const head = await fetch(r2Presign("HEAD", "chat-files/" + path, 60), { method: "HEAD" }).catch(() => null);
    await head?.body?.cancel().catch(() => {});
    if (head && head.ok) {
      return r2Presign("GET", "chat-files/" + path, 3600, download !== null ? { "response-content-disposition": `attachment; filename*=UTF-8''${rfc3986(download || path.split("/").pop()!)}` } : {});
    }
  }
  const j = await storage(`object/sign/chat-files/${encKey(path)}`, { expiresIn: 3600 });
  if (!j?.signedURL) throw new UserError("Failas nerastas.");
  return `${env("SUPABASE_URL")}/storage/v1${j.signedURL}${download !== null ? "&download=" + encodeURIComponent(download) : ""}`;
}

// ---------- Daily.co ----------
const DAILY_HOURS = 4;
async function daily(path: string, body: unknown): Promise<Record<string, unknown>> {
  const res = await fetch(`https://api.daily.co/v1/${path}`, {
    method: "POST", headers: { Authorization: `Bearer ${env("DAILY_API_KEY")}`, "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Daily ${res.status}: ${j.info || j.error || "klaida"}`);
  return j;
}
const live = (c: Call) => !c.ended_at && c.provider === "daily" && Date.now() - Date.parse(c.created_at) < DAILY_HOURS * 3600e3;
async function liveCall(cid: string): Promise<Call | null> {
  const since = new Date(Date.now() - DAILY_HOURS * 3600e3).toISOString();
  const rows = await db<Call[]>(`calls?select=*&conversation_id=eq.${cid}&ended_at=is.null&provider=eq.daily&created_at=gte.${encodeURIComponent(since)}&order=created_at.desc&limit=1`);
  return rows.find(live) ?? null;
}

// ---------- actions ----------
const PATH_OK = (cid: string, p: string) => p.startsWith(cid + "/") && !p.includes("..") && p.length < 300;
type Att = { type: string; path: string; name: string; size: number; mime: string };
async function handle(b: Record<string, unknown>) {
  const { g, m } = await load(String(b.token ?? ""));
  const me = "g-" + g.id;
  switch (b.action) {
    case "info": {
      await db(`meeting_guests?id=eq.${g.id}`, { method: "PATCH", body: JSON.stringify({ last_seen_at: new Date().toISOString() }) });
      const ids = [...new Set([m.created_by, ...(m.attendees ?? [])])];
      const people = await db<Profile[]>(`profiles?select=id,first_name,last_name,nickname,email&id=in.(${ids.join(",")})`);
      const byId = new Map(people.map((p) => [p.id, p]));
      const guests = await db<Guest[]>(`meeting_guests?select=id,email,name,status&meeting_id=eq.${m.id}&order=created_at.asc`);
      const call = m.online && m.conversation_id ? await liveCall(m.conversation_id) : null;
      return {
        guest: { id: me, name: guestName(g), named: !!(g.name || "").trim(), email: g.email, status: g.status },
        meeting: {
          title: m.title, meet_date: m.meet_date, start_time: m.start_time, end_time: m.end_time, location: m.location, description: m.description,
          online: !!m.online && !!m.conversation_id, notes: m.notes || "", uid: m.id,
          organizer: pname(byId.get(m.created_by)), organizer_email: byId.get(m.created_by)?.email || "",
          people: [...ids.map((u) => ({ name: pname(byId.get(u)), status: "member" })), ...guests.map((x) => ({ name: guestName(x), status: x.status, me: x.id === g.id }))],
        },
        call: call ? { id: call.id, media: call.media === "audio" ? "audio" : "video" } : null,
      };
    }
    case "rsvp": {
      const answer = b.answer === "no" ? "no" : "yes";
      const nm = cleanName(b.name);
      const patch: Record<string, unknown> = { status: answer, responded_at: new Date().toISOString() };
      if (nm) patch.name = nm;
      await db(`meeting_guests?id=eq.${g.id}`, { method: "PATCH", body: JSON.stringify(patch) });
      if (g.status !== answer) await notify({ mode: "guest-rsvp", guest_id: g.id });
      return { status: answer };
    }
    case "name": {
      const nm = cleanName(b.name);
      if (!nm) throw new UserError("Įrašyk vardą.");
      await db(`meeting_guests?id=eq.${g.id}`, { method: "PATCH", body: JSON.stringify({ name: nm }) });
      return { name: nm };
    }
    case "messages": {
      const cid = room(m);
      const since = typeof b.since === "string" && !isNaN(Date.parse(b.since)) ? b.since : "";
      type Row = { id: string; body: string; attachments: Att[] | null; created_at: string; sender_id: string; guest_id: string | null; guest_name: string | null };
      const rows = await db<Row[]>(`messages?select=id,body,attachments,created_at,sender_id,guest_id,guest_name&conversation_id=eq.${cid}&deleted_at=is.null&or=(parent_id.is.null,also_channel.is.true)`
        + (since ? `&created_at=gt.${encodeURIComponent(since)}&order=created_at.asc&limit=200` : "&order=created_at.desc&limit=200"));
      if (!since) rows.reverse();
      const senders = [...new Set(rows.filter((r) => !r.guest_id).map((r) => r.sender_id))];
      const mentioned = [...new Set(rows.flatMap((r) => [...String(r.body || "").matchAll(/<@([0-9a-f-]{36})>/g)].map((x) => x[1])))];
      const all = [...new Set([...senders, ...mentioned])];
      const profiles = all.length ? await db<Profile[]>(`profiles?select=id,first_name,last_name,nickname,email&id=in.(${all.join(",")})`) : [];
      const byId = new Map(profiles.map((p) => [p.id, p]));
      return {
        messages: rows.map((r) => ({
          id: r.id, created_at: r.created_at,
          body: String(r.body || "").replace(/<@([0-9a-f-]{36})>/g, (_x, id) => "@" + pname(byId.get(id))),
          attachments: (r.attachments ?? []).filter((a) => a && a.path).map((a) => ({ type: a.type, path: a.path, name: a.name || "failas", size: a.size || 0, mime: a.mime || "" })),
          who: r.guest_id ? (r.guest_name || "Svečias") : pname(byId.get(r.sender_id)),
          guest: !!r.guest_id, mine: r.guest_id === g.id, from: r.guest_id ? "g-" + r.guest_id : r.sender_id,
        })),
      };
    }
    case "send": {
      const cid = room(m);
      const body = String(b.body ?? "").slice(0, 4000).trim();
      const atts = (Array.isArray(b.attachments) ? b.attachments : []).slice(0, 10).map((a: Record<string, unknown>) => ({
        type: "file", path: String(a?.path ?? ""), name: String(a?.name ?? "failas").slice(0, 200), size: Number(a?.size) || 0, mime: String(a?.mime ?? "").slice(0, 120),
      })).filter((a) => PATH_OK(cid, a.path) && a.path.startsWith(cid + "/g-"));
      if (!body && !atts.length) throw new UserError("Tuščia žinutė.");
      const [row] = await db<{ id: string; created_at: string }[]>("messages", {
        method: "POST", headers: { Prefer: "return=representation" },
        body: JSON.stringify({ conversation_id: cid, sender_id: m.created_by, body, attachments: atts, guest_id: g.id, guest_name: guestName(g) }),
      });
      await notify({ mode: "guest-message", message_id: row.id });
      return { id: row.id, created_at: row.created_at };
    }
    case "put": {
      const cid = room(m);
      const size = Number(b.size) || 0;
      if (size > 200 * 1024 * 1024) throw new UserError("Failas per didelis (daugiausia 200 MB).");
      const ext = (String(b.name ?? "").match(/\.([A-Za-z0-9]{1,10})$/) || [])[1];
      const path = `${cid}/g-${crypto.randomUUID()}${ext ? "." + ext.toLowerCase() : ""}`;
      const type = String(b.type || "application/octet-stream").replace(/[\r\n]/g, "").slice(0, 120);
      if (r2On()) return { url: r2Presign("PUT", "chat-files/" + path, 900, {}, { "content-type": type }), type, path };
      const j = await storage(`object/upload/sign/chat-files/${encKey(path)}`, {});
      if (!j?.url) throw new Error("Nepavyko paruošti įkėlimo.");
      return { url: `${env("SUPABASE_URL")}/storage/v1${j.url}`, type, path };
    }
    case "url": {
      const cid = room(m);
      const path = String(b.path ?? "");
      if (!PATH_OK(cid, path)) throw new UserError("Failas nerastas.");
      return { url: await fileUrl(path, b.download === undefined ? null : String(b.download || "")) };
    }
    case "notes": {
      room(m);
      const notes = String(b.notes ?? "").slice(0, 20000);
      await db(`meetings?id=eq.${m.id}`, { method: "PATCH", body: JSON.stringify({ notes, updated_at: new Date().toISOString() }) });
      return { ok: true };
    }
    case "call": {
      const cid = room(m);
      if (!Deno.env.get("DAILY_API_KEY")) throw new UserError("Vaizdo skambučiai dar neįjungti.");
      let call = await liveCall(cid);
      if (!call) {
        const media = b.media === "audio" ? "audio" : "video";
        const r = await daily("rooms", {
          name: "es-" + crypto.randomUUID().replace(/-/g, "").slice(0, 16), privacy: "private",
          properties: { exp: Math.floor(Date.now() / 1000) + DAILY_HOURS * 3600, eject_at_room_exp: true, enable_prejoin_ui: false, enable_screenshare: true, enable_chat: false, enable_knocking: false, start_video_off: media === "audio" },
        });
        [call] = await db<Call[]>("calls", {
          method: "POST", headers: { Prefer: "return=representation" },
          body: JSON.stringify({ conversation_id: cid, created_by: m.created_by, provider: "daily", meet_url: r.url, room: r.name, media }),
        });
        await db("messages", { method: "POST", body: JSON.stringify({
          conversation_id: cid, sender_id: m.created_by, guest_id: g.id, guest_name: guestName(g),
          body: (media === "audio" ? "🎧 Garso" : "📹 Vaizdo") + " skambutis: " + r.url, attachments: [],
        }) });
        await notify({ mode: "guest-call", call_id: call!.id, guest_id: g.id });
      }
      const t = await daily("meeting-tokens", { properties: {
        room_name: call!.room, user_name: guestName(g) + " (svečias)", user_id: me, is_owner: false,
        exp: Math.floor(Date.parse(call!.created_at) / 1000) + DAILY_HOURS * 3600,
      } });
      return { call_id: call!.id, url: call!.meet_url, token: t.token, media: call!.media === "audio" ? "audio" : "video" };
    }
  }
  throw new UserError("Nežinomas veiksmas.");
}

export async function serve(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    if (req.method === "GET") return json({ ok: true, version: VERSION });
    if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
    const body = await req.json().catch(() => ({}));
    return json(await handle(body));
  } catch (e) {
    if (e instanceof UserError) return json({ error: e.message }, 400);
    console.error(e instanceof Error ? e.stack || e.message : e);
    return json({ error: "Klaida: " + (e instanceof Error ? e.message : String(e)).slice(0, 200) }, 500);
  }
}
if (import.meta.main) Deno.serve(serve);
