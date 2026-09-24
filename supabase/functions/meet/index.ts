// Supabase Edge Function: meet
//
// Creates Google Meet meetings for video calls in the chat, using one Google
// account that an administrator connects once (Admin → Vaizdo skambučiai).
//
// POST {"action":"status"}            (admin)  -> { configured, connected, email }
// POST {"action":"connect","origin"}  (admin)  -> { url } Google consent page
// GET  ?code=…&state=…                (Google redirects here after consent)
//      stores the refresh token (encrypted) and sends the browser back to
//      the app with ?google=ok or ?google=error&msg=…
// POST {"action":"disconnect"}        (admin)  -> { ok }
// POST {"action":"create"}            (any approved member who uses the chat)
//      -> { url: "https://meet.google.com/abc-defg-hij" }
//      or { error, code: "not_connected" } when no account is connected yet
//
// Deploy WITHOUT the JWT check (Google's redirect carries no token):
//   supabase functions deploy meet --no-verify-jwt
// Every POST checks the caller's token itself.
//
// Secrets: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET (Google Cloud → OAuth client,
// type "Web application", redirect URI = this function's URL),
// MEET_SECRET (optional; falls back to MAIL_SECRET) for encrypting the token.
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const APPROVED = ["admin", "pm", "office", "tech", "freelance", "runner"];
const SCOPE = "https://www.googleapis.com/auth/meetings.space.created openid email";
export const VERSION = 1;

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
const secret = () => Deno.env.get("MEET_SECRET") || env("MAIL_SECRET");
const selfUrl = () => `${env("SUPABASE_URL").replace(/\/$/, "")}/functions/v1/meet`;

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

type Who = { id: string; role: string; canChat: boolean };
async function caller(req: Request): Promise<Who | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const res = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, {
    headers: { apikey: env("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  const u = await res.json();
  if (!u?.id) return null;
  const [p] = await db<{ role: string }[]>(`profiles?select=role&id=eq.${u.id}`);
  const role = p?.role ?? "pending";
  let canChat = role === "admin";
  if (!canChat && APPROVED.includes(role)) {
    const perms = await db<{ can_view: boolean; can_edit: boolean }[]>(
      `role_permissions?select=can_view,can_edit&section=eq.chat&role=eq.${role}`,
    );
    canChat = !perms.length || perms.some((x) => x.can_view || x.can_edit);
  }
  return { id: u.id, role, canChat };
}

// ---------- encryption (AES-GCM) and signed state ----------
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64u = (b: Uint8Array) => b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s: string) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
async function aesKey() {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("meet:" + secret()));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
export async function encrypt(plain: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(), new TextEncoder().encode(plain)));
  const out = new Uint8Array(iv.length + ct.length); out.set(iv); out.set(ct, iv.length);
  return b64(out);
}
export async function decrypt(enc: string): Promise<string> {
  const b = unb64(enc);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.subarray(0, 12) }, await aesKey(), b.subarray(12));
  return new TextDecoder().decode(pt);
}
async function hmac(data: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode("meet-state:" + secret()), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data))));
}
// state = base64url(json{uid, origin, exp}).signature
export async function makeState(uid: string, origin: string, now = Date.now()): Promise<string> {
  const body = b64u(new TextEncoder().encode(JSON.stringify({ uid, origin, exp: now + 15 * 60e3 })));
  return body + "." + await hmac(body);
}
export async function readState(state: string, now = Date.now()): Promise<{ uid: string; origin: string } | null> {
  const [body, sig] = String(state || "").split(".");
  if (!body || !sig || await hmac(body) !== sig) return null;
  try {
    const s = JSON.parse(new TextDecoder().decode(unb64u(body)));
    if (!s.uid || !s.origin || !(s.exp > now)) return null;
    return { uid: s.uid, origin: s.origin };
  } catch { return null; }
}
export function cleanOrigin(o: string): string {
  try {
    const u = new URL(String(o || ""));
    if (u.protocol !== "https:" && !(u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1"))) return "";
    return u.origin + u.pathname.replace(/[^/]*$/, "");
  } catch { return ""; }
}

// ---------- Google ----------
async function google(url: string, init: RequestInit): Promise<Record<string, unknown>> {
  const res = await fetch(url, init);
  const text = await res.text();
  let j: Record<string, unknown> = {};
  try { j = text ? JSON.parse(text) : {}; } catch { j = { raw: text.slice(0, 300) }; }
  if (!res.ok) {
    const e = j.error as Record<string, unknown> | string | undefined;
    const msg = typeof e === "string" ? `${e}${j.error_description ? ": " + j.error_description : ""}` : (e?.message as string) || `HTTP ${res.status}`;
    const err = new Error(msg) as Error & { status?: number; code?: string };
    err.status = res.status; err.code = typeof e === "string" ? e : (e?.status as string);
    throw err;
  }
  return j;
}
function form(o: Record<string, string>) {
  return { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(o).toString() };
}
export function consentUrl(state: string): string {
  const q = new URLSearchParams({
    client_id: env("GOOGLE_CLIENT_ID"), redirect_uri: selfUrl(), response_type: "code", scope: SCOPE,
    access_type: "offline", prompt: "consent", include_granted_scopes: "true", state,
  });
  return "https://accounts.google.com/o/oauth2/v2/auth?" + q.toString();
}
function emailFromIdToken(idt: unknown): string {
  try { return JSON.parse(new TextDecoder().decode(unb64u(String(idt).split(".")[1]))).email || ""; } catch { return ""; }
}
// the access token is kept for its lifetime, but only for the account that is
// still connected (disconnecting or reconnecting drops it at once)
let cached: { token: string; exp: number; key: string } | null = null;
async function accessToken(): Promise<string | null> {
  const [row] = await db<{ refresh_token: string; connected_at: string }[]>("google_meet_auth?select=refresh_token,connected_at&id=eq.1");
  if (!row) { cached = null; return null; }
  if (cached && cached.key === row.connected_at && cached.exp > Date.now() + 60e3) return cached.token;
  const j = await google("https://oauth2.googleapis.com/token", form({
    grant_type: "refresh_token", refresh_token: await decrypt(row.refresh_token),
    client_id: env("GOOGLE_CLIENT_ID"), client_secret: env("GOOGLE_CLIENT_SECRET"),
  }));
  cached = { token: String(j.access_token), exp: Date.now() + Number(j.expires_in || 3000) * 1000, key: row.connected_at };
  return cached.token;
}
export async function createSpace(token: string): Promise<string> {
  const call = (body: unknown) => google("https://meet.googleapis.com/v2/spaces", {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  let j: Record<string, unknown>;
  try {
    // anyone with the link joins without waiting to be let in
    j = await call({ config: { accessType: "OPEN", entryPointAccess: "ALL" } });
  } catch (e) {
    if ((e as { status?: number }).status !== 400) throw e;
    j = await call({});            // some (personal) accounts do not allow these settings
  }
  const uri = String(j.meetingUri || "");
  if (!/^https:\/\/meet\.google\.com\/[a-z0-9-]+$/.test(uri)) throw new Error("Google negrąžino susitikimo nuorodos.");
  return uri;
}

// ---------- handlers ----------
async function onCallback(url: URL): Promise<Response> {
  const st = await readState(url.searchParams.get("state") || "");
  const back = (ok: boolean, msg = "") => {
    const to = new URL(st?.origin || "https://app.eventsolutions.lt/");
    to.searchParams.set("google", ok ? "ok" : "error");
    if (msg) to.searchParams.set("msg", msg.slice(0, 200));
    return new Response(null, { status: 302, headers: { Location: to.toString() } });
  };
  if (!st) return back(false, "Nuoroda nebegalioja — bandyk prijungti dar kartą.");
  if (url.searchParams.get("error")) return back(false, url.searchParams.get("error") === "access_denied" ? "Prijungimas atšauktas." : String(url.searchParams.get("error")));
  const [p] = await db<{ role: string }[]>(`profiles?select=role&id=eq.${st.uid}`);
  if (p?.role !== "admin") return back(false, "Prijungti gali tik administratorius.");
  try {
    const j = await google("https://oauth2.googleapis.com/token", form({
      grant_type: "authorization_code", code: url.searchParams.get("code") || "", redirect_uri: selfUrl(),
      client_id: env("GOOGLE_CLIENT_ID"), client_secret: env("GOOGLE_CLIENT_SECRET"),
    }));
    if (!j.refresh_token) return back(false, "Google negrąžino ilgalaikio rakto. Atjunk programą Google paskyroje (myaccount.google.com → Saugumas → Trečiųjų šalių programos) ir bandyk vėl.");
    const email = emailFromIdToken(j.id_token);
    const at = new Date().toISOString();
    await db("google_meet_auth?on_conflict=id", {
      method: "POST", headers: { Prefer: "resolution=merge-duplicates" },
      body: JSON.stringify({ id: 1, refresh_token: await encrypt(String(j.refresh_token)), email, connected_by: st.uid, connected_at: at }),
    });
    cached = { token: String(j.access_token), exp: Date.now() + Number(j.expires_in || 3000) * 1000, key: at };
    return back(true, email);
  } catch (e) {
    return back(false, (e as Error).message);
  }
}

export async function handle(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const url = new URL(req.url);
    if (req.method === "GET") {
      if (url.searchParams.has("state")) return await onCallback(url);
      return json({ ok: true, version: VERSION });
    }
    if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
    const who = await caller(req);
    if (!who || !APPROVED.includes(who.role)) return json({ error: "Reikia prisijungti." }, 401);
    const body = await req.json().catch(() => ({}));
    const configured = !!(Deno.env.get("GOOGLE_CLIENT_ID") && Deno.env.get("GOOGLE_CLIENT_SECRET"));
    const admin = who.role === "admin";
    if (body.action === "status") {
      if (!admin) return json({ error: "Tik administratoriui." }, 403);
      const [row] = await db<{ email: string; connected_at: string }[]>("google_meet_auth?select=email,connected_at&id=eq.1");
      return json({ version: VERSION, configured, connected: !!row, email: row?.email ?? "", connected_at: row?.connected_at ?? null, redirect_uri: selfUrl() });
    }
    if (body.action === "connect") {
      if (!admin) return json({ error: "Tik administratoriui." }, 403);
      if (!configured) return json({ error: "Serveryje nenustatyti GOOGLE_CLIENT_ID ir GOOGLE_CLIENT_SECRET." }, 400);
      const origin = cleanOrigin(body.origin);
      if (!origin) return json({ error: "Neteisingas programos adresas." }, 400);
      return json({ url: consentUrl(await makeState(who.id, origin)) });
    }
    if (body.action === "disconnect") {
      if (!admin) return json({ error: "Tik administratoriui." }, 403);
      await db("google_meet_auth?id=eq.1", { method: "DELETE" });
      cached = null;
      return json({ ok: true });
    }
    if (body.action === "create") {
      if (!who.canChat) return json({ error: "Nėra prieigos prie chato." }, 403);
      if (!configured) return json({ error: "Google Meet neprijungtas.", code: "not_connected" });
      try {
        const token = await accessToken();
        if (!token) return json({ error: "Google Meet neprijungtas.", code: "not_connected" });
        return json({ url: await createSpace(token) });
      } catch (e) {
        const err = e as Error & { code?: string };
        if (err.code === "invalid_grant") {
          cached = null;
          return json({ error: "Google paskyros prieiga nebegalioja — administratorius turi ją prijungti iš naujo.", code: "not_connected" });
        }
        return json({ error: "Google Meet: " + err.message });
      }
    }
    return json({ error: "Nežinomas veiksmas." }, 400);
  } catch (e) {
    console.error(e);
    return json({ error: (e as Error).message }, 500);
  }
}

if (import.meta.main) Deno.serve(handle);
