// EventSolutions App — failai Cloudflare R2 saugykloje.
//
// The app keeps its file paths exactly as before (chat-files/<conversation>/…,
// equipment-photos/rentals/<id>/…, avatars/<user>/…, venue-photos/…,
// job-files/…). New files go to R2; files uploaded earlier stay in Supabase
// Storage and keep working (the app asks here first, and signs the rest there).
// Who may read / write / delete is decided by the same database rules as the
// Supabase buckets, asked with the caller's own login.
//
// GET                                         -> { r2: true|false }
// POST {action:"put", bucket, path, type}     -> { url }          upload with PUT
// POST {action:"urls", bucket, paths, download?} -> { urls: {path: url|null} }
//        null = not in R2 (an older file: sign it in Supabase)
// POST {action:"remove", bucket, paths}       -> { removed }
// POST {action:"list", bucket, prefix}        -> { names }        (one folder)
//
// Secrets: R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET
// (Cloudflare → R2 → Manage API tokens: Object Read & Write for the bucket).
import { sha256 } from "npm:@noble/hashes@1.4.0/sha256";
import { hmac } from "npm:@noble/hashes@1.4.0/hmac";

const VERSION = 2;
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
const env = (k: string) => (Deno.env.get(k) ?? "").trim();
class UserError extends Error {}

// ---------- S3 signature (v4) for R2 ----------
const enc = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const rfc3986 = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
const encPath = (key: string) => key.split("/").map(rfc3986).join("/");
export function amzDate(d = new Date()) {
  const full = d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  return { full, day: full.slice(0, 8) };
}
// a presigned URL (query-string authentication); `uri` is already encoded
export function presignUrl(o: {
  method: string; host: string; uri: string; region: string; accessKey: string; secret: string;
  expires: number; query?: Record<string, string>; headers?: Record<string, string>; date?: Date;
}): string {
  const { full, day } = amzDate(o.date);
  const scope = `${day}/${o.region}/s3/aws4_request`;
  const headers: Record<string, string> = { host: o.host };
  for (const [k, v] of Object.entries(o.headers ?? {})) headers[k.toLowerCase()] = v;
  const names = Object.keys(headers).sort();
  const q: Record<string, string> = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": `${o.accessKey}/${scope}`, "X-Amz-Date": full,
    "X-Amz-Expires": String(o.expires), "X-Amz-SignedHeaders": names.join(";"), ...(o.query ?? {}),
  };
  const qs = Object.keys(q).sort().map((k) => rfc3986(k) + "=" + rfc3986(q[k])).join("&");
  const canonical = [o.method, o.uri, qs, names.map((n) => n + ":" + headers[n].trim()).join("\n") + "\n", names.join(";"), "UNSIGNED-PAYLOAD"].join("\n");
  const sts = ["AWS4-HMAC-SHA256", full, scope, hex(sha256(enc.encode(canonical)))].join("\n");
  let k = hmac(sha256, enc.encode("AWS4" + o.secret), enc.encode(day));
  for (const part of [o.region, "s3", "aws4_request"]) k = hmac(sha256, k, enc.encode(part));
  return `https://${o.host}${o.uri}?${qs}&X-Amz-Signature=${hex(hmac(sha256, k, enc.encode(sts)))}`;
}
const r2On = () => !!(env("R2_ACCOUNT_ID") && env("R2_ACCESS_KEY_ID") && env("R2_SECRET_ACCESS_KEY") && env("R2_BUCKET"));
function r2Url(method: string, key: string, expires: number, query: Record<string, string> = {}, headers: Record<string, string> = {}) {
  const bucket = env("R2_BUCKET");
  return presignUrl({
    method, host: `${env("R2_ACCOUNT_ID")}.r2.cloudflarestorage.com`, uri: "/" + rfc3986(bucket) + (key ? "/" + encPath(key) : ""),
    region: "auto", accessKey: env("R2_ACCESS_KEY_ID"), secret: env("R2_SECRET_ACCESS_KEY"), expires, query, headers,
  });
}

// ---------- who may do what (the same rules as the Supabase buckets) ----------
const BUCKETS = ["chat-files", "equipment-photos", "avatars", "venue-photos", "job-files"];
type Op = "read" | "write" | "delete";
type Caller = { uid: string; token: string; apikey: string };
async function rpc(c: Caller, fn: string, args: Record<string, unknown> = {}): Promise<boolean> {
  const res = await fetch(`${env("SUPABASE_URL")}/rest/v1/rpc/${fn}`, {
    method: "POST", headers: { apikey: c.apikey, Authorization: `Bearer ${c.token}`, "Content-Type": "application/json" }, body: JSON.stringify(args),
  });
  if (!res.ok) return false;
  return (await res.json()) === true;
}
async function convOwner(c: Caller, cid: string): Promise<string | null> {
  const res = await fetch(`${env("SUPABASE_URL")}/rest/v1/conversations?select=created_by&id=eq.${encodeURIComponent(cid)}`, {
    headers: { apikey: c.apikey, Authorization: `Bearer ${c.token}` },
  });
  if (!res.ok) return null;
  const [row] = await res.json();
  return row?.created_by ?? null;
}
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
async function allowed(c: Caller, bucket: string, path: string, op: Op, cache: Map<string, boolean>): Promise<boolean> {
  if (!BUCKETS.includes(bucket) || !path || path.includes("..") || path.startsWith("/") || path.length > 400) return false;
  const first = path.split("/")[0];
  const key = bucket + "|" + op + "|" + (bucket === "equipment-photos" ? path.split("/").slice(0, 2).join("/") : first);
  if (cache.has(key)) return cache.get(key)!;
  let ok = false;
  switch (bucket) {
    case "avatars": ok = op === "read" ? await rpc(c, "is_approved") : first === c.uid; break;
    case "chat-files":
      if (!UUID.test(first)) break;
      if (op === "delete") ok = (await convOwner(c, first)) === c.uid || await rpc(c, "is_admin");
      else ok = await rpc(c, "is_conv_member", { cid: first });
      break;
    case "equipment-photos": ok = await rpc(c, "equipment_photo_access", { obj_name: path, edit: op !== "read" }); break;
    case "venue-photos": ok = await rpc(c, op === "read" ? "can_view" : "can_edit", { sec: "venues" }); break;
    case "job-files": ok = op === "read" ? await rpc(c, "can_view", { sec: "jobs" }) : (await rpc(c, "can_edit", { sec: "offers" })) || (await rpc(c, "can_edit", { sec: "jobs" })); break;
  }
  cache.set(key, ok);
  return ok;
}
async function caller(req: Request): Promise<Caller | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  const apikey = req.headers.get("apikey") || env("SUPABASE_ANON_KEY");
  if (!token || /^bearer$/i.test(token) || token.split(".").length !== 3) return null;
  const res = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, { headers: { apikey, Authorization: `Bearer ${token}` } });
  if (!res.ok) return null;
  const u = await res.json();
  return u?.id ? { uid: u.id, token, apikey } : null;
}

// ---------- actions ----------
const safeName = (s: string) => String(s || "failas").replace(/[\r\n"\\]/g, "").slice(0, 150);
async function handle(c: Caller, b: Record<string, unknown>) {
  const bucket = String(b.bucket ?? "");
  const cache = new Map<string, boolean>();
  switch (b.action) {
    case "put": {
      const path = String(b.path ?? "");
      if (!(await allowed(c, bucket, path, "write", cache))) throw new UserError("Nėra teisės įkelti šio failo.");
      const type = String(b.type || "application/octet-stream").slice(0, 120);
      return { url: r2Url("PUT", bucket + "/" + path, 900, {}, { "content-type": type }), type };
    }
    case "urls": {
      const paths = (Array.isArray(b.paths) ? b.paths : []).map(String).slice(0, 200);
      const download = b.download === undefined ? null : String(b.download || "");
      const urls: Record<string, string | null> = {};
      await Promise.all(paths.map(async (p) => {
        if (!(await allowed(c, bucket, p, "read", cache))) { urls[p] = null; return; }
        const head = await fetch(r2Url("HEAD", bucket + "/" + p, 60), { method: "HEAD" }).catch(() => null);
        if (!head || !head.ok) { urls[p] = null; return; }
        const q: Record<string, string> = download !== null
          ? { "response-content-disposition": `attachment; filename="${safeName(download || p.split("/").pop()!)}"; filename*=UTF-8''${rfc3986(download || p.split("/").pop()!)}` }
          : {};
        urls[p] = r2Url("GET", bucket + "/" + p, 3600, q);
      }));
      return { urls };
    }
    case "remove": {
      const paths = (Array.isArray(b.paths) ? b.paths : []).map(String).slice(0, 500);
      let removed = 0;
      await Promise.all(paths.map(async (p) => {
        if (!(await allowed(c, bucket, p, "delete", cache))) return;
        const r = await fetch(r2Url("DELETE", bucket + "/" + p, 60), { method: "DELETE" }).catch(() => null);
        if (r && (r.ok || r.status === 404)) removed++;
        await r?.body?.cancel().catch(() => {});
      }));
      return { removed };
    }
    case "list": {
      const prefix = String(b.prefix ?? "").replace(/\/+$/, "");
      if (!(await allowed(c, bucket, prefix + "/x", "read", cache))) throw new UserError("Nėra teisės.");
      const res = await fetch(r2Url("GET", "", 60, { "list-type": "2", prefix: bucket + "/" + prefix + "/", "max-keys": "1000" }));
      const xml = await res.text();
      if (!res.ok) throw new Error("R2 list " + res.status + ": " + xml.slice(0, 200));
      const names = [...xml.matchAll(/<Key>([^<]+)<\/Key>/g)].map((m) => m[1].replace(/&amp;/g, "&").slice((bucket + "/" + prefix + "/").length));
      return { names };
    }
  }
  if (b.action === "check") {
    // the server tries R2 itself (no browser, no CORS): shows whether the
    // keys and the bucket are right
    const key = "_check/" + c.uid + ".txt";
    const out: string[] = [];
    const put = await fetch(r2Url("PUT", key, 60, {}, { "content-type": "text/plain" }), { method: "PUT", headers: { "Content-Type": "text/plain" }, body: "ok" }).catch((e) => ({ ok: false, status: 0, text: () => Promise.resolve(String(e)) } as unknown as Response));
    out.push("įrašymas: " + (put.ok ? "OK" : put.status + " " + (await put.text()).replace(/\s+/g, " ").slice(0, 160)));
    if (put.ok) {
      const get = await fetch(r2Url("GET", key, 60));
      out.push("skaitymas: " + (get.ok ? "OK" : get.status));
      await get.body?.cancel().catch(() => {});
      const cors = await fetch(r2Url("GET", key, 60), { method: "OPTIONS", headers: { Origin: String(b.origin || "https://app.eventsolutions.lt"), "Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "content-type" } });
      out.push("CORS " + String(b.origin || "") + ": " + (cors.headers.get("access-control-allow-origin") ? "OK" : "NĖRA (" + cors.status + ")"));
      await cors.body?.cancel().catch(() => {});
      await fetch(r2Url("DELETE", key, 60), { method: "DELETE" }).then((r) => r.body?.cancel()).catch(() => {});
    }
    out.push("bucket: " + env("R2_BUCKET") + " · account: " + env("R2_ACCOUNT_ID").slice(0, 6) + "…");
    return { check: out };
  }
  throw new UserError("Nežinomas veiksmas.");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    if (req.method === "GET") return json({ v: VERSION, r2: r2On() });
    if (!r2On()) return json({ v: VERSION, r2: false, error: "R2 neprijungtas." }, 400);
    const c = await caller(req);
    if (!c) return json({ error: "Reikia prisijungti." }, 401);
    const body = await req.json().catch(() => ({}));
    return json({ v: VERSION, ...(await handle(c, body)) });
  } catch (e) {
    if (e instanceof UserError) return json({ error: e.message }, 400);
    console.error(e instanceof Error ? e.stack || e.message : e);
    return json({ error: "Failų klaida: " + (e instanceof Error ? e.message : String(e)).slice(0, 200) }, 500);
  }
});
