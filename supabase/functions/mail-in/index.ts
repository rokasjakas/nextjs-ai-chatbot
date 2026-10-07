// "mail-in": letters forwarded from the mail server arrive here at once.
//
// The mail server forwards every new letter of a member (e.g. rokas@eventsolutions.lt)
// to <same name>@<MAIL_IN_DOMAIN> (e.g. rokas@in.eventsolutions.lt). Cloudflare Email
// Routing hands it to a small Email Worker (cloudflare/mail-in-worker.js), which POSTs the
// raw letter here with the shared secret. The letter is parsed and kept:
//   * mail_in            – the text (html / plain), who, when, the list of attachments
//   * storage "mail-in"  – <user>/<letter>/<file> – the attachments
// The app opens an inbox letter from here first (no waiting for the mail server),
// so even a big letter opens at once.
//
// Secrets: MAIL_IN_SECRET (the same value in the Cloudflare worker). Deploy:
//   supabase functions deploy mail-in --no-verify-jwt
import PostalMime from "npm:postal-mime@2.4.4";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const SECRET = Deno.env.get("MAIL_IN_SECRET") || "";
const BUCKET = "mail-in";
const KEEP_DAYS = 120;
const MAX_INLINE = 400_000, MAX_INLINE_TOTAL = 2_000_000, MAX_HTML = 3_000_000;

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const hdr = (extra: Record<string, string> = {}) => ({ apikey: SERVICE_KEY, Authorization: "Bearer " + SERVICE_KEY, ...extra });

async function db(path: string, init: RequestInit = {}) {
  const r = await fetch(SUPABASE_URL + "/rest/v1/" + path, { ...init, headers: hdr({ "Content-Type": "application/json", ...(init.headers as Record<string, string> || {}) }) });
  const t = await r.text();
  if (!r.ok) throw new Error(`db ${r.status}: ${t.slice(0, 300)}`);
  return t ? JSON.parse(t) : null;
}
async function put(path: string, data: Uint8Array | ArrayBuffer, type: string) {
  const r = await fetch(`${SUPABASE_URL}/storage/v1/object/${BUCKET}/${path}`, { method: "POST", headers: hdr({ "Content-Type": type || "application/octet-stream", "x-upsert": "true" }), body: data });
  if (!r.ok) throw new Error(`storage ${r.status}: ${(await r.text()).slice(0, 200)}`);
}
function timingSafeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return x === 0;
}
const addrs = (l?: { name?: string; address?: string; group?: { name?: string; address?: string }[] }[]) =>
  (l ?? []).flatMap((x) => x.group ? x.group : [x]).map((x) => ({ name: x.name || "", address: (x.address || "").toLowerCase() })).filter((x) => x.address);
const safeName = (n: string) => (n || "priedas").replace(/[\\/\u0000-\u001f]+/g, "_").replace(/^\.+/, "").slice(0, 120) || "priedas";
const b64 = (u: Uint8Array) => { let s = ""; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s); };

// whose letter: the local part of the address it was forwarded to = the member's mailbox name
async function userFor(rcpt: string[]): Promise<{ user_id: string; email: string } | null> {
  for (const r of rcpt) {
    const local = (r || "").toLowerCase().split("@")[0].replace(/\+.*$/, "");
    if (!local || !/^[a-z0-9._-]+$/.test(local)) continue;
    const rows = await db(`mail_accounts?select=user_id,email&email=ilike.${encodeURIComponent(local + "@*")}`) as { user_id: string; email: string }[];
    const exact = (rows || []).find((x) => x.email.toLowerCase().split("@")[0] === local);
    if (exact) return exact;
  }
  return null;
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ ok: true, service: "mail-in" });
  if (!SECRET || !timingSafeEqual(req.headers.get("x-mail-in-secret") || "", SECRET)) return json({ error: "forbidden" }, 403);
  const raw = new Uint8Array(await req.arrayBuffer());
  if (!raw.length) return json({ error: "empty" }, 400);
  const rcpt = [req.headers.get("x-rcpt") || ""].concat((req.headers.get("x-to") || "").split(",")).map((s) => s.trim()).filter(Boolean);
  const who = await userFor(rcpt);
  if (!who) { console.error("mail-in: unknown recipient", rcpt.join(" ")); return json({ error: "unknown recipient" }, 404); }

  const m = await new PostalMime().parse(raw);
  const id = crypto.randomUUID();
  const messageId = (m.messageId || "").trim();
  // the same letter twice (the server forwarded again): kept once
  if (messageId) {
    const dup = await db(`mail_in?select=id&user_id=eq.${who.user_id}&message_id=eq.${encodeURIComponent(messageId)}&limit=1`) as { id: string }[];
    if (dup && dup.length) return json({ ok: true, id: dup[0].id, dup: true });
  }
  let html = m.html || "";
  const atts: { filename: string; contentType: string; size: number; path: string }[] = [];
  let budget = MAX_INLINE_TOTAL;
  for (const a of m.attachments || []) {
    const content = typeof a.content === "string" ? new TextEncoder().encode(a.content) : new Uint8Array(a.content as ArrayBuffer);
    const cid = (a.contentId || "").replace(/^<|>$/g, "");
    // a small picture shown inside the text: put right into it
    if (html && cid && (a.mimeType || "").startsWith("image/") && html.includes("cid:" + cid) && content.length <= MAX_INLINE && content.length <= budget) {
      budget -= content.length;
      html = html.split("cid:" + cid).join(`data:${a.mimeType};base64,${b64(content)}`);
      continue;
    }
    const name = safeName(a.filename || ("priedas." + ((a.mimeType || "").split("/")[1] || "bin")));
    const ext = ((name.match(/\.([A-Za-z0-9]{1,8})$/) || [])[1] || "bin").toLowerCase();
    const path = `${who.user_id}/${id}/${atts.length}.${ext}`;   // storage keys: plain letters only (the real name is kept in the list)
    await put(path, content, a.mimeType || "application/octet-stream");
    atts.push({ filename: name, contentType: a.mimeType || "application/octet-stream", size: content.length, path });
  }
  if (html.length > MAX_HTML) html = html.slice(0, MAX_HTML);
  const refs = String(m.headers?.find((h: { key: string }) => h.key === "references")?.value || "").match(/<[^>\s]+>/g) || [];
  await db("mail_in", {
    method: "POST", headers: { Prefer: "return=minimal" },
    body: JSON.stringify({
      id, user_id: who.user_id, message_id: messageId || null,
      date: m.date ? new Date(m.date).toISOString() : new Date().toISOString(),
      subject: m.subject || "", from_addr: addrs(m.from ? [m.from] : []), to_addr: addrs(m.to), cc_addr: addrs(m.cc), reply_to: addrs(m.replyTo),
      refs: refs.slice(-20), html, text: (m.text || "").slice(0, 1_500_000), attachments: atts, size: raw.length,
    }),
  });
  // old letters are not kept forever
  if (Math.random() < 0.05) {
    try {
      const old = await db(`mail_in?select=id,user_id,attachments&created_at=lt.${new Date(Date.now() - KEEP_DAYS * 864e5).toISOString()}&limit=200`) as { id: string; attachments: { path: string }[] }[];
      const paths = old.flatMap((o) => (o.attachments || []).map((a) => a.path));
      if (paths.length) await fetch(`${SUPABASE_URL}/storage/v1/object/${BUCKET}`, { method: "DELETE", headers: hdr({ "Content-Type": "application/json" }), body: JSON.stringify({ prefixes: paths }) });
      if (old.length) await db(`mail_in?id=in.(${old.map((o) => o.id).join(",")})`, { method: "DELETE" });
    } catch (e) { console.error("mail-in cleanup", (e as Error).message); }
  }
  console.log(`mail-in ${who.email} ${raw.length} B, ${atts.length} att.`);
  return json({ ok: true, id });
});
