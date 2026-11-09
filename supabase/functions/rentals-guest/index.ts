// Supabase Edge Function: rentals-guest
//
// Paėmimai through a temporary link (app.eventsolutions.lt/paemimai.html?t=…), for people without an app account:
//   * a member who may edit Paėmimai makes a link (48 h); it is checked by its sha256 (public.rental_links, rental_links.sql);
//     the link itself is kept too, so that such a member can copy it again (the table is read by this function only);
//   * whoever has the link writes their name and surname, then sees the rentals (to take, taken, returned in the last 14 days),
//     ticks what was taken / returned, writes comments and units, adds photos, changes the status and reports a missing
//     item (Slack #dingę-daiktai, through slack-sync with CRON_SECRET);
//   * every change is merged on the server into the rental as it is now (other fields are not touched) and marked
//     „Vardas Pavardė (nuoroda)“; the app sees it at once (realtime).
//
// POST {action:"create"}                       member (session) who may edit Paėmimai → { url, token, expires_at }
// POST {action:"links"}                        the same member: the links still valid (who opened them)
// POST {action:"revoke", id}                   the same member: the link stops working
// POST {action:"hello", token, name}           the link: valid? (the name is remembered on the link)
// POST {action:"list", token}                  the rentals
// POST {action:"photos", token, rental_id}     signed photo addresses of one rental
// POST {action:"save", token, name, rental_id, op}   op: {t:"item", item_id, set:{ok, okNote, back, backQty, backNote}}
//                                                     | {t:"status", v, partial?, missing?} | {t:"noInside", v}
// POST {action:"upload", token, name, rental_id, side:"out"|"in"|"item"|"back", item_id?, type, data(base64)}
// POST {action:"missing", token, name, rental_id, item_id}
// SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY (given by Supabase); CRON_SECRET (to ask slack-sync).

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const APP = "https://app.eventsolutions.lt";
const HOURS = 48, BUCKET = "equipment-photos", MAX_PHOTO = 8 * 1024 * 1024;
const E = (n: string) => Deno.env.get(n) ?? "";
class UserError extends Error {}
const enc = encodeURIComponent;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" } });
}
async function db<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const key = E("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${E("SUPABASE_URL")}/rest/v1/${path}`, {
    ...init,
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json", ...(init.headers as Record<string, string> ?? {}) },
  });
  const t = await res.text();
  if (!res.ok) {
    if (/rental_links|does not exist|schema cache/i.test(t)) throw new UserError("Nuorodos dar neparuoštos – paleisk supabase/sql/rental_links.sql.");
    throw new Error(`Database ${res.status}: ${t.slice(0, 300)}`);
  }
  return (t ? JSON.parse(t) : null) as T;
}
async function sha(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function newToken(): string {
  const b = crypto.getRandomValues(new Uint8Array(24));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const today = () => new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Vilnius" }).format(new Date());
const addDays = (d: string, n: number) => { const t = new Date(d + "T12:00:00Z"); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); };

// ---- the member making a link ----
async function member(req: Request): Promise<{ id: string; name: string } | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const res = await fetch(`${E("SUPABASE_URL")}/auth/v1/user`, { headers: { apikey: E("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` } });
  if (!res.ok) return null;
  const u = await res.json() as { id?: string };
  if (!u?.id) return null;
  const [p] = await db<{ role: string; level: string | null; full_name?: string; first_name?: string; last_name?: string; email?: string }[]>(`profiles?select=role,level,full_name,first_name,last_name,email&id=eq.${enc(u.id)}`);
  if (!p || ["pending", "blocked"].includes(p.role)) return null;
  let ok = p.role === "admin" || p.level === "super";
  if (!ok) { const [x] = await db<{ can_edit: boolean }[]>(`role_permissions?select=can_edit&section=eq.rentals&role=eq.${enc(p.role)}`); ok = !!(x && x.can_edit); }
  if (!ok) throw new UserError("Nuorodą gali sukurti tie, kas redaguoja Paėmimus.");
  return { id: u.id, name: p.full_name || [p.first_name, p.last_name].filter(Boolean).join(" ") || p.email || "" };
}

// ---- the link ----
type Link = { id: string; expires_at: string; revoked_at: string | null; opened: { name: string; at: string }[]; created_by_name: string };
async function link(token: string): Promise<Link> {
  if (!token || token.length < 20) throw new UserError("Nuoroda neteisinga.");
  const [l] = await db<Link[]>(`rental_links?select=id,expires_at,revoked_at,opened,created_by_name&token_hash=eq.${await sha(token)}`);
  if (!l) throw new UserError("Nuoroda neteisinga.");
  if (l.revoked_at) throw new UserError("Ši nuoroda atšaukta.");
  if (Date.parse(l.expires_at) < Date.now()) throw new UserError("Nuorodos galiojimas (48 val.) baigėsi – paprašyk naujos.");
  return l;
}
function guestName(n: unknown): string {
  const s = String(n ?? "").replace(/\s+/g, " ").trim().slice(0, 80);
  if (s.split(" ").filter((w) => w.length > 1).length < 2) throw new UserError("Įrašyk savo vardą ir pavardę.");
  return s;
}

// ---- the rentals ----
type Photo = { path: string; at?: string; by?: string };
type Item = { id: string; name?: string; qty?: number | string; note?: string; ev?: string; ok?: boolean; okNote?: string; okByName?: string; okAt?: string;
  photos?: Photo[]; back?: boolean; backQty?: number | string; backNote?: string; backByName?: string; backAt?: string; backPhotos?: Photo[]; lost?: Record<string, unknown> };
type Rental = { id: string; status?: string; partial?: boolean; missing?: string; items?: string; list?: Item[]; place?: string; address?: string; contact?: string;
  pickupDate?: string; pickupTime?: string; returnDate?: string; returnTime?: string; notes?: string; person?: string; eventId?: string; evs?: { id: string; note?: string }[];
  photos?: { out?: Photo[]; in?: Photo[]; noInside?: boolean }; deletedAt?: string; updatedAt?: string };
function parseItems(t: string | undefined): Item[] {
  return String(t || "").split("\n").map((x) => x.trim()).filter(Boolean).map((l, i) => {
    const m = l.match(/^(\d+(?:[.,]\d+)?)\s*(?:x|×|vnt\.?)\s*(.+)$/i);
    return { id: "ri_t" + i, name: m ? m[2].trim() : l, qty: m ? Number(m[1].replace(",", ".")) : "", note: "" };
  });
}
const listOf = (r: Rental) => Array.isArray(r.list) ? r.list : parseItems(r.items);
const itemsText = (l: Item[]) => l.filter((i) => String(i.name || "").trim()).map((i) => (i.qty !== "" && i.qty != null ? String(i.qty).replace(".", ",") + " x " : "") + String(i.name).trim() + (String(i.note || "").trim() ? " – " + String(i.note).trim() : "")).join("\n");
const evIds = (r: Rental) => Array.isArray(r.evs) ? r.evs.map((x) => x.id) : (r.eventId ? [r.eventId] : []);
// what the page gets: no app-only details, photos only counted (addresses through „photos“)
function view(r: Rental, evNames: Record<string, string>) {
  const p = r.photos || {};
  return {
    id: r.id, status: r.status || "reikia", partial: !!r.partial, missing: r.missing || "", place: r.place || "", address: r.address || "", contact: r.contact || "",
    pickupDate: r.pickupDate || "", pickupTime: r.pickupTime || "", returnDate: r.returnDate || "", returnTime: r.returnTime || "", notes: r.notes || "", person: r.person || "",
    events: (Array.isArray(r.evs) ? r.evs : evIds(r).map((id) => ({ id, note: "" }))).map((x) => ({ id: x.id, name: evNames[x.id] || "", note: x.note || "" })),
    photos: { out: (p.out || []).length, in: (p.in || []).length, noInside: !!p.noInside },
    list: listOf(r).filter((i) => String(i.name || "").trim()).map((i) => ({ id: i.id, name: i.name, qty: i.qty ?? "", note: i.note || "", ev: i.ev || "", ok: !!i.ok, okNote: i.okNote || "",
      okByName: i.okByName || "", okAt: i.okAt || "", photos: (i.photos || []).length, back: !!i.back, backQty: i.backQty ?? "", backNote: i.backNote || "", backByName: i.backByName || "",
      backAt: i.backAt || "", backPhotos: (i.backPhotos || []).length, lost: i.lost ? { at: i.lost.at, qty: i.lost.qty, status: i.lost.status || "", url: i.lost.url || "" } : null })),
  };
}
async function evNamesOf(rs: Rental[]): Promise<Record<string, string>> {
  const ids = [...new Set(rs.flatMap(evIds))].filter(Boolean);
  if (!ids.length) return {};
  const out: Record<string, string> = {};
  for (let i = 0; i < ids.length; i += 80) {
    const part = ids.slice(i, i + 80).map((x) => `"${String(x).replace(/"/g, "")}"`).join(",");
    const rows = await db<{ id: string; data: { name?: string; title?: string; date?: string } }[]>(`events?select=id,data&id=in.(${part})`);
    rows.forEach((e) => { out[e.id] = `${e.data.date ? e.data.date.slice(5).replace("-", ".") + " " : ""}${e.data.name || e.data.title || "Renginys"}`; });
  }
  return out;
}
async function rentalsNow(): Promise<Rental[]> {
  const out: Rental[] = [];
  for (let f = 0; ; f += 1000) {
    const rows = await db<{ data: Rental }[]>(`rentals?select=data&order=id&offset=${f}&limit=1000`);
    rows.forEach((x) => x.data && out.push(x.data));
    if (rows.length < 1000) break;
  }
  const since = addDays(today(), -14);
  return out.filter((r) => !r.deletedAt && (r.status !== "grazinta" || String(r.returnDate || r.updatedAt || "").slice(0, 10) >= since));
}
async function loadRental(id: string): Promise<Rental> {
  const [row] = await db<{ data: Rental }[]>(`rentals?select=data&id=eq.${enc(id)}`);
  if (!row?.data) throw new UserError("Paėmimas nerastas.");
  return row.data;
}
async function saveRental(r: Rental, who: string) {
  r.updatedAt = new Date().toISOString();
  r.items = itemsText(r.list || []);
  await db(`rentals?id=eq.${enc(r.id)}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ data: r, updated_at: r.updatedAt, updated_by: "Nuoroda: " + who }) });
}
const photosReady = (r: Rental) => { const p = r.photos || {}; return (p.out || []).length > 0 && ((p.in || []).length > 0 || !!p.noInside); };
const num = (v: unknown) => { const s = String(v ?? "").trim().replace(",", "."); if (s === "") return ""; const n = Number(s); if (!isFinite(n) || n < 0 || n > 100000) throw new UserError("Neteisingas skaičius."); return n; };
const txt = (v: unknown, n = 500) => String(v ?? "").slice(0, n);

async function signed(paths: string[]): Promise<string[]> {
  if (!paths.length) return [];
  const key = E("SUPABASE_SERVICE_ROLE_KEY");
  const r = await fetch(`${E("SUPABASE_URL")}/storage/v1/object/sign/${BUCKET}`, { method: "POST", headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify({ expiresIn: 3600, paths }) });
  const d = await r.json() as { signedURL?: string; error?: string }[];
  return paths.map((_, i) => d[i]?.signedURL ? `${E("SUPABASE_URL")}/storage/v1${d[i].signedURL}` : "");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST" }, 405);
  let b: Record<string, unknown> = {};
  try { b = await req.json(); } catch { /* empty */ }
  const action = String(b.action || "");
  try {
    // ---- the app ----
    if (action === "create" || action === "links" || action === "revoke") {
      const m = await member(req);
      if (!m) return json({ error: "Prisijunk iš naujo." }, 401);
      if (action === "create") {
        const token = newToken(), exp = new Date(Date.now() + HOURS * 3600e3).toISOString();
        await db("rental_links", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ token_hash: await sha(token), token, created_by: m.id, created_by_name: m.name, expires_at: exp }) });
        return json({ ok: true, token, url: `${APP}/paemimai.html#${token}`, expires_at: exp });
      }
      if (action === "links") {
        const rows = await db<(Link & { created_at: string; token: string | null })[]>(`rental_links?select=id,created_at,expires_at,revoked_at,opened,created_by_name,token&revoked_at=is.null&expires_at=gt.${enc(new Date().toISOString())}&order=created_at.desc`);
        return json({ ok: true, links: rows.map(({ token, ...l }) => ({ ...l, url: token ? `${APP}/paemimai.html#${token}` : "" })) });
      }
      await db(`rental_links?id=eq.${enc(String(b.id || ""))}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ revoked_at: new Date().toISOString() }) });
      return json({ ok: true });
    }
    // ---- the link ----
    const l = await link(String(b.token || ""));
    if (action === "hello") {
      const name = guestName(b.name);
      const opened = (l.opened || []).filter((x) => x.name !== name).concat([{ name, at: new Date().toISOString() }]).slice(-50);
      await db(`rental_links?id=eq.${enc(l.id)}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ opened }) });
      return json({ ok: true, expires_at: l.expires_at, by: l.created_by_name });
    }
    if (action === "list") {
      const rs = await rentalsNow(), names = await evNamesOf(rs);
      return json({ ok: true, expires_at: l.expires_at, rentals: rs.map((r) => view(r, names)) });
    }
    if (action === "photos") {
      const r = await loadRental(String(b.rental_id || "")), p = r.photos || {};
      const groups: [string, string, Photo[]][] = [["out", "", p.out || []], ["in", "", p.in || []]];
      listOf(r).forEach((i) => { groups.push(["item", i.id, i.photos || []]); groups.push(["back", i.id, i.backPhotos || []]); });
      const all = groups.flatMap(([side, item, ps]) => ps.map((x) => ({ side, item, path: x.path })));
      const urls = await signed(all.map((x) => x.path));
      return json({ ok: true, photos: all.map((x, k) => ({ side: x.side, item: x.item, url: urls[k] })) });
    }
    const who = guestName(b.name), mark = who + " (nuoroda)";
    if (action === "save") {
      const r = await loadRental(String(b.rental_id || "")), op = (b.op || {}) as Record<string, unknown>, now = new Date().toISOString();
      if (op.t === "item") {
        if (!Array.isArray(r.list)) r.list = parseItems(r.items);
        const it = r.list.find((x) => x.id === op.item_id); if (!it) throw new UserError("Daiktas nerastas – atnaujink puslapį.");
        const s = (op.set || {}) as Record<string, unknown>;
        if ("ok" in s) { it.ok = !!s.ok; if (it.ok) { it.okByName = mark; it.okAt = now; } else { delete it.okByName; delete it.okAt; } }
        if ("okNote" in s) it.okNote = txt(s.okNote);
        if ("backQty" in s) { it.backQty = num(s.backQty); if (it.backQty !== "" && !it.back) { it.back = true; it.backByName = mark; it.backAt = now; } }
        if ("back" in s) { it.back = !!s.back; if (it.back) { if (it.backQty === "" || it.backQty == null) it.backQty = it.qty; it.backByName = mark; it.backAt = now; } else { delete it.backByName; delete it.backAt; } }
        if ("backNote" in s) it.backNote = txt(s.backNote);
      } else if (op.t === "status") {
        const v = String(op.v || "");
        if (!["reikia", "paimta", "grazinta"].includes(v)) throw new UserError("Neteisinga būsena.");
        if ((r.status || "reikia") === "reikia" && v !== "reikia" && !photosReady(r)) throw new UserError("Pirma įkelk išorės ir vidaus nuotraukas (arba pažymėk, kad vidaus nuotraukų padaryti negalima).");
        r.status = v;
        if (v === "paimta" && op.partial) { r.partial = true; r.missing = txt(op.missing) || r.missing || ""; }
        else if (v !== "grazinta") { delete r.partial; delete r.missing; }
      } else if (op.t === "noInside") {
        r.photos = r.photos || {}; r.photos.noInside = !!op.v;
      } else throw new UserError("Nežinomas veiksmas.");
      await saveRental(r, who);
      return json({ ok: true, rental: view(r, await evNamesOf([r])) });
    }
    if (action === "upload") {
      const r = await loadRental(String(b.rental_id || "")), side = String(b.side || "");
      if (!["out", "in", "item", "back"].includes(side)) throw new UserError("Neteisinga vieta.");
      const type = /^image\/(jpeg|png|webp|heic|heif)$/.test(String(b.type)) ? String(b.type) : "image/jpeg";
      const raw = Uint8Array.from(atob(String(b.data || "")), (c) => c.charCodeAt(0));
      if (!raw.length || raw.length > MAX_PHOTO) throw new UserError("Nuotrauka per didelė (iki 8 MB).");
      let it: Item | undefined;
      if (side === "item" || side === "back") { if (!Array.isArray(r.list)) r.list = parseItems(r.items); it = r.list.find((x) => x.id === b.item_id); if (!it) throw new UserError("Daiktas nerastas."); }
      const ext = type === "image/png" ? "png" : type === "image/webp" ? "webp" : /hei/.test(type) ? "heic" : "jpg";
      const path = `rentals/${r.id}/${side === "item" ? "item-" + it!.id + "-" : side === "back" ? "back-" + it!.id + "-" : side + "-"}${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}.${ext}`;
      const key = E("SUPABASE_SERVICE_ROLE_KEY");
      const up = await fetch(`${E("SUPABASE_URL")}/storage/v1/object/${BUCKET}/${path}`, { method: "POST", headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": type, "x-upsert": "false" }, body: raw });
      if (!up.ok) throw new Error("Saugykla: " + (await up.text()).slice(0, 200));
      const ph = { path, at: new Date().toISOString(), by: mark };
      if (side === "out" || side === "in") { r.photos = r.photos || {}; (r.photos[side] = r.photos[side] || []).push(ph); }
      else if (side === "item") (it!.photos = it!.photos || []).push(ph);
      else (it!.backPhotos = it!.backPhotos || []).push(ph);
      await saveRental(r, who);
      return json({ ok: true, rental: view(r, await evNamesOf([r])) });
    }
    if (action === "missing") {
      const res = await fetch(`${E("SUPABASE_URL")}/functions/v1/slack-sync`, { method: "POST", headers: { "Content-Type": "application/json", "x-cron-secret": E("CRON_SECRET") },
        body: JSON.stringify({ action: "missing_internal", rental_id: b.rental_id, item_id: b.item_id, by: mark }) });
      const d = await res.json().catch(() => ({})) as { error?: string };
      if (!res.ok || d.error) throw new UserError(d.error || "Slack nepasiekiamas.");
      const r = await loadRental(String(b.rental_id || ""));
      return json({ ok: true, rental: view(r, await evNamesOf([r])) });
    }
    return json({ error: "Nežinomas veiksmas." }, 400);
  } catch (e) {
    if (e instanceof UserError) return json({ error: e.message }, 400);
    console.error("rentals-guest", (e as Error).message);
    return json({ error: "Klaida: " + (e as Error).message }, 500);
  }
});
