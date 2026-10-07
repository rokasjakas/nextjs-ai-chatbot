// "freelance-portal": saskaitos.eventsolutions.lt – freelancers send their invoices without an app account.
//
//   {action:"pin", email}                       a one-time PIN to the e-mail (valid 1 hour); only e-mails known
//                                               to the company (Žmonės / app members) get one
//   {action:"login", email, pin}               -> {token, name}  (the session lasts 2 hours)
//   {action:"events", token, date}             the events of that day (from „Renginiai“), mine first
//   {action:"submit", token, id?, number, total, lines:[…], file:{name,type,base64}}
//        lines: [{date, event_id?, event_name, type:"fixed"|"hourly", amount?, hours?, rate?}] – all with taxes;
//        the lines must add up to the invoice total, then the invoice goes to „Sąskaitos“ → Freelance.
//        With id: a not yet approved / rejected invoice of this e-mail is corrected (the file may stay) and
//        goes back to „Naujos“
//   {action:"list", token}                      the invoices this e-mail sent, with their state
//   {action:"file", token, id}                  a short-lived link to the invoice's file
//
// Secrets: RESEND_API_KEY, REMINDER_FROM (as for the other e-mails), CRON_SECRET (to tell Admin+).
// Deploy: supabase functions deploy freelance-portal --no-verify-jwt
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const SECRET = Deno.env.get("FL_PORTAL_SECRET") || SERVICE_KEY;
const PIN_MIN = 60, SESSION_MIN = 120, MAX_FILE = 10 * 1024 * 1024;

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type, apikey, authorization, x-client-info", "Access-Control-Allow-Methods": "POST, OPTIONS" };
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { ...cors, "Content-Type": "application/json" } });
class UserError extends Error {}
const hdr = (x: Record<string, string> = {}) => ({ apikey: SERVICE_KEY, Authorization: "Bearer " + SERVICE_KEY, ...x });
async function db<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const r = await fetch(SUPABASE_URL + "/rest/v1/" + path, { ...init, headers: hdr({ "Content-Type": "application/json", ...(init.headers as Record<string, string> || {}) }) });
  const t = await r.text();
  if (!r.ok) {
    if (/fl_portal|ext_email|lines|does not exist|schema cache/i.test(t)) throw new UserError("Sistema dar neparuošta (paleisk freelance_portal.sql).");
    throw new Error(`db ${r.status}: ${t.slice(0, 300)}`);
  }
  return (t ? JSON.parse(t) : null) as T;
}
const enc = encodeURIComponent;
async function sha(s: string) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join(""); }
const rnd = (n: number) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
const emailRe = /^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/;
const esc = (t: string) => String(t).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
const round2 = (n: number) => Math.round(n * 100) / 100;
const today = () => new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Vilnius" }).format(new Date());
const norm = (s: string) => String(s || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/\s+/g, " ").trim();

// who is this e-mail: a person in „Žmonės“ or an app member
async function whoIs(email: string): Promise<{ name: string; contact_id: string | null } | null> {
  const cs = await db<{ id: string; data: { first?: string; last?: string; email?: string } }[]>(`contacts?select=id,data&data->>email=ilike.${enc(email)}&limit=1`).catch(() => []);
  if (cs.length) return { name: [cs[0].data.first, cs[0].data.last].filter(Boolean).join(" ").trim() || email, contact_id: cs[0].id };
  const ps = await db<{ first_name?: string; last_name?: string; full_name?: string; role: string }[]>(`profiles?select=first_name,last_name,full_name,role&email=ilike.${enc(email)}&limit=1`);
  if (ps.length && !["pending", "blocked"].includes(ps[0].role)) return { name: [ps[0].first_name, ps[0].last_name].filter(Boolean).join(" ").trim() || ps[0].full_name || email, contact_id: null };
  return null;
}
async function session(token: unknown) {
  if (typeof token !== "string" || token.length < 20) throw new UserError("Prisijunk iš naujo.");
  const [s] = await db<{ email: string; name: string; contact_id: string | null; expires_at: string }[]>(`fl_portal_sessions?select=*&token_hash=eq.${await sha(token + SECRET)}`);
  if (!s || Date.parse(s.expires_at) < Date.now()) throw new UserError("Prisijungimas baigėsi – prisijunk iš naujo.");
  return s;
}

async function sendPin(email: string, pin: string, name: string) {
  const key = Deno.env.get("RESEND_API_KEY"); if (!key) throw new Error("RESEND_API_KEY nenustatytas");
  const html = `<div style="font-family:Arial,sans-serif;font-size:15px;color:#111">
    <p>Sveiki${name ? ", " + esc(name.split(" ")[0]) : ""},</p>
    <p>Jūsų prisijungimo prie <b>Event Solutions sąskaitų</b> kodas:</p>
    <p style="font-size:30px;font-weight:bold;letter-spacing:6px;margin:16px 0">${pin}</p>
    <p style="color:#555">Kodas galioja 1 valandą ir tinka vienam prisijungimui. Jei jo neprašėte – tiesiog ignoruokite šį laišką.</p></div>`;
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: Deno.env.get("REMINDER_FROM") || "Event Solutions <onboarding@resend.dev>", to: [email], subject: `Prisijungimo kodas: ${pin}`, html }),
  });
  if (!r.ok) throw new Error(`Resend ${r.status}: ${(await r.text()).slice(0, 200)}`);
}

// the events of a day (a several-day event counts on each of its days); the person's own first
async function eventsOn(date: string, name: string) {
  const from = new Date(Date.parse(date + "T00:00:00Z") - 20 * 864e5).toISOString().slice(0, 10);
  const rows = await db<{ id: string; event_date: string; data: Record<string, unknown> }[]>(`events?select=id,event_date,data&event_date=gte.${from}&event_date=lte.${date}&order=event_date.desc&limit=300`);
  const me = norm(name);
  return rows.filter((r) => {
    const d = String(r.data.date || r.event_date || "").slice(0, 10), e = String(r.data.dateEnd || "").slice(0, 10);
    return d && d <= date && date <= (e > d ? e : d);
  }).map((r) => {
    const ev = r.data as { kind?: string; title?: string; name?: string; location?: string; crew?: { entries?: { person?: string }[] }[]; manager?: string };
    const people = (ev.crew || []).flatMap((g) => (g.entries || []).map((x) => norm(x.person || ""))).concat(norm(ev.manager || ""));
    return { id: r.id, name: ev.kind === "work" ? (ev.title || "Sandėlio darbai") : (ev.name || "Renginys"), location: ev.location || "", mine: !!me && people.includes(me) };
  }).sort((a, b) => Number(b.mine) - Number(a.mine) || a.name.localeCompare(b.name, "lt"));
}

type Mine = { id: string; number: string | null; amount: number; status: string; decision_note: string | null; decision_at: string | null; created_at: string; invoice_date: string | null; note: string | null; lines: unknown[]; files: { path: string; name: string; type: string; size: number }[]; responses: unknown[] };
async function mine(email: string, id?: string) {
  return await db<Mine[]>(`invoices?select=id,number,amount,status,decision_note,decision_at,created_at,invoice_date,note,lines,files,responses&source=eq.portal&ext_email=eq.${enc(email)}${id ? "&id=eq." + enc(id) : ""}&order=created_at.desc&limit=100`);
}
const EDITABLE = ["new", "rejected"];

type Line = { date?: string; event_id?: string; event_name?: string; type?: string; amount?: number; hours?: number; rate?: number };
async function submit(s: { email: string; name: string }, b: { id?: string; number?: string; total?: number; lines?: Line[]; file?: { name?: string; type?: string; base64?: string }; note?: string }) {
  const lines = Array.isArray(b.lines) ? b.lines.slice(0, 80) : [];
  if (!lines.length) throw new UserError("Įrašyk bent vieną renginį.");
  const ids = [...new Set(lines.map((l) => String(l.event_id || "")).filter(Boolean))];
  const known = ids.length ? await db<{ id: string; data: { kind?: string; title?: string; name?: string } }[]>(`events?select=id,data&id=in.(${ids.map((x) => `"${x.replace(/"/g, "")}"`).join(",")})`) : [];
  const nameOf = new Map(known.map((e) => [e.id, e.data.kind === "work" ? (e.data.title || "Sandėlio darbai") : (e.data.name || "Renginys")]));
  const clean = lines.map((l, i) => {
    const n = i + 1, date = String(l.date || "");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new UserError(`${n} eilutė: pasirink datą.`);
    const id = l.event_id && nameOf.has(String(l.event_id)) ? String(l.event_id) : null;
    const event = id ? nameOf.get(id)! : String(l.event_name || "").trim().slice(0, 200);
    if (!event) throw new UserError(`${n} eilutė: pasirink renginį arba įrašyk jo pavadinimą.`);
    if (l.type === "hourly") {
      const h = Number(l.hours), r = Number(l.rate);
      if (!(h > 0 && h < 1000) || !(r > 0 && r < 10000)) throw new UserError(`${n} eilutė: įrašyk valandas ir valandinį įkainį.`);
      return { date, event_id: id, event, type: "hourly", hours: h, rate: r, amount: round2(h * r), manual: !id };
    }
    const a = Number(l.amount);
    if (!(a > 0 && a < 1_000_000)) throw new UserError(`${n} eilutė: įrašyk sutartą sumą.`);
    return { date, event_id: id, event, type: "fixed", amount: round2(a), manual: !id };
  });
  const sum = round2(clean.reduce((t, l) => t + l.amount, 0)), total = round2(Number(b.total));
  if (!(total > 0)) throw new UserError("Įrašyk sąskaitos sumą.");
  if (Math.abs(sum - total) > 0.005) throw new UserError(`Sumos nesutampa: renginių suma ${sum.toFixed(2)} €, sąskaitos suma ${total.toFixed(2)} €.`);
  const editId = b.id ? String(b.id) : "";
  const old = editId ? (await mine(s.email, editId))[0] : null;
  if (editId && !old) throw new UserError("Sąskaita nerasta.");
  if (old && !EDITABLE.includes(old.status)) throw new UserError("Ši sąskaita jau patvirtinta – jos taisyti nebegalima.");
  const f = b.file || {};
  if (!f.base64 && old && old.files?.length) return await saveEdit(s, old, b, clean, total, null);
  if (!f.base64) throw new UserError("Įkelk sąskaitos failą.");
  const bytes = Uint8Array.from(atob(String(f.base64)), (c) => c.charCodeAt(0));
  if (bytes.length > MAX_FILE) throw new UserError("Failas per didelis (iki 10 MB).");
  const type = String(f.type || "application/octet-stream");
  if (!/^(application\/pdf|image\/)/.test(type)) throw new UserError("Įkelk sąskaitą PDF arba nuotrauka.");
  // the invoice belongs to an Admin+ (the table needs a member as its owner); who sent it is kept in ext_*
  const owners = await db<{ id: string }[]>("profiles?select=id&role=eq.admin&level=in.(plus,super)&order=created_at&limit=1");
  const owner = owners[0]?.id || (await db<{ id: string }[]>("profiles?select=id&role=eq.admin&order=created_at&limit=1"))[0]?.id;
  if (!owner) throw new Error("no admin");
  const id = old ? old.id : crypto.randomUUID();
  const fname = String(f.name || "saskaita").replace(/[\\/\u0000-\u001f]+/g, "_").slice(0, 120);
  const ext = ((fname.match(/\.([A-Za-z0-9]{1,6})$/) || [])[1] || (type === "application/pdf" ? "pdf" : "jpg")).toLowerCase();
  const path = `${owner}/portal/${id}/saskaita${old ? "-" + Date.now() : ""}.${ext}`;
  const up = await fetch(`${SUPABASE_URL}/storage/v1/object/invoice-files/${path}`, { method: "POST", headers: hdr({ "Content-Type": type, "x-upsert": "true" }), body: bytes });
  if (!up.ok) throw new Error("upload " + up.status + " " + (await up.text()).slice(0, 200));
  if (old) return await saveEdit(s, old, b, clean, total, { path, name: fname, type, size: bytes.length });
  await db("invoices", {
    method: "POST", headers: { Prefer: "return=minimal" },
    body: JSON.stringify({
      id, created_by: owner, kind: "freelance", supplier: s.name, number: String(b.number || "").trim().slice(0, 80) || null,
      amount: total, invoice_date: today(), note: String(b.note || "").trim().slice(0, 1000) || null,
      files: [{ path, name: fname, type, size: bytes.length }],
      ext_email: s.email, ext_name: s.name, lines: clean, source: "portal", uploader_seen: true,
    }),
  });
  // Admin+ are told (push-notify, with the cron secret)
  const cs = Deno.env.get("CRON_SECRET");
  if (cs) await fetch(SUPABASE_URL + "/functions/v1/push-notify", { method: "POST", headers: { "Content-Type": "application/json", "x-cron-secret": cs }, body: JSON.stringify({ mode: "invoice-portal", invoice_id: id }) }).catch(() => {});
  return { ok: true, id, total };
}

// a corrected invoice: the new lines (and file), back to „Naujos“; the old decision stays in its history
async function saveEdit(s: { email: string; name: string }, old: Mine, b: { number?: string; note?: string }, lines: unknown[], total: number, file: { path: string; name: string; type: string; size: number } | null) {
  const why = old.status === "rejected" ? "Pataisė netvirtintą sąskaitą" + (old.decision_note ? " (priežastis buvo: „" + old.decision_note + "“)" : "") : "Pataisė sąskaitą";
  await db(`invoices?id=eq.${old.id}`, {
    method: "PATCH", headers: { Prefer: "return=minimal" },
    body: JSON.stringify({
      number: String(b.number || "").trim().slice(0, 80) || null, amount: total, note: String(b.note || "").trim().slice(0, 1000) || null,
      lines, ext_name: s.name, status: "new", decision_note: null, decision_by: null, decision_at: null, remind_at: null, reminded_at: null,
      responses: [...(old.responses || []), { at: new Date().toISOString(), who: s.name, kind: "reply", text: why }],
      ...(file ? { files: [file] } : {}),
    }),
  });
  if (file && old.files?.length) await fetch(`${SUPABASE_URL}/storage/v1/object/invoice-files`, { method: "DELETE", headers: hdr({ "Content-Type": "application/json" }), body: JSON.stringify({ prefixes: old.files.map((x) => x.path) }) }).catch(() => {});
  const cs = Deno.env.get("CRON_SECRET");
  if (cs) await fetch(SUPABASE_URL + "/functions/v1/push-notify", { method: "POST", headers: { "Content-Type": "application/json", "x-cron-secret": cs }, body: JSON.stringify({ mode: "invoice-portal", invoice_id: old.id, edited: true }) }).catch(() => {});
  return { ok: true, id: old.id, total, edited: true };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ ok: true, service: "freelance-portal" });
  try {
    const b = await req.json().catch(() => ({})) as Record<string, unknown>;
    const action = String(b.action || "");
    if (action === "pin") {
      const email = String(b.email || "").trim().toLowerCase();
      if (!emailRe.test(email)) throw new UserError("Įrašyk el. paštą.");
      const who = await whoIs(email);
      if (!who) throw new UserError("Šio el. pašto nėra mūsų sąraše. Kreipkis į Event Solutions biurą.");
      const recent = await db<{ id: string }[]>(`fl_portal_pins?select=id&email=eq.${enc(email)}&created_at=gt.${new Date(Date.now() - 3600e3).toISOString()}`);
      if (recent.length >= 5) throw new UserError("Per daug bandymų – pabandyk po valandos.");
      const pin = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
      await db("fl_portal_pins", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ email, pin_hash: await sha(email + ":" + pin + ":" + SECRET), expires_at: new Date(Date.now() + PIN_MIN * 60e3).toISOString() }) });
      await sendPin(email, pin, who.name);
      return json({ ok: true });
    }
    if (action === "login") {
      const email = String(b.email || "").trim().toLowerCase(), pin = String(b.pin || "").replace(/\D/g, "");
      const [p] = await db<{ id: string; pin_hash: string; attempts: number }[]>(`fl_portal_pins?select=id,pin_hash,attempts&email=eq.${enc(email)}&used_at=is.null&expires_at=gt.${new Date().toISOString()}&order=created_at.desc&limit=1`);
      if (!p) throw new UserError("Kodas nebegalioja – paprašyk naujo.");
      if (p.attempts >= 5) throw new UserError("Per daug neteisingų bandymų – paprašyk naujo kodo.");
      if (p.pin_hash !== await sha(email + ":" + pin + ":" + SECRET)) {
        await db(`fl_portal_pins?id=eq.${p.id}`, { method: "PATCH", body: JSON.stringify({ attempts: p.attempts + 1 }) });
        throw new UserError("Neteisingas kodas.");
      }
      await db(`fl_portal_pins?id=eq.${p.id}`, { method: "PATCH", body: JSON.stringify({ used_at: new Date().toISOString() }) });
      const who = await whoIs(email);
      const token = rnd(32);
      await db("fl_portal_sessions", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ token_hash: await sha(token + SECRET), email, name: who?.name || email, contact_id: who?.contact_id || null, expires_at: new Date(Date.now() + SESSION_MIN * 60e3).toISOString() }) });
      return json({ ok: true, token, name: who?.name || email, email });
    }
    if (action === "events") {
      const s = await session(b.token);
      const date = String(b.date || "");
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new UserError("Pasirink datą.");
      return json({ events: await eventsOn(date, s.name) });
    }
    if (action === "list") {
      const s = await session(b.token);
      const rows = await mine(s.email);
      return json({ invoices: rows.map((v) => ({ ...v, files: (v.files || []).map((f) => ({ name: f.name, type: f.type, size: f.size })), responses: undefined, editable: EDITABLE.includes(v.status) })) });
    }
    if (action === "file") {
      const s = await session(b.token);
      const [v] = await mine(s.email, String(b.id || ""));
      const f = v?.files?.[0]; if (!f) throw new UserError("Failas nerastas.");
      const r = await fetch(`${SUPABASE_URL}/storage/v1/object/sign/invoice-files/${f.path.split("/").map(enc).join("/")}`, { method: "POST", headers: hdr({ "Content-Type": "application/json" }), body: JSON.stringify({ expiresIn: 600 }) });
      const d = await r.json().catch(() => ({})) as { signedURL?: string };
      if (!r.ok || !d.signedURL) throw new Error("sign " + r.status);
      return json({ url: SUPABASE_URL + "/storage/v1" + d.signedURL });
    }
    if (action === "submit") {
      const s = await session(b.token);
      return json(await submit(s, b as never));
    }
    throw new UserError("Nežinomas veiksmas.");
  } catch (e) {
    if (e instanceof UserError) return json({ error: e.message }, 400);
    console.error(e instanceof Error ? e.stack || e.message : e);
    return json({ error: "Klaida. Pabandyk dar kartą." }, 500);
  }
});
