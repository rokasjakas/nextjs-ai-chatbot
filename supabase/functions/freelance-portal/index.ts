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
//   {action:"scan", token, file:{type,base64}}  the total written in the invoice file (read by Claude) – the page
//                                               shows it at once; „submit“ refuses an invoice whose file says otherwise
// ANTHROPIC_API_KEY: without it the file's total is not checked (the invoice is marked „nepatikrinta“).
//
// Secrets: RESEND_API_KEY, REMINDER_FROM (as for the other e-mails), CRON_SECRET (to tell Admin+).
// Deploy: supabase functions deploy freelance-portal --no-verify-jwt
import Anthropic from "npm:@anthropic-ai/sdk";
import { extractText, getDocumentProxy } from "npm:unpdf@1.8.1";
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
const norm = (s: string) => String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/\s+/g, " ").trim();

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
  const [s] = await db<{ email: string; name: string; contact_id: string | null; expires_at: string; token_hash: string; scans?: Record<string, Scan> }[]>(`fl_portal_sessions?select=*&token_hash=eq.${await sha(token + SECRET)}`);
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

// the total payable (with taxes) written in the invoice file; cached per session by the file's hash.
// Read by Claude (ANTHROPIC_API_KEY), or by Gemini (GEMINI_API_KEY) when there is no Claude key.
type Scan = { checked: boolean; found: boolean; total: number | null; why?: string };
const SCAN_TYPES = ["application/pdf", "image/jpeg", "image/png", "image/gif", "image/webp"];
const SCAN_PROMPT = "This file should be an invoice (usually Lithuanian). Give the final total amount payable INCLUDING all taxes/VAT " +
  "(e.g. „Iš viso su PVM“, „Mokėti“, „Suma apmokėjimui“, „Iš viso“). If there is no VAT, the final total. " +
  "As a plain number in euros (e.g. 1234.5). is_invoice=false and total=null if it is not an invoice or the total can't be read.";
function scanOf(o: { is_invoice?: boolean; total?: number | null }): Scan {
  const t = typeof o.total === "number" && isFinite(o.total) && o.total > 0 ? Math.round(o.total * 100) / 100 : null;
  return { checked: true, found: !!o.is_invoice && t != null, total: t, why: o.is_invoice ? (t == null ? "no-total" : undefined) : "not-invoice" };
}
async function readClaude(key: string, b64: string, type: string): Promise<Scan> {
  const client = new Anthropic({ apiKey: key, timeout: 60_000, maxRetries: 1 });
  const file = type === "application/pdf"
    ? { type: "document", source: { type: "base64", media_type: "application/pdf", data: b64 } }
    : { type: "image", source: { type: "base64", media_type: type, data: b64 } };
  // deno-lint-ignore no-explicit-any
  const r: any = await (client.beta.messages.create as any)({
    model: "claude-opus-5-5", max_tokens: 4000,
    betas: ["server-side-fallback-2026-07-01"], fallbacks: "default",
    output_config: {
      effort: "low",
      format: { type: "json_schema", schema: {
        type: "object", additionalProperties: false, required: ["is_invoice", "total"],
        properties: { is_invoice: { type: "boolean" }, total: { type: ["number", "null"] } },
      } },
    },
    messages: [{ role: "user", content: [file, { type: "text", text: SCAN_PROMPT }] }],
  });
  if (r.stop_reason === "refusal") return { checked: false, found: false, total: null, why: "refusal" };
  const text = (r.content || []).filter((c: { type: string }) => c.type === "text").map((c: { text: string }) => c.text).join("");
  return scanOf(JSON.parse(text));
}
async function readGemini(key: string, b64: string, type: string): Promise<Scan> {
  const model = Deno.env.get("GEMINI_MODEL") || "gemini-flash-latest";
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, {
    method: "POST", signal: AbortSignal.timeout(60_000), headers: { "Content-Type": "application/json", "x-goog-api-key": key },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ inline_data: { mime_type: type, data: b64 } }, { text: SCAN_PROMPT }] }],
      generationConfig: { responseMimeType: "application/json", responseSchema: { type: "OBJECT", required: ["is_invoice", "total"],
        properties: { is_invoice: { type: "BOOLEAN" }, total: { type: "NUMBER", nullable: true } } } },
    }),
  });
  if (!r.ok) throw new Error("gemini " + r.status + " " + (await r.text()).slice(0, 200));
  const d = await r.json() as { candidates?: { content?: { parts?: { text?: string }[] } }[] };
  return scanOf(JSON.parse((d.candidates?.[0]?.content?.parts || []).map((x) => x.text || "").join("")));
}
// without an AI key (or when it can't tell): an electronic PDF's own text is searched for the total
// the final total (with taxes) in an invoice's text: the strongest keyword wins, its last number on that line
function findTotal(raw: string): number | null {
  const text = String(raw || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/\u00a0/g, " ");
  const NUM = /(\d{1,3}(?:[ .]\d{3})+(?:[.,]\d{1,2})?|\d+(?:[.,]\d{1,2})?)(?!\d)/g;
  const parse = (s: string) => {
    let t = s.replace(/ /g, "");
    if (/[.,]\d{1,2}$/.test(t)) { const d = t.slice(-3).replace(/^[.,]/, ""); t = t.slice(0, t.length - (t.match(/[.,]\d{1,2}$/)![0].length)).replace(/[.,]/g, "") + "." + d; }
    else t = t.replace(/[.,]/g, "");
    const n = Number(t); return isFinite(n) ? n : NaN;
  };
  const levels = [
    /(moketina suma|suma apmoke?jimui|suma moketi|is viso moketi|viso moketi|moketi is viso|moketi|apmoketi|amount due|total due|to pay)/,
    /(is viso su pvm|viso su pvm|suma su pvm|bendra suma su pvm|su pvm is viso|total incl|total with vat|grand total)/,
    /(is viso|viso|bendra suma|galutine suma|total|suma)/,
  ];
  const lines = text.split(/\n+/);
  for (const [li, re] of levels.entries()) {
    const found: number[] = [];
    for (const [i, line0] of lines.entries()) {
      const m = line0.match(re); if (!m) continue;
      if (li === 2 && /be pvm|pvm \d|pvm suma|zodziais|kiekis|kaina/.test(line0)) continue;
      if (li < 2 && /zodziais/.test(line0)) continue;
      // the amount after the keyword on that line, or on the next line (tables)
      let rest = line0.slice(m.index + m[0].length).replace(/\d{4}-\d{2}-\d{2}/g, " ").replace(/\d{1,3}\s?%/g, " ");
      let nums = [...rest.matchAll(NUM)].map((x) => parse(x[1])).filter((n) => n > 0);
      if (!nums.length && lines[i + 1]) nums = [...lines[i + 1].replace(/\d{4}-\d{2}-\d{2}/g, " ").matchAll(NUM)].map((x) => parse(x[1])).filter((n) => n > 0);
      if (nums.length) found.push(nums[nums.length - 1]);
    }
    if (found.length) return Math.round((li === 2 ? Math.max(...found) : found[found.length - 1]) * 100) / 100;
  }
  return null;
}
async function readPdfText(b64: string): Promise<Scan> {
  try {
    const pdf = await getDocumentProxy(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
    const { text } = await extractText(pdf, { mergePages: true });
    const body = String(text || "");
    if (body.replace(/\s+/g, "").length < 20) return { checked: true, found: false, total: null, why: "scanned" };
    const t = findTotal(body);
    return t != null && t > 0 ? { checked: true, found: true, total: t, why: "pdf-text" } : { checked: true, found: false, total: null, why: "no-total" };
  } catch (e) {
    console.error("pdf", e instanceof Error ? e.message : e);
    return { checked: false, found: false, total: null, why: "error" };
  }
}
async function readTotal(b64: string, type: string): Promise<Scan> {
  if (!SCAN_TYPES.includes(type)) return { checked: false, found: false, total: null, why: "type" };
  const ck = Deno.env.get("ANTHROPIC_API_KEY"), gk = Deno.env.get("GEMINI_API_KEY"), pdf = type === "application/pdf";
  let ai: Scan | null = null;
  if (ck || gk) {
    try { ai = ck ? await readClaude(ck, b64, type) : await readGemini(gk!, b64, type); }
    catch (e) {
      if (e instanceof Anthropic.APIError) console.error("anthropic", e.status, e.message);
      else console.error("scan", e instanceof Error ? e.message : e);
      if (ck && gk) { try { ai = await readGemini(gk, b64, type); } catch (e2) { console.error("scan2", e2 instanceof Error ? e2.message : e2); } }
    }
    if (ai && ai.found) return ai;
  }
  if (pdf) {
    const t = await readPdfText(b64);
    if (t.found || !ai) return t;
  }
  return ai || { checked: false, found: false, total: null, why: "image-off" };
}
async function scanCached(s: { token_hash?: string; scans?: Record<string, Scan> }, b64: string, type: string): Promise<Scan> {
  const h = await sha(b64);
  const hit = s.scans?.[h]; if (hit && hit.checked) return hit;
  const r = await readTotal(b64, type);
  if (r.checked && s.token_hash) {
    s.scans = { ...(s.scans || {}), [h]: r };
    await db(`fl_portal_sessions?token_hash=eq.${s.token_hash}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ scans: s.scans }) }).catch(() => {});
  }
  return r;
}
const eurTxt = (n: number) => n.toFixed(2).replace(".", ",") + " €";
// the invoice's total must be read from the file and be the same as the entered one
function mustMatch(scan: Scan, total: number) {
  if (!scan.found || scan.total == null) {
    throw new UserError(scan.why === "image-off" ? "Nuotraukos dar negalime patikrinti – įkelk sąskaitą PDF formatu."
      : scan.why === "scanned" ? "Šiame PDF nėra teksto (nuskenuotas). Įkelk elektroninę PDF sąskaitą."
      : scan.why === "not-invoice" ? "Įkeltas failas neatrodo kaip sąskaita. Įkelk sąskaitą faktūrą (PDF arba aiškią nuotrauką)."
      : scan.why === "type" ? "Sąskaitą įkelk PDF, JPG arba PNG formatu."
      : scan.checked ? "Įkeltoje sąskaitoje nepavyko rasti galutinės sumos. Įkelk aiškesnį failą (geriausia PDF)."
      : "Nepavyko patikrinti sąskaitos failo – pabandyk dar kartą po minutės.");
  }
  if (Math.abs(scan.total - total) > 0.005)
    throw new UserError(`Įkeltoje sąskaitoje nurodyta galutinė suma ${eurTxt(scan.total)}, o įvesta ${eurTxt(total)}. Sumos turi sutapti.`);
}

type Mine = { id: string; file_total?: number | null; check_msgs?: { at?: string; kind?: string; text?: string }[]; number: string | null; amount: number; status: string; decision_note: string | null; decision_at: string | null; created_at: string; invoice_date: string | null; note: string | null; lines: unknown[]; files: { path: string; name: string; type: string; size: number }[]; responses: unknown[] };
async function mine(email: string, id?: string) {
  return await db<Mine[]>(`invoices?select=id,file_total,check_msgs,number,amount,status,decision_note,decision_at,created_at,invoice_date,note,lines,files,responses&source=eq.portal&ext_email=eq.${enc(email)}${id ? "&id=eq." + enc(id) : ""}&order=created_at.desc&limit=100`);
}
const EDITABLE = ["new", "rejected"];
// what happened to the invoice, for the freelancer (inner notes and the accounting's written replies stay inside)
type Resp = { at?: string; kind?: string; text?: string; src?: string; rejected_at?: string | null; reason?: string };
function history(v: Mine) {
  const h: { at: string; t: string; note?: string; c: string }[] = [{ at: v.created_at, t: "Pateikta", c: "info" }];
  for (const r of (v.responses || []) as Resp[]) {
    if (!r.at) continue;
    if (r.src === "portal") {
      if (r.rejected_at) h.push({ at: r.rejected_at, t: "Nepatvirtinta", note: r.reason || "", c: "bad" });
      h.push({ at: r.at, t: "Pataisyta ir pateikta iš naujo", c: "info" });
    } else if (r.kind === "paid") h.push({ at: r.at, t: "Apmokėta", c: "ok" });
    else if (r.kind === "queued") h.push({ at: r.at, t: "Suvesta apmokėjimui", c: "ok" });
  }
  // the office's letters to the freelancer (ok / corrections)
  for (const m of v.check_msgs || []) {
    if (!m.at) continue;
    if (m.kind === "ok") h.push({ at: m.at, t: "Patikrinta – viskas tvarkoje", note: m.text || "", c: "ok" });
    else if (m.kind === "fix") h.push({ at: m.at, t: "Reikia korekcijų", note: m.text || "", c: "bad" });
  }
  if (v.decision_at) {
    if (v.status === "rejected") h.push({ at: v.decision_at, t: "Nepatvirtinta", note: v.decision_note || "", c: "bad" });
    else if (["approved", "sent", "queued", "paid"].includes(v.status)) h.push({ at: v.decision_at, t: "Patvirtinta, perduota buhalterijai", note: v.decision_note || "", c: "ok" });
  }
  return h.sort((a, b) => a.at.localeCompare(b.at));
}

// a line: the work at one event (fixed or hourly) plus extra costs (what, how much, a receipt photo or another invoice)
type In = { name?: string; type?: string; base64?: string };
type Extra = { what?: string; amount?: number; file?: In; keep?: number };
type Line = { date?: string; event_id?: string; event_name?: string; type?: string; amount?: number; hours?: number; rate?: number; extras?: Extra[] };
type FileRow = { path: string; name: string; type: string; size: number; role?: string };
const cleanName = (n: string) => String(n || "failas").replace(/[\\/\u0000-\u001f]+/g, "_").slice(0, 120);
function decode(f: In, label: string) {
  const bytes = Uint8Array.from(atob(String(f.base64)), (c) => c.charCodeAt(0));
  if (bytes.length > MAX_FILE) throw new UserError(`${label}: failas per didelis (iki 10 MB).`);
  const type = String(f.type || "application/octet-stream");
  if (!/^(application\/pdf|image\/)/.test(type)) throw new UserError(`${label}: įkelk PDF arba nuotrauką.`);
  return { bytes, type };
}
async function upload(path: string, bytes: Uint8Array, type: string) {
  const up = await fetch(`${SUPABASE_URL}/storage/v1/object/invoice-files/${path}`, { method: "POST", headers: hdr({ "Content-Type": type, "x-upsert": "true" }), body: bytes });
  if (!up.ok) throw new Error("upload " + up.status + " " + (await up.text()).slice(0, 200));
}
async function submit(s: { email: string; name: string; token_hash?: string; scans?: Record<string, Scan> }, b: { id?: string; number?: string; total?: number; lines?: Line[]; file?: In; note?: string }) {
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
    const extras = (Array.isArray(l.extras) ? l.extras.slice(0, 20) : []).map((x, j) => {
      const what = String(x.what || "").trim().slice(0, 200), a = Number(x.amount);
      if (!what) throw new UserError(`${n} eilutė, ${j + 1} papildoma išlaida: parašyk, už ką.`);
      if (!(a > 0 && a < 1_000_000)) throw new UserError(`${n} eilutė, papildoma išlaida „${what}“: įrašyk sumą.`);
      return { what, amount: round2(a), in: x };
    });
    const ex = round2(extras.reduce((t, x) => t + x.amount, 0));
    let work: Record<string, unknown>;
    if (l.type === "hourly") {
      const h = Number(l.hours), r = Number(l.rate);
      if (!(h > 0 && h < 1000) || !(r > 0 && r < 10000)) throw new UserError(`${n} eilutė: įrašyk valandas ir valandinį įkainį.`);
      work = { type: "hourly", hours: h, rate: r, amount: round2(h * r) };
    } else {
      const a = Number(l.amount || 0);
      if (!(a >= 0 && a < 1_000_000) || (!(a > 0) && !extras.length)) throw new UserError(`${n} eilutė: įrašyk sutartą sumą.`);
      work = { type: "fixed", amount: round2(a) };
    }
    return { date, event_id: id, event, ...work, extras, total: round2(Number(work.amount) + ex), manual: !id };
  });
  const sum = round2(clean.reduce((t, l) => t + l.total, 0)), total = round2(Number(b.total));
  if (!(total > 0)) throw new UserError("Įrašyk sąskaitos sumą.");
  if (Math.abs(sum - total) > 0.005) throw new UserError(`Sumos nesutampa: renginių ir išlaidų suma ${eurTxt(sum)}, sąskaitos suma ${eurTxt(total)}.`);
  const editId = b.id ? String(b.id) : "";
  const old = editId ? (await mine(s.email, editId))[0] : null;
  if (editId && !old) throw new UserError("Sąskaita nerasta.");
  if (old && !EDITABLE.includes(old.status)) throw new UserError("Ši sąskaita jau patvirtinta – jos taisyti nebegalima.");
  const oldFiles = (old?.files || []) as FileRow[];

  // the invoice file: a new one is read and must say the same total; a kept one was read when it came
  const f = b.file || {};
  let main: { bytes: Uint8Array; type: string; name: string } | null = null, scan: Scan | null = null;
  if (f.base64) {
    const d = decode(f, "Sąskaita");
    scan = await scanCached(s, String(f.base64), d.type);
    mustMatch(scan, total);
    main = { ...d, name: cleanName(f.name || "saskaita") };
  } else if (old && oldFiles.length) {
    if (old.file_total == null) throw new UserError("Įkelk sąskaitos failą iš naujo – jame bus patikrinta galutinė suma.");
    if (Math.abs(Number(old.file_total) - total) > 0.005)
      throw new UserError(`Įkeltoje sąskaitoje nurodyta galutinė suma ${eurTxt(Number(old.file_total))}, o įvesta ${eurTxt(total)}. Pataisyk sumas arba įkelk naują failą.`);
  } else throw new UserError("Įkelk sąskaitos failą.");

  // the invoice belongs to an Admin+ (the table needs a member as its owner); who sent it is kept in ext_*
  const owners = await db<{ id: string }[]>("profiles?select=id&role=eq.admin&level=in.(plus,super)&order=created_at&limit=1");
  const owner = owners[0]?.id || (await db<{ id: string }[]>("profiles?select=id&role=eq.admin&order=created_at&limit=1"))[0]?.id;
  if (!owner) throw new Error("no admin");
  const id = old ? old.id : crypto.randomUUID(), ts = Date.now();
  const extOf = (name: string, type: string) => ((name.match(/\.([A-Za-z0-9]{1,6})$/) || [])[1] || (type === "application/pdf" ? "pdf" : "jpg")).toLowerCase();
  const files: FileRow[] = [];
  if (main) {
    const path = `${owner}/portal/${id}/saskaita-${ts}.${extOf(main.name, main.type)}`;
    await upload(path, main.bytes, main.type);
    files.push({ path, name: main.name, type: main.type, size: main.bytes.length, role: "invoice" });
  } else files.push(oldFiles[0]);
  // receipts / extra invoices: new ones uploaded, kept ones taken from the old invoice's files (by their place)
  const lineRows = [];
  for (const [i, l] of clean.entries()) {
    const extras = [];
    for (const [j, x] of l.extras.entries()) {
      let file: string | null = null;
      if (x.in.file && x.in.file.base64) {
        const d = decode(x.in.file, `Išlaida „${x.what}“`), nm = cleanName(x.in.file.name || "cekis");
        const path = `${owner}/portal/${id}/islaida-${ts}-${i + 1}-${j + 1}.${extOf(nm, d.type)}`;
        await upload(path, d.bytes, d.type);
        files.push({ path, name: `Išlaida – ${x.what} (${nm})`.slice(0, 160), type: d.type, size: d.bytes.length, role: "receipt" });
        file = path;
      } else if (typeof x.in.keep === "number" && oldFiles[x.in.keep] && oldFiles[x.in.keep].role === "receipt") {
        files.push(oldFiles[x.in.keep]); file = oldFiles[x.in.keep].path;
      }
      extras.push({ what: x.what, amount: x.amount, file });
    }
    const { extras: _e, ...rest } = l;
    lineRows.push({ ...rest, extras });
  }
  const row = {
    number: String(b.number || "").trim().slice(0, 80) || null, amount: total, note: String(b.note || "").trim().slice(0, 1000) || null,
    lines: lineRows, files, ext_name: s.name, ...(scan ? { file_total: scan.total, file_check: "ok" } : {}),
  };
  const cs = Deno.env.get("CRON_SECRET");
  if (old) {
    const why = old.status === "rejected" ? "Pataisė netvirtintą sąskaitą" + (old.decision_note ? " (priežastis buvo: „" + old.decision_note + "“)" : "") : "Pataisė sąskaitą";
    await db(`invoices?id=eq.${old.id}`, {
      method: "PATCH", headers: { Prefer: "return=minimal" },
      body: JSON.stringify({
        ...row, status: "new", decision_note: null, decision_by: null, decision_at: null, remind_at: null, reminded_at: null,
        checked_at: null, checked_by: null,   // corrected: the office checks it again
        responses: [...(old.responses || []), { at: new Date().toISOString(), who: s.name, kind: "reply", text: why, src: "portal", ...(old.status === "rejected" ? { rejected_at: old.decision_at, reason: old.decision_note || "" } : {}) }],
      }),
    });
    const gone = oldFiles.filter((x) => !files.some((y) => y.path === x.path)).map((x) => x.path);
    if (gone.length) await fetch(`${SUPABASE_URL}/storage/v1/object/invoice-files`, { method: "DELETE", headers: hdr({ "Content-Type": "application/json" }), body: JSON.stringify({ prefixes: gone }) }).catch(() => {});
  } else {
    await db("invoices", {
      method: "POST", headers: { Prefer: "return=minimal" },
      body: JSON.stringify({ ...row, id, created_by: owner, kind: "freelance", supplier: s.name, invoice_date: today(), ext_email: s.email, source: "portal", uploader_seen: true }),
    });
  }
  // Admin+ are told (push-notify, with the cron secret)
  if (cs) await fetch(SUPABASE_URL + "/functions/v1/push-notify", { method: "POST", headers: { "Content-Type": "application/json", "x-cron-secret": cs }, body: JSON.stringify({ mode: "invoice-portal", invoice_id: id, edited: !!old }) }).catch(() => {});
  return { ok: true, id, total, edited: !!old };
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
      // file paths stay on the server: a receipt is named by its place in the invoice's files
      const fixL = (v: Mine) => (v.lines || []).map((l) => {
        const x = l as { extras?: { file?: string | null }[] };
        return { ...x, extras: (x.extras || []).map((e) => ({ ...e, file: undefined, file_idx: e.file ? v.files.findIndex((f) => f.path === e.file) : -1 })) };
      });
      return json({ invoices: rows.map((v) => {
        // the last word of the office: corrections asked (and not sent again since)
        const fix = [...(v.check_msgs || [])].reverse().find((m) => m.kind === "fix" || m.kind === "ok");
        return { ...v, lines: fixL(v), files: (v.files || []).map((f) => ({ name: f.name, type: f.type, size: f.size })), responses: undefined, check_msgs: undefined, history: history(v), editable: EDITABLE.includes(v.status),
          ...(fix?.kind === "fix" && v.status === "new" ? { fix_note: fix.text || "" } : {}) };
      }) });
    }
    if (action === "file") {
      const s = await session(b.token);
      const [v] = await mine(s.email, String(b.id || ""));
      const f = v?.files?.[Math.max(0, Number(b.idx) || 0)]; if (!f) throw new UserError("Failas nerastas.");
      const r = await fetch(`${SUPABASE_URL}/storage/v1/object/sign/invoice-files/${f.path.split("/").map(enc).join("/")}`, { method: "POST", headers: hdr({ "Content-Type": "application/json" }), body: JSON.stringify({ expiresIn: 600 }) });
      const d = await r.json().catch(() => ({})) as { signedURL?: string };
      if (!r.ok || !d.signedURL) throw new Error("sign " + r.status);
      return json({ url: SUPABASE_URL + "/storage/v1" + d.signedURL });
    }
    if (action === "scan") {
      const s = await session(b.token);
      const f = (b.file || {}) as { type?: string; base64?: string };
      if (!f.base64) throw new UserError("Nėra failo.");
      if (f.base64.length > MAX_FILE * 1.4) throw new UserError("Failas per didelis (iki 10 MB).");
      return json(await scanCached(s as never, f.base64, String(f.type || "")));
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
