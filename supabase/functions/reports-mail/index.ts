// Supabase Edge Function: reports-mail
//
// Ataskaitos → Bolt / Wolt: the month's summary as a PDF – the first page the short, important part (who, how
// many trips / orders, how much it cost, for Bolt the personal trips to deduct), then everything in detail
// (Bolt: each trip marked work or personal). Downloaded, sent to the saved addresses, or sent by itself
// (sql/report_mail.sql: e.g. the month's last working day at 16:00).
//
// POST {"kind":"bolt"|"wolt","month":"2026-09","action":"pdf"}   -> application/pdf          (Admin)
// POST {"kind":"bolt"|"wolt","month":"2026-09","action":"send","to"?:[…]} -> {"mailed":n}   (Admin)
// POST {"mode":"cron"}  header x-cron-secret (push-notify's cron, every 5 min) -> the automatic letters that are due
// SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY are given by Supabase; RESEND_API_KEY, REMINDER_FROM, CRON_SECRET – the
// same secrets push-notify uses.

import { PDFDocument, rgb, type PDFFont, type PDFPage, type RGB } from "npm:pdf-lib@1.17.1";
import fontkit from "npm:@pdf-lib/fontkit@1.1.1";
import { BARLOW_MEDIUM, BARLOW_REGULAR } from "./fonts.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" } });
const env = (n: string) => Deno.env.get(n) ?? "";

async function db<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${env("SUPABASE_URL")}/rest/v1/${path}`, {
    ...init,
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`Database ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const t = await res.text();
  return (t ? JSON.parse(t) : null) as T;
}
// all the rows (PostgREST gives at most 1000 at a time)
async function dbAll<T>(path: string): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; ; from += 1000) {
    const part = await db<T[]>(path, { headers: { Range: `${from}-${from + 999}`, "Range-Unit": "items" } });
    out.push(...part);
    if (part.length < 1000) return out;
  }
}
async function caller(req: Request): Promise<string | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const res = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, { headers: { apikey: env("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` } });
  if (!res.ok) return null;
  const u = await res.json();
  return u?.id ?? null;
}
type Profile = { id: string; role: string; first_name: string | null; last_name: string | null; full_name: string | null; nickname: string | null; email: string };
const pname = (p?: Profile) => !p ? "" : p.nickname || [p.first_name, p.last_name].filter(Boolean).join(" ") || p.full_name || p.email.split("@")[0];

/* ---------- months, days (Vilnius), Lithuanian holidays ---------- */
const MONTHS = ["sausis", "vasaris", "kovas", "balandis", "gegužė", "birželis", "liepa", "rugpjūtis", "rugsėjis", "spalis", "lapkritis", "gruodis"];
const monthName = (m: string) => `${m.slice(0, 4)} m. ${MONTHS[+m.slice(5, 7) - 1] ?? ""}`;
const lastDay = (m: string) => new Date(Date.UTC(+m.slice(0, 4), +m.slice(5, 7), 0)).getUTCDate();
const monthShift = (m: string, k: number) => { const d = new Date(Date.UTC(+m.slice(0, 4), +m.slice(5, 7) - 1 + k, 1)); return d.toISOString().slice(0, 7); };
function vilnius(d = new Date()) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Vilnius", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false })
    .formatToParts(d).map((x) => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, hour: +p.hour % 24, minute: +p.minute };
}
function easter(y: number): string {   // Gregorian Easter Sunday
  const a = y % 19, b = Math.floor(y / 100), c = y % 100, d = Math.floor(b / 4), e = b % 4, f = Math.floor((b + 8) / 25), g = Math.floor((b - f + 1) / 3);
  const h = (19 * a + b - d - g + 15) % 30, i = Math.floor(c / 4), k = c % 4, l = (32 + 2 * e + 2 * i - h - k) % 7, m = Math.floor((a + 11 * h + 22 * l) / 451);
  const mo = Math.floor((h + l - 7 * m + 114) / 31), da = ((h + l - 7 * m + 114) % 31) + 1;
  return `${y}-${String(mo).padStart(2, "0")}-${String(da).padStart(2, "0")}`;
}
function workday(iso: string): boolean {
  const d = new Date(iso + "T12:00:00Z"), wd = d.getUTCDay();
  if (wd === 0 || wd === 6) return false;
  const md = iso.slice(5);
  if (["01-01", "02-16", "03-11", "05-01", "06-24", "07-06", "08-15", "11-01", "11-02", "12-24", "12-25", "12-26"].includes(md)) return false;
  const e = new Date(easter(d.getUTCFullYear()) + "T12:00:00Z"); e.setUTCDate(e.getUTCDate() + 1);   // Velykų antroji diena
  return e.toISOString().slice(0, 10) !== iso;
}
type Setting = { kind: string; emails: string[]; auto: boolean; rule: string; day: number; hour: number; period: string; last_auto: string | null };
function dueDay(s: Setting, m: string): string {
  const days = Array.from({ length: lastDay(m) }, (_, i) => `${m}-${String(i + 1).padStart(2, "0")}`);
  if (s.rule === "first_workday") return days.find(workday) ?? days[0];
  if (s.rule === "day") return days[Math.min(Math.max(1, s.day || 1), days.length) - 1];
  return [...days].reverse().find(workday) ?? days[days.length - 1];
}

/* ---------- money, text ---------- */
const eur = (n: number) => (Math.round(n * 100) / 100).toLocaleString("lt-LT", { minimumFractionDigits: 2, maximumFractionDigits: 2 }).replace(/ /g, " ") + " €";
const day = (s: string | null) => s ? s.slice(0, 10).split("-").reverse().slice(0, 2).join(".") : "";
const hm = (iso: string | null) => { if (!iso) return ""; const t = new Intl.DateTimeFormat("lt-LT", { timeZone: "Europe/Vilnius", hour: "2-digit", minute: "2-digit" }).format(new Date(iso)); return t === "00:00" ? "" : t; };
// only the letters the PDF font has (Latin, Lithuanian, punctuation, €); anything else – away
const clean = (s: unknown) => String(s ?? "").replace(/→/g, "–").replace(/[\t\r\n]+/g, " ")
  .replace(/[^ -~ -ſ‐-‧€№·]/g, "").replace(/\s+/g, " ").trim();
const escHtml = (s: unknown) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/* ---------- the PDF: pages, text that wraps, tables that go on to the next page ---------- */
const INK = rgb(0.07, 0.07, 0.07), DIM = rgb(0.42, 0.42, 0.45), LINE = rgb(0.86, 0.86, 0.88), HEAD = rgb(0.95, 0.95, 0.96);
const PINK = rgb(0.85, 0.2, 0.36), PERS_BG = rgb(1, 0.94, 0.95), WORK = rgb(0.18, 0.55, 0.47), RED = rgb(0.7, 0.05, 0.15);
type Col = { t: string; w: number; right?: boolean };
type Cell = string | { t: string; bold?: boolean; color?: RGB };
class Pdf {
  doc!: PDFDocument; f!: PDFFont; b!: PDFFont; page!: PDFPage; y = 0; n = 0;
  W = 595.28; H = 841.89; M = 36; foot = "";
  static async make(foot: string) {
    const p = new Pdf(); p.foot = foot;
    p.doc = await PDFDocument.create(); p.doc.registerFontkit(fontkit);
    const bytes = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    p.f = await p.doc.embedFont(bytes(BARLOW_REGULAR), { subset: true });
    p.b = await p.doc.embedFont(bytes(BARLOW_MEDIUM), { subset: true });
    p.add();
    return p;
  }
  add() {
    this.page = this.doc.addPage([this.W, this.H]); this.n++; this.y = this.H - this.M;
    this.page.drawText(clean(this.foot), { x: this.M, y: 18, size: 8, font: this.f, color: DIM });
    const pn = `${this.n} psl.`; this.page.drawText(pn, { x: this.W - this.M - this.f.widthOfTextAtSize(pn, 8), y: 18, size: 8, font: this.f, color: DIM });
  }
  need(h: number) { if (this.y - h < this.M + 14) { this.add(); return true; } return false; }
  wrap(s: string, w: number, size: number, font: PDFFont): string[] {
    const words = clean(s).split(" "), out: string[] = []; let line = "";
    for (const wd of words) {
      const t = line ? line + " " + wd : wd;
      if (font.widthOfTextAtSize(t, size) <= w) { line = t; continue; }
      if (line) out.push(line);
      line = wd;
      while (font.widthOfTextAtSize(line, size) > w && line.length > 1) {   // a very long word: cut
        let k = line.length - 1; while (k > 1 && font.widthOfTextAtSize(line.slice(0, k), size) > w) k--;
        out.push(line.slice(0, k)); line = line.slice(k);
      }
    }
    if (line || !out.length) out.push(line);
    return out;
  }
  text(s: string, size = 10, o: { font?: PDFFont; color?: RGB; gap?: number; x?: number; w?: number } = {}) {
    const font = o.font ?? this.f, x = o.x ?? this.M, w = o.w ?? this.W - 2 * this.M;
    for (const l of this.wrap(s, w, size, font)) { this.need(size + 3); this.page.drawText(l, { x, y: this.y - size, size, font, color: o.color ?? INK }); this.y -= size + 3; }
    this.y -= o.gap ?? 0;
  }
  // the short numbers on the first page, in boxes
  kpis(items: { k: string; v: string; red?: boolean }[]) {
    const gap = 8, w = (this.W - 2 * this.M - gap * (items.length - 1)) / items.length, h = 46;
    this.need(h + 8);
    items.forEach((it, i) => {
      const x = this.M + i * (w + gap);
      this.page.drawRectangle({ x, y: this.y - h, width: w, height: h, color: it.red ? PERS_BG : HEAD, borderColor: LINE, borderWidth: 0.6 });
      this.page.drawText(clean(it.k), { x: x + 8, y: this.y - 15, size: 8.5, font: this.f, color: DIM });
      const v = clean(it.v); let size = 14; while (size > 8 && this.b.widthOfTextAtSize(v, size) > w - 16) size -= 0.5;
      this.page.drawText(v, { x: x + 8, y: this.y - 36, size, font: this.b, color: it.red ? RED : INK });
    });
    this.y -= h + 12;
  }
  table(cols: Col[], rows: Cell[][], o: { size?: number; tint?: (i: number) => RGB | null; boldRow?: (i: number) => boolean } = {}) {
    const size = o.size ?? 9, pad = 4, total = cols.reduce((a, c) => a + c.w, 0), k = (this.W - 2 * this.M) / total;
    const ws = cols.map((c) => c.w * k);
    const head = () => {
      const h = size + 2 * pad + 2;
      this.page.drawRectangle({ x: this.M, y: this.y - h, width: this.W - 2 * this.M, height: h, color: HEAD });
      let x = this.M;
      cols.forEach((c, i) => { const t = clean(c.t); const tw = this.b.widthOfTextAtSize(t, size - 0.5);
        this.page.drawText(t, { x: c.right ? x + ws[i] - pad - tw : x + pad, y: this.y - pad - size + 0.5, size: size - 0.5, font: this.b, color: DIM }); x += ws[i]; });
      this.y -= h;
    };
    this.need(3 * (size + 2 * pad)); head();
    rows.forEach((r, ri) => {
      const bold = o.boldRow?.(ri) ?? false;
      const lines = r.map((c, i) => { const cc = typeof c === "string" ? { t: c } : c; return this.wrap(cc.t, ws[i] - 2 * pad, size, cc.bold || bold ? this.b : this.f); });
      const h = Math.max(...lines.map((l) => l.length)) * (size + 2) + 2 * pad;
      if (this.need(h)) head();
      const tint = o.tint?.(ri);
      if (tint) this.page.drawRectangle({ x: this.M, y: this.y - h, width: this.W - 2 * this.M, height: h, color: tint });
      let x = this.M;
      r.forEach((c, i) => {
        const cc = typeof c === "string" ? { t: c } : c, font = cc.bold || bold ? this.b : this.f;
        lines[i].forEach((l, li) => {
          const tw = font.widthOfTextAtSize(l, size);
          this.page.drawText(l, { x: cols[i].right ? x + ws[i] - pad - tw : x + pad, y: this.y - pad - size - li * (size + 2) + 1, size, font, color: cc.color ?? INK });
        });
        x += ws[i];
      });
      this.page.drawLine({ start: { x: this.M, y: this.y - h }, end: { x: this.W - this.M, y: this.y - h }, thickness: 0.5, color: LINE });
      this.y -= h;
    });
    this.y -= 10;
  }
  async bytes() { return await this.doc.save(); }
}

/* ---------- Bolt ---------- */
type Trip = { id: string; trip_at: string | null; trip_on: string | null; person_name: string; person_id: string | null; vehicle_cat: string | null; from_addr: string; to_addr: string; amount: number | null; note: string; kind: string; kind_manual: boolean };
type Person = { name: string; member: boolean; n: number; sum: number; wn: number; ws: number; pn: number; ps: number; list: Trip[] };
async function boltData(m: string) {
  const trips = await dbAll<Trip>(`bolt_trips?select=id,trip_at,trip_on,person_name,person_id,vehicle_cat,from_addr,to_addr,amount,note,kind,kind_manual&trip_on=gte.${m}-01&trip_on=lte.${m}-${lastDay(m)}&order=trip_at.asc.nullsfirst,trip_on.asc`);
  const ids = [...new Set(trips.map((t) => t.person_id).filter(Boolean))] as string[];
  const ps = ids.length ? await db<Profile[]>(`profiles?select=id,role,first_name,last_name,full_name,nickname,email&id=in.(${ids.map((i) => `"${i}"`).join(",")})`) : [];
  const by = new Map<string, Person>();
  for (const t of trips) {
    const p = t.person_id ? ps.find((x) => x.id === t.person_id) : undefined, name = clean(pname(p) || t.person_name || "Nežinomas"), key = t.person_id || "n:" + name.toLowerCase();
    const g = by.get(key) ?? { name, member: !!t.person_id, n: 0, sum: 0, wn: 0, ws: 0, pn: 0, ps: 0, list: [] };
    const a = +(t.amount ?? 0) || 0;
    g.n++; g.sum += a; if (t.kind === "work") { g.wn++; g.ws += a; } else { g.pn++; g.ps += a; }
    g.list.push(t); by.set(key, g);
  }
  const when = (t: Trip) => t.trip_at || (t.trip_on ? t.trip_on + "T00:00:00Z" : "");
  by.forEach((g) => g.list.sort((a, b) => when(a).localeCompare(when(b))));
  const people = [...by.values()].sort((a, b) => b.sum - a.sum || a.name.localeCompare(b.name, "lt"));
  const tot = people.reduce((a, p) => ({ n: a.n + p.n, sum: a.sum + p.sum, wn: a.wn + p.wn, ws: a.ws + p.ws, pn: a.pn + p.pn, ps: a.ps + p.ps, ded: a.ded + (p.member ? p.ps : 0) }), { n: 0, sum: 0, wn: 0, ws: 0, pn: 0, ps: 0, ded: 0 });
  return { people, tot };
}
async function boltPdf(m: string, who: string) {
  const { people, tot } = await boltData(m);
  const P = await Pdf.make(`Bolt · ${monthName(m)} · sudaryta ${vilnius().date} ${who ? "· " + who : ""}`);
  P.text("Bolt kelionių ataskaita", 20, { font: P.b, gap: 2 });
  P.text(monthName(m), 12, { color: DIM, gap: 10 });
  if (!people.length) { P.text("Šio mėnesio Bolt kelionių dar nėra (ataskaita neįkelta).", 11); return { pdf: await P.bytes(), people, tot }; }
  P.kpis([{ k: "Kelionių", v: String(tot.n) }, { k: "Iš viso kainavo", v: eur(tot.sum) }, { k: `Darbo (${tot.wn})`, v: eur(tot.ws) }, { k: `Asmeninės (${tot.pn})`, v: eur(tot.ps) }, { k: "Išskaičiuoti", v: eur(tot.ded), red: tot.ded > 0 }]);
  P.text("Kas kiek keliavo", 12, { font: P.b, gap: 2 });
  P.table([{ t: "Vardas", w: 30 }, { t: "Kelionių", w: 10, right: true }, { t: "Kainavo", w: 14, right: true }, { t: "Darbo", w: 16, right: true }, { t: "Asmeninės", w: 16, right: true }, { t: "Išskaičiuoti", w: 14, right: true }],
    people.map((p) => [p.name + (p.member ? "" : " (ne narys)"), String(p.n), eur(p.sum), `${p.wn} · ${eur(p.ws)}`, `${p.pn} · ${eur(p.ps)}`,
      p.member && p.ps > 0 ? { t: eur(p.ps), bold: true, color: RED } : p.ps > 0 ? { t: "—", color: DIM } : eur(0)])
      .concat([[{ t: "Iš viso", bold: true }, { t: String(tot.n), bold: true }, { t: eur(tot.sum), bold: true }, { t: `${tot.wn} · ${eur(tot.ws)}`, bold: true }, { t: `${tot.pn} · ${eur(tot.ps)}`, bold: true }, { t: eur(tot.ded), bold: true, color: tot.ded ? RED : INK }]]),
    { tint: (i) => i === people.length ? HEAD : null });
  const ded = people.filter((p) => p.member && p.ps > 0);
  if (ded.length) {
    P.text("Išskaičiuoti iš atlyginimo (asmeninės kelionės)", 12, { font: P.b, gap: 2 });
    ded.forEach((p) => P.text(`${p.name}: ${eur(p.ps)} (${p.pn} ${p.pn === 1 ? "kelionė" : p.pn % 10 >= 2 && p.pn % 10 <= 9 && (p.pn % 100 < 12 || p.pn % 100 > 19) ? "kelionės" : "kelionių"})`, 10.5, { x: P.M + 8 }));
    P.y -= 6;
  }
  P.text("Asmeninė kelionė – be įrašyto tikslo, „P“ ar „asmeninė“ (arba pažymėta tikrinant). Išskaičiuoti – programos nariams: jų asmeninės kelionės įmonės nepadengiamos. Ne nariams išskaičiavimas neskaičiuojamas.", 8.5, { color: DIM });
  // the second page on: every trip, by person
  P.add();
  P.text("Visos kelionės", 15, { font: P.b, gap: 2 });
  P.text(`${monthName(m)} · asmeninės pažymėtos rausvai`, 9.5, { color: DIM, gap: 8 });
  for (const p of people) {
    P.need(60);
    P.text(`${p.name}${p.member ? "" : " (ne narys)"} – ${p.n} kel. · ${eur(p.sum)} · darbo ${eur(p.ws)} · asmeninės ${eur(p.ps)}`, 10.5, { font: P.b, gap: 2 });
    P.table([{ t: "Data", w: 11 }, { t: "Iš – Į", w: 40 }, { t: "Kelionės priežastis", w: 27 }, { t: "Tipas", w: 10 }, { t: "Kaina", w: 12, right: true }],
      p.list.map((t) => [`${day(t.trip_on)} ${hm(t.trip_at)}`.trim(), `${clean(t.from_addr) || "—"} – ${clean(t.to_addr) || "—"}`, (clean(t.note) || "—") + (t.kind_manual ? " (pakeista ranka)" : ""),
        t.kind === "work" ? { t: "Darbo", color: WORK } : { t: "Asmeninė", bold: true, color: PINK }, t.amount != null ? eur(+t.amount) : ""]),
      { size: 8.5, tint: (i) => p.list[i].kind === "work" ? null : PERS_BG });
  }
  return { pdf: await P.bytes(), people, tot };
}

/* ---------- Wolt ---------- */
type Order = { report_id: string; order_at: string | null; order_on: string | null; person_name: string; venue: string; amount: number | null };
async function woltData(m: string) {
  const reps = await db<{ id: string; total: number | null; orders: number }[]>(`wolt_reports?select=id,total,orders&month=eq.${m}`);
  const orders = reps.length ? await dbAll<Order>(`wolt_orders?select=report_id,order_at,order_on,person_name,venue,amount&report_id=in.(${reps.map((r) => r.id).join(",")})&order=order_at.asc.nullsfirst,order_on.asc`) : [];
  let n = 0, sum = 0;
  reps.forEach((r) => { const os = orders.filter((o) => o.report_id === r.id); n += os.length || r.orders || 0; sum += os.length ? os.reduce((s, o) => s + (+(o.amount ?? 0) || 0), 0) : +(r.total ?? 0) || 0; });
  const group = (k: "person_name" | "venue") => { const g = new Map<string, { name: string; n: number; sum: number; list: Order[] }>();
    orders.forEach((o) => { const name = clean(o[k]) || (k === "person_name" ? "Nenurodyta" : "—"); const x = g.get(name) ?? { name, n: 0, sum: 0, list: [] }; x.n++; x.sum += +(o.amount ?? 0) || 0; x.list.push(o); g.set(name, x); });
    return [...g.values()].sort((a, b) => b.sum - a.sum); };
  return { reps, orders, n, sum, people: group("person_name"), venues: group("venue") };
}
async function woltPdf(m: string, who: string) {
  const W = await woltData(m);
  const P = await Pdf.make(`Wolt · ${monthName(m)} · sudaryta ${vilnius().date} ${who ? "· " + who : ""}`);
  P.text("Wolt užsakymų ataskaita", 20, { font: P.b, gap: 2 });
  P.text(monthName(m), 12, { color: DIM, gap: 10 });
  if (!W.reps.length) { P.text("Šio mėnesio Wolt suvestinė dar neįkelta.", 11); return { pdf: await P.bytes(), W }; }
  P.kpis([{ k: "Užsakymų", v: String(W.n) }, { k: "Išleista", v: eur(W.sum) }, { k: "Vidutinis užsakymas", v: W.n ? eur(W.sum / W.n) : "—" }, { k: "Užsakė žmonių", v: String(W.people.length || "—") }]);
  if (W.people.length) {
    P.text("Kas kiek užsakė", 12, { font: P.b, gap: 2 });
    P.table([{ t: "Vardas", w: 50 }, { t: "Užsakymų", w: 20, right: true }, { t: "Suma", w: 30, right: true }],
      W.people.map((p) => [p.name, String(p.n), eur(p.sum)]).concat([[{ t: "Iš viso", bold: true }, { t: String(W.n), bold: true }, { t: eur(W.sum), bold: true }]]), { tint: (i) => i === W.people.length ? HEAD : null });
  }
  if (W.venues.length) {
    P.text("Dažniausi restoranai", 12, { font: P.b, gap: 2 });
    P.table([{ t: "Restoranas", w: 50 }, { t: "Užsakymų", w: 20, right: true }, { t: "Suma", w: 30, right: true }], W.venues.slice(0, 10).map((v) => [v.name, String(v.n), eur(v.sum)]));
  }
  if (!W.orders.length) { P.text("Dokumente užsakymų sąrašo nebuvo – mėnesio suma įrašyta ranka.", 9.5, { color: DIM }); return { pdf: await P.bytes(), W }; }
  P.add();
  P.text("Visi užsakymai", 15, { font: P.b, gap: 2 });
  P.text(monthName(m), 9.5, { color: DIM, gap: 8 });
  for (const p of W.people) {
    P.need(60);
    P.text(`${p.name} – ${p.n} užs. · ${eur(p.sum)}`, 10.5, { font: P.b, gap: 2 });
    P.table([{ t: "Data", w: 16 }, { t: "Restoranas", w: 64 }, { t: "Suma", w: 20, right: true }],
      p.list.map((o) => [`${day(o.order_on)} ${hm(o.order_at)}`.trim(), clean(o.venue) || "—", o.amount != null ? eur(+o.amount) : ""]), { size: 8.5 });
  }
  return { pdf: await P.bytes(), W };
}

/* ---------- the letter ---------- */
function b64(bytes: Uint8Array): string {
  let s = ""; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
async function mailTo(to: string[], subject: string, html: string, file?: { name: string; bytes: Uint8Array }): Promise<string> {
  const key = env("RESEND_API_KEY");
  if (!key) return "RESEND_API_KEY nenustatytas";
  const res = await fetch("https://api.resend.com/emails", {
    signal: AbortSignal.timeout(20000), method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env("REMINDER_FROM") || "Event Solutions <onboarding@resend.dev>", to, subject, html, ...(file ? { attachments: [{ filename: file.name, content: b64(file.bytes) }] } : {}) }),
  });
  return res.ok ? "" : `Resend ${res.status}: ${(await res.text()).slice(0, 200)}`;
}
async function build(kind: string, m: string, who: string) {
  const row = (k: string, v: string, red = false) => `<tr><td style="padding:5px 14px 5px 0;color:#666;">${escHtml(k)}</td><td style="padding:5px 0;"><b style="${red ? "color:#b00020;" : ""}">${escHtml(v)}</b></td></tr>`;
  const wrapHtml = (title: string, inner: string) => `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#111;max-width:640px;">
<div style="font-size:12px;letter-spacing:.5px;text-transform:uppercase;color:#e04e6c;font-weight:bold;">${escHtml(title)}</div>
<h2 style="margin:6px 0 12px;font-size:21px;">${escHtml(monthName(m))}</h2>${inner}
<p style="color:#888;font-size:12px;margin-top:20px;">Detali ataskaita – prisegtame PDF. Išsiuntė Event Solutions programa${who ? " (" + escHtml(who) + ")" : ""}.</p></div>`;
  const th = (t: string, r = false) => `<th style="text-align:${r ? "right" : "left"};padding:6px 8px;background:#f2f2f4;font-size:12px;color:#555;">${escHtml(t)}</th>`;
  const td = (t: string, r = false, st = "") => `<td style="text-align:${r ? "right" : "left"};padding:6px 8px;border-bottom:1px solid #e5e5e8;${st}">${escHtml(t)}</td>`;
  if (kind === "bolt") {
    const { pdf, people, tot } = await boltPdf(m, who);
    const ded = people.filter((p) => p.member && p.ps > 0);
    const inner = !people.length ? `<p>Šio mėnesio Bolt kelionių dar nėra (ataskaita neįkelta).</p>` :
      `<table style="border-collapse:collapse;">${row("Kelionių", String(tot.n))}${row("Iš viso kainavo", eur(tot.sum))}${row(`Darbo kelionės (${tot.wn})`, eur(tot.ws))}${row(`Asmeninės kelionės (${tot.pn})`, eur(tot.ps))}${row("Išskaičiuoti iš viso", eur(tot.ded), tot.ded > 0)}</table>
<table style="border-collapse:collapse;margin-top:14px;width:100%;"><tr>${th("Vardas")}${th("Kelionių", true)}${th("Kainavo", true)}${th("Asmeninės", true)}${th("Išskaičiuoti", true)}</tr>
${people.map((p) => `<tr>${td(p.name + (p.member ? "" : " (ne narys)"))}${td(String(p.n), true)}${td(eur(p.sum), true)}${td(`${p.pn} · ${eur(p.ps)}`, true)}${td(p.member && p.ps ? eur(p.ps) : "—", true, p.member && p.ps ? "color:#b00020;font-weight:bold;" : "color:#999;")}</tr>`).join("")}</table>
${ded.length ? `<p style="margin-top:12px;"><b>Išskaičiuoti:</b> ${ded.map((p) => escHtml(p.name) + " – " + escHtml(eur(p.ps))).join("; ")}.</p>` : `<p style="margin-top:12px;">Išskaičiuoti nereikia – asmeninių kelionių nariams nėra.</p>`}`;
    return { pdf, subject: `Bolt ataskaita – ${monthName(m)}`, html: wrapHtml("Bolt kelionių ataskaita", inner), file: `Bolt_${m}.pdf` };
  }
  const { pdf, W } = await woltPdf(m, who);
  const inner = !W.reps.length ? `<p>Šio mėnesio Wolt suvestinė dar neįkelta.</p>` :
    `<table style="border-collapse:collapse;">${row("Užsakymų", String(W.n))}${row("Išleista", eur(W.sum))}${row("Vidutinis užsakymas", W.n ? eur(W.sum / W.n) : "—")}</table>
${W.people.length ? `<table style="border-collapse:collapse;margin-top:14px;width:100%;"><tr>${th("Vardas")}${th("Užsakymų", true)}${th("Suma", true)}</tr>${W.people.map((p) => `<tr>${td(p.name)}${td(String(p.n), true)}${td(eur(p.sum), true)}</tr>`).join("")}</table>` : ""}`;
  return { pdf, subject: `Wolt ataskaita – ${monthName(m)}`, html: wrapHtml("Wolt užsakymų ataskaita", inner), file: `Wolt_${m}.pdf` };
}
const okMails = (list: unknown[]) => [...new Set(list.map((x) => String(x).trim().toLowerCase()).filter((x) => /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(x)))].slice(0, 20);

/* ---------- the automatic letters (push-notify's cron, every 5 minutes) ---------- */
async function cron() {
  const now = vilnius(), cur = now.date.slice(0, 7), out: unknown[] = [];
  const list = await db<Setting[]>(`report_mail?select=*&auto=eq.true`);
  for (const s of list) {
    if (!s.emails?.length || s.last_auto === cur) continue;
    if (now.date !== dueDay(s, cur) || now.hour < (s.hour ?? 16)) continue;
    const m = s.period === "previous" ? monthShift(cur, -1) : cur;
    let res = "";
    try { const r = await build(s.kind, m, ""); res = await mailTo(okMails(s.emails), r.subject, r.html, { name: r.file, bytes: r.pdf }); }
    catch (e) { res = (e as Error).message; }
    await db(`report_mail?kind=eq.${s.kind}`, { method: "PATCH", headers: { Prefer: "return=minimal" },
      body: JSON.stringify({ last_auto: cur, last_sent_at: new Date().toISOString(), last_result: res ? "Klaida: " + res.slice(0, 300) : `Išsiųsta automatiškai: ${m}` }) });
    out.push({ kind: s.kind, month: m, error: res || undefined });
  }
  return { sent: out };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST" }, 405);
  try {
    const body = await req.json().catch(() => ({}));
    if (body?.mode === "cron") {
      const secret = env("CRON_SECRET");
      if (!secret || req.headers.get("x-cron-secret") !== secret) return json({ error: "Unauthorized" }, 401);
      return json(await cron());
    }
    const uid = await caller(req);
    if (!uid) return json({ error: "Prisijunk iš naujo" }, 401);
    const [me] = await db<Profile[]>(`profiles?select=id,role,first_name,last_name,full_name,nickname,email&id=eq.${uid}`);
    if (!me || me.role !== "admin") return json({ error: "Tik Admin" }, 403);
    const kind = body.kind === "wolt" ? "wolt" : body.kind === "bolt" ? "bolt" : "";
    const m = String(body.month ?? "");
    if (!kind || !/^\d{4}-\d{2}$/.test(m)) return json({ error: "Blogas mėnuo" }, 400);
    const r = await build(kind, m, pname(me));
    if (body.action === "pdf") return new Response(r.pdf, { headers: { ...corsHeaders, "Content-Type": "application/pdf", "Content-Disposition": `attachment; filename="${r.file}"` } });
    if (body.action === "send") {
      let to = okMails(Array.isArray(body.to) ? body.to : []);
      if (!to.length) { const [s] = await db<Setting[]>(`report_mail?select=*&kind=eq.${kind}`); to = okMails(s?.emails ?? []); }
      if (!to.length) return json({ error: "Įrašyk bent vieną el. paštą (Siuntimo nustatymai)" }, 400);
      const err = await mailTo(to, r.subject, r.html, { name: r.file, bytes: r.pdf });
      if (err) return json({ error: err }, 502);
      await db(`report_mail?kind=eq.${kind}`, { method: "PATCH", headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ last_sent_at: new Date().toISOString(), last_result: `Išsiuntė ${pname(me)}: ${m} → ${to.join(", ")}` }) }).catch(() => {});
      return json({ mailed: to.length, to });
    }
    return json({ error: "Nežinomas veiksmas" }, 400);
  } catch (e) {
    return json({ error: "Nepavyko: " + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});
