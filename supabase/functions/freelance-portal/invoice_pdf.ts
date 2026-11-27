// A simple invoice made on saskaitos.eventsolutions.lt (LR Buhalterinės apskaitos įstatymas 13 str.: document name,
// series and number, date, seller and buyer details, what was done, amounts; a VAT payer – PVM įstatymas 80 str.:
// „PVM sąskaita faktūra“, both VAT codes, the amount without VAT, the VAT rate and amount).
// The libraries and the fonts are passed in (the server gives Deno's, a test gives Node's).

export type Seller = { kind: "iv" | "vl" | "mb" | "uab" | "kita"; name: string; code: string; address: string; vat?: string; iban: string; bank?: string; email?: string; phone?: string };
export type Buyer = { name: string; code: string; vat: string; address: string };
export type InvLine = { text: string; qty: number; unit: string; total: number };   // total – with taxes (as agreed)
export type InvData = { seller: Seller; buyer: Buyer; series: string; number: string; date: string; due?: string; lines: InvLine[]; note?: string };

export const BUYER: Buyer = { name: "UAB „Centas plius“ (Event Solutions)", code: "300062528", vat: "LT100001285010", address: "Kuršmarių g. 8, Rusnė, LT-99348 Šilutės r." };
export const VAT_RATE = 21;
const CODE_LABEL: Record<string, string> = { iv: "Individualios veiklos pažymos Nr.", vl: "Verslo liudijimo Nr.", mb: "Įmonės kodas", uab: "Įmonės kodas", kita: "Kodas" };

const r2 = (n: number) => Math.round(n * 100) / 100;
const money = (n: number) => r2(n).toLocaleString("lt-LT", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

// the sum in words: „šimtas penkiasdešimt eurų 00 ct“
const ONES = ["", "vienas", "du", "trys", "keturi", "penki", "šeši", "septyni", "aštuoni", "devyni"];
const TEENS = ["dešimt", "vienuolika", "dvylika", "trylika", "keturiolika", "penkiolika", "šešiolika", "septyniolika", "aštuoniolika", "devyniolika"];
const TENS = ["", "", "dvidešimt", "trisdešimt", "keturiasdešimt", "penkiasdešimt", "šešiasdešimt", "septyniasdešimt", "aštuoniasdešimt", "devyniasdešimt"];
function form(n: number, one: string, few: string, many: string) { const t = n % 100, u = n % 10; return t >= 10 && t <= 20 || u === 0 ? many : u === 1 ? one : few; }
function upTo999(n: number): string {
  const h = Math.floor(n / 100), rest = n % 100, w: string[] = [];
  if (h) w.push(h === 1 ? "šimtas" : ONES[h] + " šimtai");
  if (rest >= 10 && rest < 20) w.push(TEENS[rest - 10]);
  else { if (Math.floor(rest / 10)) w.push(TENS[Math.floor(rest / 10)]); if (rest % 10) w.push(ONES[rest % 10]); }
  return w.join(" ");
}
export function sumWords(total: number): string {
  const eur = Math.floor(r2(total) + 1e-9), ct = Math.round((r2(total) - eur) * 100);
  const parts: string[] = [];
  const mil = Math.floor(eur / 1e6), th = Math.floor((eur % 1e6) / 1000), rest = eur % 1000;
  if (mil) parts.push(upTo999(mil) + " " + form(mil, "milijonas", "milijonai", "milijonų"));
  if (th) parts.push(upTo999(th) + " " + form(th, "tūkstantis", "tūkstančiai", "tūkstančių"));
  if (rest || !parts.length) parts.push(rest ? upTo999(rest) : "nulis");
  const s = parts.join(" ").replace(/\s+/g, " ").trim();
  return s.charAt(0).toUpperCase() + s.slice(1) + " " + form(eur, "euras", "eurai", "eurų") + " " + String(ct).padStart(2, "0") + " ct";
}
export function totals(d: InvData) {
  const vat = !!String(d.seller.vat || "").trim();
  const total = r2(d.lines.reduce((t, l) => t + l.total, 0));
  const net = vat ? r2(total / (1 + VAT_RATE / 100)) : total;
  return { vat, total, net, vatSum: r2(total - net) };
}

// deps: { PDFDocument, rgb, fontkit, regular: Uint8Array, bold: Uint8Array }
// deno-lint-ignore no-explicit-any
export async function buildInvoicePdf(d: InvData, deps: any): Promise<Uint8Array> {
  const { PDFDocument, rgb, fontkit } = deps;
  const doc = await PDFDocument.create();
  doc.registerFontkit(fontkit);
  const F = await doc.embedFont(deps.regular, { subset: true }), B = await doc.embedFont(deps.bold, { subset: true });
  const t = totals(d), title = t.vat ? "PVM SĄSKAITA FAKTŪRA" : "SĄSKAITA FAKTŪRA";
  doc.setTitle(`${title} ${d.series}${d.number}`); doc.setAuthor(d.seller.name); doc.setCreator("saskaitos.eventsolutions.lt");
  let page = doc.addPage([595.28, 841.89]);
  const W = 595.28, M = 46, ink = rgb(0.1, 0.1, 0.12), dim = rgb(0.42, 0.42, 0.46), line = rgb(0.82, 0.82, 0.85);
  let y = 841.89 - 56;
  // deno-lint-ignore no-explicit-any
  const text = (s: string, x: number, yy: number, o: any = {}) => page.drawText(String(s), { x, y: yy, size: o.size || 9.5, font: o.bold ? B : F, color: o.color || ink });
  const width = (s: string, size = 9.5, bold = false) => (bold ? B : F).widthOfTextAtSize(String(s), size);
  const wrap = (s: string, maxW: number, size = 9.5, bold = false) => {
    const out: string[] = []; for (const para of String(s || "").split("\n")) { let cur = "";
      for (const w of para.split(/\s+/)) { const nx = cur ? cur + " " + w : w; if (width(nx, size, bold) > maxW && cur) { out.push(cur); cur = w; } else cur = nx; } out.push(cur); }
    return out;
  };
  const right = (s: string, xr: number, yy: number, o: { size?: number; bold?: boolean } = {}) => text(s, xr - width(s, o.size || 9.5, !!o.bold), yy, o);
  // the head
  text(title, M, y, { size: 17, bold: true });
  right(`Serija ${d.series} Nr. ${d.number}`, W - M, y + 2, { size: 11, bold: true });
  y -= 18; right(`Data: ${d.date}`, W - M, y);
  if (d.due) { y -= 13; right(`Apmokėti iki: ${d.due}`, W - M, y); }
  y -= 26;
  // the parties
  const col = (x: number, head: string, rows: string[]) => { let yy = y; text(head, x, yy, { size: 8.5, bold: true, color: dim }); yy -= 14;
    rows.filter(Boolean).forEach((r, i) => { wrap(r, (W - 2 * M) / 2 - 16, 9.5, i === 0).forEach((ln) => { text(ln, x, yy, { bold: i === 0 }); yy -= 12.5; }); }); return yy; };
  const s = d.seller;
  const yl = col(M, "PARDAVĖJAS", [s.name, `${CODE_LABEL[s.kind] || "Kodas"} ${s.code}`, s.vat ? `PVM mokėtojo kodas ${s.vat}` : "", s.address, `A. s. ${s.iban}${s.bank ? ", " + s.bank : ""}`, [s.phone, s.email].filter(Boolean).join(", ")]);
  const yr = col(W / 2 + 8, "PIRKĖJAS", [d.buyer.name, `Įmonės kodas ${d.buyer.code}`, `PVM mokėtojo kodas ${d.buyer.vat}`, d.buyer.address]);
  y = Math.min(yl, yr) - 14;
  // the table
  // the right edges of the number columns (the headers fit above them)
  const cx = { nr: M, name: M + 24, unit: W - M - 232, qty: W - M - 168, price: W - M - 140, sum: W - M };
  const head = () => { page.drawRectangle({ x: M, y: y - 5, width: W - 2 * M, height: 19, color: rgb(0.95, 0.95, 0.97) });
    text("Nr.", cx.nr + 3, y, { size: 8.5, bold: true }); text("Paslaugos pavadinimas", cx.name, y, { size: 8.5, bold: true }); text("Mato vnt.", cx.unit, y, { size: 8.5, bold: true });
    right("Kiekis", cx.qty + 30, y, { size: 8.5, bold: true }); right(t.vat ? "Kaina be PVM, €" : "Kaina, €", cx.price + 72, y, { size: 8.5, bold: true }); right(t.vat ? "Suma be PVM, €" : "Suma, €", cx.sum - 3, y, { size: 8.5, bold: true }); y -= 20; };
  head();
  d.lines.forEach((l, i) => {
    const lt = t.vat ? r2(l.total / (1 + VAT_RATE / 100)) : l.total, price = l.qty ? r2(lt / l.qty) : lt;
    const rows = wrap(l.text, cx.unit - cx.name - 8);
    if (y - rows.length * 12 < 120) { page = doc.addPage([595.28, 841.89]); y = 841.89 - 56; head(); }
    text(String(i + 1), cx.nr + 3, y); rows.forEach((r, k) => text(r, cx.name, y - k * 12)); text(l.unit, cx.unit, y);
    right(String(l.qty).replace(".", ","), cx.qty + 30, y); right(money(price), cx.price + 72, y); right(money(lt), cx.sum - 3, y);
    y -= Math.max(1, rows.length) * 12 + 5;
    page.drawLine({ start: { x: M, y: y + 8 }, end: { x: W - M, y: y + 8 }, thickness: 0.5, color: line });
  });
  // the totals
  y -= 8;
  const tot = (label: string, v: string, bold = false) => { right(label, cx.price + 72, y, { bold }); right(v, cx.sum - 3, y, { bold }); y -= 14; };
  if (t.vat) { tot("Suma be PVM:", money(t.net) + " €"); tot(`PVM ${VAT_RATE} %:`, money(t.vatSum) + " €"); tot("Iš viso su PVM:", money(t.total) + " €", true); }
  else tot("Iš viso:", money(t.total) + " €", true);
  y -= 6;
  wrap("Suma žodžiais: " + sumWords(t.total), W - 2 * M).forEach((ln) => { text(ln, M, y); y -= 12.5; });
  if (!t.vat) { y -= 2; text("Pardavėjas nėra PVM mokėtojas.", M, y, { color: dim, size: 8.5 }); y -= 12; }
  if (d.note) { y -= 4; wrap("Pastaba: " + d.note, W - 2 * M, 9).forEach((ln) => { text(ln, M, y, { size: 9 }); y -= 12; }); }
  // the signature
  y = Math.max(y - 40, 70);
  text("Sąskaitą išrašė:", M, y, { color: dim }); text(s.kind === "mb" || s.kind === "uab" ? `${s.name} atstovas` : s.name, M + 86, y);
  page.drawLine({ start: { x: M + 86, y: y - 4 }, end: { x: M + 300, y: y - 4 }, thickness: 0.5, color: line });
  text("Sąskaita sukurta saskaitos.eventsolutions.lt", M, 40, { size: 7.5, color: dim });
  return await doc.save();
}
