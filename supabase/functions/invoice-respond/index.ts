// Supabase Edge Function: invoice-respond
//
// The answer to an approved invoice sent by e-mail (public.invoices, see
// supabase/sql/invoices.sql). The letter's buttons open the app
// (./?invresp=<token>&a=paid|queued|reply); the app shows a small page and
// calls this function – no sign-in, the token in the letter is the key.
//
// POST {"t":"<token>"}                                  -> what the letter was about
// POST {"t":"<token>","a":"paid|queued|reply","who":"…","text":"…"} -> saves the answer
//
// After an answer: Admin+ get an app notification (push-notify, mode
// invoice-reply) and the sender plus every recipient of that letter get an
// e-mail with the answer (Resend: RESEND_API_KEY, INVOICE_FROM or REMINDER_FROM).
// Secrets: CRON_SECRET (to call push-notify). SUPABASE_URL and
// SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.

const VERSION = 1;
const DEFAULT_FROM = "Event Solutions <onboarding@resend.dev>";
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const KIND: Record<string, string> = { freelance: "Freelance", service: "Paslaugų", rent: "Nuomos" };
const ANSWER: Record<string, string> = { paid: "Sąskaita apmokėta", queued: "Sąskaita suvesta apmokėjimui", reply: "Atsakymas" };

type Sent = { at: string; by?: string; by_email?: string; to: string[]; comment?: string; token: string };
type Resp = { at: string; who: string; kind: string; text: string; token: string };
type Invoice = { id: string; kind: string; supplier: string | null; number: string | null; amount: number | null; invoice_date: string | null; due_date: string | null; status: string; sent: Sent[]; responses: Resp[] };

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" } });
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
const esc = (s: string) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const money = (n: number | null) => n == null ? "" : Number(n).toFixed(2).replace(".", ",") + " €";
export const invTitle = (v: Pick<Invoice, "kind" | "supplier" | "number" | "amount">) =>
  [KIND[v.kind] ? KIND[v.kind] + " sąskaita" : "Sąskaita", v.supplier || "", v.number ? "nr. " + v.number : "", money(v.amount)].filter(Boolean).join(" · ");

async function byToken(t: string): Promise<{ v: Invoice; s: Sent } | null> {
  if (!/^[A-Za-z0-9_-]{16,80}$/.test(t)) return null;
  const rows = await db<Invoice[]>(`invoices?select=*&sent=cs.${encodeURIComponent(JSON.stringify([{ token: t }]))}`);
  const v = rows[0]; if (!v) return null;
  const s = (v.sent || []).find((x) => x.token === t); return s ? { v, s } : null;
}

async function mailAnswer(v: Invoice, s: Sent, r: Resp) {
  const key = Deno.env.get("RESEND_API_KEY"); if (!key) return { mailed: 0, note: "RESEND_API_KEY not set" };
  const to = [...new Set([s.by_email, ...(s.to || [])].filter(Boolean).map((x) => String(x).toLowerCase()))];
  if (!to.length) return { mailed: 0 };
  const html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;line-height:1.5;">
    <p><b>${esc(ANSWER[r.kind] || "Atsakymas")}</b> — ${esc(invTitle(v))}</p>
    <p>Atsakė: <b>${esc(r.who || "—")}</b></p>
    ${r.text ? `<p style="white-space:pre-wrap;border-left:3px solid #F35E7D;padding-left:10px;">${esc(r.text)}</p>` : ""}
    <p style="color:#777;font-size:12px;margin-top:18px;">Event Solutions · automatinis pranešimas</p></div>`;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: Deno.env.get("INVOICE_FROM") || Deno.env.get("REMINDER_FROM") || DEFAULT_FROM, to, subject: `${ANSWER[r.kind] || "Atsakymas"}: ${invTitle(v)}`, html, ...(s.by_email ? { reply_to: s.by_email } : {}) }),
  });
  if (!res.ok) { console.error("Resend", res.status, (await res.text()).slice(0, 300)); return { mailed: 0 }; }
  return { mailed: to.length };
}

if (import.meta.main) Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed, use POST" }, 405);
  let b: Record<string, unknown> = {};
  try { b = await req.json(); } catch { /* empty */ }
  try {
    const hit = await byToken(String(b.t ?? ""));
    if (!hit) return json({ error: "Nuoroda netinka arba sąskaita ištrinta." }, 404);
    const { v, s } = hit;
    const about = { v: VERSION, title: invTitle(v), supplier: v.supplier, number: v.number, amount: v.amount, invoice_date: v.invoice_date, due_date: v.due_date,
      recipients: s.to || [], comment: s.comment || "", from: s.by || "", status: v.status,
      answers: (v.responses || []).filter((r) => r.token === s.token).map(({ at, who, kind, text }) => ({ at, who, kind, text })) };
    const a = String(b.a ?? "");
    if (!a) return json(about);
    if (!ANSWER[a]) return json({ error: "Nežinomas atsakymas." }, 400);
    const text = String(b.text ?? "").trim().slice(0, 2000);
    if (a === "reply" && !text) return json({ error: "Parašyk atsakymą." }, 400);
    const r: Resp = { at: new Date().toISOString(), who: String(b.who ?? "").trim().slice(0, 120), kind: a, text, token: s.token };
    const status = a === "paid" ? "paid" : a === "queued" && v.status !== "paid" ? "queued" : v.status;
    await db(`invoices?id=eq.${v.id}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ responses: [...(v.responses || []), r], status, uploader_seen: status !== v.status ? false : undefined }) });
    const secret = Deno.env.get("CRON_SECRET");
    if (secret) await fetch(`${env("SUPABASE_URL")}/functions/v1/push-notify`, { method: "POST", headers: { "Content-Type": "application/json", "x-cron-secret": secret }, body: JSON.stringify({ mode: "invoice-reply", invoice_id: v.id }) }).catch(() => {});
    const m = await mailAnswer(v, s, r).catch((e) => ({ mailed: 0, error: String(e) }));
    return json({ ...about, status, answers: [...about.answers, { at: r.at, who: r.who, kind: r.kind, text: r.text }], saved: true, ...m });
  } catch (err) {
    console.error(err);
    return json({ error: "Nepavyko. Pabandykite dar kartą." }, 500);
  }
});
