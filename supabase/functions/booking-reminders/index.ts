// Supabase Edge Function: booking-reminders
//
// Emails people from the „Žmonės“ archive a reminder of the days they agreed
// to work (public.booking_reminders, see supabase/sql/people3.sql).
//
// POST {"mode":"cron"}                    header x-cron-secret: <CRON_SECRET>
//   Hourly run: every active reminder whose send_hour is the current hour
//   (Lithuanian time) is sent when its every_days have passed since the last
//   one, and also on the day before a booked day when day_before is on.
//   At most once a day. When all its days are over the reminder switches off.
//
// POST {"mode":"send","id":"<reminder id>"}   Authorization: Bearer <user token>
//   „Siųsti dabar“ from the app. Only users who may edit „Žmonės“.
//
// Secrets: RESEND_API_KEY, CRON_SECRET, REMINDER_FROM (optional sender).
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.

const VERSION = 1;
const DEFAULT_FROM = "Event Solutions <onboarding@resend.dev>";
const TIME_ZONE = "Europe/Vilnius";
const DAY_MS = 24 * 60 * 60 * 1000;
const WEEKDAYS = ["sekmadienis", "pirmadienis", "antradienis", "trečiadienis", "ketvirtadienis", "penktadienis", "šeštadienis"];
const MONTHS = ["sausio", "vasario", "kovo", "balandžio", "gegužės", "birželio", "liepos", "rugpjūčio", "rugsėjo", "spalio", "lapkričio", "gruodžio"];

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

export type Reminder = {
  id: string;
  contact_id: string;
  email: string;
  dates: string[];
  every_days: number;
  send_hour: number;
  day_before: boolean;
  message: string | null;
  active: boolean;
  last_sent: string | null;
  sent_count: number;
  reply_to: string | null;
  created_by_name: string | null;
};

type Contact = { first?: string; last?: string };

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

function env(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`${name} is not configured`);
  return value;
}

export function todayInVilnius(now = new Date()): string {
  return new Intl.DateTimeFormat("en-CA", { timeZone: TIME_ZONE }).format(now);
}

export function hourInVilnius(now = new Date()): number {
  const h = new Intl.DateTimeFormat("en-GB", { timeZone: TIME_ZONE, hour: "2-digit", hourCycle: "h23" }).format(now);
  return Number(h) % 24;
}

export function addDays(day: string, n: number): string {
  return new Date(Date.parse(`${day}T00:00:00Z`) + n * DAY_MS).toISOString().slice(0, 10);
}

function daysBetween(from: string, to: string): number {
  return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY_MS);
}

export function upcoming(r: Reminder, today: string): string[] {
  return [...new Set((r.dates ?? []).map((d) => String(d).slice(0, 10)))].filter((d) => d >= today).sort();
}

// Is this reminder to be sent in this hour?
export function isDue(r: Reminder, today: string, hour: number): boolean {
  if (!r.active || r.send_hour !== hour) return false;
  const days = upcoming(r, today);
  if (!days.length) return false;
  if (r.last_sent === today) return false;
  if (r.day_before && days.includes(addDays(today, 1))) return true;
  if (!r.last_sent) return true;
  return daysBetween(r.last_sent, today) >= Math.max(1, r.every_days);
}

export function dayLabel(d: string): string {
  const t = new Date(`${d}T12:00:00Z`);
  return `${MONTHS[t.getUTCMonth()]} ${t.getUTCDate()} d. (${WEEKDAYS[t.getUTCDay()]})`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

export function buildEmail(r: Reminder, c: Contact | null, today: string) {
  const days = upcoming(r, today);
  const first = (c?.first ?? "").trim();
  const tomorrow = days.includes(addDays(today, 1));
  const subject = days.length === 1
    ? `Priminimas: ${tomorrow ? "rytoj " : ""}dirbate su Event Solutions ${dayLabel(days[0])}`
    : `Priminimas: jūsų darbo dienos su Event Solutions (${days.length})`;
  const list = days.map((d) =>
    `<li style="margin:3px 0;"><b>${escapeHtml(dayLabel(d))}</b>${d === today ? " — šiandien" : d === addDays(today, 1) ? " — rytoj" : ""}</li>`
  ).join("");
  const who = r.created_by_name ? escapeHtml(r.created_by_name) : "Event Solutions";
  const html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;line-height:1.5;">
    <p>Sveiki${first ? ", " + escapeHtml(first) : ""},</p>
    <p>primename, kad esate užsiregistravę dirbti su Event Solutions šiomis dienomis:</p>
    <ul style="padding-left:18px;">${list}</ul>
    ${r.message ? `<p style="white-space:pre-wrap;">${escapeHtml(r.message)}</p>` : ""}
    <p>Jei planai pasikeitė — atsakykite į šį laišką arba susisiekite su ${who}.</p>
    <p style="color:#777;font-size:12px;margin-top:18px;">Event Solutions · automatinis priminimas</p>
  </div>`;
  return { subject, html };
}

async function db(path: string, init: RequestInit = {}): Promise<Response> {
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${env("SUPABASE_URL")}/rest/v1/${path}`, {
    ...init,
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`Database ${res.status}: ${(await res.text()).slice(0, 300)}`);
  return res;
}

async function contactOf(id: string): Promise<Contact | null> {
  const rows = (await (await db(`contacts?select=data&id=eq.${encodeURIComponent(id)}`)).json()) as { data: Contact }[];
  return rows[0]?.data ?? null;
}

async function patch(id: string, body: Record<string, unknown>) {
  await db(`booking_reminders?id=eq.${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify(body),
  });
}

async function sendEmail(to: string, subject: string, html: string, replyTo: string | null): Promise<void> {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env("RESEND_API_KEY")}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: Deno.env.get("REMINDER_FROM") || DEFAULT_FROM,
      to: [to],
      subject,
      html,
      ...(replyTo ? { reply_to: replyTo } : {}),
    }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${(await res.text()).slice(0, 300)}`);
}

async function deliver(r: Reminder, today: string) {
  const { subject, html } = buildEmail(r, await contactOf(r.contact_id), today);
  await sendEmail(r.email, subject, html, r.reply_to);
  await patch(r.id, { last_sent: today, sent_count: (r.sent_count ?? 0) + 1, last_error: null });
}

async function editor(req: Request): Promise<boolean> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token || token.split(".").length !== 3) return false;
  const res = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, {
    headers: { apikey: env("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return false;
  const user = await res.json();
  if (!user?.id) return false;
  const profiles = (await (await db(`profiles?select=role&id=eq.${encodeURIComponent(user.id)}`)).json()) as { role: string }[];
  const role = profiles[0]?.role;
  if (!role) return false;
  if (role === "admin") return true;
  const perms = (await (await db(
    `role_permissions?select=can_edit&section=eq.people&role=eq.${encodeURIComponent(role)}`,
  )).json()) as { can_edit: boolean }[];
  return !!perms[0]?.can_edit;
}

async function runScheduled() {
  const today = todayInVilnius();
  const hour = hourInVilnius();
  const rows = (await (await db("booking_reminders?select=*&active=eq.true")).json()) as Reminder[];
  const sent: unknown[] = [];
  for (const r of rows) {
    if (!upcoming(r, today).length) {
      await patch(r.id, { active: false });
      continue;
    }
    if (!isDue(r, today, hour)) continue;
    try {
      await deliver(r, today);
      sent.push({ id: r.id, to: r.email });
    } catch (err) {
      console.error(`Reminder ${r.id} failed:`, err);
      await patch(r.id, { last_error: String(err).slice(0, 300) }).catch(() => {});
      sent.push({ id: r.id, error: String(err) });
    }
  }
  return { v: VERSION, date: today, hour, checked: rows.length, sent };
}

if (import.meta.main) Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed, use POST" }, 405);
  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* empty body = scheduled run */ }
  try {
    if (body?.mode === "send") {
      if (!(await editor(req))) return json({ error: "Neturi teisės redaguoti „Žmonės“ skilties." }, 403);
      const id = String(body.id ?? "");
      const rows = (await (await db(`booking_reminders?select=*&id=eq.${encodeURIComponent(id)}`)).json()) as Reminder[];
      const r = rows[0];
      if (!r) return json({ error: "Priminimas nerastas." }, 404);
      const today = todayInVilnius();
      if (!upcoming(r, today).length) return json({ error: "Visos priminimo dienos jau praėjo." }, 400);
      await deliver(r, today);
      return json({ sent: true, to: r.email });
    }
    const secret = Deno.env.get("CRON_SECRET");
    if (!secret || req.headers.get("x-cron-secret") !== secret) return json({ error: "Unauthorized" }, 401);
    return json(await runScheduled());
  } catch (err) {
    console.error(err);
    const message = err instanceof Error ? err.message : String(err);
    const shown = /is not configured|^Resend \d+|^Database \d+/.test(message) ? message : "Nepavyko išsiųsti priminimo";
    return json({ error: shown }, 500);
  }
});
