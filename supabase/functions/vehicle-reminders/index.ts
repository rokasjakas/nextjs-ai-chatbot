// Supabase Edge Function: vehicle-reminders
//
// Emails reminders about vehicle documents (insurance, technical inspection,
// road tax) that expire soon or have expired. Vehicles live in the
// public.vehicle_reminders table (see supabase/sql/vehicle_reminders.sql).
//
// POST {"mode":"cron"}                 header x-cron-secret: <CRON_SECRET>
//   Hourly run: for every vehicle whose reminder_hours include the current hour
//   (Lithuanian time), sends one email listing the documents that are due
//   (expiry within that document's lead days, or expired). Within a day it sends once per chosen
//   hour; it starts again every frequency_days days. Recorded in last_sent.
//
// POST {"mode":"send","vehicleId":"..."}  Authorization: Bearer <user token>
//   "Send now" from the website: emails the vehicle's document status right
//   away. Only signed-in users whose access level can see „Transportas“
//   (public.profiles / public.role_permissions) may call it.
//
// Secrets: RESEND_API_KEY (required), CRON_SECRET (for the hourly run),
// REMINDER_FROM (optional sender, e.g. "Event Solutions <auto@eventsolutions.lt>").
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.

const DEFAULT_FROM = "Event Solutions <onboarding@resend.dev>";
const TIME_ZONE = "Europe/Vilnius";
const DAY_MS = 24 * 60 * 60 * 1000;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

type DocKey = "insurance" | "inspection" | "road_tax";

const DOCS: { key: DocKey; column: string; label: string }[] = [
  { key: "insurance", column: "insurance_until", label: "Draudimas" },
  { key: "inspection", column: "inspection_until", label: "Techninė apžiūra" },
  { key: "road_tax", column: "road_tax_until", label: "Kelių mokestis" },
];

type Vehicle = {
  vehicle_id: string;
  name: string;
  plate: string | null;
  insurance_until: string | null;
  inspection_until: string | null;
  road_tax_until: string | null;
  lead_days: number;
  // per document, e.g. {"insurance": 30, "inspection": 14, "road_tax": 7};
  // a missing document falls back to lead_days
  lead_days_by_doc: Partial<Record<DocKey, number>> | null;
  frequency_days: number;
  emails: string[];
  reminder_hours: number[] | null;
  last_sent: Partial<Record<DocKey, SentMark>>;
};

// date/hours: the day reminders were sent and the hours already used that day.
type SentMark = { date: string; until: string; hours?: number[] };

type DocStatus = {
  key: DocKey;
  label: string;
  until: string | null;
  days: number | null;
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function env(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`${name} is not configured`);
  return value;
}

function todayInVilnius(): string {
  // en-CA formats as YYYY-MM-DD.
  return new Intl.DateTimeFormat("en-CA", { timeZone: TIME_ZONE }).format(
    new Date(),
  );
}

function hourInVilnius(): number {
  const h = new Intl.DateTimeFormat("en-GB", {
    timeZone: TIME_ZONE,
    hour: "2-digit",
    hourCycle: "h23",
  }).format(new Date());
  return Number(h) % 24;
}

function reminderHours(v: Vehicle): number[] {
  const hours = (v.reminder_hours ?? []).filter((h) => h >= 0 && h <= 23);
  return hours.length ? hours : [9];
}

function daysBetween(from: string, to: string): number {
  return Math.round(
    (Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY_MS,
  );
}

function docStatuses(v: Vehicle, today: string): DocStatus[] {
  return DOCS.map(({ key, column, label }) => {
    const until = (v as unknown as Record<string, string | null>)[column];
    return { key, label, until, days: until ? daysBetween(today, until) : null };
  });
}

function leadDays(v: Vehicle, key: DocKey): number {
  const n = v.lead_days_by_doc?.[key];
  return typeof n === "number" && n >= 0 ? n : v.lead_days;
}

function isDue(v: Vehicle, doc: DocStatus, today: string, hour: number): boolean {
  if (!doc.until || doc.days === null || doc.days > leadDays(v, doc.key)) return false;
  if (!reminderHours(v).includes(hour)) return false;
  const last = v.last_sent?.[doc.key];
  // A new expiry date (document renewed) starts the reminders over.
  if (!last || last.until !== doc.until) return true;
  // Same day: once for every chosen hour.
  if (last.date === today) return !(last.hours ?? []).includes(hour);
  return daysBetween(last.date, today) >= Math.max(1, v.frequency_days);
}

function markSent(v: Vehicle, doc: DocStatus, today: string, hour: number): SentMark {
  const last = v.last_sent?.[doc.key];
  const sameDay = last && last.date === today && last.until === doc.until;
  return {
    date: today,
    until: doc.until as string,
    hours: [...(sameDay ? last.hours ?? [] : []), hour],
  };
}

function validEmails(emails: string[] | null): string[] {
  return (emails ?? [])
    .map((e) => e.trim())
    .filter((e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e));
}

// --- Supabase REST (service role) ---------------------------------------

async function db(path: string, init: RequestInit = {}): Promise<Response> {
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${env("SUPABASE_URL")}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Database ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
  return res;
}

async function loadVehicles(vehicleId?: string): Promise<Vehicle[]> {
  const filter = vehicleId
    ? `&vehicle_id=eq.${encodeURIComponent(vehicleId)}`
    : "";
  const res = await db(`vehicle_reminders?select=*${filter}`);
  return (await res.json()) as Vehicle[];
}

async function saveLastSent(v: Vehicle): Promise<void> {
  await db(`vehicle_reminders?vehicle_id=eq.${encodeURIComponent(v.vehicle_id)}`, {
    method: "PATCH",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify({ last_sent: v.last_sent }),
  });
}

async function signedInTeamMember(req: Request): Promise<string | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const res = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, {
    headers: {
      apikey: env("SUPABASE_SERVICE_ROLE_KEY"),
      Authorization: `Bearer ${token}`,
    },
  });
  if (!res.ok) return null;
  const user = await res.json();
  if (!user?.id) return null;
  const profiles = (await (await db(
    `profiles?select=role&id=eq.${encodeURIComponent(user.id)}`,
  )).json()) as { role: string }[];
  const role = profiles[0]?.role;
  if (!role) return null;
  if (role === "admin") return String(user.email ?? "");
  const perms = (await (await db(
    `role_permissions?select=can_view,can_edit&section=eq.fleet&role=eq.${encodeURIComponent(role)}`,
  )).json()) as { can_view: boolean; can_edit: boolean }[];
  return perms[0]?.can_view || perms[0]?.can_edit ? String(user.email ?? "") : null;
}

// --- Email ---------------------------------------------------------------

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!
  );
}

function describe(doc: DocStatus): string {
  if (!doc.until || doc.days === null) return "nenurodyta";
  if (doc.days < 0) return `baigėsi ${doc.until} (prieš ${-doc.days} d.)`;
  if (doc.days === 0) return `baigiasi šiandien (${doc.until})`;
  return `baigiasi ${doc.until} (po ${doc.days} d.)`;
}

function buildEmail(v: Vehicle, docs: DocStatus[]) {
  const car = v.plate ? `${v.name} (${v.plate})` : v.name;
  const worst = docs
    .filter((d) => d.days !== null)
    .sort((a, b) => (a.days as number) - (b.days as number))[0];
  const subject = worst
    ? `Priminimas: ${car} — ${worst.label.toLowerCase()} ${describe(worst)}`
    : `Priminimas: ${car} — dokumentų būklė`;
  const rows = docs
    .map((d) => {
      const color = d.days === null
        ? "#777"
        : d.days < 0
        ? "#c0392b"
        : d.days <= leadDays(v, d.key)
        ? "#d68910"
        : "#1e8449";
      return `<tr><td style="padding:6px 12px 6px 0;">${escapeHtml(d.label)}</td>` +
        `<td style="padding:6px 0;color:${color};font-weight:600;">${escapeHtml(describe(d))}</td></tr>`;
    })
    .join("");
  const html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;">
    <p>Automobilis <b>${escapeHtml(car)}</b>:</p>
    <table style="border-collapse:collapse;">${rows}</table>
    <p style="color:#777;font-size:12px;margin-top:18px;">Priminimas iš EventSolutions App.
    Kai dokumentą atnaujinsi, įrašyk naują datą skiltyje „Automobiliai“ — priminimai sustos.</p>
  </div>`;
  return { subject, html };
}

async function sendEmail(to: string[], subject: string, html: string): Promise<void> {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env("RESEND_API_KEY")}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: Deno.env.get("REMINDER_FROM") || DEFAULT_FROM,
      to,
      subject,
      html,
    }),
  });
  if (!res.ok) {
    throw new Error(`Resend ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
}

// --- Modes ---------------------------------------------------------------

async function runScheduled() {
  const today = todayInVilnius();
  const hour = hourInVilnius();
  const vehicles = await loadVehicles();
  const results: unknown[] = [];
  for (const v of vehicles) {
    const to = validEmails(v.emails);
    const statuses = docStatuses(v, today);
    const due = statuses.filter((d) => isDue(v, d, today, hour));
    if (!due.length || !to.length) continue;
    try {
      const { subject, html } = buildEmail(v, due);
      await sendEmail(to, subject, html);
      v.last_sent = { ...(v.last_sent ?? {}) };
      for (const d of due) v.last_sent[d.key] = markSent(v, d, today, hour);
      await saveLastSent(v);
      results.push({ vehicle: v.name, to, docs: due.map((d) => d.key) });
    } catch (err) {
      console.error(`Reminder for ${v.vehicle_id} failed:`, err);
      results.push({ vehicle: v.name, error: String(err) });
    }
  }
  return { date: today, hour, checked: vehicles.length, sent: results };
}

async function sendNow(vehicleId: string) {
  const [v] = await loadVehicles(vehicleId);
  if (!v) return json({ error: "Automobilis nerastas serveryje — palauk kelias sekundes ir bandyk dar kartą." }, 404);
  const to = validEmails(v.emails);
  if (!to.length) return json({ error: "Automobiliui nenurodytas nė vienas el. paštas." }, 400);
  const { subject, html } = buildEmail(v, docStatuses(v, todayInVilnius()));
  await sendEmail(to, subject, html);
  return json({ sent: true, to });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return json({ error: "Method not allowed, use POST" }, 405);
  }

  let body: Record<string, unknown> = {};
  try {
    body = await req.json();
  } catch {
    // An empty body means the daily run.
  }

  try {
    if (body?.mode === "send") {
      if (!(await signedInTeamMember(req))) {
        return json({ error: "Neturi prieigos prie „Transportas“ skilties." }, 403);
      }
      const vehicleId = String(body.vehicleId ?? "");
      if (!vehicleId) return json({ error: "vehicleId is required" }, 400);
      return await sendNow(vehicleId);
    }

    const secret = Deno.env.get("CRON_SECRET");
    if (!secret || req.headers.get("x-cron-secret") !== secret) {
      return json({ error: "Unauthorized" }, 401);
    }
    return json(await runScheduled());
  } catch (err) {
    console.error(err);
    const message = err instanceof Error ? err.message : String(err);
    // Configuration problems are safe to show; other details stay in the logs.
    const shown = /is not configured|^Resend \d+/.test(message)
      ? message
      : "Nepavyko išsiųsti priminimo";
    return json({ error: shown }, 500);
  }
});
