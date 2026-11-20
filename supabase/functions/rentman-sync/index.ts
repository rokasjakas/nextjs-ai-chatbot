// Supabase Edge Function: rentman-sync
//
// POST /functions/v1/rentman-sync
//   {"mode":"list","from":"YYYY-MM-DD","to":"YYYY-MM-DD"}
//     -> {"projects":[{"rentmanId":"1114","name":"...","date":"YYYY-MM-DD"}]}
//     Projects whose event date falls within [from, to]. The event date is
//     taken from the project name ("(09.15) ...") or else the usage start.
//
//   {"mode":"usage","from":"YYYY-MM-DD","to":"YYYY-MM-DD"}
//     -> {"projects":[{"rentmanId","name","from","to","equipment":[{"qty","name","equipmentId"}]}]}
//     Projects whose plan period (loading → return) overlaps [from, to], with
//     their equipment, so the app can count what Rentman holds on each day.
//
//   {"mode":"detail","rentmanId":"1114"}
//     -> {"name":"...","eventDate":"YYYY-MM-DD",
//         "schedule":{"montazas":"...","renginys":"...","demontazas":"..."},
//         "equipment":[{"qty":16,"name":"..."}]}
//
// The Rentman API token is read from the RENTMAN_API_TOKEN secret and never
// leaves the server.

const RENTMAN_BASE_URL = "https://api.rentman.net";
const PAGE_LIMIT = 300;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

type RentmanRecord = Record<string, unknown>;

class RentmanError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

async function rentmanGet<T>(path: string, token: string): Promise<T> {
  const res = await fetch(`${RENTMAN_BASE_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new RentmanError(
      `Rentman API ${res.status} on ${path}: ${text.slice(0, 500)}`,
      res.status,
    );
  }
  return (await res.json()) as T;
}

async function rentmanGetAll(
  path: string,
  token: string,
): Promise<RentmanRecord[]> {
  const items: RentmanRecord[] = [];
  let offset = 0;
  while (true) {
    const sep = path.includes("?") ? "&" : "?";
    const page = await rentmanGet<{ data: RentmanRecord[] }>(
      `${path}${sep}limit=${PAGE_LIMIT}&offset=${offset}`,
      token,
    );
    items.push(...page.data);
    if (page.data.length < PAGE_LIMIT) break;
    offset += PAGE_LIMIT;
  }
  return items;
}

// Rentman returns local times with an offset ("2026-09-16T06:00:00+03:00"),
// so the leading characters are the local date and time.
function str(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}
const datePart = (v: string | null) => (v ? v.slice(0, 10) : null);
const timePart = (v: string) => v.slice(11, 16);

// Usage period start; fall back to plan period start.
function eventStart(p: RentmanRecord): string | null {
  return str(p.usageperiod_start) ?? str(p.planperiod_start);
}

// Project names start with the event date, e.g. "(09.15) Seb Arena" or
// "(09-04/05/06) Knygų aikštė", while the usage period often starts on the
// set-up day before. A name date further than this from the usage start is
// treated as a typo.
const NAME_DATE_MAX_DAYS = 7;
const DAY_MS = 24 * 60 * 60 * 1000;

function dateFromName(name: unknown, near: string): string | null {
  if (typeof name !== "string") return null;
  const m = name.match(/\((\d{1,2})[.-](\d{1,2})/);
  if (!m) return null;
  const month = Number(m[1]);
  const day = Number(m[2]);
  const nearMs = Date.parse(`${near}T00:00:00Z`);
  const year = Number(near.slice(0, 4));

  let best: { iso: string; diff: number } | null = null;
  // The name has no year: pick the one closest to the usage start, so a
  // "(01.02)" project set up in late December lands in the next year.
  for (const y of [year - 1, year, year + 1]) {
    const d = new Date(Date.UTC(y, month - 1, day));
    if (d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day) continue;
    const diff = Math.abs(d.getTime() - nearMs);
    if (!best || diff < best.diff) {
      best = { iso: d.toISOString().slice(0, 10), diff };
    }
  }
  return best && best.diff <= NAME_DATE_MAX_DAYS * DAY_MS ? best.iso : null;
}

// Event date: the date in the project name, else the usage period start.
function eventDate(p: RentmanRecord): string | null {
  const start = datePart(eventStart(p));
  if (!start) return null;
  return dateFromName(p.displayname ?? p.name, start) ?? start;
}

function shiftDate(date: string, days: number): string {
  const ms = Date.parse(`${date}T00:00:00Z`) + days * DAY_MS;
  return new Date(ms).toISOString().slice(0, 10);
}

function formatRange(start: string | null, end: string | null): string {
  if (!start || !end || start >= end) return "";
  if (datePart(start) === datePart(end)) {
    return `${datePart(start)} ${timePart(start)}–${timePart(end)}`;
  }
  return `${datePart(start)} ${timePart(start)} – ${datePart(end)} ${timePart(end)}`;
}

function normalize(s: string): string {
  return s
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .toLowerCase();
}

type Phase = "montazas" | "renginys" | "demontazas";

function phaseOf(name: unknown): Phase | null {
  if (typeof name !== "string") return null;
  const n = normalize(name);
  if (n.includes("demontaz")) return "demontazas";
  if (n.includes("montaz")) return "montazas";
  if (n.includes("rengin")) return "renginys";
  return null;
}

// Schedule is derived from the project periods: set-up runs from plan start
// to usage start, the event is the usage period, tear-down runs from usage
// end to plan end. Project functions named "Montažas", "Renginys" or
// "Demontažas" override the derived value for their phase.
function buildSchedule(
  project: RentmanRecord,
  functions: RentmanRecord[],
): Record<Phase, string> {
  const planStart = str(project.planperiod_start);
  const planEnd = str(project.planperiod_end);
  const useStart = str(project.usageperiod_start);
  const useEnd = str(project.usageperiod_end);

  const schedule: Record<Phase, string> = {
    montazas: formatRange(planStart, useStart),
    renginys: formatRange(useStart ?? planStart, useEnd ?? planEnd),
    demontazas: formatRange(useEnd, planEnd),
  };

  const spans = new Map<Phase, { start: string; end: string }>();
  for (const f of functions) {
    const phase = phaseOf(f.name);
    const start = str(f.planperiod_start);
    const end = str(f.planperiod_end);
    if (!phase || !start || !end) continue;
    const span = spans.get(phase);
    spans.set(phase, {
      start: span && span.start < start ? span.start : start,
      end: span && span.end > end ? span.end : end,
    });
  }
  for (const [phase, { start, end }] of spans) {
    schedule[phase] = formatRange(start, end);
  }
  return schedule;
}

async function listProjects(from: string, to: string, token: string) {
  // The event date can differ from the usage start by up to
  // NAME_DATE_MAX_DAYS, so query a wider window and filter locally.
  const queryFrom = shiftDate(from, -NAME_DATE_MAX_DAYS);
  const queryTo = shiftDate(to, NAME_DATE_MAX_DAYS);
  const filtered =
    `/projects?usageperiod_start[gte]=${queryFrom}T00:00:00` +
    `&usageperiod_start[lte]=${queryTo}T23:59:59`;
  let projects: RentmanRecord[];
  try {
    projects = await rentmanGetAll(filtered, token);
  } catch (err) {
    if (!(err instanceof RentmanError && err.status === 400)) throw err;
    console.warn(`Filtered project query rejected, filtering locally: ${err}`);
    projects = await rentmanGetAll("/projects", token);
  }

  return projects
    .map((p) => ({
      rentmanId: String(p.id),
      name: String(p.displayname ?? p.name ?? ""),
      date: eventDate(p),
      sortKey: eventStart(p) ?? "",
    }))
    .filter(
      (p): p is typeof p & { date: string } =>
        p.date !== null && p.date >= from && p.date <= to,
    )
    .sort(
      (a, b) =>
        a.date.localeCompare(b.date) || a.sortKey.localeCompare(b.sortKey),
    )
    .map(({ sortKey: _sortKey, ...p }) => p);
}

// equipment held by projects in a period (plan period = loading to return)
async function usage(from: string, to: string, token: string) {
  const filtered = `/projects?planperiod_start[lte]=${to}T23:59:59&planperiod_end[gte]=${from}T00:00:00`;
  let projects: RentmanRecord[];
  try {
    projects = await rentmanGetAll(filtered, token);
  } catch (err) {
    if (!(err instanceof RentmanError && err.status === 400)) throw err;
    projects = await rentmanGetAll("/projects", token);
  }
  const hit = projects.filter((p) => {
    const a = datePart(str(p.planperiod_start) ?? eventStart(p)), b = datePart(str(p.planperiod_end)) ?? a;
    return a !== null && b !== null && a <= to && b >= from;
  }).slice(0, 80);
  const out: unknown[] = [];
  // a few at a time: Rentman limits the request rate
  for (let i = 0; i < hit.length; i += 5) {
    const part = await Promise.all(hit.slice(i, i + 5).map(async (p) => {
      const eq = await rentmanGetAll(`/projects/${p.id}/projectequipment`, token).catch(() => [] as RentmanRecord[]);
      const a = datePart(str(p.planperiod_start) ?? eventStart(p))!;
      return {
        rentmanId: String(p.id),
        name: String(p.displayname ?? p.name ?? ""),
        from: a,
        to: datePart(str(p.planperiod_end)) ?? a,
        date: eventDate(p),
        equipment: eq.map((e) => ({
          qty: Number(e.quantity ?? e.quantity_total ?? 0),
          name: String(e.name ?? ""),
          equipmentId: (() => { const r = e.equipment; if (typeof r === "number") return String(r); if (typeof r === "string") { const m = r.match(/(\d+)\s*$/); return m ? m[1] : null; } return null; })(),
        })).filter((e) => e.qty > 0),
      };
    }));
    out.push(...part);
  }
  return out;
}

async function projectDetail(rentmanId: string, token: string) {
  const [{ data: project }, functions, equipment] = await Promise.all([
    rentmanGet<{ data: RentmanRecord }>(`/projects/${rentmanId}`, token),
    rentmanGetAll(`/projects/${rentmanId}/projectfunctions`, token),
    rentmanGetAll(`/projects/${rentmanId}/projectequipment`, token),
  ]);

  return {
    name: String(project.displayname ?? project.name ?? ""),
    eventDate: eventDate(project),
    schedule: buildSchedule(project, functions),
    equipment: equipment.map((e) => ({
      qty: Number(e.quantity ?? e.quantity_total ?? 0),
      name: String(e.name ?? ""),
      equipmentId: (() => { const r = e.equipment; if (typeof r === "number") return String(r); if (typeof r === "string") { const m = r.match(/(\d+)\s*$/); return m ? m[1] : null; } return null; })(),
    })),
  };
}

// --- who may call: a signed-in, approved team member who may see projects /
// events / warehouse. The public anon key alone is not enough (it is in the page).
const ALLOWED_SECTIONS = ["projects", "newproj", "events", "rentals", "load", "inventory"];
async function rpcAsUser(fn: string, args: Record<string, unknown>, token: string): Promise<unknown> {
  const url = Deno.env.get("SUPABASE_URL") ?? "";
  const anon = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
  const res = await fetch(`${url}/rest/v1/rpc/${fn}`, {
    method: "POST",
    headers: { apikey: anon, Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(args),
  });
  if (!res.ok) return null;
  return await res.json();
}
async function teamMemberAllowed(req: Request): Promise<boolean> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token || token === (Deno.env.get("SUPABASE_ANON_KEY") ?? "")) return false;
  const url = Deno.env.get("SUPABASE_URL") ?? "";
  const who = await fetch(`${url}/auth/v1/user`, {
    headers: { apikey: Deno.env.get("SUPABASE_ANON_KEY") ?? "", Authorization: `Bearer ${token}` },
  });
  if (!who.ok) return false;
  const user = await who.json();
  if (!user?.id) return false;
  if ((await rpcAsUser("is_approved", {}, token)) !== true) return false;
  if ((await rpcAsUser("is_admin", {}, token)) === true) return true;
  for (const sec of ALLOWED_SECTIONS) {
    if ((await rpcAsUser("can_view", { sec }, token)) === true) return true;
  }
  return false;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (!(await teamMemberAllowed(req))) {
    return json({ error: "Prisijunk kaip patvirtintas komandos narys." }, 401);
  }
  if (req.method !== "POST") {
    return json({ error: "Method not allowed, use POST" }, 405);
  }

  const token = Deno.env.get("RENTMAN_API_TOKEN");
  if (!token) {
    return json({ error: "RENTMAN_API_TOKEN is not configured" }, 500);
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Request body must be JSON" }, 400);
  }

  try {
    if (body?.mode === "list") {
      const { from, to } = body;
      if (
        typeof from !== "string" ||
        typeof to !== "string" ||
        !DATE_RE.test(from) ||
        !DATE_RE.test(to)
      ) {
        return json({ error: "list requires from and to as YYYY-MM-DD" }, 400);
      }
      return json({ projects: await listProjects(from, to, token) });
    }

    if (body?.mode === "usage") {
      const { from, to } = body;
      if (typeof from !== "string" || typeof to !== "string" || !DATE_RE.test(from) || !DATE_RE.test(to)) {
        return json({ error: "usage requires from and to as YYYY-MM-DD" }, 400);
      }
      if (Date.parse(to) - Date.parse(from) > 93 * DAY_MS) return json({ error: "usage: at most 3 months" }, 400);
      return json({ projects: await usage(from, to, token) });
    }

    if (body?.mode === "detail") {
      const rentmanId = String(body.rentmanId ?? "");
      if (!/^\d+$/.test(rentmanId)) {
        return json({ error: "detail requires a numeric rentmanId" }, 400);
      }
      return json(await projectDetail(rentmanId, token));
    }

    return json({ error: 'mode must be "list", "usage" or "detail"' }, 400);
  } catch (err) {
    if (err instanceof RentmanError) {
      console.error(err.message);
      return err.status === 404
        ? json({ error: "Project not found" }, 404)
        : json({ error: "Rentman API request failed" }, 502);
    }
    console.error(err);
    return json({ error: "Internal error" }, 500);
  }
});
