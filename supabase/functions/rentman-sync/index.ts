// Supabase Edge Function: rentman-sync
//
// POST /functions/v1/rentman-sync
//   {"mode":"list","from":"YYYY-MM-DD","to":"YYYY-MM-DD"}
//     -> {"projects":[{"rentmanId":"1114","name":"...","date":"YYYY-MM-DD"}]}
//     Projects whose event date (usage period start) falls within [from, to].
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

// Event date = usage period start; fall back to plan period start.
function eventStart(p: RentmanRecord): string | null {
  return str(p.usageperiod_start) ?? str(p.planperiod_start);
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
  const filtered =
    `/projects?usageperiod_start[gte]=${from}T00:00:00` +
    `&usageperiod_start[lte]=${to}T23:59:59`;
  let projects: RentmanRecord[];
  try {
    projects = await rentmanGetAll(filtered, token);
  } catch (err) {
    if (!(err instanceof RentmanError && err.status === 400)) throw err;
    console.warn(`Filtered project query rejected, filtering locally: ${err}`);
    projects = await rentmanGetAll("/projects", token);
  }

  // Filter again locally: the API filter is on usageperiod_start only, and
  // projects without a usage period fall back to the plan period.
  return projects
    .map((p) => ({
      rentmanId: String(p.id),
      name: String(p.displayname ?? p.name ?? ""),
      date: datePart(eventStart(p)),
      sortKey: eventStart(p) ?? "",
    }))
    .filter((p) => p.date !== null && p.date >= from && p.date <= to)
    .sort((a, b) => a.sortKey.localeCompare(b.sortKey))
    .map(({ sortKey: _sortKey, ...p }) => p);
}

async function projectDetail(rentmanId: string, token: string) {
  const [{ data: project }, functions, equipment] = await Promise.all([
    rentmanGet<{ data: RentmanRecord }>(`/projects/${rentmanId}`, token),
    rentmanGetAll(`/projects/${rentmanId}/projectfunctions`, token),
    rentmanGetAll(`/projects/${rentmanId}/projectequipment`, token),
  ]);

  return {
    name: String(project.displayname ?? project.name ?? ""),
    eventDate: datePart(eventStart(project)),
    schedule: buildSchedule(project, functions),
    equipment: equipment.map((e) => ({
      qty: Number(e.quantity ?? e.quantity_total ?? 0),
      name: String(e.name ?? ""),
    })),
  };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
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

    if (body?.mode === "detail") {
      const rentmanId = String(body.rentmanId ?? "");
      if (!/^\d+$/.test(rentmanId)) {
        return json({ error: "detail requires a numeric rentmanId" }, 400);
      }
      return json(await projectDetail(rentmanId, token));
    }

    return json({ error: 'mode must be "list" or "detail"' }, 400);
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
