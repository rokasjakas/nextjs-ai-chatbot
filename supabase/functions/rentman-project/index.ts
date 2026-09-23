// Supabase Edge Function: rentman-project
//
// GET  /functions/v1/rentman-project?id=123
// POST /functions/v1/rentman-project  { "id": 123 }
//   Returns the Rentman project's name, dates, schedule (project functions)
//   and equipment list.
//
// GET  /functions/v1/rentman-project?date=2026-09-16
// GET  /functions/v1/rentman-project?from=2026-09-01&to=2026-09-30
//   Returns the projects whose plan period overlaps the given day(s).
//
// The Rentman API token is read from the RENTMAN_API_TOKEN secret and never
// leaves the server.

const RENTMAN_BASE_URL = "https://api.rentman.net";
const PAGE_LIMIT = 300;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
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
    const page = await rentmanGet<{ data: RentmanRecord[]; itemCount?: number }>(
      `${path}${sep}limit=${PAGE_LIMIT}&offset=${offset}`,
      token,
    );
    items.push(...page.data);
    if (page.data.length < PAGE_LIMIT) break;
    offset += PAGE_LIMIT;
  }
  return items;
}

// Equipment groups only provide group names, so a failure here should not
// fail the whole request. Rentman names this collection in the singular.
async function getEquipmentGroups(
  projectId: string,
  token: string,
): Promise<RentmanRecord[]> {
  try {
    return await rentmanGetAll(
      `/projects/${projectId}/projectequipmentgroup`,
      token,
    );
  } catch (err) {
    console.warn(`Could not load equipment groups: ${err}`);
    return [];
  }
}

// Rentman references look like "/equipment/42"; extract the numeric id.
function refId(ref: unknown): number | null {
  if (typeof ref !== "string") return null;
  const id = Number(ref.split("/").pop());
  return Number.isFinite(id) ? id : null;
}

type Params = { id?: string; from?: string; to?: string };

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

async function getParams(req: Request): Promise<Params> {
  const url = new URL(req.url);
  const raw: Record<string, unknown> = Object.fromEntries(url.searchParams);
  if (req.method === "POST") {
    try {
      Object.assign(raw, await req.json());
    } catch {
      // No or invalid JSON body; query parameters only.
    }
  }
  const str = (v: unknown) => (v != null && v !== "" ? String(v) : undefined);
  const date = str(raw.date);
  return {
    id: str(raw.id),
    from: str(raw.from) ?? date,
    to: str(raw.to) ?? date,
  };
}

// Projects whose plan period overlaps [from, to] (inclusive, YYYY-MM-DD).
async function listProjects(
  from: string,
  to: string,
  token: string,
): Promise<Response> {
  const filter =
    `/projects?planperiod_start[lte]=${to}T23:59:59` +
    `&planperiod_end[gte]=${from}T00:00:00`;
  let projects: RentmanRecord[];
  try {
    projects = await rentmanGetAll(filter, token);
  } catch (err) {
    if (!(err instanceof RentmanError && err.status === 400)) throw err;
    console.warn(`Filtered project query rejected, filtering locally: ${err}`);
    projects = await rentmanGetAll("/projects", token);
  }

  // Rentman returns local times with an offset, so the first 10 characters
  // are the local date. Filter again in case the API ignored the filter.
  const day = (v: unknown) => (typeof v === "string" ? v.slice(0, 10) : "");
  const result = projects
    .filter(
      (p) => day(p.planperiod_start) <= to && day(p.planperiod_end) >= from,
    )
    .map((p) => ({
      id: p.id,
      number: p.number ?? null,
      name: p.displayname ?? p.name,
      planperiod_start: p.planperiod_start ?? null,
      planperiod_end: p.planperiod_end ?? null,
    }))
    .sort((a, b) =>
      String(a.planperiod_start ?? "").localeCompare(
        String(b.planperiod_start ?? ""),
      ),
    );

  return json({ from, to, projects: result });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "GET" && req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  const token = Deno.env.get("RENTMAN_API_TOKEN");
  if (!token) {
    return json({ error: "RENTMAN_API_TOKEN is not configured" }, 500);
  }

  const { id: projectId, from, to } = await getParams(req);
  const usage =
    "Provide a numeric project id (?id=123) or a date (?date=2026-09-16, " +
    "or ?from=2026-09-01&to=2026-09-30)";

  if (!projectId) {
    if (!from || !to || !DATE_RE.test(from) || !DATE_RE.test(to)) {
      return json({ error: usage }, 400);
    }
    try {
      return await listProjects(from, to, token);
    } catch (err) {
      console.error(err instanceof Error ? err.message : err);
      return json({ error: "Rentman API request failed" }, 502);
    }
  }
  if (!/^\d+$/.test(projectId)) {
    return json({ error: usage }, 400);
  }

  try {
    const [{ data: project }, functions, equipment, equipmentGroups] =
      await Promise.all([
        rentmanGet<{ data: RentmanRecord }>(`/projects/${projectId}`, token),
        rentmanGetAll(`/projects/${projectId}/projectfunctions`, token),
        rentmanGetAll(`/projects/${projectId}/projectequipment`, token),
        getEquipmentGroups(projectId, token),
      ]);

    const groupNames = new Map(
      equipmentGroups.map((g) => [g.id as number, g.name as string]),
    );

    const schedule = functions
      .map((f) => ({
        id: f.id,
        name: f.name,
        group: refId(f.group),
        planperiod_start: f.planperiod_start ?? null,
        planperiod_end: f.planperiod_end ?? null,
        usageperiod_start: f.usageperiod_start ?? null,
        usageperiod_end: f.usageperiod_end ?? null,
        quantity: f.amount ?? null,
        remark: f.remark ?? null,
      }))
      .sort((a, b) =>
        String(a.planperiod_start ?? "").localeCompare(
          String(b.planperiod_start ?? ""),
        ),
      );

    const equipmentList = equipment.map((e) => {
      const groupId = refId(e.equipment_group);
      return {
        id: e.id,
        name: e.name,
        equipment_id: refId(e.equipment),
        quantity: e.quantity ?? null,
        quantity_total: e.quantity_total ?? null,
        group: groupId != null ? (groupNames.get(groupId) ?? null) : null,
        planperiod_start: e.planperiod_start ?? null,
        planperiod_end: e.planperiod_end ?? null,
        remark: e.remark ?? null,
      };
    });

    return json({
      id: project.id,
      number: project.number ?? null,
      name: project.displayname ?? project.name,
      dates: {
        planperiod_start: project.planperiod_start ?? null,
        planperiod_end: project.planperiod_end ?? null,
        usageperiod_start: project.usageperiod_start ?? null,
        usageperiod_end: project.usageperiod_end ?? null,
      },
      schedule,
      equipment: equipmentList,
    });
  } catch (err) {
    if (err instanceof RentmanError) {
      console.error(err.message);
      const status = err.status === 404 ? 404 : 502;
      return json(
        {
          error:
            status === 404 ? "Project not found" : "Rentman API request failed",
        },
        status,
      );
    }
    console.error(err);
    return json({ error: "Internal error" }, 500);
  }
});
