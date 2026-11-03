// Supabase Edge Function: slack-sync
//
// Every event (Renginiai, not „Sandėlio darbai“) gets its own public channel in the company Slack, as the
// event channel in the app's chat (that one stays too):
//   * the channel „#2026-11-05-festivalis-ruduo“ is made when the event is saved (or by the daily run);
//   * the team is invited – app members found by name in the event's team and among its managers, matched to
//     Slack by e-mail; Freelance members are not invited; someone added to the team later is invited then;
//   * the first message is the event's brief (dates, place, times, contacts, the team by day, transport) and it
//     is updated when the event changes;
//   * a cancelled / deleted event: a message in the channel and the channel is archived; 7 days after the event
//     ended the channel is archived by the daily run.
// The channel of each event is kept in public.slack_channels (supabase/sql/slack.sql).
//
// POST {action:"status"}             signed-in member: is Slack connected (workspace, bot)
// POST {action:"sync", event_id}     signed-in member who may edit Renginiai: make / update the event's channel
// POST {action:"backfill"}           the same, every upcoming event (60 days) – Admin
// POST {action:"sweep"}              header x-cron-secret: the daily run (archive old, make missing, update)
// POST {action:"diag", event_id?}    header x-cron-secret: the connection and (optionally) one event synced – the answers as they are
// Secrets: SLACK_BOT_TOKEN (xoxb-…, scopes channels:manage channels:read chat:write users:read users:read.email),
// CRON_SECRET (the daily run). SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are given by Supabase.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const APP = "https://app.eventsolutions.lt";
const KEEP_DAYS = 7, AHEAD_DAYS = 60;
const E = (n: string) => Deno.env.get(n) ?? "";
class UserError extends Error {}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" } });
}
async function db<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const key = E("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${E("SUPABASE_URL")}/rest/v1/${path}`, {
    ...init,
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json", ...(init.headers as Record<string, string> ?? {}) },
  });
  const t = await res.text();
  if (!res.ok) {
    if (/slack_channels|does not exist|schema cache/i.test(t)) throw new UserError("Slack dar neparuoštas – paleisk supabase/sql/slack.sql.");
    throw new Error(`Database ${res.status}: ${t.slice(0, 300)}`);
  }
  return (t ? JSON.parse(t) : null) as T;
}
const enc = encodeURIComponent;
const today = () => new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Vilnius" }).format(new Date());
const addDays = (d: string, n: number) => { const t = new Date(d + "T12:00:00Z"); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); };
const norm = (s: unknown) => String(s ?? "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/\s+/g, " ").trim();
const md = (s: unknown) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const dm = (d: string) => d ? d.slice(5).replace("-", ".") : "";

// ---- Slack Web API ----
type SlackRes = { ok: boolean; error?: string; [k: string]: unknown };
async function slack(method: string, args: Record<string, string | boolean | number>): Promise<SlackRes> {
  const token = E("SLACK_BOT_TOKEN");
  if (!token) throw new UserError("Slack neprijungtas: Supabase → Edge Functions → Secrets įrašyk SLACK_BOT_TOKEN.");
  const body = new URLSearchParams(); Object.entries(args).forEach(([k, v]) => body.set(k, String(v)));
  for (let i = 0; i < 3; i++) {
    const r = await fetch(`https://slack.com/api/${method}`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/x-www-form-urlencoded" }, body });
    if (r.status === 429) { await new Promise((ok) => setTimeout(ok, (Number(r.headers.get("retry-after")) || 2) * 1000)); continue; }
    const d = await r.json() as SlackRes;
    if (!d.ok && /invalid_auth|not_authed|token_revoked|account_inactive/.test(String(d.error))) throw new UserError("Slack atmetė raktą (SLACK_BOT_TOKEN): " + d.error);
    if (!d.ok && d.error === "missing_scope") throw new UserError(`Slack bot'ui trūksta teisės (${String(d.needed || "")}) – api.slack.com/apps → OAuth & Permissions → pridėk ir „Reinstall to Workspace“.`);
    return d;
  }
  return { ok: false, error: "ratelimited" };
}
let TEAM: { url: string; team: string; bot: string } | null = null;
async function team() {
  if (TEAM) return TEAM;
  const a = await slack("auth.test", {});
  if (!a.ok) throw new UserError("Slack: " + a.error);
  return TEAM = { url: String(a.url || "").replace(/\/?$/, "/"), team: String(a.team || ""), bot: String(a.user || "") };
}

// ---- the event ----
type Entry = { pos?: string; person?: string; status?: string };
type Ev = { id: string; kind?: string; name?: string; title?: string; date?: string; dateEnd?: string; status?: string; deletedAt?: string; handoverId?: string;
  location?: string; organizer?: string; organizerPhone?: string; manager?: string; times?: { label?: string; time?: string }[];
  crew?: { title?: string; entries?: Entry[] }[]; logistics?: { day?: string; vehicle?: string; driver?: string }[] };
type Member = { id: string; email: string; full_name?: string; first_name?: string; last_name?: string; nickname?: string; role: string };
type Row = { event_id: string; channel_id: string; name: string; url: string; brief_ts: string | null; invited: string[]; archived_at: string | null };

const evEnd = (ev: Ev) => ev.dateEnd && ev.dateEnd > String(ev.date || "") ? ev.dateEnd : String(ev.date || "");
function slug(ev: Ev): string {
  const n = norm(ev.name).replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "renginys";
  return `${String(ev.date || "").slice(0, 10)}-${n}`.replace(/^-/, "").slice(0, 70).replace(/-+$/, "");
}
const memberName = (m: Member) => (m.full_name || [m.first_name, m.last_name].filter(Boolean).join(" ") || m.email || "").trim();
function findMember(name: string, members: Member[]): Member | null {
  const n = norm(name).replace(/[.,;]+$/, ""); if (!n) return null;
  let hit = members.filter((m) => norm(memberName(m)) === n || (m.nickname && norm(m.nickname) === n) || norm([m.first_name, m.last_name].filter(Boolean).join(" ")) === n);
  if (!hit.length) { const f = members.filter((m) => norm(memberName(m)).split(" ")[0] === n); if (f.length === 1) hit = f; }   // only a first name, if nobody else has it
  return hit.length === 1 ? hit[0] : null;
}
// who goes to the channel: the team and the managers – app members, not Freelance
function wanted(ev: Ev, members: Member[]): { emails: Set<string>; unknown: string[] } {
  const emails = new Set<string>(), unknown: string[] = [];
  const names: string[] = [];
  (ev.crew || []).forEach((g) => (g.entries || []).forEach((e) => { if (String(e.person || "").trim() && !/negali|atsisake/.test(String(e.status || ""))) names.push(String(e.person).trim()); }));
  String(ev.manager || "").split(/[,\n]/).map((x) => x.replace(/\+?\d[\d\s]{6,}/, "").replace(/^(office|tech)\s*:\s*/i, "").trim()).filter(Boolean).forEach((x) => names.push(x));
  [...new Set(names)].forEach((n) => {
    const m = findMember(n, members);
    if (m && m.email && m.role !== "freelance") emails.add(m.email.toLowerCase());
    else if (!m) unknown.push(n);
  });
  return { emails, unknown };
}
function brief(ev: Ev): string {
  const L: string[] = [];
  const range = dm(String(ev.date || "")) + (evEnd(ev) !== ev.date ? " – " + dm(evEnd(ev)) : "");
  const loc = String(ev.location || "").split("\n")[0].trim();
  L.push(`*🎉 ${md(ev.name || "Renginys")}*`);
  L.push(`📅 ${md(range)}${loc ? `  ·  📍 <https://maps.google.com/?q=${enc(loc)}|${md(loc)}>` : ""}${ev.status === "unconf" ? "  ·  _nepatvirtintas_" : ""}`);
  const times = (ev.times || []).filter((t) => String(t.time || "").trim());
  if (times.length) { L.push("", "*⏰ Laikai*"); times.forEach((t) => L.push(`• *${md(t.time)}* ${md(t.label || "")}`)); }
  const org = String(ev.organizer || "").split("\n")[0].trim(), mgr = String(ev.manager || "").trim();
  if (org || mgr) { L.push("", "*📞 Kontaktai*"); if (org) L.push(`• Organizatorius: ${md(org)}${ev.organizerPhone ? " " + md(ev.organizerPhone) : ""}`); if (mgr) L.push(`• Atsakingi: ${md(mgr.replace(/\n/g, ", "))}`); }
  const groups = (ev.crew || []).map((g) => ({ t: String(g.title || "").trim(), p: (g.entries || []).filter((e) => String(e.person || "").trim()) })).filter((g) => g.p.length);
  if (groups.length) { L.push("", "*👥 Komanda*"); groups.forEach((g) => L.push(`• *${md(g.t || "Komanda")}*: ${g.p.map((e) => (e.pos ? md(e.pos) + " " : "") + md(e.person) + (/negali|atsisake/.test(String(e.status || "")) ? " ~(negali)~" : "")).join(", ")}`)); }
  const tr = (ev.logistics || []).filter((l) => String(l.vehicle || "").trim() || String(l.driver || "").trim());
  if (tr.length) { L.push("", "*🚚 Transportas*"); tr.forEach((l) => L.push(`• ${l.day ? md(String(l.day).trim()) + " d.: " : ""}${md(String(l.vehicle || "").split("\n").join(", "))}${l.driver ? " – " + md(String(l.driver).split("\n").join(", ")) : ""}`)); }
  L.push("", `<${APP}/?ev=${enc(ev.id)}|Atidaryti programoje> · _atnaujinta ${new Intl.DateTimeFormat("lt-LT", { timeZone: "Europe/Vilnius", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date())}_`);
  return L.join("\n");
}

async function loadMembers(): Promise<Member[]> {
  return await db<Member[]>("profiles?select=id,email,full_name,first_name,last_name,nickname,role&role=not.in.(pending,blocked)");
}
async function slackOn(): Promise<boolean> {
  const [c] = await db<{ value: { on?: boolean } }[]>("app_config?select=value&key=eq.slack");
  return !!(c && c.value && c.value.on);
}
async function saveRow(r: Row) {
  await db("slack_channels?on_conflict=event_id", { method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" }, body: JSON.stringify({ ...r, updated_at: new Date().toISOString() }) });
}
async function patchRow(eventId: string, f: Record<string, unknown>) {
  await db(`slack_channels?event_id=eq.${enc(eventId)}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ ...f, updated_at: new Date().toISOString() }) });
}

// make / update one event's channel
async function syncEvent(ev: Ev, members: Member[]): Promise<Record<string, unknown>> {
  if (!ev || ev.kind === "work" || ev.handoverId) return { skipped: "ne renginys" };
  const [row] = await db<Row[]>(`slack_channels?event_id=eq.${enc(ev.id)}&select=*`);
  const gone = ev.status === "cancel" || !!ev.deletedAt;
  if (gone) {
    if (row && !row.archived_at) {
      await slack("chat.postMessage", { channel: row.channel_id, text: `❌ Renginys *${md(ev.name || "")}* ${ev.deletedAt ? "ištrintas" : "atšauktas"}. Kanalas archyvuojamas.` });
      const a = await slack("conversations.archive", { channel: row.channel_id });
      await patchRow(ev.id, { archived_at: new Date().toISOString(), last_error: a.ok || a.error === "already_archived" ? null : String(a.error) });
      return { archived: true };
    }
    return { skipped: "atšauktas" };
  }
  if (!ev.date) return { skipped: "be datos" };
  if (row && row.archived_at) return { url: row.url, archived: true };
  const t = await team();
  let r = row;
  if (!r) {
    const base = slug(ev);
    let made: SlackRes | null = null, name = base;
    for (let k = 1; k <= 6; k++) {
      name = k === 1 ? base : `${base}-${k}`;
      made = await slack("conversations.create", { name, is_private: false });
      if (made.ok || made.error !== "name_taken") break;
    }
    if (!made || !made.ok) throw new UserError("Slack kanalo sukurti nepavyko: " + (made ? made.error : ""));
    const ch = made.channel as { id: string; name: string };
    r = { event_id: ev.id, channel_id: ch.id, name: ch.name, url: `${t.url}archives/${ch.id}`, brief_ts: null, invited: [], archived_at: null };
    await saveRow(r);
    await slack("conversations.setPurpose", { channel: ch.id, purpose: `${ev.name || "Renginys"} · ${dm(String(ev.date))}${evEnd(ev) !== ev.date ? "–" + dm(evEnd(ev)) : ""} · iš Event Solutions programos` }).catch(() => null);
  }
  // the brief: the first message, kept up to date
  const text = brief(ev);
  let ts = r.brief_ts;
  if (ts) { const u = await slack("chat.update", { channel: r.channel_id, ts, text }); if (!u.ok) ts = null; }
  if (!ts) { const p = await slack("chat.postMessage", { channel: r.channel_id, text, unfurl_links: false }); if (p.ok) ts = String(p.ts); }
  // the people
  const { emails, unknown } = wanted(ev, members);
  const invited = new Set((r.invited || []).map((x) => x.toLowerCase())), notInSlack: string[] = [];
  let added = 0;
  for (const email of emails) {
    if (invited.has(email)) continue;
    const u = await slack("users.lookupByEmail", { email });
    if (!u.ok) { notInSlack.push(email); continue; }
    const uid = String((u.user as { id: string }).id);
    const inv = await slack("conversations.invite", { channel: r.channel_id, users: uid });
    if (inv.ok || /already_in_channel|cant_invite_self/.test(String(inv.error))) { invited.add(email); if (inv.ok) added++; }
    else notInSlack.push(email + " (" + inv.error + ")");
  }
  await patchRow(ev.id, { brief_ts: ts, invited: [...invited], last_error: notInSlack.length ? "Slack nerasta: " + notInSlack.join(", ") : null });
  return { url: r.url, name: r.name, invited: added, total: invited.size, notInSlack, unknown };
}
async function loadEvent(id: string): Promise<Ev | null> {
  const [e] = await db<{ id: string; data: Ev }[]>(`events?id=eq.${enc(id)}&select=id,data`);
  return e && e.data ? { ...e.data, id: e.id } : null;
}
async function upcoming(): Promise<Ev[]> {
  const from = addDays(today(), -1), to = addDays(today(), AHEAD_DAYS);
  const rows = await db<{ id: string; data: Ev }[]>(`events?select=id,data&event_date=gte.${from}&event_date=lte.${to}`);
  return rows.map((e) => ({ ...e.data, id: e.id })).filter((e) => e.date);
}
// the daily run: archive channels 7 days after their event, cancelled / deleted ones too; make the missing, update the brief
async function sweep(): Promise<Record<string, unknown>> {
  const out = { archived: 0, synced: 0, errors: [] as string[] };
  const rows = await db<Row[]>("slack_channels?archived_at=is.null&select=*");
  for (const r of rows) {
    const ev = await loadEvent(r.event_id);
    const old = !ev || ev.status === "cancel" || !!ev.deletedAt || addDays(evEnd(ev), KEEP_DAYS) < today();
    if (!old) continue;
    if (ev && (ev.status === "cancel" || ev.deletedAt)) { await syncEvent(ev, []); out.archived++; continue; }
    const a = await slack("conversations.archive", { channel: r.channel_id });
    await patchRow(r.event_id, { archived_at: new Date().toISOString(), last_error: a.ok || a.error === "already_archived" ? null : String(a.error) });
    out.archived++;
  }
  if (await slackOn()) {
    const members = await loadMembers();
    for (const ev of await upcoming()) {
      try { await syncEvent(ev, members); out.synced++; } catch (e) { out.errors.push(`${ev.name}: ${(e as Error).message}`); }
    }
  }
  return out;
}

// who calls: a signed-in member (their role, and whether they may edit Renginiai)
async function caller(req: Request): Promise<{ id: string; role: string; level: string; edit: boolean } | null> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const res = await fetch(`${E("SUPABASE_URL")}/auth/v1/user`, { headers: { apikey: E("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` } });
  if (!res.ok) return null;
  const user = await res.json() as { id?: string };
  if (!user?.id) return null;
  const [p] = await db<{ role: string; level: string | null }[]>(`profiles?select=role,level&id=eq.${enc(user.id)}`);
  if (!p || ["pending", "blocked"].includes(p.role)) return null;
  let edit = p.role === "admin" || p.level === "super";
  if (!edit) { const [x] = await db<{ can_edit: boolean }[]>(`role_permissions?select=can_edit&section=eq.events&role=eq.${enc(p.role)}`); edit = !!(x && x.can_edit); }
  return { id: user.id, role: p.role, level: p.level || "", edit };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST" }, 405);
  let b: { action?: string; event_id?: string } = {};
  try { b = await req.json(); } catch { /* empty */ }
  const action = String(b.action || "");
  try {
    if (action === "sweep") {
      const s = E("CRON_SECRET");
      if (!s || req.headers.get("x-cron-secret") !== s) return json({ error: "Unauthorized" }, 401);
      if (!E("SLACK_BOT_TOKEN")) return json({ ok: true, skipped: "no token" });
      return json({ ok: true, ...(await sweep()) });
    }
    // a check run from the database (same secret): the connection, and one event's channel made / updated, with Slack's own answer
    if (action === "diag") {
      const s2 = E("CRON_SECRET");
      if (!s2 || req.headers.get("x-cron-secret") !== s2) return json({ error: "Unauthorized" }, 401);
      const out: Record<string, unknown> = { token: E("SLACK_BOT_TOKEN") ? "yra" : "NĖRA", on: await slackOn() };
      try { out.team = await team(); } catch (e) { out.team_error = (e as Error).message; return json(out); }
      if (b.event_id) { try { const ev = await loadEvent(String(b.event_id)); out.event = ev ? ev.name : "nerastas"; if (ev) out.sync = await syncEvent(ev, await loadMembers()); } catch (e) { out.sync_error = (e as Error).message; } }
      return json(out);
    }
    const who = await caller(req);
    if (!who) return json({ error: "Prisijunk iš naujo." }, 401);
    if (action === "status") {
      if (!E("SLACK_BOT_TOKEN")) return json({ ok: false, connected: false, error: "Nėra SLACK_BOT_TOKEN (Supabase → Edge Functions → Secrets)." });
      const t = await team();
      const rows = await db<{ event_id: string }[]>("slack_channels?select=event_id&archived_at=is.null");
      return json({ ok: true, connected: true, team: t.team, url: t.url, bot: t.bot, on: await slackOn(), open: rows.length });
    }
    if (action === "sync") {
      if (!who.edit) return json({ error: "Kanalą kuria tie, kas redaguoja Renginius." }, 403);
      if (!(await slackOn())) return json({ ok: true, skipped: "išjungta" });
      const ev = await loadEvent(String(b.event_id || ""));
      if (!ev) return json({ error: "Renginys nerastas (dar neišsaugotas?)." }, 404);
      return json({ ok: true, ...(await syncEvent(ev, await loadMembers())) });
    }
    if (action === "backfill") {
      if (!(who.role === "admin" || who.level === "super")) return json({ error: "Tik administratoriams." }, 403);
      if (!(await slackOn())) return json({ error: "Slack išjungtas – įjunk Admin skiltyje." }, 400);
      const members = await loadMembers(), list = await upcoming(), out = { synced: 0, errors: [] as string[] };
      for (const ev of list) { try { const r = await syncEvent(ev, members); if (!r.skipped) out.synced++; } catch (e) { out.errors.push(`${ev.name}: ${(e as Error).message}`); } }
      return json({ ok: true, ...out, events: list.length });
    }
    return json({ error: "Nežinomas veiksmas." }, 400);
  } catch (e) {
    if (e instanceof UserError) return json({ error: e.message }, 400);
    console.error("slack-sync", (e as Error).message);
    return json({ error: "Klaida: " + (e as Error).message }, 500);
  }
});
