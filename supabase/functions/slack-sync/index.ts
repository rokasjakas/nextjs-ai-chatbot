// Supabase Edge Function: slack-sync
//
// Every event (Renginiai, not „Sandėlio darbai“) gets its own public channel in the company Slack, as the
// event channel in the app's chat (that one stays too):
//   * the channel „#2026-11-05-festivalis-ruduo“ is made when a NEW event is made in the app (create "auto"), or for an older
//     event when its „#“ is pressed (create "force"); the daily run and saving only update channels that exist;
//   * every active member of the Slack workspace is invited (no guests, bots or deactivated accounts); someone
//     who joins Slack later is invited at the next sync of the event (saving it, or the daily run);
//   * a channel archived or deleted in Slack is left alone (until „#“ makes a new one);
//   * the first message is the event's brief (name, dates, place, the organizer's contacts, notes) and it
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
// POST {action:"missing_internal", rental_id, item_id, by}  header x-cron-secret: the same from the temporary Paėmimai link (rentals-guest)
// POST {action:"missing", rental_id, item_id}  member who may edit Paėmimai: a missing item found on the return – a message
//                                    in #dingę-daiktai (made if there is none, every active member invited) with @channel,
//                                    buttons Rasta / Nerasta / Grąžinta and „Kam kasdien priminti“ (handled by the gdrive function,
//                                    Slack's Interactivity URL); the daily run sends those people a direct message until it is marked
// Secrets: SLACK_BOT_TOKEN (xoxb-…, scopes channels:manage channels:read chat:write users:read users:read.email; emoji:read – the icons;
//   for #dingę-daiktai also channels:join (a channel made by a person) and im:write (the daily reminders)),
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

// ---- Slack icons: Material Symbols (Outlined, Fill · Apache 2.0) uploaded as the workspace's own emoji „ms-…“
// (app.eventsolutions.lt/slack-emoji/); the usual emoji is swapped for one only once that picture is in Slack
// (emoji.list, scope emoji:read; read again every 10 min.) – before that, and without the scope, nothing changes
const ICONS: [RegExp, string][] = [[/🎉|🎪/g, "ms-event"], [/📅/g, "ms-calendar"], [/📍/g, "ms-location"], [/📞/g, "ms-call"], [/📝/g, "ms-note"], [/❌/g, "ms-cancel"],
  [/🔗/g, "ms-link"], [/📎/g, "ms-attach"], [/🔔/g, "ms-bell"], [/⚠️?/g, "ms-warning"], [/📦/g, "ms-package"], [/💬/g, "ms-chat"], [/🔎/g, "ms-search"], [/✅/g, "ms-check"],
  [/📁/g, "ms-folder"], [/⏳/g, "ms-hourglass"]];
let EMO: Set<string> | null = null, EMO_AT = 0;
async function emojiSet(): Promise<Set<string>> {
  if (EMO && Date.now() - EMO_AT < 10 * 60e3) return EMO;
  EMO_AT = Date.now();
  try {
    const r = await fetch("https://slack.com/api/emoji.list", { headers: { Authorization: `Bearer ${E("SLACK_BOT_TOKEN")}` } });
    const d = await r.json() as { ok: boolean; emoji?: Record<string, string> };
    EMO = new Set(d.ok ? Object.keys(d.emoji || {}).filter((k) => k.startsWith("ms-")) : []);
  } catch { EMO = new Set(); }
  return EMO;
}
function iconText(s: string, have: Set<string>): string { let t = s; for (const [re, n] of ICONS) if (have.has(n)) t = t.replace(re, `:${n}:`); return t; }
const KEEP = new Set(["action_id", "value", "block_id", "url", "channel", "ts", "thread_ts", "image_url", "user", "users"]);
async function iconize<T>(x: T): Promise<T> {
  const have = await emojiSet(); if (!have.size) return x;
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") return iconText(v, have);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      const o = Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, w]) => [k, KEEP.has(k) ? w : walk(w)])) as Record<string, unknown>;
      if (o.type === "plain_text") o.emoji = true;   // the icon in a button / a placeholder
      return o;
    }
    return v;
  };
  return walk(x) as T;
}
// ---- Slack Web API ----
type SlackRes = { ok: boolean; error?: string; [k: string]: unknown };
async function slack(method: string, args: Record<string, string | boolean | number>): Promise<SlackRes> {
  const token = E("SLACK_BOT_TOKEN");
  if (!token) throw new UserError("Slack neprijungtas: Supabase → Edge Functions → Secrets įrašyk SLACK_BOT_TOKEN.");
  if (/^chat\.(postMessage|update)$/.test(method)) {   // the icons
    args = { ...args };
    if (typeof args.text === "string") args.text = await iconize(args.text);
    if (typeof args.blocks === "string") { try { args.blocks = JSON.stringify(await iconize(JSON.parse(args.blocks))); } catch { /* as it is */ } }
  }
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

// every active member of the workspace: no deactivated, bots, Slackbot, guests (single / multi-channel)
let SLACK_MEMBERS: string[] | null = null, SLACK_MEMBERS_AT = 0;
async function slackMembers(): Promise<string[]> {
  if (SLACK_MEMBERS && Date.now() - SLACK_MEMBERS_AT < 10 * 60e3) return SLACK_MEMBERS;
  const out: string[] = []; let cursor = "";
  for (let k = 0; k < 50; k++) {
    const args: Record<string, string | number> = { limit: 200 }; if (cursor) args.cursor = cursor;
    const d = await slack("users.list", args);
    if (!d.ok) throw new UserError("Slack narių sąrašo gauti nepavyko: " + d.error);
    for (const u of (d.members || []) as { id: string; deleted?: boolean; is_bot?: boolean; is_app_user?: boolean; is_restricted?: boolean; is_ultra_restricted?: boolean }[]) {
      if (u.deleted || u.is_bot || u.is_app_user || u.is_restricted || u.is_ultra_restricted || u.id === "USLACKBOT") continue;
      out.push(u.id);
    }
    cursor = String(((d.response_metadata || {}) as { next_cursor?: string }).next_cursor || "");
    if (!cursor) break;
  }
  SLACK_MEMBERS_AT = Date.now();
  return SLACK_MEMBERS = out;
}

// ---- the event ----
type Entry = { pos?: string; person?: string; status?: string };
type Ev = { id: string; kind?: string; name?: string; title?: string; date?: string; dateEnd?: string; status?: string; deletedAt?: string; handoverId?: string;
  location?: string; notes?: string; organizer?: string; organizerPhone?: string; manager?: string; times?: { label?: string; time?: string }[];
  crew?: { title?: string; entries?: Entry[] }[]; logistics?: { day?: string; vehicle?: string; driver?: string }[];
  intro?: { notes?: string; links?: string[]; files?: { name: string; url?: string; error?: string }[]; ready?: boolean; at?: string } };
type Member = { id: string; email: string; full_name?: string; first_name?: string; last_name?: string; nickname?: string; role: string };
type Row = { event_id: string; channel_id: string; name: string; url: string; brief_ts: string | null; invited: string[]; archived_at: string | null; intro_ts?: string | null };

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
// the brief: the name, dates and place, the organizer's contacts and the notes (not the team, times or transport)
function brief(ev: Ev): string {
  const L: string[] = [];
  const range = dm(String(ev.date || "")) + (evEnd(ev) !== ev.date ? " – " + dm(evEnd(ev)) : "");
  const loc = String(ev.location || "").split("\n")[0].trim();
  L.push(`*🎉 ${md(ev.name || "Renginys")}*`);
  L.push(`📅 ${md(range)}${loc ? `  ·  📍 <https://maps.google.com/?q=${enc(loc)}|${md(loc)}>` : ""}${ev.status === "unconf" ? "  ·  _nepatvirtintas_" : ""}`);
  const org = String(ev.organizer || "").split("\n")[0].trim(), tel = String(ev.organizerPhone || "").trim();
  if (org || tel) L.push("", "*📞 Organizatorius*", `${md(org)}${tel ? (org ? "  ·  " : "") + md(tel) : ""}`);
  const notes = String(ev.notes || "").trim();
  if (notes) L.push("", "*📝 Pastabos*", md(notes));
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
// create: "auto" – a channel is made only if the event never had one (a new event made in the app);
// "force" – the „#“ pressed: made also when its earlier channel was archived or deleted in Slack; none – only an existing one is updated
async function syncEvent(ev: Ev, members: Member[], create: "" | "auto" | "force" = ""): Promise<Record<string, unknown>> {
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
  let r: Row | null = row ?? null;
  // archived or deleted in Slack by someone: not written to any more
  if (r && !r.archived_at) {
    const info = await slack("conversations.info", { channel: r.channel_id });
    const ch = info.channel as { is_archived?: boolean } | undefined;
    if (!info.ok && /channel_not_found/.test(String(info.error)) || ch?.is_archived) { await patchRow(ev.id, { archived_at: new Date().toISOString() }); r.archived_at = new Date().toISOString(); }
  }
  if (r && r.archived_at) {
    if (create !== "force") return { url: r.url, archived: true };
    await db(`slack_channels?event_id=eq.${enc(ev.id)}`, { method: "DELETE", headers: { Prefer: "return=minimal" } }); r = null;
  }
  if (!r && !create) return { skipped: "kanalo nėra – spausk „#“ prie renginio" };
  const t = await team();
  if (!r) {
    const base = slug(ev);
    let made: SlackRes | null = null, name = base;
    for (let k = 1; k <= 6; k++) {
      name = k === 1 ? base : `${base}-${k}`;
      made = await slack("conversations.create", { name, is_private: false });
      if (made.ok || made.error !== "name_taken") break;
    }
    if (made && made.error === "restricted_action") throw new UserError("Slack neleidžia botui kurti kanalų: Slack → Tools & settings → Workspace settings → Permissions → Channel Management → „People who can create public channels“ → Everyone (be svečių).");
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
  // what was added when the event was made (Naujas renginys: notes, links, files – the files in its Drive folder):
  // one message, once; waits until the files are in Drive (or 15 min.)
  const it = ev.intro;
  if (it && !r.intro_ts && (it.ready || Date.now() - Date.parse(it.at || "") > 15 * 60e3)) {
    const parts: string[] = [];
    if (String(it.notes || "").trim()) parts.push("📝 *Pastabos*\n" + md(String(it.notes).trim()));
    const links = (it.links || []).map((x) => String(x).trim()).filter(Boolean);
    if (links.length) parts.push("🔗 *Nuorodos*\n" + links.map((l) => "• " + (/^https?:\/\//i.test(l) ? `<${l}>` : md(l))).join("\n"));
    const files = it.files || [];
    if (files.length) parts.push("📎 *Failai* (renginio Google Drive)\n" + files.map((f) => "• " + (f.url ? `<${f.url}|${md(f.name).replace(/[|<>]/g, "")}>` : md(f.name) + (f.error ? " – neįkeltas: " + md(f.error) : ""))).join("\n"));
    if (parts.length) {
      const p = await slack("chat.postMessage", { channel: r.channel_id, text: parts.join("\n\n"), unfurl_links: false });
      if (p.ok) await patchRow(ev.id, { intro_ts: String(p.ts) });
    }
  }
  // the people: every active member of the Slack workspace (no guests, no bots, no deactivated accounts);
  // someone who joins Slack later is invited at the next sync. `invited` keeps their Slack user ids.
  const all = await slackMembers();
  const invited = new Set(r.invited || []), errors: string[] = [];
  const todo = all.filter((id) => !invited.has(id));
  let added = 0;
  for (let i = 0; i < todo.length; i += 500) {
    const part = todo.slice(i, i + 500);
    const inv = await slack("conversations.invite", { channel: r.channel_id, users: part.join(","), force: true });
    if (inv.ok) { part.forEach((id) => invited.add(id)); added += part.length; continue; }
    // force:true still answers an error when nobody new could be added; the per-user errors say who
    const bad = new Set(((inv.errors || []) as { user?: string; error?: string }[]).filter((e) => !/already_in_channel|cant_invite_self/.test(String(e.error))).map((e) => String(e.user)));
    if (/already_in_channel|cant_invite_self/.test(String(inv.error)) || Array.isArray(inv.errors)) part.forEach((id) => { if (!bad.has(id)) invited.add(id); });
    else errors.push(String(inv.error));
    ((inv.errors || []) as { user?: string; error?: string }[]).forEach((e) => { if (bad.has(String(e.user))) errors.push(`${e.user}: ${e.error}`); });
  }
  const notInSlack = errors, unknown: string[] = [];
  await patchRow(ev.id, { brief_ts: ts, invited: [...invited], last_error: errors.length ? "Slack kvietimas: " + errors.slice(0, 5).join(", ") : null });
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
// Paėmimai: a direct message every day to those chosen under the #dingę-daiktai message, until it is marked
// Rasta / Nerasta / Grąžinta (or the item is gone)
async function lostReminders(): Promise<number> {
  const rows = await db<{ id: string; data: { place?: string; list?: { id: string; name?: string; lost?: { qty?: number; url?: string; status?: string; remind?: string[]; remindDay?: string } }[] } }[]>("rentals?select=id,data");
  const day = today(); let sent = 0;
  for (const row of rows) {
    let changed = false;
    for (const it of row.data?.list || []) {
      const l = it.lost; if (!l || l.status || !(l.remind || []).length || l.remindDay === day) continue;
      for (const u of l.remind || []) {
        let ch = u; const o = await slack("conversations.open", { users: u }); if (o.ok) ch = String((o.channel as { id: string }).id);
        const m = await slack("chat.postMessage", { channel: ch, unfurl_links: false,
          text: `🔔 Priminimas: vis dar trūksta *${md(it.name || "")}* – ${String(l.qty ?? "").replace(".", ",")} vnt. (paėmimas: ${md(row.data.place || "—")}). ${l.url ? `<${l.url}|Atidaryk žinutę #dingę-daiktai>` : ""} ir pažymėk: Rasta, Nerasta ar Grąžinta.` });
        if (m.ok) sent++;
      }
      l.remindDay = day; changed = true;
    }
    if (changed) await db(`rentals?id=eq.${enc(row.id)}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ data: row.data, updated_at: new Date().toISOString(), updated_by: "Slack: priminimai" }) });
  }
  return sent;
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
    try { (out as Record<string, unknown>).lostReminders = await lostReminders(); } catch (e) { out.errors.push("dingę daiktai: " + (e as Error).message); }
    const members = await loadMembers();
    for (const ev of await upcoming()) {
      try { await syncEvent(ev, members); out.synced++; } catch (e) { out.errors.push(`${ev.name}: ${(e as Error).message}`); }
    }
  }
  return out;
}

// ---- Paėmimai: a missing item (the return) → #dingę-daiktai ----
const LOST_NAMES = ["dingę-daiktai", "dinge-daiktai", "dingę_daiktai", "dinge_daiktai"];
let LOST_CH = "";
async function lostChannel(): Promise<string> {
  if (LOST_CH) return LOST_CH;
  let cursor = "", found: { id: string; is_member?: boolean } | null = null;
  for (let k = 0; k < 30 && !found; k++) {
    const args: Record<string, string | number | boolean> = { limit: 1000, exclude_archived: true, types: "public_channel" }; if (cursor) args.cursor = cursor;
    const d = await slack("conversations.list", args);
    if (!d.ok) throw new UserError("Slack kanalų sąrašo gauti nepavyko: " + d.error);
    found = ((d.channels || []) as { id: string; name: string; is_member?: boolean }[]).find((c) => LOST_NAMES.includes(c.name)) || null;
    cursor = String(((d.response_metadata || {}) as { next_cursor?: string }).next_cursor || ""); if (!cursor) break;
  }
  if (found) {
    if (!found.is_member) { const j = await slack("conversations.join", { channel: found.id }); if (!j.ok && j.error !== "already_in_channel") throw new UserError("Botas negali prisijungti prie #dingę-daiktai: " + j.error + " – pakviesk jį į kanalą (/invite) Slack'e."); }
    return LOST_CH = found.id;
  }
  let made = await slack("conversations.create", { name: LOST_NAMES[0], is_private: false });
  if (!made.ok && /invalid_name/.test(String(made.error))) made = await slack("conversations.create", { name: LOST_NAMES[1], is_private: false });
  if (!made.ok) throw new UserError("Kanalo #dingę-daiktai sukurti nepavyko: " + made.error);
  const id = (made.channel as { id: string }).id;
  await slack("conversations.setPurpose", { channel: id, purpose: "Trūkstami daiktai grąžinant paėmimus – iš Event Solutions programos" }).catch(() => null);
  return LOST_CH = id;
}
async function inviteAll(channel: string) {
  const all = await slackMembers();
  for (let i = 0; i < all.length; i += 500) await slack("conversations.invite", { channel, users: all.slice(i, i + 500).join(","), force: true }).catch(() => null);
}
function lostPickerBlock(rentalId: string, itemId: string) {
  return { type: "section", block_id: `lostrm|${rentalId}|${itemId}`.slice(0, 255), text: { type: "mrkdwn", text: "🔔 *Kam kasdien priminti?* (asmeninė žinutė, kol nepažymėta)" },
    accessory: { type: "multi_users_select", action_id: "lost_remind", placeholder: { type: "plain_text", text: "Pasirink narius" } } };
}
// the picker under an earlier message (a reply in its thread)
async function lostPickerReply(rentalId: string, itemId: string): Promise<Record<string, unknown>> {
  const [row] = await db<{ data: { list?: RItem[] } }[]>(`rentals?select=data&id=eq.${enc(rentalId)}`);
  const it = (row?.data?.list || []).find((x) => x.id === itemId) as (RItem & { lost?: { ts?: string; channel?: string } }) | undefined;
  if (!it?.lost?.ts || !it.lost.channel) throw new UserError("Apie šį daiktą dar nepranešta.");
  const p = await slack("chat.postMessage", { channel: it.lost.channel, thread_ts: it.lost.ts, text: "Kam kasdien priminti?", blocks: JSON.stringify([lostPickerBlock(rentalId, itemId)]) });
  return { ok: p.ok, error: p.error, meta: p.response_metadata };
}
type RItem = { id: string; name?: string; qty?: number | string; note?: string; ev?: string; back?: boolean; backQty?: number | string; backNote?: string };
async function reportMissing(rentalId: string, itemId: string, by: string): Promise<Record<string, unknown>> {
  const [row] = await db<{ data: Record<string, unknown> }[]>(`rentals?select=data&id=eq.${enc(rentalId)}`);
  const r = row && row.data as { place?: string; pickupDate?: string; returnDate?: string; person?: string; list?: RItem[]; evs?: { id: string; note?: string }[]; eventId?: string } | undefined;
  if (!r) throw new UserError("Paėmimas nerastas (dar neišsaugotas?).");
  const it = (r.list || []).find((x) => x.id === itemId);
  if (!it) throw new UserError("Daiktas nerastas – palauk akimirką ir bandyk dar kartą.");
  const had = Number(it.qty), got = it.backQty === "" || it.backQty == null ? NaN : Number(it.backQty);
  const miss = isFinite(had) && isFinite(got) ? Math.round((had - got) * 1000) / 1000 : NaN;
  if (!(miss > 0)) throw new UserError("Pagal įrašą nieko netrūksta – įrašyk, kiek vienetų grąžinama.");
  const evIds = it.ev ? [it.ev] : (r.evs && r.evs.length ? r.evs.map((x) => x.id) : (r.eventId ? [r.eventId] : []));
  const evs = evIds.length ? await db<{ id: string; data: Ev }[]>(`events?select=id,data&id=in.(${evIds.map((x) => `"${String(x).replace(/"/g, "")}"`).join(",")})`) : [];
  const evTxt = evs.map((e) => `${md(e.data.name || e.data.title || "Renginys")}${e.data.date ? " (" + dm(String(e.data.date)) + ")" : ""}`).join(", ");
  const n = (v: number) => String(v).replace(".", ",");
  const lines = [
    `<!channel> ⚠️ *Trūksta daikto:* ${md(it.name || "")} – *${n(miss)} vnt.*`,
    `Buvo paimta ${n(had)} vnt., grąžinant rasta ${n(got)} vnt.`,
    evTxt ? `🎪 Renginys: ${evTxt}` : "",
    `📦 Paėmimas: ${md(r.place || "—")}${r.pickupDate ? " · paimta " + dm(String(r.pickupDate)) : ""}${r.returnDate ? " · grąžinti " + dm(String(r.returnDate)) : ""}${r.person ? " · atsakingas " + md(r.person) : ""}`,
    it.backNote ? `💬 ${md(it.backNote)}` : "",
    `Pranešė: ${md(by)} · <${APP}|Event Solutions programa>`,
  ].filter(Boolean);
  const ch = await lostChannel();
  await inviteAll(ch);
  // buttons under it: Rasta / Nerasta / Grąžinta – pressed in Slack, the item changes in the app (the gdrive function gets Slack's buttons)
  const val = JSON.stringify({ r: rentalId, i: itemId });
  const blocks = [
    { type: "section", text: { type: "mrkdwn", text: lines.join("\n") } },
    { type: "actions", block_id: `lost|${rentalId}|${itemId}`.slice(0, 255), elements: [
      { type: "button", text: { type: "plain_text", text: "🔎 Rasta" }, action_id: "lost_found", value: val },
      { type: "button", text: { type: "plain_text", text: "❌ Nerasta" }, action_id: "lost_notfound", value: val, style: "danger" },
      { type: "button", text: { type: "plain_text", text: "✅ Grąžinta" }, action_id: "lost_returned", value: val, style: "primary" },
    ] },
    // who gets a daily reminder (a direct message) until it is marked Rasta / Nerasta / Grąžinta (a multi-select: only as a section's accessory)
    lostPickerBlock(rentalId, itemId),
  ];
  // Slack may refuse a part of the layout: then simpler (without the reminder picker, then without the buttons) – the message goes anyway
  const why = (x: SlackRes) => String(x.error) + (x.response_metadata ? " " + JSON.stringify(x.response_metadata).slice(0, 400) : "");
  let p = await slack("chat.postMessage", { channel: ch, text: lines.join("\n"), blocks: JSON.stringify(blocks), unfurl_links: false });
  const refused: string[] = [];
  if (!p.ok && /invalid_blocks/.test(String(p.error))) { refused.push(why(p)); p = await slack("chat.postMessage", { channel: ch, text: lines.join("\n"), blocks: JSON.stringify(blocks.slice(0, 2)), unfurl_links: false }); }
  if (!p.ok && /invalid_blocks/.test(String(p.error))) { refused.push(why(p)); p = await slack("chat.postMessage", { channel: ch, text: lines.join("\n"), unfurl_links: false }); }
  if (!p.ok) throw new UserError("Slack žinutės išsiųsti nepavyko: " + why(p));
  if (refused.length) console.error("slack-sync missing: blocks refused", refused.join(" | "));
  const t = await team();
  const lost = { at: new Date().toISOString(), qty: miss, by, ts: String(p.ts), channel: ch, url: `${t.url}archives/${ch}/p${String(p.ts).replace(".", "")}`, status: "", remind: [] as string[] };
  // kept on the item at once (the app's copy follows through realtime / the answer)
  const [cur] = await db<{ data: Record<string, unknown> }[]>(`rentals?select=data&id=eq.${enc(rentalId)}`);
  if (cur) {
    const d = cur.data as { list?: (RItem & { lost?: unknown })[] }; const x = (d.list || []).find((y) => y.id === itemId);
    if (x) { x.lost = lost; await db(`rentals?id=eq.${enc(rentalId)}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ data: d, updated_at: new Date().toISOString(), updated_by: "Slack: " + by }) }); }
  }
  return { ...lost, missing: miss, ...(refused.length ? { refused } : {}) };
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
  let b: { action?: string; event_id?: string; create?: string; rental_id?: string; item_id?: string } = {};
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
      const out: Record<string, unknown> = { token: E("SLACK_BOT_TOKEN") ? "yra" : "NĖRA", on: await slackOn(), icons: [...await emojiSet()] };
      try { out.team = await team(); } catch (e) { out.team_error = (e as Error).message; return json(out); }
      if (b.event_id) { try { const ev = await loadEvent(String(b.event_id)); out.event = ev ? ev.name : "nerastas"; if (ev) out.sync = await syncEvent(ev, await loadMembers()); } catch (e) { out.sync_error = (e as Error).message; } }
      // a missing item reported as from the app (the one who saved the rental last)
      if (b.rental_id && b.item_id) {
        try {
          const [rw] = await db<{ updated_by: string | null }[]>(`rentals?select=updated_by&id=eq.${enc(String(b.rental_id))}`);
          const em = String(rw?.updated_by || "").replace(/^Slack: /, "");
          const [pr] = em.includes("@") ? await db<{ full_name?: string }[]>(`profiles?select=full_name&email=eq.${enc(em)}`) : [];
          out.missing = (b as { picker?: boolean }).picker ? await lostPickerReply(String(b.rental_id), String(b.item_id)) : await reportMissing(String(b.rental_id), String(b.item_id), pr?.full_name || em || "programa");
        } catch (e) { out.missing_error = (e as Error).message; }
      }
      return json(out);
    }
    // a missing item from the temporary Paėmimai link (rentals-guest, with the same secret): who reported it is given
    if (action === "missing_internal") {
      const s3 = E("CRON_SECRET");
      if (!s3 || req.headers.get("x-cron-secret") !== s3) return json({ error: "Unauthorized" }, 401);
      if (!(await slackOn())) return json({ error: "Slack išjungtas – pranešti nepavyko." }, 400);
      return json({ ok: true, ...(await reportMissing(String(b.rental_id || ""), String(b.item_id || ""), String((b as { by?: string }).by || "nuoroda").slice(0, 100))) });
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
      const id = String(b.event_id || "");
      const ev = await loadEvent(id);
      if (!ev) {
        // the event was deleted in the app: its channel – a message and archived at once
        const [row] = await db<Row[]>(`slack_channels?event_id=eq.${enc(id)}&select=*`);
        if (row && !row.archived_at) return json({ ok: true, ...(await syncEvent({ id, name: row.name, deletedAt: new Date().toISOString() }, [])) });
        return json({ error: "Renginys nerastas (dar neišsaugotas?)." }, 404);
      }
      const cr = b.create === "force" ? "force" : b.create === "auto" ? "auto" : "";
      return json({ ok: true, ...(await syncEvent(ev, await loadMembers(), cr)) });
    }
    if (action === "missing") {
      let ok = who.role === "admin" || who.level === "super";
      if (!ok) { const [x] = await db<{ can_edit: boolean }[]>(`role_permissions?select=can_edit&section=eq.rentals&role=eq.${enc(who.role)}`); ok = !!(x && x.can_edit); }
      if (!ok) return json({ error: "Pranešti gali tie, kas redaguoja Paėmimus." }, 403);
      if (!(await slackOn())) return json({ error: "Slack išjungtas – įjunk Admin skiltyje." }, 400);
      const [p] = await db<{ full_name?: string; first_name?: string; last_name?: string; email?: string }[]>(`profiles?select=full_name,first_name,last_name,email&id=eq.${enc(who.id)}`);
      const by = p ? (p.full_name || [p.first_name, p.last_name].filter(Boolean).join(" ") || p.email || "") : "";
      return json({ ok: true, ...(await reportMissing(String(b.rental_id || ""), String(b.item_id || ""), by)) });
    }
    if (action === "backfill") {
      if (!(who.role === "admin" || who.level === "super")) return json({ error: "Tik administratoriams." }, 403);
      if (!(await slackOn())) return json({ error: "Slack išjungtas – įjunk Admin skiltyje." }, 400);
      const members = await loadMembers(), list = await upcoming(), out = { synced: 0, errors: [] as string[] };
      for (const ev of list) { try { const r = await syncEvent(ev, members, ""); if (!r.skipped && !r.archived) out.synced++; } catch (e) { out.errors.push(`${ev.name}: ${(e as Error).message}`); } }
      return json({ ok: true, ...out, events: list.length });
    }
    return json({ error: "Nežinomas veiksmas." }, 400);
  } catch (e) {
    if (e instanceof UserError) return json({ error: e.message }, 400);
    console.error("slack-sync", (e as Error).message);
    return json({ error: "Klaida: " + (e as Error).message }, 500);
  }
});
