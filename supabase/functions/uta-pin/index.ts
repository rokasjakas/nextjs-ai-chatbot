// Supabase Edge Function: uta-pin
//
// „Kuro kortelė“ in the event letter (supabase/sql/uta_pin_links.sql, uta_card_cvc.sql): the driver
// opens auto.html?pin=<token> and types the digits printed on the card's back after „CVC:“ – the card
// with that code is found among the event's cards and its PIN is shown. No sign-in: the link's token
// is the key, and it works only on the event's days (a day before and after) and only for the event's
// vehicles' cards. Every attempt is written to uta_pin_views with the name, time and the phone's
// place; at most 10 attempts a link per hour, and the link is locked for a day after 5 wrong codes.
//
// POST {"t":"<token>","name":"Vardas Pavardė","loc":{"lat":54.6,"lng":25.2,"acc":12},"cvc":"123"}
//   -> {"pin":"1234","card":"•••• 0046 9","title":"AUTO 1","vehicle":"Iveco Daily MPL 840"}
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are given by Supabase.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const HOURLY = 10, LINK_FAILS = 5;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" } });
}
const E = (n: string) => Deno.env.get(n) ?? "";
async function db<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const key = E("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${E("SUPABASE_URL")}/rest/v1/${path}`, {
    ...init,
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`Database ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const t = await res.text();
  return (t ? JSON.parse(t) : null) as T;
}
const digits = (s: unknown) => String(s ?? "").replace(/\D/g, "");
const mask = (no: string) => { const g = String(no).trim().split(/\s+/); return g.length >= 3 ? "•••• " + g.slice(-2).join(" ") : "•••• " + digits(no).slice(-6); };
const today = () => new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Vilnius" }).format(new Date());
const addDays = (d: string, n: number) => { const t = new Date(d + "T12:00:00Z"); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); };
// the same in time: no hint from how long a wrong CVC takes
function same(a: string, b: string): boolean { if (a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; }

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST" }, 405);
  let body: { t?: string; name?: string; loc?: { lat?: number; lng?: number; acc?: number }; cvc?: string };
  try { body = await req.json(); } catch { return json({ error: "Blogas užklausos formatas." }, 400); }
  const t = String(body.t ?? "");
  if (!/^[0-9a-f]{24,64}$/.test(t)) return json({ error: "Nuoroda neteisinga." }, 400);
  const name = String(body.name ?? "").replace(/\s+/g, " ").trim().slice(0, 120);
  if (name.length < 3) return json({ error: "Įrašyk savo vardą ir pavardę." }, 400);
  const cvc = digits(body.cvc);
  if (cvc.length < 3 || cvc.length > 8) return json({ error: "Nurašyk skaičius kortelės gale po „CVC:“." }, 400);
  const L = body.loc, num = (x: unknown, lo: number, hi: number) => typeof x === "number" && isFinite(x) && x >= lo && x <= hi ? x : null;
  const lat = L ? num(L.lat, -90, 90) : null, lng = L ? num(L.lng, -180, 180) : null;
  const where = lat != null && lng != null ? { lat: +lat.toFixed(6), lng: +lng.toFixed(6), acc: L && num(L.acc, 0, 100000) != null ? Math.round(L.acc as number) : null } : {};
  const log = (row: Record<string, unknown>) => db("uta_pin_views", { method: "POST", body: JSON.stringify({ token: t, driver_name: name, ...where, ...row }) }).catch(() => {});

  try {
    const [l] = await db<{ token: string; event_name: string; card_ids: string[]; valid_from: string; valid_to: string }[]>(`uta_pin_links?token=eq.${t}&select=*`);
    if (!l) return json({ error: "Nuoroda nebegalioja." }, 404);
    const d = today();
    if (d < addDays(l.valid_from, -1) || d > addDays(l.valid_to, 1)) return json({ error: "Nuoroda galioja tik renginio dienomis." }, 403);
    const since = new Date(Date.now() - 3600_000).toISOString();
    const recent = await db<{ id: number }[]>(`uta_pin_views?token=eq.${t}&at=gte.${encodeURIComponent(since)}&select=id`);
    if (recent.length >= HOURLY) return json({ error: "Per daug bandymų – pabandyk po valandos." }, 429);

    // a link locked for a day after too many wrong codes
    const dayAgo = new Date(Date.now() - 86400_000).toISOString();
    const fails = await db<{ id: number }[]>(`uta_pin_views?token=eq.${t}&reason=eq.${encodeURIComponent("neteisingas kodas")}&at=gte.${encodeURIComponent(dayAgo)}&select=id`);
    if (fails.length >= LINK_FAILS) return json({ error: "Per daug neteisingų bandymų – nuoroda užrakinta parai. Kreipkis į ofisą." }, 429);

    const cards = await db<{ id: string; card_no: string; title: string; vehicle_name: string | null }[]>(`uta_cards?select=id,card_no,title,vehicle_name&active=eq.true`);
    const allowed = (l.card_ids ?? []).length ? cards.filter((c) => l.card_ids.includes(c.id)) : cards;
    if (!allowed.length) return json({ error: "Šiam renginiui kortelių nėra – kreipkis į ofisą." }, 404);
    const codes = await db<{ card_id: string; cvc: string }[]>(`uta_card_cvc?card_id=in.(${allowed.map((c) => c.id).join(",")})&select=card_id,cvc`);
    const hit = allowed.filter((c) => codes.some((x) => x.card_id === c.id && same(x.cvc, cvc)));
    if (hit.length !== 1) {
      await log({ event_name: l.event_name, ok: false, reason: hit.length ? "keli atitikmenys" : "neteisingas kodas", card_read: cvc.replace(/.(?=.{2})/g, "•") });
      return json({ error: hit.length ? "Šis kodas tinka kelioms kortelėms – kreipkis į ofisą." : !codes.length ? "Šio renginio kortelėms kodai dar neįrašyti – kreipkis į ofisą." : "Tokios kortelės nėra – patikrink skaičius po „CVC:“." }, hit.length ? 409 : 404);
    }
    const c = hit[0];
    const [p] = await db<{ pin: string }[]>(`uta_pins?card_id=eq.${c.id}&select=pin`);
    await log({ event_name: l.event_name, card_id: c.id, ok: !!p, reason: p ? null : "PIN neįrašytas", card_read: null, vehicle: [c.title, c.vehicle_name].filter(Boolean).join(" · ") || null });
    if (!p) return json({ error: "Šios kortelės PIN dar neįrašytas – kreipkis į ofisą." }, 404);
    return json({ pin: p.pin, card: mask(c.card_no), title: c.title || "", vehicle: c.vehicle_name || "" });
  } catch (e) {
    return json({ error: "Nepavyko: " + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});
