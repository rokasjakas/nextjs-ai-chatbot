// Supabase Edge Function: uta-pin
//
// „Kuro kortelė“ in the event letter (supabase/sql/uta_pin_links.sql): the driver opens
// auto.html?pin=<token>, photographs the UTA card's front and back, and this function reads the
// card number from the photos (AI), finds that card and returns its PIN. No sign-in: the link's
// token is the key, and it works only on the event's days (a day before and after) and only for
// the event's vehicles' cards. The number is never typed in – the cards' numbers follow each other
// (…0046 9, …0047 7), so only a photo of the card itself shows the PIN.
// Every attempt is written to uta_pin_views; at most 10 attempts a link per hour.
//
// POST {"t":"<token>","front":{"mime":"image/jpeg","data":"<base64>"},"back":{…}}
//   -> {"pin":"1234","card":"•••• 0046 9","title":"AUTO 1","vehicle":"Iveco Daily MPL 840"}
// Secrets: GROQ_API_KEY or GEMINI_API_KEY (as ai-chat). SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are given.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const MAX_IMAGE = 6_000_000;   // base64 characters of one photo
const HOURLY = 10;

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
// the same card with / without the check digit, or an old short number (as in the app)
function sameNo(a: string, b: string): boolean {
  const x = digits(a), y = digits(b); if (!x || !y) return false; if (x === y) return true;
  const [s, l] = x.length < y.length ? [x, y] : [y, x];
  if (s.length >= 12) return l.length === s.length + 1 && l.startsWith(s);
  return s.length >= 4 && s.length <= 8 && l.length >= 12 && l.slice(0, -1).endsWith(s);
}
const mask = (no: string) => { const g = String(no).trim().split(/\s+/); return g.length >= 3 ? "•••• " + g.slice(-2).join(" ") : "•••• " + digits(no).slice(-6); };
const today = () => new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Vilnius" }).format(new Date());
const addDays = (d: string, n: number) => { const t = new Date(d + "T12:00:00Z"); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); };

type Img = { mime: string; data: string };
const PROMPT = "Pirmoje nuotraukoje – degalų kortelės (UTA / Union Tank) priekis, antroje – galas. " +
  "Perskaityk kortelės numerį (dažniausiai 7060… – 17–19 skaitmenų, gali būti suskirstytas grupėmis). " +
  "Atsakyk TIK JSON: {\"card\":\"skaitmenys be tarpų arba tuščia\",\"is_card\":true|false,\"back\":true|false} – " +
  "is_card: ar tai tikrai degalų / mokėjimo kortelė (ne ekranas, ne popierius); back: ar antroje nuotraukoje kortelės galas.";

async function readCard(front: Img, back: Img): Promise<{ card: string; is_card: boolean; back: boolean }> {
  let text = "";
  if (E("GROQ_API_KEY")) {
    const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${E("GROQ_API_KEY")}` },
      body: JSON.stringify({ model: E("GROQ_VISION_MODEL") || "meta-llama/llama-4-scout-17b-16e-instruct", temperature: 0, max_tokens: 200,
        messages: [{ role: "user", content: [{ type: "text", text: PROMPT },
          { type: "image_url", image_url: { url: `data:${front.mime};base64,${front.data}` } },
          { type: "image_url", image_url: { url: `data:${back.mime};base64,${back.data}` } }] }] }),
    });
    if (!r.ok) throw new Error("AI " + r.status);
    const j = await r.json(); text = j?.choices?.[0]?.message?.content ?? "";
  } else if (E("GEMINI_API_KEY")) {
    const model = E("GEMINI_MODEL") || "gemini-flash-latest";
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, {
      method: "POST", headers: { "Content-Type": "application/json", "x-goog-api-key": E("GEMINI_API_KEY") },
      body: JSON.stringify({ generationConfig: { temperature: 0 }, contents: [{ role: "user", parts: [{ text: PROMPT },
        { inline_data: { mime_type: front.mime, data: front.data } }, { inline_data: { mime_type: back.mime, data: back.data } }] }] }),
    });
    if (!r.ok) throw new Error("AI " + r.status);
    const j = await r.json(); text = (j?.candidates?.[0]?.content?.parts ?? []).map((p: { text?: string }) => p.text ?? "").join("");
  } else throw new Error("AI nesukonfigūruotas");
  const m = text.match(/\{[\s\S]*\}/);
  try { const o = JSON.parse(m ? m[0] : text); return { card: digits(o.card), is_card: o.is_card !== false, back: o.back !== false }; }
  catch { return { card: digits(text).slice(0, 20), is_card: true, back: true }; }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST" }, 405);
  let body: { t?: string; front?: Img; back?: Img };
  try { body = await req.json(); } catch { return json({ error: "Blogas užklausos formatas." }, 400); }
  const t = String(body.t ?? "");
  if (!/^[0-9a-f]{24,64}$/.test(t)) return json({ error: "Nuoroda neteisinga." }, 400);
  const ok = (i?: Img) => !!i && /^image\/(jpeg|png|webp)$/.test(String(i.mime)) && typeof i.data === "string" && i.data.length > 1000 && i.data.length < MAX_IMAGE;
  if (!ok(body.front) || !ok(body.back)) return json({ error: "Nufotografuok kortelės priekį ir galą." }, 400);

  const log = (row: Record<string, unknown>) => db("uta_pin_views", { method: "POST", body: JSON.stringify({ token: t, ...row }) }).catch(() => {});
  try {
    const [l] = await db<{ token: string; event_name: string; card_ids: string[]; valid_from: string; valid_to: string }[]>(`uta_pin_links?token=eq.${t}&select=*`);
    if (!l) return json({ error: "Nuoroda nebegalioja." }, 404);
    const d = today();
    if (d < addDays(l.valid_from, -1) || d > addDays(l.valid_to, 1)) return json({ error: "Nuoroda galioja tik renginio dienomis." }, 403);
    const since = new Date(Date.now() - 3600_000).toISOString();
    const recent = await db<{ id: number }[]>(`uta_pin_views?token=eq.${t}&at=gte.${encodeURIComponent(since)}&select=id`);
    if (recent.length >= HOURLY) return json({ error: "Per daug bandymų – pabandyk po valandos." }, 429);

    const img = (i: Img) => ({ mime: i.mime, data: i.data.replace(/\s+/g, "") });
    const read = await readCard(img(body.front!), img(body.back!));
    if (!read.is_card) { await log({ event_name: l.event_name, ok: false, reason: "ne kortelė", card_read: read.card || null }); return json({ error: "Nuotraukoje kortelės neatpažinau – nufotografuok pačią kortelę iš arti." }, 422); }
    if (!read.back) { await log({ event_name: l.event_name, ok: false, reason: "be galo", card_read: read.card || null }); return json({ error: "Antroje nuotraukoje – kortelės galas (kita pusė)." }, 422); }
    if (read.card.length < 12) { await log({ event_name: l.event_name, ok: false, reason: "numeris neperskaitytas", card_read: read.card || null }); return json({ error: "Kortelės numerio perskaityti nepavyko – fotografuok iš arčiau, be atspindžių." }, 422); }

    const cards = await db<{ id: string; card_no: string; title: string; vehicle_name: string | null; active: boolean }[]>(`uta_cards?select=id,card_no,title,vehicle_name,active&active=eq.true`);
    const allowed = (l.card_ids ?? []).length ? cards.filter((c) => l.card_ids.includes(c.id)) : cards;
    const hit = allowed.filter((c) => sameNo(c.card_no, read.card));
    if (hit.length !== 1) {
      await log({ event_name: l.event_name, ok: false, reason: cards.some((c) => sameNo(c.card_no, read.card)) ? "ne šio renginio kortelė" : "kortelė nerasta", card_read: read.card });
      return json({ error: cards.some((c) => sameNo(c.card_no, read.card)) ? "Ši kortelė ne šio renginio automobiliui." : "Tokios kortelės nėra – pabandyk nufotografuoti dar kartą." }, 404);
    }
    const c = hit[0];
    const [p] = await db<{ pin: string }[]>(`uta_pins?card_id=eq.${c.id}&select=pin`);
    await log({ event_name: l.event_name, card_id: c.id, ok: !!p, reason: p ? null : "PIN neįrašytas", card_read: read.card });
    if (!p) return json({ error: "Šios kortelės PIN dar neįrašytas – kreipkis į ofisą." }, 404);
    return json({ pin: p.pin, card: mask(c.card_no), title: c.title || "", vehicle: c.vehicle_name || "" });
  } catch (e) {
    return json({ error: "Nepavyko: " + (e instanceof Error ? e.message : String(e)) }, 500);
  }
});
