// Supabase Edge Function: ai-chat
//
// The „AI asistentas“ card on the app's home page: a team member asks everyday
// questions, Google Gemini answers in Lithuanian. The answer is streamed back as
// plain text (chunks of UTF-8), so it appears while it is being written.
//
// POST { messages: [{ role:"user"|"assistant", content:"…" }, …] }   (the last one is the user's)
//   -> text/plain stream with the answer
// POST { messages, image: { mime:"image/jpeg"|"image/png"|"application/pdf", data:"<base64>" } }
//   the picture goes with the last question (e.g. Transportas: read a document's end date; pictures and PDF)
//
// Only a signed-in, approved member may ask (the public anon key alone is not enough).
//   GEMINI_API_KEY    aistudio.google.com → Get API key („AIza…“, GEMINI_MODEL default gemini-flash-latest)
//                     or a Vertex AI express mode key from Google Cloud („AQ.…“, default gemini-2.5-flash)
//   Supabase → Edge Functions → Secrets (or: supabase secrets set GEMINI_API_KEY=…)
// Deploy:  supabase functions deploy ai-chat
// On free plans the service may use the questions to improve its models – the card says so.

export const VERSION = 6;
const MAX_IMAGE = 5_500_000;   // base64 signs (~4 MB file)
const MAX_TURNS = 40;          // messages kept from the conversation
const MAX_CHARS = 12000;       // per message

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" } });

const SYSTEM = `Tu esi „Event Solutions“ komandos (renginių techninis aptarnavimas: garsas, šviesa, video, scenos, sandėlis, logistika) pagalbininkas programėlėje.
Atsakyk lietuviškai, nebent narys rašo kita kalba. Atsakymai trumpi ir praktiški; jei reikia – žingsniai ar sąrašas.
Nežinai įmonės vidinių duomenų (renginių, sandėlio, žmonių) – jei klausiama apie juos, pasakyk, kur jų ieškoti programėlėje, ir nespėliok skaičių.`;

async function approvedMember(req: Request): Promise<boolean> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  const anon = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
  if (!token || token === anon) return false;
  const url = Deno.env.get("SUPABASE_URL") ?? "";
  const who = await fetch(`${url}/auth/v1/user`, { headers: { apikey: anon, Authorization: `Bearer ${token}` } });
  if (!who.ok) return false;
  const user = await who.json();
  if (!user?.id) return false;
  const res = await fetch(`${url}/rest/v1/rpc/is_approved`, {
    method: "POST",
    headers: { apikey: anon, Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: "{}",
  });
  return res.ok && (await res.json()) === true;
}

type Turn = { role: "user" | "model"; parts: { text: string }[] };
type Img = { mime: string; data: string } | null;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  if (!(await approvedMember(req))) return json({ error: "Prisijunk iš naujo (tik patvirtintiems nariams)." }, 401);
  const E = (k: string) => (Deno.env.get(k) ?? "").trim();
  if (!E("GEMINI_API_KEY")) return json({ error: "AI dar nesukonfigūruotas: Supabase → Edge Functions → Secrets → GEMINI_API_KEY (raktas: aistudio.google.com)." }, 503);

  let body: { messages?: { role?: string; content?: string }[]; image?: { mime?: string; data?: string } };
  try { body = await req.json(); } catch { return json({ error: "Blogas užklausos formatas." }, 400); }
  // only plain user/assistant text, alternating, starting and ending with the user
  const turns: Turn[] = [];
  for (const m of (body.messages ?? []).slice(-MAX_TURNS)) {
    const role = m?.role === "assistant" ? "model" : m?.role === "user" ? "user" : null;
    const text = String(m?.content ?? "").slice(0, MAX_CHARS).trim();
    if (!role || !text) continue;
    if (turns.length && turns[turns.length - 1].role === role) turns[turns.length - 1].parts[0].text += "\n\n" + text;
    else turns.push({ role, parts: [{ text }] });
  }
  while (turns.length && turns[0].role !== "user") turns.shift();
  if (!turns.length || turns[turns.length - 1].role !== "user") return json({ error: "Nėra klausimo." }, 400);
  let img: Img = null;
  if (body.image && typeof body.image.data === "string") {
    const mime = String(body.image.mime ?? "");
    if (!/^(image\/(jpeg|png|webp)|application\/pdf)$/.test(mime)) return json({ error: "Netinkamas failo tipas (tik nuotrauka arba PDF)." }, 400);
    if (body.image.data.length > MAX_IMAGE) return json({ error: "Failas per didelis AI skaitymui." }, 413);
    img = { mime, data: body.image.data.replace(/\s+/g, "") };
  }

  // two kinds of keys: a Gemini API key from aistudio.google.com („AIza…“) and a Vertex AI key from Google Cloud
  // (express mode, „AQ.…“) – each has its own address; the other one is tried when the first refuses
  const key = E("GEMINI_API_KEY"), vertexKey = /^AQ\./.test(key);
  const payload = JSON.stringify({ systemInstruction: { parts: [{ text: SYSTEM }] },
    contents: img ? turns.map((t, i) => i === turns.length - 1 ? { role: t.role, parts: [...t.parts, { inlineData: { mimeType: img!.mime, data: img!.data } }] } : t) : turns,
    generationConfig: { maxOutputTokens: 4096 } });
  const studio = (m: string) => fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(m)}:streamGenerateContent?alt=sse`, {
    method: "POST", headers: { "Content-Type": "application/json", "x-goog-api-key": key }, body: payload });
  const vertex = (m: string) => fetch(`https://aiplatform.googleapis.com/v1/publishers/google/models/${encodeURIComponent(m)}:streamGenerateContent?alt=sse&key=${encodeURIComponent(key)}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: payload });
  // Vertex AI has no „…-latest“ names: a fixed model there
  const vModel = E("GEMINI_MODEL") && !/latest/.test(E("GEMINI_MODEL")) ? E("GEMINI_MODEL") : "gemini-2.5-flash";
  const sModel = E("GEMINI_MODEL") || "gemini-flash-latest";
  let model = vertexKey ? vModel : sModel;
  let api = await (vertexKey ? vertex(model) : studio(model));
  if (!api.ok && [400, 401, 403, 404].includes(api.status)) {
    const other = await (vertexKey ? studio(sModel) : vertex(vModel)).catch(() => null);
    if (other && other.ok) { api = other; model = vertexKey ? sModel : vModel; }
  }
  // a model name Google does not know (any more): the next Flash models
  if (!api.ok && api.status === 404) {
    for (const m of ["gemini-2.5-flash", "gemini-2.0-flash"].filter((x) => x !== model)) {
      const r = await (vertexKey ? vertex(m) : studio(m)).catch(() => null);
      if (r && r.ok) { api = r; model = m; break; }
    }
  }
  if (!api.ok || !api.body) {
    const t = await api.text().catch(() => "");
    console.error("ai-chat", api.status, t.slice(0, 500));
    // Google's own reason, so the cause is seen in the app (the key itself is never in it)
    let why = "", reason = "";
    try { const j = JSON.parse(t)?.error ?? {}; why = String(j.message ?? ""); reason = String((j.details ?? []).map((d: { reason?: string }) => d?.reason ?? "").filter(Boolean)[0] ?? j.status ?? ""); } catch { /* not JSON */ }
    const hint = /SERVICE_DISABLED|has not been used|is disabled/i.test(why + reason) ? (vertexKey ? " – Google Cloud projekte įjunk „Vertex AI API“ (APIs & Services → Library)." : " – Google Cloud projekte įjunk „Generative Language API“ (arba susikurk raktą aistudio.google.com).")
      : /API_KEY_HTTP_REFERRER_BLOCKED|referer|referrer/i.test(why + reason) ? " – rakte nuimk „Application restrictions“ (svetainių / referrer apribojimą): serveris jo nesiunčia."
      : /API_KEY_IP_ADDRESS_BLOCKED|IP address/i.test(why + reason) ? " – rakte nuimk IP adresų apribojimą."
      : /API_KEY_SERVICE_BLOCKED|blocked/i.test(why + reason) ? " – rakto „API restrictions“ turi leisti „Generative Language API“."
      : /unregistered callers|API key not/i.test(why) ? " – raktas Google nepasiekė: Supabase paslaptis turi vadintis tiksliai GEMINI_API_KEY, reikšmė – tik raktas (be tarpų ir kabučių)."
      : /location|region|country/i.test(why) ? " – Gemini API šiam regionui / projektui neprieinamas."
      : /billing|quota/i.test(why) ? " – patikrink kvotą / mokėjimus Google AI Studio." : "";
    const msg = api.status === 429 ? "Pasiektas nemokamo plano limitas – pabandyk po minutės."
      : api.status === 401 || (api.status === 400 && /API key/i.test(t)) ? "Neteisingas Gemini raktas (patikrink Supabase paslaptį GEMINI_API_KEY – be tarpų ir kabučių)."
      : api.status === 403 ? `Gemini raktas neturi teisės${hint || "."}${why ? " Google: " + why.slice(0, 220) : ""}`
      : api.status === 404 || /model.*(not found|does not exist|decommissioned)/i.test(t) ? `Modelis „${model}“ nerastas – nurodyk kitą (GEMINI_MODEL).`
      : `AI klaida (${api.status})${why ? ": " + why.slice(0, 220) : "."}`;
    return json({ error: msg }, 502);
  }

  // Google sends Server-Sent Events: "data: {json}" lines; only the answer's text goes on to the app
  const enc = new TextEncoder(), dec = new TextDecoder();
  const reader = api.body.getReader();
  const out = new ReadableStream<Uint8Array>({
    async start(ctrl) {
      let buf = "", any = false, blocked = "";
      const take = (line: string) => {
        if (!line.startsWith("data:")) return;
        const data = line.slice(5).trim(); if (!data || data === "[DONE]") return;
        try {
          const j = JSON.parse(data);
          const c = j?.candidates?.[0];
          for (const p of c?.content?.parts ?? []) if (typeof p?.text === "string" && !p.thought) { ctrl.enqueue(enc.encode(p.text)); any = true; }
          if (c?.finishReason === "MAX_TOKENS") blocked = "\n\n(Atsakymas nutrūko – per ilgas.)";
          else if (c?.finishReason && !["STOP", "FINISH_REASON_UNSPECIFIED"].includes(c.finishReason)) blocked = "\n\n(Į šį klausimą atsakyti negaliu.)";
          if (j?.promptFeedback?.blockReason) blocked = "\n\n(Į šį klausimą atsakyti negaliu.)";
        } catch { /* a broken line: skip */ }
      };
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let i;
          while ((i = buf.indexOf("\n")) >= 0) { take(buf.slice(0, i).replace(/\r$/, "")); buf = buf.slice(i + 1); }
        }
        if (buf) take(buf);
        if (blocked) ctrl.enqueue(enc.encode(blocked));
        else if (!any) ctrl.enqueue(enc.encode("(Atsakymo nėra.)"));
      } catch (e) {
        console.error("ai-chat stream", (e as Error).message);
        ctrl.enqueue(enc.encode("\n\n⚠ Ryšys su AI nutrūko."));
      } finally {
        ctrl.close();
      }
    },
  });
  return new Response(out, { headers: { ...corsHeaders, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
});
