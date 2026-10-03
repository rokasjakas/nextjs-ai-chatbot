// Supabase Edge Function: ai-chat
//
// The „AI asistentas“ card on the app's home page: a team member asks everyday
// questions, a free AI service (Groq or Google Gemini) answers in Lithuanian. The answer is streamed back as
// plain text (chunks of UTF-8), so it appears while it is being written.
//
// POST { messages: [{ role:"user"|"assistant", content:"…" }, …] }   (the last one is the user's)
//   -> text/plain stream with the answer
//
// Only a signed-in, approved member may ask (the public anon key alone is not enough).
// The AI service is the one whose key is set (first found):
//   GROQ_API_KEY      free key, no card: console.groq.com → API Keys      (GROQ_MODEL, default openai/gpt-oss-120b)
//   GEMINI_API_KEY    aistudio.google.com → Get API key                   (GEMINI_MODEL, default gemini-flash-latest)
//   AI_API_KEY + AI_BASE_URL + AI_MODEL   any OpenAI-compatible service, e.g. OpenRouter
//     (AI_BASE_URL=https://openrouter.ai/api/v1, AI_MODEL=<a model id ending in :free>)
//   supabase secrets set GROQ_API_KEY=…
// Deploy:  supabase functions deploy ai-chat
// On free plans the service may use the questions to improve its models – the card says so.

export const VERSION = 3;
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

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  if (!(await approvedMember(req))) return json({ error: "Prisijunk iš naujo (tik patvirtintiems nariams)." }, 401);
  const E = (k: string) => (Deno.env.get(k) ?? "").trim();
  const provider = E("GROQ_API_KEY") ? "groq" : E("GEMINI_API_KEY") ? "gemini" : E("AI_API_KEY") && E("AI_BASE_URL") && E("AI_MODEL") ? "openai" : "";
  if (!provider) return json({ error: "AI dar nesukonfigūruotas: Supabase → Edge Functions → Secrets → GROQ_API_KEY (nemokamas raktas: console.groq.com)." }, 503);

  let body: { messages?: { role?: string; content?: string }[] };
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

  let api: Response, model: string;
  if (provider === "gemini") {
    model = E("GEMINI_MODEL") || "gemini-flash-latest";
    api = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:streamGenerateContent?alt=sse`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": E("GEMINI_API_KEY") },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: SYSTEM }] }, contents: turns, generationConfig: { maxOutputTokens: 4096 } }),
    });
  } else {
    // Groq and the other OpenAI-compatible services: /chat/completions with stream:true
    const base = provider === "groq" ? "https://api.groq.com/openai/v1" : E("AI_BASE_URL").replace(/\/$/, "");
    const key = provider === "groq" ? E("GROQ_API_KEY") : E("AI_API_KEY");
    model = provider === "groq" ? (E("GROQ_MODEL") || "openai/gpt-oss-120b") : E("AI_MODEL");
    const req: Record<string, unknown> = {
      model, stream: true, max_tokens: 4096,
      messages: [{ role: "system", content: SYSTEM }, ...turns.map((t) => ({ role: t.role === "model" ? "assistant" : "user", content: t.parts[0].text }))],
    };
    if (provider === "groq" && /gpt-oss/.test(model)) req.reasoning_effort = "low";   // everyday questions: quick answers
    api = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
      body: JSON.stringify(req),
    });
  }
  if (!api.ok || !api.body) {
    const t = await api.text().catch(() => "");
    console.error("ai-chat", api.status, t.slice(0, 500));
    const msg = api.status === 429 ? "Pasiektas nemokamo plano limitas – pabandyk po minutės."
      : api.status === 401 || (api.status === 400 && /API key/i.test(t)) ? "Neteisingas AI raktas (patikrink Supabase paslaptį)."
      : api.status === 403 ? "AI raktas neturi teisės (patikrink raktą)."
      : api.status === 404 || /model.*(not found|does not exist|decommissioned)/i.test(t) ? `Modelis „${model}“ nerastas – nurodyk kitą (${provider === "groq" ? "GROQ_MODEL" : provider === "gemini" ? "GEMINI_MODEL" : "AI_MODEL"}).`
      : `AI klaida (${api.status}).`;
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
          if (Array.isArray(j?.choices)) {   // OpenAI-compatible: only the answer, not the model's reasoning
            const ch = j.choices[0];
            const t = ch?.delta?.content;
            if (typeof t === "string" && t) { ctrl.enqueue(enc.encode(t)); any = true; }
            if (ch?.finish_reason === "length") blocked = "\n\n(Atsakymas nutrūko – per ilgas.)";
            else if (ch?.finish_reason === "content_filter") blocked = "\n\n(Į šį klausimą atsakyti negaliu.)";
            return;
          }
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
