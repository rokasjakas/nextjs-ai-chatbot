// Supabase Edge Function: ai-chat
//
// The „AI asistentas“ card on the app's home page: a team member asks everyday
// questions, Claude answers in Lithuanian. The answer is streamed back as plain
// text (chunks of UTF-8), so it appears while it is being written.
//
// POST { messages: [{ role:"user"|"assistant", content:"…" }, …] }   (the last one is the user's)
//   -> text/plain stream with the answer
//
// Only a signed-in, approved member may ask (the public anon key alone is not enough).
// Secret: ANTHROPIC_API_KEY   (supabase secrets set ANTHROPIC_API_KEY=sk-ant-…)
// Deploy: supabase functions deploy ai-chat
import Anthropic from "npm:@anthropic-ai/sdk";

export const VERSION = 1;
const MODEL = "claude-opus-5-5";
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

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  if (!(await approvedMember(req))) return json({ error: "Prisijunk iš naujo (tik patvirtintiems nariams)." }, 401);
  const key = (Deno.env.get("ANTHROPIC_API_KEY") ?? "").trim();
  if (!key) return json({ error: "AI dar nesukonfigūruotas: Supabase → Edge Functions → Secrets → ANTHROPIC_API_KEY." }, 503);

  let body: { messages?: { role?: string; content?: string }[] };
  try { body = await req.json(); } catch { return json({ error: "Blogas užklausos formatas." }, 400); }
  // only plain user/assistant text, alternating, starting and ending with the user
  const msgs: Anthropic.MessageParam[] = [];
  for (const m of (body.messages ?? []).slice(-MAX_TURNS)) {
    const role = m?.role === "assistant" ? "assistant" : m?.role === "user" ? "user" : null;
    const text = String(m?.content ?? "").slice(0, MAX_CHARS).trim();
    if (!role || !text) continue;
    if (msgs.length && msgs[msgs.length - 1].role === role) msgs[msgs.length - 1].content += "\n\n" + text;
    else msgs.push({ role, content: text });
  }
  while (msgs.length && msgs[0].role !== "user") msgs.shift();
  if (!msgs.length || msgs[msgs.length - 1].role !== "user") return json({ error: "Nėra klausimo." }, 400);

  const client = new Anthropic({ apiKey: key });
  const enc = new TextEncoder();
  const out = new ReadableStream<Uint8Array>({
    async start(ctrl) {
      try {
        // a declined request is re-run on Anthropic's recommended fallback model (server side)
        const params = {
          model: MODEL,
          max_tokens: 16000,
          betas: ["server-side-fallback-2026-07-01"],
          fallbacks: "default",
          output_config: { effort: "low" },   // everyday questions: quick answers
          system: SYSTEM,
          messages: msgs,
        };
        // deno-lint-ignore no-explicit-any
        const stream = client.beta.messages.stream(params as any);
        for await (const ev of stream) {
          if (ev.type === "content_block_delta" && ev.delta.type === "text_delta") ctrl.enqueue(enc.encode(ev.delta.text));
        }
        const final = await stream.finalMessage();
        if (final.stop_reason === "refusal") ctrl.enqueue(enc.encode("\n\n(Į šį klausimą atsakyti negaliu.)"));
        else if (final.stop_reason === "max_tokens") ctrl.enqueue(enc.encode("\n\n(Atsakymas nutrūko – per ilgas.)"));
      } catch (e) {
        let msg = "AI klaida.";
        if (e instanceof Anthropic.AuthenticationError) msg = "Neteisingas ANTHROPIC_API_KEY.";
        else if (e instanceof Anthropic.RateLimitError) msg = "Per daug užklausų – pabandyk po minutės.";
        else if (e instanceof Anthropic.APIError) msg = `AI klaida (${e.status}).`;
        console.error("ai-chat", (e as Error).message);
        ctrl.enqueue(enc.encode("\n\n⚠ " + msg));
      } finally {
        ctrl.close();
      }
    },
  });
  return new Response(out, { headers: { ...corsHeaders, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
});
