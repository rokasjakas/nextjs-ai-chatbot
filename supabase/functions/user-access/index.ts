// Supabase Edge Function: user-access
//
// E-mails around access requests (public.profiles, see sql/user_roles.sql).
//
// POST {"mode":"registered","email":"..."}
//   Called by the website right after someone signs up (they have no
//   session yet). Only acts on a profile that is still waiting for approval,
//   was created within the last day and was not notified before, so it can
//   not be used to send mail to arbitrary addresses: tells the new user the
//   request went to the administrator and tells the administrators someone
//   is waiting.
//
// POST {"mode":"approved","userId":"..."}  Authorization: Bearer <admin token>
//   Called from the Admin panel after an administrator grants access: tells
//   the user which access level they got.
//
// Secrets: RESEND_API_KEY (required), ACCESS_FROM or REMINDER_FROM (sender),
// SITE_URL (optional, the website link put in the e-mails).
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided by Supabase.

const DEFAULT_FROM = "Event Solutions <onboarding@resend.dev>";
const ROLE_LABEL: Record<string, string> = {
  admin: "Admin",
  office: "Office",
  tech: "Tech",
  freelance: "Freelance",
  runner: "Runner",
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

type Profile = {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  created_at: string;
  notified_at: string | null;
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

function env(name: string): string {
  const v = Deno.env.get(name);
  if (!v) throw new Error(`${name} is not configured`);
  return v;
}

async function db(path: string, init: RequestInit = {}): Promise<Response> {
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  const res = await fetch(`${env("SUPABASE_URL")}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Database ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
  return res;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!
  );
}

async function sendEmail(to: string[], subject: string, html: string): Promise<void> {
  if (!to.length) return;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env("RESEND_API_KEY")}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: Deno.env.get("ACCESS_FROM") || Deno.env.get("REMINDER_FROM") || DEFAULT_FROM,
      to,
      subject,
      html,
    }),
  });
  if (!res.ok) {
    throw new Error(`Resend ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
}

function layout(title: string, body: string): string {
  const site = Deno.env.get("SITE_URL");
  return `<div style="font-family:Arial,sans-serif;font-size:14px;color:#111;max-width:560px;">
    <h2 style="margin:0 0 12px;">${escapeHtml(title)}</h2>
    ${body}
    ${site ? `<p><a href="${escapeHtml(site)}">${escapeHtml(site)}</a></p>` : ""}
    <p style="color:#777;font-size:12px;">Event Solutions · Krovinių planuotojas</p>
  </div>`;
}

// --- modes ------------------------------------------------------------------

async function registered(email: string): Promise<void> {
  const found = (await (await db(
    `profiles?select=*&role=eq.pending&notified_at=is.null&email=eq.${encodeURIComponent(email.toLowerCase())}`,
  )).json()) as Profile[];
  const p = found[0];
  if (!p) return;
  if (Date.now() - new Date(p.created_at).getTime() > 24 * 3600 * 1000) return;

  // mark first, so a repeated call can not send twice
  await db(`profiles?id=eq.${p.id}`, {
    method: "PATCH",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify({ notified_at: new Date().toISOString() }),
  });

  const name = p.full_name || p.email;
  await sendEmail(
    [p.email],
    "Registracija gauta — laukiama patvirtinimo",
    layout(
      "Registracija gauta",
      `<p>Sveiki, ${escapeHtml(name)}.</p>
       <p>Jūsų prašymas prisijungti prie Event Solutions krovinių planuotojo perduotas administratoriui.
       Kai administratorius suteiks prieigą, gausite dar vieną laišką ir galėsite prisijungti.</p>`,
    ),
  );

  const admins = (await (await db("profiles?select=email&role=eq.admin")).json()) as { email: string }[];
  await sendEmail(
    admins.map((a) => a.email).filter(Boolean),
    `Naujas vartotojas laukia patvirtinimo: ${name}`,
    layout(
      "Naujas vartotojas laukia patvirtinimo",
      `<p><b>${escapeHtml(name)}</b> (${escapeHtml(p.email)}) užsiregistravo ir laukia prieigos.</p>
       <p>Prieigą suteiksite svetainės skiltyje <b>Admin</b>.</p>`,
    ),
  );
}

async function callerIsAdmin(req: Request): Promise<boolean> {
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return false;
  const res = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, {
    headers: { apikey: env("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return false;
  const user = await res.json();
  if (!user?.id) return false;
  const rows = (await (await db(
    `profiles?select=role&id=eq.${encodeURIComponent(user.id)}`,
  )).json()) as { role: string }[];
  return rows[0]?.role === "admin";
}

async function approved(userId: string): Promise<boolean> {
  const rows = (await (await db(
    `profiles?select=*&id=eq.${encodeURIComponent(userId)}`,
  )).json()) as Profile[];
  const p = rows[0];
  const label = p && ROLE_LABEL[p.role];
  if (!label) return false;
  await sendEmail(
    [p.email],
    "Prieiga suteikta",
    layout(
      "Prieiga suteikta",
      `<p>Sveiki, ${escapeHtml(p.full_name || p.email)}.</p>
       <p>Administratorius suteikė jums prieigą prie Event Solutions krovinių planuotojo.
       Prieigos lygis: <b>${label}</b>.</p>
       <p>Galite prisijungti savo el. paštu ir slaptažodžiu.</p>`,
    ),
  );
  return true;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed, use POST" }, 405);

  let body: Record<string, unknown> = {};
  try {
    body = await req.json();
  } catch {
    return json({ error: "JSON body required" }, 400);
  }

  try {
    if (body.mode === "registered") {
      const email = String(body.email ?? "").trim();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "email is required" }, 400);
      await registered(email);
      // the same answer either way: it does not tell who is registered
      return json({ ok: true });
    }
    if (body.mode === "approved") {
      if (!(await callerIsAdmin(req))) return json({ error: "Tik administratorius." }, 403);
      const userId = String(body.userId ?? "");
      if (!userId) return json({ error: "userId is required" }, 400);
      return json({ ok: await approved(userId) });
    }
    return json({ error: "Unknown mode" }, 400);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    return json({ error: "Nepavyko išsiųsti laiško." }, 500);
  }
});
