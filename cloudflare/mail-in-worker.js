// EventSolutions – Cloudflare Email Worker: a forwarded letter goes straight into the app.
//
// The mail server forwards each member's new letters to <name>@<forwarding domain>
// (e.g. rokas@in.eventsolutions.lt). Cloudflare Email Routing gives every such letter to
// this worker, which sends it to the Supabase function "mail-in" (it keeps the letter
// for the app). When the app cannot take it, a copy can go to FALLBACK (if set).
//
// Cloudflare → Workers & Pages → Create → Worker → paste this file → Deploy.
// Settings → Variables and Secrets:
//   MAIL_IN_URL     https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/mail-in
//   MAIL_IN_SECRET  (Secret) the same long random text as the Supabase secret MAIL_IN_SECRET
//   FALLBACK        (optional) a verified address to receive letters the app could not take
// Email → Email Routing → Routing rules → Catch-all → Send to a Worker → this worker.
export default {
  async email(message, env, ctx) {
    const raw = await new Response(message.raw).arrayBuffer();
    let ok = false, why = '';
    for (let attempt = 0; attempt < 3 && !ok; attempt++) {
      try {
        const r = await fetch(env.MAIL_IN_URL, {
          method: 'POST',
          headers: { 'content-type': 'message/rfc822', 'x-mail-in-secret': env.MAIL_IN_SECRET, 'x-rcpt': message.to },
          body: raw,
        });
        if (r.ok) { ok = true; break; }
        why = r.status + ' ' + (await r.text()).slice(0, 200);
        if (r.status === 404 || r.status === 403) break;          // unknown address / wrong secret: trying again does not help
      } catch (e) { why = String(e && e.message || e); }
      await new Promise((res) => setTimeout(res, 1500 * (attempt + 1)));
    }
    if (ok) return;
    console.log('mail-in failed for ' + message.to + ': ' + why);
    // the original stays in the mailbox on the mail server (the app still reads it from there),
    // so the sender gets no bounce; a copy can go to FALLBACK
    if (env.FALLBACK) await message.forward(env.FALLBACK);
  },
};
