// Cloudflare Pages Function (site/_routes.json sends only /EventSolutions-* here):
// the Windows and Mac apps, kept in Cloudflare R2 (bucket bound to this Pages
// project as DOWNLOADS). Same address as the site, so no CORS and no public bucket.
// Until the bucket is bound or a file is in it, the old copy in Supabase Storage is used.
const NAME = /^EventSolutions-(Setup\.json|Setup\.exe\.part\d+|Mac-(arm64|x64)\.json|Mac-(arm64|x64)\.zip\.part\d+)$/;
const SUPABASE = 'https://yakmikxkcudwloxruhvx.supabase.co/storage/v1/object/public/desktop/';

export async function onRequest({ request, env, next }) {
  const name = decodeURIComponent(new URL(request.url).pathname.slice(1));
  if (!NAME.test(name) || !['GET', 'HEAD'].includes(request.method)) return next();
  const obj = env.DOWNLOADS ? await env.DOWNLOADS.get(name) : null;
  if (!obj) return Response.redirect(SUPABASE + name, 302);
  const headers = new Headers({
    'content-type': name.endsWith('.json') ? 'application/json' : 'application/octet-stream',
    'cache-control': name.endsWith('.json') ? 'no-cache' : 'public, max-age=300',
    'content-length': String(obj.size),
    etag: obj.httpEtag,
  });
  return new Response(request.method === 'HEAD' ? null : obj.body, { headers });
}
