// Uploads a built program in parts of 24 MB plus a manifest <name>.json
// { version, size, sha256, parts } to Cloudflare R2 (when R2_* are set; the site
// serves them through functions/[[path]].js) or else to Supabase Storage (bucket "desktop").
//   node publish.mjs                                  -> dist/EventSolutions-Setup.exe (Windows)
//   node publish.mjs dist/EventSolutions-Mac-arm64.zip EventSolutions-Mac-arm64   (Mac)
// Only a newer DESK_VERSION (main.js) is uploaded; the parts go first, the list last;
// parts an older, bigger version left behind are removed. After a move to R2 the
// Supabase copies are removed too.
// Env: R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_DOWNLOADS_BUCKET
//      and/or SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY. Run by .github/workflows/desktop.yml.
import fs from 'node:fs';
import crypto from 'node:crypto';

const PART = 24 * 1024 * 1024;
const version = Number((fs.readFileSync(new URL('./main.js', import.meta.url), 'utf8').match(/const DESK_VERSION = (\d+);/) || [])[1]);
if (!version) { console.error('DESK_VERSION not found in main.js'); process.exit(1); }
const SRC = process.argv[2] || 'dist/EventSolutions-Setup.exe';
const NAME = process.argv[3] || 'EventSolutions-Setup';
const FILE = SRC.split('/').pop();                 // parts: <file>.part1, .part2 …
const E = (k) => (process.env[k] || '').trim();

// ---------- Supabase Storage ----------
function supabase() {
  const url = E('SUPABASE_URL').replace(/\/$/, ''), key = E('SUPABASE_SERVICE_ROLE_KEY'), bucket = 'desktop';
  if (!url || !key) return null;
  const auth = { Authorization: `Bearer ${key}`, apikey: key };
  return {
    label: 'Supabase',
    async get(name) {
      const r = await fetch(`${url}/storage/v1/object/public/${bucket}/${name}?t=${Date.now()}`).catch(() => null);
      return r && r.ok ? Buffer.from(await r.arrayBuffer()) : null;
    },
    async put(name, body, type) {
      const r = await fetch(`${url}/storage/v1/object/${bucket}/${name}`, { method: 'POST', headers: { ...auth, 'Content-Type': type, 'x-upsert': 'true', 'cache-control': 'max-age=60' }, body });
      if (!r.ok) throw new Error(`${name}: ${r.status} ${await r.text()}`);
    },
    async list(prefix) {
      const r = await fetch(`${url}/storage/v1/object/list/${bucket}`, { method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' }, body: JSON.stringify({ prefix: '', search: prefix, limit: 1000 }) }).catch(() => null);
      const j = r && r.ok ? await r.json() : [];
      return (Array.isArray(j) ? j : []).map((o) => o.name).filter((n) => n && n.startsWith(prefix));
    },
    async remove(names) {
      if (!names.length) return;
      const r = await fetch(`${url}/storage/v1/object/${bucket}`, { method: 'DELETE', headers: { ...auth, 'Content-Type': 'application/json' }, body: JSON.stringify({ prefixes: names }) });
      if (!r.ok) console.log('could not remove from Supabase (' + r.status + ')', names);
    },
  };
}

// ---------- Cloudflare R2 (S3 API, signature v4) ----------
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const hmac = (k, s) => crypto.createHmac('sha256', k).update(s).digest();
const rfc3986 = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
function r2() {
  const acct = E('R2_ACCOUNT_ID'), id = E('R2_ACCESS_KEY_ID'), secret = E('R2_SECRET_ACCESS_KEY'), bucket = E('R2_DOWNLOADS_BUCKET');
  if (!acct || !id || !secret || !bucket) return null;
  const host = `${acct}.r2.cloudflarestorage.com`;
  async function call(method, key, { query = {}, body = null, type = '' } = {}) {
    const full = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, ''), day = full.slice(0, 8);
    const uri = '/' + rfc3986(bucket) + (key ? '/' + key.split('/').map(rfc3986).join('/') : '');
    const qs = Object.keys(query).sort().map((k) => rfc3986(k) + '=' + rfc3986(query[k])).join('&');
    const payload = sha(body || '');
    const headers = { host, 'x-amz-content-sha256': payload, 'x-amz-date': full, ...(type ? { 'content-type': type } : {}) };
    const names = Object.keys(headers).sort();
    const canonical = [method, uri, qs, names.map((n) => n + ':' + headers[n]).join('\n') + '\n', names.join(';'), payload].join('\n');
    const scope = `${day}/auto/s3/aws4_request`;
    const sts = ['AWS4-HMAC-SHA256', full, scope, sha(canonical)].join('\n');
    let k = hmac('AWS4' + secret, day);
    for (const p of ['auto', 's3', 'aws4_request']) k = hmac(k, p);
    const sig = crypto.createHmac('sha256', k).update(sts).digest('hex');
    const h = { ...headers, authorization: `AWS4-HMAC-SHA256 Credential=${id}/${scope}, SignedHeaders=${names.join(';')}, Signature=${sig}` };
    delete h.host;
    return fetch(`https://${host}${uri}${qs ? '?' + qs : ''}`, { method, headers: h, body: body || undefined });
  }
  return {
    label: 'Cloudflare R2',
    async get(name) {
      const r = await call('GET', name).catch(() => null);
      return r && r.ok ? Buffer.from(await r.arrayBuffer()) : null;
    },
    async put(name, body, type) {
      const r = await call('PUT', name, { body, type });
      if (!r.ok) throw new Error(`${name}: R2 ${r.status} ${await r.text()}`);
    },
    async list(prefix) {
      const r = await call('GET', '', { query: { 'list-type': '2', prefix, 'max-keys': '1000' } });
      const xml = r.ok ? await r.text() : '';
      return [...xml.matchAll(/<Key>([^<]+)<\/Key>/g)].map((m) => m[1].replace(/&amp;/g, '&'));
    },
    async remove(names) {
      for (const n of names) { const r = await call('DELETE', n); if (!r.ok && r.status !== 404) console.log('could not remove from R2', n, r.status); }
    },
  };
}

const R2 = r2(), SB = supabase();
const store = R2 || SB;
if (!store) { console.error('Set R2_* (Cloudflare R2) or SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY'); process.exit(1); }

const current = await store.get(NAME + '.json').then((b) => (b ? JSON.parse(b.toString()) : null)).catch(() => null);
if (current && Number(current.version) >= version && !process.env.FORCE) {
  console.log(`${NAME}: ${store.label} already has version ${current.version} (this build: ${version}) – nothing uploaded. Raise DESK_VERSION in main.js to publish.`);
} else {
  const exe = fs.readFileSync(new URL('./' + SRC, import.meta.url));
  const parts = [];
  for (let i = 0; i < exe.length; i += PART) {
    const name = `${FILE}.part${parts.length + 1}`;
    await store.put(name, exe.subarray(i, i + PART), 'application/octet-stream');
    console.log('uploaded', name);
    parts.push(name);
  }
  const manifest = { version, size: exe.length, sha256: crypto.createHash('sha256').update(exe).digest('hex'), parts };
  await store.put(NAME + '.json', Buffer.from(JSON.stringify(manifest)), 'application/json');
  console.log(`published to ${store.label}`, manifest);
  const stale = (await store.list(FILE + '.part')).filter((n) => !parts.includes(n));
  if (stale.length) { await store.remove(stale); console.log('removed old parts', stale); }
}

// moved to R2: the copies in Supabase are no longer used
if (R2 && SB && await R2.get(NAME + '.json')) {
  const old = [...(await SB.list(FILE + '.part')), ...(await SB.list(NAME + '.json'))];
  if (old.length) { await SB.remove(old); console.log('removed from Supabase', old); }
}
