// Uploads a built program to Supabase Storage (bucket "desktop"):
// parts of 24 MB (Supabase free plan: max 50 MB per file) and a manifest
// <name>.json { version, size, sha256, parts }.
//   node publish.mjs                                  -> dist/EventSolutions-Setup.exe (Windows)
//   node publish.mjs dist/EventSolutions-Mac-arm64.zip EventSolutions-Mac-arm64   (Mac) The app and the
// site's download button read them from there (site/_redirects).
// Only a newer DESK_VERSION (main.js) is uploaded; the parts go first, the list last.
// Env: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY. Run by .github/workflows/desktop.yml.
import fs from 'node:fs';
import crypto from 'node:crypto';

const URL_ = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
if (!URL_ || !KEY) { console.error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are needed'); process.exit(1); }
const BUCKET = 'desktop', PART = 24 * 1024 * 1024;
const version = Number((fs.readFileSync(new URL('./main.js', import.meta.url), 'utf8').match(/const DESK_VERSION = (\d+);/) || [])[1]);
if (!version) { console.error('DESK_VERSION not found in main.js'); process.exit(1); }

const SRC = process.argv[2] || 'dist/EventSolutions-Setup.exe';
const NAME = process.argv[3] || 'EventSolutions-Setup';
const FILE = SRC.split('/').pop();                 // parts: <file>.part1, .part2 …
const pub = (name) => `${URL_}/storage/v1/object/public/${BUCKET}/${name}`;
const current = await fetch(pub(NAME + '.json') + '?t=' + Date.now()).then((r) => (r.ok ? r.json() : null)).catch(() => null);
if (current && Number(current.version) >= version && !process.env.FORCE) {
  console.log(`${NAME}: storage already has version ${current.version} (this build: ${version}) – nothing uploaded. Raise DESK_VERSION in main.js to publish.`);
  process.exit(0);
}

async function put(name, body, type) {
  const res = await fetch(`${URL_}/storage/v1/object/${BUCKET}/${name}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${KEY}`, apikey: KEY, 'Content-Type': type, 'x-upsert': 'true', 'cache-control': 'max-age=60' },
    body,
  });
  if (!res.ok) throw new Error(`${name}: ${res.status} ${await res.text()}`);
  console.log('uploaded', name, body.length);
}

const exe = fs.readFileSync(new URL('./' + SRC, import.meta.url));
const parts = [];
for (let i = 0; i < exe.length; i += PART) {
  const name = `${FILE}.part${parts.length + 1}`;
  await put(name, exe.subarray(i, i + PART), 'application/octet-stream');
  parts.push(name);
}
const manifest = { version, size: exe.length, sha256: crypto.createHash('sha256').update(exe).digest('hex'), parts };
await put(NAME + '.json', Buffer.from(JSON.stringify(manifest)), 'application/json');
console.log('published', manifest);

// parts left over from an older, bigger version (e.g. .part5 when there are 4 now)
const listed = await fetch(`${URL_}/storage/v1/object/list/${BUCKET}`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${KEY}`, apikey: KEY, 'Content-Type': 'application/json' },
  body: JSON.stringify({ prefix: '', search: FILE + '.part', limit: 1000 }),
}).then((r) => (r.ok ? r.json() : [])).catch(() => []);
const stale = (Array.isArray(listed) ? listed : []).map((o) => o.name).filter((n) => n && n.startsWith(FILE + '.part') && !parts.includes(n));
if (stale.length) {
  const res = await fetch(`${URL_}/storage/v1/object/${BUCKET}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${KEY}`, apikey: KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ prefixes: stale }),
  });
  console.log(res.ok ? 'removed old parts' : 'could not remove old parts (' + res.status + ')', stale);
}
