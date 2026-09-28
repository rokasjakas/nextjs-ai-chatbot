// Uploads dist/EventSolutions-Setup.exe to Supabase Storage (bucket "desktop"):
// parts of 24 MB (Supabase free plan: max 50 MB per file) and
// EventSolutions-Setup.json { version, size, sha256, parts }. The app and the
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

const pub = (name) => `${URL_}/storage/v1/object/public/${BUCKET}/${name}`;
const current = await fetch(pub('EventSolutions-Setup.json') + '?t=' + Date.now()).then((r) => (r.ok ? r.json() : null)).catch(() => null);
if (current && Number(current.version) >= version && !process.env.FORCE) {
  console.log(`Storage already has version ${current.version} (this build: ${version}) – nothing uploaded. Raise DESK_VERSION in main.js to publish.`);
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

const exe = fs.readFileSync(new URL('./dist/EventSolutions-Setup.exe', import.meta.url));
const parts = [];
for (let i = 0; i < exe.length; i += PART) {
  const name = `EventSolutions-Setup.exe.part${parts.length + 1}`;
  await put(name, exe.subarray(i, i + PART), 'application/octet-stream');
  parts.push(name);
}
const manifest = { version, size: exe.length, sha256: crypto.createHash('sha256').update(exe).digest('hex'), parts };
await put('EventSolutions-Setup.json', Buffer.from(JSON.stringify(manifest)), 'application/json');
console.log('published', manifest);
