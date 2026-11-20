// Atsarginė kopija: Supabase Storage failų (išlaidų kvitai, sąskaitos, darbų nuotraukos, gauti laiškai) atsisiuntimas
// į vietinį aplanką, iš kurio rclone juos užšifruotus įkelia į kopijų vietą. Jau ten esantys (tokio paties dydžio)
// failai neatsiunčiami – jų sąrašas (rclone lsjson -R) duodamas per HAVE=failas.json.
// Naudojimas: SUPABASE_URL=… SUPABASE_SERVICE_ROLE_KEY=… HAVE=have.json node site-tools/backup_storage.mjs mirror
import fs from 'node:fs';
import path from 'node:path';

const URL0 = (process.env.SUPABASE_URL || '').replace(/\/$/, ''), KEY = process.env.SUPABASE_SERVICE_ROLE_KEY, OUT = process.argv[2] || 'mirror/supabase';
if (!URL0 || !KEY) { console.error('Trūksta SUPABASE_URL arba SUPABASE_SERVICE_ROLE_KEY'); process.exit(1); }
const H = { apikey: KEY, Authorization: 'Bearer ' + KEY };
const HAVE = new Map();
try { for (const f of JSON.parse(fs.readFileSync(process.env.HAVE || '', 'utf8'))) if (!f.IsDir) HAVE.set(f.Path, f.Size); } catch (e) {}

async function api(p, body) {
  const r = await fetch(URL0 + p, body ? { method: 'POST', headers: { ...H, 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : { headers: H });
  if (!r.ok) throw new Error(p + ': ' + r.status + ' ' + (await r.text()).slice(0, 200));
  return r.json();
}
// every file of a bucket (folders are entries without id)
async function listAll(bucket, prefix = '') {
  const out = [];
  for (let offset = 0; ; offset += 1000) {
    const rows = await api('/storage/v1/object/list/' + encodeURIComponent(bucket), { prefix, limit: 1000, offset, sortBy: { column: 'name', order: 'asc' } });
    for (const r of rows) {
      const full = prefix ? prefix + '/' + r.name : r.name;
      if (r.id === null || r.id === undefined) out.push(...await listAll(bucket, full));
      else out.push({ name: full, size: (r.metadata && r.metadata.size) || 0 });
    }
    if (rows.length < 1000) break;
  }
  return out;
}
const enc = p => p.split('/').map(encodeURIComponent).join('/');
let files = 0, got = 0, bytes = 0, failed = 0;
const buckets = await api('/storage/v1/bucket');
for (const b of buckets) {
  const list = await listAll(b.name);
  for (const f of list) {
    files++; bytes += f.size;
    const dest = path.join(OUT, b.name, ...f.name.split('/'));
    if (HAVE.get(b.name + '/' + f.name) === f.size) continue;   // already in the backup place
    try {
      const r = await fetch(URL0 + '/storage/v1/object/' + encodeURIComponent(b.name) + '/' + enc(f.name), { headers: H });
      if (!r.ok) throw new Error(r.status);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
      got++;
    } catch (e) { failed++; console.error('Nepavyko:', b.name + '/' + f.name, e.message); }
  }
  console.error(b.name + ': ' + list.length + ' failų');
}
console.log(JSON.stringify({ buckets: buckets.length, files, new: got, failed, mb: Math.round(bytes / 1048576) }));
if (failed) process.exitCode = 2;
