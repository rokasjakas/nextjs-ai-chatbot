#!/usr/bin/env python3
"""System map data – run at every release (after editing index.html).
Reads the app (site/index.html) and the server functions (supabase/functions/*/index.ts) and writes
site/sys-map.json for the „Sistema“ page (Super Admin only): which page uses which tables, server functions and
shared state, which server function talks to which outside service and needs which secrets (names only).
Nothing is guessed by hand – a new page, table or function shows up on the map by itself after the next release.
Usage: python3 site-tools/sys_build.py site/index.html supabase/functions site/sys-map.json"""
import re, sys, os, json, datetime
src, fdir, out = sys.argv[1], sys.argv[2], sys.argv[3]
html = open(src, encoding='utf-8').read()

# the app script: the largest inline <script>, with its first line number in index.html
scripts = [(m.start(1), m.group(1)) for m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.S)]
off, js = max(scripts, key=lambda x: len(x[1]))
line0 = html.count('\n', 0, off) + 1

# top-level definitions: a chunk of code from one unindented definition to the next
DEF = re.compile(r'^(?:async\s+)?function\s+(\w+)|^(?:const|let|var)\s+(\w+)\s*=', re.M)
defs = []
for m in DEF.finditer(js):
    defs.append((m.group(1) or m.group(2), m.start(), bool(m.group(1)) or bool(re.match(r'\s*(async\s*)?(\(|\w+\s*=>|function)', js[m.end():m.end() + 40]))))
chunks = {}
for i, (name, pos, isfn) in enumerate(defs):
    end = defs[i + 1][1] if i + 1 < len(defs) else len(js)
    if name not in chunks:
        chunks[name] = {'code': js[pos:end], 'line': line0 + js.count('\n', 0, pos), 'fn': isfn}
FN_NAMES = {n for n, c in chunks.items() if c['fn']}

def uses(code):
    return {
        'tables': set(re.findall(r"\.from\(\s*'([a-z_0-9]+)'", code)),
        'rpcs': set(re.findall(r"\.rpc\(\s*'([a-z_0-9]+)'", code)),
        'fns': set(re.findall(r"/functions/v1/([a-z_0-9-]+)", code)),
        'state': set(re.findall(r"\bSTATE\.([a-zA-Z_]\w*)", code)),
        'refs': set(re.findall(r"\b([A-Za-z_]\w*)\b", code)) & FN_NAMES,
    }
U = {n: uses(c['code']) for n, c in chunks.items()}
# a helper that only builds a function's address (const MAIL_FN = ()=>…/functions/v1/mail) counts as that function
FN_HELPERS = {n: u['fns'] for n, u in U.items() if u['fns'] and len(chunks[n]['code']) < 400}

# the pages: TABS = { key: renderFn, … } and their names from the left menu
tabs_src = re.search(r'const TABS = \{(.*?)\};', js, re.S).group(1)
TABS = dict(re.findall(r'(\w+):\s*(\w+)', tabs_src))
TABS.pop('system', None)   # the map page itself is not on the map
LABEL = {}
for k, l in re.findall(r'data-tab="([a-z]+)"[^>]*?data-label="([^"]+)"', html):
    LABEL.setdefault(k, l)
# two pages with one menu name (Projektai): the home tile's title tells them apart
TITLE = dict(re.findall(r"\{tab:'([a-z]+)', title:'([^']+)'", js))
for k in list(LABEL):
    if list(LABEL.values()).count(LABEL[k]) > 1 and TITLE.get(k) and TITLE[k] != LABEL[k]:
        LABEL[k] = TITLE[k]
SAME_NAME = {'projects': 'Projektai (Rentman)'}
for k in list(LABEL):
    if list(LABEL.values()).count(LABEL[k]) > 1:
        LABEL[k] = SAME_NAME.get(k) or LABEL[k] + ' (' + k + ')'
RENDERS = set(TABS.values())
# never follow into page switching or other pages, and not into the big shared helpers every page touches
HUB_LIMIT = 12
refcount = {}
for n, u in U.items():
    for r in u['refs']:
        refcount[r] = refcount.get(r, 0) + 1
BLOCK = RENDERS | {'setTab', 'saveState', 'renderAll', 'boot', 'applyAccess'}

def closure(start, depth=4):
    seen, front = {start}, [start]
    for d in range(depth):
        nxt = []
        for f in front:
            for r in U.get(f, {}).get('refs', ()):
                if r in seen or r in BLOCK and r != start:
                    continue
                # the page's own first steps are always followed; deeper, the shared helpers are not
                if d >= 2 and refcount.get(r, 0) > HUB_LIMIT and r not in FN_HELPERS:
                    continue
                seen.add(r); nxt.append(r)
        front = nxt
    return seen

pages = {}
for key, fn in TABS.items():
    if fn not in chunks:
        continue
    cl = closure(fn)
    t, r, f, s = set(), set(), set(), set()
    for n in cl:
        u = U.get(n)
        if not u:
            continue
        t |= u['tables']; r |= u['rpcs']; f |= u['fns']; s |= u['state']
        if n in FN_HELPERS:
            f |= FN_HELPERS[n]
    pages[key] = {'label': LABEL.get(key, key), 'render': fn, 'line': chunks[fn]['line'],
                  'tables': sorted(t), 'rpcs': sorted(r), 'fns': sorted(f), 'state': sorted(s),
                  'code': len(cl)}

# the server functions
funcs = {}
for name in sorted(os.listdir(fdir)):
    p = os.path.join(fdir, name, 'index.ts')
    if not os.path.isfile(p):
        continue
    c = open(p, encoding='utf-8').read()
    hosts = sorted({h for h in re.findall(r'https://([a-z0-9.-]+\.[a-z]{2,})', c) if 'supabase' not in h})
    funcs[name] = {
        'hosts': hosts,
        'secrets': sorted(set(re.findall(r"Deno\.env\.get\(\s*['\"]([A-Z_0-9]+)", c))),
        'tables': sorted((set(re.findall(r"\.from\(\s*['\"]([a-z_0-9]+)", c)) | set(re.findall(r"/rest/v1/([a-z_0-9]+)", c))) - {'rpc'}),
        'rpcs': sorted(set(re.findall(r"\.rpc\(\s*['\"]([a-z_0-9]+)", c)) | set(re.findall(r"/rest/v1/rpc/([a-z_0-9]+)", c))),
        'lines': c.count('\n') + 1,
    }

# where each table / database function is made (the SQL file to run when it is missing)
sql = {'tables': {}, 'rpcs': {}}
sdir = os.path.join(os.path.dirname(os.path.abspath(fdir)), 'sql')
if os.path.isdir(sdir):
    for name in sorted(os.listdir(sdir)):
        if not name.endswith('.sql') or name == 'atnaujinimas.sql':
            continue
        c = open(os.path.join(sdir, name), encoding='utf-8').read()
        for t in re.findall(r'create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?([a-z_0-9]+)', c, re.I):
            sql['tables'].setdefault(t, name)
        for f in re.findall(r'create\s+(?:or\s+replace\s+)?function\s+(?:public\.)?"?([a-z_0-9]+)', c, re.I):
            sql['rpcs'].setdefault(f, name)

# every code function: its line in index.html and, when only one page reaches it, that page (to place an error)
owner = {}
for key, fn in TABS.items():
    if fn in chunks:
        for n in closure(fn):
            owner.setdefault(n, set()).add(key)
code = {n: [c['line'], (sorted(owner[n])[0] if len(owner.get(n, ())) == 1 else '')] for n, c in chunks.items() if c['fn']}

ver = re.search(r"const APP_VER = '(v\d+)'", js)
data = {'ver': ver.group(1) if ver else '', 'built': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M'),
        'lines': html.count('\n') + 1, 'pages': pages, 'funcs': funcs, 'sql': sql, 'code': code}
json.dump(data, open(out, 'w', encoding='utf-8'), ensure_ascii=False, separators=(',', ':'))
print('sys map: %d pages, %d server functions, %d tables' % (len(pages), len(funcs),
      len({t for p in pages.values() for t in p['tables']} | {t for f in funcs.values() for t in f['tables']})))
