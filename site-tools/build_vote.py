#!/usr/bin/env python3
"""Builds site/balsuoti.html – the voter's page opened by the QR code – from site/index.html.
 * a small page (tens of KB instead of the whole app): opens at once on a phone
 * no supabase-js: the few database functions are called with fetch (same headers as supabase-js)
 * the voting code and styles are taken from index.html by name, so both always match
index.html sends ?balsuoti=… here as the very first thing it does (old QR codes keep working).
Run before sec_build.py on every release:
  python3 site-tools/build_vote.py site/index.html site/balsuoti.html"""
import re, sys
src, out = sys.argv[1], sys.argv[2]
s = open(src, encoding='utf-8').read()

# ---------- styles: the page's colours and fonts, and every voting rule ----------
css_all = ''.join(m.group(1) for m in re.finditer(r'<style[^>]*>(.*?)</style>', s, re.S))
root = re.search(r'\n:root\{.*?\n\}', css_all, re.S).group(0)
base_names = [r'\*\{box-sizing', r'html,body\{', r'body\{', r'#toast\{', r'#toast\.show\{', r'\.hidden\{', r'#authGate, #guestView\{']
base = []
for pat in base_names:
    m = re.search(r'\n(' + pat + r'.*?\})\s*\n', css_all, re.S)
    assert m, 'style not found: ' + pat
    base.append(m.group(1))
poll_css = [l for l in css_all.split('\n') if re.search(r'poll-|pl-txt|pollPulse|pollReveal', l)]
for l in poll_css:
    assert not l.startswith((' ', '\t')) and l.count('{') == l.count('}'), 'voting style inside a block: ' + l[:80]
css = root + '\n' + '\n'.join(base) + '\n' + '\n'.join(poll_css)

# ---------- code: the voting functions, taken whole (a top-level definition ends where the next one starts) ----------
main = max((m.group(1) for m in re.finditer(r'<script>(.*?)</script>', s, re.S)), key=len)
lines = main.split('\n')
def grab(name):
    pat = re.compile(r'^(async function|function|const|let)\s+' + re.escape(name) + r'\b')
    for i, l in enumerate(lines):
        if pat.match(l):
            j = i + 1
            while j < len(lines) and (lines[j] == '' or lines[j][0] in ' \t})]'):
                j += 1
            return '\n'.join(lines[i:j]).rstrip()
    raise SystemExit('build_vote: not found in index.html: ' + name)
NAMES = ['toast', 'esc', 'ltPlural', 'pollClock', 'pollTimeout', 'POLL_FONTS', 'POLL_GF', 'pollGfOk', 'pollGFont', 'pollFont',
         'pollPage', 'pollStops', 'pollGrad', 'pollCssUrl', 'pollBrandCss', 'POLL_SIZES', 'pollWinXY', 'POLL_ASSETS', 'pollAsset',
         'pollLookFast', 'pollResolve', 'pollNumOpts', 'PN_SRC', 'pollNameNorm', 'pollLev', 'pollWordNear', 'pollNameNear',
         'PV', 'pollVoterId', 'pollVotedKey', 'renderPollVote', 'pollVoteLoad', 'pollVoteLoad0', 'pollVoteMsg', 'pollVoteDraw',
         'pollWriteDraw', 'pollVoteTick', 'pollVoteSend', 'pollThanks']
code = '\n'.join(grab(n) for n in NAMES)
sb_url = re.search(r'const SUPABASE_URL = "([^"]+)"', s).group(1)
sb_key = re.search(r'const SUPABASE_KEY = "([^"]+)"', s).group(1)
shim = f'''const SUPABASE_URL = "{sb_url}";
const SUPABASE_KEY = "{sb_key}";
// the database functions over plain fetch (the same headers supabase-js sends); a request is cut after 10 s
const SBL = {{ rpc(name, args){{
  const c = new AbortController(), t = setTimeout(()=>c.abort(), 10000);
  return fetch(SUPABASE_URL+'/rest/v1/rpc/'+name, {{ method:'POST', signal:c.signal, headers:{{ apikey:SUPABASE_KEY, Authorization:'Bearer '+SUPABASE_KEY, 'Content-Type':'application/json' }}, body:JSON.stringify(args || {{}}) }})
    .then(async r=>{{ const txt = await r.text(); let d = null; try{{ d = txt ? JSON.parse(txt) : null; }}catch(e){{}}
      return r.ok ? {{ data:d, error:null }} : {{ data:null, error:{{ message:(d && d.message) || ('HTTP '+r.status) }} }}; }})
    .catch(e=>({{ data:null, error:{{ message:String(e && e.message || e) }} }}))
    .finally(()=>clearTimeout(t));
}} }};
function getSb(){{ return SBL; }}
async function pollSbReady(){{ return SBL; }}'''
start = '''const token = new URLSearchParams(location.search).get('balsuoti');
document.getElementById('guestView').classList.remove('hidden');
if(token) renderPollVote(token); else document.getElementById('guestView').innerHTML = '<div class="poll-pub"><div class="poll-pub-in"><div class="poll-msg">Ši nuoroda nebegalioja.</div></div></div>';'''
fonts = re.search(r'<link href="(https://fonts\.googleapis\.com/css2\?[^"]+)"', s).group(1)
page = f'''<!DOCTYPE html>
<html lang="lt">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#101010">
<meta name="robots" content="noindex">
<title>Balsavimas · Event Solutions</title>
<link rel="icon" href="icons/icon-192.png">
<link rel="preconnect" href="{sb_url}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="{fonts}" rel="stylesheet" media="print" id="appFonts">
<style>
{css}
</style>
</head>
<body>
<div id="guestView" class="hidden"></div>
<div id="toast"></div>
<script>
// built from index.html by site-tools/build_vote.py – edit the voting code there, not here
(()=>{{ const l = document.getElementById('appFonts'); if(!l) return; const on = ()=>{{ l.media = 'all'; }}; if(l.sheet) on(); else {{ l.addEventListener('load', on); l.addEventListener('error', on); }} }})();
{shim}
{code}
{start}
</script>
</body>
</html>
'''
open(out, 'w', encoding='utf-8').write(page)
print('balsuoti.html:', round(len(page.encode()) / 1024), 'KB')
