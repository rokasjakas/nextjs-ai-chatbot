#!/usr/bin/env python3
"""Security build step – run before every release (after editing index.html).
 * hashes every inline <script> (sha256) → Content-Security-Policy without 'unsafe-inline' for scripts
 * writes the CSP as <meta> into index.html (works on any host) and
 * writes site/_headers for Cloudflare Pages (CSP + frame-ancestors + other security headers).
Usage: python3 site-tools/sec_build.py site/index.html site/_headers [site/balsuoti.html site/auto.html …]
(the other pages get the same CSP; their inline scripts are hashed too)"""
import re, sys, hashlib, base64
src, headers_out, extra = sys.argv[1], sys.argv[2], sys.argv[3:]
pages = {}
hashes = []
for f in [src] + extra:
    t = open(f, encoding='utf-8').read()
    t = re.sub(r'\n?<meta http-equiv="Content-Security-Policy"[^>]*>', '', t)   # the previous one (also a wrongly placed one)
    pages[f] = t
    for m in re.finditer(r'<script(?![^>]*\bsrc=)([^>]*)>(.*?)</script>', t, re.S):
        if 'application/json' in m.group(1): continue
        h = "'sha256-" + base64.b64encode(hashlib.sha256(m.group(2).encode('utf-8')).digest()).decode() + "'"
        if h not in hashes: hashes.append(h)
SB = 'yakmikxkcudwloxruhvx.supabase.co'
csp = {
  'default-src': "'self'",
  # c.dailywebrtc.net: the Daily call bundle (loaded as a script, dailyConfig.avoidEval)
  'script-src': "'self' " + ' '.join(hashes) + " https://cdn.jsdelivr.net https://c.dailywebrtc.net",
  'worker-src': "'self' blob: https://cdn.jsdelivr.net https://c.dailywebrtc.net",
  'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com",
  'font-src': f"'self' data: https://fonts.gstatic.com https://{SB}",
  'img-src': "'self' data: blob: https:",
  'media-src': "'self' data: blob: https:",
  'connect-src': f"'self' https: wss://{SB} wss://*.daily.co wss://*.dailywebrtc.net wss://*.dailywebrtc.com",
  'frame-src': "'self' blob: data: https:",
  'manifest-src': "'self'",
  'object-src': "'none'",
  'base-uri': "'self'",
  'form-action': "'self'",
}
meta_csp = '; '.join(f'{k} {v}' for k, v in csp.items())
head_csp = meta_csp + "; frame-ancestors 'none'; upgrade-insecure-requests"
# only inside the page's own <head> (the scripts also contain '<meta charset' in strings)
for f, s in pages.items():
    hm = re.search(r'<head>\s*(<meta charset="[^"]*">)', s[:5000], re.I)
    assert hm, 'no <head><meta charset> at the top of ' + f
    s = s[:hm.end()] + '\n<meta http-equiv="Content-Security-Policy" content="' + meta_csp + '">' + s[hm.end():]
    open(f, 'w', encoding='utf-8').write(s)
open(headers_out, 'w').write(f"""/*
  Content-Security-Policy: {head_csp}
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: payment=(), usb=(), serial=(), bluetooth=(), hid=()
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Cross-Origin-Opener-Policy: same-origin-allow-popups
/sw.js
  Cache-Control: no-cache
/index.html
  Cache-Control: no-cache
/balsuoti
  Cache-Control: no-cache
/balsuoti.html
  Cache-Control: no-cache
/auto
  Cache-Control: no-cache
/auto.html
  Cache-Control: no-cache
/saskaitos
  Cache-Control: no-cache
/saskaitos.html
  Cache-Control: no-cache
/.well-known/assetlinks.json
  Content-Type: application/json
/EventSolutions.apk
  Content-Type: application/vnd.android.package-archive
  Content-Disposition: attachment; filename="EventSolutions.apk"
""")
print('inline scripts hashed:', len(hashes))
