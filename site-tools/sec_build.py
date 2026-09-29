#!/usr/bin/env python3
"""Security build step – run before every release (after editing index.html).
 * hashes every inline <script> (sha256) → Content-Security-Policy without 'unsafe-inline' for scripts
 * writes the CSP as <meta> into index.html (works on any host) and
 * writes site/_headers for Cloudflare Pages (CSP + frame-ancestors + other security headers).
Usage: python3 site-tools/sec_build.py site/index.html site/_headers"""
import re, sys, hashlib, base64
src, headers_out = sys.argv[1], sys.argv[2]
s = open(src, encoding='utf-8').read()
s = re.sub(r'\n?<meta http-equiv="Content-Security-Policy"[^>]*>', '', s)   # the previous one (also a wrongly placed one)
hashes = []
for m in re.finditer(r'<script(?![^>]*\bsrc=)([^>]*)>(.*?)</script>', s, re.S):
    if 'application/json' in m.group(1): continue
    hashes.append("'sha256-" + base64.b64encode(hashlib.sha256(m.group(2).encode('utf-8')).digest()).decode() + "'")
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
hm = re.search(r'<head>\s*(<meta charset="[^"]*">)', s[:5000], re.I)
assert hm, 'no <head><meta charset> at the top of the page'
s = s[:hm.end()] + '\n<meta http-equiv="Content-Security-Policy" content="' + meta_csp + '">' + s[hm.end():]
open(src, 'w', encoding='utf-8').write(s)
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
/.well-known/assetlinks.json
  Content-Type: application/json
/EventSolutions.apk
  Content-Type: application/vnd.android.package-archive
  Content-Disposition: attachment; filename="EventSolutions.apk"
""")
print('inline scripts hashed:', len(hashes))
