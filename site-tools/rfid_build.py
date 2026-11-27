#!/usr/bin/env python3
"""RFID page data – run at every release (after editing index.html).
Writes site/rfid-items.json: the warehouse items built into index.html (id, name, code, group, folder, qty)
and the group names, so rfid.html (made for old Android scanners) needs no 4 MB index.html.
Usage: python3 site-tools/rfid_build.py site/index.html site/rfid-items.json"""
import re, sys, json
src, out = sys.argv[1], sys.argv[2]
s = open(src, encoding='utf-8').read()
items = json.loads(re.search(r'<script[^>]*id="inv-data"[^>]*>(.*?)</script>', s, re.S).group(1))
meta = json.loads(re.search(r'<script[^>]*id="meta-data"[^>]*>(.*?)</script>', s, re.S).group(1))
keep = [{k: it.get(k) for k in ('id', 'name', 'code', 'group', 'folder', 'qty') if it.get(k) not in (None, '')} for it in items]
json.dump({'items': keep, 'groups': meta.get('GROUP_LABEL', {})}, open(out, 'w', encoding='utf-8'), ensure_ascii=False, separators=(',', ':'))
print('rfid items:', len(keep))
