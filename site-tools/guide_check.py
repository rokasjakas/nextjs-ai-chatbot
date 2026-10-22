#!/usr/bin/env python3
"""Gidas check – run at every release: every page of the menu (data-tab rail buttons) must have its article in GUIDE
(except the Super Admin's Sistema). Exits 1 and lists the missing ones, so a new page never ships without its guide.
Usage: python3 site-tools/guide_check.py site/index.html"""
import re, sys
s = open(sys.argv[1], encoding='utf-8').read()
tabs = set(re.findall(r'class="rail-btn[^"]*"[^>]*data-tab="([a-z_]+)"', s))
a = s.index('const GUIDE = ['); b = s.index('\n];', a)
have = set(re.findall(r"\btab:'([a-z_]+)'", s[a:b]))
skip = {'system', 'admin', 'projects', 'guide'}   # Sistema, Admin – not in the guide; the old Rentman list (hidden); the guide itself
miss = sorted(tabs - have - skip)
if miss: print('Gidas: nėra straipsnio puslapiams:', ', '.join(miss)); sys.exit(1)
print('Gidas: visi', len(tabs - skip), 'puslapiai aprašyti')
