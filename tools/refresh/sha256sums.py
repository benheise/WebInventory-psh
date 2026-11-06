#!/usr/bin/env python3
"""Rewrite dist/SHA256SUMS.txt for the release files (same list and order as the release zip).

usage: sha256sums.py <dist dir>
"""
import hashlib, os, sys

FILES = ['Invoke-WebInventory.ps1', 'WebInventory.rules.recog.json', 'WebInventory.rules.wappalyzer.json', 'WebInventory.cloud.json', 'WebInventory.example.psd1',
         'README.md', 'PERFORMANCE.md', 'THIRD-PARTY-NOTICES.txt', 'LICENSE-GPL-3.0.txt', 'Test-WebInventoryStore.ps1']
d = sys.argv[1]
with open(os.path.join(d, 'SHA256SUMS.txt'), 'w', newline='\n') as f:
    for n in FILES:
        f.write('%s  %s\n' % (hashlib.sha256(open(os.path.join(d, n), 'rb').read()).hexdigest(), n))
