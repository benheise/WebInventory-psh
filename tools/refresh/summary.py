#!/usr/bin/env python3
"""Markdown summary of a list refresh (tools/refresh/refresh.sh): what changed upstream, what that changed in the rule
packs, the CPE supplement, the version-candidate index and the coverage table, and whether the checks passed.

usage: summary.py --repo <checkout> --work <refresh work dir> --recog OLD NEW --wappalyzer OLD NEW --supplement-changed 0|1
"""
import argparse, collections, json, os, subprocess

ap = argparse.ArgumentParser()
ap.add_argument('--repo', required=True); ap.add_argument('--work', required=True)
ap.add_argument('--recog', nargs=2, default=['', '']); ap.add_argument('--wappalyzer', nargs=2, default=['', ''])
ap.add_argument('--supplement-changed', default='0')
a = ap.parse_args()
B = os.path.join(a.work, 'before')
load = lambda p: json.load(open(p, encoding='utf-8-sig'))
out = []
w = out.append


def products(pack):
    """name -> (has CPE, captures a version) over every output of the pack"""
    p = {}
    for r in pack['rules']:
        for o in (r.get('out') or [r]):
            n = o.get('n')
            if not n or '{' in n or o.get('vo'):
                continue
            c, v = p.get(n, (False, False))
            p[n] = (c or bool(o.get('p')), v or '{' in (o.get('v') or ''))
    return p


def names(xs, limit=40):
    xs = sorted(xs, key=str.lower)
    s = ', '.join('`%s`' % x for x in xs[:limit])
    return s + (' and %d more' % (len(xs) - limit) if len(xs) > limit else '')


def tail(name, n=1):
    p = os.path.join(a.work, 'logs', name)
    if not os.path.exists(p):
        return '(not run)'
    lines = [l.rstrip() for l in open(p, encoding='utf-8', errors='replace') if l.strip()]
    return '\n'.join(lines[-n:]) if lines else '(empty)'


fails = [l.strip() for l in open(os.path.join(a.work, 'failures.txt'))] if os.path.exists(os.path.join(a.work, 'failures.txt')) else []
fails = [f for f in fails if f]
w('## External lists refresh\n')
w('**Checks: %s**\n' % ('passed' if not fails else 'FAILED'))
for f in fails:
    w('- ' + f)
if fails:
    w('')

w('### Upstream\n')
w('| Source | Was | Now |\n|---|---|---|')
for label, repo, (old, new) in (('Rapid7 Recog', 'rapid7/recog', a.recog), ('webappanalyzer', 'enthec/webappanalyzer', a.wappalyzer)):
    link = ('[compare](https://github.com/%s/compare/%s...%s)' % (repo, old[:12], new[:12])) if old and new and old != new else 'unchanged'
    w('| %s | `%s` | `%s` %s |' % (label, old[:12] or '-', new[:12] or '-', link))
w('')

w('### Rule packs\n')
for n in ('recog', 'wappalyzer'):
    f = 'WebInventory.rules.%s.json' % n
    old, new = load(os.path.join(B, f)), load(os.path.join(a.repo, 'dist', f))
    if old['rules'] == new['rules']:
        w('- **%s**: unchanged (%d rules)' % (n, len(new['rules'])))
        continue
    po, pn = products(old), products(new)
    w('- **%s**: %d -> %d rules, %d -> %d products' % (n, len(old['rules']), len(new['rules']), len(po), len(pn)))
    add, rem = set(pn) - set(po), set(po) - set(pn)
    if add:
        w('  - new products (%d): %s' % (len(add), names(add)))
    if rem:
        w('  - products no longer named (%d): %s' % (len(rem), names(rem)))
    lost_cpe = [x for x in set(po) & set(pn) if po[x][0] and not pn[x][0]]
    got_cpe = [x for x in set(po) & set(pn) if pn[x][0] and not po[x][0]]
    got_ver = [x for x in set(po) & set(pn) if pn[x][1] and not po[x][1]]
    lost_ver = [x for x in set(po) & set(pn) if po[x][1] and not pn[x][1]]
    for label, xs in (('gained a CPE', got_cpe), ('lost their CPE', lost_cpe), ('now capture a version', got_ver), ('no longer capture a version', lost_ver)):
        if xs:
            w('  - %s (%d): %s' % (label, len(xs), names(xs)))
    new_nocpe = [x for x in add if not pn[x][0]]
    if new_nocpe:
        w('  - new products without a CPE are listed under "CPE candidates" when NVD has one')
w('')

w('### CPE supplement\n')
so, sn = load(os.path.join(B, 'cpe-supplement.json')), load(os.path.join(a.repo, 'src', 'cpe-supplement.json'))
if a.supplement_changed == '1':
    w('Regenerated from the current NVD CPE Dictionary (retired names follow their successor):\n')
    for k in ('fill', 'replace', 'aliases'):
        w('- %s: %d -> %d' % (k, len(so[k]), len(sn[k])))
    ga, gb = {tuple(g) for g in so['aliases']}, {tuple(g) for g in sn['aliases']}
    for label, xs in (('alias groups added', gb - ga), ('alias groups removed', ga - gb)):
        if xs:
            w('- %s: %s' % (label, '; '.join(', '.join(g) for g in sorted(xs)[:20])))
else:
    w('Unchanged: every reviewed name is still in the dictionary and no retired name gained a successor.')
w('')
rv = os.path.join(a.work, 'review.txt')
cands = [l.rstrip() for l in open(rv, encoding='utf-8')] if os.path.exists(rv) else []
w('### CPE candidates for review (not applied)\n')
if cands:
    w('%d product%s NVD candidates and %s not in `tools/cpe/decisions.py` yet. Review them by the rules in '
      '`tools/cpe/README.md` (most CVEs first):\n' % (len(cands), ' has' if len(cands) == 1 else 's have', 'is' if len(cands) == 1 else 'are'))
    w('```\n' + '\n'.join(cands[:25]) + ('\n...' if len(cands) > 25 else '') + '\n```')
else:
    w('None: every product with an NVD candidate has been reviewed.')
w('')

w('### Version coverage\n')
eo, en = load(os.path.join(B, 'external.json')), load(os.path.join(a.repo, 'tools', 'version', 'external.json'))
newc = sorted(k for k in en if en[k] and not eo.get(k))
w('Version-candidate index (`tools/version/external.json`): %d -> %d products with a candidate.' % (
    sum(1 for v in eo.values() if v), sum(1 for v in en.values() if v)))
if newc:
    w('New candidates to review with the container or sample checks in `tools/version/README.md`: %s' % names([k.split('|', 1)[1] for k in newc]))
w('\n```diff')
before = [l.rstrip() for l in open(os.path.join(a.work, 'coverage.before.txt'), encoding='utf-8') if l.startswith(('products', ' '))]
after = [l.rstrip() for l in open(os.path.join(a.work, 'coverage.after.txt'), encoding='utf-8') if l.startswith(('products', ' '))]
for x, y in zip(before, after):
    w(('  ' + y) if x == y else ('- %s\n+ %s' % (x, y)))
w('```\n')

w('### Cloud / CDN IP ranges\n')
co, cn = load(os.path.join(B, 'WebInventory.cloud.json')), load(os.path.join(a.repo, 'dist', 'WebInventory.cloud.json'))
if all(co.get(k) == cn.get(k) for k in ('names', 'v4', 'v6')):
    w('Unchanged (v%s).' % co.get('version'))
else:
    w('v%s -> v%s: %d -> %d prefixes.\n' % (co.get('version'), cn.get('version'), len(co['v4']) + len(co['v6']), len(cn['v4']) + len(cn['v6'])))
    w('| Provider | Was | Now |\n|---|---:|---:|')
    for p in sorted(set(co.get('counts', {})) | set(cn.get('counts', {}))):
        w('| %s | %d | %d |' % (p, co.get('counts', {}).get(p, 0), cn.get('counts', {}).get(p, 0)))
    w('\nSources: ' + '; '.join('%s (%s)' % (x['name'], x.get('note') or x['sha256'][:12]) for x in cn.get('sources', [])))
w('')

w('### Tests\n')
w('- `-SelfTest`: ' + tail('selftest.txt'))
w('- `-TestRules`: ' + tail('testrules.txt'))
w('- version-only rules: ' + tail('version-rules.txt'))
w('')
st = subprocess.run(['git', '-C', a.repo, 'status', '--porcelain'], stdout=subprocess.PIPE, text=True).stdout.strip()
w('### Files\n\n```\n' + (st or '(none)') + '\n```')
w('\nThe Windows PowerShell 5.1 self-test runs in the next job of the workflow and comments on this pull request.')
print('\n'.join(out))
