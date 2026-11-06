#!/usr/bin/env python3
"""Version coverage of the rule packs: which products with a CPE get a version, from which kind of rule, and why the
rest do not.

usage: coverage.py --repo <checkout> [--cve <cve_vp.json from tools/cpe/cvecpe.py>] [--md out.md]
A product is (kind, name) as the rules name it. "captured" = a detection rule captures the version; "fixed" = a rule
only writes one in (a favicon's "1.5.0+"); "version-only" = a reviewed version-only rule (tools/version/rules.py).
By CPE product the picture is better than by name: several names often share one CPE, and a detection under any of
them can carry the version (e.g. Recog's "Elastic Search" favicon and the built-in Elasticsearch rule).
"""
import argparse, collections, fnmatch, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import targets as T
import rules as RULES


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--repo', required=True); ap.add_argument('--cve'); ap.add_argument('--md')
    a = ap.parse_args()
    packs = {'builtin': json.load(open(os.path.join(a.repo, 'src', 'builtin-rules.json'), encoding='utf-8'))['rules']}
    for n in ('recog', 'wappalyzer'):
        packs[n] = json.load(open(os.path.join(a.repo, 'dist', 'WebInventory.rules.%s.json' % n), encoding='utf-8'))['rules']
    vr = json.load(open(os.path.join(a.repo, 'src', 'version-rules.json'), encoding='utf-8'))['rules']
    sup = json.load(open(os.path.join(a.repo, 'src', 'cpe-supplement.json'), encoding='utf-8'))
    plats = sup.get('platforms', [])
    cv = json.load(open(a.cve)) if a.cve else {}
    P = {}
    for pk, rs in list(packs.items()) + [('versions', vr)]:
        for r in rs:
            for o in T.outs(r):
                n = o.get('n')
                if not n or '{' in n:
                    continue
                kd = o.get('t') or 'service'
                d = P.setdefault((kd, n), {'keys': set(), 'captured': False, 'fixed': False, 'vo': False, 'packs': set()})
                if o.get('vo'):
                    d['vo'] = True; continue
                d['packs'].add(pk)
                if o.get('p'):
                    d['keys'].add(T.key(o['p']))
                v = o.get('v') or ''
                if v:
                    d['captured' if '{' in v else 'fixed'] = True
    prods = {k: d for k, d in P.items() if d['keys']}
    keyver = collections.defaultdict(set)
    for k, d in prods.items():
        for c in d['keys']:
            if d['captured'] or d['vo']:
                keyver[c].add(k)
    nv = RULES.NO_VERSION
    ext_path = os.path.join(HERE, 'external.json')
    ext = json.load(open(ext_path)) if os.path.exists(ext_path) else None
    status = {}
    for k, d in prods.items():
        if d['captured']:
            s = 'captured'
        elif d['vo']:
            s = 'version-only'
        elif d['fixed']:
            s = 'fixed only'
        elif any(keyver.get(c) for c in d['keys']):
            s = 'same CPE captured'
        elif any(c.startswith('h:') for c in d['keys']):
            s = 'hardware'
        elif any(fnmatch.fnmatch(c, p) or c == p for c in d['keys'] for p in plats):
            s = 'platform'
        elif k[1] in nv:
            s = nv[k[1]][0]
        elif ext is not None and not ext.get('%s|%s' % k):
            s = 'no-known-location'
        else:
            s = 'unreviewed'
        status[k] = s
    before = sum(1 for d in prods.values() if d['captured'] or d['fixed'])
    c = collections.Counter(status.values())
    print('products with a CPE: %d' % len(prods))
    print('  with a version before version-only rules (captured or fixed): %d' % before)
    print('  with a version now (captured, fixed or version-only): %d' % sum(1 for k, d in prods.items() if d['captured'] or d['fixed'] or d['vo']))
    for s, n in c.most_common():
        print('  %-18s %d' % (s, n))
    unknown = [n for n in nv if not any(k[1] == n for k in prods)]
    if unknown:
        print('NO_VERSION names without a product:', unknown)
    gap = [k for k, s in status.items() if s not in ('captured', 'version-only', 'fixed only')]
    if a.cve:
        w = lambda k: max((cv.get(x, [0, 0])[0] for x in prods[k]['keys']), default=0)
        kev = lambda k: max((cv.get(x, [0, 0])[1] for x in prods[k]['keys']), default=0)
        print('still without a version: %d products, %d with NVD CVEs, %d with KEV entries' % (
            len(gap), sum(1 for k in gap if w(k)), sum(1 for k in gap if kev(k))))
        un = sorted((k for k in gap if status[k] == 'unreviewed'), key=lambda k: (-kev(k), -w(k)))
        print('unreviewed, most CVEs first:', ', '.join('%s (%d) %s' % (k[1], w(k), (ext or {}).get('%s|%s' % k, '')) for k in un[:60]))
    if a.md:
        with open(a.md, 'w', encoding='utf-8') as f:
            f.write('| Product | Kind | CPE | CVEs | KEV | Version | Rule or reason |\n|---|---|---|---:|---:|---|---|\n')
            order = sorted(prods, key=lambda k: (-(max((cv.get(x, [0, 0])[1] for x in prods[k]['keys']), default=0)),
                                                 -(max((cv.get(x, [0, 0])[0] for x in prods[k]['keys']), default=0)), k[1].lower()))
            for k in order:
                s = status[k]
                if s == 'captured':
                    continue
                note = nv[k[1]][1] if k[1] in nv and s == nv[k[1]][0] else ''
                if s == 'version-only':
                    note = ', '.join('%s (%s)' % (e['id'], e.get('cls', '')) for e in RULES.ENTRIES
                                     if k[1] in (e['n'] if isinstance(e['n'], list) else [e['n']]) and e.get('t', 'service') == k[0])
                elif s == 'unreviewed' and ext:
                    note = 'candidates: ' + ', '.join(ext.get('%s|%s' % k, []))
                f.write('| %s | %s | %s | %d | %d | %s | %s |\n' % (k[1].replace('|', '/'), k[0], ', '.join(sorted(prods[k]['keys'])),
                        max((cv.get(x, [0, 0])[0] for x in prods[k]['keys']), default=0), max((cv.get(x, [0, 0])[1] for x in prods[k]['keys']), default=0),
                        s, note.replace('|', '/')))


if __name__ == '__main__':
    main()
