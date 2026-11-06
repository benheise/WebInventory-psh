#!/usr/bin/env python3
"""Build src/version-rules.json from the reviewed entries in rules.py.

usage: gen_rules.py --repo <checkout> [--version 2.3.2]
Each entry names a product whose detection rules carry a CPE but capture no version. The generated rule is version-only
("vo"): it adds the captured version to that product when a detection rule found it, and is discarded otherwise. One
output is written per CPE product the detection rules use, so the rule joins whichever of them matched. The entry's
evidence stays in rules.py (and in the generated evidence table); it is not embedded in the script.
"""
import argparse, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import targets as T
import rules as RULES


def cpe_template(c):
    # the detection rule's CPE with the version slot left for {v}
    if c.startswith('cpe:/'):
        f = c[5:].split(':')
        f = (f + ['', '', '', ''])[:4]
        f[3] = '{v}'
        return 'cpe:/' + ':'.join(f)
    f = re.split(r'(?<!\\):', c)
    f = (f + ['*'] * 13)[:13]
    if f[5] in ('*', '-', '', '{v}'):
        f[5] = '{v}'
    return ':'.join(f).rstrip(':')


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--repo', required=True); ap.add_argument('--version', default='')
    a = ap.parse_args()
    P, _ = T.load(a.repo)
    rules, seen, bad = [], set(), []
    for e in RULES.ENTRIES:
        kind = e.get('t', 'service')
        prods = e['n'] if isinstance(e['n'], list) else [e['n']]
        outs, keys = [], set()
        for pn in prods:
            d = P.get((kind, pn))
            if not d:
                bad.append('%s: no detection rule for (%s, %s)' % (e['id'], kind, pn)); continue
            if d['ver'] and not e.get('force'):
                bad.append('%s: %s already captures a version' % (e['id'], pn)); continue
            for c in d['cpes']:
                k = T.key(c)
                if k in keys:
                    continue
                keys.add(k)
                o = {'n': pn, 'v': e['v'], 'p': cpe_template(c), 'vo': True}
                if kind != 'service':
                    o['t'] = kind
                outs.append(o)
        if not outs:
            continue
        if e['id'] in seen:
            bad.append('duplicate id ' + e['id'])
        if '(?<v>' in e['r'] or '{v}' in e['v']:
            bad.append('%s: the group name v is the CPE placeholder; use another name' % e['id'])
        seen.add(e['id'])
        r = {'id': e['id'], 'f': e['f'], 'r': e['r']}
        if e.get('o'):
            r['o'] = e['o']
        if e.get('and'):
            r['and'] = e['and']
        r['src'] = 'builtin'
        if len(outs) == 1:
            r.update(outs[0])
        else:
            r['out'] = outs
        r['ex'] = e['ex']; r['exv'] = e['exv']
        rules.append(r)
    for b in bad:
        print('ERROR', b)
    if bad:
        sys.exit(1)
    doc = {'name': 'builtin-versions', 'version': a.version,
           'source': 'Version-only rules for products whose detection rules carry a CPE but no version; each checked against '
                     'responses of the product itself (container or published samples), see tools/version'}
    j = lambda x: json.dumps(x, ensure_ascii=False, separators=(',', ':'))
    text = '{"name":%s,"version":%s,\n"source":%s,\n"rules":[\n' % (j(doc['name']), j(doc['version']), j(doc['source']))
    text += ',\n'.join(j(r) for r in rules) + '\n]}\n'
    json.loads(text)
    open(os.path.join(a.repo, 'src', 'version-rules.json'), 'w', encoding='utf-8').write(text)
    print('version rules: %d (%d products)' % (len(rules), len({(e.get('t', 'service'), n) for e in RULES.ENTRIES for n in (e['n'] if isinstance(e['n'], list) else [e['n']])})))


if __name__ == '__main__':
    main()
