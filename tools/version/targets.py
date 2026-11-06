"""Products whose rules carry a CPE but capture no version, with the names and CPE templates their detection rules use.

usage: targets.py --repo <checkout> [--json out.json]
A version-only rule for one of these products must use the same kind and CPE product (or the same name) as a detection
rule, so that it joins that detection.
"""
import argparse, collections, json, os, re

def outs(r):
    return r['out'] if r.get('out') else [r]

def key(c):
    if not c:
        return None
    if c.startswith('cpe:/'):
        f = c[5:].split(':')
    else:
        f = [re.sub(r'\\(.)', r'\1', x) for x in re.split(r'(?<!\\):', c[8:])]
    return ':'.join(f[:3]).lower()

def load(repo):
    packs = {'builtin': json.load(open(os.path.join(repo, 'src', 'builtin-rules.json')))['rules']}
    vr = os.path.join(repo, 'src', 'version-rules.json')
    for n in ('recog', 'wappalyzer'):
        packs[n] = json.load(open(os.path.join(repo, 'dist', 'WebInventory.rules.%s.json' % n)))['rules']
    P = {}
    for pk, rs in packs.items():
        for r in rs:
            for o in outs(r):
                n = o.get('n')
                if not n or '{' in n or o.get('vo'):
                    continue
                kd = o.get('t') or 'service'
                d = P.setdefault((kd, n), {'cpes': collections.Counter(), 'ver': False, 'rules': []})
                if o.get('p'):
                    d['cpes'][o['p']] += 1
                if o.get('v'):
                    d['ver'] = True
                d['rules'].append(r['id'])
    vo = collections.defaultdict(list)
    if os.path.exists(vr):
        for r in json.load(open(vr))['rules']:
            for o in outs(r):
                vo[(o.get('t') or 'service', o['n'])].append(r['id'])
    return P, vo

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--repo', required=True); ap.add_argument('--json')
    a = ap.parse_args()
    P, vo = load(a.repo)
    gap = {k: d for k, d in P.items() if d['cpes'] and not d['ver']}
    print('products with a CPE but no version capture: %d (%d have version-only rules)' % (len(gap), sum(1 for k in gap if k in vo)))
    if a.json:
        json.dump({'%s|%s' % k: {'cpes': list(d['cpes']), 'rules': d['rules'], 'vo': vo.get(k, [])} for k, d in gap.items()}, open(a.json, 'w'), indent=0)
