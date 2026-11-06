"""Build src/cpe-supplement.json from decisions.py and apply it to src/builtin-rules.json.

usage: gen_supplement.py --work <dir> --repo <webinventory checkout> --meta <nvdcpe-2.0.meta> --version <yyyy.mm.dd>
Needs <work>/cpe_products.json (cpedb.py). Entries already in the current supplement are kept (a regenerated pack has
its CPEs, so they no longer show up as missing); remove one by deleting it from src/cpe-supplement.json first.
Every CPE named in the supplement must exist in the NVD dictionary or the run fails.
"""
import argparse, collections, json, os, re, sys

ap = argparse.ArgumentParser()
ap.add_argument('--work', required=True); ap.add_argument('--repo', required=True)
ap.add_argument('--meta', required=True); ap.add_argument('--version', required=True)
a = ap.parse_args()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decisions as D

CP = json.load(open(os.path.join(a.work, 'cpe_products.json')))
meta = dict(l.strip().split(':', 1) for l in open(a.meta) if ':' in l)
SUP = os.path.join(a.repo, 'src', 'cpe-supplement.json')
BUILTIN = os.path.join(a.repo, 'src', 'builtin-rules.json')
packs = {'builtin': json.load(open(BUILTIN))['rules']}
for n in ('recog', 'wappalyzer'):
    packs[n] = json.load(open(os.path.join(a.repo, 'dist', 'WebInventory.rules.%s.json' % n)))['rules']
prev = json.load(open(SUP)) if os.path.exists(SUP) else {'fill': []}


def outs(r):
    return r['out'] if r.get('out') else [r]


def key_of(cpe):
    if not cpe:
        return None
    if cpe.startswith('cpe:/'):
        f = cpe[5:].split(':')
    else:
        f = [re.sub(r'\\(.)', r'\1', x) for x in re.split(r'(?<!\\):', cpe[8:])]
    return (f[0] + ':' + f[1] + ':' + f[2]).lower() if len(f) >= 3 else None


def template(key):
    part, vendor, product = key.split(':', 2)
    esc = lambda s: re.sub(r'([^A-Za-z0-9._\-])', r'\\\1', s)
    return 'cpe:2.3:%s:%s:%s:{v}' % (part, esc(vendor), esc(product))


kinds = collections.defaultdict(set)
used = set()
sib = collections.defaultdict(collections.Counter)
missing = set()
for rs in packs.values():
    for r in rs:
        for o in outs(r):
            n = o.get('n')
            if not n:
                continue
            kd = o.get('t') or 'service'
            kinds[n].add(kd)
            k = key_of(o.get('p'))
            if k and '*' not in k:
                used.add(k); sib[(kd, n)][k] += 1
            elif not o.get('p'):
                missing.add((kd, n))

fill = {(e['t'], e['n']): key_of(e['p']) for e in prev.get('fill', []) if (e['t'], e['n']) not in D.REJECT}
unfill = {(e['t'], e['n']): e['p'] for e in prev.get('fill', []) if (e['t'], e['n']) in D.REJECT}
for (kd, n), c in sib.items():                                   # same product, CPE in another rule
    if (kd, n) in missing and n not in D.SIBLING_SKIP and '{' not in n and (kd, n) not in D.REJECT:
        fill.setdefault((kd, n), c.most_common(1)[0][0])
fill.update(D.ACCEPT)
for n, k in D.MANUAL.items():
    for kd in kinds.get(n, ()):
        fill[(kd, n)] = k
for skip in D.SIBLING_SKIP | {r[0] for r in D.REPLACE}:
    for kd in ('service', 'os', 'hw'):
        if (kd, skip) in fill and (kd, skip) not in D.ACCEPT and skip not in D.MANUAL:
            del fill[(kd, skip)]

bad = [(kd, n, k) for (kd, n), k in fill.items() if k not in CP]
bad += [('replace', n, new) for n, _, new in D.REPLACE if new and new not in CP]
bad += [('alias', '', k) for g in D.ALIASES for k in g if k not in CP]
bad += [('platform', '', k) for k in D.PLATFORMS if not k.endswith('*') and k not in CP]
if bad:
    for b in bad:
        print('not in the NVD dictionary:', b)
    sys.exit(1)

# alias groups: reviewed + retired names with a single successor (not ones that encode a version or model)
used |= set(fill.values()) | {r[2] for r in D.REPLACE if r[2]}
parent = {}


def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]; x = parent[x]
    return x


for g in D.ALIASES:
    for k in g[1:]:
        parent[find(k)] = find(g[0])
digits = lambda k: set(re.findall(r'\d+', k.split(':', 2)[2]))
for k, e in CP.items():
    if e['n'] and e['dep'] == e['n']:
        succ = [t for t in e['depBy'] if t != k]
        if len(succ) == 1 and (succ[0] in used or k in used) and digits(k) == digits(succ[0]):
            parent[find(k)] = find(succ[0])
groups = collections.defaultdict(set)
for k in list(parent):
    groups[find(k)].add(k)
aliases = sorted(sorted(g) for g in groups.values() if len(g) > 1 and g & used)

doc = {
    'name': 'cpe-supplement', 'version': a.version,
    'source': 'Product names from the built-in, Recog and Wappalyzer rules mapped to NVD CPE names, checked against the NVD CPE '
              'Dictionary 2.0 feed (lastModified %s, sha256 %s) and reviewed by hand' % (meta.get('lastModifiedDate', '').strip(), meta.get('sha256', '').strip()),
    'notice': 'This product uses data from the NVD API but is not endorsed or certified by the NVD.',
    'fill': [{'t': kd, 'n': n, 'p': template(k)} for (kd, n), k in sorted(fill.items(), key=lambda kv: (kv[0][1].lower(), kv[0][0]))],
    'replace': [{'n': n, 'was': was, 'p': template(new) if new else ''} for n, was, new in D.REPLACE],
    'aliases': aliases,
    'platforms': list(D.PLATFORMS),
}
j = lambda x: json.dumps(x, ensure_ascii=False, separators=(',', ':'))
rows = lambda xs: [j(x) + (',' if i < len(xs) - 1 else '') for i, x in enumerate(xs)]
text = '\n'.join(['{"name":%s,"version":%s,' % (j(doc['name']), j(doc['version'])), '"source":%s,' % j(doc['source']),
                  '"notice":%s,' % j(doc['notice']), '"fill":['] + rows(doc['fill']) + ['],"replace":['] + rows(doc['replace'])
                 + ['],"aliases":['] + rows(doc['aliases']) + ['],"platforms":' + j(doc['platforms']) + '}']) + '\n'
assert json.loads(text) == doc
open(SUP, 'w', encoding='utf-8').write(text)

# the built-in pack carries its CPEs directly (one rule per line, same serialisation as the file)
F = {(e['t'], e['n']): e['p'] for e in doc['fill']}
R = {e['n']: e for e in doc['replace']}
lines = open(BUILTIN, encoding='utf-8').read().split('\n')
filled = replaced = 0
for i in range(1, len(lines) - 2):
    s = lines[i]; comma = s.endswith(',')
    r = json.loads(s[:-1] if comma else s)
    changed = False
    for o in outs(r):
        n = o.get('n')
        if not n or '{' in n:
            continue
        kd = o.get('t') or 'service'
        if o.get('p') and unfill.get((kd, n)) == o['p']:                # moved to REJECT: take back the CPE we added
            o.pop('p'); replaced += 1; changed = True
        elif o.get('p') and n in R and key_of(o['p']) == R[n]['was']:
            if R[n]['p']:
                o['p'] = R[n]['p']
            else:
                o.pop('p')
            replaced += 1; changed = True
        elif not o.get('p') and (kd, n) in F and not (o.get('v') and '{' not in o['v']):   # a literal version is a guess
            o['p'] = F[(kd, n)]; filled += 1; changed = True
    if changed:
        lines[i] = json.dumps(r, separators=(',', ':'), ensure_ascii=False) + (',' if comma else '')
open(BUILTIN, 'w', encoding='utf-8').write('\n'.join(lines))
json.loads(open(BUILTIN, encoding='utf-8').read())
print('supplement %s: fill %d, replace %d, alias groups %d; built-in rules: %d filled, %d corrected'
      % (a.version, len(doc['fill']), len(doc['replace']), len(aliases), filled, replaced))
