"""Find rule outputs without a CPE and propose NVD candidates for the ones not yet reviewed.

usage: gap.py --work <dir> --repo <webinventory checkout> --recog <recog checkout> --wappalyzer <webappanalyzer checkout>
Reads <work>/cpe_products.json (cpedb.py) and <work>/cve_vp.json (cvecpe.py) and the rule packs (src/builtin-rules.json,
dist/WebInventory.rules.*.json). Writes <work>/review.txt: one line per product that has candidates and is in neither
decisions.ACCEPT/MANUAL nor decisions.REJECT, best candidates first (most NVD CVEs). Review each line and add it to
ACCEPT or REJECT in decisions.py, then run gen_supplement.py.
"""
import argparse, collections, glob, json, os, re, sys, xml.etree.ElementTree as ET
from urllib.parse import urlparse

ap = argparse.ArgumentParser()
ap.add_argument('--work', required=True); ap.add_argument('--repo', required=True)
ap.add_argument('--recog', required=True); ap.add_argument('--wappalyzer', required=True)
a = ap.parse_args()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decisions as D

CP = json.load(open(os.path.join(a.work, 'cpe_products.json')))
CV = json.load(open(os.path.join(a.work, 'cve_vp.json')))
packs = {'builtin': json.load(open(os.path.join(a.repo, 'src', 'builtin-rules.json')))['rules']}
for n in ('recog', 'wappalyzer'):
    packs[n] = json.load(open(os.path.join(a.repo, 'dist', 'WebInventory.rules.%s.json' % n)))['rules']

web = {}
for f in glob.glob(os.path.join(a.wappalyzer, 'src', 'technologies', '*.json')):
    for k, v in json.load(open(f)).items():
        h = (urlparse(v.get('website', '') or '').hostname or '').lower()
        web[k] = h[4:] if h.startswith('www.') else h
rv = {}
for f in glob.glob(os.path.join(a.recog, 'xml', '*.xml')):
    base = os.path.basename(f)[:-4]
    try:
        root = ET.parse(f).getroot()
    except ET.ParseError:
        continue
    for i, fp in enumerate(root.findall('fingerprint'), 1):
        rv['recog:%s:%d' % (base, i)] = {p.get('name'): p.get('value') for p in fp.findall('param')}


def outs(r):
    return r['out'] if r.get('out') else [r]


def alnum(s):
    return re.sub(r'[^a-z0-9]', '', s.lower())


prods = {}
for pk, rules in packs.items():
    for r in rules:
        for o in outs(r):
            n = o.get('n')
            if not n:
                continue
            kind = o.get('t') or 'service'
            d = prods.setdefault((kind, n), {'missing': 0, 'cpe': False, 'ver': False, 'packs': set(), 'vendor': set(), 'web': set(), 'cat': set()})
            d['packs'].add(pk); d['cat'].add(o.get('c', ''))
            d['missing'] += 0 if o.get('p') else 1
            d['cpe'] |= bool(o.get('p')); d['ver'] |= bool(o.get('v'))
            if pk == 'recog' and r['id'] in rv:
                v = rv[r['id']].get(kind + '.vendor') or rv[r['id']].get('service.component.vendor')
                if v and not v.startswith('{'):
                    d['vendor'].add(v)
            if pk == 'wappalyzer':
                t = r['id'].split(':', 1)[1].rsplit(':', 1)[0]
                if web.get(t):
                    d['web'].add(web[t])

byprod, byvp, bydom = collections.defaultdict(list), collections.defaultdict(list), collections.defaultdict(list)
for k, e in CP.items():
    part, v, p = k.split(':', 2)
    byprod[alnum(p)].append(k); byvp[alnum(v + p)].append(k)
    for dm in e['doms']:
        bydom[dm].append(k)

reviewed = set(D.ACCEPT) | set(D.REJECT) | {(kd, n) for (kd, n) in prods if n in D.MANUAL}
lines = []
for (kind, n), d in prods.items():
    if d['cpe'] or (kind, n) in reviewed or '{' in n or len(alnum(n)) < 3:
        continue
    an = alnum(n)
    sc = collections.Counter()
    for k in byvp.get(an, []): sc[k] += 3
    for k in byprod.get(an, []): sc[k] += 2
    vend = [alnum(v) for v in d['vendor']]
    for k in list(sc):
        part, v, p = k.split(':', 2)
        if alnum(v) == alnum(p): sc[k] += 1
        if any(x and (alnum(v) == x or x.startswith(alnum(v)) or alnum(v).startswith(x)) for x in vend): sc[k] += 2
    for dm in d['web']:
        for k in bydom.get(dm, []):
            part, v, p = k.split(':', 2)
            if alnum(p) and (alnum(p) in an or an in alnum(p) or alnum(v + p) == an): sc[k] += 3
    want = {'service': ('a', 'o'), 'os': ('o',), 'hw': ('h',)}.get(kind, ('a', 'o', 'h'))
    cands = sorted(((s + (1 if CV.get(k, [0])[0] else 0), k) for k, s in sc.items() if k.split(':')[0] in want), key=lambda t: (-t[0], -CV.get(t[1], [0])[0]))
    if not cands:
        continue
    best = max(CV.get(k, [0, 0])[0] for _, k in cands)
    cs = ' | '.join('%s cve%d%s "%s"' % (k, CV.get(k, [0, 0])[0], (' kev%d' % CV[k][1]) if CV.get(k, [0, 0])[1] else '', (CP[k]['titles'] or [''])[0][:36]) for _, k in cands[:3])
    lines.append((best, '(%r, %r)%s {%s} [%s] %s :: %s' % (kind, n, ' v' if d['ver'] else '', '/'.join(sorted(d['cat'])), '/'.join(sorted(d['packs'])),
                                                        ','.join(sorted(d['vendor'] or d['web'])), cs)))
lines.sort(key=lambda t: -t[0])
with open(os.path.join(a.work, 'review.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(l for _, l in lines) + '\n')
print('%d products to review -> %s' % (len(lines), os.path.join(a.work, 'review.txt')))
