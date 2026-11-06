#!/usr/bin/env python3
"""Which products some public fingerprint database extracts a version for (candidates to review).

usage: external.py --repo <checkout> --whatweb <WhatWeb checkout> --nuclei <nuclei-templates checkout>
                   --webappanalyzer <checkout> --recog <checkout> [--out tools/version/external.json]
Sources: WhatWeb passive plugins (:version without :url), nuclei-templates http/technologies and http/exposed-panels
extractors, webappanalyzer version patterns (also the js/dom ones the scanner cannot use), Recog fingerprints whose
examples contain a version. A product none of them covers is reported as "no-known-location" by coverage.py.
"""
import argparse, collections, glob, json, os, re, sys
import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import targets as T

A = lambda s: re.sub(r'[^a-z0-9]', '', (s or '').lower())


def keys(name, cpes):
    ks = {A(name), A(re.sub(r'^(apache|microsoft|oracle|ibm|cisco|vmware|atlassian|jetbrains|manageengine|zoho|hashicorp|elastic|adobe|f5|citrix|'
                            r'google|red hat|redhat|solarwinds|progress|sap|hp|hpe|dell|netgate|fortinet|ignite realtime|mozilla|the)\s+', '', name, flags=re.I))}
    for c in cpes:
        k = T.key(c)
        if not k:
            continue
        p, v, pr = k.split(':', 2)
        ks |= {A(pr), A(v + pr)}
    return {k for k in ks if len(k) >= 4}


def main():
    ap = argparse.ArgumentParser()
    for x in ('repo', 'whatweb', 'nuclei', 'webappanalyzer', 'recog'):
        ap.add_argument('--' + x, required=True)
    ap.add_argument('--out', default=os.path.join(HERE, 'external.json'))
    a = ap.parse_args()
    idx = collections.defaultdict(set)
    for f in glob.glob(os.path.join(a.whatweb, 'plugins', '*.rb')):
        s = open(f, encoding='utf-8', errors='replace').read()
        if any(':version' in e and ':url' not in e for e in re.findall(r'\{[^{}]*\}', s)):
            nm = re.search(r'^name\s+"([^"]+)"', s, re.M)
            for k in {A(nm.group(1) if nm else ''), A(os.path.basename(f)[:-3])}:
                idx[k].add('whatweb:' + os.path.basename(f)[:-3])
    import yaml
    for d in ('http/technologies', 'http/exposed-panels'):
        for f in glob.glob(os.path.join(a.nuclei, d, '**', '*.yaml'), recursive=True):
            try:
                t = yaml.safe_load(open(f, encoding='utf-8'))
            except Exception:
                continue
            if not isinstance(t, dict) or not any(rq.get('extractors') for rq in (t.get('http') or []) if isinstance(rq, dict)):
                continue
            info = t.get('info') or {}; md = info.get('metadata') or {}
            for k in {A(str(md.get('product') or '')), A(str(md.get('vendor') or '') + str(md.get('product') or '')),
                      A(re.sub(r'\b(panel|login|detect|detection|version|page|portal|console|dashboard|exposure|admin)\b', '', str(info.get('name') or ''), flags=re.I))}:
                if k:
                    idx[k].add('nuclei:' + os.path.basename(f)[:-5])
    for f in glob.glob(os.path.join(a.webappanalyzer, 'src', 'technologies', '*.json')):
        for n, t in json.load(open(f, encoding='utf-8')).items():
            if ';version:' in json.dumps(t):
                idx[A(n)].add('webappanalyzer:' + n)
    for f in glob.glob(os.path.join(a.recog, 'xml', '*.xml')):
        try:
            root = ET.parse(f).getroot()
        except ET.ParseError:
            continue
        for fp in root.findall('fingerprint'):
            ps = {p.get('name'): p.get('value') for p in fp.findall('param')}
            if not any(k.endswith('.version') and v and (v.startswith('{') or re.match(r'\d', v)) for k, v in ps.items()) and \
               not any(re.search(r'\d+\.\d+', e.text or '') for e in fp.findall('example')):
                continue
            for k, v in ps.items():
                if k.endswith('.product'):
                    idx[A(v)].add('recog:' + os.path.basename(f)[:-4])
    P, _ = T.load(a.repo)
    out = {}
    for (kd, n), d in P.items():
        if not d['cpes'] or d['ver']:
            continue
        hit = sorted({s for k in keys(n, d['cpes']) for s in idx.get(k, ())})
        out['%s|%s' % (kd, n)] = hit
    json.dump(out, open(a.out, 'w'), indent=0, sort_keys=True)
    print('products without a captured version: %d, with a candidate in some database: %d' % (len(out), sum(1 for v in out.values() if v)))


if __name__ == '__main__':
    main()
