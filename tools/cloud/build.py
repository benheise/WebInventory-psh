#!/usr/bin/env python3
"""Build dist/WebInventory.cloud.json from the IP-range lists that cloud and CDN providers publish.

Every source is the provider's own machine-readable list (no third-party aggregation). Each prefix becomes one entry
"<network>/<len>|<provider>|<region>|<service>" (names as indices into "names"). The scanner does a longest-prefix
match on each service's IP, so a more specific prefix (an Azure service tag inside an AzureCloud region range, a
Google Cloud range inside Google's) decides.

usage: build.py [--cache DIR] [--offline] [--out dist/WebInventory.cloud.json] [--version YYYY.MM.DD]
  --cache DIR   keep the downloaded lists in DIR (default: a temporary folder); with --offline, read them from there
"""
import argparse, csv, datetime, hashlib, io, ipaddress, json, os, re, sys, tempfile, urllib.request

UA = 'WebInventory-cloud-ranges (+https://github.com/benheise/WebInventory-psh)'
# Azure publishes its Service Tags under a new URL every week; the download page names the current file
AZURE = [('Azure', 56519, 'ServiceTags_Public'), ('Azure Government', 57063, 'ServiceTags_AzureGovernment'), ('Azure China', 57062, 'ServiceTags_China')]
SOURCES = [
    ('aws', 'https://ip-ranges.amazonaws.com/ip-ranges.json'),
    ('gcp', 'https://www.gstatic.com/ipranges/cloud.json'),
    ('google', 'https://www.gstatic.com/ipranges/goog.json'),
    ('cloudflare4', 'https://www.cloudflare.com/ips-v4'),
    ('cloudflare6', 'https://www.cloudflare.com/ips-v6'),
    ('fastly', 'https://api.fastly.com/public-ip-list'),
    ('oracle', 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json'),
    ('digitalocean', 'https://www.digitalocean.com/geo/google.csv'),
    ('linode', 'https://geoip.linode.com/'),
]
# when two providers list the same prefix, the earlier one wins (Google Cloud's ranges are also in Google's list)
PRIORITY = ['AWS', 'Azure', 'Azure Government', 'Azure China', 'Google Cloud', 'Oracle Cloud', 'DigitalOcean', 'Akamai (Linode)',
            'Cloudflare', 'Fastly', 'Google']


def fetch(url, path, offline):
    if offline or (os.path.exists(path) and os.path.getsize(path) > 0 and os.environ.get('WI_CLOUD_REUSE')):
        return open(path, 'rb').read()
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    with open(path + '.part', 'wb') as f:
        f.write(data)
    os.replace(path + '.part', path)
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cache'); ap.add_argument('--offline', action='store_true')
    ap.add_argument('--out', default='dist/WebInventory.cloud.json'); ap.add_argument('--version')
    a = ap.parse_args()
    cache = a.cache or tempfile.mkdtemp(prefix='wi-cloud-')
    os.makedirs(cache, exist_ok=True)
    entries = []          # (network, provider, region, service)
    sources = []

    def src(name, url, data, note=''):
        sources.append({'name': name, 'url': url, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'note': note})

    def add(net, provider, region='', service=''):
        try:
            n = ipaddress.ip_network(net.strip(), strict=False)
        except ValueError:
            return
        entries.append((n, provider, (region or '').strip(), (service or '').strip()))

    raw = {}
    for name, url in SOURCES:
        raw[name] = (url, fetch(url, os.path.join(cache, name), a.offline))

    # AWS: every prefix is listed under AMAZON plus each specific service it serves
    url, d = raw['aws']; j = json.loads(d)
    src('AWS', url, d, 'syncToken %s, created %s' % (j.get('syncToken'), j.get('createDate')))
    for p in j.get('prefixes', []):
        add(p['ip_prefix'], 'AWS', p.get('region'), p.get('service'))
    for p in j.get('ipv6_prefixes', []):
        add(p['ipv6_prefix'], 'AWS', p.get('region'), p.get('service'))

    # Azure Service Tags (public cloud, Azure Government, Azure China)
    for prov, fid, stem in AZURE:
        page = os.path.join(cache, 'azure-%d.html' % fid)
        html = fetch('https://www.microsoft.com/en-us/download/details.aspx?id=%d' % fid, page, a.offline).decode('utf-8', 'replace')
        m = re.search(r'https://download\.microsoft\.com/download/[^"\s]+/%s_\d{8}\.json' % stem, html)
        if not m:
            sys.exit('%s: the download page no longer names a %s_<date>.json file' % (prov, stem))
        url = m.group(0)
        d = fetch(url, os.path.join(cache, 'azure-%d.json' % fid), a.offline)
        j = json.loads(d.decode('utf-8-sig'))
        src(prov, url, d, 'changeNumber %s, cloud %s' % (j.get('changeNumber'), j.get('cloud')))
        for v in j.get('values', []):
            name = v.get('name', ''); pr = v.get('properties', {})
            region = pr.get('region', '')
            if name == 'AzureCloud':
                service = ''
            elif name.startswith('AzureCloud.'):
                service = ''
            elif region and '.' in name:
                service = name.rsplit('.', 1)[0]          # AppService.EastUS -> AppService
            else:
                service = name                            # AzureFrontDoor.Frontend, AppService (global)
            for net in pr.get('addressPrefixes', []):
                add(net, prov, region, service)

    # Google Cloud (customer ranges, scope = region) and Google (all Google-owned ranges)
    url, d = raw['gcp']; j = json.loads(d)
    src('Google Cloud', url, d, 'syncToken %s, created %s' % (j.get('syncToken'), j.get('creationTime')))
    for p in j.get('prefixes', []):
        add(p.get('ipv4Prefix') or p.get('ipv6Prefix'), 'Google Cloud', p.get('scope'), '')
    url, d = raw['google']; j = json.loads(d)
    src('Google', url, d, 'syncToken %s, created %s' % (j.get('syncToken'), j.get('creationTime')))
    for p in j.get('prefixes', []):
        add(p.get('ipv4Prefix') or p.get('ipv6Prefix'), 'Google', '', '')

    for key in ('cloudflare4', 'cloudflare6'):
        url, d = raw[key]
        src('Cloudflare', url, d)
        for l in d.decode().split():
            add(l, 'Cloudflare', '', 'CDN')
    url, d = raw['fastly']; j = json.loads(d)
    src('Fastly', url, d)
    for net in j.get('addresses', []) + j.get('ipv6_addresses', []):
        add(net, 'Fastly', '', 'CDN')

    url, d = raw['oracle']; j = json.loads(d)
    src('Oracle Cloud', url, d, 'last updated %s' % j.get('last_updated_timestamp'))
    for r in j.get('regions', []):
        for c in r.get('cidrs', []):
            add(c['cidr'], 'Oracle Cloud', r.get('region'), ';'.join(sorted(c.get('tags', []))))

    # RFC 8805 geofeeds: prefix, country, region (ISO 3166-2), city, postal code
    for key, prov in (('digitalocean', 'DigitalOcean'), ('linode', 'Akamai (Linode)')):
        url, d = raw[key]
        src(prov, url, d)
        for row in csv.reader(io.StringIO(d.decode('utf-8', 'replace'))):
            if not row or row[0].startswith('#'):
                continue
            city = row[3].strip() if len(row) > 3 else ''
            cc = row[1].strip() if len(row) > 1 else ''
            add(row[0], prov, ', '.join(x for x in (city, cc) if x), '')

    # merge: one entry per prefix. Same provider: union of services, first non-empty region. Different providers:
    # PRIORITY decides. AWS lists every prefix as AMAZON too; AMAZON is kept only where no specific service is listed.
    best = {}
    for n, prov, region, service in entries:
        k = n
        cur = best.get(k)
        if cur is None:
            best[k] = [prov, region, {service} if service else set()]
            continue
        if cur[0] != prov:
            if PRIORITY.index(prov) < PRIORITY.index(cur[0]):
                best[k] = [prov, region, {service} if service else set()]
            continue
        if service:
            cur[2].add(service)
        if not cur[1] and region:
            cur[1] = region
    for v in best.values():
        if len(v[2]) > 1 and 'AMAZON' in v[2]:
            v[2].discard('AMAZON')
    # Azure service tags without a region: take the region of the AzureCloud.<region> range that contains them
    regional = {}
    for n, (prov, region, sv) in best.items():
        if prov.startswith('Azure') and region and not sv:
            regional.setdefault((prov, n.version), {}).setdefault(n.prefixlen, {})[int(n.network_address)] = region
    for n, v in best.items():
        prov, region, sv = v
        if not prov.startswith('Azure') or region:
            continue
        tab = regional.get((prov, n.version), {})
        addr = int(n.network_address); bits = n.max_prefixlen
        for plen in sorted((p for p in tab if p <= n.prefixlen), reverse=True):
            key = (addr >> (bits - plen)) << (bits - plen)
            if key in tab[plen]:
                v[1] = tab[plen][key]; break

    names = ['']
    index = {'': 0}

    def nid(s):
        if s not in index:
            index[s] = len(names); names.append(s)
        return index[s]
    v4, v6 = [], []
    counts = {}
    for n in sorted(best, key=lambda x: (x.version, int(x.network_address), x.prefixlen)):
        prov, region, sv = best[n]
        counts[prov] = counts.get(prov, 0) + 1
        line = '%s|%d|%d|%d' % (n.with_prefixlen, nid(prov), nid(region), nid(';'.join(sorted(sv))))
        (v4 if n.version == 4 else v6).append(line)
    version = a.version or datetime.datetime.now(datetime.timezone.utc).strftime('%Y.%m.%d')
    out = {'format': 1, 'name': 'cloud', 'version': version,
           'generated': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
           'about': 'IP ranges published by cloud and CDN providers; built by tools/cloud/build.py. Longest prefix wins.',
           'sources': sources, 'counts': dict(sorted(counts.items())), 'names': names, 'v4': v4, 'v6': v6}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, 'w', encoding='utf-8', newline='\n') as f:
        # one entry per line keeps weekly diffs readable
        f.write('{\n')
        for k in ('format', 'name', 'version', 'generated', 'about'):
            f.write('  %s: %s,\n' % (json.dumps(k), json.dumps(out[k])))
        f.write('  "sources": [\n' + ',\n'.join('    ' + json.dumps(s, sort_keys=True) for s in sources) + '\n  ],\n')
        f.write('  "counts": %s,\n' % json.dumps(out['counts']))
        f.write('  "names": [\n' + ',\n'.join('    ' + json.dumps(s) for s in names) + '\n  ],\n')
        for k in ('v4', 'v6'):
            f.write('  %s: [\n' % json.dumps(k) + ',\n'.join('    ' + json.dumps(s) for s in out[k]) + '\n  ]' + (',\n' if k == 'v4' else '\n'))
        f.write('}\n')
    print('%s: %d IPv4 + %d IPv6 prefixes, %d names; %s' % (a.out, len(v4), len(v6), len(names),
          ', '.join('%s %d' % kv for kv in sorted(counts.items()))))


if __name__ == '__main__':
    main()
