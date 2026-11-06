#!/usr/bin/env python3
"""Run a product container and record what Invoke-WebInventory would see, to find where the product shows its version.

usage:
  vlab.py run  --case <cases.json entry name> --tag <tag> [--keep]
  vlab.py grep --case <name> --tag <tag> [--version <expected>]

For each case (tools/version/cases.json) the container (and any dependency containers) is started on a private docker
network, the HTTP(S) port is published on 127.0.0.1, and once it answers, the same requests the scanner makes by default
are sent: GET / following same-host redirects, /favicon.ico, /robots.txt, /.well-known/security.txt and one random
404 path. Headers and bodies are written to <out>/<case>/<tag>/. 'grep' then lists every place the expected version
string occurs, with context, so a version-capturing rule can be written against what the product really sends.
"""
import argparse, hashlib, json, os, re, socket, ssl, subprocess, sys, time, urllib.parse, http.client

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get('VLAB_OUT', os.path.join(HERE, 'out'))


def sh(*a, check=True, capture=True):
    r = subprocess.run(list(a), stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None, text=True)
    if check and r.returncode:
        raise SystemExit('command failed (%d): %s\n%s' % (r.returncode, ' '.join(a), r.stdout))
    return r.stdout if capture else ''


def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p


def fetch(tls, port, path, host_hdr, timeout=15):
    ctx = ssl._create_unverified_context() if tls else None
    c = http.client.HTTPSConnection('127.0.0.1', port, timeout=timeout, context=ctx) if tls else http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
    c.request('GET', path, headers={'Host': host_hdr, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebInventory/2.0 (authorized asset inventory)',
                                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Encoding': 'identity', 'Connection': 'close'})
    r = c.getresponse()
    body = r.read(262144)
    hdrs = r.getheaders()
    c.close()
    return r.status, r.reason, hdrs, body


def capture(case, port, outdir):
    tls = bool(case.get('tls'))
    host = '127.0.0.1:%d' % port
    res = {'hops': [], 'extras': {}}
    path = case.get('path', '/')
    for hop in range(6):
        st, rs, hd, body = fetch(tls, port, path, host)
        res['hops'].append({'path': path, 'status': st, 'reason': rs, 'headers': hd, 'len': len(body)})
        open(os.path.join(outdir, 'hop%d.body' % hop), 'wb').write(body)
        loc = next((v for k, v in hd if k.lower() == 'location'), None)
        if st in (301, 302, 303, 307, 308) and loc:
            u = urllib.parse.urlsplit(urllib.parse.urljoin('http%s://%s%s' % ('s' if tls else '', host, path), loc))
            if u.hostname not in ('127.0.0.1', 'localhost'):
                break
            path = u.path + ('?' + u.query if u.query else '')
            continue
        break
    for name, p in (('favicon', '/favicon.ico'), ('robots', '/robots.txt'), ('securitytxt', '/.well-known/security.txt'), ('notfound', '/wi-0a1b2c3d4e.html')):
        try:
            st, rs, hd, body = fetch(tls, port, p, host)
        except Exception as e:
            res['extras'][name] = {'error': str(e)}; continue
        res['extras'][name] = {'status': st, 'headers': hd, 'len': len(body), 'md5': hashlib.md5(body).hexdigest()}
        if name != 'favicon':
            open(os.path.join(outdir, name + '.body'), 'wb').write(body)
    json.dump(res, open(os.path.join(outdir, 'capture.json'), 'w'), indent=1)
    return res


def wait_http(case, port, deadline):
    tls = bool(case.get('tls'))
    want = case.get('ready', '')
    last = ''
    while time.time() < deadline:
        try:
            path = case.get('path', '/')
            for hop in range(6):
                st, rs, hd, body = fetch(tls, port, path, '127.0.0.1:%d' % port, timeout=5)
                loc = next((v for k, v in hd if k.lower() == 'location'), None)
                if st in (301, 302, 303, 307, 308) and loc:
                    u = urllib.parse.urlsplit(urllib.parse.urljoin('http://127.0.0.1:%d%s' % (port, path), loc))
                    if u.hostname in ('127.0.0.1', 'localhost'):
                        path = u.path + ('?' + u.query if u.query else ''); continue
                break
            last = '%d %s' % (st, body[:120])
            if st < 500 and (not want or want.encode() in body or any(want in v for k, v in hd)):
                return True
        except Exception as e:
            last = str(e)
        time.sleep(3)
    print('not ready:', last)
    return False


def run(case, tag, keep):
    slug = case['name']
    outdir = os.path.join(OUT, slug, tag); os.makedirs(outdir, exist_ok=True)
    net = 'vlab-' + slug
    sh('docker', 'network', 'create', net, check=False)
    started = []
    try:
        for dep in case.get('deps', []):
            dn = 'vlab-%s-%s' % (slug, dep['name'])
            sh('docker', 'rm', '-f', dn, check=False)
            args = ['docker', 'run', '-d', '--name', dn, '--network', net, '--network-alias', dep['name']]
            for k, v in dep.get('env', {}).items():
                args += ['-e', '%s=%s' % (k, v.replace('{tag}', tag))]
            args += [dep['image'].replace('{tag}', tag)] + [c.replace('{tag}', tag) for c in dep.get('cmd', [])]
            sh(*args); started.append(dn)
            time.sleep(dep.get('sleep', 5))
        port = free_port()
        cn = 'vlab-%s' % slug
        sh('docker', 'rm', '-f', cn, check=False)
        args = ['docker', 'run', '-d', '--name', cn, '--network', net, '-p', '127.0.0.1:%d:%d' % (port, case['port'])]
        if case.get('privileged'):
            args.append('--privileged')  # products that run their own container runtime inside (Rancher's k3s)
        for k, v in case.get('env', {}).items():
            args += ['-e', '%s=%s' % (k, v.replace('{tag}', tag))]
        if case.get('entrypoint') is not None:
            args += ['--entrypoint', case['entrypoint']]
        args += ['%s:%s' % (case['image'], tag)] + [c.replace('{tag}', tag) for c in case.get('cmd', [])]
        sh(*args); started.append(cn)
        ok = wait_http(case, port, time.time() + case.get('wait', 180))
        time.sleep(case.get('settle', 0))
        res = capture(case, port, outdir)
        print('%s %s: ready=%s hops=%s' % (slug, tag, ok, [(h['status'], h['path']) for h in res['hops']]))
        open(os.path.join(outdir, 'port'), 'w').write(str(port))
        return port
    finally:
        if not keep:
            for n in reversed(started):
                sh('docker', 'rm', '-f', n, check=False)
            sh('docker', 'network', 'rm', net, check=False)


def grep(case, tag, version):
    outdir = os.path.join(OUT, case['name'], tag)
    if not version:
        m = re.search(case.get('vre', r'v?(\d+(?:\.\d+)+)'), tag)
        version = m.group(1) if m else tag
    cap = json.load(open(os.path.join(outdir, 'capture.json')))
    pats = [re.escape(version)]
    parts = re.findall(r'\d+', version)
    if len(parts) >= 2:
        pats.append(r'(?<![\d.])' + r'\.'.join(parts[:2]) + r'(?![\d])')
    rx = re.compile('|'.join(pats))
    found = 0
    for i, h in enumerate(cap['hops']):
        for k, v in h['headers']:
            if rx.search(v):
                print('hop%d header %s: %s' % (i, k, v)); found += 1
    for name, e in cap['extras'].items():
        for k, v in e.get('headers', []):
            if rx.search(v):
                print('%s header %s: %s' % (name, k, v)); found += 1
    for f in sorted(os.listdir(outdir)):
        if not f.endswith('.body'):
            continue
        t = open(os.path.join(outdir, f), 'rb').read().decode('utf-8', 'replace')
        seen = {}
        for m in rx.finditer(t):
            found += 1
            a, b = max(0, m.start() - 60), min(len(t), m.end() + 30)
            ctx = t[a:b].replace('\n', '\\n')
            # occurrences that differ only in file names (asset lists) are shown once
            key = re.sub(r'[\w/.-]*\.(?:js|css|png|svg|ico|woff2?)', 'F', t[max(0, m.start() - 25):m.end() + 10])
            if key in seen:
                seen[key] += 1; continue
            seen[key] = 1
            if len(seen) <= 12:
                print('%s @%d: %s' % (f, m.start(), ctx))
        if len(seen) > 12:
            print('%s: %d more distinct contexts' % (f, len(seen) - 12))
    print('-- %d occurrences of %s' % (found, version))


def scan(case, tag, script):
    # run the real scanner against the kept container and print what it identified
    outdir = os.path.join(OUT, case['name'], tag)
    port = int(open(os.path.join(outdir, 'port')).read())
    work = os.path.join(outdir, 'scan'); os.makedirs(work, exist_ok=True)
    for f in os.listdir(work):
        os.remove(os.path.join(work, f))
    sh('pwsh', '-NoProfile', '-File', script, '-Target', '127.0.0.1:%d' % port, '-NoProgress', '-Quiet', '-NoHtml', '-OutputDir', work, check=False)
    js = [f for f in os.listdir(work) if f.endswith('.jsonl')]
    rows = [json.loads(l) for f in js for l in open(os.path.join(work, f), encoding='utf-8-sig') if l.strip()]
    for r in rows:
        print('%s %s products=%r cpes=%r' % (r.get('Url'), r.get('StatusCode'), r.get('Products'), r.get('CPEs')))
    return rows


def stop(case):
    slug = case['name']
    names = sh('docker', 'ps', '-a', '--format', '{{.Names}}', check=False).split()
    for n in names:
        if n == 'vlab-' + slug or n.startswith('vlab-%s-' % slug):
            sh('docker', 'rm', '-f', n, check=False)
    sh('docker', 'network', 'rm', 'vlab-' + slug, check=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['run', 'grep', 'scan', 'stop'])
    ap.add_argument('--script', default=os.path.join(HERE, '..', '..', 'dist', 'Invoke-WebInventory.ps1'))
    ap.add_argument('--case', required=True); ap.add_argument('--tag', default='')
    ap.add_argument('--version'); ap.add_argument('--keep', action='store_true')
    ap.add_argument('--cases', default=os.path.join(HERE, 'cases.json'))
    a = ap.parse_args()
    cases = {c['name']: c for c in json.load(open(a.cases))}
    c = cases[a.case]
    if a.cmd == 'run':
        run(c, a.tag, a.keep)
        grep(c, a.tag, a.version)
    elif a.cmd == 'scan':
        scan(c, a.tag, a.script)
    elif a.cmd == 'stop':
        stop(c)
    else:
        grep(c, a.tag, a.version)


if __name__ == '__main__':
    main()
