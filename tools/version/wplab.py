#!/usr/bin/env python3
"""WordPress plugin lab: install plugins at known versions and record the ?ver= of their front-end assets.

usage: wplab.py --round latest|older [--plugins slug,slug,...] [--wp wordpress-image-tag]

WordPress (official image) and MariaDB run on a private docker network; plugin zips are downloaded from
downloads.wordpress.org on this host and copied in (the containers need no network access); WP-CLI installs WordPress
and activates them. The home page is then fetched like the scanner does and, for every plugin, each asset URL under
/wp-content/plugins/<slug>/ is listed with its ?ver= and whether that equals the installed plugin version or the
WordPress version (which WordPress appends when a plugin passes none). Results: out/wordpress/<round>.json
"""
import argparse, io, json, os, re, shutil, subprocess, sys, tempfile, time, urllib.request, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vlab

PLUGINS = ['elementor', 'essential-addons-for-elementor-lite', 'essential-blocks', 'brizy', 'bold-page-builder', 'jetpack',
           'litespeed-cache', 'otter-blocks', 'the-events-calendar', 'asgaros-forum', 'blocksy-companion', 'chaty',
           'pixelyoursite', 'coblocks', 'rafflepress', 'smart-slider-3', 'svg-support', 'creative-mail-by-constant-contact',
           'easy-accordion-free', 'ewww-image-optimizer', 'genesis-blocks', 'speedycache', 'elasticpress', 'better-wp-security',
           'jetpack-boost', 'wp-optimize', 'custom-fonts', 'ml-slider', 'gutenberg', 'nextgen-gallery', 'wp-fastest-cache',
           'woocommerce', 'woocommerce-gateway-stripe']


def versions(slug):
    u = 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=%s&request[fields][versions]=1' % slug
    d = json.load(urllib.request.urlopen(u, timeout=30))
    vs = [v for v in d.get('versions', {}) if re.match(r'^\d+(\.\d+)+$', v)]
    key = lambda v: [int(x) for x in v.split('.')]
    return d.get('version'), sorted(vs, key=key)


def pick(slug, rnd):
    latest, vs = versions(slug)
    if rnd == 'latest' or not vs:
        return latest
    # an older release: about a quarter of the way back through the published versions (at least 3 releases back)
    i = max(0, len(vs) - max(3, len(vs) // 4) - 1)
    return vs[i]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--round', default='latest'); ap.add_argument('--plugins', default=','.join(PLUGINS))
    ap.add_argument('--wp', default='php8.2-apache'); ap.add_argument('--keep', action='store_true')
    a = ap.parse_args()
    out = os.path.join(vlab.OUT, 'wordpress'); os.makedirs(out, exist_ok=True)
    net = 'vlab-wp'
    vlab.sh('docker', 'network', 'create', net, check=False)
    for n in ('vlab-wp-db', 'vlab-wp'):
        vlab.sh('docker', 'rm', '-f', n, check=False)
    port = vlab.free_port()
    env = ['-e', 'WORDPRESS_DB_HOST=db', '-e', 'WORDPRESS_DB_USER=wp', '-e', 'WORDPRESS_DB_PASSWORD=wp', '-e', 'WORDPRESS_DB_NAME=wp']
    try:
        vlab.sh('docker', 'run', '-d', '--name', 'vlab-wp-db', '--network', net, '--network-alias', 'db', '-e', 'MARIADB_ROOT_PASSWORD=root',
                '-e', 'MARIADB_DATABASE=wp', '-e', 'MARIADB_USER=wp', '-e', 'MARIADB_PASSWORD=wp', 'mariadb:11')
        time.sleep(15)
        vlab.sh('docker', 'run', '-d', '--name', 'vlab-wp', '--network', net, '-p', '127.0.0.1:%d:80' % port, *env, 'wordpress:' + a.wp)
        vlab.wait_http({'path': '/'}, port, time.time() + 120)
        cli = ['docker', 'run', '--rm', '--network', net, '--volumes-from', 'vlab-wp', '--user', '33:33', *env, 'wordpress:cli-php8.2', 'wp']
        for i in range(10):
            r = subprocess.run(cli + ['core', 'install', '--url=http://127.0.0.1:%d' % port, '--title=vlab', '--admin_user=vlabadmin',
                                      '--admin_password=Vlab-Passw0rd-1', '--admin_email=admin@example.com', '--skip-email'],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if r.returncode == 0:
                break
            time.sleep(6)
        print(r.stdout.strip()[-200:])
        wpver = subprocess.run(cli + ['core', 'version'], stdout=subprocess.PIPE, text=True).stdout.strip()
        installed = {}
        tmp = tempfile.mkdtemp()
        for slug in a.plugins.split(','):
            try:
                v = pick(slug, a.round)
                data = urllib.request.urlopen('https://downloads.wordpress.org/plugin/%s.%s.zip' % (slug, v), timeout=120).read()
                zipfile.ZipFile(io.BytesIO(data)).extractall(tmp)
                installed[slug] = v
            except Exception as e:
                print('download failed', slug, e)
        vlab.sh('docker', 'cp', tmp + '/.', 'vlab-wp:/var/www/html/wp-content/plugins/')
        vlab.sh('docker', 'exec', 'vlab-wp', 'chown', '-R', 'www-data:www-data', '/var/www/html/wp-content/plugins')
        shutil.rmtree(tmp)
        active = {}
        for slug in installed:
            # WP-CLI loads no other plugin (one of them may not run under the CLI); the site itself loads them all
            r = subprocess.run(cli + ['plugin', 'activate', slug, '--skip-plugins', '--skip-themes'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            ok = r.returncode == 0
            # a plugin that breaks the site (fatal error on every request) is switched off again, so the others still load
            try:
                st = vlab.fetch(False, port, '/', '127.0.0.1:%d' % port, timeout=30)[0]
            except Exception:
                st = 0
            if not ok or st >= 500 or st == 0:
                subprocess.run(cli + ['plugin', 'deactivate', slug, '--skip-plugins', '--skip-themes'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                print('activate failed', slug, 'status', st, r.stdout.strip()[-120:].replace('\n', ' '))
                ok = False
            active[slug] = ok
        # a page with blocks of the block plugins is not needed: assets that a plugin loads on every page are what counts
        rdir = os.path.join(out, a.round); os.makedirs(rdir, exist_ok=True)
        res = vlab.capture({'path': '/'}, port, rdir)
        open(os.path.join(rdir, 'port'), 'w').write(str(port))
        bodies = ''.join(open(os.path.join(rdir, f), encoding='utf-8', errors='replace').read() for f in os.listdir(rdir) if f.startswith('hop') and f.endswith('.body'))
        report = {'round': a.round, 'wordpress': wpver, 'plugins': {}}
        for slug, v in installed.items():
            urls = sorted(set(re.findall(r'/wp-content/plugins/%s/[^"\'\s<>]+' % re.escape(slug), bodies)))
            vers = [re.search(r'[?&]ver=([^&"\']+)', u) for u in urls]
            rows = [{'url': u, 'ver': m.group(1) if m else None, 'is_plugin': bool(m and m.group(1) == v), 'is_wp': bool(m and m.group(1) == wpver)}
                    for u, m in zip(urls, vers)]
            report['plugins'][slug] = {'version': v, 'active': active.get(slug), 'assets': rows}
            print('%-36s %-10s active=%s assets=%d plugin-ver=%d wp-ver=%d other=%s' % (
                slug, v, active.get(slug), len(rows), sum(r['is_plugin'] for r in rows), sum(r['is_wp'] for r in rows),
                sorted({r['ver'] for r in rows if r['ver'] and not r['is_plugin'] and not r['is_wp']})[:4]))
        json.dump(report, open(os.path.join(out, a.round + '.json'), 'w'), indent=1)
    finally:
        if not a.keep:
            for n in ('vlab-wp', 'vlab-wp-db'):
                vlab.sh('docker', 'rm', '-f', n, check=False)
            vlab.sh('docker', 'network', 'rm', net, check=False)


if __name__ == '__main__':
    main()
