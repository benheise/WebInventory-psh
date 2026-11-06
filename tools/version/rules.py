"""Reviewed version-only rules (input of gen_rules.py).

Each entry:
  id   rule id (v:<product>[:n])
  n    product name(s) exactly as a detection rule names them (kind t, default service); the generated rule carries the
       CPE product of each, so it joins whichever detection matched
  f/r/o  field, .NET regex, options (i = ignore case, s = dot-all, a = absolute anchors)
  v    version template ({1}, {name})
  ex/exv  a value of that field and the version it must yield (checked by -SelfTest / -TestRules): recorded from the
          container or lab for those classes, written from the published pattern for sample entries
  ev   evidence: where the value was seen (container image and tags, or the published sample it comes from)

Acceptance rules (see README.md): the value is the product's own release version as NVD numbers it (never a build
hash, protocol/API/component version, copyright year or cache-buster), it has at least major.minor, and it was seen
in a response the scanner already receives (GET / and its same-host redirects, the 404 probe, robots.txt,
security.txt, the favicon) or in a published sample of exactly that response.
"""
import re


def cdn(id, n, ex, exv, cdnjs=None, npm=None, extra=()):
    """A script loaded from a public CDN names the exact package version in its path (cdnjs, jsDelivr, unpkg, or the
    project's own CDN). Query strings (?v=...) are never used: they are cache-busters of the page, not the library."""
    alts = []
    if cdnjs:
        alts.append(r'cdnjs\.cloudflare\.com/ajax/libs/' + re.escape(cdnjs) + '/')
    if npm:
        alts += [r'cdn\.jsdelivr\.net/npm/' + re.escape(npm) + '@', r'unpkg\.com/' + re.escape(npm) + '@']
    alts += list(extra)
    r = r'(?:^|//)(?:' + '|'.join(alts) + r')(\d+\.\d+\.\d+)/'
    return dict(id=id, cls='library', n=n, f='scriptsrc', o='i', r=r, v='{1}', ex=ex, exv=exv,
                ev='CDN path version (exact package release); the example version exists on that CDN'
                   + (' (cdnjs: %s)' % cdnjs if cdnjs else '') + (' (npm: %s)' % npm if npm else ''))



def libfile(id, n, files, ex, exv):
    """A self-hosted copy that keeps the release in the library's own file name (lodash-4.17.21.min.js), the
    convention webappanalyzer relies on for jQuery and others. Only the library's own file stem is accepted."""
    return dict(id=id, cls='library', n=n, f='scriptsrc', o='i', v='{1}', ex=ex, exv=exv,
                r=r'(?:^|/)(?:' + '|'.join(re.escape(f) for f in files) + r')[.-](\d+\.\d+\.\d+)(?:[.-]min)?\.js(?:[?#]|$)',
                ev='release in the library file name (%s-x.y.z[.min].js)' % '/'.join(files))


ENTRIES = [
    # ---------------------------------------------------------------- verified against the product's own container
    dict(id='v:roundcube', cls='container', n='RoundCube', f='body',
         r=r'"rcversion":(?<a>[1-9]\d?)(?:0(?<b>\d)|(?<b>[1-9]\d))(?:0(?<c>\d)|(?<c>[1-9]\d))[,}]', v='{a}.{b}.{c}',
         ex='"locale":"en_US","devel_mode":null,"rcversion":10620,"cookie_domain":""', exv='1.6.20',
         ev='roundcube/roundcubemail 1.6.20-apache, 1.7.5-apache: login page rcmail.set_env({... "rcversion":10620 ...}); '
            'RCMAIL_VERSION_ID = major*10000 + minor*100 + patch (program/include/iniset.php)'),
    dict(id='v:solr', cls='container', n='Apache Solr', f='scriptsrc', r=r'^libs/angular\.min\.js\?_=(\d+\.\d+\.\d+)$', v='{1}',
         ex='libs/angular.min.js?_=9.4.1', exv='9.4.1',
         ev='solr 9.4.1, 10.1.0: / redirects to /solr/ (Admin UI); every script carries ?_=<solr version>'),
    dict(id='v:consul', cls='container', n='HashiCorp Consul', f='body', r=r'<!-- CONSUL_VERSION: (\d+\.\d+\.\d+)', v='{1}',
         ex='<!-- CONSUL_VERSION: 1.22.7\n -->', exv='1.22.7',
         ev='hashicorp/consul 1.22.7, 2.1.0: / redirects to /ui/, whose HTML carries <!-- CONSUL_VERSION: x.y.z -->'),
    dict(id='v:nextcloud', cls='container', n=['Nextcloud', 'Nextcloud Server'], f='body', r=r'"versionstring":"(\d+\.\d+\.\d+)"', v='{1}',
         ex='"sharing.minSearchStringLength":0,"version":"32.0.15.1","versionstring":"32.0.15","enable_non-accessible_features"',
         exv='32.0.15',
         ev='nextcloud 32.0.15-apache, 35.0.2-apache: / redirects to /login, whose oc_config JSON carries "versionstring"'),

    dict(id='v:spark', cls='container', n='Apache Spark', f='body', r=r'<span class="version"[^>]*>(\d+\.\d+\.\d+)</span>', v='{1}',
         ex='<img src="/static/spark-logo-77x50px-hd.png" />\n          <span class="version" style="margin-right: 15px;">3.5.9</span>', exv='3.5.9',
         ev='apache/spark 3.5.9, 4.1.4 (standalone master UI at /): header logo followed by <span class="version">'),
    dict(id='v:jupyterhub', cls='container', n='JupyterHub', f='header:x-jupyterhub-version', r=r'^(\d+\.\d+\.\d+)$', v='{1}',
         ex='5.5.4', exv='5.5.4', ev='quay.io/jupyterhub/jupyterhub 5.5.4, 6.1.1: X-JupyterHub-Version on every response (/, /hub/login, the 404)'),

    dict(id='v:xwiki-webjar', cls='container', n='XWiki', f='body', r=r'webjars\\?/wiki%3Axwiki\\?/xwiki-platform-[a-z-]+\\?/(\d+\.\d+(?:\.\d+)?)\\?/', v='{1}',
         ex='"xwiki-bootstrap":"\\/webjars\\/wiki%3Axwiki\\/xwiki-platform-bootstrap\\/16.10.19\\/js\\/xwiki-bootstrap.min.js?r=1"', exv='16.10.19',
         ev='xwiki 16.10.19, 18.4.8 (postgres-tomcat): the pages load the platform webjars from '
            '/webjars/wiki:xwiki/xwiki-platform-<module>/<platform version>/ in the RequireJS config and script tags  (platform modules are released together; XWiki numbers some releases major.minor, e.g. 15.10). Recorded on the first-run '
            'distribution wizard, where the webappanalyzer XWiki rules do not fire (they read <meta name=wiki content=xwiki> of a configured wiki)'),
    dict(id='v:xwiki-footer', cls='sample', n='XWiki', f='body', r=r'<div id="xwikiplatformversion">\s*(?:Powered by )?(?:XWiki (?:Enterprise )?)?(\d+\.\d+(?:\.\d+)?)\b', v='{1}',
         ex='<div id="xwikiplatformversion">XWiki 15.10.8</div>', exv='15.10.8',
         ev='WhatWeb xwiki (page footer <div id="xwikiplatformversion">)'),
    # WordPress plugins: official wordpress image + the plugin at two releases (wplab.py); only the asset files whose ?ver= was the
    # plugin's own release in both are read (others carry WordPress's version, a bundled library's, a hash or a timestamp)
    dict(id='v:wp-essential-addons', cls='wordpress', n='Essential Addons for Elementor', f='body',
         r=r'/wp-content/plugins/essential-addons-for-elementor-lite/assets/front-end/(?:css|js)/view/general\.min\.(?:css|js)\?ver=(\d+\.\d+\.\d+)', v='{1}',
         ex="<link rel='stylesheet' id='eael-general-css' href='https://www.example.org/wp-content/plugins/essential-addons-for-elementor-lite/assets/front-end/css/view/general.min.css?ver=6.0.4' media='all' />",
         exv='6.0.4', ev='wplab: 6.0.4 and 6.8.8, front-end general.min.css/js'),
    dict(id='v:wp-bold-page-builder', cls='wordpress', n='Bold Page Builder', f='body',
         r=r'/wp-content/plugins/bold-page-builder/(?:css/front_end/content_elements\.crush\.css|content_elements_misc/js/content_elements\.js)\?ver=(\d+\.\d+\.\d+)', v='{1}',
         ex="<script src=\"https://www.example.org/wp-content/plugins/bold-page-builder/content_elements_misc/js/content_elements.js?ver=5.9.6\" id=\"bt_bb_elements-js\"></script>",
         exv='5.9.6', ev='wplab: 5.9.6 and 5.9.11, content_elements.crush.css and content_elements.js'),
    dict(id='v:wp-pixelyoursite', cls='wordpress', n='PixelYourSite', f='body',
         r=r'/wp-content/plugins/pixelyoursite/dist/scripts/public\.js\?ver=(\d+\.\d+\.\d+(?:\.\d+)?)', v='{1}',
         ex="<script src=\"https://www.example.org/wp-content/plugins/pixelyoursite/dist/scripts/public.js?ver=10.0.4\" id=\"pys-js\"></script>",
         exv='10.0.4', ev='wplab: 10.0.4 and 11.4.5, dist/scripts/public.js (jquery.bind-first-*.js carried the WordPress version in 10.0.4)'),
    dict(id='v:wp-coblocks', cls='wordpress', n='GoDaddy CoBlocks', f='body',
         r=r'/wp-content/plugins/coblocks/dist/js/coblocks-animation\.js\?ver=(\d+\.\d+\.\d+)', v='{1}',
         ex="<script src=\"https://www.example.org/wp-content/plugins/coblocks/dist/js/coblocks-animation.js?ver=2.24.0\" id=\"coblocks-animation-js\"></script>",
         exv='2.24.0', ev='wplab: 2.24.0 and 3.1.17, dist/js/coblocks-animation.js (the bundled GoDaddy Styles CSS carries its own version)'),
    dict(id='v:wp-gutenberg', cls='wordpress', n='Gutenberg', f='body',
         r=r'/wp-content/plugins/gutenberg/build/(?:styles/)?components/style(?:\.min)?\.css\?ver=(\d+\.\d+\.\d+)', v='{1}',
         ex="<link rel='stylesheet' id='wp-components-css' href='https://www.example.org/wp-content/plugins/gutenberg/build/components/style.css?ver=18.4.0' media='all' />",
         exv='18.4.0', ev='wplab: 18.4.0 (build/components/style.css) and 24.3.1 (build/styles/components/style.min.css); block styles carry hashes'),
    dict(id='v:wp-events-calendar', cls='wordpress', n='The Events Calendar', f='body',
         r=r'/wp-content/plugins/the-events-calendar/build/css/tribe-events-[\w-]+\.css\?ver=(\d+\.\d+\.\d+(?:\.\d+)?)', v='{1}',
         ex="<link rel='stylesheet' id='tribe-events-v2-single-skeleton-css' href='https://www.example.org/wp-content/plugins/the-events-calendar/build/css/tribe-events-single-skeleton.css?ver=6.18.3.1' media='all' />",
         exv='6.18.3.1', ev='wplab: 6.18.3.1, build/css/tribe-events-*.css (6.3.2 loads nothing on a page without events; common/ assets carry hashes)'),
    # ---------------------------------------------------------------- verified in the product's page templates
    dict(id='v:bugzilla', cls='source', n='Mozilla Bugzilla', f='body', r=r'class="header_addl_info">version (\d+\.\d+(?:\.\d+)?)<', v='{1}',
         ex='<span id="information" class="header_addl_info">version 5.0.4</span>', exv='5.0.4',
         ev='bugzilla template/en/default/index.html.tmpl sets header_addl_info = "version $constants.BUGZILLA_VERSION"; '
            'global/header.html.tmpl prints it in <span class="header_addl_info"> (5.0, 5.2) or <p class="header_addl_info"> (4.4); '
            'development builds ("5.2+") are not matched'),
    dict(id='v:bludit', cls='source', n='Bludit', f='body', r=r'/bl-(?:kernel|themes)/[^"\'?]+\.(?:css|js)\?version=(\d+\.\d+\.\d+)["\']', v='{1}',
         ex='<link rel="stylesheet" href="/bl-kernel/css/bootstrap.min.css?version=3.14.1">', exv='3.14.1',
         ev='bludit bl-kernel/helpers/theme.class.php: every core and theme CSS/JS link gets ?version=BLUDIT_VERSION'),
    dict(id='v:weblate', cls='source', n='Weblate', f='body', r=r'Powered by <a href="https://weblate\.org/[^"]*">Weblate (\d+\.\d+(?:\.\d+)?)</a>', v='{1}',
         ex='Powered by <a href="https://weblate.org/">Weblate 5.8.4</a>', exv='5.8.4',
         ev='weblate templates/footer.html "Powered by {{ weblate_version_link }}"; trans/context_processors.py builds it as '
            '<a href="WEBLATE_URL">Weblate VERSION</a> unless the version is hidden'),
    dict(id='v:bookstack', cls='source', n='BookStack', f='body', r=r'/(?:dist/)?(?:app\.js|styles\.css|print-styles\.css)\?version=v(\d+\.\d+(?:\.\d+)?)["\']', v='{1}',
         ex='<link rel="stylesheet" href="https://wiki.example.org/dist/styles.css?version=v24.02.3">', exv='24.02.3',
         ev='bookstack app/App/helpers.php versioned_asset(): ?version= + AppVersion (the release tag, e.g. v24.02.3); '
            'development installs append a hash and are not matched'),
    dict(id='v:jspwiki', cls='source', n='Apache JSPWiki', f='body', r=r'<div class="wiki-version">JSPWiki v(\d+\.\d+\.\d+)(?![\w.-])', v='{1}',
         ex='<div class="wiki-version">JSPWiki v2.12.1\n', exv='2.12.1',
         ev='jspwiki templates/default/Footer.jsp: <div class="wiki-version"><%=Release.APPNAME%> v<%=Release.getVersionString()%>; '
            'milestone builds (-M7) are not matched'),
    dict(id='v:laravel', cls='source', n='Laravel', f='body', r=r'>\s*Laravel v(\d+\.\d+\.\d+) \(PHP v\d', v='{1}',
         ex='<div class="ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0">\n                        Laravel v10.48.2 (PHP v8.2.15)',
         exv='10.48.2',
         ev='laravel/laravel 10.x and 11.x resources/views/welcome.blade.php (the default home page): '
            'Laravel v{{ Application::VERSION }} (PHP v{{ PHP_VERSION }})'),
    dict(id='v:symfony', cls='source', n='Symfony', f='body',
         r=r'Welcome to</small> Symfony <span class="version">(\d+\.\d+\.\d+)</span>|You are using Symfony <strong>(\d+\.\d+\.\d+)</strong> version',
         v='{1}{2}', ex='<h1><small>Welcome to</small> Symfony <span class="version">6.4.3</span></h1>', exv='6.4.3',
         ev='symfony HttpKernel/Resources/welcome.html.php (the page shown while no homepage route exists): 5.4/6.4 '
            '"Welcome to Symfony <span class=version>", 7.x "You are using Symfony <strong>x.y.z</strong> version"'),
    dict(id='v:cakephp', cls='source', n='CakePHP', f='body', r=r'Welcome to CakePHP (\d+\.\d+\.\d+)', v='{1}',
         ex='<h1>\n                Welcome to CakePHP 5.0.1 Chiffon (🍰)\n', exv='5.0.1',
         ev='cakephp/app templates/Pages/home.php (the default home page): Welcome to CakePHP <?= Configure::version() ?>'),
    dict(id='v:rails', cls='source', n='Ruby on Rails', f='title', r=r'^Ruby on Rails (\d+\.\d+\.\d+(?:\.\d+)?)$', v='{1}',
         ex='Ruby on Rails 7.1.2', exv='7.1.2',
         ev='rails railties/lib/rails/templates/rails/welcome/index.html.erb (the default home page): <title>Ruby on Rails <%= Rails.version %></title>'),
    dict(id='v:piwigo', cls='source', n='Piwigo', f='scriptsrc', r=r'themes/default/js/jquery\.min\.js\?v(\d+\.\d+\.\d+)$', v='{1}',
         ex='themes/default/js/jquery.min.js?v14.5.0', exv='14.5.0',
         ev='piwigo include/template.class.php: scripts without their own version get ?v . PHPWG_VERSION; the core jQuery '
            'is declared without one (combine_script id=jquery path=themes/default/js/jquery.min.js); beta builds are not matched'),
    dict(id='v:proxmox-ve', cls='source', n='Proxmox Virtual Environment', f='body', r=r'/pve2/css/ext6-pve\.css\?ver=(\d+)\.(\d+)(?:[.-]\d+)*"', v='{1}.{2}',
         ex='<link rel="stylesheet" type="text/css" href="/pve2/css/ext6-pve.css?ver=8.1.4" />', exv='8.1',
         ev='pve-manager www/index.html.tpl (the page at /): ext6-pve.css?ver=[% version %] = PVE::pvecfg::version() (8.1.4 = PVE 8.1); '
            'NVD names Proxmox VE releases major.minor (7.4, 8.0); the ExtJS assets (?ver=7.0.0) are not matched'),
    dict(id='v:openfire', cls='source', n='Ignite Realtime OpenFire', f='body', r=r'id="jive-loginVersion">\s*Openfire, [^:<]{1,30}: (\d+\.\d+\.\d+)', v='{1}',
         ex='<div class="text" id="jive-loginVersion"> Openfire, Version: 4.7.5</div>', exv='4.7.5',
         ev='openfire xmppserver/src/main/webapp/login.jsp (the admin console redirects to it): '
            '<div id="jive-loginVersion"> AppName, <fmt:message key="login.version"/>: getVersionString()'),
    dict(id='v:k8s-version', cls='source', n='Kubernetes API', f='path:/version.body', r=r'"gitVersion"\s*:\s*"v(\d+\.\d+\.\d+)', v='{1}',
         ex='{\n  "major": "1",\n  "minor": "28",\n  "gitVersion": "v1.28.3",\n  "gitCommit": "a8a1abc25cad87333840cd7d54be2efaf31a3177",', exv='1.28.3',
         ev='-IdentifyPaths only: GET /version on a Kubernetes API server returns version.Info JSON (k8s.io/apimachinery/pkg/version); '
            'gitVersion is the release (v1.28.3); vendor suffixes (+k3s1, -eks-...) follow the three numbers and are not captured'),

    dict(id='v:mastodon', cls='source', n='Mastodon', f='body', r=r'<script id="initial-state" type="application/json">\{"meta":\{[^<]{0,20000}?"version":"(\d+\.\d+\.\d+)(?=["+])', v='{1}',
         ex='<script id="initial-state" type="application/json">{"meta":{"access_token":null,"activity_api_enabled":true,"admin":null,"domain":"social.example.org","trends_enabled":true,"version":"4.3.1"}}</script>',
         exv='4.3.1',
         ev='mastodon app/helpers/application_helper.rb render_initial_state (<script id="initial-state" type="application/json">) with '
            'app/serializers/initial_state_serializer.rb meta.version = Mastodon::Version (pre-releases "-beta.1" are not matched, build metadata "+..." is)'),

    dict(id='v:mattermost', cls='container', n='Mattermost', f='header:x-version-id', r=r'^(\d+\.\d+\.\d+)\.', v='{1}',
         ex='10.11.26.41049445879.40550bdafb186783981245c23d63fd90.false', exv='10.11.26',
         ev='mattermost/mattermost-preview 10.11.26, 12.1.0: X-Version-Id: <version>.<build>.<config hash>.<licensed> on GET / and every other '
            'response (server/channels/web/handlers.go); nuclei-templates mattermost-panel reads it from /login'),

    dict(id='v:metabase', cls='container', n='Metabase', f='body', r=r'"version":\{[^{}]{0,300}?"tag":"v(\d+\.\d+\.\d+(?:\.\d+)?)"', v='{1}',
         ex='<script type="application/json" id="_metabaseBootstrap">\n      {"version":{"date":"2023-11-01","tag":"v0.47.6","branch":"release-x.47.x","hash":"c6b9de1"},"site-name":"Metabase"}',
         exv='0.47.6',
         ev='metabase/metabase v0.58.39, v0.65.3: GET / (the app page, also before login) embeds the public settings as _metabaseBootstrap JSON '
            'with "version":{"date":...,"tag":"v0.65.3",...} (resources/frontend_client/index_template.html; the setting is :visibility :public); '
            'tag v0.x = OSS, v1.x = Enterprise, as NVD numbers them; the block sat 106 KB into the 0.58 page, inside the 128 KB a rule reads'),

    dict(id='v:pgadmin', cls='container', n='pgAdmin', f='body', r=r'\.(?:css|js)\?ver=(?<a>[1-9]\d?)(?:0(?<b>\d)|(?<b>[1-9]\d))00["\']', v='{a}.{b}',
         ex='<link type="text/css" rel="stylesheet" href="/static/js/generated/style.css?ver=91900"/>', exv='9.19',
         ev='dpage/pgadmin4 9.8, 9.19: / redirects to /login, whose stylesheets and scripts carry ?ver=90800 / 91900; '
            'web/version.py APP_VERSION_INT = release*10000 + revision*100, appended as ?ver= (config.py APP_VERSION_PARAM); '
            'NVD numbers pgAdmin 4 releases major.minor'),

    dict(id='v:kibana', cls='source', n='Elastic Kibana', f='body', r=r'<kbn-injected-metadata data="\{&quot;version&quot;:&quot;(\d+\.\d+\.\d+)&quot;', v='{1}',
         ex='<kbn-injected-metadata data="{&quot;version&quot;:&quot;8.19.6&quot;,&quot;buildNumber&quot;:86547,&quot;branch&quot;:&quot;8.19&quot;', exv='8.19.6',
         ev='kibana src/core/packages/rendering/server-internal: rendering_service.tsx injectedMetadata = {version: env.packageInfo.version, ...}, '
            'views/template.tsx renders it as <kbn-injected-metadata data="JSON"> on every page, the login page included'),

    dict(id='v:forgejo', cls='container', n='Forgejo', f='scriptsrc', r=r'(?:^|/)assets/js/(?:index|webcomponents)\.js\?v=(\d+\.\d+\.\d+(?:-\d+)?)(?:~gitea-\d+(?:\.\d+)*)?$', v='{1}',
         ex='/assets/js/index.js?v=9.0.3~gitea-1.22.0', exv='9.0.3',
         ev='codeberg.org/forgejo/forgejo 9.0.3, 17.0.1: every page loads /assets/js/index.js?v=<AssetVersion> (AppVer with + as ~); '
            'the footer shows it too unless SHOW_FOOTER_VERSION = false, the asset URL always'),
    dict(id='v:forgejo-footer', cls='container', n='Forgejo', f='body', r=r'>Powered by Forgejo</a>\s*Version:\s*(\d+\.\d+\.\d+(?:-\d+)?)(?:&#43;gitea-[\d.]+)?\s', v='{1}',
         ex='<a target="_blank" rel="noopener noreferrer" href="https://forgejo.org">Powered by Forgejo</a>\n\t\t\n\t\t\n\t\t\tVersion:\n\t\t\t\n\t\t\t\t9.0.3&#43;gitea-1.22.0\n\t\t\t\n',
         exv='9.0.3', ev='codeberg.org/forgejo/forgejo 9.0.3, 17.0.1: page footer "Powered by Forgejo ... Version: <AppVer>" (default SHOW_FOOTER_VERSION = true)'),

    dict(id='v:teamcity-maintenance', cls='container', n='JetBrains TeamCity', f='body', r=r'<div id="footer2">\s*TeamCity (\d{4}\.\d{1,2}(?:\.\d+)?) \(build \d+\)', v='{1}',
         ex='      <div id="footer2">\n        TeamCity 2025.11.8 (build 208382)\n      </div>', exv='2025.11.8',
         ev='jetbrains/teamcity-server 2025.11.8, 2026.2.2: the maintenance page (first start, upgrade; HTTP 503 at /) shows the running release in its footer'),

    dict(id='v:checkmk', cls='container', n='Checkmk', f='scriptsrc', r=r'(?:^|/)js/main_min\.js\?v=(\d+\.\d+\.\d+(?:p\d+)?)(?:\.c[a-z]e)?$', v='{1}',
         ex='js/main_min.js?v=2.4.0p39', exv='2.4.0p39',
         ev='checkmk/check-mk-raw 2.3.0p38, 2.4.0p39: / redirects to /<site>/, then check_mk/ and login.py (three same-host hops), which loads js/main_min.js?v=<version>; '
            'NVD numbers Checkmk as version 2.4.0 + update p39, which the vulnerability join compares as 2.4.0p39; betas (2.5.0b1) are not matched'),

    dict(id='v:gitea-footer', cls='container', n='Gitea', f='body', force=True,
         r=r'>Powered by Gitea</a>\s*(?:<span>\s*)?Version:\s*(\d+\.\d+\.\d+)\s', v='{1}',
         ex='<a target="_blank" href="https://about.gitea.com">Powered by Gitea</a>\n\t\t\n\t\t\n\t\t\t<span>\n\t\t\tVersion:\n\t\t\t\n\t\t\t\t1.27.3\n\t\t\t\n\t\t\t</span>',
         exv='1.27.3',
         ev='gitea/gitea 1.22.3, 1.27.3: page footer "Powered by Gitea ... Version: <AppVer>" for anonymous visitors (default SHOW_FOOTER_VERSION = true); '
            'the webappanalyzer Gitea pattern ("(c) Gitea Version:") predates this footer, so its captured version still wins where it matches; '
            'development builds (1.28.0+dev-...) are not matched'),

    dict(id='v:gitea-asset', cls='container', n='Gitea', f='scriptsrc', force=True,
         r=r'(?:^|/)assets/js/(?:index|webcomponents)\.js\?v=(\d+\.\d+\.\d+)$', v='{1}',
         ex='/assets/js/index.js?v=1.22.3', exv='1.22.3',
         ev='gitea/gitea 1.22.3: every page loads /assets/js/index.js?v=<AppVer> (also with SHOW_FOOTER_VERSION = false); 1.27.3 uses '
            'hashed file names instead. Forgejo, which Gitea rules also detect through the i_like_gitea cookie, appends ~gitea-<base>, '
            'which this pattern does not accept'),

    dict(id='v:n8n', cls='container', n='n8n', f='meta:n8n:config:sentry', o='b', r=r'"release"\s*:\s*"n8n@(\d+\.\d+\.\d+)"', v='{1}',
         ex='eyJkc24iOiIiLCJlbnZpcm9ubWVudCI6ImRldmVsb3BtZW50IiwicmVsZWFzZSI6Im44bkAyLjQ3LjIifQ==', exv='2.47.2',
         ev='docker.n8n.io/n8nio/n8n 2.47.2, 1.123.92: the editor page (/) carries <meta name="n8n:config:sentry" content="<base64 JSON>"> '
            'with "release":"n8n@<version>" (nuclei-templates n8n-panel decodes the same tag); o=b matches the decoded text'),

    # ---------------------------------------------------------------- published samples of the same response
    dict(id='v:exchange2007-imap', cls='sample', n='Microsoft Exchange 2007 Server', f='banner.imap', r=r'^Microsoft Exchange Server (2007) IMAP4 service ready', v='{1}',
         ex='Microsoft Exchange Server 2007 IMAP4 service ready', exv='2007',
         ev='Recog imap_banners example; NVD versions Exchange Server by release (cpe:2.3:a:microsoft:exchange_server:2007:sp3), so the release year is the version'),
    dict(id='v:exchange2007-pop3', cls='sample', n='Microsoft Exchange 2007 Server', f='banner.pop3', r=r'^Microsoft Exchange Server (2007) POP3 service ready', v='{1}',
         ex='Microsoft Exchange Server 2007 POP3 service ready', exv='2007',
         ev='Recog pop_banners example; see v:exchange2007-imap'),
    dict(id='v:prtg-server', cls='sample', n='PRTG Network Monitor', f='header:server', r=r'^PRTG/(\d+\.\d+\.\d+\.\d+)$', v='{1}',
         ex='PRTG/23.4.90.1299', exv='23.4.90.1299',
         ev='WhatWeb prtg-network-monitor (Server: PRTG/<version>); NVD numbers PRTG releases the same way (22.2.77.2204)'),
    dict(id='v:prtg-css', cls='sample', n='PRTG Network Monitor', f='body', r=r'/css/prtgmini\.css\?prtgversion=(\d+\.\d+\.\d+\.\d+)', v='{1}',
         ex='<link rel="stylesheet" type="text/css" href="/css/prtgmini.css?prtgversion=23.4.90.1299" media="print,screen,projection" />',
         exv='23.4.90.1299', ev='WhatWeb prtg-network-monitor (login page stylesheet ?prtgversion=)'),
    dict(id='v:zope', cls='sample', n='Zope', f='header:server', r=r'^Zope/\((?:Zope )?(\d+\.\d+\.\d+)', v='{1}',
         ex='Zope/(Zope 2.10.6-final, python 2.4.5, linux2) ZServer/1.1', exv='2.10.6',
         ev='WhatWeb zope (Server: Zope/(<version>, python ..., <platform>) ZServer/1.1; 2.10 adds "Zope " and "-final")'),
    dict(id='v:wingftp', cls='sample', n='Wing FTP Server', f='header:server', r=r'^Wing FTP Server/(\d+\.\d+\.\d+)', v='{1}',
         ex='Wing FTP Server/6.4.4(XXX Corp)', exv='6.4.4', ev='WhatWeb wing-ftp-server (Server: Wing FTP Server/<version>(<company>))'),
    dict(id='v:sawmill', cls='sample', n='Sawmill', f='header:server', r=r'^Sawmill/(\d+\.\d+(?:\.\d+)+)', v='{1}',
         ex='Sawmill/8.7.9.4', exv='8.7.9.4', ev='WhatWeb sawmill (Server: Sawmill/<version>)'),
    dict(id='v:oam-footer', cls='sample', n='Oracle Access Manager', f='body', r=r'<p id="footerVersion">Oracle Access Manager Version: (\d+\.\d+\.\d+(?:\.\d+)*)</p>', v='{1}',
         ex='<p id="footerVersion">Oracle Access Manager Version: 10.1.4.3</p>', exv='10.1.4.3',
         ev='WhatWeb oracle-access-manager (10g login page footer)'),
    dict(id='v:lansweeper', cls='sample', n='Lansweeper', f='body', r=r'"/js/CustomControls\.js\?(\d+\.\d+\.\d+(?:\.\d+)?)"', v='{1}',
         ex='<script src="/js/CustomControls.js?10.4.1.2" type="text/javascript"></script>', exv='10.4.1.2',
         ev='nuclei-templates lansweeper-login (login.aspx, where / redirects): CustomControls.js?<version>'),
    dict(id='v:chevereto', cls='sample', n='Chevereto', f='meta:generator', r=r'^Chevereto (\d+\.\d+\.\d+)', v='{1}',
         ex='Chevereto 4.0.6', exv='4.0.6',
         ev='the webappanalyzer Chevereto rule only matches a generator with a version (Chevereto followed by digits); nuclei-templates chevereto-detect'),
    dict(id='v:a-blog', cls='sample', n='a-blog cms', f='meta:generator', r=r'^a-blog cms (?:Ver\.|v)?(\d+\.\d+\.\d+)', v='{1}',
         ex='a-blog cms Ver.3.1.12', exv='3.1.12', ev='nuclei-templates a-blog-cms-detect (generator "a-blog cms Ver.x.y.z")'),
    dict(id='v:smartstore', cls='sample', n='Smartstore biz', f='meta:generator', r=r'^Smartstore (\d+\.\d+\.\d+)', v='{1}',
         ex='Smartstore 5.1.0', exv='5.1.0', ev='nuclei-templates smartstore-detect (<meta name="generator" content="Smartstore x.y.z" />)'),
    dict(id='v:dokuwiki', cls='sample', n='Dokuwiki', f='meta:generator', r=r'^DokuWiki Release (\d{4}-\d{2}-\d{2}[a-z]?)', v='{1}',
         ex='DokuWiki Release 2009-12-25c', exv='2009-12-25c',
         ev='WhatWeb dokuwiki (generator "DokuWiki Release <date>", older releases; current ones say "DokuWiki"); '
            'NVD names DokuWiki releases by date (cpe:2.3:a:dokuwiki:dokuwiki:2009-12-25)'),
    dict(id='v:movabletype', cls='sample', n='Movable Type', f='meta:generator', r=r'^Movable Type(?: Pro| Advanced| Enterprise| Open Source)? (\d+\.\d+(?:\.\d+)?)', v='{1}',
         ex='Movable Type Pro 6.3.2', exv='6.3.2', ev='WhatWeb movable_type (generator "Movable Type <edition> <version>")'),
    dict(id='v:cmsms', cls='sample', n='CMS Made Simple', f='body', o='i', r=r'powered by <a[^>]{0,200}>CMS Made Simple</a> version (\d+\.\d+(?:\.\d+)*)', v='{1}',
         ex='This site is powered by <a href="http://www.cmsmadesimple.org">CMS Made Simple</a> version 1.11.13', exv='1.11.13',
         ev='WhatWeb cms-made-simple ("Powered by" footer of the default templates)'),
    dict(id='v:rundeck', cls='sample', n='Rundeck', f='body', r=r'data-version-string="(\d+\.\d+\.\d+)', v='{1}',
         ex='<div class="rundeck-version-block" data-version-string="4.17.0-20230925" data-version-date="2023-09-25"', exv='4.17.0',
         ev='nuclei-templates rundeck-login (/user/login, where / redirects): data-version-string="<version>-<date>"'),
    dict(id='v:moodle-footer', cls='sample', n='Moodle', f='body', r=r'<a title="Moodle (\d+\.\d+(?:\.\d+)?)[ +(]', v='{1}',
         ex='<a title="Moodle 2.2.3+ (Build: 20120615)" href="http://moodle.org/">', exv='2.2.3',
         ev='WhatWeb moodle (footer logo link of Moodle 1.9-2.x: title="Moodle <release> (Build: <date>)"; current releases print no version)'),
    dict(id='v:opencart-footer', cls='sample', n='OpenCart', f='body', r=r'OpenCart Version (\d+\.\d+\.\d+(?:\.\d+)?)<', v='{1}',
         ex='All Rights Reserved.<br />OpenCart Version 1.5.6.4</div>', exv='1.5.6.4', ev='WhatWeb opencart (footer of 1.x default theme)'),
    dict(id='v:opencms-generator', cls='sample', n='OpenCms', f='meta:generator', o='i', r=r'^OpenCms version (\d+\.\d+\.\d+)', v='{1}',
         ex='Opencms version 7.5.2', exv='7.5.2', ev='WhatWeb opencms (<meta name="generator" content="Opencms version x.y.z">)'),
    dict(id='v:cubecart-footer', cls='sample', n='CubeCart', f='body', r=r'Powered by CubeCart version (\d+\.\d+\.\d+)', v='{1}',
         ex='<p class="defaultText">Powered by CubeCart version 4.4.3<br />', exv='4.4.3', ev='WhatWeb cubecart (footer)'),
    dict(id='v:dokeos-footer', cls='sample', n='Dokeos', f='body', r=r'href="http://www\.dokeos\.com" target="_blank">\s*Dokeos (\d+\.\d+(?:\.\d+)?)</a>', v='{1}',
         ex='<div class="copyright">Platform <a href="http://www.dokeos.com" target="_blank"> Dokeos 2.1.1</a>', exv='2.1.1', ev='WhatWeb dokeos (footer)'),
    dict(id='v:wolfcms-footer', cls='sample', n='Wolf CMS', f='body', r=r'\.png" /> Wolf CMS (\d+\.\d+\.\d+)</div>', v='{1}',
         ex='<img src="/wolf/admin/images/wolf.png" /> Wolf CMS 0.7.8</div>', exv='0.7.8', ev='WhatWeb wolfcms (backend footer)'),
    dict(id='v:openx-generator', cls='sample', n='OpenX', f='meta:generator', r=r'^OpenX v(\d+\.\d+\.\d+)', v='{1}',
         ex='OpenX v2.8.7 - http://www.openx.org', exv='2.8.7', ev='WhatWeb openx (<meta name="generator" content="OpenX v<version> - http://www.openx.org">)'),
    dict(id='v:fluxbb-footer', cls='sample', n='FluxBB', f='body', r=r'>P(?:owered by|ropuls&#233; par) <a href="http://fluxbb\.org/">FluxBB</a> (\d+\.\d+\.\d+)<', v='{1}',
         ex='<p id="poweredby">Powered by <a href="http://fluxbb.org/">FluxBB</a> 1.5.10</p>', exv='1.5.10', ev='WhatWeb fluxbb (footer; English and French)'),
    dict(id='v:statusnet-footer', cls='sample', n='status.net', f='body', r=r'powered by <a href="http://status\.net/">StatusNet</a> version (\d+\.\d+\.\d+)', o='i', v='{1}',
         ex='<p>This site is powered by <a href="http://status.net/">StatusNet</a> version 0.9.9, available under', exv='0.9.9',
         ev='WhatWeb statusnet (footer)'),
    dict(id='v:luci-footer', cls='sample', n='OpenWrt LuCI', f='body', r=r'<a href="/cgi-bin/luci/about">Powered by LuCI (?:(\d+\.\d+\.\d+)</a>|[^<]{1,60} \(v(\d+\.\d+\.\d+)\)</a>)', v='{1}{2}',
         ex='<p class="luci"><a href="/cgi-bin/luci/about">Powered by LuCI 0.11 Branch (v0.11.1)</a></p>', exv='0.11.1',
         ev='WhatWeb luci (footer of LuCI 0.x; current builds print a git branch, which is not matched)'),

    dict(id='v:splunk', cls='sample', n=['Splunk', 'Splunkd'], f='body', r=r'"VERSION_LABEL"\s*:\s*"(\d+\.\d+\.\d+(?:\.\d+)?)"', v='{1}',
         ex='"BUILD_NUMBER": 1234567, "BUILD_PUSH_NUMBER": 0, "VERSION_LABEL": "9.1.2", "LOCALE": "en-US"', exv='9.1.2',
         ev='nuclei-templates splunk-enterprise-panel (/en-US/account/login, where / redirects: $C config with VERSION_LABEL); '
            'container splunk/splunk 9.4.17: that login page carries no version (only a staticAssetId hash), so the rule reads only the releases that still embed it'),

    dict(id='v:wazuh', cls='sample', n='Wazuh', f='body', r=r'&quot;wazuhVersion&quot;:&quot;(\d+\.\d+\.\d+)&quot;', v='{1}',
         ex='&quot;wazuhVersion&quot;:&quot;4.7.2&quot;,&quot;revision&quot;:&quot;40722&quot;', exv='4.7.2',
         ev='nuclei-templates wazuh-panel (/app/login, where / redirects: injected metadata); only wazuhVersion is used, '
            'since "version" there is the OpenSearch Dashboards release'),
    dict(id='v:superset', cls='sample', n='Apache Superset', f='body', r=r'&#34;version_string&#34;:\s*&#34;(\d+\.\d+\.\d+)&#34;', v='{1}',
         ex='&#34;version_string&#34;: &#34;2.1.0&#34;, &#34;version_sha&#34;: &#34;e5d5b4a&#34;', exv='2.1.0',
         ev='nuclei-templates superset-login (/login/, where / redirects: data-bootstrap common.menu_data.navbar_right.version_string); '
            'release candidates (2.1.0rc1) are not matched'),
    dict(id='v:plesk-onyx', cls='sample', n='Plesk', f='body', r=r'alt="Plesk Onyx (\d+\.\d+\.\d+)"', v='{1}',
         ex='<img src="/images/logos/plesk/plesk-onyx-login.png" alt="Plesk Onyx 17.8.11" />', exv='17.8.11',
         ev='nuclei-templates plesk-onyx-login (/login_up.php, where / redirects; Plesk Onyx 17.x only)'),
    dict(id='v:snews', cls='sample', n='sNews', f='meta:generator', r=r'^sNews (\d+\.\d+(?:\.\d+)?)$', v='{1}',
         ex='sNews 1.7.1', exv='1.7.1', ev='WhatWeb snews (<meta name="Generator" content="sNews x.y">); NVD names sNews releases 1.6, 1.7.1'),

    dict(id='v:teamcity', cls='sample', n='JetBrains TeamCity', f='body', r=r'Version</span> (\d{4}\.\d{1,2}(?:\.\d+)?) \(build \d+\)', v='{1}',
         ex='<span class="greyNote version"><span class="vers">Version</span> 2023.05.3 (build 129390)</span>', exv='2023.05.3',
         ev='nuclei-templates teamcity-login-panel (/login.html, where / redirects): "Version</span> <release> (build <n>)"'),
    dict(id='v:citrix-hypervisor', cls='sample', n='Citrix Hypervisor', f='body', r=r'Welcome to Citrix Hypervisor (\d+\.\d+(?:\.\d+)?)\b', v='{1}',
         ex='<h1>Welcome to Citrix Hypervisor 8.2.1</h1>', exv='8.2.1', ev='nuclei-templates citrix-hypervisor-page (the host welcome page at /)'),
    dict(id='v:play1', cls='sample', n='Play', f='header:server', r=r'^Play! Framework;(\d+\.\d+(?:\.\d+)*);', v='{1}',
         ex='Play! Framework;1.2.4;prod', exv='1.2.4', ev='WhatWeb play-framework (Server: Play! Framework;<version>;<mode>, Play 1.x)'),

    dict(id='v:hotaru', cls='sample', n='Hotaru CMS', f='meta:generator', r=r'^Hotaru CMS (\d+\.\d+(?:\.\d+)*)$', v='{1}',
         ex='Hotaru CMS 1.4.2', exv='1.4.2', ev='WhatWeb hotaru-cms (<meta name="generator" content="Hotaru CMS x.y.z" />)'),

    dict(id='v:ipb', cls='sample', n='Invision Power Board', f='body', r=r'>Invision Power Board</a>(?:\(U\))?\s*v(\d+\.\d+\.\d+(?:\.\d+)?) &copy; 20\d\d', v='{1}',
         ex='Powered by <a href="http://www.invisionboard.com" title="Invision Power Board" target="_blank">Invision Power Board</a>(U) v2.3.6 &copy; 2008 &nbsp;',
         exv='2.3.6', ev='WhatWeb invision-power-board ("powered by 3": Invision Power Board</a> v<version> &copy; <year>, 2.x footer)'),
    dict(id='v:ipb-ips', cls='sample', n='Invision Power Board', f='body', r=r'\bv?(\d+\.\d+\.\d+(?:\.\d+)?) &copy; 20\d\d &nbsp;<a href=\'http://www\.invisionpower\.com\'', v='{1}',
         ex='v2.1.7 &copy; 2006 &nbsp;<a href=\'http://www.invisionpower.com\' style=\'text-decoration:none\' target=\'_blank\'>IPS, Inc.</a>', exv='2.1.7',
         ev='WhatWeb invision-power-board ("powered by 2": <version> &copy; <year> &nbsp;<a href=\'http://www.invisionpower.com\'>IPS)'),
    dict(id='v:esyndicat-generator', cls='sample', n='eSyndiCat', f='meta:generator', r=r'^eSyndiCat Web Directory Software (\d+\.\d+(?:\.\d+)*)$', v='{1}',
         ex='eSyndiCat Web Directory Software 2.2', exv='2.2',
         ev='WhatWeb esyndicat (<meta name="generator" content="eSyndiCat Web Directory Software x.y" />); NVD names releases 2.2, 2.3'),
    dict(id='v:esyndicat-footer', cls='sample', n='eSyndiCat', f='body',
         r=r'Powered by <a href="http://www\.esyndicat\.com/">eSyndiCat(?: Pro v(?<ver>\d+\.\d+(?:\.\d+)*)</a>| ?</a> Version (?<ver>\d+\.\d+(?:\.\d+)*))<br', v='{ver}',
         ex='Powered by <a href="http://www.esyndicat.com/">eSyndiCat Pro v2.3</a><br />', exv='2.3',
         ev='WhatWeb esyndicat (footer "eSyndiCat Pro v<version>" or "eSyndiCat</a> Version <version>")'),
    dict(id='v:guppy', cls='sample', n='GuppY', f='body',
         r=r'(?:Site powered by GuppY v(?<ver>\d+\.\d+(?:\.\d+)*) </a>|<!--\[\s+GuppY v(?<ver>\d+\.\d+(?:\.\d+)*) CeCILL Copyright)', v='{ver}',
         ex='<!--[  GuppY v4.5.18 CeCILL Copyright (C) 2004-2009 by Laurent Duveau - http://www.freeguppy.org/  ]-->', exv='4.5.18',
         ev='WhatWeb guppy (footer "Site powered by GuppY v<version>" and the page comment "GuppY v<version> CeCILL Copyright")'),
    dict(id='v:edirectory', cls='sample', n='eDirectory', f='body',
         r=r'<blockquote class="eDirectoryVersion"><span class="basePowered">Powered by <a href="[^"]*" target="_blank">eDirectory&trade;</a> </span> v\.(\d+\.\d+(?:\.\d+)*)</blockquote>', v='{1}',
         ex='<blockquote class="eDirectoryVersion"><span class="basePowered">Powered by <a href="http://www.edirectory.com" target="_blank">eDirectory&trade;</a> </span> v.10.4</blockquote>',
         exv='10.4', ev='WhatWeb edirectory (footer <blockquote class="eDirectoryVersion"> ... v.<version>)'),
    dict(id='v:uportal', cls='sample', n='uPortal', f='body', r=r'(?:alt="Powered by uPortal (?<ver>\d+\.\d+(?:\.\d+)*)"|>Powered by uPortal (?<ver>\d+\.\d+(?:\.\d+)*)</a>)', v='{ver}',
         ex='<img src="media/skins/universality/uportal3/images/portal_logo.png" alt="Powered by uPortal 3.2.4" />', exv='3.2.4',
         ev='WhatWeb uportal (logo alt text or footer link "Powered by uPortal <version>")'),
    dict(id='v:uportal-header', cls='sample', n='uPortal', f='header:uportal-version', r=r'^uPortal_rel-(\d+)-(\d+)-(\d+)\b', v='{1}.{2}.{3}', o='i',
         ex='uPortal_rel-3-2-4', exv='3.2.4', ev='WhatWeb uportal (uPortal-Version: uPortal_rel-<major>-<minor>-<patch> header)'),

    # ---------------------------------------------------------------- JavaScript libraries loaded from a public CDN
    cdn('v:cdn-tinymce', 'TinyMCE', 'https://cdnjs.cloudflare.com/ajax/libs/tinymce/5.10.9/tinymce.min.js', '5.10.9', cdnjs='tinymce', npm='tinymce'),
    cdn('v:cdn-jspdf', 'jsPDF', 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js', '2.5.1', cdnjs='jspdf', npm='jspdf'),
    cdn('v:cdn-yui', 'YUI', 'https://yui.yahooapis.com/3.18.1/build/yui/yui-min.js', '3.18.1', cdnjs='yui', npm='yui', extra=[r'yui\.yahooapis\.com/']),
    cdn('v:cdn-marked', 'Marked', 'https://cdn.jsdelivr.net/npm/marked@4.3.0/marked.min.js', '4.3.0', cdnjs='marked', npm='marked'),
    cdn('v:cdn-lodash', 'Lodash', 'https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js', '4.17.21', cdnjs='lodash.js', npm='lodash'),
    cdn('v:cdn-mermaid', 'Mermaid', 'https://cdn.jsdelivr.net/npm/mermaid@10.6.1/dist/mermaid.min.js', '10.6.1', cdnjs='mermaid', npm='mermaid'),
    cdn('v:cdn-swiper', 'Swiper', 'https://cdnjs.cloudflare.com/ajax/libs/Swiper/8.4.7/swiper-bundle.min.js', '8.4.7', cdnjs='Swiper', npm='swiper'),
    cdn('v:cdn-moment', 'Moment.js', 'https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.4/moment.min.js', '2.29.4', cdnjs='moment.js', npm='moment'),
    cdn('v:cdn-mathjs', 'math.js', 'https://cdnjs.cloudflare.com/ajax/libs/mathjs/11.11.0/math.min.js', '11.11.0', cdnjs='mathjs', npm='mathjs'),
    cdn('v:cdn-bootstrap-table', 'Bootstrap Table', 'https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.22.1/bootstrap-table.min.js', '1.22.1',
        cdnjs='bootstrap-table', npm='bootstrap-table'),
    cdn('v:cdn-datatables', 'DataTables', 'https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js', '1.13.6', cdnjs='datatables', npm='datatables.net',
        extra=[r'cdn\.datatables\.net/']),
    cdn('v:cdn-jszip', 'JSZip', 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js', '3.10.1', cdnjs='jszip', npm='jszip'),
    cdn('v:cdn-revealjs', 'Reveal.js', 'https://cdnjs.cloudflare.com/ajax/libs/reveal.js/4.6.1/reveal.min.js', '4.6.1', cdnjs='reveal.js', npm='reveal.js'),
    cdn('v:cdn-backbone', 'Backbone.js', 'https://cdnjs.cloudflare.com/ajax/libs/backbone.js/1.4.1/backbone-min.js', '1.4.1', cdnjs='backbone.js', npm='backbone'),
    cdn('v:cdn-d3', 'D3', 'https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js', '7.8.5', cdnjs='d3', npm='d3'),
    cdn('v:cdn-mootools', 'MooTools', 'https://ajax.googleapis.com/ajax/libs/mootools/1.6.0/mootools.min.js', '1.6.0', cdnjs='mootools',
        extra=[r'ajax\.googleapis\.com/ajax/libs/mootools/']),
    cdn('v:cdn-prettyphoto', 'prettyPhoto', 'https://cdnjs.cloudflare.com/ajax/libs/prettyPhoto/3.1.6/js/jquery.prettyPhoto.min.js', '3.1.6', cdnjs='prettyPhoto'),
    cdn('v:cdn-scriptaculous', 'script.aculo.us', 'https://ajax.googleapis.com/ajax/libs/scriptaculous/1.9.0/scriptaculous.js', '1.9.0', cdnjs='scriptaculous',
        extra=[r'ajax\.googleapis\.com/ajax/libs/scriptaculous/']),
    cdn('v:cdn-select2', 'Select2', 'https://cdnjs.cloudflare.com/ajax/libs/select2/4.0.13/js/select2.min.js', '4.0.13', cdnjs='select2', npm='select2'),
    libfile('v:file-lodash', 'Lodash', ['lodash'], '/static/js/lodash-4.17.20.min.js', '4.17.20'),
    libfile('v:file-moment', 'Moment.js', ['moment'], '/assets/js/moment-2.29.4.min.js', '2.29.4'),
    libfile('v:file-select2', 'Select2', ['select2'], '/js/select2-4.0.13.min.js?ver=6.4.2', '4.0.13'),
    libfile('v:file-backbone', 'Backbone.js', ['backbone'], '/js/vendor/backbone-1.4.1.min.js', '1.4.1'),
    cdn('v:cdn-openui5', 'OpenUI5', 'https://openui5.hana.ondemand.com/1.120.1/resources/sap-ui-core.js', '1.120.1',
        extra=[r'openui5\.hana\.ondemand\.com/', r'sdk\.openui5\.org/']),
]

# ------------------------------------------------------------------------------------------------------------------
# Reviewed products that get no version-only rule, and why. Categories:
#   platform      general-purpose OS: the patch level is not visible remotely (see cpe-supplement "platforms")
#   hardware      a hardware CPE: NVD gives hardware no software version
#   hidden        checked: the responses the scanner receives carry no version
#   other-url     the version is only at another URL (an API or file the scanner does not request)
#   coarse        only a major or major.minor number is visible, but releases have more parts
#   not-version   the number visible is not the product's version (build hash, cache-buster, API/protocol/component
#                 version, copyright year, build date)
#   unverified    a public database has a candidate, but neither an image of the product nor a sample of the
#                 response is available to check it against (the value's format and NVD's numbering are unconfirmed)
NO_VERSION = {
    # ---- appliances and enterprise software that publish no version to anonymous clients
    'Fortinet FortiOS': ('hidden', 'login pages (/, /remote/login) carry no version; build only in authenticated API'),
    'Palo Alto Networks PAN-OS': ('hidden', 'GlobalProtect/management pages carry no version (only ETag/Last-Modified dates, a lookup table)'),
    'Palo Alto GlobalProtect': ('hidden', 'see PAN-OS'),
    'Ivanti Connect Secure': ('other-url', '/dana-na/nc/nc_gina_ver.txt; the welcome page carries none'),
    'Pulse Connect Secure': ('other-url', 'see Ivanti Connect Secure'),
    'Pulse Secure': ('other-url', 'see Ivanti Connect Secure'),
    'Cisco ASA': ('other-url', 'only in the reply to an AnyConnect config-auth POST'),
    'F5 BIG-IP': ('hidden', 'TMUI/APM pages carry no version'), 'F5 BIG-IP LTM': ('hidden', 'see F5 BIG-IP'),
    'F5 BIG-IP APM': ('hidden', 'see F5 BIG-IP'), 'F5 Advanced WAF (ASM)': ('hidden', 'see F5 BIG-IP'),
    'Citrix Gateway': ('not-version', 'only resource hashes (?v=<md5>), a lookup table'), 'Citrix NetScaler Gateway': ('not-version', 'see Citrix Gateway'),
    'Citrix NetScaler ADC': ('hidden', 'no version in default responses'),
    'VMware vCenter Server': ('other-url', 'only via the SOAP /sdk RetrieveServiceContent call'), 'VMware vCenter': ('other-url', 'see VMware vCenter Server'),
    'VMware ESXi': ('other-url', 'see VMware vCenter Server'),
    'Juniper J-Web': ('hidden', 'login page carries the model, not the Junos release'),
    'QNAP QTS': ('other-url', '/cgi-bin/authLogin.cgi'),
    'Cisco ISE': ('not-version', '?_isever=<build timestamp>'),
    'WatchGuard Firebox': ('hidden', 'no version on the login page'),
    'Veeam Backup & Replication': ('hidden', 'no version on the web console login'),
    'Cisco Unified Communications Manager': ('other-url', '/cucm-uds/version'),
    'SonicWall SonicOS': ('hidden', 'no version on the login page'),
    'Oracle PeopleSoft': ('not-version', 'only copyright years'),
    'Sitecore': ('other-url', '/sitecore/shell/sitecore.version.xml'),
    'Adobe ColdFusion': ('hidden', 'no version in default responses'),
    'Oracle Fusion Middleware': ('coarse', 'welcome page names the generation (11g/12c), not the release'),
    'WebSphere': ('coarse', 'Server header gives major.minor (9.0) of four-part releases'),
    'Plex Media Server': ('other-url', '/identity; X-Plex-Protocol is the protocol version'),
    'GitLab': ('hidden', 'sign-in page carries a git revision, not the release; /help needs a login'),
    'Splunkd': ('hidden', 'management port: Server header without version'),
    'Craft CMS': ('hidden', 'X-Powered-By: Craft CMS, no version'),
    'MinIO': ('hidden', 'Server: MinIO, no version'),
    'Caddy': ('hidden', 'Server: Caddy, no version'),
    'Envoy': ('hidden', 'server: envoy, no version'), 'Istio': ('hidden', 'see Envoy'),
    'Varnish Cache': ('coarse', 'Via: 1.1 varnish (Varnish/6.6) gives major.minor only'),
    'HAProxy': ('hidden', ''),
    'Java': ('not-version', 'X-Powered-By JSP/2.3 is the JSP specification, not the JRE'),
    'ASP.NET Core': ('hidden', ''), 'Spring': ('hidden', ''), 'Spring Boot': ('hidden', ''),
    'MongoDB': ('hidden', 'the HTTP-on-driver-port text carries no version'), 'PostgreSQL': ('hidden', 'startup error carries no version'),
    'Redis': ('hidden', '-NOAUTH/-ERR replies carry no version'), 'Dovecot': ('hidden', 'banner says "Dovecot ready."'),
    'MailEnable': ('hidden', ''), 'OpenBSD OpenSMTPD': ('hidden', 'banner says "ESMTP OpenSMTPD"'),
    'Net-SNMP SNMP Agent': ('not-version', 'sysDescr describes the host kernel, not net-snmp'),
'Facebook Proxygen': ('hidden', ''),
    'Ruby Rack': ('hidden', ''), 'ThinkPHP': ('hidden', 'X-Powered-By: ThinkPHP, no version'), 'Yii': ('hidden', ''),
    'Strapi': ('hidden', 'X-Powered-By: Strapi <strapi.io>'), 'Livewire': ('not-version', 'livewire.js?id=<hash>'),
    'OXID eShop': ('coarse', 'generator gives the major (Version 6)'),
    'TYPO3 CMS': ('coarse', 'generator "TYPO3 4.5 CMS" (major.minor; none since 6.x)'),
    'Joomla!': ('hidden', 'container joomla 4.4.14, 5.4.10: no version in the site page (1.x generators gave major.minor only)'), 'Silverstripe': ('coarse', 'generator "SilverStripe 2.4" on 2.x, none since'),
    'Atlassian Jira Service Management': ('not-version', 'ajs-version-number is the Jira platform version, not the JSM release'),
    'MyBB': ('not-version', 'general.js?ver= comes from the theme template, not the installed release'),
    'ownCloud': ('not-version', 'login page assets carry content hashes (container owncloud/server 10.16.7)'),
    'ownCloud Server': ('not-version', 'see ownCloud'),
    'HashiCorp Vault': ('hidden', 'container hashicorp/vault 1.20.4, 2.2.1: /ui/ carries no version (only /v1/sys/health)'),
    'Riverbed RiOS': ('not-version', 'X-RBT-Optimized-By names the appliance on the path, not the scanned host'),
    'Microsoft Commerce Server': ('hidden', ''), 'Commerce Server': ('hidden', ''),
    'Socket.io': ('not-version', 'a CDN client script says nothing about the server release'),
    'Riot.js': ('not-version', 'the CPE names riot-compiler, not the library a page loads'),
    'Oracle ILOM': ('not-version', 'Server header carries the web server version'),
    'Rapid7 Nexpose': ('not-version', 'Server: NSC/0.6.4 is a component version'),
    'Zabbix': ('hidden', 'ui/include/views/general.login.php renders makePageFooter(false): the login page footer has no version'),
    'N-able N-central': ('other-url', 'the page at / is a script redirect; the version is on /login'),
    'DNN': ('not-version', 'only ?cdv= client-dependency counters'),
    'ManageEngine ServiceDesk Plus': ('not-version', 'login assets carry the build number; NVD needs release + build, which no response gives'),
    'ManageEngine ADSelfService Plus': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine Endpoint Central': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine SupportCenter Plus': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine ServiceDesk Plus MSP': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine Password Manager Pro': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine PAM360': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine Access Manager Plus': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine ADManager Plus': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine ADAudit Plus': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine AssetExplorer': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine OpManager': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine Analytics Plus': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'ManageEngine AD360': ('not-version', 'see ManageEngine ServiceDesk Plus'),
    'Apache ActiveMQ': ('other-url', 'the console start page (/) is static; the version is on /admin/ (authenticated) or hawtconfig.json (Artemis)'),
    'WSO2 API Manager': ('hidden', 'Server: WSO2 Carbon Server, no version'),
    'WSO2 Identity Server': ('hidden', 'no version in current releases'),
    'Progress WS_FTP': ('hidden', 'the web client carries none (the SSH banner of the same server does, on another port)'),
    'Cisco Expressway': ('hidden', 'login page names the edition, not the release'),
    'PrestaShop': ('other-url', 'only on the back-office login, whose path is random per shop'),
    'McAfee ePolicy Orchestrator': ('hidden', 'the agent port this detection comes from carries none'),
    'Cisco Wireless LAN Controller': ('hidden', ''),
    'Odoo': ('other-url', 'POST /web/webclient/version_info'),
    'Netgate pfSense': ('not-version', 'pfSense.js?v=<hash>'),
    'Mailman': ('other-url', 'Mailman 2 prints it on /mailman/listinfo pages, not on /'),
    'phpBB': ('coarse', 'phpBB 3 prints none; cookies give the major only'),
    'Subrion': ('other-url', 'admin panel only'),
    'Harbor': ('other-url', '/api/v2.0/systeminfo'),
    'Tableau Server': ('not-version', 'data-buildId'),
    'Rapid7 Nexpose/InsightVM': ('not-version', 'Server: NSC/0.6.4 is a component version'),
    'Rapid7 (NeXpose)': ('not-version', 'see Rapid7 Nexpose'),
    'Power BI Report Server': ('other-url', '/reports/api/v2.0/System'),
    'Bitwarden Server': ('hidden', ''),
    'xtCommerce': ('hidden', 'only in a JavaScript variable (needs a browser)'),
    'ExtJS': ('hidden', 'only in a JavaScript variable (needs a browser)'),
    'VMware Horizon': ('other-url', '/portal/info.jsp'),
    'Inductive Automation Ignition Gateway': ('hidden', 'the title names the gateway, not the release'),
    'FreshTomato': ('hidden', ''),
    'Zimbra': ('other-url', '/js/zimbraMail/share/model/ZmSettings.js'),
    'Ametys': ('other-url', 'admin login only'),
    'Argo CD': ('other-url', '/api/version'),
    'F5 BigIP': ('hidden', 'see F5 BIG-IP'),
    'CrushFTP': ('coarse', 'old Server headers gave "Version 6.5"; NVD numbers builds 11.3.7_69'),
    'CrushFTP Web Interface': ('coarse', 'see CrushFTP'),
    'Apache Airflow': ('hidden', 'airflow/www/templates/airflow/main.html prints the version in the footer only when logged in'),
    'JivoChat': ('hidden', 'third-party chat widget; version only in a JavaScript variable'),
    'Meteor': ('hidden', 'only in a JavaScript variable (needs a browser)'), 'ReDoc': ('hidden', 'only in a JavaScript variable'),
    'Stripe': ('hidden', 'third-party payment script; version only in a JavaScript variable'),
    'Afterpay': ('hidden', 'third-party payment widget; version only in a JavaScript variable'),
    'Wink': ('hidden', 'only in a JavaScript variable'),
    'HP OpenView': ('not-version', 'Server headers carry component versions (BBC, coda, ovbbccb)'),
    'HipServ': ('not-version', 'the SSH banner carries the OpenSSH version'),
    'OpenBSD httpd': ('hidden', ''), 'Netdata': ('other-url', '/api/v1/info'),
    'Lotus-Domino': ('hidden', 'Server: Lotus-Domino without version (the mail banners of the same server carry it, on other ports)'),
    'HCL Domino': ('hidden', 'see Lotus-Domino'),
    'Cloudflare': ('other-url', 'WordPress plugin readme.txt'),
    'UNIX': ('platform', 'a generic OS name'),
    'Red Hat': ('platform', 'Red Hat Enterprise Linux from a Server token'), 'Gentoo': ('platform', ''), 'Gentoo Linux': ('platform', ''),
    'Conectiva Linux': ('platform', ''), 'Trustix Secure Linux': ('platform', ''), 'SGI Irix': ('platform', ''), 'NetBSD': ('platform', ''),
    'Google Android': ('platform', ''), 'Apple Mac OS': ('platform', ''),
    'Traefik': ('hidden', 'container traefik v2.11.61, v3.7.17: / redirects to /dashboard/, whose HTML carries no version (only the API does)'),
    'Traefik Proxy': ('hidden', 'see Traefik'),
    'Vaultwarden': ('other-url', 'container vaultwarden 1.37.5: the web vault page at / carries no version; only /api/version and /api/config do'),
    'Brizy WordPress': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'Jetpack': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'LiteSpeed Cache': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'Litespeed Cache': ('hidden', 'see LiteSpeed Cache'),
    'Otter Blocks': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'Blocksy Companion': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'Premio Chaty': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'RafflePress': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'Smart Slider 3': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'SVG Support': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'Easy Accordion': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'EWWW Image Optimizer': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'SpeedyCache': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'ElasticPress': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'iThemes Security': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'Jetpack Boost': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'WP-Optimize': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'Custom Fonts': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'WP Fastest Cache': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'WooCommerce Stripe Payment Gateway': ('hidden', 'wplab (two releases): no asset of the plugin on a page that does not use it'),
    'Matomo Analytics': ('other-url', 'CHANGELOG.md'),
    'Contao': ('other-url', 'the back-end login page and CHANGELOG.md'),
    'Apache Flink': ('other-url', 'the REST API /config'),
    'osTicket': ('hidden', 'only the installer page names the release'),
    'phpwcms': ('other-url', 'files under the installation, not the site pages'),
    'Complianz': ('hidden', 'only in a JavaScript variable (needs a browser)'),
    'Couchbase Server': ('hidden', 'container couchbase 7.6.12: / redirects to /ui/index.html, which carries no version'),
    'Keycloak': ('not-version', 'container quay.io/keycloak/keycloak 26.6: / redirects to the admin console, whose resources carry a random resourceVersion'),
    'Redmine': ('hidden', 'container redmine 6.0.12, 7.0.3: "Powered by Redmine" without version'),
    'Essential Blocks': ('not-version', 'wplab 5.4.0, 6.5.3: front-end assets carry a content hash'),
    'Genesis blocks': ('not-version', 'wplab 3.1.3, 3.1.11: front-end assets carry a timestamp'),
    'RabbitMQ': ('hidden', 'container rabbitmq 4.2.9-management, 4.3.7-management: the management UI page carries no version (only /api/overview, authenticated)'),
    'osCommerce': ('no-known-location', 'the one candidate (nuclei oscommerce-detect) is a generic "osCommerce <n>" body match; the default catalog footer prints no version'),
    'ExpressionEngine': ('no-known-location', 'the one candidate (nuclei expressionengine-detect) is a generic "ExpressionEngine <n>" body match; the default templates print no version'),
    'Google Web Server': ('hidden', 'Server: gws carries no version (the recog candidate names the product only)'),
    'Google Web Services': ('hidden', 'see Google Web Server'),
    'Ubiquiti UniFi': ('not-version', 'the version recog reads from the SNMP sysDescr is the device firmware, not the UniFi Network application'),
    'Sophos Firewall': ('unverified', 'nuclei sophos-fw-version-detect reads typography.css?version= on login.jsp; no image or sample of the value, and NVD numbers SFOS by release and MR update (17.5 maintenance_release9)'),
    'Rancher': ('unverified', 'container rancher/rancher v2.15.3 does not start in the lab (its embedded Kubernetes needs cgroup v2); the one candidate (nuclei rancher-panel: <!-- x.y.z --> in the older Ember UI, whose static title is "Loading") is not on the page the Rancher title rule detects'),
    'HashiCorp Nomad': ('hidden', 'container hashicorp/nomad 1.10.5 (server agent): / redirects to /ui/, whose HTML and Ember config meta carry no version (only the HTTP API does)'),
}
