# Invoke-WebInventory.ps1 v2.6.1

Non-intrusive web service discovery and fingerprinting for Windows PowerShell 5.1 (also runs on PowerShell 7). It is a CMDB-lite replacement: TCP connect, HTTP/HTTPS auto-detection on any port, identification, certificate and TLS posture, written to CSV/JSONL/HTML with run and error logs. Nothing is installed and there are no external binaries; the inline C# engine compiles at first run.

With `-Store`, every complete run also goes into an inventory store with first/last seen, versions and a change log per
service, kept in Windows' built-in ESENT database engine and backed by an append-only, hash-chained archive of every run
(see "Inventory store"). The store's inventory can be joined offline with NVD, CISA KEV and FIRST EPSS files to list
the known vulnerabilities of what was found (see "What v2.3 adds").

Each service's IP is also matched offline against the IP ranges that cloud and CDN providers publish (AWS, Azure
including Azure Government, Google Cloud, Oracle Cloud, DigitalOcean, Akamai/Linode, Cloudflare, Fastly). This fills
the `Cloud`, `CloudRegion` and `CloudService` columns. `-Cname` adds the CNAME chain of hostname targets, and
`-Screenshot` captures are now checked: each is labelled ok, blank, suspect or failed, with a reason (see "What v2.5.0
adds").

Every result is also written as JSON Lines (the delta, the screenshot index, the errors, the store queries and a per-run
vulnerability join included), and `-ShipTo` sends a finished run to Tideline, the results platform. The run goes as a
signed envelope over mutual TLS. `Register-WebInventorySensor.ps1` enrolls the host with Tideline's CA (step-ca), and
`Send-WebInventoryRun.ps1` sends runs later or carries them by hand (see "What v2.6.0 adds" and `SHIPPING.md`).

It does not exploit, brute-force, guess credentials or enumerate paths. The optional `-IdentifyPaths` set is a fixed list
of 16 public landing/version pages; the optional `-VersionPaths` sends one GET to a product's documented version URL,
and only after that product was detected without a version. The only credentials it ever uses are an SNMP community or SNMPv3 user you supply
with `-Snmp`; SMB and RDP stop at the server's first, unauthenticated NTLM message.

## Files

| File | Purpose |
|---|---|
| `Invoke-WebInventory.ps1` | The tool (single file; embeds the engine, 515 curated rules, 114 version-only rules and the reviewed CPE supplement) |
| `WebInventory.rules.recog.json` | 3,098 Rapid7 Recog rules converted to .NET regex (BSD-2), including SNMP sysDescr/sysObjectID, SMB NativeOS/NativeLM and JARM fingerprints. Auto-loaded when it sits next to the script |
| `WebInventory.rules.wappalyzer.json` | 7,824 webappanalyzer (Wappalyzer fork) rules covering 5,926 technologies: JS libraries, CMS, frameworks, analytics, CDNs, e-commerce (GPL-3.0 data). Auto-loaded |
| `WebInventory.cloud.json` | 92,358 IP ranges published by AWS, Azure (public, Government, China), Google Cloud, Google, Oracle Cloud, DigitalOcean, Akamai (Linode), Cloudflare and Fastly, with region and service. Matched offline against each service's IP; auto-loaded when it sits next to the script (only once a service on a public address answers). Rebuilt weekly in the repository |
| `WebInventory.example.psd1` | Example settings file for scheduled runs (`-ConfigFile`) |
| `THIRD-PARTY-NOTICES.txt` | Licences, upstream commits and how to regenerate each pack |
| `LICENSE-GPL-3.0.txt` | Full GPL-3.0 text, which must travel with the Wappalyzer pack |
| `PERFORMANCE.md` | The v2.1 performance checklist (what was measured, kept, rejected and why), and the v2.2, v2.3, v2.3.1, v2.3.2, v2.4.0, v2.5.0 and v2.6.0 A/B runs showing the scan path unchanged |
| `Test-WebInventoryStore.ps1` | One-off validation of the inventory store on the scanner host (ESENT vs portable engine, hard kills, verify, rebuild) |
| `Send-WebInventoryRun.ps1` | Sends finished runs to Tideline, resumes stopped deliveries, shows a run's state there, or writes a bundle to carry by hand (self-contained) |
| `Register-WebInventorySensor.ps1` | Enrolls this host as a Tideline sensor with step-ca and renews its certificate; on Windows the key is a non-exportable machine key made by `certreq.exe` (self-contained) |
| `SHIPPING.md` | JSON outputs, sensor setup, the shipping protocol, delivery state and exit codes |
| `SHA256SUMS.txt` | Hashes of the files above |

All three rule sets load together: 11,551 rules (with the 114 version-only rules), about 0.6 s at startup. A literal prefilter skips every rule whose required text is absent from the value, so matching a 120 KB page takes about 8 ms (110 ms in v2.0.2). To run without a pack, delete or move its file, or use `-NoCompanionRules` to load only the embedded rules.

### The Wappalyzer pack
- **Generated from** enthec/webappanalyzer commit `d91f7e510e93` (2026-10-19), passive HTTP patterns only:
  - headers, cookies, meta tags, `<script src>`
  - HTML/inline-script/text markers, URL, certificate issuer, robots.txt

  Wappalyzer's `js` (JavaScript variable) and `dom` (CSS selector) checks need a browser and are skipped, so libraries detectable only that way won't appear. All 7,824 converted patterns compile under .NET.
- **Semantics kept from Wappalyzer:**
  - JavaScript regex dialect, translated (identity escapes such as `\_`, `[^]`).
  - `^`/`$` anchor to the whole value, not each line.
  - Version capture (946 rules), CPE (1,294 rules: 867 upstream, 427 from the v2.3.1 CPE supplement), `implies`/`excludes`/`requires`, and `requiresCategory`. That last one matters: 100 rules, mostly shipping carriers matched on page text, count only when something in the required category (e-commerce) is also detected, which stops a page that merely mentions "DHL" from being flagged.
  - Implied technologies inherit kind, category and CPE (IIS → Windows Server goes to `OsHint`).
- **Licence:** GPL-3.0. Using it inside your organisation creates no obligations. If you pass the pack outside the organisation, keep `LICENSE-GPL-3.0.txt` and the notice with it; the upstream commit is recorded inside the pack for source traceability. The script itself only reads the pack as data at runtime.
- **Refresh:** the repository's weekly workflow does this and opens a pull request (`tools/refresh`, "What v2.4.0 adds"). By hand: `git clone https://github.com/enthec/webappanalyzer`, run `.\Invoke-WebInventory.ps1 -ImportRules .\webappanalyzer\src -ImportOutput .\WebInventory.rules.wappalyzer.json`, then `-TestRules`. The same pattern works for Recog with `-ImportRules .\recog\xml`. Rules that won't compile or that fail their own published example are dropped and listed in the error log.

## Quick start

```powershell
.\Invoke-WebInventory.ps1 -SelfTest                                   # 156 offline checks on Windows (149 without ESENT)
.\Invoke-WebInventory.ps1 10.0.0.0/24 -ListTargets                    # expand + scope-check only; sends nothing
.\Invoke-WebInventory.ps1 10.0.0.5
.\Invoke-WebInventory.ps1 10.0.0.0/24 web01:8443 '10.0.1.1-50' -Port web -Exclude 10.0.0.1 -Scope 10.0.0.0/16
.\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -PortFile .\ports.txt -ScopeFile .\authorized.txt -Pace Polite -BaselineCsv auto
.\Invoke-WebInventory.ps1 -TargetFile .\hostports.txt -IdentifyPaths -ProbeSans -ReverseDns -Tag Weekly-DMZ
.\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -VersionPaths -Store D:\WebInventoryStore   # + version URLs of detected products
.\Invoke-WebInventory.ps1 -HostFile .\dmz-names.txt -Cname -Screenshot                    # + CNAME chains, checked screenshots
.\Invoke-WebInventory.ps1 -ConfigFile .\WebInventory.example.psd1    # scheduled-task style
.\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -Store D:\WebInventoryStore   # ...and keep history (see "Inventory store")
.\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -Smb -Rdp -TlsFingerprint -Screenshot -Store D:\WebInventoryStore
.\Invoke-WebInventory.ps1 -HostFile .\dmz.txt -Proxy http://jump01:3128 -ProxyCredential (Get-Credential)
.\Register-WebInventorySensor.ps1 -Token '<one-time token from the Tideline admin>' -GrantKeyAccess 'CORP\svc-webinv'   # once, elevated
.\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -Store D:\WebInventoryStore -ShipTo https://tideline.corp.example:8443 -Engagement eng-2026-014
```

Target syntax (CLI, `-TargetFile`, `-HostFile`, `-Exclude`, `-Scope` all share it):

- Single hosts and lists: an IP or hostname, `[IPv6]:port`, URLs, `host:80,443,8000-8100`, `host:web`.
- Ranges: `10.0.0.0/24`, `10.0.0.1-10.0.0.50`, `10.0.0.1-50`, nmap octets `'192.168.0-3,7.1-254'`.
- Port keywords: `web` (26 common web ports), `web-extended` (114), `mgmt` (BMC and appliance consoles), `all`.
- Protocol URLs for services on other ports: `smb://fs01:4445`, `rdp://[fe80::5]:3390`, `snmp://10.0.0.9:1161` (with the
  matching `-Smb`, `-Rdp`, `-Snmp`).

PowerShell splits unquoted commas, so `-Target web01:80,443` arrives as `web01:80` + `443`. The script glues bare port tokens back on. A partial numeric such as `7.1` or `443` is refused, because the resolver would otherwise turn it into `7.0.0.1`/`0.0.1.187`. Quote octet ranges that contain commas.

## What v2.6.1 changes

- **Tideline accepts the envelopes.** 2.6.0 put the tool's own run id (`tool_run`) into every envelope, and
  Tideline's `tideline-envelope/1` allows no extra fields, so Tideline refused every run. The field is gone; the id
  is still in `run.json`, which ships with the run as its `run-info` artifact. The part fields 2.6.0 added
  (`encoding`, `role`, `chunk`, `chunks`, `file_bytes`, `file_sha256`) and media types with a charset are part of
  `tideline-envelope/1` from minor 1 (benheise/Tideline, tag `schemas-v1.1.0`).
- **The shipping tests check every received envelope against Tideline's own schema** (`tests/v26/received.py`, with
  a copy of `tideline-envelope.1.json`), so a field Tideline does not know fails the build.

## What v2.6.0 adds

- **JSON for every output.** Each output that had only a CSV or text form now also has a JSON Lines file next to it:
  - `_errors.jsonl`: the error log's entries and the run log's warnings, including the DNS, scope and input errors
    logged before the output files exist;
  - `_delta.jsonl` with `-BaselineCsv`;
  - `_screenshots.jsonl` with `-Screenshot`;
  - a `.jsonl` next to every `-StoreQuery` CSV.

  These files use the CSV's column names and its cells as text, without the CSV's formula guard. Counts, ports, sizes
  and durations are numbers, as in the results JSONL, whose format is unchanged. JSON Schemas for every record type
  are in the repository's `schemas/` folder, generated from the script's column lists.
- **`-NvdFeed` on a scan run.** With `-NvdFeed` (and `-KevFile`, `-EpssFile`), a scan joins its own services with the
  NVD, KEV and EPSS files, offline, the same way as `-StoreQuery Vulnerabilities`. No store is needed. The result is
  `_vulns.csv`, `_vulns.jsonl` and `_vulns.provenance.json`, written before the run's manifest.
- **`run.json`** records `runUuid` (made once per run and kept across resumed sessions), `engagement` (`-Engagement`)
  and `exitCode`.
- **Shipping to Tideline: `-ShipTo https://tideline:8443`.** After a run is complete (and added to `-Store`, if
  given), the script sends it:
  - **What:** the JSONL files, `run.json`, the run's manifest, the logs and the screenshots, unchanged. The CSV and
    HTML are not sent.
  - **How:** the manifest names every part with its SHA-256 and is signed (ES256) with the sensor certificate's key.
    The parts follow over HTTPS with mutual TLS; the server must chain to the pinned Tideline root, not the machine
    trust store.
  - **Checks first:** only complete runs whose files still match their own manifest are sent. The certificate, its
    key and the root are checked before the scan starts, so a long scan never ends unable to deliver.
  - **Failure:** a delivery that fails exits 2 and leaves `_ship-state.json`, from which `Send-WebInventoryRun.ps1`
    sends only the missing parts later. That script also sweeps a whole folder, shows a run's state at Tideline, and
    writes a signed bundle for hosts that cannot reach it.
  - **Results unchanged:** a scan with `-ShipTo` gives the same rows as without it.

  Options: `-ShipCertThumbprint` or `-ShipCertPath` (default: the newest valid sensor certificate in
  `LocalMachine\My`), `-ShipCaFile` (default: the root enrollment saved), `-Engagement`, `-ShipRetries`.
- **Enrollment and renewal: `Register-WebInventorySensor.ps1`.**
  - **Enroll:** the Tideline administrator makes a one-time token (`step ca token wi-scan01 --san
    urn:tideline:sensor:wi-scan01`). The script fetches the CA's root by the token's fingerprint, then has
    `certreq.exe` create a non-exportable ECDSA P-256 machine key and installs the issued certificate in
    `LocalMachine\My`.
  - **Renew:** `-Renew` (daily, from a scheduled task) renews through step-ca's rekey endpoint with a new key, keeps
    the sensor's name, removes the previous certificate and key, and keeps the key's readers (`-GrantKeyAccess`).
  - **Off Windows:** the key and certificate go to a PFX readable by its owner only.

  See `SHIPPING.md` for the protocol, the exit codes and the bundle format.

## What v2.5.0 adds

- **Cloud and CDN attribution (offline).** `WebInventory.cloud.json` holds the IP ranges these providers publish for
  their customers' firewalls:
  - AWS;
  - Azure Service Tags for the public cloud, Azure Government and Azure China;
  - Google Cloud and Google;
  - Oracle Cloud, DigitalOcean and Akamai (Linode);
  - Cloudflare and Fastly.

  That is 92,358 prefixes, built from each provider's own list by `tools/cloud/build.py`. Each service's IP is
  matched against them, and the most specific range wins:
  - `Cloud` is the provider (`AWS`, `Azure Government`, `Cloudflare`).
  - `CloudRegion` is the region (`us-east-1`, `usgovvirginia`, `us-central1`, a city for the geofeed providers).
  - `CloudService` is the service the provider names (`EC2`, `CLOUDFRONT`, `AppService`, `AzureFrontDoor.Frontend`,
    `CDN`).

  How it behaves:
  - Nothing is sent anywhere.
  - Private, loopback, link-local and shared (CGNAT) addresses never match. The file is loaded only when the first
    service on a public address answers, so an internal scan does not pay its 0.3 s load time.
  - `-CloudFile` points at another file (loaded before the scan, so a bad file stops the run); `-NoCloud` turns the
    lookup off.
  - A service behind a CDN shows the CDN, which is the address the scanner reached. The run log warns when the file
    is more than 45 days old; the repository's weekly refresh rebuilds it.
  - The store gates the three columns. The first run with the ranges records `Enriched`, not `Changed`, and a run
    with `-NoCloud` keeps the previous values.
- **`-Cname` (opt-in): CNAME chains of hostname targets.** For every target given as a name, the `Cname` column lists
  the chain in order (`www.example.com` → `example.trafficmanager.net;example.azurewebsites.net`). This shows which
  load balancer, CDN or SaaS front end a name points at.
  - Each name gets one A query to this host's own resolvers; nothing goes to the targets.
  - On Windows the query goes through the system DNS client (`DnsQuery_W`: the same servers, suffix search, cache and
    name resolution policy as the OS). Elsewhere it is a standard UDP query to the resolvers in `/etc/resolv.conf`.
  - `-DnsServer 10.0.0.53` (or `ip:port`) asks one server directly.
  - A name that is not in DNS (hosts file, NetBIOS) has no CNAME; a resolver that does not answer is logged as a
    `CNAME` error.
  - SAN virtual hosts and IP targets are not looked up. Gated in the store like the cloud columns.
- **Screenshot checks.** After each capture the browser reports:
  - the page it ended on;
  - the HTTP status of the main document;
  - its title and how much text it shows.

  The PNG is decoded to measure how much of it is a single colour. Each capture gets a `Status` and a `Reason` in the
  screenshot index, the run log and the HTML report:
  - **failed**: no image (navigation error, timeout, browser exit). Also when the page went to an origin outside the
    scan, so the image shows the scope proxy's refusal, or when the browser showed its own error page.
  - **blank**: the page is empty (0-byte body), or the image is at least 99.5 % one colour and the page shows no
    text. The reason names the origins the page asked for that the scope proxy refused; a single-page app whose
    scripts come from a CDN renders blank behind the proxy.
  - **suspect**: the browser received an error status while the scan saw success; or the title the browser rendered
    is not the one the scan saw (a contained title such as `Home - Grafana` for `Grafana` is fine); or the same image
    stands for several services the scan saw with different titles (a shared error or proxy page).
  - **ok**: otherwise. A capture taken before the load event fired is still ok, and its reason says so.

  New index columns: `Reason`, `BrowserUrl`, `BrowserStatus`, `Capture` (the raw capture result). The checks follow
  run-recon's ok/blank/suspect/failed scheme and add the pixel test.
- **Exit code 4: nothing answered.** The run completed, but no service answered: every port closed or filtered,
  every name unresolved, or the network was down. Before, such a run exited 0 like a quiet success. Exit 4 takes
  precedence over 2 (logged errors). A resumed run counts the rows of its earlier sessions. Scheduled tasks should
  alert on 1, 3 and 4. The store still ingests such a run: its services are recorded as missing, as before.
- **RDP certificates past Schannel.** When Schannel cannot handshake with an RDP server (a TLS 1.0-only server on
  a scanner host where TLS 1.0 is disabled), the certificate is now read with the scan engine's raw ClientHello
  after a fresh X.224 exchange, as the HTTPS probe already does. All certificate columns and flags (`WeakTLS`,
  `SelfSigned`, expiry) then apply. `CertSource` is `rdp-raw` and `ProtocolInfo` says so. There is no chain check,
  and the NTLM names need the full handshake.
- **Detection fixes:**
  - Forgejo pages were also reported as Gitea (Forgejo 9 still carries Gitea markers). Two built-in Forgejo rules
    (its default `keywords` meta tag and its `data-theme="forgejo-…"` page attribute) now exclude Gitea.
  - The Cloudflare CDN detection carried `cpe:2.3:a:cloudflare:cloudflare`, which NVD uses for the "Cloudflare for
    WordPress" plugin. The CPE supplement now clears it, so a site behind Cloudflare no longer lists that plugin's
    CVEs.

## What v2.4.1 fixes: Windows PowerShell 5.1

The first runs of the new Windows CI (GitHub's `windows-2022` runners, Windows PowerShell 5.1, ESENT) showed that
**earlier releases did not start on Windows PowerShell 5.1**: `Add-Type` there treats compiler warnings as errors,
and the Windows C# compiler (CodeDom csc, C# 5) raised warning CS0675 on the certificate OID parser, a warning the
C# 5 check on Linux does not report. 2.4.1 is the first release verified on Windows PowerShell 5.1 itself.

- **Engine compile:** the OID parser no longer ORs a sign-extended operand (same result: the low seven bits are
  free after the shift). All three C# blocks compile through Windows PowerShell 5.1's compiler with 0 errors and
  0 warnings; CI fails on any new warning.
- **Warnings no longer stop the tool:** the script compiles its C# blocks with `IgnoreWarnings`, so a newer .NET
  marking an API obsolete cannot stop it at startup (PowerShell 7 on .NET 10 does that today with SYSLIB0058 for
  `SslStream.CipherAlgorithm`, which still works).
- **Prefilter case folding:** .NET Framework's invariant casing leaves the Kelvin sign and the long s unmapped, so
  the literal prefilter could be stricter there than a culture-sensitive case-insensitive rule. The fold map now
  pins the four characters Unicode case-maps onto ASCII letters (K, long s, dotted and dotless I) on every runtime;
  the filter stays a necessary condition for a match. ASCII values are unaffected (lab and farm output identical).
- **`Test-WebInventoryStore.ps1`:** `$PSScriptRoot` is empty in parameter defaults under `powershell.exe -File`, so
  the default `-Script` path failed; it is resolved in the script body now.
- **Results on Windows PowerShell 5.1 (CI):** `-SelfTest` 140/140 (with the ESENT checks), `-TestRules` 0 mismatches
  over 11,549 rules, `Test-WebInventoryStore.ps1` 10/10 (ESENT against the portable engine on three runs of 2,000
  services, four hard kills of an ESENT ingest, verify, rebuild across engines, backfill, event-log anchoring); the
  three C# blocks 0 errors and 0 warnings. The lab and 200-service farm scans of 2.4.1 are identical to 2.4.0's and
  the 25 regression scenarios pass (Linux).

## What v2.4.0 adds

- **`-VersionPaths` (opt-in): version URLs as a confirmation step.** Some products publish their version only at a
  fixed URL of their own (Apache Flink `/config`, Plex `/identity`, Vaultwarden and Argo CD `/api/version`, Mailman 2
  `/mailman/listinfo`, Sitecore `/sitecore/shell/sitecore.version.xml`). With `-VersionPaths`, after a service is
  fingerprinted, the engine lists the products it detected **without** a version whose rules name such a URL, and the
  worker sends one GET to each (same scheme, host and port as the page; no redirects followed; no login; at most 4 per
  service). The response only feeds version-only rules, so it can add a version but never a product. Nothing is sent
  for a product that is not detected or whose version is already known; the `VersionPaths` column lists what was
  requested and the status codes. Off by default (the behaviour WhatWeb calls aggression level 3, here limited to
  documented version URLs). In the store, `VersionPaths` is gated like `IdentifiedPaths`; switching `-VersionPaths`
  on or off between runs records the versions it adds or no longer adds as `Changed` events (their `ProfileChange`
  shows `versionPaths=1` on one side), so keep it consistent per store.
- **Version coverage of the 27 products whose version was "only at another URL":** 6 are read with `-VersionPaths`
  (Flink, Plex and Vaultwarden checked on their own containers at two releases, Argo CD in its source, whose
  anonymous `/api/version` returns the release tag, Mailman and Sitecore from published samples). The other 21 stay
  without a version, each with a recorded reason: behind a login (Harbor's `systeminfo`, ActiveMQ's console, Power BI
  Report Server, Ametys, Subrion), in a POST reply (Odoo, VMware vCenter), a per-site path (PrestaShop, phpwcms), a
  number NVD does not use (Cisco UCM builds, Horizon's client version, Matomo's changelog, Cloudflare's CDN edge), no
  patch level (Pulse Secure, Zimbra), or nothing to verify against (QNAP, N-central, Contao). Netdata, found on the
  way, prints its version in its `Server` header, so it gets it without any extra request. Products with a CPE that
  get a version: 691 by default (690 in v2.3.2), 697 with `-VersionPaths`; `docs/web-inventory-coverage.md` lists
  every product.
- **Vaultwarden is recognised again:** current web vaults title their page `Vaultwarden Web`, which the Recog title
  rule (`Vaultwarden Web Vault`) no longer matched; a built-in title rule covers both.
- **Two CPE alias groups found by comparing with run-recon's product table:** Atlassian Jira (NVD files most Jira
  Server and Data Center CVEs under `jira_server`, `jira_data_center`, `jira_software_data_center`) and Varnish
  (`varnish_cache_project:varnish_cache` and the LTS edition's `varnish-software:varnish_cache`). For a Jira 8.20.0
  service the vulnerability join goes from 2 to 18 rows (1 KEV), for Varnish 6.0.10 from 1 to 3 (KEV CVE-2023-44487).
  The full comparison is `docs/web-inventory-v2.4.0-run-recon.md`.
- **The external lists refresh themselves** (repository): `.github/workflows/refresh-lists.yml` runs every Monday,
  pulls the newest Recog, webappanalyzer, NVD CPE Dictionary, NVD CVE feeds, CISA KEV, nuclei-templates and WhatWeb,
  rebuilds the packs, checks the reviewed CPE names and the version-only rules against them, runs the tests on
  PowerShell 7 and Windows PowerShell 5.1, and opens one pull request with a summary. New CPE mappings and version
  candidates are listed for review, never applied unreviewed. `.github/workflows/check.yml` runs the self-test, the
  rule examples and `Test-WebInventoryStore.ps1` on Windows PowerShell 5.1 for every push and pull request. See
  `tools/refresh/README.md`.

## What v2.3.2 adds: version capture

v2.3.1 gave the products it can identify their NVD names; v2.3.2 reads their versions. Many rules recognise a
product by a title, a cookie or a favicon and capture no version, while the same responses show it elsewhere: in a
footer, a meta tag, an asset URL, a JSON bootstrap block or a header. **Version-only rules** read it from there.

- **What a version-only rule may do.** It is a rule output marked `"vo": true`. It only adds its version to a
  product another rule detected (same kind and CPE product, or the same name); otherwise it is discarded. It never
  creates a detection, never changes the detected product's name, category or confidence, never lifts a
  `requiresCategory` gate, and never replaces a version a detection rule captured. It does replace a version a rule
  only writes in (Recog maps one Roundcube favicon to `1.5.0+`; the login page says `1.6.20`). No new request is
  sent: the rules read `GET /` and its same-host redirects, the 404 probe, `robots.txt`, `security.txt`, the favicon
  and, with `-IdentifyPaths`, its fixed paths.
- **106 rules for 92 products**, embedded in the built-in pack (`v:` ids, `src/version-rules.json`),
  each with a self-tested example. Where they come from:
  - **the product's own container (14 products)**: the image was run, the responses a scan receives were recorded, and
    the rule was replayed through the scanner's matcher against two releases: Solr, Consul, Nextcloud, Roundcube,
    Apache Spark, JupyterHub, XWiki (on its first-run page), Forgejo, Checkmk, n8n, Mattermost (`X-Version-Id`),
    Metabase, pgAdmin, and TeamCity's maintenance page (Gitea, whose rules only matched an older footer, gets the same
    treatment);
  - **the product's page templates or code (15)**: Bugzilla, Mastodon, Kibana, Proxmox VE, Openfire, Bludit,
    BookStack, Weblate, JSPWiki, Piwigo, the Kubernetes API server, and the default welcome pages of Laravel,
    Symfony, CakePHP and Ruby on Rails;
  - **published samples of the same response (37)**: WhatWeb passive plugins, nuclei-templates detection templates,
    Recog examples and webappanalyzer patterns (TeamCity's login page, Splunk before 9.4, PRTG, Lansweeper, Rundeck,
    Wazuh, Superset, Zope, Wing FTP, Exchange 2007 banners, Invision Power Board, uPortal, and older CMS footers and
    generator tags);
  - **WordPress plugins (6)**: WordPress was run with the plugins at two releases each; a rule reads only the
    asset files that carry the plugin's own `?ver=` (WordPress appends its own version, or a bundled library's, to
    others);
  - **JavaScript libraries (20)**: the release in a public CDN path (cdnjs, jsDelivr, unpkg or the project's own
    CDN), or in the library's own file name (`lodash-4.17.21.min.js`); never a query string.
- **What was rejected.** A number that is not the product's release (a build hash, a cache-buster, an API or
  component version, a copyright year, a build timestamp), a major or major.minor where releases have more parts,
  pre-releases, and anything only at another URL (no extra request is sent for a version by default; v2.4.0 adds
  the opt-in `-VersionPaths` for six such products). The ManageEngine
  family, for instance, shows build numbers that NVD would need a build-to-release table for.
- **Coverage.** Of the 1,327 products with a CPE, 690 now have a rule that gives them a version (598 in v2.3.1; 92
  gained one). Of the 637 without, 31 share their CPE with a product whose rules read one (often on another service,
  e.g. an SNMP sysDescr); the others, by reason: no-known-location 390, hidden 87, not-version 42, hardware 30,
  other-url 27, platform 21, coarse 7, unverified 2. Every product and its reason is listed in
  `docs/web-inventory-coverage.md` (repository and development suite); `tools/version/coverage.py` recomputes
  it.
- **Effect on results:** `Products`, `CPEs` and the JSONL detections gain versions; no product appears or
  disappears. On the lab and the 200-service farm, every other column is identical to v2.3.1 (see
  `PERFORMANCE.md`). The first store run after the upgrade records `changed` events for the services whose
  `Products`/`CPEs` gained a version; `-StoreQuery Vulnerabilities` then matches them by version.

## What v2.3.1 adds: CPE coverage

`-StoreQuery Vulnerabilities` can only see services that fingerprinting gave a CPE, ideally with a version. v2.3.1
widens that without changing how anything is detected:

- **More rules carry a CPE.** 715 more rule outputs now name their product in NVD's terms (149 built-in, 139 Recog,
  427 Wappalyzer). Products with a CPE: 906 -> 1,327 of 7,743; products whose rules also capture a version:
  421 -> 598.
- **Every name was checked against NVD and reviewed by hand.** Candidates came from the NVD CPE Dictionary (product
  names, titles, vendor web sites) and the vendor:product pairs NVD's CVE records actually use. Left without a CPE on
  purpose:
  - plugins whose only candidate was the platform (a WordPress plugin is not WordPress core);
  - third-party services a page embeds (analytics, chat, payment, CDN): the scanned host does not run them;
  - generic names (`FTP server`, `HTTP`) and hardware families without a model;
  - general-purpose operating systems (Windows releases from NTLM builds, Linux kernels, distributions): the patch level
    cannot be seen remotely, so every CVE of the release would be listed;
  - rules whose "version" is not the product's version: the rsync protocol version, the Oracle ILOM web-server version,
    a major number only (`Undertow/1`, OXID `Version 6`), or a version written into the rule as a guess (an IOS login
    realm mapped to `11`).
- **Wrong upstream CPEs corrected.** The Wappalyzer data mapped Mattermost to a Jenkins plugin (`jenkins:mattermost`) and
  AWS Certificate Manager to AWStats, and gave Sitecore, Okta and Salesforce a product of `*`. 12 rule outputs were
  corrected or cleared.
- **Former NVD names count.** NVD files one product under several names over time: Pulse Connect Secure became
  `ivanti:connect_secure`, concrete5 became `concretecms:concrete_cms`, NGINX moved to `f5:nginx`, NetScaler has software
  and firmware entries. The vulnerability join now compares each service's CPE under every name of its product (183
  groups: retired names from the NVD dictionary plus reviewed renames). A row found through another name says so in
  `Match`, e.g. `range (as concretecms:concrete_cms)`. Retired names that encode a version or a model (`ios_xe_2.1`,
  `vpn_3015_concentrator`) are not treated as aliases.
- **No KEV flood from operating systems.** A service that hides its version still gets its KEV-listed CVEs, except on a
  general-purpose operating system (Ubuntu, Debian, RHEL, Windows, macOS, the Linux kernel...; 36 names): there every KEV
  entry of the release would be listed for every host. Those rows are counted in the summary and the provenance file
  instead. Appliance systems (FortiOS, PAN-OS, IOS, Junos, ESXi) are not on that list. On the lab store this removed 453
  of 560 KEV rows, all from an `(Ubuntu)` or `(Debian)` token in a `Server` header.
- **How it is wired.** One reviewed table, `cpe-supplement` (embedded in the script, version 2026.11.06, built from the
  NVD CPE Dictionary of 2026-11-04), has four parts: `fill` (product name -> CPE), `replace` (known-wrong CPE -> right
  one), `aliases` and `platforms`. The built-in rules carry their CPEs directly. `-ImportRules` applies `fill` and
  `replace` to Recog and Wappalyzer data (only where a rule has no CPE, or still has exactly the wrong one) and notes it
  in the pack's `source`, so a pack regenerated from upstream keeps them. The shipped packs were regenerated from the
  same upstream commits and are identical to v2.3.0's apart from CPEs. The Vulnerabilities query loads `aliases` and
  `platforms` and records the table version in its provenance file. `tools/cpe/` (development suite) rebuilds the table
  from a newer NVD dictionary; only names nobody has reviewed yet come up for review.
- **Effect on scan results:** only the `CPEs` column and the CPE of each JSONL detection change, for services these
  products run (the evidence text of a detection can list the same items in a different order). Verified with an A/B
  lab scan (see "How this was validated").

## What v2.3 adds

All new probes are opt-in, so a scan without the new switches sends exactly what v2.2 sent. The probe code is a third
C# block compiled only when one of them is used. New output columns are appended after `Notes` (existing CSV
consumers keep their column positions): `DeviceName`, `Domain`, `ProtocolInfo`, `Jarm`, `Ja4s`.

### Known vulnerabilities, offline: `-StoreQuery Vulnerabilities`
Joins the CPEs of the current inventory with files you download yourself; nothing is fetched and nothing is sent to a
target.

```powershell
# NVD CVE JSON 2.0 feeds (nvdcve-2.0-YYYY.json.gz for every year + nvdcve-2.0-modified.json.gz), CISA KEV, FIRST EPSS
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Vulnerabilities -NvdFeed D:\feeds\nvd `
    -KevFile D:\feeds\known_exploited_vulnerabilities.json -EpssFile D:\feeds\epss_scores-current.csv.gz
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Vulnerabilities -NvdFeed D:\feeds\nvd -KevFile ... -Filter 'Kev=Yes'
```

- **Output:** `WebInventory_store_vulnerabilities_<stamp>.csv`, one row per service and CVE: `Host`, `IP`, `Port`, `Url`,
  `Status`, `Products`, `Cpe`, `Cve`, `Kev`, `KevDateAdded`, `KevDueDate`, `KevRansomware`, `Epss`, `EpssPercentile`,
  `CvssScore`, `CvssSeverity`, `CvssVersion`, `Published`, `Match`, `EntityId`, `Description`. Sorted KEV first, then
  EPSS, then CVSS. A `.provenance.json` sidecar records each feed's file name, SHA-256 and record count, the KEV
  catalog version and the EPSS model version and score date, so a report can be tied to exactly the data behind it.
- **Matching:** CPE 2.3 vendor and product must match; versions are compared numerically, including the NVD update
  field (`openssh:9.3:p1` matches a service reporting `9.3p1`) and `versionStart*/versionEnd*` ranges; pre-release words
  (`rc`, `beta`) sort before the release and vendor letters (`1.0.2k`, `p1`) after it; `2.4` equals `2.4.0`. When the
  feed lists a CVE several times (yearly feed plus the modified feed), the most recently modified record decides.
  Rejected CVEs are skipped.
- **`Match` says how sure the row is:** `version` or `range` (the service's version is affected), `all-versions` (the
  NVD entry names the product without a version limit), `... (platform not verified)` (the NVD configuration also
  needs a platform, for example PHP *on Windows*, that the service's other CPEs do not show), and `product-only` (the
  service hides its version). `product-only` rows are listed only for CVEs on the KEV list; the summary line counts the
  rest.
- **What it cannot see:** distribution packages with backported fixes report the upstream version, so a patched
  Debian/RHEL package can still match; a service only matches when fingerprinting produced a CPE with a version.
- Measured on this build's test data: 447,034 NVD records (all years 2002-2026 plus the modified feed, 253 MB
  compressed) in about 60 s; KEV 1,766 entries; EPSS 398,142 rows.

### Scanning through a jump host: `-Proxy`
`-Proxy http://jump01:3128` sends every TCP connection of the scan (connect test, HTTP, TLS probes, JARM, SMB, RDP,
screenshots) through an HTTP CONNECT proxy; `-ProxyCredential` adds Basic authentication. Port state comes from the
proxy's answer: 200 = open, 502/503 = closed (or filtered when Squid reports a timeout/unreachable errno), 504 or no
answer = filtered. The proxy must answer CONNECT only after it has reached the target, as Squid, tinyproxy and Apache
`mod_proxy_connect` do. Names still resolve on the scanning host, so give IP addresses when the jump host sees a
different DNS. Before scanning, the script checks the proxy is reachable and that it does not demand authentication
that was not supplied. A CONNECT the proxy refuses (for example Squid's default rule that allows only port 443) is
logged as a `PROXY` error and that check stays unfinished for `-Resume`; the run summary counts them. `-Snmp` (UDP)
cannot go through a CONNECT proxy and is refused with `-Proxy`. Lab test: a proxied scan of the regression lab gave
field-for-field the same results as the direct scan (26 rows, 0 differences), with and without proxy authentication.

### TLS fingerprints: `-TlsFingerprint`
- **JARM** (salesforce/jarm, BSD 3-Clause): 10 extra ClientHellos per TLS service, the fuzzy hash in `Jarm`. Same
  packets, parsing and hash as `jarm.py`; on six lab TLS services the values matched `jarm.py` exactly. As in `jarm.py`,
  a timeout in any of the 10 probes yields 62 zeros; the script retries the set once before recording that.
- **JA4S** (FoxIO JA4+, FoxIO License 1.1): computed from the ServerHello the existing TLS scan already receives (no
  extra traffic), in `Ja4s`. **Licence:** FoxIO permits use inside your own organisation that does not monetise it;
  using JA4+ to provide value to paying customers needs a FoxIO OEM licence, and FoxIO states the JA4+ methods are
  patent pending (`THIRD-PARTY-NOTICES.txt`). `-NoJa4s` keeps JARM and leaves JA4S out.
  It describes the server's reply to WebInventory's first accepted ClientHello (the TLS 1.3
  one where supported), so compare it with other WebInventory scans rather than with JA4S from passive sensors, whose
  clients send different ClientHellos. Checked against FoxIO's `ja4.py` on captured handshakes.
- JARM and JA4S also feed the rules (`tls.jarm` from the Recog JARM database). In the store they are gated by
  `-TlsFingerprint` (and JA4S separately by `-NoJa4s`): a run without it keeps the previous values, and the first run
  with it records `Enriched`, not `Changed`.

### SMB, RDP and SNMP: `-Smb`, `-Rdp`, `-Snmp`
Each adds one check per target host (TCP 445, TCP 3389, UDP 161); `smb://`, `rdp://`, `snmp://` URLs point at other
ports. Rows have `Service`/`Scheme` `smb`, `rdp` or `snmp` and are printed even without `-ShowNonWeb`.
- **SMB:** an SMB2/3 NEGOTIATE (dialects 2.0.2 to 3.1.1) for the dialect and signing mode, one SESSION_SETUP carrying
  an NTLM NEGOTIATE to read the server's CHALLENGE (NetBIOS and DNS computer and domain names, forest, Windows build),
  and a separate SMBv1 NEGOTIATE ("NT LM 0.12") to see whether SMBv1 is still enabled (SMBv1 servers also give
  NativeOS/NativeLM). No login, no null session, no share listing. `DeviceName` and `Domain` come from the CHALLENGE,
  `ProtocolInfo` holds `dialect`, `signing`, `smbv1` and `osBuild`. Flags: `SMBv1`, `SMBSigningNotRequired`.
- **RDP:** the X.224 connection request offering TLS and CredSSP shows which security the server picks; TLS gives the
  RDP certificate (all certificate columns and flags apply, `CertSource` = `rdp`); a CredSSP TSRequest with an NTLM
  NEGOTIATE returns the CHALLENGE (names, domain, build). Two more connection requests check whether NLA is enforced
  (the server answers HYBRID_REQUIRED_BY_SERVER to a TLS-only request) and whether standard RDP security is still
  accepted. Flags: `RdpNlaNotRequired`, `RdpStandardSecurity`. The TLS handshake goes through Schannel. When Schannel
  cannot complete it (a server that only speaks TLS 1.0, on a host where TLS 1.0 is disabled), v2.5 reads the
  certificate with the scan engine's raw ClientHello on a fresh connection (`CertSource` `rdp-raw`, no chain check;
  the NTLM names need the full handshake and stay empty).
- **SNMP:** a GET of sysDescr (in `Banner`), sysObjectID, sysName (`DeviceName`) and sysLocation. v1/v2c only with the
  `-SnmpCommunity` you give; SNMPv3 with `-SnmpCredential` (user + authentication password; MD5, SHA or SHA-256 with
  `-SnmpAuthProtocol`) and optionally `-SnmpPrivPassword` (AES-128 or DES with `-SnmpPrivProtocol`). With no
  credentials at all, `-Snmp` sends only the unauthenticated SNMPv3 engine discovery and records the engine ID.
  WebInventory never tries a default community. Silence is `filtered` (no row), an ICMP port-unreachable is `closed`.
  Community strings and passwords are written to neither the logs nor `run.json` (the parameter dump shows
  `<redacted>`). Flag: `SnmpV1V2c` (cleartext community).
- **Identification:** the Windows build from NTLM maps to the Windows release (`OsHint`), with 31 builds from
  Windows 2000 to Windows 11 25H2 / Server 2025 (one build number is shared by a client and a server release, so both
  names are given). sysDescr and sysObjectID go through the built-in rules (Cisco IOS/IOS XE, Junos, Windows, Linux)
  and the 630 Recog SNMP fingerprints; SMB NativeOS/NativeLM through Recog.
- Tested against impacket's SMB server (SMB1 and SMB2), a lab RDP listener (NLA, TLS-only, legacy and RDP-only modes)
  and a pysnmp agent (v1, v2c, v3 with SHA/AES, SHA-256, MD5/DES, noAuthNoPriv, wrong password); the SMB packets decode
  cleanly in Wireshark's dissector.

### Screenshots: `-Screenshot`
After the scan, each web service is opened in the Microsoft Edge already on the host (`-BrowserPath` for another
Chromium browser), headless, one fresh temporary profile per page, `-ScreenshotThreads` at a time (default 4),
`-ScreenshotSize` (default 1366x768), `-ScreenshotTimeoutSec` per page (default 30). The page is driven over the
browser's DevTools protocol on 127.0.0.1 (navigate, wait for the load event, capture).
- **The browser only reaches what was scanned.** It runs behind a loopback proxy that forwards only to the origins this
  run scanned on that IP, always to the IP the scanner used, and answers 403 to everything else: CDNs, web fonts,
  analytics, other hosts, and the browser's own background traffic. With `-Proxy` the allowed connections go through
  the jump host too. Before the first page, a canary request checks that the browser really uses that proxy (an
  enterprise policy can force its own proxy or disable headless mode or remote debugging); if not, no screenshots are
  taken and the error log says why.
- **Output:** PNGs in `WebInventory_<RunId>_screenshots\`, an index `WebInventory_<RunId>_screenshots.csv` (`Url`,
  `File`, `Sha256`, `Status`, `PageTitle`, `PageRequests`, `BlockedOrigins` the page asked for, `Ms`), all in the
  manifest, and the image in the HTML report's row details. Pages that need a login prompt (HTTP Basic) are recorded
  as failed with the browser's reason. Screenshots stay in `-OutputDir`; they are not copied into the store.

### Inventory store additions
- **Manual merge and split.** `-StoreMerge <idA>,<idB> -Reason '...'` folds a service into the one it continues (a
  missed address-move pairing: one service ended, the other began). It is refused when the two were ever seen in the
  same run. The earlier entity keeps its id; the later one's history is attached as a `Rekeyed` event with rule
  `manual-merge`, and the earlier one's absences from that point on are dropped. `-StoreSplit <id> [-SplitAt <RunId>]
  -Reason '...'` undoes the latest (or the given run's) pairing, automatic or manual: from that run on the history
  becomes a separate service again, and the original goes back to its old address with its missing/retired history
  recomputed from the archived check lists. A split is refused when something has since been seen at the old address.
  Ids are the `EntityId` column of Inventory and History queries.
- **Corrections are ledger entries, never rewrites.** Each one is `archive\corrections\<seq>-<op>\correction.json`
  (who, when, why) plus its derived changes, chained into the ledger like a run and applied at its position whenever
  the database is rebuilt or verified. `Merged` and `Split` events carry the reason in `Note`.
- **Older runs:** `-ImportRun <older run> -Backfill` inserts runs older than the newest one. The run is archived and a
  `rebase` ledger entry records the new order (runs by start time; corrections stay right after the run they followed)
  with every position's digests; the working database is replayed in that order. Nothing already in the ledger
  changes, and `-VerifyStore` replays both the original order and the rebase. A correction whose services no longer
  exist in the new order is recorded as void. Cost: a full replay (about the time of `-RebuildStore`).
- **Archive growth:** `-SnapshotEvery N` (kept in `STORE.json`) keeps the full `state.jsonl.gz` for the first run and
  every N-th run; the others keep their change log. `-AsOf` on a run without a snapshot replays the history in memory
  up to that run (same rows, measured in the self-test and the scenario test). State digests are still computed and
  recorded for every run, so verification is unchanged.
- **Anchoring the ledger:** `-AnchorEventLog` writes each new ledger head to the Windows Application log (source
  `WebInventory`, event 4100; register the source once, as administrator, with `-RegisterEventSource`).
  `-AnchorCertificate <thumbprint>` signs each new ledger line with a certificate from `CurrentUser\My` or
  `LocalMachine\My` (detached CMS/PKCS#7, SHA-256, `archive\anchors\<seq>.p7s`). Both settings are kept in `STORE.json`,
  so scheduled scans keep anchoring without the switches (`-AnchorEventLog:$false` / `-AnchorCertificate ''` turn them
  off). `-VerifyStore` checks every signature against its ledger line, reports entries since signing began that have
  none, and compares the event-log entries with the ledger (an entry for a seq the ledger no longer has, or with a
  different head, fails verification).
- **Enriched events:** when a newly enabled probe fills fields that were empty and the previous version was made
  without that probe (for example the first run with `-TlsFingerprint` or `-Options`), the event is `Enriched` instead
  of `Changed`, so turning a probe on does not look like every service changed.
- Query output files get a `_2`, `_3`... suffix instead of overwriting a file from the same second. Inventory queries
  filter while reading instead of loading every row first.

## Inventory store (v2.2): history across runs, nothing to install

`-Store <folder>` turns single scans into an inventory with history: when each service was first and last seen, every
version of its fingerprint, and a change log (added, changed, missing, retired, reappeared, moved). It is built for
one scanner host and uses only what Windows already has.

```powershell
.\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -ScopeFile .\authorized.txt -Store D:\WebInventoryStore   # scan, then add the run
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -ImportRun D:\Scans\2026-*                           # add earlier v2.x runs, oldest first
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Inventory                               # current inventory -> CSV + HTML
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Changes -WithinDays 7 -ChangeType Added,Retired
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Inventory -Filter 'Technologies=Jenkins','CertDaysLeft<30'
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery History -Filter 'Host=web01.corp.local'
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Inventory -AsOf '2026-06-30'           # as it stood then
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -VerifyStore                                        # audit the whole store
```

### How it is built
- **Working database: ESENT.** The Extensible Storage Engine (`esent.dll`) ships with every Windows version and is
  what Windows itself uses for Active Directory, Windows Update and Search. The script calls it directly (P/Invoke from
  the inline C#; no ManagedEsent DLL, nothing installed). It gives transactions, crash recovery from its own logs and
  keyed lookups: each sighting costs one lookup and one small last-seen update, and new versions and change events
  are written only for services that changed. One process opens a store at a time; a
  second one waits up to 30 s for the `LOCK` and then reports the store as busy.
- **Long-term record: the archive.** Every ingested run is copied into `archive\runs\yyyy\MM\<RunId>\` (results JSONL,
  CSV and HTML report, the list of checks made, `run.json`, logs, manifest, all gzip-compressed where large) and
  recorded in `archive\ledger.jsonl`. Each ledger line holds the SHA-256 of every archived file and of the line before
  it, so editing, removing or reordering anything breaks the chain. The derived `changes.jsonl.gz` (that run's events)
  and `state.jsonl.gz` (the whole inventory after that run) are plain JSON, readable without this tool.
- **The database is disposable.** It is a deterministic function of the archive. Deleting `db\` makes the next open
  rebuild it; `-RebuildStore` does that on purpose (and switches engine with `-StoreEngine`), checking every run's
  change and state digest against the ledger. `-VerifyStore` checks the chain, every archived file, rebuilds the whole
  history in memory and compares it run by run, then compares the live database.
- **The scan is untouched.** The store has its own C# engine, compiled only when the store is used, after the scan
  has finished; the scan engine is the v2.1.0 code unchanged. Ingest starts once the run's files are final (results,
  logs, manifest). An ingest failure never affects the scan output: the run stays in `-OutputDir` and can be added
  later with `-ImportRun`.
- **Portable engine.** `-StoreEngine File` keeps the same data in one file (in memory while open, saved atomically). It
  is what PowerShell 7 on Linux/macOS uses, and the reference the ESENT engine is checked against: `-SelfTest` on
  Windows requires both engines to produce byte-identical digests.

### What counts as a change
- **Identity.** A service is `Host` + `IP` + `Port` (+ virtual-host flag). A DNS name keeps its history when its
  address changes, and so does a service scanned by address when it moves, if the move is unambiguous: the same
  reverse-DNS name, or the same certificate, title, server and products, held by exactly one service that disappeared
  and one that appeared in the same run, and by no other service seen in that run. These show up as `Rekeyed` with the
  rule used and the old and new address.
- **Versions.** 65 fingerprint fields define a version (products, CPEs, title, server, headers, TLS, certificate,
  flags, banner...). Per-sighting detail never creates one: response time, body hash and length (dynamic pages), the
  scan clock, `CertDaysLeft`, notes. Two values are compared in a normalised form: banner clock/date text (SMTP and FTP
  greetings carry the time) and the day count in `CertExpiring:<n>d`.
- **Probes that were switched off.** A run with `-NoTlsScan`, `-NoFavicon`, `-NoExtras`, or without `-Options`,
  `-IdentifyPaths`, `-ReverseDns`, `-TlsFingerprint`, keeps the previous values of the fields only that probe collects instead of
  recording them as removed. Changes made while the probe set differs from the previous version's are marked in
  `ProfileChange`.
- **Incomplete observations.** A row the scanner marked `incomplete:` (local socket exhaustion) updates last-seen but
  never creates a version.
- **Absence is scoped.** A service is `Missing` only when the run actually checked its host and port (the run's
  `_progress.txt`); a run of a different subnet, an `-Exclude`d host or a check that errored says nothing about it.
  SAN virtual hosts only go missing in runs made with `-ProbeSans`. After `-RetireAfter` consecutive in-scope runs
  without it (default 3) a service is `Retired`; if it comes back it is `Reappeared` with whatever changed.
- **Run order.** Runs are applied in start order; a run older than the newest one in the store is refused unless
  imported with `-Backfill` (see "What v2.3 adds"). Incomplete
  runs (interrupted, `-MaxRuntimeMinutes`) are not added; resume them and they are added when they complete, or import
  one as partial with `-ImportRun ... -Force`.

### Queries
`-StoreQuery Inventory | Changes | History | Runs | Vulnerabilities` writes `WebInventory_store_<query>_<stamp>.csv` to `-OutputDir`
(Inventory also gets the HTML report) and with `-PassThru` returns the rows as objects.
- `-Status Active,Missing,Retired,All` (Inventory default `Active,Missing`), `-ChangeType Added,Changed,Enriched,Missing,Retired,Reappeared,Rekeyed,Merged,Split`.
- `-Since`, `-Until`, `-WithinDays`: the window for events (Changes/History), last-seen (Inventory) or start time (Runs).
- `-AsOf <date>`: the inventory exactly as the archive recorded it after the last run started by then.
- `-Filter 'Field<op>Value'`, all clauses must match; several as an array or joined with ` -and `. `=` matches the whole
  value or one `;` item (`Technologies=nginx`), and a flag name matches its detail (`Flags=CertExpiring`); `~` contains;
  `!=`, `!~`; `<`, `<=`, `>`, `>=` compare numbers, then dates, then text. `Any~text` searches every column.
  `CertDaysLeft` is recomputed at query time (or relative to `-AsOf`).

Inventory columns: `Status`, `Host`, `IP`, `Port`, `Vhost`, the 65 fingerprint fields, `FirstSeen`, `LastSeen`,
`LastChange`, `Versions`, `MissingSince`, `MissingRuns`, `RetiredAt`, `FirstRun`, `LastRun`, `EntityId`, and the
last sighting's `ScannedAt`, `VhostOf`, `BodyLength`, `BodySha256`, `ResponseMs`, `CertDaysLeft`, `Notes`, `ScanTag`.
Changes/History: one row per changed field (`Field`, `Old`, `New`), plus `Rule`/`OldKey` for moves and `Note` for
corrections. Runs lists corrections too (`RunId` `correction-<seq>`).

### Operating it
- **Back up the archive, not the database.** Copy `archive\` and `STORE.json` (append-only, so `robocopy /E /XO`
  works); `-VerifyStore` works on a copy, even without `db\` and on another machine. The ESENT database is tied to
  this Windows installation (a newer Windows upgrades it in place, an older one cannot open it); rebuild instead of
  copying it.
- **Evidence.** Each ingest prints and logs the new ledger head hash. Recording it outside the store lets anyone later
  prove the archive up to that run is unchanged; `-AnchorEventLog` and `-AnchorCertificate` do that automatically.
- **Local disk only.** ESENT needs a local NTFS volume; put the store on the scanner host, not a share.
- **Validation on your host.** `Test-WebInventoryStore.ps1` runs the self-test, ingests synthetic runs into ESENT and
  File stores and compares every digest, hard-kills ESENT ingests at four points and checks the repair, then verifies
  and rebuilds across engines. Run it once on the scanner host and after Windows feature updates.

## What v2.1 changes (performance, measured)

Same probes, same rules, same output, and in the benchmark lab every field matched the reference scan. The work was
benchmark-driven: a suite measured v2.0.2, a checklist of 19 candidate optimisations was worked through (14 measured,
most of them A/B tested one at a time), and only the ones that were faster with identical results were kept. `PERFORMANCE.md` has the checklist and all numbers.

| Benchmark (2 vCPU, PowerShell 7.4) | v2.0.2 | v2.1.0 |
|---|---:|---:|
| 200 web services on 50 hosts | 39.7 s, 67 s CPU, results differ from reference in every run | 12.4 s, 20 s CPU, identical |
| Same at 20 ms RTT | 41.9 s | 13.0 s |
| 4,000 closed ports | 139 s, 202 s CPU, 2.8 GB RAM | 12.1 s, 20 s CPU, 0.46 GB |
| 40 silent listeners (tarpit / SYN-proxy firewall) | 12.9 s | 8.1 s |
| 320 filtered ports | 17.4 s | 12.8 s |
| Target expansion, /18 x 26 ports (425,984 checks) | 3.1 s | 0.7 s |

What changed:
- **Rule engine:** an Aho-Corasick prefilter over each value. Every rule regex is reduced to the literal text a match
  must contain (an OR of AND-sets, so alternations work too), and the regex runs only when that text is present. 9,485
  of 10,668 rules get a prefilter; the rest always run, as before. Equivalence is checked on all 2,335 rule examples.
- **Dispatcher:** long-lived workers pull checks from a C# scheduler (same per-host cap, round-robin across hosts) and
  hand results back through a signalled queue. v2.0.2 created a PowerShell instance per check (about 32 ms each) and
  polled every 20 ms, which kept half a core busy even while waiting. Worker functions are registered once in an
  `InitialSessionState`; defining them in every runspace made PowerShell background-compile them once per runspace.
- **Connect:** non-blocking connect plus `Socket.Select` on the worker's own thread. With `BeginConnect`, completions
  queue behind a busy .NET thread pool; in testing that turned 1,992 of 4,000 closed ports into false "filtered".
- **TLS warm-up:** the certificate chain engine is initialised once (about 110 ms) before workers start. Without it,
  dozens of first handshakes initialising it at once stalled for seconds and HTTPS services were lost under load.
- **Silent listeners:** when plain HTTP and the Schannel handshake both get zero bytes before the timeout, the five raw
  TLS version probes are sent concurrently instead of one after another (about 3 timeouts per silent port instead of 7).
  Every probe is still sent.
- **C# instead of interpreted loops:** HTTP response parsing and observation building, CSV/JSONL row writing (same
  quoting, formula guard and JSON types), target expansion and `-ListTargets` formatting.
- **DNS:** a sliding window of 32 lookups, each on its own timeout. One slow name no longer holds up its batch.
- **Local socket exhaustion:** if the scanner runs out of ephemeral ports or socket buffers, connects back off and
  retry instead of reporting the port filtered. Anything still skipped is logged, the row's `Notes` says
  `incomplete: ...`, and the summary warns. Faster scans open connections faster, so this matters more now.

Rejected after testing: a worker ramp-up (no measurable gain) and RTT-derived timeouts (a 1.5 s application was lost
at 1000 ms and 500 ms timeouts). Not adopted: parallel TLS probes on responsive ports (5 connections at once to one
port would break the `-MaxPerHost` contract), compiled regexes, keep-alive, and console-output changes.

**Caveat:** measured under PowerShell 7.4 on Linux; Windows PowerShell 5.1 was not available. The removed costs are
interpreter and dispatch overheads, which are typically larger on 5.1, but run `tests/perf` or a lab VLAN comparison
on Windows before quoting these numbers.

## What v2.0 changes

### Bugs fixed from v1.0 (found in review, reproduced where possible)
1. **Cookie flags were wrong.** `"$nm:no-Secure"` is parsed as a drive-qualified variable, so every entry collapsed to `-Secure` and lost the cookie name. Confirmed under PowerShell.
2. **No size check before expanding a CIDR.** The whole list was built before `-MaxTargets` was checked, so a typo'd `/8` built 16.7M entries. Sizes are now computed from the ranges first.
3. **`Set-Cookie` from redirect hops was overwritten** by later hops. All hops are now kept.
4. **SAN parsing depended on the OS language.** It used `X509Extension.Format()`, which is locale-dependent. Now a DER parser (DNS, IPv4/IPv6, email, URI).
5. **FIPS hosts could not match favicons.** MD5 came back as `FIPS-blocked`. A managed MD5 is now used, for content matching only; SHA-256 uses the platform CNG provider with a managed fallback.
6. **Results were written only at the end,** so Ctrl+C or a crash lost the run. Rows now stream to CSV/JSONL with a progress file and `-Resume`.
7. **One host could get 128 parallel connections** (host-major job order). Now there is a `-MaxPerHost` cap and round-robin dispatch.
8. **Ambiguous TLS protocol selection.** On Windows PowerShell 5.1 (legacy AppContext), `SslProtocols.None` behaviour is unclear. The protocol set is now explicit: TLS 1.0-1.2, plus 1.3 on Server 2022 / Windows 11 with .NET 4.8.
9. **`Write-Progress` ran every 25 ms,** which is slow on 5.1. It is now throttled to 500 ms, with an ETA.

### Error handling and safety
- **Fail-closed input.** Any malformed target, exclusion or scope entry stops the run before a packet is sent. `-SkipInvalidInput` overrides this for targets only; exclusions and scope are never partially applied.
- **Authorised scope.** With `-Scope`/`-ScopeFile`, any target outside scope stops the run (`-DropOutOfScope` to skip them instead). Off-host redirects (`-FollowOffHost`) and SAN vhosts are held to scope and exclusions too.
- **Typos.** A misspelled parameter (`-Treads 4`) is refused rather than becoming a target.
- **Preflight logging.** The run log records: .NET release, FIPS policy, Schannel client protocol registry state, execution policy, Authenticode status of the script, SHA-256 of every rule pack, and all effective parameters (marking defaults). The run refuses to start on .NET older than 4.7.2 or if the mmh3 self-check fails.
- **Retries and watchdog.** `-Retries` re-tries silent ports, which reduces false "filtered" results. A per-check watchdog stops hung workers. `-MaxRuntimeMinutes` stops dispatching cleanly and leaves a resumable progress file.
- **ReDoS guard.** Every rule regex runs with a 200 ms timeout, and timeouts are counted in the summary. One Recog rule with catastrophic backtracking was caught this way and is dropped at import.
- **Hostile-content handling.** Scanned hosts control titles and headers. CSV cells starting with `= + - @` are prefixed with `'` to block Excel formula injection (`-NoCsvSanitize` turns this off). Control characters and ANSI escapes are stripped before console output. The HTML report never uses `innerHTML` for data, and the embedded JSON is escaped.
- **Exit codes and audit evidence.** `0` clean, `1` fatal/refused, `2` completed with logged errors (or, since v2.6, a failed Tideline delivery), `3` interrupted or time limit hit, `4` (v2.5) completed but nothing answered. Each run also writes a `_manifest.txt` with SHA-256 of every output and both logs.

### Detection quality
- **Raw TLS ClientHello probes**, independent of the scanning host's Schannel policy:
  - version matrix (SSL3 to TLS 1.3) and the cipher chosen per version
  - ALPN, giving HTTP/2 detection (impossible through .NET Framework's `SslStream`)
  - weak-cipher acceptance: RC4, 3DES, DES, NULL, EXPORT, anon
  - the leaf certificate even when Schannel cannot connect
  
  Legacy TLS 1.0-only BMCs and printers now show up with certificate and identity instead of vanishing (`SchannelIncompatible` flag).
- **NULL-probe banner wait on non-HTTP ports.** This identifies SSH, FTP, SMTP, POP3, IMAP, MySQL/MariaDB, VNC, PostgreSQL, Redis and AMQP without sending HTTP to them first.
- **Plaintext 400 handling.** Any plaintext 400 now also gets a TLS attempt, not just responses containing the nginx, Apache or Go mismatch strings.
- **One random-path 404 probe** (nmap `FourOhFourRequest`), which surfaces Tomcat, IIS, nginx and Apache versions from error pages. Also: `robots.txt`, `security.txt`, and an optional `OPTIONS` request.
- **Hostname-based extras.**
  - Optional SAN virtual-host probing, same IP only, de-duplicated across jobs.
  - Optional reverse DNS (cached).
  - With `-AllAddresses`, a hostname's every A/AAAA record is scanned.
- **Rule engine in C#.** Fields indexed:
  - headers, cookies, title, body, meta, script src, location, auth
  - favicon mmh3/MD5, certificate subject/issuer (Go DN format, as Recog uses), SAN, ALPN
  - banners, identify-path responses

  Rules support AND/NOT conditions, port scoping, version capture, CPE 2.3 output, implies/excludes/requires, and merging across sources (by CPE, by name, and by CPE product + version).

### New fingerprint coverage (475 embedded rules)
- **Microsoft stack:** IIS/HTTP.sys/WinRM, Exchange (OWA version header and cookies), SharePoint, AD FS, RD Web, Windows Admin Center, SSRS/PBIRS, ASP.NET/MVC/Core, and AD CS Web Enrollment (`ADCSWebEnrollment` flag, relevant to ESC8).
- **Edge and VPN:** FortiGate/FortiOS, Palo Alto GlobalProtect, Cisco ASA, Ivanti Connect Secure, Citrix Gateway/StoreFront/ADC, F5 BIG-IP (LTM/APM/ASM/TMUI), SonicWall, Check Point, Sophos, WatchGuard, pfSense/OPNsense.
- **Out-of-band management and infrastructure:** iDRAC, iLO, XClarity, Supermicro, CIMC, ESXi/vCenter/Horizon, Proxmox, Nutanix, NetApp, Synology, QNAP, Veeam, APC, Niagara/Metasys/SIMATIC.
- **DevOps and monitoring:** Jenkins, GitLab, Gitea, Atlassian (versions via meta tags and applinks), SonarQube, Nexus, Artifactory, Kubernetes/Docker/registry, Grafana, Kibana/Elasticsearch, Prometheus, Splunk, Graylog, Zabbix, PRTG, SolarWinds, Nessus/Tenable.sc/Nexpose.
- **CDN/WAF/LB:** Cloudflare, Akamai, CloudFront, Azure Front Door/App Gateway, Imperva, Fastly, AWS ELB.
- **File transfer:** MOVEit, GoAnywhere, Serv-U, CrushFTP.
- **Printers, cameras and phones:** HP, Xerox, Canon, Brother, Konica, Ricoh, Lexmark, Kyocera; Hikvision, Axis; Polycom.
- **Hygiene flags:**
  - `DefaultPage`, `DirectoryListing`, `PhpInfoExposed`, `DefaultCert`, `DevServer`, `APIDocs`, `ShadowIT`, `MgmtInterface`
  - TLS and certificate: `WeakTLS`, `WeakCipher`, `CertExpired`/`CertExpiring`, `SelfSigned`, `WeakSig`, `WeakKey`, `CertNameMismatch`, `CertUntrusted`
  - HTTP: `CleartextAuth`, `PlainHttp`, `RiskyMethods`

### Quality of life
- `-Pace Polite|Normal|Fast` presets.
- `-ConfigFile` (data-only `.psd1`; command line wins; unknown keys refused).
- `-ListTargets` dry run, `-Resume`, `-MaxRuntimeMinutes`.
- `-BaselineCsv auto` writes a field-level delta: NEW / REMOVED / CHANGED.
- Offline HTML report: filter, sort, drill-down, light/dark, phone width.
- `-PassThru` objects for the pipeline.
- `-Quiet`, `-NoProgress`, `-ShowNonWeb`, `-Tag`.
- Rule tooling: `-SelfTest`, `-TestRules`, `-ImportRules` (Recog / webappanalyzer), `-ExportRules`.

## Outputs (in `-OutputDir`; logs always in the current directory)
`WebInventory_<RunId>.csv` (83 columns, UTF-8 BOM for Excel), `.jsonl` (same plus per-detection confidence/source/evidence), `.html`, `_progress.txt`, `_run.json` (when, how and by whom: probe switches, sessions, completeness, run UUID, engagement, exit code), `_errors.jsonl`, `_delta.csv` + `.jsonl`, `_screenshots.csv` + `.jsonl`, `_vulns.csv` + `.jsonl` + `.provenance.json` (`-NvdFeed`), `_manifest.txt`, `_ship-state.json` (`-ShipTo`), `_run.log`, `_error.log`. Store queries write `WebInventory_store_<query>_<stamp>.csv` + `.jsonl` (+ `.html`). JSON types and schemas: `SHIPPING.md`.

Columns that matter most for a CMDB import:
- **Identity:** `Host`, `IP`, `Port`, `Service`, `Url`/`FinalUrl`, `Title`, `Server`
- **Fingerprint:** `Products` (name + version), `CPEs` (CPE 2.3), `Categories`, `OsHint`, `Hardware`
- **TLS and certificate:** `TlsSupported`, `CertSubject`/`CertSANs`/`CertNotAfter`/`CertSha256`
- **Review:** `Flags`
- **Hosting:** `Cloud`, `CloudRegion`, `CloudService` (published cloud/CDN ranges), `Cname` (`-Cname`)
- **Requests beyond the default set:** `IdentifiedPaths` (`-IdentifyPaths`), `VersionPaths` (`-VersionPaths`: each version URL requested and its status)

CPEs built from banners are hints: distros backport fixes without changing version strings.

## Custom rules
`-ExportRules .\mine.json` writes the embedded pack. Edit it, rename to `WebInventory.rules.<name>.json` and keep it next to the script (auto-loaded) or pass `-RulesFile`. A minimal rule:
```json
{"id":"acme:portal","f":"title","r":"^ACME Portal v([\\d.]+)","n":"ACME Portal","c":"Web application","v":"{1}","p":"cpe:2.3:a:acme:portal:{v}","k":90,"ex":"ACME Portal v4.2","exv":"4.2"}
```
`f` fields:
- `header:<name>`, `title`, `body`, `meta:<name>`, `scriptsrc`, `cookiename`, `cookie:<name>`, `setcookie`, `auth`, `location`, `status`, `url`
- `favicon.mmh3`, `favicon.md5`, `cert.subject`, `cert.issuer`, `cert.san`, `alpn`
- `banner`, `banner.ssh|ftp|smtp|pop3|imap|mysql`, `robots`, `path:<path>.<field>`

Other keys: `o` (`i` ignore case, `s` dot-all, `a` absolute anchors, `b` the value is base64 text and the pattern is matched against its UTF-8 decoding, e.g. n8n's `n8n:config:sentry` meta tag), `and` (list of `{f,r,not}`), `ports`, `out` (several outputs with `t`: service/os/hw), `im`/`xs`/`rq`, `flag`, `vo` (version-only: the output only adds its version to a product another rule detected, see "What v2.3.2 adds"), `get` (a version-only rule's fixed path, requested with `-VersionPaths` only when its product is detected without a version; the rule's `f` must be `path:<get>.<field>`). Run `-TestRules` after editing; every rule with `ex` is checked.

## Operational notes
- **Signing and placement.** Sign the script (`Set-AuthenticodeSignature`), run it under AllSigned/RemoteSigned, and keep it plus the rule packs in a write-protected folder. The run log records the signature status and pack hashes, so tampering shows up.
- **Evidence.** Run with `-ScopeFile` that mirrors your written authorisation, and keep run log, error log and manifest together as the record of each run. With `-Store` this happens automatically: the archive keeps them per run and the ledger chains their hashes; `-VerifyStore` proves them intact, and the ledger head printed after each ingest can be recorded somewhere outside the store.
- **Inventory review.** `-StoreQuery Inventory` is the current inventory with first/last seen; `-StoreQuery Changes -WithinDays 30` lists additions and removals for review; `-AsOf` answers "what did we have on date X" from the archive.
- **Scheduled tasks.** Use `-ConfigFile` with `-Quiet -NoProgress`. Alert on exit code 1, 3 or 4 (4: nothing answered); review 2. With `-ShipTo`, add a daily `Register-WebInventorySensor.ps1 -Renew` task and, if Tideline can be down for longer than a run's retries, a `Send-WebInventoryRun.ps1 <OutputDir> -ShipTo ...` task that sends what is still pending.
- **Air-gapped enclaves.** If HTTPS handshakes are slow there, Windows is trying to fetch intermediate certificates (AIA). The raw TLS probe is unaffected; consider the "Turn off Automatic Root Certificates Update" policy on the scanner host.
- **Network sign-off.** Register the scanner host with the SOC. The User-Agent ends in `(authorized asset inventory)`; set your own with `-UserAgent`.

## How this was validated
- **Engine compile:** C# 5 against the official .NET Framework 4.7.2 reference assemblies, with only the assemblies Windows PowerShell 5.1 references: 0 errors, 0 warnings.
- **Static analysis:** PSScriptAnalyzer with the Windows PowerShell 5.1 compatibility profiles (Windows 10 1809 and Server 2016): syntax, commands, types clean. The only remaining findings are deliberate empty `catch` blocks.
- **Hash and parser vectors:** mmh3, Shodan favicon hash, MD5 and SHA-256 match Python's `mmh3`/`hashlib` vectors. The Go-format DN parser reproduces a Recog test vector exactly.
- **Runtime:** executed under PowerShell 7.4 (Linux) against a local lab, as 106 self-test assertions plus 25 scenario tests. Lab coverage:
  - IIS-like, nginx-like with SAN vhosts, plaintext-to-TLS 400 mismatch, TLS 1.0-only, weak 3DES and anon-DH endpoints
  - Basic-auth Tomcat Manager, Kubernetes API, WordPress with hostile title/header values
  - A Node/Express single-page app and a WooCommerce store, for client-side detection and the `requiresCategory` gate
  - Five PHP2Shell hosts (header-only, no PHP runtime): vulnerable mod_php 8.3.6, patched 8.4.27, EOL 7.4.33, Ubuntu build 8.1.2-1ubuntu2.20, version hidden
  - SSH/FTP/MySQL banners, tarpit, closed port
  - Ctrl+C + `-Resume`, baseline delta, config file, scope fail-closed, `-PassThru`
- **Performance suite (v2.1):** 8 macro scenarios x 3 runs with field-by-field comparison against a low-concurrency v2.0.2 reference, a leave-one-out A/B study of each change, micro-benchmarks, and a prefilter equivalence check over every rule example. Details in `PERFORMANCE.md`.
- **Recog import:** 2,336 published examples checked after conversion; the one rule that failed its own example (catastrophic backtracking) was dropped, and the remaining 2,335 pass.
- **Wappalyzer import:** all 7,824 patterns compile. On the lab pages the pack identified jQuery 3.5.1, Bootstrap 5.2.3, React 18.2.0, Lodash, Moment.js, Google Analytics/Tag Manager, Express → Node.js and WooCommerce 8.2.1, and it correctly suppressed "DHL" on the non-store page. The upstream data has no published examples, so per-rule accuracy beyond these pages is Wappalyzer's own.
- **Windows PowerShell 5.1:** since 2.4.1 the repository's CI compiles every C# block with Windows PowerShell 5.1's compiler and runs `-SelfTest` (with ESENT), `-TestRules` and `Test-WebInventoryStore.ps1` there; releases before 2.4.1 did not compile on 5.1 (see "What v2.4.1 fixes"). Live scans have only been run from Linux: before production, run a lab VLAN pass from the Windows scanner host against known IIS, nginx, iDRAC/iLO and printer hosts. Schannel behaviour (cipher order, TLS 1.0 policy) differs from the Linux/OpenSSL stack used in testing.
- **Inventory store** (Linux workspace, portable engine; ESENT itself needs Windows, see below):
  - Both C# blocks (scan engine, store engine) compile as C# 5 against the .NET Framework 4.7.2 reference assemblies with 0 errors and 0 warnings. The scan engine is the v2.1.0 source with only the version constant changed.
  - 14 store self-test checks (19 on Windows), and a 40-check command-line scenario: five synthetic runs with every expected event and no other (title change with the expiry-day count ignored, three kinds of address move, an ambiguous move left unpaired, carry-over through a `-NoTlsScan` run, no false absence for SAN vhosts without `-ProbeSans`, retirement, reappearance with the diff), every query mode and filter form, refused imports (duplicate, older, incomplete), tampered archive file, edited ledger line, torn ledger tail, interrupted ingest, deleted database, rebuild, lock wait.
  - `kill -9` at four points of a 50,000-service ingest: every reopen finished the run with digests byte-identical to an uninterrupted ingest.
  - Ingest time (PowerShell 7, 2 vCPU, portable engine): 50,000 services 18 s for the first run, 17 s for the next; 200,000 services 70 s and 56 s. Archive about 13 MB per 50,000-service run.
  - Two consecutive lab scans with `-Store`: the second produced zero change events.
  - **Not run here:** the ESENT engine itself (this workspace has no Windows). `-SelfTest` on Windows adds ESENT conformance, ESENT-vs-portable digest equality and ESENT crash repair; `Test-WebInventoryStore.ps1` adds hard kills (`Stop-Process -Force`) of real ESENT ingests and cross-engine rebuilds. Run it on the scanner host before relying on the store.

- **v2.3 additions** (same Linux workspace):
  - All three C# blocks (scan engine, store, opt-in probes) compile as C# 5 against the .NET Framework 4.7.2 reference
    assemblies with 0 errors and 0 warnings; the probe and store blocks against only `mscorlib`, `System` and
    `System.Core`. PSScriptAnalyzer (5.1 profiles): the only new findings are the `System.Security.Cryptography.Pkcs`
    types used for ledger signing, which the script loads explicitly (`Add-Type -AssemblyName System.Security`).
  - Self-test 121/121 (128 with ESENT on Windows); the 25 lab regression scenarios; the v2.2 store scenario (40 checks)
    unchanged; a v2.3 store scenario of 34 checks (merge refusal and success, split with absences recomputed from the
    archive, verify/rebuild with corrections, backfill equal to in-order import for inventory and every change event,
    corrections keeping their place in a backfill, a correction voided by a backfill, rebuild in rebased order, snapshot
    thinning with `-AsOf` replay equal to a full store, ledger signatures including a swapped and a missing signature,
    unique query file names); a gating test (`Enriched` on the first `-TlsFingerprint` run, values kept without it,
    `-NoJa4s`).
  - Stores written by v2.2.0 open, verify and ingest under v2.3.0 with identical digests.
  - JARM equal to `jarm.py` on 6 lab TLS services; JA4S equal to FoxIO `ja4.py` on captured handshakes (2 ports
    directly, 2 more from tshark-decoded ServerHellos and the JA4S formula).
  - Proxy: direct and proxied scans of the lab identical field by field (26 rows), with and without Basic
    authentication; missing authentication stops the run before the scan; ports the proxy refuses are logged and left
    for `-Resume`; credentials appear only as `<redacted>` in the log.
  - SMB against impacket (SMB2 and SMB1 servers); RDP against a lab listener in four modes (NLA, TLS without NLA,
    legacy, standard security only); SNMP against a pysnmp agent (v1, v2c, wrong community, closed port, v3 SHA/AES,
    SHA-256, MD5/DES, noAuthNoPriv, discovery only, wrong password). Secrets were absent from every log and `run.json`.
  - Screenshots with headless Chromium (the same DevTools path Edge uses) over HTTP and HTTPS, directly and through
    the CONNECT proxy; every third-party resource on the test page (fonts, CDN script, tracker, other port, other IP)
    and the browser's own background requests were refused by the scope proxy.
  - Vulnerabilities on real feeds (NVD 2002-2026 + modified, KEV catalog 2026.10.30, EPSS v2026.06.15) for a synthetic
    inventory: e.g. Apache httpd 2.4.49 -> CVE-2021-41773/42013 (`version`, KEV), Confluence 7.13.0 -> CVE-2022-26134
    (KEV) but not CVE-2021-26084 (fixed in 7.13.0) or CVE-2023-22515 (Data Center 8.x only), OpenSSH 9.3p1 ->
    CVE-2023-38408 (`version`), PHP 8.1.2 -> CVE-2024-4577 marked `platform not verified` (Windows-only), Jenkins
    without a version -> only its KEV entries.
  - Interleaved A/B against v2.2.0 without the new switches: identical results in 12/12 comparisons
    (`PERFORMANCE.md`).
  - **Not run here:** Windows PowerShell 5.1 itself, ESENT, Edge, the Windows event log, Schannel for RDP. Run
    `-SelfTest` and `Test-WebInventoryStore.ps1` (now also backfill on ESENT and event-log anchoring) on the scanner
    host, and try `-Screenshot` once interactively there (Edge policies can block headless mode or remote debugging; the
    canary reports it).

- **v2.6.0 additions** (Linux workspace and GitHub's Windows and Ubuntu runners):
  - **Compile and static checks.** The four C# blocks (the shipping code is new) compile with Windows PowerShell
    5.1's compiler (CI) and as C# 5 against the .NET Framework 4.7.2 reference assemblies with 0 errors and 0
    warnings. PSScriptAnalyzer with the 5.1 profiles reports no compatibility finding in the three scripts.
  - **Tests.** Self-test 156/156 on Windows PowerShell 5.1 (ESENT) and 149/149 on PowerShell 7; 3,225 rule examples;
    the 30 lab regression scenarios; store scenarios v2.2 40/40 and v2.3 34/34; gating 4/4 and 4/4;
    `Test-WebInventoryStore.ps1` 10/10 on Windows.
  - **Scan path unchanged.** An interleaved A/B against v2.5.0 found 0 differences on the lab (26 rows), the farm
    (200) and the closed-port run. The same scan with and without `-ShipTo` gives the same rows, and only
    `_ship-state.json` is added.
  - **Shipping** (`tests/v26/ship.sh` against `lab/tideline_mock.py`, which checks what the platform plan gives
    ingest): 29/29 here (28 on CI, which has no browser):
    - the round trip is byte-identical: services, delta, vulnerabilities, screenshots, errors and every artifact;
    - delivery: already delivered (no request), `-Force`, `-Status`; a connection dropped mid-upload, then a resume
      that sent only the missing parts; a 503 retried; Tideline unreachable (exit 2, state kept);
    - refused: a changed file; an inactive sensor; a client certificate from another CA; expired, URN-less and RSA
      certificates (before the scan); a server outside the pinned root or with the wrong name; a conflicting
      manifest (409); an engagement the sensor is not assigned to; a record that fails its schema (422 with the line);
    - a file sent as chunks; the export bundle verified offline, and a tampered one caught; an incomplete run;
    - a PFX password file; exit 4 still shipped; the errors part.
  - **Enrollment** against step-ca 0.30.2 (`tests/v26/register.sh`), 10/10 here and on CI: enroll; token reuse,
    expired token, token without a sensor name and wrong root fingerprint refused; renewal with a new key and the
    same name; a scan shipped with only the enrolled defaults.
  - **Windows PowerShell 5.1** (`tests/v26/windows.ps1` on GitHub's runner, elevated, against step-ca):
    - certreq enrollment: a non-exportable ECDSA P-256 machine key, no pending request left, the root pinned, the
      intermediate in `LocalMachine\CA`;
    - `-GrantKeyAccess` (NETWORK SERVICE) in the key's security descriptor;
    - a scan shipped over Schannel with that key; `-Status`; an export bundle whose chain came from the machine store;
    - renewal: new key, previous certificate and key removed, readers carried over; shipping after renewal.
  - **JSON contract.** Every results line a scan wrote in earlier releases' saved lab and benchmark runs validates
    against `webinventory.service/1`, and so does every new JSONL file of the A/B and shipping runs.
  - **Cost.** Shipping a 200-service run: 0.71 MB of files as 0.03 MB on the wire, 1.3 s with PowerShell start-up.
    A 20,000-service run (65 MB of JSONL, 2 chunks): 2.6 MB on the wire, 14.9 s against the mock, which checks every
    record against its schema.
  - **Not covered here:** a real Tideline ingest (not built yet; the mock implements the plan's checks), a Windows
    host with a non-administrator scan account (the runner is elevated; `-GrantKeyAccess` was checked through the
    key's security descriptor, not by shipping as NETWORK SERVICE), and AD-joined or hardened Schannel policies.

- **v2.5.0 additions** (Linux workspace and GitHub's Windows and Ubuntu runners):
  - **Compile and static checks.** The three C# blocks compile with Windows PowerShell 5.1's compiler (CI) and as
    C# 5 against the .NET Framework 4.7.2 reference assemblies with 0 errors and 0 warnings. PSScriptAnalyzer
    findings are unchanged.
  - **Tests.** Self-test 146/146 on Windows PowerShell 5.1 (ESENT) and 139/139 on PowerShell 7. All 3,225 rule
    examples pass on both. The 30 lab regression scenarios pass, including the new exit-code and option checks.
    Store scenarios v2.2 40/40 and v2.3 34/34; gating v2.3 4/4 and v2.5 4/4; `Test-WebInventoryStore.ps1` 10/10 on
    Windows.
  - **Cloud lookup.** Compared with a Python longest-prefix match over the same file: 80,000 addresses (inside
    ranges, on every edge and its neighbours, anywhere) with 0 mismatches on PowerShell 7, and 40,000 with 0 on
    Windows PowerShell 5.1. No published range overlaps private, loopback, link-local, CGNAT, multicast or reserved
    space. A service on a public address in a test range loaded the ranges and filled all three columns; a run with
    only internal addresses did not load them.
  - **CNAME.** Loopback responder in the self-test. Five public names give the same chain as `Resolve-DnsName`
    (Windows DNS client) and as `dig` (UDP, Linux) in CI. A lab scan with `-DnsServer` put the expected chain on
    every row of the name.
  - **Screenshot checks.** Real headless Chromium against eight lab cases
    (`lab/shotcases.py`):
    - ok: a normal page;
    - blank: an empty body;
    - blank: a white app shell whose script comes from a CDN, with the refused origin named;
    - failed: a redirect to another host, with both refused origins named;
    - suspect: a 503 to the browser and a 200 to the scanner;
    - suspect, both: two identical pages under two titles;
    - suspect: a script that renames the page.
  - **RDP.** A TLS 1.0-only fake RDP server, which the PowerShell 7/OpenSSL client refuses, gives its certificate,
    TLS 1.0 and `WeakTLS:TLS1.0` through the raw ClientHello. An NLA server keeps the Schannel path and its NTLM build
    (`tests/v25/rdp-raw.sh`).
  - **Forgejo.** Replayed container recordings: Forgejo 9.0.3 and 17.0.1 give Forgejo only; Gitea 1.22.3 and
    1.27.3 are unchanged. The re-imported Wappalyzer pack differs from v2.4.1's only in the five Cloudflare rules.
  - **A/B against v2.4.1.** Two interleaved runs each (`PERFORMANCE.md`): lab, 200-service farm and closed ports are
    identical field by field, and wall times are within run-to-run noise. The closed-port run now exits 4.

- **v2.4.0 additions** (same Linux workspace):
  - The three C# blocks compile as C# 5 against the .NET Framework 4.7.2 reference assemblies with 0 errors and 0
    warnings; PSScriptAnalyzer findings unchanged (16 deliberate empty `catch` blocks, 12 notes on the explicitly
    loaded `System.Security.Cryptography.Pkcs` types). Self-test 133/133 (140 with ESENT on Windows); the 25 lab
    regression scenarios pass; all 3,223 rule examples pass (`-TestRules`, 11,549 rules); the store scenarios pass
    (v2.2: 40/40, v2.3: 34/34, enriched gating: 4/4).
  - `-VersionPaths` against the product containers: Vaultwarden 1.37.5 and Flink 2.2.1 scanned without the switch
    report no version; with it, `Vaultwarden 1.37.5` (`/api/version=200`) and `Apache Flink 2.2.1` (`/config=200`),
    one extra request each (Vaultwarden's log shows a single `/api/version` request). Recordings replayed with
    `-VersionPaths` ask only for the products detected without a version (Gitea and Solr, which have a version, ask
    for nothing). Flink 1.20.5, Plex 1.40.0.7998 and 1.43.5.11079, Vaultwarden 1.35.8 and Netdata v1.47.5 and v2.12.3
    (whose `Server` header needs no request) give exactly the image's version.
  - Store: the Vaultwarden/Flink scans without and with the switch, ingested in order, record `Changed` on
    `Products`, `CPEs` and `VersionPaths` for those two services only, with `versionPaths=1` in `ProfileChange`.
  - A/B against v2.3.2, two runs each (`PERFORMANCE.md`): lab, 200-service farm and closed ports identical field by
    field; with `-VersionPaths`, lab and farm also identical with the same request counts (no product there needs a
    version URL). Wall times within run-to-run noise (farm 11.03/10.97 s vs 11.42/11.29 s, lab 39.08/39.00 s vs
    39.16/38.89 s); startup +0.1 s (median of 6 interleaved pairs), not in the rule engine.
  - Jira and Varnish aliases on real feeds (NVD 2002–2026, KEV): a Jira 8.20.0 service 2 → 18 rows (1 KEV), Varnish
    6.0.10 1 → 3 (KEV CVE-2023-44487).
  - The list refresh run end to end on current upstream data in a scratch copy (exit 10: files changed, all checks
    passed): webappanalyzer d91f7e5 → c708f0b (7,824 → 7,874 rules, 38 new products), Recog unchanged, supplement
    unchanged, 1 CPE candidate listed for review, `-SelfTest` and `-TestRules` pass.
  - **Windows PowerShell 5.1:** the first CI runs on GitHub's `windows-2022` runners found that the engine did not
    compile there; fixed in 2.4.1, which passes every check there (see "What v2.4.1 fixes"). Edge headless policy,
    Schannel for the RDP probe and live scans from a Windows host still need a check on the scanner host itself.

- **v2.3.2 additions** (same Linux workspace):
  - The three C# blocks compile as C# 5 against the .NET Framework 4.7.2 reference assemblies with 0 errors and 0
    warnings; PSScriptAnalyzer findings unchanged. Self-test 131/131 (138 with ESENT on Windows); the 25 lab
    regression scenarios pass; all 3,214 rule examples pass (`-TestRules`).
  - Product containers (Solr 9.4.1/10.1.0, Consul 1.22.7/2.1.0, Nextcloud 32.0.15/35.0.2, Roundcube 1.6.20/1.7.5,
    Spark 3.5.9/4.1.4, JupyterHub 5.5.4/6.1.1, Forgejo 9.0.3/17.0.1, Gitea 1.22.3/1.27.3, Checkmk 2.3.0p38/2.4.0p39,
    n8n 1.123.92/2.47.2, Mattermost 10.11.26/12.1.0, Metabase 0.58.39/0.65.3, pgAdmin 9.8/9.19, TeamCity
    2025.11.8/2026.2.2 (maintenance page), and XWiki 16.10.19/18.4.8 (version in the webjar paths of the first-run
    page, where no XWiki rule fires)): the responses a default scan receives were recorded and replayed through the
    scanner's matcher; each detected product carried exactly the image's version. Products whose recorded responses
    carry no version are listed as such (Vault 1.20.4/2.2.1, Traefik 2.11.61/3.7.17, RabbitMQ 4.2.9/4.3.7, Redmine
    6.0.12/7.0.3, Keycloak 26.6/26.8.2, Joomla 4.4.14/5.4.10, ownCloud 10.16.7, Couchbase 7.6.12, Nomad 1.10.5,
    Vaultwarden 1.37.5, and Splunk 9.4.17, whose login page no longer embeds the version the published-sample rule
    reads).
  - WordPress 7.1 with 33 plugins at two releases each: only the asset files whose `?ver=` was the plugin's own
    release in both are read (PixelYourSite's `jquery.bind-first` carried the WordPress version in one release,
    CoBlocks and WooCommerce ship libraries with their own versions, Gutenberg and Essential Blocks hashes, Genesis
    Blocks a timestamp).
  - Same detections: replaying 17 recordings (one per product, plus the two WordPress rounds) with v2.3.1 and
    v2.3.2 gives the same 104 detections; only versions and the version field of CPEs differ.
  - Vulnerabilities for those recordings (NVD 447,034 records, KEV, EPSS): 149 rows (52 KEV) before, 197 (35 KEV)
    after. Gone: 21 Roundcube range rows (6 KEV) that came from Recog's favicon guess `1.5.0` for a 1.6.20 server,
    and 11 KEV listings of version-unknown services whose real version is outside the CVE's range (TeamCity 4, Solr
    3, Metabase 2, Spark CVE-2022-33891, n8n CVE-2025-68613). New, because the version now falls inside a range or
    is listed by NVD: Gitea 1.22.3 40 (its KEV listing CVE-2026-60004 is now a range match), TeamCity 2025.11.8 13,
    Solr 9.4.1 7, Metabase 0.58.39 5, CoBlocks and PixelYourSite 5, Checkmk 2.4.0p39 4 (NVD enumerates
    `2.4.0:p39`), Mattermost 10.11.26 3; and 3 entries NVD gives for all versions (Mattermost 2, Spark 1), which the
    join lists only once a version is known.
  - A/B against v2.3.1, two runs each (`PERFORMANCE.md`): farm 10.82/10.76 s vs 11.08/11.00 s, lab 38.48/38.58 s vs
    38.65/38.50 s, startup 2.81/3.17 s vs 3.00/2.83 s. Lab output identical field by field; on the farm only the 50
    rows that load `lodash-4.17.<n>.min.js` change, gaining `Lodash 4.17.<n>` and its CPE version.
- **v2.3.1 additions** (same Linux workspace):
  - The three C# blocks compile as C# 5 against the .NET Framework 4.7.2 reference assemblies with 0 errors and 0
    warnings. Self-test 125/125 (132 with ESENT on Windows); the 25 lab regression scenarios pass.
  - Every CPE in the supplement exists in the NVD CPE Dictionary (the generator refuses to write one that does not).
  - The regenerated Recog and Wappalyzer packs have the same 3,098 and 7,824 rules as v2.3.0's and differ only in CPEs
    (139 filled; 431 filled, 8 corrected, 4 cleared).
  - All 139 Recog rules that got a CPE and have a published example were evaluated on that example: each detection
    carries its CPE, with the captured version in it where the rule captures one.
  - A/B against v2.3.0 (lab and 200-service farm, two runs each): every CSV column identical except `CPEs` on the two
    FortiGate lab rows; in the JSONL only the order of evidence items changed where rules now share a CPE.
  - Vulnerabilities on real feeds: the lab store went from 1,347 rows (518 KEV) to 936 rows (107 KEV): 42 FortiOS KEV
    rows added, 453 KEV rows of Ubuntu/Debian `Server` tokens no longer listed (counted). A synthetic inventory found
    what the new CPEs and aliases should find: Serv-U 15.2.3 -> CVE-2021-35211 (KEV), TeamCity 2023.05.3 ->
    CVE-2023-42793 (KEV), Ivanti/Pulse 9.1R8 -> CVE-2021-22893 (KEV) and three CVEs filed under
    `pulsesecure:pulse_connect_secure`, Contact Form 7 5.3.1 -> CVE-2020-35489, PAN-OS without a version -> its 17 KEV
    entries; concrete5 8.5.4 0 -> 133 rows (`as concretecms:concrete_cms`), `nginx:nginx` 1.16.1 0 -> 7, Mattermost 46 ->
    79, Citrix Gateway 13 -> 18 KEV entries (e.g. CVE-2019-19781 `as citrix:netscaler_gateway_firmware`).
  - Query time unchanged (48.7 s vs 50.0 s on the lab store, `PERFORMANCE.md`).

## Version advisories (PHP2Shell)
The scanner can mark services that are **likely exposed by version** to a named vulnerability, using only the version the server itself advertises. It never sends anything to test exploitability. The first entry is **PHP2Shell**: CVE-2026-109618 and CVE-2026-109619, CVSS v4 9.2, exploitation attempts reported in the wild.

| Flag | Meaning |
|---|---|
| `PHP2Shell:vulnerable` | Advertised PHP is below its branch's fixed release (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, released 2026-10-21) |
| `PHP2Shell:eol-branch` | PHP 8.1 or older: no upstream release; only vendor/backported builds are fixed |
| `+mod_php` | The PHP token appears in an Apache `Server` header, which means mod_php, the configuration PHP rates highest-risk |
| `+vendor-build` | Version carries a distro/package suffix (e.g. `8.1.2-1ubuntu2.20`); the fix may be backported, so check the package changelog |
| `PHP2Shell:version-hidden` | PHP was detected (cookie, framework) but `expose_php` hides the version; verify on the host |

The `Advisories` column holds the reasoning for each finding, including "fixed" results, so coverage is auditable. The HTML report counts exposures on its own card, and the `-BaselineCsv` delta tracks the column, so patching shows up as CHANGED.

**Limits:**
- A hidden or rewritten header gives no version.
- Distro packages can backport fixes without changing the upstream version.
- The follow-on CVE-2026-115560 (session upload progress) has no fixed release yet, so it is not flagged by version. PHP's interim mitigation is `session.upload_progress.enabled=0`.

Treat these flags as a prioritised work list for the owning teams, not as confirmed vulnerabilities. Advisories are a data table (`$Advisories` near the top of the script), so another product/CVE pair can be added with a version regex, the fixed releases and the oldest fixed branch.

## Changes in 2.6.0
- **JSONL outputs:** `_errors.jsonl` (every run), `_delta.jsonl`, `_screenshots.jsonl`, and a `.jsonl` for every
  store query. Errors logged before the output files open are held and written when they do.
- **`-NvdFeed` on scan runs:** `_vulns.csv`/`.jsonl`/`.provenance.json` from `WebInv.Vulns.Run` over the run's own
  services.
- **`run.json`:** `runUuid`, `engagement`, `exitCode`; the exit code is now worked out before `run.json` is
  written. The store ignores the new fields.
- **Tideline shipping:** `-ShipTo`, `-ShipCertThumbprint`, `-ShipCertPath`, `-ShipCertPasswordFile`, `-ShipCaFile`,
  `-Engagement`, `-ShipRetries`; companion `Send-WebInventoryRun.ps1`; `SHIPPING.md`. The C# (`src/ship.cs`) is
  compiled only when shipping and is embedded in the companion scripts as well.
- **Sensor enrollment:** `Register-WebInventorySensor.ps1` (step-ca JWK token; `certreq.exe` on Windows, PFX
  elsewhere; renewal through step-ca's rekey endpoint).
- **Schemas:** `schemas/*.schema.json` (JSON Schema 2020-12), generated by `tools/schemas/gen.py`; CI checks they
  match the source.
- **Self-test:** 149 checks (156 on Windows): adds the shipping code (JSON round trip, sensor names, the ES256
  signature, the pinned chain, run collection, chunking, gzip parts, refusals, option checks).
- **Runtime warnings:** compiler warnings are no longer printed under PowerShell 7.5+, where .NET 9 marks some
  certificate APIs obsolete. CI still compiles every block warning-free with Windows PowerShell 5.1's compiler.
- **CI:**
  - the shipping suite against the mock ingest;
  - enrollment against step-ca 0.30.2 on PowerShell 7;
  - on Windows PowerShell 5.1: certreq enrollment, a scan shipped over Schannel with the machine key, export,
    renewal and shipping again.

## Changes in 2.5.0
- **Cloud/CDN attribution:** `WebInventory.cloud.json` (`tools/cloud/build.py`, refreshed weekly), engine lookup
  `WebInv.Cloud` (longest prefix, IPv4/IPv6/mapped), new columns `Cloud`, `CloudRegion`, `CloudService`,
  `-CloudFile`, `-NoCloud`. The file is loaded only when a service on a public address answers.
- **`-Cname`, `-DnsServer`:** new column `Cname`. Windows `DnsQuery_W`, otherwise UDP (RFC 1035 parser with
  compression and loop guards).
- **Screenshot checks:** `WebInv.Png` (8-bit PNG decoder) and `WebInv.ShotCheck`; the capture also records the final
  URL, the main document's status and the visible text length. Index columns `Reason`, `BrowserUrl`,
  `BrowserStatus`, `Capture`; the HTML report shows the status of every capture that is not ok.
- **Exit code 4** when a completed run found no open service; a run whose every target name failed to resolve also
  exits 4.
- **RDP:** the certificate through a raw ClientHello when Schannel cannot handshake (`CertSource` `rdp-raw`). The
  engine's raw hello (`Tls.HelloOn`) now runs on an existing stream; the HTTPS path is unchanged.
- **Store:** `Cname` and the cloud columns are material and gated (`cname`, `cloud` profile flags). Their first fill
  is `Enriched`; `run.json` records the cloud range version and `-DnsServer`.
- **Rules:** `b:m-forgejo`, `b:b-forgejo` (exclude Gitea), 515 built-in rules. The CPE supplement (2026.11.06.2)
  clears `cloudflare:cloudflare` from the CDN detection. The Wappalyzer pack was re-imported from the same upstream
  commit; only the five Cloudflare rules changed.
- **Self-test:** 139 checks (146 on Windows), adding:
  - the cloud lookup (longest prefix, IPv6, mapped addresses, bad entries, private addresses, the shipped file);
  - CNAME over UDP against a loopback responder (chain, no CNAME, not in DNS, no answer, compression loop);
  - the PNG decoder (all five filter types);
  - the screenshot rules.
- **CI:** the cloud lookup is cross-checked against a Python longest-prefix oracle (40,000 addresses). CNAME chains
  are compared with `Resolve-DnsName` on Windows and `dig` on Linux.

## Changes in 2.4.1
- **Windows PowerShell 5.1:** the engine compiles (OID parser without a sign-extended OR, CS0675); every C# block is
  compiled with `IgnoreWarnings`; the prefilter folds the Kelvin sign, long s and dotted/dotless I onto ASCII on
  every runtime; `Test-WebInventoryStore.ps1` resolves its default `-Script` path in the body.
- **CI** (`.github/workflows/check.yml`): compiles the three C# blocks with Windows PowerShell 5.1's compiler and
  fails on any warning; runs `-SelfTest`, `-TestRules` and `Test-WebInventoryStore.ps1` there and on PowerShell 7;
  reports every failing check as an annotation on the commit or pull request.
- No change to what is scanned or reported (lab and 200-service farm identical to 2.4.0, `PERFORMANCE.md`).

## Changes in 2.4.0
- **`-VersionPaths`** (off by default): one GET to the version URL of each product detected without a version, at
  most 4 per service, no redirects, no credentials. Engine: version-only rules may carry `"get"` (validated path;
  field `path:<get>.<part>`), and `Matcher.VersionPaths` returns the paths of detected, version-less products only.
  Worker: the step runs after every other observation of the service and re-evaluates the row only when something
  was fetched. New CSV/JSONL column `VersionPaths` (79 columns); run.json profile `versionPaths`; the store gates the
  column like `IdentifiedPaths`.
- **Rules:** 8 new version-only rules (Netdata `Server` header and `/api/v1/info`, Flink, Plex, Vaultwarden, Argo
  CD, Mailman, Sitecore), 114 in all; `b:t-vaultwarden` detects current Vaultwarden web vaults again (513 built-in
  rules). The 21 products that stay without a version are recorded with their reason.
- **CPE supplement:** alias groups for Atlassian Jira (Server / Data Center names) and Varnish (both editions), 184
  groups.
- **Repository:** `tools/refresh/` and `.github/workflows/refresh-lists.yml` (weekly refresh of every external list
  as one pull request), `.github/workflows/check.yml` (Windows PowerShell 5.1 and PowerShell 7 checks on every push
  and pull request); `docs/web-inventory-coverage.md` (renamed from the 2.3.2 table; regenerated with each release
  and refresh); `docs/web-inventory-v2.4.0-run-recon.md`.
- **Self-test:** 133 checks (140 on Windows): `VersionPaths` returns the path for a detected product without a
  version and nothing once a version is captured or when the product is not detected; the fetched response adds the
  version; a `get` on a detection rule or with a `..` segment is refused.
- **Results:** default scans unchanged except Netdata (gains its version) and Vaultwarden (detected again); A/B in
  `PERFORMANCE.md`.

## Changes in 2.3.2
- **Version-only rules:** 106 rules (`v:` ids) in the built-in pack read the version of 92 products whose
  detection rules capture none. Engine: rule outputs with `"vo": true` only join a detected product (kind + CPE
  product, or kind + name), never create, rename, re-rate or ungate one, and rank below a captured detection version
  but above a version written into a rule. `build.py` appends `src/version-rules.json` (generated by
  `tools/version/gen_rules.py`) to the embedded pack.
- **Rule option `b`:** `"o": "b"` matches a rule against the base64 decoding of the value (UTF-8; a value that is
  not base64 is skipped). n8n publishes its release only inside the base64 JSON of its `n8n:config:sentry` meta tag.
- **Tooling:** `tools/version/` (development suite): the reviewed rules and the products reviewed without one
  (`rules.py`), coverage, a container lab that records exactly what a scan receives from a product image, a
  WordPress plugin lab, and a replay that feeds recordings through the scanner's own matcher.
- **Self-test:** 131 checks (138 on Windows): version-only outputs never create a detection, add their version in
  either evaluation order without changing confidence or category, never replace a captured version, never lift a
  `requiresCategory` gate, and replace a version written into a rule; a base64 rule matches the decoded value only;
  built-in and `v:` rule examples must all pass.
- **Results:** `Products`, `CPEs` and JSONL detections gain versions; nothing else in a scan changes (A/B in
  `PERFORMANCE.md`). The first store run after the upgrade records `changed` events for those services.

## Changes in 2.3.1
- **CPE coverage:** 715 more rule outputs carry an NVD CPE (built-in rules edited; Recog and Wappalyzer packs
  regenerated from the same commits with the reviewed `cpe-supplement`, which `-ImportRules` now applies); 12 wrong
  upstream CPEs corrected or cleared.
- **Vulnerability join:** compares each CPE under all NVD names of its product (183 alias groups); version-unknown KEV
  rows are no longer listed for general-purpose operating systems (counted instead); percent-encoded CPE names
  (`tcp%2fip`) are decoded; the provenance file records the table version and both counts.
- **Docs:** README column count (78) and a duplicated JA4S licence sentence fixed.
- **Self-test:** 125 checks (132 on Windows): CPE key parsing, the supplement's fill/replace rules (including no CPE for a
  fixed version), built-in rules consistent with the supplement, alias matching, alias-platform exclusion and the OS KEV
  rule in the NVD correlation test.

## Changes in 2.3.0
- **Known vulnerabilities offline:** `-StoreQuery Vulnerabilities` with `-NvdFeed`, `-KevFile`, `-EpssFile`
  (version-aware CPE matching, KEV and EPSS columns, provenance sidecar).
- **Jump hosts:** `-Proxy` / `-ProxyCredential` (HTTP CONNECT) for every TCP connection of the scan.
- **TLS fingerprints:** `-TlsFingerprint` adds `Jarm` (validated against `jarm.py`) and `Ja4s` (validated against FoxIO's
  `ja4.py`).
- **Beyond web:** `-Smb`, `-Rdp`, `-Snmp` (with `-SnmpCommunity` or `-SnmpCredential`; never a guessed community) and
  `smb://`, `rdp://`, `snmp://` targets; new columns `DeviceName`, `Domain`, `ProtocolInfo`; flags `SMBv1`,
  `SMBSigningNotRequired`, `RdpNlaNotRequired`, `RdpStandardSecurity`, `SnmpV1V2c`; 37 new built-in rules (Windows
  builds from NTLM, SNMP sysDescr); the Recog pack regenerated from the same commit with the SNMP, SMB and JARM
  databases (2,369 -> 3,098 rules; the existing rules are unchanged).
- **Screenshots:** `-Screenshot` with the host's Edge, headless, confined to the scanned origins by a loopback proxy;
  index CSV, manifest entries, images in the HTML report.
- **Store:** `-StoreMerge` / `-StoreSplit` corrections as ledger entries, `-Backfill` for older runs (rebase entry),
  `-SnapshotEvery`, `-AnchorEventLog` / `-RegisterEventSource`, `-AnchorCertificate`, `Enriched` events, unique query
  file names, Inventory queries filter while reading. Stores made by v2.2 open, verify and ingest unchanged (same
  digests; the five new fields are empty in old versions and do not enter their hashes).
- **Scan path:** the v2.2 engine with two additions only: the connect routine can tunnel through a proxy (one branch
  when `-Proxy` is not set) and the TLS probe keeps the ServerHello's extension list for JA4S. A scan without the new
  switches sends the same traffic as v2.2 (A/B in `PERFORMANCE.md`).
- **Self-test:** 121 checks (128 on Windows): JARM/JA4S/NTLM/SNMPv3-key vectors, protocol URLs, the screenshot scope
  proxy, NVD/KEV/EPSS correlation on a hand-made feed, corrections on every engine, an interrupted correction,
  backfill and snapshot thinning.

## Changes in 2.2.0
- **Inventory store** (`-Store`, `-ImportRun`, `-StoreQuery`, `-VerifyStore`, `-RebuildStore`; see "Inventory store"):
  history across runs in Windows' built-in ESENT engine, rebuilt on demand from an append-only archive of every run
  with a hash-chained ledger. Portable file engine for PowerShell 7 elsewhere.
- **Scan unchanged:** the scan engine is v2.1.0's source (version constant aside); the store compiles separately, on
  first use, after the scan. Interleaved A/B against v2.1.0: identical output field by field in every comparison,
  timings within run-to-run noise, about 0.1 s more startup (`PERFORMANCE.md`).
- **`_run.json`** per run: start/finish, probe switches, sessions of a resumed run, completeness. The store relies on
  it; older output is imported with a synthesised one.
- **Self-test:** 106 checks (111 on Windows): store engine compile, SHA-256 accumulator, key-value engine contract on every engine, a
  synthetic three-run history with exact expected counts, ESENT-vs-portable digest equality, crash repair at three
  points per engine, tamper detection, rebuild, queries.
- **`Test-WebInventoryStore.ps1`:** validates the store on the scanner host (ESENT vs portable digests, hard kills,
  verify, cross-engine rebuild).

## Changes in 2.1.0
- **Performance:** see "What v2.1 changes" and `PERFORMANCE.md`. Web-heavy scans about 3.2x faster with 70% less CPU;
  closed-port sweeps about 11.6x faster with a sixth of the memory.
- **Accuracy under load:** the v2.0.2 farm benchmark lost HTTPS services and detections in every run (rule regex
  timeouts and stalled TLS handshakes on a saturated 2-core host); v2.1.0 matched the reference in every run.
- **Robustness:** connects no longer depend on the .NET thread pool; local port/buffer exhaustion is retried, logged and
  marked `incomplete` instead of looking like a filtered port; a worker that crashes mid-check is replaced and the check
  is logged as failed.
- **Self-test:** 92 checks, adding the prefilter, C# parser and writer, scheduler, job builder, DNS window, connect
  states and silent-listener detection (loopback listeners only, no network).

## Changes in 2.0.2
- **PHP2Shell version advisory:**
  - flags and an `Advisories` column
  - HTML "Advisory exposures" card
  - included in the baseline delta
- **Wappalyzer false-positive guard:** a bare-word header pattern must start at a word boundary (145 patterns). Upstream "Bun" matched `PHP/8.1.2-1ubuntu2` as the Bun runtime.
- **HTML report hygiene:** control characters from hostile headers are stripped from report data.
- **Self-test:** 78 checks (advisory version logic, suffix parsing, mod_php inference).

## Changes in 2.0.1
- **Wappalyzer pack shipped** (7,824 rules), with the GPL-3.0 text and upstream commit.
- **Engine:**
  - `rc` (requires category) gating
  - `a` option for whole-value anchors
  - JavaScript-to-.NET regex translation (`FromJs`)
  - implied technologies inherit kind/category/CPE
- **Converter fixes:** regex-escaped Wappalyzer cookie names (`connect\.sid`) now match. Both importers record the upstream git commit in the pack.
- **Self-test:** 72 checks (JS dialect, anchors, category gate).

## Original backlog status
| Item | Status |
|---|---|
| Virtual hosts from certificate SANs | Done: `-ProbeSans` (same IP only, de-duplicated) |
| Reverse DNS | Done: `-ReverseDns` (cached, with timeout) |
| ALPN / HTTP/2 | Done: raw ClientHello probe (`Alpn`, `Http2` columns) |
| TLS version enumeration | Done, and wider than planned: raw ClientHellos for SSL3 to TLS 1.3, independent of Schannel, plus weak-cipher acceptance |
| Resume / checkpoint | Done: progress file + `-Resume` |
| HTML report | Done |
| Recog import (replace the 60 embedded rules) | Done: `-ImportRules`, shipped pack, plus 475 embedded rules |
| Wappalyzer pack | Done (2.0.1) |
| HTTP CONNECT proxy | Done (2.3.0): `-Proxy` |
| JARM | Done (2.3.0): `-TlsFingerprint`, with JA4S |
| What not to add | Respected: no brute-forcing, default-credential checks, non-detection Nuclei templates or aggressive WhatWeb levels |

## Further recommendations (not implemented)
1. **Screenshots in the store.** Screenshots stay in `-OutputDir`; archiving them (and diffing them across runs) would
   make the store several times larger, so it was left out.
2. **Version capture, continued.** 635 of the 1,326 products with a CPE still get no version by default (629 with
   `-VersionPaths`), mostly because nothing a scan receives shows it (the reasons are listed per product in
   `docs/web-inventory-coverage.md`). Six have a candidate that could not be checked here (Sophos Firewall: no image or
   sample of the value; Rancher: its image needs a cgroup v2 host; QNAP QTS (service and OS), N-central, Contao: no sample of how the
   version is printed); `tools/version/coverage.py` lists them as `unverified`. The weekly refresh pull request lists
   new candidates as upstream databases add them.
3. **Hosting attribution, continued.** Akamai's CDN, IBM Cloud, Alibaba Cloud, Hetzner and OVH publish no
   machine-readable range list, so their addresses stay unattributed (their CNAMEs, with `-Cname`, usually name
   them). SAN virtual hosts get no CNAME lookup.
