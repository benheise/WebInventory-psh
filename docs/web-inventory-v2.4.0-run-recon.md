# WebInventory 2.4.0 compared with run-recon

The features and code of WebInventory 2.4.0 checked against the run-recon repository (`benheise/run-recon`):
`main` at 59e48b3 (v1.19.0, 2026-11-05) and the newest branch, `batch-3-email-dns` at 54ef6af (1.20.0-dev,
2026-11-06). WebInventory stays standalone: nothing here makes it depend on run-recon. The comparison only looks for
capabilities, fixes and data that WebInventory can use within its own rules (inventory only; no exploitation, brute
force, default credentials or path enumeration; no loss of accuracy).

## Two different jobs

| | WebInventory | run-recon |
|---|---|---|
| Purpose | Agentless inventory of the services on the hosts and ranges you list (CMDB replacement) | External attack-surface mapping: seed domains to every URL found on them |
| Form | One PowerShell 5.1 script with an inline C# engine; no installs, no external binaries | Bash pipeline around about 40 OSS tools (ProjectDiscovery httpx, katana, tlsx, dnsx, nuclei, naabu, subfinder, ffuf, wpscan, …) installed by a setup script |
| Where it runs | Windows scanner host inside the network (also PowerShell 7 on Linux) | Kali / Debian / WSL with internet egress |
| Traffic | Connect scan, GET / and same-host redirects, favicon, robots.txt, security.txt, one 404 probe; opt-in probes | Passive collectors, crawling, validation; opt-in brute force, fuzzing and nuclei scans |

Most differences follow from that: run-recon discovers names and URLs, WebInventory identifies what answers on a
given address.

## Feature map

"WI" = WebInventory 2.4.0, "RR" = run-recon on `batch-3-email-dns`.

| Capability | WI | RR | For WebInventory |
|---|---|---|---|
| Scope | fail-closed `-Scope`/`-ScopeFile`, `-ListTargets` dry run, redirects and SAN vhosts held to it | per-seed filter on discovered names; scope file and dry run planned (its batch 4) | WI ahead |
| Port and protocol detection | connect scan, HTTP/TLS on any port, banners | naabu (`--ports`), httpx | parity in approach |
| Host and name discovery | none by design: only the targets given, plus SAN names that resolve to the same IP | subfinder, CT logs, permutations, DNS brute force, zone transfer / NSEC walk, TLD variants, cloudlist, favicon and certificate pivots | out of scope (enumeration and brute force are excluded) |
| HTTP fields (final URL, redirect chain, auth, cookies and flag gaps, security headers, HSTS, Alt-Svc, body hash, response time) | yes | yes since v1.19 (ported from WI); per-URL `Location` instead of the followed chain | parity |
| Favicon, robots.txt, security.txt, 404 probe | default | opt-in (`--extras`) | parity |
| Password form over plain HTTP | `CleartextAuth` (also Basic/Digest over HTTP) | `CleartextAuth` from the auth header only; form detection planned | WI ahead |
| Fingerprint rules | 11,549 rules: built-in, version-only, Recog (HTTP, TLS, SSH/FTP/SMTP banners, SMB, SNMP, JARM) and webappanalyzer | httpx tech detection (Wappalyzer data) and the `Server` header | WI ahead |
| CPE names | 1,327 products with a reviewed NVD CPE, plus 184 alias groups for split NVD names | a hand table of 58 products (`--cpe-map` file to extend it) | WI ahead; the cross-check found two alias gaps in WI (fixed, below) |
| Versions | 697 of those products get a version (691 without `-VersionPaths`) | whatever httpx reports | WI ahead |
| TLS posture | version matrix, ciphers, weak ciphers, key and signature strength, chain validation, JARM, JA4S | negotiated version and cipher, expiry, self-signed, name mismatch, chain validation, JARM (`--origin`) | WI ahead (RR plans the matrix) |
| SMB / RDP / SNMP identity | opt-in, no login | none (not planned: internal probes) | WI only |
| Cloud provider, RDAP owner, geolocation per IP | none (reverse DNS only) | `--enrich` from the providers' published IP-range lists, RDAP, MaxMind | candidate (recommendation 1) |
| CNAME inventory, dangling CNAME | none | `--takeover` | candidate for hostname targets (recommendation 4); the takeover check itself is out of scope |
| CDN / edge detection, origin search | CDN products detected from headers and cookies | `--origin`: edge per host, then verified origin candidates | origin search is out of scope (it probes other hosts) |
| Email and DNS posture (SPF, DMARC, MTA-STS, CAA, dangling MX/NS) | none | `--dns-posture` | out of scope (not service inventory) |
| Active testing (nuclei, ffuf/feroxbuster, wpscan and other CMS scanners, parameter and secret discovery, bucket enumeration) | none | opt-in | excluded by design |
| Screenshots | headless Edge, confined to the scanned origins by a scope proxy | httpx / gowitness, routed like httpx; every capture classified ok / blank / failed / suspect | candidate: capture validation (recommendation 2) |
| History | inventory store (ESENT or file): first/last seen, change events, retirement, append-only archive, hash-chained ledger | PostgreSQL cache and per-run host rows; first/last seen planned | WI ahead |
| Vulnerability join | offline NVD 2.0, KEV, EPSS | offline NVD, KEV, EPSS; optional online `--vulnx` | parity; WI stays offline |
| Run record | `run.json`, SHA-256 manifest, field-level delta, CSV/JSONL/HTML | `run.json` with tool versions and warnings, exit status 3 when a run found nothing | candidate: WI's 3 means interrupted; an empty run exits 0 (recommendation 3) |
| Dependencies | none at run time; rule packs record their upstream commit and SHA-256 in the run log | about 40 tools, versions pinned, a warning when one is not the lab-verified version | WI's equivalent is the list refresh (`tools/refresh`, new in 2.4.0) |
| Lab, A/B, "no slower, identical output" | yes | yes (the same method) | parity |

## Code checks: run-recon's findings applied to WebInventory

run-recon's TOOL-COVERAGE.md lists what running the real tools showed. Each was checked against WebInventory:

| run-recon finding | WebInventory |
|---|---|
| 9: under load the live probe lost HTTPS (all HTTPS attempts failed in a spike, host recorded as `http://` only); fixed with a late retry | Not reproduced. WebInventory uses its own socket code, not an external prober. Three runs on the 200-service farm at `-Pace Fast -Threads 128 -MaxPerHost 8` gave 200/200 web services and 50/50 TLS services each time, the same as the reference run. No change. |
| 10: no CSV formula-injection guard | Present since 2.0 (`WebInv.Out`: cells starting with `= + - @`, tab or CR are prefixed). |
| 7: a tool ignored the configured resolvers and proxy | One network path for every request. With `-Proxy`, names still resolve on the scanning host, which the guide already says; give IP addresses when the jump host sees different DNS. No change. |
| httpx without `-nfs` probed `http://` inputs over HTTPS | An explicit scheme fixes the order (`https://` → TLS only, `http://` → plain only). No change. |
| A single dropped connection blanked a row (fixed with retries) | Same farm runs as above: no blank rows. Connect retries on silence and the plaintext-400 → TLS fallback cover the cases seen so far. |
| Pinned tool versions, warning when a version is not lab-verified | Rule packs carry their upstream commit; the run log records each pack's version, SHA-256 and source. The new `tools/refresh` workflow rebuilds them from upstream and runs the tests before anything is merged. |
| Product → CPE table | Cross-checked against WebInventory's 1,327 CPE names. Two gaps found in WebInventory, fixed in 2.4.0 (below). |

### Fixed from the CPE cross-check

| Product | Before | 2.4.0 | Effect (NVD 2002–2026, KEV) |
|---|---|---|---|
| Atlassian Jira | `atlassian:jira` only | alias group `atlassian:jira`, `jira_server`, `jira_data_center`, `jira_software_data_center`, `jira_server_and_data_center` | a Jira 8.20.0 service: 2 rows → 18 rows, 1 of them KEV (NVD files most Server / Data Center CVEs under those names) |
| Varnish | `varnish-software:varnish_cache` (the LTS edition's name, 7 CVEs) | alias group with `varnish_cache_project:varnish_cache` (14 CVEs, 1 KEV), `varnish-cache:varnish_cache`, `varnish-cache:varnish` | a Varnish 6.0.10 service: 1 row → 3 rows, incl. KEV CVE-2023-44487 |

Both are alias groups in `tools/cpe/decisions.py`, so they only widen the vulnerability join; no detection changes.

### Noted for run-recon (not changed here)

- Its CPE table maps Jira only to `atlassian:jira` and Varnish only to `varnish_cache_project:varnish_cache`, so it
  misses the same Jira Server / Data Center entries and the LTS edition's.
- It has no version-only rules; products that httpx names without a version (a title, a cookie) stay
  version-less, which WebInventory's 2.3.2 work showed is about half of all products with a CPE.

## Recommendations for WebInventory

All four were implemented in 2.5.0 (`web-inventory-v2.5.0.md`): cloud and CDN attribution
(`Cloud`/`CloudRegion`/`CloudService`), screenshot checks (ok/blank/suspect/failed), exit code 4 for a run in which
nothing answered (3 stayed "interrupted"), and `-Cname`.


1. **Hosting attribution.** A `Cloud` column from the IP ranges the providers publish (AWS `ip-ranges.json`, Azure
   Service Tags, Google `cloud.json`, Cloudflare `ips-v4`/`ips-v6`, Oracle, DigitalOcean). Offline lookup, no
   traffic to the targets; the lists would be refreshed by the same workflow as the rule packs. Useful for DMZ and
   public ranges; internal addresses stay empty.
2. **Screenshot validation.** Classify each capture (ok, blank, error page, failed) as run-recon does, so a blank
   capture is not taken as evidence.
3. **Exit status for an empty run.** The exit codes are 0 clean, 1 fatal or refused, 2 completed with logged errors,
   3 interrupted. A scheduled run in which nothing answered (network down, all names unresolved) exits 0 like a quiet
   success; a distinct code would let the scheduler alert.
4. **CNAME for hostname targets.** Record the CNAME chain of a hostname target as inventory data (which load
   balancer or SaaS front end a name points at). No takeover verdict.
