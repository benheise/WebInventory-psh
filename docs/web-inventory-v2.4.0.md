# WebInventory v2.4.0 — version URLs, list refresh, run-recon cross-check

Decision record and implementation notes for v2.4.0. Constraints carried forward: stock Windows PowerShell 5.1 + .NET
Framework 4.7.2 (also PS7), no installs, inventory only (no exploitation, no brute force, no default credentials, no
directory enumeration, nothing at WhatWeb's aggression level 3 or above by default), no loss of accuracy, standalone
tool.

## Problem
After v2.3.2, 27 products with an NVD CPE were filed as "other-url": the version exists, but only at a URL of its own
(Vaultwarden's `/api/version`, Flink's `/config`) that a scan does not request. Reading it needs one more request per
product, which the scan path deliberately does not send, and which WhatWeb would call aggression level 3 (requests
chosen from what was detected).

## Decision
An opt-in switch, `-VersionPaths`, off by default. With it, the version URL of a product is requested only as a
**confirmation step after detection**:

1. The service is scanned as before (GET /, same-host redirects, favicon, robots.txt, security.txt, the 404 probe,
   `-IdentifyPaths` if set, certificate and TLS observations).
2. The engine evaluates every observation. `Matcher.VersionPaths(detections, MinConfidence, 4)` returns the paths of
   version-only rules whose product was detected (by a detection rule, at `-MinConfidence` or above) **without** a
   version captured by a rule. A product that is not detected, is below the confidence floor, or already has a
   version gets no request.
3. The worker sends one GET per path (same scheme, host, port, SNI and Host header as the page; no redirects
   followed; no credentials; no body), at most 4 per service. A path that `-IdentifyPaths` already fetched is not
   requested again. A 200 response is added as `path:<path>.body` / `.header:*` observations.
4. The row is evaluated again. The response feeds only version-only rules, which can add a version to a product
   that is already detected and can never create, rename or re-rate one.
5. The `VersionPaths` column (CSV column 79, JSONL, run.json profile `versionPaths`) lists each request and its
   status, e.g. `/api/version=200`.

Rule format: a version-only rule may name its path with `"get": "/api/version"`; its field must then be
`path:<get>.<part>`. The engine refuses a `get` on a rule with a detection output, a relative path, `.` or `..`
segments, `//`, a query string, or more than 200 characters.

Rejected: sending the requests on every scan (changes the traffic profile of every run for 7 products); a path list
per product kept outside the rules (a second place to review); following redirects from the version URL (a login
redirect would make it a request to a page the rule did not name).

## Results: the 27 "other-url" products
- **Read with `-VersionPaths` (6):** Apache Flink (`/config` "flink-version"; container 1.20.5 and 2.2.1), Plex
  Media Server (`/identity`; container 1.40.0.7998 and 1.43.5.11079), Vaultwarden (`/api/version`; container 1.35.8
  and 1.37.5), Argo CD (`/api/version` "Version"; from its source, development builds not matched), Mailman 2
  (`/mailman/listinfo` footer; WhatWeb and nuclei samples), Sitecore (`/sitecore/shell/sitecore.version.xml`,
  major.minor as NVD numbers it; nuclei sample).
- **Not read (21), each with its reason in the coverage table:**
  - behind a login (other-url): Harbor (`/api/v2.0/systeminfo` returns `harbor_version` only to signed-in users),
    Apache ActiveMQ Classic (`/admin/`), Power BI Report Server (Windows authentication), Ametys, Subrion;
  - only in a POST reply (other-url): Odoo (`/web/webclient/version_info`), VMware vCenter and vCenter Server (SOAP
    `/sdk`);
  - a path that differs per site (other-url): PrestaShop (random back-office folder), phpwcms (installation files);
  - the number is not the release NVD uses (not-version): Cisco UCM (build, NVD uses SU releases), VMware Horizon
    (the HTML Access client's version), Matomo (changelog), Cloudflare (the detection is the CDN edge);
  - no patch level (coarse): Pulse Connect Secure, Pulse Secure (build numbers that map to NVD's releases only
    through Ivanti's table), Zimbra (GA build without the patch level);
  - nothing to verify against (unverified): QNAP QTS (service and OS rows), N-able N-central, Contao.
- **Netdata** (filed as "same CPE captured" before) prints its version in the `Server` header of every response: a
  plain version-only rule, no extra request (container v1.47.5 and v2.12.3; `/api/v1/info` is its `-VersionPaths`
  fallback when a proxy hides the header).
- **Vaultwarden detection.** Current web vaults title their page `Vaultwarden Web`; the Recog rule only knew
  `Vaultwarden Web Vault`, so Vaultwarden was no longer detected at all. A built-in title rule (`b:t-vaultwarden`)
  covers both.
- **Coverage** of the 1,327 products with a CPE: 691 get a version by default (690 in v2.3.2, +Netdata), 697 with
  `-VersionPaths`. Per product: [`web-inventory-coverage.md`](web-inventory-coverage.md) (regenerated with each
  release and by the list refresh; the 2.3.2 table is in the file's history).

## Results: run-recon cross-check
[`web-inventory-v2.4.0-run-recon.md`](web-inventory-v2.4.0-run-recon.md). Its CPE table showed two alias gaps in
WebInventory, fixed as alias groups in `tools/cpe/decisions.py` (vulnerability join only, no detection change):
Atlassian Jira (`jira_server`, `jira_data_center`, `jira_software_data_center`, `jira_server_and_data_center`; a Jira
8.20.0 service goes from 2 to 18 rows, 1 KEV) and Varnish (`varnish_cache_project:varnish_cache` next to the LTS
edition's `varnish-software:varnish_cache`; a Varnish 6.0.10 service goes from 1 to 3 rows, incl. KEV
CVE-2023-44487). Its tool-coverage findings (HTTPS lost under load, CSV formula injection, proxy and resolver
bypass, scheme order, blank rows on a dropped connection) were checked against WebInventory: none reproduced or
already handled. Four recommendations are recorded there, not implemented.

## Results: external lists refresh themselves
`tools/refresh/refresh.sh` pulls the newest Rapid7 Recog, webappanalyzer, NVD CPE Dictionary, NVD CVE feeds, CISA
KEV, nuclei-templates and WhatWeb; rebuilds the two rule packs (only when the upstream commit or the CPE supplement
changed), checks every reviewed CPE name against the dictionary, checks that every version-only rule still joins a
detection rule, regenerates the version-candidate index and the coverage table, runs `-SelfTest` and `-TestRules`,
rewrites `dist/SHA256SUMS.txt` and writes a summary. `.github/workflows/refresh-lists.yml` runs it every Monday,
opens or updates one pull request (`refresh/external-lists`), and runs the Windows PowerShell 5.1 checks on that
branch. Reviewed data (`tools/cpe/decisions.py`, `tools/version/rules.py`) is never changed automatically; new CPE
and version candidates are listed in the pull request for review. `.github/workflows/check.yml` runs the build
reproducibility check, the self-test, the rule examples and `Test-WebInventoryStore.ps1` on Windows PowerShell 5.1
and PowerShell 7 for every push and pull request, so the Windows checks no longer depend on a manual run.

End-to-end test of the refresh (current upstream, real NVD feeds and dictionary, in a scratch copy): webappanalyzer
moved from d91f7e5 to c708f0b, the pack went from 7,824 to 7,874 rules (38 new products, none lost); Recog unchanged;
the supplement unchanged; 1 CPE candidate for review; version-only rules all join; `-SelfTest` 133/133, `-TestRules`
0 mismatches over 11,599 rules; exit 10 (changed, checks passed) after the one script fix the test found.

## Behaviour changes to flag
- Default scans: unchanged traffic. Netdata services gain their version; Vaultwarden services are detected again.
- `-VersionPaths`: up to 4 extra GETs per service, only for detected products without a version (none on the lab
  and the 200-service farm, whose products all have a version or no version URL; `PERFORMANCE.md`).
- CSV: 79 columns (`VersionPaths` appended). Readers that address columns by name are unaffected.
- Store: `VersionPaths` is gated like `IdentifiedPaths`. Switching `-VersionPaths` on or off between runs records the
  versions it adds or no longer adds as `Changed` events, with `versionPaths=1` on one side of `ProfileChange`
  (checked: the Vaultwarden and Flink scans without and with the switch, ingested in order, gave `Changed` on
  `Products`, `CPEs` and `VersionPaths` for exactly those two services); keep the switch consistent per store.
- Vulnerabilities: Jira and Varnish services match more CVEs (the alias groups above).

## Pre-existing, noted, not changed
- Forgejo is also reported as Gitea (Gitea's rules match Forgejo's pages; Forgejo is a fork and NVD lists them
  separately).
- The Cloudflare CDN detection carries the CPE NVD uses for Cloudflare's WordPress plugin; its vulnerability rows
  should be read with that in mind.
