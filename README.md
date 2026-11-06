# WebInventory (Invoke-WebInventory.ps1)

Non-intrusive web service discovery and fingerprinting for Windows PowerShell 5.1 (also PowerShell 7), built as a
standalone CMDB replacement. One script, no installs, no external binaries: TCP connect, HTTP/HTTPS detection on any
port, product/version/CPE identification from 11,549 rules, certificate and TLS posture, hygiene flags, and opt-in
SMB/RDP/SNMP identity, written to CSV, JSONL and HTML. An optional inventory store keeps first/last seen, versions and
a change log per service on an append-only, hash-chained archive, and can be joined offline with NVD, CISA KEV and
FIRST EPSS files.

It is an inventory tool only. It does not exploit, brute-force, guess credentials or enumerate paths. The only
credentials it ever uses are an SNMP community or SNMPv3 user you supply. Requests beyond the default set are opt-in:
`-IdentifyPaths` (16 fixed public pages) and `-VersionPaths` (one GET to a product's documented version URL, only
after that product was detected without a version).

**Current release: 2.4.0** (opt-in version URLs for detected products, `-VersionPaths`; Jira and Varnish CPE
aliases from a comparison with run-recon; the external lists refresh themselves through a weekly pull request). See
[`docs/web-inventory-v2.4.0.md`](docs/web-inventory-v2.4.0.md) and
[`docs/web-inventory-v2.4.0-run-recon.md`](docs/web-inventory-v2.4.0-run-recon.md); 2.3.2 (version capture):
[`docs/web-inventory-v2.3.2-versions.md`](docs/web-inventory-v2.3.2-versions.md); 2.3.1 (CPE coverage):
[`docs/web-inventory-v2.3.1-cpe.md`](docs/web-inventory-v2.3.1-cpe.md).

## Use

Everything an operator needs is in [`dist/`](dist):

| File | Purpose |
|---|---|
| `Invoke-WebInventory.ps1` | The tool (engine, built-in and version-only rules and the CPE supplement embedded) |
| `WebInventory.rules.recog.json` | 3,098 Rapid7 Recog rules (BSD-2), auto-loaded next to the script |
| `WebInventory.rules.wappalyzer.json` | 7,824 webappanalyzer rules (GPL-3.0 data), auto-loaded; refreshed by the weekly pull request |
| `WebInventory.example.psd1` | Settings template for scheduled runs |
| `Test-WebInventoryStore.ps1` | One-off store validation on the scanner host |
| `README.md` | Full operator guide |
| `PERFORMANCE.md` | Measured performance and A/B records |
| `THIRD-PARTY-NOTICES.txt`, `LICENSE-GPL-3.0.txt` | Licences and upstream provenance |
| `SHA256SUMS.txt` | Hashes of the files above |

```powershell
.\Invoke-WebInventory.ps1 -SelfTest                                   # offline checks
.\Invoke-WebInventory.ps1 10.0.0.0/24 -ListTargets                    # expand + scope-check only; sends nothing
.\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -ScopeFile .\authorized.txt -Pace Polite -BaselineCsv auto
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Vulnerabilities -NvdFeed D:\feeds\nvd `
    -KevFile D:\feeds\known_exploited_vulnerabilities.json -EpssFile D:\feeds\epss_scores-current.csv.gz
```

Scan only what you are authorised to scan; `-ScopeFile` mirrors the written authorisation and out-of-scope targets
are refused.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | Sources: PowerShell sections (`10-header.ps1` … `60-main.ps1`), the C# engine, store and probe blocks, `builtin-rules.json`, `version-rules.json` (generated), `cpe-supplement.json`, the self-test certificate (public part only) |
| `build.py` | Assembles `dist/Invoke-WebInventory.ps1` (UTF-8 BOM, CRLF) and `dist/Test-WebInventoryStore.ps1` |
| `dist/` | Built release files (byte-exact; see `.gitattributes`) |
| `docs/` | Decision records (v2.3, v2.3.1, v2.3.2, v2.4.0), the run-recon comparison, the per-product version coverage table and the product sheet |
| `lab/` | Local lab fixtures: web farm, TLS, CONNECT proxy, RDP, SNMP agent, screenshot pages (127.0.0.1 only) |
| `tests/` | Regression scenarios, C# compile check, PSScriptAnalyzer profile run, store scenarios, performance A/B harness |
| `tools/cpe/` | Rebuilds the CPE supplement from a newer NVD CPE Dictionary; see its README |
| `tools/version/` | The reviewed version-only rules (`rules.py` → `src/version-rules.json`), coverage, and the container, WordPress and replay harnesses that check them; see its README |
| `tools/refresh/` | Pulls the newest upstream lists (Recog, webappanalyzer, NVD CPE Dictionary and CVE feeds, CISA KEV, nuclei-templates, WhatWeb), rebuilds, tests and summarises; see its README |
| `.github/workflows/` | `refresh-lists.yml`: the refresh every Monday as one pull request, with the Windows PowerShell 5.1 checks; `check.yml`: build reproducibility, self-test, rule examples and store validation on Windows PowerShell 5.1 and PowerShell 7 for every push and pull request |

## Build and test

```bash
python3 build.py                                  # writes dist/Invoke-WebInventory.ps1
pwsh ./dist/Invoke-WebInventory.ps1 -SelfTest     # 133 checks on PowerShell 7 (140 on Windows with ESENT)
# lab regression scenarios (Linux; needs python3 + openssl; certificates are generated, never committed)
bash lab/make-certs.sh /tmp/wi-certs
bash lab/with-lab.sh /tmp/wi-certs bash tests/scenarios.sh pwsh "$PWD/dist/Invoke-WebInventory.ps1" /tmp/wi-work
```

Inline C# targets C# 5 / .NET Framework 4.7.2 so the script compiles on stock Windows PowerShell 5.1;
`tests/cscheck.ps1` checks that against the reference assemblies. The `Check` workflow runs the self-test, the rule
examples and `Test-WebInventoryStore.ps1` on Windows PowerShell 5.1 for every push and pull request.

## Keeping the lists current

`tools/refresh/refresh.sh` (run weekly by `.github/workflows/refresh-lists.yml`) pulls the newest version of every
external list WebInventory is built from and opens one pull request, `refresh/external-lists`, with the rebuilt rule
packs, the regenerated coverage table and a summary of what changed upstream. The CPE mappings
(`tools/cpe/decisions.py`) and the version-only rules (`tools/version/rules.py`) stay hand-reviewed: the pull request
lists new candidates and fails its checks when a reviewed name has left the NVD dictionary or a version-only rule no
longer finds its product. Repository setting needed once: Settings > Actions > General > Workflow permissions >
"Allow GitHub Actions to create and approve pull requests". Details: [`tools/refresh/README.md`](tools/refresh/README.md).

## Licensing

Third-party data and methods are listed in [`dist/THIRD-PARTY-NOTICES.txt`](dist/THIRD-PARTY-NOTICES.txt): the
Wappalyzer pack is GPL-3.0 data (keep `LICENSE-GPL-3.0.txt` with it), Recog is BSD-2-Clause, JARM is BSD-3-Clause, and
JA4S follows the FoxIO License 1.1 (internal, non-monetised use; `-NoJa4s` turns it off). NVD data is used under NVD's
terms of use: this product uses data from the NVD API but is not endorsed or certified by the NVD.
