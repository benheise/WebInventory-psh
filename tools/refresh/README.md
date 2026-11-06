# External list refresh

WebInventory is built from lists maintained elsewhere. `refresh.sh` pulls the newest version of each, rebuilds what
depends on it, runs the offline tests and writes a summary. `.github/workflows/refresh-lists.yml` runs it every Monday
and opens (or updates) one pull request, `refresh/external-lists`, with that summary; nothing is merged without review.

| List | Upstream | What is rebuilt | Applied automatically? |
|---|---|---|---|
| Rapid7 Recog fingerprints | `rapid7/recog` (`xml/`) | `dist/WebInventory.rules.recog.json` with `-ImportRules` (the embedded CPE supplement is applied while importing; rules .NET cannot compile, or that fail their own example, are dropped) | yes, when the upstream commit changed |
| webappanalyzer (Wappalyzer data, GPL-3.0) | `enthec/webappanalyzer` | `dist/WebInventory.rules.wappalyzer.json` (passive HTTP patterns only) | yes, when the upstream commit changed |
| NVD CPE Dictionary 2.0 | `nvd.nist.gov/feeds/json/cpe/2.0/` | `src/cpe-supplement.json`: every reviewed name must still exist; a retired name follows its single successor | only machine-checkable changes; new product mappings are listed for review (`tools/cpe/decisions.py` stays hand-reviewed) |
| NVD CVE 2.0 feeds, CISA KEV | `nvd.nist.gov/feeds/json/cve/2.0/`, `cisa.gov` | CVE/KEV counts per CPE for the CPE candidates and the coverage table | the table only changes together with another list |
| nuclei-templates, WhatWeb | `projectdiscovery/nuclei-templates`, `urbanadventurer/WhatWeb` | `tools/version/external.json`: which public database extracts a version for which product | yes; new candidates are listed for review |
| version coverage table | (all of the above) | `docs/web-inventory-coverage.md` | yes |

The version-only rules (`tools/version/rules.py`) are not changed by a refresh: each needs a container, source or
sample check. The refresh only verifies that every one still joins a detection rule after the packs changed, and fails
the check when one does not (an upstream rename, for example).

The NVD, KEV and EPSS files that `-StoreQuery Vulnerabilities` reads on the scanner host are not in the repository;
operators download them as the operator guide describes.

## Checks

`refresh.sh` fails the run (exit 11, and the pull request title says so) when:

- a reviewed CPE name is no longer in the NVD dictionary,
- a pack import fails,
- a version-only rule no longer finds its detection rule,
- `-SelfTest` or `-TestRules` fails on PowerShell 7.

The workflow then runs `-SelfTest`, `-TestRules` and `Test-WebInventoryStore.ps1` on Windows PowerShell 5.1 against
the pull request branch and comments the result. `.github/workflows/check.yml` runs the same Windows and Linux
checks on every push to `main` and every pull request opened by a person.

## Running it by hand

Needs bash, git, curl, Python 3 with PyYAML, and PowerShell 7 (`pwsh`).

```bash
bash tools/refresh/refresh.sh --work /tmp/wi-refresh            # downloads everything (about 600 MB)
bash tools/refresh/refresh.sh --work /tmp/wi-refresh --feeds D/feeds --cpedict D/cpedict --sources D/src
cat /tmp/wi-refresh/summary.md
```

`--feeds` takes a folder with `nvdcve-2.0-*.json.gz` and `known_exploited_vulnerabilities.json`, `--cpedict` one with
`nvdcpe-2.0.tar.gz` (or its extracted `nvdcpe-2.0-chunks`) and `nvdcpe-2.0.meta`, `--sources` one with checkouts named
`recog`, `webappanalyzer`, `nuclei-templates` and `WhatWeb`. Start from a clean checkout: the exit status reports
whether the refresh changed any file. Exit 0 = nothing changed, 10 = changed and all checks passed, 11 = changed and a
check failed.

## Repository settings

- Settings > Actions > General > Workflow permissions: allow GitHub Actions to create and approve pull requests
  (the workflow's token opens the pull request).
- GitHub suspends scheduled workflows in a public repository after 60 days without activity; a merge of a refresh
  pull request counts as activity.
