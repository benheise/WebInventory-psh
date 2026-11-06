# Version-only rules

`-StoreQuery Vulnerabilities` can only compare a service with NVD's version ranges when fingerprinting found its
version. Many detection rules identify a product (by a title, a cookie, a favicon) but capture no version, although
the same responses often show it somewhere else: in a footer, a meta tag, an asset URL, a JSON bootstrap block or a
header. A **version-only rule** reads it from there.

```json
{"id":"v:solr","f":"scriptsrc","r":"^libs/angular\\.min\\.js\\?_=(\\d+\\.\\d+\\.\\d+)$","n":"Apache Solr","v":"{1}",
 "p":"cpe:2.3:a:apache:solr:{v}:*:*:*:*:*:*:*","vo":true,"ex":"libs/angular.min.js?_=9.4.1","exv":"9.4.1"}
```

`"vo": true` makes the output version-only (engine: `Matcher.Aggregate`):

- it never creates a detection: it only joins a product another rule detected (same kind and CPE product, or the
  same name) and is discarded otherwise;
- it never changes that detection's name, category or confidence, and never lifts a `requiresCategory` gate;
- a version a detection rule captured beats it; it beats a version a rule merely writes in (a favicon's `1.5.0+`).

So a version-only rule can add a version to a scan result, and nothing else. The rules are part of the built-in pack
(`src/version-rules.json`, appended by `build.py`), carry the `v:` id prefix, and each has an example that
`-SelfTest`/`-TestRules` checks. A version template uses group numbers (`{1}`) or named groups (`{a}.{b}`); the name
`v` is reserved for the CPE's version slot (`gen_rules.py` refuses it). `"o": "b"` matches the base64-decoded value (n8n puts its
release in a base64 JSON meta tag); such a rule has no literal prefilter.

## Files

| File | What it is |
|---|---|
| `rules.py` | The reviewed rules (with their evidence) and `NO_VERSION`: reviewed products that get none, and why |
| `gen_rules.py` | Builds `src/version-rules.json` from `rules.py`, with one output per CPE product the detection rules use |
| `targets.py` | Products whose rules carry a CPE but capture no version, with the names and CPEs a rule must join |
| `coverage.py` | Version coverage of the packs (`--md` writes the per-product table used in the docs) |
| `external.py`, `external.json` | Which products a public fingerprint database extracts a version for (review candidates) |
| `vlab.py`, `cases.json`, `batch.sh` | Runs a product container and records exactly what the scanner fetches |
| `wplab.py` | WordPress with plugins at known versions: which assets carry the plugin's own `?ver=` |
| `replay.ps1` | Feeds recorded responses into the scanner's own matcher and prints the detections with versions |

## Acceptance rules

A rule is added only when all of these hold:

1. **The number is the product's release version, numbered as NVD numbers it.** Not a build hash, a cache-buster, a
   protocol/API/component version (`JSP/2.3`, `pve-api-daemon/3.0`), a copyright year or a build date.
2. **It has at least the parts the product's releases have.** A major (`Undertow/1`) or a major.minor of three-part
   releases (`Varnish/6.6`) is rejected: `2.4` would compare as `2.4.0` and match every fix in the branch. Where the
   vendor numbers releases major.minor (pgAdmin 8.6, Proxmox VE 8.1), that is the version.
3. **It is in a response the scanner already receives**: `GET /` and its same-host redirects, the 404 probe,
   `robots.txt`, `security.txt`, the favicon, or (with `-IdentifyPaths`) one of its fixed paths. No new request is
   ever added for a version.
4. **There is evidence for the exact location**, in this order of strength:
   - *container*: the product's own image was run (`vlab.py`) and the version appeared where the rule reads it, for
     two releases; `replay.ps1` confirms the rule yields the image's version;
   - *source*: the product's page template or code prints the version there (file named in the rule's evidence);
   - *published sample*: a public fingerprint database matched that location in real responses (WhatWeb passive
     plugins, nuclei-templates detection templates, Recog examples, webappanalyzer patterns).
5. **Pre-releases are not matched** (`-beta.1`, `rc1`, `+` development builds), so a candidate never reads as the
   release it precedes.
6. **CDN paths only, never query strings, for libraries**: `cdnjs.cloudflare.com/ajax/libs/<lib>/<x.y.z>/`,
   `cdn.jsdelivr.net/npm/<pkg>@<x.y.z>/`, `unpkg.com/<pkg>@<x.y.z>/` and the project's own CDN name the exact package
   release; `?v=` on a library is the page's cache-buster.

## Adding or refreshing rules

```bash
# products to look at, most CVEs first (needs cve_vp.json from tools/cpe/cvecpe.py)
python3 tools/version/coverage.py --repo . --cve $W/cve_vp.json
# run a product (cases.json) and list where its version appears in what the scanner would receive
python3 tools/version/vlab.py run --case nextcloud --tag 32.0.15-apache
# write the rule in rules.py, then
python3 tools/version/gen_rules.py --repo . --version <release>
python3 build.py
pwsh tools/version/replay.ps1 -Script dist/Invoke-WebInventory.ps1 -Capture tools/version/out/nextcloud/32.0.15-apache
pwsh dist/Invoke-WebInventory.ps1 -SelfTest
```

`vlab.py` needs Docker. Images come from Docker Hub (mind its anonymous pull limit), the AWS ECR Public mirror of
Docker Official Images, quay.io, ghcr.io, codeberg.org, docker.n8n.io and docker.elastic.co; pull one image at a time
(parallel pulls into one daemon can fail with `failed commit on ref`). Captured responses stay in `tools/version/out/`
(not committed). NVD, WhatWeb and nuclei-templates data are only read; nothing from them is copied into the rules
beyond the location of a version string.
