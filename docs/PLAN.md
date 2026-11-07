# Hinterland plan

The tracked list of open work for Hinterland (`Invoke-WebInventory.ps1`, formerly the WebInventory repository).
Each item says how it will be checked. The rules every item keeps:

- inventory only: no exploitation, brute force, default credentials or path enumeration;
- stock Windows PowerShell 5.1 with .NET Framework 4.7.2 (PowerShell 7 too), and nothing to install;
- the scan's User-Agent stays the SOC-registered `WebInventory/2.0 (authorized asset inventory)`;
- a change to the default path is kept only if it is no slower and its output is identical, or the difference is a
  justified accuracy fix.

**Status:** Done · In progress · Planned · Blocked (needs something from Ben) · Won't do
**Last updated:** 2026-11-07: AutoAR items done in 2.6.1 and 2.7.0; section 2 added from the competitor review.

## 1. From the AutoAR review

AutoAR (h0tak88r/AutoAR) is a Go bug-bounty pipeline. Its web and HTTP side was reviewed for ideas (project doc
`claude/autoar-web-research.md`). Most of what it does is out of scope here. The items below are the ones that fit
an inventory tool: flags read from responses Hinterland already receives, a small opt-in GET list, and lessons
from AutoAR's defects.

The platform's share is in the Tideline plan, section 15 (TA1–TA15). Outcrop's share is in its `PLAN.md`,
section 10 (OA1–OA20).

| ID | Item | Status | Check |
|---|---|---|---|
| HA1 | **`WafBlocked` flag.** A response that is a WAF's own block page adds `WafBlocked:<vendor>` to `Flags`, so the gap shows in the inventory instead of a thin row. Read from the response already received; the User-Agent does not change. Vendors: F5 (support-ID page) and Imperva at any status; Cloudflare, Akamai, AWS CloudFront, Sucuri, Azure Front Door and ModSecurity at 403, 406, 429 or 503. AutoAR found WAFs blocking scanner User-Agents, which made hosts look clean | Done (2.7.0) | lab: Cloudflare, Akamai and F5 block pages (`tests/scenarios.sh`); no extra request |
| HA2 | **`OriginDnsError` flag (Cloudflare 1016).** A 530 answer whose body says `error code: 1016` (Cloudflare's own text) means a proxied record whose origin is gone, which is a takeover risk. Read from the response already received. Not tied to Cloudflare's address ranges as first planned: the text is Cloudflare's, and a range check would miss a service reached through a forward proxy | Done (2.7.0) | lab fixture answering 530 / 1016 |
| HA3 | **`-ApiDocPaths` (opt-in).** 14 GET paths for API documents and consoles (OpenAPI and Swagger JSON and YAML, Swagger UI, ReDoc, GraphiQL, GraphQL Playground) and Docker files (`docker-compose.yml`, `.yaml`, `Dockerfile`). A hit needs a 200 whose body holds that document's own keywords, and for the data documents a body that is not HTML. Hits go to the new `ApiDocPaths` column with `ApiDocsExposed` or `DockerFileExposed`. A separate switch, so `-IdentifyPaths` keeps its traffic profile; gated in the store like `IdentifiedPaths` (profile `apiDocPaths=1`). GraphQL introspection is a POST and is never sent | Done (2.7.0) | lab: exposed fixture (hits and flags); catch-all fixture gives no hit; profile flag in run.json |
| HA4 | **MCP server exposure.** An `initialize` request and the three list calls would be Hinterland's first POST to a target | Won't do (Ben, 2026-11-07: Hinterland stays GET-only; MCP exposure stays Outcrop's opt-in `--mcp`) | — |
| HA5 | **Throttle accounting.** Each check counts its timeouts, connection resets and HTTP 429 answers. At `-ThrottleThreshold` (default 3) or more the row's `Notes` say the results may be incomplete; every session in run.json gets `throttle` (totals, the threshold, the number of throttled checks and the 50 worst targets), and the run log a `Throttling:` warning, so Tideline's run-health panel (TA10) can show them. AutoAR filtered exactly these errors out of its logs | Done (2.7.0) | lab: a fixture answering 429 (Notes and run.json) |
| HA6 | **One request policy, tested on every path.** A lab fixture records the User-Agent of every request it receives; a run with `-IdentifyPaths -VersionPaths -ApiDocPaths -Options` must show one User-Agent across the main request, favicon, robots.txt, security.txt, the 404 probe, OPTIONS and the opt-in paths. AutoAR fixed its User-Agent in one code path and missed the path its main workflow uses | Done (2.7.0; the code already used one policy, now a test holds it) | `tests/scenarios.sh`: single User-Agent across all paths |
| HA7 | **Envelopes that validate against Tideline's schema.** 2.6.0 wrote `tool_run` into every envelope and sent part fields `schemas-v1.0.0` lacked. Decided by Ben on Tideline TA15: `tool_run` moves to run.json only, and Tideline accepts the part fields from envelope minor 1 | Done (2.6.1) | `tests/v26/ship.sh`: every received envelope valid against `tideline-envelope/1` minor 1 |
| HA8 | **Vendor the schemas from the Tideline tag.** `schemas/` now holds Tideline's `tideline-envelope.1.json` and `webinventory.*.1.json` with their lines of Tideline's `SHA256SUMS` and a `VENDORED.txt` naming the tag (`tools/schemas/vendor.sh`). `tools/schemas/gen.py` is replaced by `tools/schemas/check.py`, which checks them against the column lists in `src/`. CI runs `sha256sum -c` and the check | Done (2.7.0) | CI; `tests/v26/contract.py` and the Tideline mock validate against the vendored files |

Not adopted, because they fall outside the inventory-only rule:

- AutoAR's backup-file, content and 403-bypass fuzzing;
- its S3 write and delete probes;
- its default-credential and exploit checks.

## 2. From the competitor review

A review of commercial EASM and asset-inventory products and open-source rivals (project doc
`claude/competitor-review.md`) produced seven items for Hinterland. runZero, which also fingerprints without
security probes, is the closest model. Outcrop's items are OB1–OB11 in its `PLAN.md`, section 11; Tideline's are
TB1–TB13 in the Tideline plan, section 16.

| ID | Item | Status | Check |
|---|---|---|---|
| HB1 | **Evidence on every detection.** Each detection already carried its source (rule pack), the field and value matched (`Evidence`) and a confidence. 2.7.0 adds `Rules`: the ids of the rules behind it, `;`-separated, kept when detections merge (at most 12) | Done (2.7.0) | self-test (merge keeps both ids); lab: the iDRAC fixture's detection names `b:t-idrac` |
| HB2 | **Favicon MD5 and Shodan-style mmh3.** Both are computed from the one favicon request the default scan already makes (the page's `<link rel=icon>`, else `/favicon.ico`; `-NoFavicon` turns it off) into the `FaviconMd5` and `FaviconMmh3` columns, and Recog's favicon rules match on the MD5. The review suggested putting it under `-IdentifyPaths`; it stays where it is, since moving it would remove data from default runs | Already in place | self-test: known-hash fixtures |
| HB3 | **Rule packs verified over canonical bytes.** The companion packs next to the script (`WebInventory.rules.*.json`) must match the SHA-256 this release was built with, taken after removing a byte-order mark and normalising CRLF and lone CR to LF, so a CRLF checkout verifies and a line hidden behind a CR does not. A changed pack is refused and logged; `-AllowModifiedRules` loads it with a warning. Packs given with `-RulesFile` are the operator's own and not checked. The pins are in the script, so there is no signature line to confuse | Done (2.7.0) | self-test (canonical hash cases); lab: CRLF + BOM pack loads, one added field is refused, `-AllowModifiedRules` loads it |
| HB4 | **Licence split.** The webappanalyzer data ships as its own file (`WebInventory.rules.wappalyzer.json`) with `LICENSE-GPL-3.0.txt` and `THIRD-PARTY-NOTICES.txt`; the script's licence is separate | Already in place | release file list |
| HB5 | **Appliance over OS.** New `Appliance` column: the first detection (at `-MinConfidence` or above) that is hardware or in an appliance category (firewall, load balancer, out-of-band controller, storage, printer, camera, power, building automation and the like). `OsHint` keeps the operating system underneath, so an iDRAC on CentOS reads Appliance `Dell iDRAC`, OS CentOS | Done (2.7.0) | lab: iDRAC-on-CentOS fixture |
| HB6 | **Correlation guards.** The store re-keys a service to a new address only through its name (R1), its reverse DNS (R2) or cert + port + title + server + products (R3), and only when the match is unique in the run, so many hosts behind one shared address or one wildcard certificate never merge | Already in place (store) | `tests/store/scenario.sh` (ambiguous move) |
| HB7 | **`-ExplainFingerprint`.** Writes `WebInventory_<RunId>_explain.log`: per service, every rule that matched (`FP-MATCH`, with pack, rule id, field and value), every rule whose literal prefilter passed but whose regex or condition then failed (`FP-FAIL`), and the detections the row reports (`RESULT`). Sends nothing extra | Done (2.7.0) | self-test; lab: the iDRAC fixture's FP-MATCH and RESULT lines |

Not adopted from the review: intrusive validation of any kind (Detectify, Xpanse attack-surface tests, Hadrian),
which stays out of Hinterland by its first rule.
