# WebInventory v2.7.0: block pages, appliances, throttling, explainable fingerprints

## Why

Two reviews produced the items in [`PLAN.md`](PLAN.md): AutoAR's web side (section 1, HA1–HA8) and a review of
commercial EASM and asset-inventory products and their open-source rivals (section 2, HB1–HB7). This release does the
ones that keep Hinterland's rules: inventory only, GET requests (and OPTIONS with `-Options`), stock Windows
PowerShell 5.1, nothing to install, and the SOC-registered User-Agent.

## Decisions (Ben, 2026-11-07)

- **Hinterland stays GET-only.** HA4 (MCP exposure with an `initialize` POST) is Won't do; MCP checks stay Outcrop's
  opt-in `--mcp`.
- **The schemas come from Tideline.** `schemas/` is vendored from benheise/Tideline at a `schemas-v*` tag instead of
  generated here (HA8). Tideline's `schemas-v1.1.0` adds the 2.7 fields as minor 1 of `webinventory.service/1`.

## What changes

### On the default path (no switch)

| Change | Output | Requests |
|---|---|---|
| `WafBlocked:<vendor>` in `Flags` when the response is a WAF's own block page: F5 (the support-ID page) and Imperva at any status; Cloudflare, Akamai, AWS CloudFront, Sucuri, Azure Front Door and ModSecurity at 403, 406, 429 or 503 | new flag | none extra |
| `OriginDnsError` in `Flags` for a 530 whose body says `error code: 1016` (Cloudflare: the proxied name's origin does not resolve, a takeover risk) | new flag | none extra |
| `Appliance` column (appended): the first detection at `-MinConfidence` or above that is hardware or in an appliance category (firewall, network device, load balancer, storage, out-of-band management, power, building automation, printer, camera and the like). `OsHint` keeps the OS underneath | new column | none |
| `Rules` in each JSONL detection: the ids of the rules behind it, `;`-separated, kept when detections merge (at most 12) | new field | none |
| Throttle accounting: each check counts timeouts (connection open, no byte received), connection resets and HTTP 429. At `-ThrottleThreshold` (default 3) or more, the row's `Notes` say `throttled: … (results for this service may be incomplete)`. run.json gets `sessions[].throttle` (totals, threshold, throttled checks, the 50 worst targets) and the run log a `Throttling:` line, a warning when a check reached the threshold | `Notes`, run.json, run log | none |
| Companion rule packs (`WebInventory.rules.*.json` next to the script) must match the SHA-256 this release was built with, taken over the pack without a byte-order mark and with CRLF and lone CR turned into LF. A changed pack is refused and logged (`RULES` in the error log, `REFUSED: modified` in the run log's pack list); `-AllowModifiedRules` loads it with a warning. A pack with another name is the operator's own and loads as before, and so do `-RulesFile` packs | refusal of an edited shipped pack | none |

### Opt-in

- **`-ApiDocPaths`**: 14 GET paths, no redirects followed: `/openapi.json`, `/swagger.json`, `/v3/api-docs`,
  `/v2/api-docs`, `/swagger/v1/swagger.json`, `/openapi.yaml`, `/swagger-ui/index.html`, `/swagger-ui.html`, `/redoc`,
  `/graphiql`, `/playground`, `/docker-compose.yml`, `/docker-compose.yaml`, `/Dockerfile`. A path counts only on a
  200 whose body holds that document's own keywords, and for the data documents a body that is not HTML, so a site
  that answers 200 for every path gives no hit. Hits go to the new `ApiDocPaths` column (`path=kind;…`) with the
  `ApiDocsExposed` or `DockerFileExposed` flag. The store gates the column like `IdentifiedPaths` (run.json profile
  `apiDocPaths=1`), so turning the switch on or off is not a change. GraphQL introspection is a POST and is never sent.
- **`-ExplainFingerprint`**: `WebInventory_<RunId>_explain.log` with, per service, every rule that matched
  (`FP-MATCH builtin b:t-idrac title=…`), every rule whose literal prefilter passed but whose regex, base64 or
  condition failed (`FP-FAIL`), a `SUMMARY` line and the detections and flags the row reports (`RESULT`). It sends
  nothing extra and warns when given more than 16 checks.

### Schemas (HA8)

- `schemas/` holds Tideline's `tideline-envelope.1.json` and the five `webinventory.*.1.json` files with their lines
  of Tideline's `SHA256SUMS`, and `VENDORED.txt` naming the tag and commit. `tools/schemas/vendor.sh <tideline> <tag>`
  copies them in.
- `tools/schemas/gen.py` is gone. `tools/schemas/check.py` checks the vendored files against `src/`: the service
  properties are the 85 columns in order plus `Detections`, whose properties are the nine the worker writes; vuln,
  screenshot, delta and error match their column lists; fields added in a minor are optional and the rest required;
  the envelope is minor 1 or later and has no `tool_run`. CI runs `sha256sum -c` and the check.
- `tests/v26/contract.py`, `tests/v26/received.py` and `lab/tideline_mock.py` validate against the vendored files,
  keyed by their `x-tideline-schema` id. `tests/v26/tideline-envelope.1.json` is removed.

## Not done, and why

- HA4: see the decision above.
- HB2 (favicon MD5 and mmh3) and HB4 (licence split) were already in place; HB6 (store correlation guards) too.
- HB1 asked for evidence on every detection. Direct detections have it; a detection implied by another product
  (webappanalyzer's `implies`, e.g. Java from Jenkins) names that product in `Source` (`implied:Jenkins`) and has no
  rule or evidence of its own.
- The review's idea of moving the favicon hashes under `-IdentifyPaths` was not taken: it would remove data from
  default runs.

## Checks

| Check | Result |
|---|---|
| `-SelfTest`, PowerShell 7 on Linux | 156 of 156 (149 in 2.6.1); new: rule ids kept through a merge, explain lines, canonical pack hash cases, pins present |
| `-TestRules` | 11,551 rules, 3,225 with examples, 0 mismatches |
| `tests/scenarios.sh` | 50 of 50; 20 new: the three WAF pages, 530/1016, `-ApiDocPaths` hits, flags and no hit on a catch-all host, no `WafBlocked` on an ordinary 200, throttle `Notes` and run.json, one User-Agent across every request path, `Appliance` with CentOS left in `OsHint`, detection rule ids, explain lines, the profile flag, pack pinning (CRLF + BOM verifies, one added field is refused, `-AllowModifiedRules` loads it) |
| `tests/v26/ship.sh` | 28 of 28, every envelope and record valid against the vendored Tideline schemas |
| `tools/schemas/check.py` | 0 problems |
| Output against 2.6.1 (lab, farm, farm at 20 ms RTT) | 426 rows: no field differs except the new `Appliance` (set on the two FortiGate-certificate fixtures) and `Rules`. 862 of 862 direct detections carry both evidence and rule ids |

### Speed (2-vCPU lab machine, PowerShell 7)

Three runs each, then five interleaved runs (2.6.1, 2.7.0, 2.6.1, …) of the two scenarios where the first set
differed:

| Scenario | 2.6.1 wall, median | 2.7.0 wall, median | CPU, median |
|---|---|---|---|
| farm (200 web services) | 9.88 s | 9.82 s | 15.26 s → 15.28 s |
| farm-rtt (same at 20 ms RTT), interleaved | 10.82 s (10.36–11.26) | 10.96 s (10.81–11.34) | 15.92 s → 15.99 s |
| closed (4,000 closed ports), interleaved | 9.49 s (9.18–10.55) | 9.60 s (8.77–9.96) | 15.41 s → 15.58 s |
| lab (every fixture) | 38.57 s | 38.76 s | 11.79 s → 11.96 s |
| startup (`-ListTargets`, one target) | 2.95 s | 2.92 s | 3.96 s → 3.98 s |

Every median is within 1.3% of 2.6.1's, and in the interleaved runs 2.7.0's median falls inside 2.6.1's own range,
so the differences are noise at this sample size. Nothing on the default path adds a request: the flags and the
`Appliance` column read the response already received, and the counters are additions.
