# Hinterland plan

The tracked list of open work for Hinterland (`Invoke-WebInventory.ps1`, formerly the WebInventory repository).
Each item says how it will be checked. The rules every item keeps:

- inventory only: no exploitation, brute force, default credentials or path enumeration;
- stock Windows PowerShell 5.1 with .NET Framework 4.7.2 (PowerShell 7 too), and nothing to install;
- the scan's User-Agent stays the SOC-registered `WebInventory/2.0 (authorized asset inventory)`;
- a change to the default path is kept only if it is no slower and its output is identical, or the difference is a
  justified accuracy fix.

**Status:** Done · In progress · Planned · Blocked (needs something from Ben) · Won't do
**Last updated:** 2026-11-07, created for the items from the AutoAR review.

## 1. From the AutoAR review

AutoAR (h0tak88r/AutoAR) is a Go bug-bounty pipeline. Its web and HTTP side was reviewed for ideas (project doc
`claude/autoar-web-research.md`). Most of what it does is out of scope here. The items below are the ones that fit
an inventory tool: flags read from responses Hinterland already receives, a small opt-in GET list, and lessons
from AutoAR's defects.

The platform's share is in the Tideline plan, section 15 (TA1–TA15). Outcrop's share is in its `PLAN.md`,
section 10 (OA1–OA20).

| ID | Item | Status | Check |
|---|---|---|---|
| HA1 | **`WafBlocked` flag.** A response that is a WAF block page (403, 406, 429 or 503 with a known vendor's page: Cloudflare, Akamai, Imperva, AWS WAF, F5 and the like) adds `WafBlocked:<vendor>` to `Flags`, so the gap shows in the inventory instead of a thin row. The User-Agent does not change. AutoAR found WAFs blocking scanner User-Agents, which made hosts look clean | Planned | lab: one block-page fixture per vendor; the request count per service is unchanged |
| HA2 | **`OriginDnsError` flag (Cloudflare 1016).** A service whose address is in Cloudflare's ranges (`WebInventory.cloud.json`) and that answers 530 with "error code: 1016" has a proxied record whose origin is gone, which is a takeover risk. Read from the response already received: no extra request | Planned | lab fixture answering 530 / 1016; self-test |
| HA3 | **`-ApiDocPaths` (opt-in).** A fixed list of GET paths for API documents and consoles (Swagger and OpenAPI, GraphQL UI pages) and Docker files (`docker-compose.yml`, `Dockerfile`). Each hit is confirmed by keywords in the body, not by the status code, and is recorded in its own column with an `ApiDocsExposed` or `DockerFileExposed` flag. It is a separate switch, like `-VersionPaths`, so `-IdentifyPaths` keeps its traffic profile. In the store it is gated like `IdentifiedPaths`. GraphQL introspection is a POST, so it stays out | Planned | lab: exposed and soft-404 fixtures; no false positive on a catch-all host; store `Changed` events only when the switch changes |
| HA4 | **MCP server exposure (opt-in).** An `initialize` request and the three list calls only, never `tools/call`. This would be Hinterland's first POST to a target, so it needs a decision first | Blocked (needs Ben: a POST to targets) | lab: an MCP server with and without auth |
| HA5 | **Throttle accounting.** Count timeouts, connection resets and 429s per target. Write the counts to run.json, and add a `Throttled` flag over a threshold, so Tideline's run-health panel (TA10) can show them. AutoAR filtered exactly these errors out of its logs | Planned | lab: a rate-limiting fixture; self-test |
| HA6 | **One request policy, tested on every path.** A test asserts that every request to a target carries `-UserAgent` and any `-Header` values: the main scan, `-IdentifyPaths`, `-VersionPaths`, `-ProbeSans` and the extras. The shipper's own User-Agent, used only for Tideline, stays separate. AutoAR fixed its User-Agent in one code path and missed the path its main workflow uses | Planned | lab access log across all switches |
| HA7 | **Envelopes that validate against `schemas-v1.0.0`.** Hinterland 2.6.0 writes `tool_run` into every envelope, and `tideline-envelope/1` allows no extra fields, so Tideline's validator refuses the envelope. Hinterland also has `webinventory.delta/1` and `webinventory.error/1`, which Tideline's `schemas/` lacks, and treats the screenshot and vuln schemas as final while Tideline marks them draft. Follows Ben's decision on Tideline TA15 | Blocked (needs Ben: Tideline TA15) | Tideline's `validate.py envelope` accepts a Hinterland envelope |
| HA8 | **Vendor the schemas from the Tideline tag.** Replace the copies in `schemas/` with `schemas/schemas/` and `schemas/SHA256SUMS` from benheise/Tideline at a `schemas-v*` tag, and run `sha256sum -c` in `check.yml` | Planned (after HA7) | CI |

Not adopted, because they fall outside the inventory-only rule:

- AutoAR's backup-file, content and 403-bypass fuzzing;
- its S3 write and delete probes;
- its default-credential and exploit checks.
