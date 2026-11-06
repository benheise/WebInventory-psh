# WebInventory v2.3.1 — CPE coverage

Decision record and implementation notes for v2.3.1. Constraints carried forward: stock Windows PowerShell 5.1 + .NET
Framework 4.7.2 (also PS7), no installs, inventory only, no loss of accuracy, standalone tool.

## Problem
`-StoreQuery Vulnerabilities` joins the inventory with NVD by CPE. A service matches only when its fingerprint rule
emits a CPE, and matches precisely only when that CPE carries a version. In v2.3.0, 906 of 7,743 product names across
the built-in, Recog and Wappalyzer rules carried a CPE (421 with version capture). Products like Serv-U, TeamCity,
Contact Form 7, Pulse/Ivanti (from SNMP) and FortiOS were detected but invisible to the join.

## Decision
Add CPEs from one reviewed table instead of editing rule packs by hand, so regenerated packs keep them:

- `src/cpe-supplement.json` (embedded at build time as `$CpeSupplementJson`, version 2026.11.06):
  - `fill` (523 entries): kind + product name -> CPE template (`cpe:2.3:part:vendor:product:{v}`).
  - `replace` (5): known-wrong upstream CPE -> correct one or none (Mattermost was `jenkins:mattermost`; AWS Certificate
    Manager was `awstats:awstats`; Sitecore, Okta and Salesforce had product `*`).
  - `aliases` (183 groups): NVD names of one product (renames, retired names with one successor, software vs firmware).
  - `platforms` (36): general-purpose operating systems (Windows, macOS, Linux kernel, distributions).
- Built-in rules carry their CPEs directly (149 outputs). `-ImportRules` applies `fill`/`replace` through
  `Matcher.ApplyCpeSupplement` and appends a note to the pack's `source`.
- The vulnerability join loads `aliases` and `platforms` (`Vulns.SetAliases`).

## Review rules (applied to every candidate)
Candidates came from the NVD CPE Dictionary 2.0 (product names, titles, vendor domains matched to Wappalyzer
`website`) and the vendor:product pairs NVD CVE records actually use. Accepted only when the detected thing is the
product NVD names and it runs on the scanned host:
- a plugin is not its platform (no WordPress plugin gets `wordpress:wordpress`);
- embedded third-party services (analytics, chat, payment, CDN, maps) get no CPE;
- generic names and hardware families without a model get none;
- general-purpose operating systems get none (patch level is not visible remotely);
- rules whose captured "version" is not the product's version get none: rsync protocol version, ILOM web-server
  version, major-only versions (`Undertow/1`, OXID `Version 6`, X-Cart N), versions written into a rule as a guess
  (IOS login realm -> `11`). `VersionCmp` zero-pads, so `6` would equal 6.0.0 and over-report ranges.
- where NVD uses several names, the one most CVEs use is filled and the rest become aliases;
- retired names that encode a version or model (`ios_xe_2.1`, `jenkins1.381`, `vpn_3015_concentrator`,
  `application_server_10g`) are never aliases: their `-` version would match every version.

Review state lives in `tools/cpe/decisions.py`: 394 ACCEPT, 29 MANUAL (name-keyed, all kinds), 441 REJECT,
15 SIBLING_SKIP, 5 REPLACE, 61 reviewed alias groups, 36 platforms. Derived aliases (retired name with exactly one
successor, same digit set, one side in use) make up the rest of the 183 groups.

## Engine behaviour
- `Matcher.Supplement` fills only outputs without a CPE, skips templated names (`{...}`) and outputs with a literal
  (non-captured) version, and replaces only when the current CPE's `part:vendor:product` key equals the recorded wrong
  one. `Matcher.CpeKey` normalises both CPE 2.3 (backslash escapes) and `cpe:/` URI (percent-encoding) forms.
- `NormalizeCpe` already injected the captured version into `{v}`, so any captured version flows into the new CPEs.
- `Matcher.Aggregate` pass 1 merges by CPE key; new shared CPEs can change merge order (evidence order) only.
- `Vulns.Run`: each inventory CPE also gets alias copies (`Cpe.As`, with `Origin`/`Root`) for every other name in its
  group; rows found through a copy say `(as vendor:product)` in `Match`; an AND configuration never counts the same
  service CPE twice (`Root` comparison). `Cpe.Parse` decodes `%xx` in URI-form names.

## Behaviour change to flag
Product-only rows (service hides its version) were listed for every KEV CVE of the product. For general-purpose
operating systems this listed every KEV entry of the release for every host whose `Server` header said `(Ubuntu)` or
`(Debian)`: 453 of 560 KEV rows on the lab store. v2.3.1 no longer lists product-only KEV rows for the 36 platform
names; it counts them in the summary message and in the provenance file (`osVersionUnknownKevNotListed`). Version or
range matches on those platforms are still listed. Appliance systems (FortiOS, PAN-OS, IOS, Junos, ESXi) are not
platforms and keep their product-only KEV rows.

## Results
- Rule outputs given a CPE: 715 (149 built-in, 139 Recog, 427 Wappalyzer net of 4 cleared); 12 corrected or cleared.
- Products with a CPE: 906 -> 1,327; with version capture: 421 -> 598.
- Rules with a CPE: built-in 353/512, Recog 1,476 -> 1,584 of 3,098, Wappalyzer 867 -> 1,294 of 7,824.
- Lab store vulnerability rows: 1,347 (518 KEV) -> 936 (107 KEV): 453 OS KEV rows held back, 42 FortiOS KEV rows new.
- Synthetic inventory on real feeds: Serv-U 15.2.3 -> CVE-2021-35211, TeamCity 2023.05.3 -> CVE-2023-42793,
  Ivanti 9.1R8 -> CVE-2021-22893 and three CVEs filed under `pulsesecure`, Contact Form 7 5.3.1 -> CVE-2020-35489,
  PAN-OS (no version) -> 17 KEV, concrete5 8.5.4 0 -> 133 (as `concretecms:concrete_cms`), `nginx:nginx` 1.16.1
  0 -> 7, Mattermost 46 -> 79, Citrix Gateway 13 -> 18 KEV.

## Scan path
Unchanged apart from rule data. A/B against v2.3.0 (two runs each): farm identical in every CSV column; lab differs
only in `CPEs` on the two FortiGate rows; JSONL evidence order changes where rules now share a CPE. Wall times within
run-to-run spread (PERFORMANCE.md). Script +77 KB. Vulnerability query 48.7 s -> 50.0 s on the lab store.

## Validation (Linux workspace)
- C# 5 / net472 compile of all three blocks: 0/0. Self-test 125/125 (132 on Windows with ESENT). Regressions 25/25.
- Store scenario VulnCheck extended: alias match labelled `(as ...)`, percent-encoded URI CPE (`tcp%2fip`) matching a
  range, AND configuration with the alias as platform, OS product-only KEV listed without the platform list and held
  back with it.
- Regenerated Recog and Wappalyzer packs: same rule ids as v2.3.0, differences only in `p`.
- `tools/cpe/gen_supplement.py` reproduces `src/cpe-supplement.json` byte for byte from `decisions.py` and fails when
  any name is absent from the NVD dictionary.
- Windows to-do (unchanged from v2.3): -SelfTest (132), Test-WebInventoryStore.ps1, interactive -Screenshot, RDP
  against real Windows hosts.

## Remaining gap
729 of the 1,327 products with a CPE come from rules without version capture (mostly Wappalyzer technologies detected
by script names or headers that carry no version); they match only `all-versions` entries and KEV CVEs. Widening that
means new version-capturing patterns, not more CPEs.

## Refresh
`tools/cpe/README.md`: download the NVD CPE dictionary, run `cpedb.py`/`cvecpe.py`, re-import the packs, run `gap.py`
(only names nobody has reviewed come up), add each line to ACCEPT or REJECT, run `gen_supplement.py`, `build.py`,
re-import, `-SelfTest`. NVD data stays outside the repository.
