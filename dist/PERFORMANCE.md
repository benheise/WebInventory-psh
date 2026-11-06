# WebInventory 2.1 performance work: checklist and results

v2.1.0 is the result of measuring v2.0.2, writing a checklist of 19 candidate optimisations, testing them, and keeping
only the ones that were faster **and** produced field-for-field identical results. Every number below comes from the
suite in `tests/perf` (see its README) and can be reproduced.

## How it was measured

- **Machine:** 2 vCPU Linux container, PowerShell 7.4.6 on .NET 8. Windows PowerShell 5.1 was not available, so
  absolute numbers will differ on Windows. Interpreter-bound costs (the ones v2.1 removes) are usually higher on 5.1,
  so the relative gains should hold or grow; verify with the suite before relying on them.
- **Lab:** the regression fixtures, plus a farm of 200 web services on 50 loopback hosts (nginx-style, WordPress,
  a 120 KB single-page app, TLS Jenkins), 40 silent listeners, 320 dropped ports, and the farm again behind a relay
  adding 20 ms RTT.
- **Method:** 3 runs per scenario, medians reported. CPU is the scanner process only. Accuracy: every run is compared
  field by field (CSV and JSONL) with a reference scan made by v2.0.2 at low concurrency with 10 s timeouts, where
  nothing is lost to load. A difference anywhere fails the run.
- **A/B:** an instrumented candidate could switch each component back to its v2.0.2 behaviour one at a time
  (leave-one-out), so each item's contribution was measured on the scenarios it targets.

## Headline: v2.0.2 vs v2.1.0

| Scenario | v2.0.2 wall s | v2.1 wall s | speed-up | v2.0.2 CPU s | v2.1 CPU s | CPU saved | peak RSS MB (old→new) | accuracy v2.0.2 | accuracy v2.1 |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| lab | 40.3 | 39.4 | 1.02x | 17.0 | 12.8 | 24% | 387→409 | 3/3 identical | 3/3 identical |
| farm | 39.7 | 12.4 | 3.21x | 67.1 | 19.8 | 70% | 1115→543 | 0/3 identical (450 differences; 585 differences; 540 differences) | 3/3 identical |
| farm-rtt | 41.9 | 13.0 | 3.22x | 69.3 | 20.4 | 71% | 1072→534 | 0/3 identical (720 differences; 585 differences; 450 differences) | 3/3 identical |
| tarpit | 12.9 | 8.1 | 1.59x | 14.0 | 10.0 | 29% | 446→430 | 3/3 identical | 3/3 identical |
| closed | 139.4 | 12.1 | 11.56x | 202.2 | 20.2 | 90% | 2809→459 | open=0 closed=4000 filtered=0 | open=0 closed=4000 filtered=0 |
| filtered | 17.4 | 12.8 | 1.36x | 25.3 | 12.3 | 51% | 807→436 | open=0 closed=0 filtered=320 | open=0 closed=0 filtered=320 |
| startup | 3.1 | 3.6 | 0.85x | 4.2 | 5.0 | -17% | 326→366 | - | - |
| expand | 11.6 | 8.9 | 1.30x | 14.4 | 11.5 | 20% | 356→406 | - | - |

`lab` is bounded by its 1.5 s slow-application fixture (22 sequential requests), so only its CPU drops. Startup is ~0.5 s slower: the engine is larger and builds the prefilter automata.

Accuracy finding: under full load (64 threads on 2 cores) **v2.0.2 lost data in every farm run**: 450-720 field
differences against the reference, mostly HTTPS sites reported as bare `tls` and detections lost to 86-101 rule regex
timeouts. v2.1.0 matched the reference exactly in every run, because the work that caused the timeouts is gone.

## Micro-benchmarks (per operation)

| Operation | v2.0.2 | v2.1.0 | factor |
|---|---:|---:|---:|
| Rule evaluation, 120 KB single-page app | 108.6 ms | 8.4 ms | 12.9x |
| Rule evaluation, 34 KB WordPress page | 47.6 ms | 3.8 ms | 12.6x |
| Rule evaluation, 13 KB corporate page | 14.9 ms | 1.2 ms | 12.0x |
| Parse + build observations, SPA response | 11.6 ms | 2.9 ms | 4.0x |
| Parse + build observations, WordPress response | 6.3 ms | 3.0 ms | 2.1x |
| One result row to CSV + JSONL | 2.0 ms | 1.0 ms | 2.1x |
| Per-check overhead (closed port, dispatch included) | 32.1 ms | 2.3 ms | 13.8x |
| Rule pack load (10,668 rules, incl. prefilter build) | 524 ms | 548 ms | 0.96x |
| DNS, 600 names, 5% of them 1.5 s slow, 32 in flight (simulated resolver) | 27.0 s | 2.3 s | 12.0x |

## The checklist

Sources: the scanner research (items P1-P12) and what profiling the baseline showed. "Accepted" means faster in the A/B
test with identical output; contributions are the full v2.1 build compared with the same build with only that item
switched off.

| # | Recommendation | Source | Test | Result | Verdict |
|---|---|---|---|---|---|
| 1 | Literal prefilter for rule regexes (Aho-Corasick over each value; a rule runs only if its required literals are present) | P6 | farm, farm-rtt; `prefilter-check.ps1` (2,335 rule examples + page corpus, on vs off) | farm 1.39x faster, 1.47x less CPU; SPA page evaluation 109 → 8 ms; body-rule regexes run on that page: 1,326+ → 5; regex timeouts under load 126-133 → 0; identical detections | **Accepted** |
| 2 | Long-lived workers pulling from a C# scheduler (per-host cap, round-robin), results via a signalled queue, no 20 ms polling | P2 | closed, filtered, farm, tarpit | closed 12.6x faster (156 → 12.4 s), farm 2.7x, filtered 1.4x; v2.0.2's idle dispatcher burned ~0.5 core while waiting | **Accepted** |
| 3 | Register worker functions once in an `InitialSessionState` | found while testing #2 | closed sweep at 4/16/64 threads | defining functions inside each long-lived runspace made PowerShell background-compile them once per runspace (~9 s CPU each; 500 checks took 37 s at 16 threads). Shared definitions compile once: 5.3 s at any thread count | **Accepted** (required by #2) |
| 4 | Non-blocking connect + `Socket.Select` instead of `BeginConnect` | found while testing #2 | closed, filtered | when the thread pool was busy, `BeginConnect` completions arrived late and **1,992 of 4,000 closed ports were reported filtered**; select-based connect never uses the pool. Clean-pool A/B: closed 1.08x faster | **Accepted** (accuracy) |
| 5 | Warm the certificate chain engine before dispatch (110 ms) | found by the farm accuracy check | farm | without it, dozens of first TLS handshakes initialising the chain engine at once stalled for seconds and servers timed out: farm 1.55x slower and 51 field differences in 1 of 3 runs | **Accepted** |
| 6 | Silent listeners: after plain HTTP and Schannel both get zero bytes before the timeout, send the 5 raw TLS version probes concurrently instead of one after another | P1, P7 | tarpit | 12.5 → 9.3 s (each silent port now costs ~3 timeouts instead of 7); every probe still sent, results identical | **Accepted** |
| 7 | HTTP response parsing and observation building in C# | P3 | farm; micro | farm 1.14x faster; parsing the SPA response 11.6 → 2.8 ms | **Accepted** |
| 8 | CSV/JSONL row writer in C# (same quoting, formula guard and JSON types as `ConvertTo-Json`) | P11 | farm; micro | farm 1.13x faster; one row 2.0 → 1.0 ms | **Accepted** |
| 9 | Target expansion and `-ListTargets` formatting in C# | P10 | expand (/18 x 26 ports, 425,984 checks) | expansion 2.9 → 0.8 s; output byte-identical | **Accepted** |
| 10 | DNS lookups in a sliding window (each name on its own timeout) instead of fixed batches of 32 | P9 | micro: 600 names, 5% taking 1.5 s | 27.0 → 2.3 s, same results | **Accepted** |
| 11 | Back off and retry when the scanner itself runs out of ephemeral ports or socket buffers, instead of reporting "filtered" | P12 | 4-port local range, TIME_WAIT reuse off | v2.0.2 silently produced an incomplete row; v2.1 logs each skipped request, warns in the summary and marks the row `incomplete` | **Accepted** (accuracy; matters more now that v2.1 opens connections faster) |
| 12 | Slow-start worker ramp (8 workers, +8 per 100 ms) | idea from #5 | farm | 1.05x, within run-to-run noise | Rejected (no measurable gain) |
| 13 | Adaptive, RTT-derived timeouts | P8 | 1.5 s slow-app fixture at 2000/1000/500 ms | found at 2000 ms, lost at 1000 and 500 ms. On a LAN an RTT-derived timeout is milliseconds, so slow but real apps would vanish | Rejected (accuracy) |
| 14 | Request de-duplication across a check | P4 | server-side request log of a farm scan | 1,050 requests, 0 duplicates: nothing to remove | No change needed |
| 15 | Raw TLS version probes in parallel for every TLS port | P7 | not adopted | would open 5 connections at once to one port, breaking the `-MaxPerHost` politeness contract and risking connection-limited BMCs/printers; used only for silent listeners (#6) | Not adopted |
| 16 | `RegexOptions.Compiled` for body rules | P6 | not testable here | needs proof on .NET Framework 4.8, where compiling ~10,000 regexes costs seconds of startup and memory; the prefilter already removes most regex work | Not adopted |
| 17 | Reuse the port-check connection for the first request; HTTP keep-alive within an origin | P2/P7 | not adopted | the relay cannot emulate connect RTT, so the saving could not be proven; keep-alive changes response framing on fragile embedded servers | Not adopted |
| 18 | `[Console]::WriteLine` instead of `Write-Host` | P11 | not adopted | only positive hits are printed (negligible cost), and Windows PowerShell transcripts do not capture `[Console]` output | Not adopted |
| 19 | Port-hinted protocol order; no NULL-probe wait on known web ports | P5 | already in v2.0.2 | - | No change needed |

## Contributions (leave-one-out)

| Switched off | Scenario | full v2.1 wall / CPU s | without it wall / CPU s | contribution (wall, CPU) | accuracy without it |
|---|---|---:|---:|---:|---|
| literal prefilter | farm | 12.4 / 20.6 | 17.3 / 30.4 | 1.39x, 1.47x | 2/3 identical (17 differences) |
| literal prefilter | farm-rtt | 13.2 / 21.3 | 18.6 / 32.0 | 1.42x, 1.50x | 2/3 identical (6 differences) |
| scheduler + long-lived workers | closed | 12.4 / 21.7 | 156.5 / 229.9 | 12.63x, 10.58x | open=0 closed=4000 filtered=0 |
| scheduler + long-lived workers | filtered | 12.9 / 19.5 | 17.9 / 26.9 | 1.39x, 1.38x | open=0 closed=0 filtered=320 |
| scheduler + long-lived workers | farm | 12.4 / 20.6 | 32.9 / 53.1 | 2.66x, 2.57x | 3/3 identical |
| scheduler + long-lived workers | tarpit | 9.3 / 14.3 | 9.6 / 12.6 | 1.04x, 0.88x | 3/3 identical |
| silent-listener parallel TLS probes | tarpit | 9.3 / 14.3 | 12.5 / 19.2 | 1.34x, 1.34x | 3/3 identical |
| C# response parsing | farm | 12.4 / 20.6 | 14.1 / 23.8 | 1.14x, 1.15x | 2/3 identical (2 differences) |
| C# CSV/JSONL writer | farm | 12.4 / 20.6 | 14.0 / 23.8 | 1.13x, 1.15x | 2/3 identical (6 differences) |
| TLS warm-up + worker ramp | farm | 12.4 / 20.6 | 20.6 / 36.9 | 1.66x, 1.79x | 1/3 identical (45 differences; 180 differences) |
| TLS warm-up + worker ramp | farm-rtt | 13.2 / 21.3 | 21.7 / 37.4 | 1.65x, 1.76x | 1/3 identical (135 differences; 180 differences) |
| TLS warm-up | farm | 12.4 / 20.6 | 19.3 / 34.3 | 1.55x, 1.66x | 2/3 identical (51 differences) |
| worker ramp | farm | 12.4 / 20.6 | 13.1 / 22.2 | 1.05x, 1.07x | 2/3 identical (1 differences) |
| C# target expansion | expand | 9.4 / 12.1 | 10.7 / 13.5 | 1.14x, 1.11x | - |
| select-based connect | closed | 12.4 / 21.7 | 13.3 / 23.8 | 1.08x, 1.09x | open=0 closed=4000 filtered=0 |
| select-based connect | filtered | 12.9 / 19.5 | 12.6 / 16.2 | 0.98x, 0.83x | open=0 closed=0 filtered=320 |

(Each row: the instrumented full v2.1 candidate vs the same build with one item switched back to v2.0.2 behaviour. "Accuracy without it" shows how often the stripped build still matched the reference; differences there are load-induced losses.)

## What did not change

- Probe set, request contents and order per check, timeouts, retries, `-MaxPerHost`, rule packs and output schema.
- The only new output text is the `incomplete:` note (item 11) and a run-log warning when local sockets run out.
- Startup is about 0.5 s slower (larger engine to compile, prefilter automata, warm-up); it pays back after a few
  web services.

## v2.2.0: the scan path is unchanged

v2.2.0 adds the inventory store. Its code is a separate C# block compiled only when the store is used, after a scan
has finished, and the scan engine source is v2.1.0's with only the version constant changed. An interleaved A/B
(v2.1.0 and v2.2.0 alternating, same lab, same session) confirmed it:

| Scenario | v2.1.0 wall s (mean) | v2.2.0 wall s (mean) | rounds | accuracy (v2.2.0 vs v2.1.0, field by field) |
|---|---:|---:|---:|---|
| farm (200 web services, 64 threads) | 16.5 | 15.0 | 3 | identical in 3/3; also identical to the low-concurrency reference in 3/3 |
| lab (all fixtures, all probes) | 40.4 | 40.2 | 3 | identical in 3/3 |
| farm-ref (4 threads, 10 s timeouts) | 22.6 | 23.1 | 3 | identical in 3/3 |
| closed (4,000 refused ports) | 12.4 | 12.7 | 5 | n/a (no rows) |
| startup (`-ListTargets`) | 3.68 | 3.80 | 5 | n/a |

Run-to-run spread on this host was larger than any of the differences (v2.1.0 alone ranged 14.6-21.7 s on the farm
across rounds). The one consistent cost is about 0.1 s of startup and 6 MB to parse the larger script file.

A first build that compiled the store into the scan engine paid about 0.5 s more wall and 1 s more CPU per launch for
the larger compile; that is why the store became a separate, on-demand block.

Ingest itself runs after the scan (portable engine, same host): 50,000 services 18 s for the first run and 17 s for
the next, 200,000 services 70 s and 56 s. The first-run figure was 25 s (and 860 MB peak) until the move-pairing step
stopped loading candidates when a run had no disappeared services to pair them with; digests were unchanged by that
fix.

## v2.3.0: the scan path without the new switches

v2.3.0 adds opt-in probes (TLS fingerprints, SMB, RDP, SNMP, screenshots), a CONNECT proxy and store features. The
probe code is a third C# block compiled only when one of those switches is used. The scan engine changed in two
places: the connect routine checks one static field to decide whether to tunnel through a proxy, and the raw TLS probe
keeps the ServerHello's extension list (for JA4S). Two interleaved A/B series against v2.2.0 (same lab, same session,
versions alternating):

| Scenario | v2.2.0 wall s (mean) | v2.3.0 wall s (mean) | rounds | accuracy (v2.3.0 vs v2.2.0, field by field) |
|---|---:|---:|---:|---|
| farm (200 web services, 64 threads) | 10.50 | 11.14 | 7 | identical in 3/3 compared |
| lab (all fixtures, all probes) | 38.41 | 38.90 | 3 | identical in 3/3 |
| farm-ref (4 threads, 10 s timeouts) | 20.50 | 20.83 | 3 | identical in 3/3 |
| closed (4,000 refused ports) | 10.44 | 10.23 | 3 | identical (no rows) |
| startup (`-ListTargets`) | 2.91 | 3.10 | 7 | n/a |

- **Startup +0.1-0.2 s.** The script is 814 KB instead of 558 KB (the probe and store sources are here-strings):
  parsing takes about 35 ms longer, and the larger Recog pack (3,098 rules, +729 for SNMP/SMB/JARM) about 0.1 s more to
  load. Without the companion packs, a bare `-ListTargets` launch went from 1.49 s to 1.62 s.
- **Farm +0.3-0.6 s.** The scan phase alone (run-log timestamps) averaged 9.45 s vs 9.78 s in the second series, and
  v2.3.0 with the v2.2.0 rule packs measured 9.69 s - so most of the difference is not the rules, and it is within the
  0.7 s spread v2.2.0 showed on its own across rounds. CPU averaged 17.4 s vs 18.0 s.
- Lab, farm-ref and closed are within run-to-run noise. Every compared result set was field-for-field identical to
  v2.2.0 (the five new columns are empty without the new switches).

### Cost of the new probes (when switched on)
- `-TlsFingerprint`: 10 extra connections per TLS service (JARM; each waits for the ServerHello or an alert). JA4S
  needs no traffic.
- `-Smb`: 2-3 connections per host with port 445 open (SMB2 negotiate + session setup, SMBv1 negotiate [+ session setup
  on SMBv1 servers]). `-Rdp`: 2-3 connections. `-Snmp`: one UDP request (+ one for SNMPv3 discovery), retried
  `-Retries` times on silence.
- `-Screenshot`: one browser process per page, 4 at a time by default; in the lab 2-4 s per page.
- `-StoreQuery Vulnerabilities`: 447,034 NVD records (all yearly feeds plus the modified feed, 253 MB compressed) read
  in about 60 s on this 2-vCPU host; records whose CPEs name no product in the inventory are skipped without parsing.

## v2.3.1: CPE coverage, same scan path

v2.3.1 changes rule data (CPEs) and the offline vulnerability join; the scan engine only gained two static helpers used
by `-ImportRules` (CPE key parsing, supplement application). A/B against v2.3.0 on the same lab, two runs each
(PowerShell 7.4, 2 vCPU):

| Scenario | v2.3.0 wall (s) | v2.3.1 wall (s) |
|---|---|---|
| farm (200 services) | 11.05, 10.81 | 10.15, 10.62 |
| lab (26 services, all probes of the lab profile) | 38.51, 38.70 | 38.38, 38.48 |
| closed ports | 9.65, 10.08 | 9.89, 10.22 |
| startup only | 3.05, 2.91 | 2.84, 2.72 |

Accuracy, field by field (both runs): the farm results are identical in every CSV column; in the lab the only CSV change
is `CPEs` on the two FortiGate rows (`cpe:2.3:o:fortinet:fortios`, which the built-in rule now carries). In the JSONL,
detections whose rules now share a CPE list the same evidence items in a different order (merge order); names,
versions, confidence and sources are unchanged. The script is 77 KB larger (the embedded `cpe-supplement` table and the
CPEs in the built-in rules); startup is within run-to-run noise.

`-StoreQuery Vulnerabilities` on the lab store with the same feeds (NVD 447,034 records): 48.7 s (v2.3.0), 50.0 s
(v2.3.1). The alias table (425 names) only widens the vendor:product prefilter.

## v2.3.2: version-only rules, same scan path

v2.3.2 adds 106 version-only rules to the built-in pack, changes how detections merge when one of them takes
part, and adds rule option `b` (match the base64 decoding of a value); nothing else in the scan path changed, and no
request was added. A/B against v2.3.1 on the same lab, two runs each (PowerShell 7.4, 2 vCPU), measured with the
final rule set (106 rules):

| Scenario | v2.3.1 wall (s) | v2.3.2 wall (s) |
|---|---|---|
| farm (200 services) | 11.08, 11.00 | 10.82, 10.76 |
| lab (26 services, all probes of the lab profile) | 38.65, 38.50 | 38.48, 38.58 |
| closed ports | 10.45, 10.63 | 10.39, 10.71 |
| startup only | 3.00, 2.83 | 2.81, 3.17 |

Accuracy, field by field: in the lab every CSV column and every JSONL detection is identical (both runs). On the farm,
the only change is Lodash: 50 of the 200 rows load `/static/js/lodash-4.17.<n>.min.js`, and v2.3.2 reports
`Lodash 4.17.<n>` with `cpe:2.3:a:lodash:lodash:4.17.<n>` where v2.3.1 said `Lodash` (`v:file-lodash`; the JSONL detection
lists `wappalyzer+builtin` as its sources). Every other column of every row, the set of detections and their
confidence and category are identical (apart from `RunId`, `ScannedAt` and `ResponseMs`, which differ per run).

Rule matching: the new rules are literal-prefiltered like all others: 103 of them carry a fixed string that must
occur in the value before their regex runs, so a page without those strings costs nothing beyond the existing
Aho-Corasick pass; of the other three, two read a dedicated header (`X-Version-Id`, `X-JupyterHub-Version`) that only
those products send, and n8n's reads one short base64 meta value (`n8n:config:sentry`), decoded only when present.

## v2.4.0: same scan path; `-VersionPaths` sends nothing unless a product needs it

v2.4.0 adds 9 rules (8 version-only, 1 title rule), two CPE alias groups, and the opt-in `-VersionPaths` step, which
runs after a service's other observations and only when a detected product has no version and a rule names a version
URL for it. A/B against v2.3.2 on the same lab, two runs each (PowerShell 7.4, 2 vCPU):

| Scenario | v2.3.2 wall (s) | v2.4.0 wall (s) | v2.4.0 with `-VersionPaths` (s) |
|---|---|---|---|
| farm (200 services) | 11.42, 11.29 | 11.03, 10.97 | 11.39, 10.82 |
| lab (26 services, all probes of the lab profile) | 39.16, 38.89 | 39.08, 39.00 | 39.06, 39.10 |
| closed ports | 11.17, 10.90 | 10.70, 11.05 | |
| startup only | 3.12, 3.17 | 3.37, 3.24 | |

Accuracy, field by field (`tests/perf/golden.py`, CSV and JSONL): lab, farm and closed-port runs of v2.4.0 are
identical to v2.3.2 (0 differences; the new `VersionPaths` column is empty). With `-VersionPaths` the lab and the
farm are identical too, with the same request counts (457 and 1,400): none of their products is detected without a
version and has a version URL, so no request was added and `VersionPaths` stayed empty on every row. Against the
product containers (Vaultwarden 1.37.5 and Flink 2.2.1 scanned without and with the switch), the switch added
one request per service, the one its `VersionPaths` cell lists (`/api/version=200`, `/config=200`; Vaultwarden's
log shows a single `/api/version` request), and the version.

Startup: in 4 more interleaved pairs, v2.4.0 took 3.20–3.41 s and v2.3.2 2.98–3.23 s (median +0.12 s). The rule
engine is not where it goes: loading the same built-in, Recog and Wappalyzer packs with each version's engine in
isolation takes no longer (median 447 ms with the v2.4.0 engine, 540 ms with v2.3.2's, 15 loads of all three each),
and the scan phases are unchanged. The difference is within the 0.35 s spread v2.3.2 showed in its own A/B (2.81–3.17 s).

**2.4.1** changes nothing on the scan path except the prefilter's fold map for four non-ASCII characters (the
Kelvin sign, long s, dotted and dotless I now fold onto k, s and i on every runtime). One run each of the lab, the
200-service farm and the closed-port sweep: identical to 2.4.0 field by field (farm 10.98 s, lab 38.96 s, closed
11.41 s).

## v2.5.0: same scan path; cloud lookup only on public addresses; `-Cname` costs one DNS query per name

v2.5.0 adds:
- the cloud/CDN range lookup (offline; the 3.2 MB file loads in about 0.27 s, only when a service on a public address
  answers);
- `-Cname` (opt-in, one DNS query per hostname target);
- the screenshot checks (after the scan);
- exit code 4;
- the raw-ClientHello certificate fallback for RDP. The engine's raw TLS hello now runs on a given stream; the HTTPS
  probe calls it on its own connection as before.

Interleaved A/B against v2.4.1 on the same lab, two runs each (PowerShell 7.4, 2 vCPU):

| Scenario | v2.4.1 wall (s) | v2.5.0 wall (s) |
|---|---|---|
| farm (200 services) | 10.94, 11.40 | 11.28, 11.36 |
| lab (26 services, all probes of the lab profile) | 38.92, 38.62 | 38.90, 38.85 |
| closed ports | 10.69, 10.73 (exit 0) | 10.41, 10.28 (exit 4: nothing answered) |
| startup only | 3.16, 3.29 | 3.01, 3.15 |

Accuracy, field by field (`tests/perf/golden.py`, CSV and JSONL): lab, farm and closed-port runs of v2.5.0 are
identical to v2.4.1 (0 differences; the four new columns are empty, since every lab address is loopback and no target
was looked up with `-Cname`). The cloud ranges were never loaded in these runs, because no service had a public
address.

With `-Cname` the lab run is identical too. Its target phase took 0.65 s instead of about 0.2 s: one query per lab
name to the workspace's resolvers, which do not know the lab names, so they come back with no CNAME.

Cloud lookup on its own: loading the 92,358 prefixes takes about 0.27 s; a lookup takes about 10 µs (80,000 lookups,
including PowerShell's loop overhead, in 0.84 s).
