# WebInventory v2.2 — inventory store (ESENT working database + archive)

Decision record and implementation notes for the history store added in v2.2.0. Constraints carried forward: no
installs (stock Windows PowerShell 5.1 + .NET Framework 4.7.2), single scanner host, inventory only (no assessment),
no change to scan accuracy or speed.

## Decision
- **Working database: ESENT** (`esent.dll`, part of Windows) through direct P/Invoke from the inline C# 5 engine.
  Declarations follow ManagedEsent (MIT); no DLL shipped. One table `kv` (k Binary(255) primary key, v LongBinary)
  under an ordered key-value interface. Circular logging (the archive is the backup), lazy-flush batch commits,
  durable commit at the end of each run.
- **Long-term record: the archive.** Per-run immutable folder (results JSONL/CSV/HTML, checked keys, run.json, logs,
  manifest; gzip) + `ledger.jsonl`, one line per run with SHA-256 of every file and of the previous line.
- **Database = deterministic function of the archive.** Delete it and the next open rebuilds it; `-VerifyStore`
  re-applies the whole history in memory and compares every per-run digest with the ledger.
- **Portable engine** (`FileKv`): same contract, in-memory ordered map saved atomically; PS7 on Linux/macOS and the
  reference ESENT is checked against.

## History model
- Identity: Host + IP + Port (+ vhost flag). Moves paired only when unambiguous (same DNS name; same reverse DNS; same
  cert+title+server+products), held by exactly one gone and one added service and no other service seen that run.
- 60 material fields define a version (hash of normalised values). Observed-only: ScannedAt, ResponseMs, BodyLength,
  BodySha256, CertDaysLeft, Notes, VhostOf, ScanTag. Normalised: banner clock/date text, `CertExpiring:<n>d` day count.
- Probe switches off -> fields only that probe collects carry over (no false "removed"). Incomplete observations
  update last-seen only.
- Absence scoped to the run's checked host|port (from `_progress.txt`); SAN vhosts only with -ProbeSans. Missing ->
  Retired after `-RetireAfter` (default 3) consecutive in-scope runs; Reappeared with the diff.
- Ingest is idempotent per run (applied-seq marker per entity), so any crash is repaired by re-applying.

## Scan path
- The store is a separate C# block compiled on first use, after the scan; the scan engine is v2.1.0's source with only
  the version constant changed. (A first build compiled both together and paid ~0.5 s wall / 1 s CPU per launch.)
- Interleaved A/B vs v2.1.0: output identical field by field in 9/9 comparisons; farm 15.0 vs 16.5 s, lab 40.2 vs
  40.4 s, closed 12.7 vs 12.4 s, startup 3.80 vs 3.68 s (+6 MB) - all within run-to-run noise except ~0.1 s startup.

## Validation (Linux workspace; ESENT itself needs a Windows run)
- C# 5 / net472 reference-assembly compile of both blocks: 0 errors, 0 warnings (store block also against only
  mscorlib + System + System.Core, the Windows PowerShell 5.1 reference set). PSSA 5.1 profiles clean.
- Self-test 106/106 (111 on Windows with ESENT). 25/25 lab regression scenarios.
- CLI scenario: 40/40 (every expected event and no other, queries, refusals, tamper, torn ledger, pending repair,
  rebuild, lock wait).
- kill -9 at four points during ingest: always resumed to byte-identical digests.
- Ingest timing (portable engine, pwsh 7 / Linux, 2 vCPU): 50k services 18 s first run / 17 s next; 200k services
  70 s / 56 s; archive ~13 MB per 50k-service run. Two consecutive lab scans with -Store: zero change events.
- Validator dry run (portable engine standing in for ESENT): 8/8.
- Windows to-do: run `Test-WebInventoryStore.ps1` on the scanner host (self-test incl. ESENT checks, ESENT vs File
  digests, Stop-Process -Force at 4 points of an ESENT ingest, verify, rebuild ESENT->File->ESENT). Not yet run on
  Windows PowerShell 5.1 itself.

## Release
- v2.2.0: Invoke-WebInventory.ps1 sha256 073f77b0d50a698424eac29a63b34dc36a1430b80de5e168f7516ec1feeb73b6
  (558,401 bytes), Test-WebInventoryStore.ps1 sha256 30cc08ff421bd74535bf80967b6afb637ec8b34b265629048725a78f98374683.
