# Inventory store tests

| File | What it does |
|---|---|
| `gen.py <outdir>` | Synthetic scanner output: five runs that exercise every history rule (change, three kinds of address move, an ambiguous move, `-NoTlsScan` carry-over, vhost absence without `-ProbeSans`, retirement, reappearance), an interrupted run and an old-format run without `run.json`. `--big N` writes two N-service runs for ingest timing |
| `scenario.sh <workdir> [script]` | 40 checks through the script's own command line: imports, every query mode and filter form, refusals, tamper detection, torn ledger, interrupted ingest, deleted database, rebuild, lock wait |
| `load-engine.ps1` | Dot-source to load the store engine from a built script into a PowerShell session |

The script's `-SelfTest` also runs store checks (engine contract on every engine, crash repair through a failpoint,
cross-engine digests on Windows). `dist/Test-WebInventoryStore.ps1` is the Windows validation for the scanner host.
Hard-kill tests on Linux: ingest a `--big 50000` run, `kill -9` the process at several delays, re-run the import and
compare the ledger digests with an uninterrupted ingest (see the v2.2 notes in `dist/README.md`).
