# WebInventory v2.6.1: envelopes Tideline accepts

## Problem

Checking the shipping tests' envelopes against Tideline's own schema (benheise/Tideline `schemas/`, tag
`schemas-v1.0.0`) showed that Tideline would refuse every run 2.6.0 ships:

- 2.6.0 wrote `tool_run` (the tool's own run id, `yyyyMMdd_HHmmss`) at the top of every envelope, and
  `tideline-envelope/1` allows no extra fields.
- Its parts also carried six fields that `schemas-v1.0.0` did not define (`encoding`, `role`, `chunk`, `chunks`,
  `file_bytes`, `file_sha256`), and artifact media types with a charset (`text/plain; charset=utf-8`).

The 2.6.0 tests checked envelopes against WebInventory's own generated copy of the schema, which had the extra
fields, so nothing failed.

## Decision (Ben, 2026-11-07)

- **`tool_run` leaves the envelope.** The id is still in `run.json`, which ships with every run as its `run-info`
  artifact; the envelope keeps `run_id` (run.json's `runUuid`) and `tool_manifest_sha256`.
- **Tideline accepts the part fields.** `tideline-envelope/1` minor 1 (`schemas-v1.1.0`) adds them as optional fields,
  allows media parameters, and accepts the name-based (version 5) run ids of runs made before 2.6. Outcrop sends none of
  them and is unaffected.

## Changes

- `src/ship.cs`: the manifest no longer adds `tool_run`. Everything else in it is unchanged, so a run already shipped
  by 2.6.0 gets a different manifest; re-sending it opens a new run at Tideline (the old one was refused anyway).
- `tools/schemas/gen.py`: the envelope schema drops `tool_run`.
- `tests/v26/received.py`: validates every envelope the mock received against `tests/v26/tideline-envelope.1.json`, a
  copy of Tideline's schema (minor 1), and finds the run by `runUuid` instead of `tool_run`.
- `lab/tideline_mock.py`: its listing shows `tool_version` instead of `tool_run`.

## Checks

- `tests/v26/ship.sh` (PowerShell 7 on Linux): 28 of 28 scenarios, every envelope valid against Tideline's schema,
  including a run split into three chunks.
- The same check on a 2.6.0 manifest fails with "Additional properties are not allowed ('tool_run' was unexpected)".
- `-SelfTest` and `-TestRules` unchanged.
