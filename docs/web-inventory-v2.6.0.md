# WebInventory v2.6.0: JSON outputs and shipping to Tideline

This is the decision record for v2.6.0. It does two things:
- adds a JSON form of every output that had only a CSV or text form;
- implements the WebInventory side of the results platform plan (`recon-platform-plan-v0.5.md`, section 11) under
  the platform's chosen name, Tideline: shipping finished runs, and enrolling the scanner host as a sensor.

The constraints are unchanged:
- stock Windows PowerShell 5.1 with .NET Framework 4.7.2 (also PowerShell 7);
- no installs;
- inventory only;
- no loss of accuracy.

WebInventory stays standalone: shipping is opt-in, and without `-ShipTo` a run behaves as 2.5.0 apart from the new
JSONL files.

## 1. JSONL for every CSV-only output

**Decision.** A JSON Lines file is written next to each CSV-only output:
- `_delta.jsonl`;
- `_screenshots.jsonl`;
- `_errors.jsonl` (the error log's entries and the run log's warnings);
- `-StoreQuery` results (`WebInventory_store_<query>_<stamp>.jsonl`);
- the new per-run vulnerability join (`_vulns.jsonl`).

The results JSONL (`WebInventory_<RunId>.jsonl`) is unchanged.

**Types.**
- The mirrored files use the CSV's column names and cells as text, without the CSV's formula guard, which only
  protects spreadsheets.
- Counts, ports, sizes and durations are numbers when the cell holds one, `""` when it is empty. This is the
  convention the results JSONL has followed since v2.0 (`StatusCode` is a number or `""`), so a consumer meets one
  rule everywhere.

**Errors before the output files exist.** DNS, scope and input errors happen before the run's files open. They are
held in memory and written when the files open, so `_errors.jsonl` matches the error log. A test found this:
an unresolved name was in the error log but not in the first `_errors.jsonl`.

**Per-run vulnerabilities.** `-NvdFeed` (with `-KevFile`, `-EpssFile`) was a store-query option. On a scan run it now
joins the run's own services with the feeds:
- the matching is the same `WebInv.Vulns.Run` as `-StoreQuery Vulnerabilities`, and no store is needed;
- the output is `_vulns.csv`, `_vulns.jsonl` and `_vulns.provenance.json`;
- it is written before the run's manifest, so it is part of the run.

The platform plan's envelope has a `vulns` part; without this, WebInventory could only produce CVE data from a store,
outside any run.

**Schemas.** `tools/schemas/gen.py` writes JSON Schema 2020-12 files to `schemas/` from the column lists in the
source:
- `tideline-envelope-1`;
- `webinventory.service-1`, `.delta-1`, `.screenshot-1`, `.vuln-1`, `.error-1`.

CI fails when the committed schemas differ from what the source generates. `webinventory.service/1` documents the
existing row rather than inventing a format, as the plan asks:
- 83 columns with their JSON types, plus `Detections`;
- the required fields are the key fields, so runs of earlier releases, which lack later columns, still validate;
- a column added later is a minor version.

**Check.** Every results line that a scan wrote, out of 540,115 kept from earlier releases' lab and benchmark runs,
validates. The 128 lines that do not are hand-made store-test fixtures without `ScannedAt`. The contract test also
runs on each new output in the shipping suite.

## 2. Shipping: `-ShipTo` and `Send-WebInventoryRun.ps1`

**Decision.** This implements plan section 5 with the identifiers renamed for Tideline, as the naming note
recommended before they freeze:
- `tideline-envelope/1`;
- `Tideline-Signature`;
- `urn:tideline:sensor:<id>`.

The shipping code is one C# file (`src/ship.cs`) and one PowerShell file of helpers. The build puts the same code into
`Invoke-WebInventory.ps1` (compiled only with `-ShipTo`) and into both companion scripts, so each companion can be
copied to a host on its own.

- **Envelope.** A manifest names every part with its kind, schema or role, name, size, record count and SHA-256
  (before compression), and the SHA-256 of the run's own `_manifest.txt`.
  - It is deterministic: the same run, sensor and engagement always give the same bytes, so a re-send is recognised
    as the same run (200) and a different one as a conflict (409).
  - ES256 signature over the exact bytes, with the client certificate's key (P1363, as .NET produces it).
- **Parts.**
  - Sent: the JSONL files (gzip), `run.json`, `_manifest.txt`, the logs of each session, the vulnerability provenance
    and the screenshot PNGs.
  - Not sent: the CSV and the HTML report (Tideline builds its own) and the progress file.
  - An NDJSON file above 32 MiB goes as parts split at line ends, each with the whole file's size and SHA-256.
- **Integrity before sending.** Only a complete run is shipped, and every file must still match the run's own
  manifest; a changed file is refused. Each part is hashed again as it is read for upload.
- **Transport.**
  - HTTPS/1.1 over `SslStream`, TLS 1.2 or later (TLS 1.3 on .NET 5+).
  - The server must chain to the pinned root (not the machine trust store) and name the host.
  - Written on `SslStream` rather than `HttpWebRequest`, so certificate selection, protocol and validation are the
    same on .NET Framework and .NET 8, and nothing depends on the obsolete API's proxy or connection-pool behaviour.
- **Delivery.**
  - `ship-state.json` per run and target records the accepted manifest, the parts sent and every attempt.
  - A later call sends only the parts Tideline lists as missing. A manifest Tideline never accepted is not pinned:
    a delivery attempted with the wrong certificate can be repeated with the right one.
  - Retries for network errors and 408/429/5xx: 5 s, 15 s, 45 s.
- **Exit codes.** A scan whose delivery fails exits 2 and keeps its state for a later `Send-WebInventoryRun.ps1`. The
  companion's codes are 0 delivered, 1 refused before sending, 2 retry later, 3 refused by Tideline.
- **Before the scan.** The certificate, its key's usability by this account, and the root are all checked first, so a
  scan never runs for hours and then cannot deliver.
- **Export bundle.** The bundle holds the manifest, the signature, the sensor chain and the parts; Tideline can verify
  it offline.

**Rejected:**
- `HttpWebRequest` (obsolete on .NET 8; client certificate and TLS behaviour differ between runtimes).
- Re-serializing rows through `ConvertTo-Json` (depth and speed limits); the files are sent as written.
- A shipping time or the shipper's version in the manifest: either would make re-sends conflict.

## 3. Enrollment: `Register-WebInventorySensor.ps1`

**Decision.** step-ca for every sensor, as the plan decided (D4), with nothing installed.

- **Token.** The administrator's one-time token (`step ca token <id> --san urn:tideline:sensor:<id>`) carries:
  - the CA URL (`aud`);
  - the root's fingerprint (`sha`);
  - the names (`sans`).

  The script fetches the root by that fingerprint, then requires the CA's TLS certificate to chain to it. The CA
  therefore needs no separate trust step on the host.
- **Windows.**
  - `certreq.exe -new -machine` creates an ECDSA P-256 key in the Software Key Storage Provider, machine key set,
    not exportable.
  - The issued certificate is added to `LocalMachine\My`, and `certutil -repairstore` binds it to that key; the
    intermediate goes to `LocalMachine\CA`.
  - Not `certreq -accept`: it refuses a certificate whose chain does not end in the machine's Trusted Root store
    (CERT_E_CHAINING, found on the Windows CI runner). The Tideline root is pinned for shipping and is deliberately
    not trusted machine-wide.
  - certreq's pending request is removed afterwards, and with its key if the CA did not issue.
  - `-GrantKeyAccess` adds read access to the key file for the scan's account.
- **Elsewhere.** A key in memory and a PFX at `~/.config/webinventory/tideline-sensor.pfx`, created with mode 0600.
- **Renewal.** `-Renew` posts a new key's request to step-ca's `rekey` endpoint, over mutual TLS with the current
  certificate. step-ca copies the old certificate's names: a request asking for another sensor name was checked and
  still received the original names. The previous certificate and key are removed, and the key's readers carry over.

  The plan proposed an X5C provisioner with a SAN-copying template. `rekey` gives the same result with no extra
  provisioner, so the plan's section 9 can drop the X5C provisioner.

**Shipping finds the certificate by its sensor name, not by thumbprint.** The newest valid certificate in
`LocalMachine\My` with a `urn:tideline:sensor:` name is used, so a renewal (new thumbprint) needs no change to
scheduled tasks. Several sensors' certificates on one host need `-ShipCertThumbprint`.

## 4. Tests

| Suite | What | Result |
|---|---|---|
| `tests/v26/ship.sh` (29 scenarios, mock ingest) | round trip byte-identical; delta, vulns, screenshots, errors parts; A/B against the same scan without shipping; already delivered, `-Force`, `-Status`; connection dropped mid-upload then resumed with only the missing parts; 503 retried; Tideline unreachable (exit 2, state kept); changed file refused; inactive sensor 403; rogue client CA; expired, URN-less and RSA certificates refused before the scan; server outside the pinned root; host name mismatch; 409 conflict; engagement not assigned; schema 422 with the line number; chunked file; export bundle verified and a tampered one caught; incomplete run; PFX password file; option checks; exit 4 still shipped; the errors part | 29/29 |
| `tests/v26/register.sh` (step-ca 0.30.2) | enroll; key and certificate contents; token reuse, expired token, token without a sensor name, wrong root fingerprint refused; `-Show`; renewal not due; renewal now (new key, same name, PFX still 0600); a scan shipped with only the enrolled defaults | 10/10 |
| `tests/v26/windows.ps1` (CI, Windows PowerShell 5.1) | certreq enrollment; non-exportable machine key; `-GrantKeyAccess`; a scan shipped over Schannel with the CNG key; `-Status`; export bundle with the chain from the machine store; renewal (old certificate and key removed, readers kept); shipping after renewal; `-Show` | see CI |
| `-SelfTest` | JSON round trip, sensor names, ES256 signature, pinned chain, run collection, chunking, gzip parts, refusals, option checks | 149/149 (PowerShell 7) |

The mock (`lab/tideline_mock.py`) checks what the plan gives ingest: the client chain, the active sensor, the
signature, sensor and engagement, part numbering, sizes and hashes, every record against its schema, record counts,
and the limits. It also injects faults.

## 5. Behaviour changes

- **New files in every run folder:** `_errors.jsonl`. Also `_delta.jsonl` with `-BaselineCsv`,
  `_screenshots.jsonl` with `-Screenshot`, `_vulns.*` with `-NvdFeed`, and a `.jsonl` for each store query. The
  run's manifest lists them.
- **`run.json`** gains `runUuid`, `engagement` and `exitCode`. The store ignores the new fields.
- **New parameters:** `-ShipTo`, `-ShipCertThumbprint`, `-ShipCertPath`, `-ShipCertPasswordFile`, `-ShipCaFile`,
  `-Engagement`, `-ShipRetries`. `-NvdFeed`/`-KevFile`/`-EpssFile` now also apply to scan runs.
- **New files in the release:** `Send-WebInventoryRun.ps1`, `Register-WebInventorySensor.ps1`, `SHIPPING.md`.
- **The store archive is unchanged:** it keeps the same files per run as 2.5.0.
