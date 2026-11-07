# JSON outputs and shipping to Tideline (WebInventory 2.6.0)

WebInventory writes every result as JSON Lines next to its CSV. With `-ShipTo` it sends a finished run to Tideline,
the results platform. The run's files go unchanged, as a signed envelope over mutual TLS.

Shipping is an output stage. It reads a run's files after the run is complete and its manifest is written, so it
changes nothing in what is scanned or found: a run with `-ShipTo` gives the same rows as the same run without it, and
`WebInventory_<RunId>_ship-state.json` is the only extra file. Without `-ShipTo` the script behaves as 2.5.0, apart
from the new JSONL files.

## 1. JSON outputs

Every file is UTF-8, one JSON object per line (JSON Lines), next to the run's other files in `-OutputDir`.

| File | Written when | One line is | Schema |
|---|---|---|---|
| `WebInventory_<RunId>.jsonl` | every run (since v2.0) | a service: the 83 CSV columns with JSON types, plus `Detections` | `webinventory.service/1` |
| `WebInventory_<RunId>_errors.jsonl` | every run | an error (`level` `error` or `fatal`, with `category` and `target`) or a run-log warning (`warning`) | `webinventory.error/1` |
| `WebInventory_<RunId>_delta.jsonl` | `-BaselineCsv` | a change against the baseline run: `NEW`, `CHANGED` (with the field) or `REMOVED` | `webinventory.delta/1` |
| `WebInventory_<RunId>_screenshots.jsonl` | `-Screenshot` | a capture and its check (`ok`, `blank`, `suspect`, `failed`, with `Reason`) | `webinventory.screenshot/1` |
| `WebInventory_<RunId>_vulns.jsonl` | `-NvdFeed` on a scan run | a service and a CVE, with KEV and EPSS when given | `webinventory.vuln/1` |
| `WebInventory_store_<query>_<stamp>.jsonl` | `-StoreQuery` | a row of the query (Inventory, Changes, History, Runs, Vulnerabilities) | Vulnerabilities: `webinventory.vuln/1` |

Types:

- **Results JSONL:** unchanged since v2.0. `Port` is a number, `IsWeb` and `Vhost` are booleans. `StatusCode`,
  `BodyLength`, `ResponseMs`, `FaviconMmh3`, `CertDaysLeft` and `CertKeySize` are a number or `""`, and `Http2` and
  `CertSelfSigned` are a boolean or `""`. Everything else is a string.
- **The other JSONL files mirror their CSV.** They use the CSV's column names and its cells as text, without the CSV's
  formula guard. Counts, ports, sizes and durations are numbers when the cell holds one, `""` when it is empty.
- **Ordering:** errors in the order they happened. The delta and the screenshot index are in the CSV's order.

Errors logged before the output files exist (DNS, scope and input errors) are held and written when the run's files
open, so `_errors.jsonl` holds everything the error log holds for that run.

`-NvdFeed` (with `-KevFile`, `-EpssFile`) on a scan run joins this run's services with the NVD, KEV and EPSS files,
offline. It uses the same version-aware matching as `-StoreQuery Vulnerabilities`, needs no store, and writes
`_vulns.csv`, `_vulns.jsonl` and `_vulns.provenance.json` (the feed files and their hashes) before the run's manifest.
Reading every NVD year takes about 60 s (447,034 records, measured for the same join in 2.3).

The JSON Schemas (2020-12) are in the repository's `schemas/` folder: since 2.7.0 they are Tideline's own files
(benheise/Tideline `schemas/`, the tag named in `schemas/VENDORED.txt`), and CI checks them against the script's column
lists (`tools/schemas/check.py`). `tests/v26/contract.py` validates any output folder against them. `webinventory.service/1` is frozen
from the 2.5.0 field set and requires every field of it; the fields 2.7.0 adds (`ApiDocPaths`, `Appliance`, each
detection's `Rules`) are its minor 1 and optional, so lines written by 2.5.0 and later validate. Lines from releases
before 2.5.0 lack fields it requires.

## 2. Setting up a scanner host

The Tideline administrator registers the sensor id and makes a one-time token on the CA (step-ca):

```bash
step ca token wi-scan01 --san urn:tideline:sensor:wi-scan01
```

The token is valid for five minutes. It names the CA, the fingerprint of the CA's root and the sensor's name.

**Windows (elevated PowerShell):**

```powershell
.\Register-WebInventorySensor.ps1 -Token '<token>' -GrantKeyAccess 'CORP\svc-webinv'
```

- `certreq.exe` creates an ECDSA P-256 key in the machine key store. The key is not exportable.
- The issued certificate goes to `LocalMachine\My`, bound to that key with `certutil -repairstore`, and the CA's
  intermediate to `LocalMachine\CA`. The Tideline root is not added to the machine's Trusted Root store; it is
  pinned for shipping only.
- The root is fetched by the token's fingerprint and saved to `%ProgramData%\WebInventory\tideline-root.crt`. The
  CA's own TLS certificate must chain to it. `tideline-sensor.json` records the CA URL.
- `-GrantKeyAccess` lets the account of the scheduled scan use the key (SYSTEM and Administrators always can).
- Nothing is installed.

Renew daily from a scheduled task (elevated). A renewal happens when a third or less of the lifetime is left:

```powershell
.\Register-WebInventorySensor.ps1 -Renew
```

- A new key and request go to step-ca's `rekey` endpoint over mutual TLS with the current certificate.
- step-ca copies the certificate's names, so a renewal cannot change the sensor's identity.
- The previous certificate and its key are removed (`-KeepPrevious` keeps them), and the accounts that could read
  the old key can read the new one.
- An expired certificate cannot renew: enroll again with a new token. The run log warns when the sensor certificate
  has less than two days left.
- `-Show` lists the sensor certificate, the pinned root and the CA URL.

**Linux or macOS (PowerShell 7):** the same command. The key and certificate go to
`~/.config/webinventory/tideline-sensor.pfx` (mode 0600, folder 0700), the root and the record next to it.

**Then add `-ShipTo` to the scan.** The certificate and root are found where enrollment put them:

```powershell
.\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -Store D:\WebInventoryStore -ShipTo https://tideline.corp.example:8443 -Engagement eng-2026-014
```

## 3. Options

| Option | Meaning |
|---|---|
| `-ShipTo <url>` | Tideline ingest (`https://host:8443`). Without it nothing is sent. |
| `-ShipCertThumbprint` | A sensor certificate in `LocalMachine\My` or `CurrentUser\My`. Default: the newest valid certificate there with a `urn:tideline:sensor:<id>` name and its private key, so a renewal needs no change to scheduled tasks. Several sensors' certificates on one host: give the thumbprint. |
| `-ShipCertPath`, `-ShipCertPasswordFile` | A PFX instead of the store (default off Windows: `~/.config/webinventory/tideline-sensor.pfx`); the password file's first line is the PFX password, so it never appears on a command line. |
| `-ShipCaFile` | The Tideline root (PEM) the server must chain to. Default: the root enrollment saved. The machine trust store is not used. |
| `-Engagement <id>` | Written to `run.json` and the envelope. Letters, digits, `.`, `_`, `-`; up to 64. A resumed run keeps its engagement. |
| `-ShipRetries` | Attempts after the first (default 3; waits 5 s, 15 s, 45 s). |

Everything shipping needs is checked before the scan starts: the URL, the certificate (valid now, with a sensor
name, its ECDSA P-256 key usable by this account) and the root. A scan therefore never runs for hours and then cannot
deliver. Nothing goes to Tideline until the run is complete.

## 4. What is sent

| Part | `kind` | Encoding |
|---|---|---|
| results JSONL | `services` | gzip |
| delta, screenshot index, vulnerabilities, errors JSONL | `delta`, `screenshots`, `vulns`, `errors` | gzip |
| `run.json` | `artifact`, role `run-info` | gzip |
| the run's `_manifest.txt` (SHA-256 of every output) | `artifact`, role `tool-manifest` | gzip |
| `_vulns.provenance.json` | `artifact`, role `vuln-provenance` | identity |
| the run and error logs of each session | `artifact`, role `log` | gzip |
| screenshot PNGs | `artifact`, role `screenshot` | identity |

Not sent: the CSV and the HTML report (Tideline makes its own from the JSON) and the progress file.

Checks before sending:
- The run must be complete (`run.json` `complete: true`). An interrupted run is shipped when its resumed run completes.
- Every file must still match the run's own manifest. A file changed after the run is refused, never sent.

An NDJSON file larger than 32 MiB goes as several parts, split at line ends. Each part carries its `chunk`/`chunks`,
plus the whole file's size and SHA-256.

## 5. Protocol

HTTPS/1.1, TLS 1.2 or later (TLS 1.3 under PowerShell 7). The sensor's certificate authenticates it; the server's
certificate must chain to the pinned root and name the host.

| Request | Body | Answer |
|---|---|---|
| `POST /v1/runs` | the manifest (`application/json`), header `Tideline-Signature: alg=ES256; enc=p1363; sig=<base64>` | `201` new, `200` the same manifest seen before; both `{"run_id", "state", "missing": [n...]}`. `409` the run id exists with a different manifest |
| `PUT /v1/runs/{run_id}/parts/{n}` | the part, `Content-Type` its media type, `Content-Encoding: gzip` for NDJSON and text | `204`; `422 {"error", "lines": [...]}` when a record fails its schema |
| `POST /v1/runs/{run_id}/complete` | empty | `202 {"state": "verified"}`; `409 {"missing": [...]}` |
| `GET /v1/runs/{run_id}` | | `{"state", "received", "missing"}` |

- **Signature:** over the manifest's exact bytes, with the key of the client certificate (IEEE P1363 r‖s, as .NET
  produces it).
- **Manifest:** deterministic. The same run, sensor and engagement always give the same bytes, so a re-send is
  recognised as the same run. The format (`tideline-envelope/1`) is `schemas/tideline-envelope.1.json`.
- **The run's id** is `runUuid` from `run.json`, made once per run and kept across resumed sessions. A run made before
  2.6 gets a name-based UUID from its computer, run id and manifest.

```json
{"schema":"tideline-envelope/1","run_id":"3f6c0d2e-7a51-4b8e-9d0f-2c4b1e7a9f10","tool":"webinventory","tool_version":"2.6.1",
 "sensor":"wi-scan01","engagement":"eng-2026-014","job_id":null,
 "started":"2026-11-06T14:02:11Z","finished":"2026-11-06T14:19:47Z","exit_code":0,"profile":{"tlsScan":true,"...":"..."},
 "tool_manifest_sha256":"<sha256 of _manifest.txt>",
 "parts":[{"n":1,"kind":"services","schema":"webinventory.service/1","media":"application/x-ndjson","name":"WebInventory_20261106_140211.jsonl",
           "records":1834,"bytes":9214410,"sha256":"<sha256 before compression>","encoding":"gzip"},
          {"n":7,"kind":"artifact","role":"screenshot","media":"image/png","name":"WebInventory_20261106_140211_screenshots/0001_10.20.30.40_443.png",
           "bytes":84112,"sha256":"<sha256>","encoding":"identity"}]}
```

`exit_code` is the scan's own exit code; the store and shipping stages that follow it are not included.

## 6. Delivery, resume and exit codes

`WebInventory_<RunId>_ship-state.json`, next to the run, records for each Tideline URL:
- the manifest Tideline accepted;
- the parts sent;
- every attempt, with its time and error.

A later call sends only the parts Tideline lists as missing. Once Tideline has accepted a manifest it is never
changed; a manifest it never accepted is made again, for example with the right certificate.

| Result | `Invoke-WebInventory.ps1 -ShipTo` | `Send-WebInventoryRun.ps1` |
|---|---|---|
| delivered, or already delivered | the scan's exit code | 0 |
| refused before sending (certificate, root, an incomplete or changed run) | 1 before the scan; 2 after it | 1 |
| not delivered, retry later (network, server busy, 5xx) | 2 | 2 |
| Tideline refused the run (403, 409, 422; a server that does not chain to the root) | 2 | 3 |

A failed delivery never changes the scan's own results. Exit 3 (interrupted) and 4 (nothing answered) keep their
meaning; a run that exits 4 is still shipped.

With TLS 1.3 the server checks the client certificate after the client's side of the handshake is done. A refused
sensor certificate therefore shows as a connection reset right after the handshake, which is retried. The error says
so ("Tideline may not accept the sensor certificate"); check the sensor's status in Tideline.

```powershell
.\Send-WebInventoryRun.ps1 D:\scans -ShipTo https://tideline:8443                 # every run in the folder not yet delivered
.\Send-WebInventoryRun.ps1 D:\scans\WebInventory_20261106_140211_run.json -ShipTo https://tideline:8443 -Status
.\Send-WebInventoryRun.ps1 D:\scans\WebInventory_20261106_140211_run.json -Export E:\carry\scan01.zip
```

A folder sweep:
- skips runs already delivered without reading them again;
- passes over runs that are still going or were interrupted.

It suits a scheduled catch-up task after an outage.

## 7. Export bundle (for a host that cannot reach Tideline)

`-Export` writes one zip:
- `manifest.json` (the exact bytes) and `manifest.sig` (the signature header value);
- `sensor-chain.pem` (the sensor certificate and its intermediate);
- `parts/0001.gz` ... (each part as it would be uploaded);
- `bundle.json` (part number, path, encoding, media type).

Tideline can verify everything offline: the chain to its root, the signature, every part's SHA-256 and every record's
schema. `lab/tideline_mock.py verify-bundle` does exactly that.

## 8. What Tideline should check (and the mock checks)

`lab/tideline_mock.py` is a stand-in for Tideline's ingest, used by the tests. It is not a server to deploy. It
implements the checks the platform plan gives ingest:

- the client certificate chains to the step-ca intermediate and names an active sensor;
- the manifest's signature verifies with that certificate's key;
- the manifest's `sensor` is the certificate's;
- the sensor is assigned to the engagement;
- parts are numbered 1..N;
- each part's size and SHA-256 are as declared;
- every NDJSON record matches its schema (one bad line rejects the part, with the line numbers);
- record count as declared;
- limits: manifest 1 MiB, part 64 MiB compressed and 512 MiB uncompressed, ratio 50:1 above 1 MiB, record 1 MiB.

## 9. Differences from the platform plan

- **Names.** The identifiers use Tideline's name, as the naming note proposed before they freeze: `tideline-envelope/1`,
  the `Tideline-Signature` header, `urn:tideline:sensor:<id>`. Record schemas keep WebInventory's name
  (`webinventory.service/1`).
- **Renewal** uses step-ca's `rekey` endpoint (mutual TLS with the current certificate and a new key) instead of an
  X5C provisioner. step-ca copies the old certificate's names itself, so no X5C provisioner or SAN-copying template is
  needed. Tested against step-ca 0.30.2.
- **The CA's intermediate** is installed in `LocalMachine\CA`, so Schannel sends the chain. Ingest should still trust
  the intermediate, as the plan says.
