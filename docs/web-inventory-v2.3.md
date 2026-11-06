# WebInventory v2.3 — offline vulnerability join, jump-host proxy, TLS fingerprints, SMB/RDP/SNMP, screenshots, store corrections

Decision record and implementation notes for v2.3.0. Constraints carried forward: stock Windows PowerShell 5.1 + .NET
Framework 4.7.2 (also PS7), no installs, inventory only (no exploitation, no brute force, no default credentials, no
directory enumeration), no loss of accuracy. Standalone tool.

## What was added
- **-StoreQuery Vulnerabilities** (-NvdFeed, -KevFile, -EpssFile): current inventory's CPEs joined offline with NVD CVE
  JSON 2.0 feeds, CISA KEV and FIRST EPSS. Streaming feed reader (records without an inventory vendor:product are not
  parsed), newest record per CVE wins, rejected CVEs skipped. Version-aware: numeric compare, update field
  (openssh 9.3:p1 = 9.3p1), ranges, pre-release ordering, 2.4 = 2.4.0. Match column: version / range / all-versions /
  "(platform not verified)" for AND configurations / product-only (listed only for KEV CVEs). Provenance sidecar JSON
  (feed hashes, KEV catalogVersion, EPSS model/date). 447k NVD records in ~60 s.
- **-Proxy http://host:port [-ProxyCredential]**: every TCP connection through HTTP CONNECT (port state from the proxy
  answer, Squid errno mapping). Pre-check: proxy reachable, no unexpected 407. Refused CONNECTs -> PROXY errors, checks
  left for -Resume. -Snmp refused with -Proxy (UDP).
- **-TlsFingerprint**: JARM (BSD-3, 10 extra handshakes, matches jarm.py) + JA4S (from the existing TLS probe's first
  ServerHello, matches FoxIO ja4.py). **JA4S licence: FoxIO License 1.1 — internal non-monetised use only; paid
  client-facing use needs a FoxIO OEM licence; JA4+ methods patent pending. -NoJa4s keeps JARM only.**
- **-Smb / -Rdp / -Snmp** (+ smb://, rdp://, snmp:// targets): SMB2/3 negotiate + one NTLM leg (names, domain, Windows
  build), SMBv1 check; RDP security protocol, NLA enforcement, standard-security acceptance, certificate, NTLM leg via
  CredSSP; SNMP sysDescr/sysObjectID/sysName/sysLocation with a supplied community or SNMPv3 user (MD5/SHA/SHA-256,
  AES/DES); no credentials -> v3 engine discovery only. Secrets redacted from logs/run.json. New columns DeviceName,
  Domain, ProtocolInfo, Jarm, Ja4s (appended). New flags SMBv1, SMBSigningNotRequired, RdpNlaNotRequired,
  RdpStandardSecurity, SnmpV1V2c. 37 built-in rules (Windows builds via NTLM, SNMP sysDescr); Recog pack regenerated
  from the same commit with SNMP/SMB/JARM databases (3,098 rules, existing ones unchanged).
- **-Screenshot**: headless Edge (or -BrowserPath), driven over the DevTools protocol (the --screenshot switch hung in
  testing with current Chromium), one temp profile per page, behind a loopback scope proxy that only forwards to
  origins scanned on that IP (403 for CDNs, fonts, trackers, browser chatter); canary detects policy-forced proxies.
  Index CSV + manifest + images in the HTML report; not archived in the store.
- **Store**: -StoreMerge / -StoreSplit as correction ledger entries applied at their position (no rewrites); split
  recomputes the original's absences from archived check lists; -Backfill inserts older runs via a "rebase" ledger
  entry (runs by start time, corrections keep their place, voided when their entities no longer exist) and a replay;
  -SnapshotEvery N thins state files (-AsOf replays in memory); -AnchorEventLog (+ -RegisterEventSource) and
  -AnchorCertificate (detached CMS per ledger line) persisted in STORE.json and checked by -VerifyStore; Enriched
  events for newly enabled probes; unique query file names; Inventory queries filter while reading.

## Scan path
- Third C# block (extras) compiled only when a new probe is used. Engine changes: proxy branch in Connect, ServerHello
  extension list kept for JA4S.
- Interleaved A/B vs v2.2.0: identical results 12/12; startup +0.1-0.2 s (bigger script, bigger Recog pack); farm
  +0.3-0.6 s, within v2.2's own round-to-round spread.

## Validation (Linux workspace)
- C# 5 / net472 compile of all three blocks: 0/0. Self-test 121/121 (128 on Windows). Regressions 25/25. Store
  scenarios: v2.2 40/40, v2.3 34 checks. Enriched gating 4/4. v2.2 stores verify unchanged.
- Lab: proxy (26 rows identical, auth, 407 stop, 403 logged), JARM 6/6 vs jarm.py, JA4S vs ja4.py, SMB vs impacket,
  RDP 4 modes, SNMP 10 modes, screenshots direct/proxied/HTTPS, one end-to-end scan with every new switch plus -Store, vulnerabilities on real feeds (expected CVEs present,
  fixed ones absent).
- Windows to-do: -SelfTest, Test-WebInventoryStore.ps1 (now incl. backfill on ESENT and event-log anchoring), one
  interactive -Screenshot run (Edge policies), RDP probe against real Windows hosts.

## Release
- v2.3.0: Invoke-WebInventory.ps1 sha256 479efef63e5343dfed37e53351ab2b1f57b9db6985dd784ad4e966fa616116f0 (814,218 bytes); full list in SHA256SUMS.txt.
