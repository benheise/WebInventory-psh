# Invoke-WebInventory v2.3.1 — Product Sheet

**Agentless web and service inventory for Windows, with history, evidence and offline vulnerability correlation, in a single PowerShell file.**

Release 2.3.1 · Windows PowerShell 5.1 + .NET Framework 4.7.2 (also PowerShell 7) · nothing to install

---

## 1. At a glance

| | |
|---|---|
| **What it does** | Finds web services on any port, identifies what they are (product, version, CPE, OS, hardware), records TLS and certificate posture and hygiene flags, and (opt-in) reads SMB, RDP and SNMP identity. The result is a CMDB-grade inventory. |
| **Footprint** | One script, `Invoke-WebInventory.ps1` (891 KB), plus optional rule packs placed next to it. There is no installer, no agent, no external binary and no internet dependency. |
| **Platforms** | Windows PowerShell 5.1 with .NET Framework 4.7.2+ (4.8 for TLS 1.3 through Schannel). Also PowerShell 7 on Windows, Linux and macOS; the store uses its portable engine off Windows. |
| **Knowledge base** | 11,434 fingerprint rules: 512 curated built-in, 3,098 Rapid7 Recog, 7,824 Wappalyzer (webappanalyzer). 1,327 products carry a reviewed NVD CPE (598 of them with a version). |
| **Per-run output** | 78-column CSV, JSONL with per-detection evidence, offline HTML report, field-level delta, `run.json`, SHA-256 manifest, run and error logs. |
| **History** | Inventory store: first/last seen, versions and a change log per service. The database is Windows' built-in ESENT, rebuilt on demand from an append-only, hash-chained archive. |
| **Vulnerability view** | Inventory CPEs joined offline with NVD CVE JSON 2.0 feeds, CISA KEV and FIRST EPSS, under every NVD name of each product (183 alias groups). |
| **Safety model** | Scope is fail-closed. No exploitation, no brute force, no default credentials, no path enumeration. |

## 2. Design commitments

These limits are deliberate, and the code enforces them.

- **Inventory, not attack.** It never sends exploit payloads, brute-forces anything, tries default credentials or enumerates directories. The optional `-IdentifyPaths` list is fixed at 16 public landing/version pages, all requested with GET.
- **Credentials only when you supply them.** The only credential the tool ever uses is an SNMP community or SNMPv3 user given with `-Snmp`. SMB and RDP stop at the server's first, unauthenticated NTLM message: no login, no null session, no share listing. Secrets are written to neither the logs, `run.json` nor the store; they appear as `<redacted>`.
- **Fail-closed scope.** A malformed target, exclusion or scope entry, or any target outside `-Scope`, stops the run before the first packet is sent. Redirects, SAN virtual hosts and screenshots are held to the same scope.
- **Opt-in probes add traffic only when switched on.** With the v2.3 switches off, the tool sends exactly the traffic v2.2 sent; the A/B test against v2.2 was identical field by field in 12 of 12 comparisons.
- **Evidence by default.** Every run has a manifest of output hashes and a preflight record of the host's crypto and TLS policy, the script signature and the rule-pack hashes. With `-Store`, every run is archived under a hash-chained ledger.
- **Standalone.** It talks only to the targets (and to a jump-host proxy, if given). Feeds for vulnerability correlation are files you download yourself.

## 3. Architecture

### 3.1 One file, three compiled engines

`build.py` assembles eight PowerShell parts and three inline C# blocks into one script. All C# compiles as C# 5 against the .NET Framework 4.7.2 reference assemblies that Windows PowerShell 5.1 already loads.

```
Invoke-WebInventory.ps1  (built from src/ by build.py)
+--------------------------------------------------------------------------------------------+
| PowerShell parts                                                                           |
|   10-header   parameters, help, -ConfigFile merge, -Pace presets, logging, engine compile  |
|   20-input    port sets, nmap-style target/exclude/scope parsing, smb:// rdp:// snmp://    |
|   30-worker   the per-check pipeline (runs inside RunspacePool workers)                    |
|   35-extras   extras compile + engine binding, screenshots, extras self-test               |
|   40-output   78-column schema, CSV/JSONL writers, console hits, delta, manifest, HTML     |
|   45-store    run.json, ingest, store modes, ledger anchoring, store self-test             |
|   50-tools    rule packs: load / import / export / test; -SelfTest                         |
|   60-main     preflight, proxy, targets -> jobs, dispatcher, watchdog, finalize, ingest    |
+--------------------------------------------------------------------------------------------+
| C# scan engine     compiled at startup, always                                             |
|   WebInv.Net (connect, proxy tunnel, HTTP probe, DNS window, rDNS)  Tls (raw ClientHello)  |
|   Der (X.509/SAN, Go-format DN)  Hash (mmh3, MD5, SHA-256)  Html (response parse)          |
|   Matcher + Lit + AhoCorasick (rules)  Advisory  Out (CSV/JSONL)  JobBuilder  Sched        |
|   RangeSet  Json  Util                                                                     |
| C# extras block    compiled only when -TlsFingerprint/-Smb/-Rdp/-Snmp/-Screenshot is used  |
|   Jarm  Ja4s  Ntlm  Smb  Rdp  Snmp  CdpCapture (DevTools)  ScopeProxy                      |
|   every TCP connection goes through WebInv.Net.Connect (bound by delegate at load)         |
| C# store block     compiled only after the scan has finished, only with -Store             |
|   EsentNative/EsentKv (P/Invoke esent.dll)  FileKv  InventoryStore  InvSchema  RunInfo     |
|   RowFilter  Vulns (NVD/KEV/EPSS)  StoreSelfTest                                           |
| Embedded data      512 built-in rules (JSON), CPE supplement (JSON), self-test certificate |
+--------------------------------------------------------------------------------------------+
```

| Block | Compiled | References | Why separate |
|---|---|---|---|
| Scan engine | At startup, once per PowerShell session (version-checked) | mscorlib, System, System.Core, System.Security, System.Runtime.Serialization, System.Xml | The scan path stays the code that was benchmarked and A/B tested |
| Extras | Only when an opt-in probe is used | mscorlib, System, System.Core | No cost and no change to scan behaviour unless a v2.3 probe is on |
| Store | After the scan, only for store work | mscorlib, System, System.Core | Store problems can never affect a scan; a failed ingest leaves the run intact for `-ImportRun` |

### 3.2 How a run flows

```
targets / ports / exclude / scope
   -> parse (nmap syntax) + size check + scope check ............. fail-closed, nothing sent yet
   -> DNS: 32 lookups in flight, each with its own timeout
   -> JobBuilder: protocol jobs first (smb/rdp/snmp), then host:port checks, port-major
   -> Sched (C#): per-host cap (-MaxPerHost), round-robin across hosts
   -> N long-lived workers (RunspacePool, functions pre-registered in an InitialSessionState)
        Invoke-Check: connect -> protocol detect -> HTTP / TLS / banner -> raw TLS probes
                      -> favicon, robots, security.txt, 404 probe, [OPTIONS], [identify paths]
                      -> [JARM/JA4S] -> Observation -> Matcher -> Complete-Row
                      -> [SAN vhosts] -> [reverse DNS]
   -> signalled result queue -> CSV + JSONL + progress file (streamed) + console hits
after the loop:  [screenshots] -> HTML report -> [delta] -> run.json -> manifest -> [store ingest]
store modes:     -StoreQuery (incl. Vulnerabilities) | -ImportRun [-Backfill] | -StoreMerge | -StoreSplit
                 | -VerifyStore | -RebuildStore | options only (-SnapshotEvery, -Anchor*)
```

## 4. Coverage

### 4.1 Protocols and services

| Layer | Coverage |
|---|---|
| Port state | TCP connect scan (nmap `-sT` semantics): RST = `closed`, silence/unreachable = `filtered`, with `-Retries` on silence. Through `-Proxy`, the state comes from the proxy's CONNECT answer. |
| Web | HTTP and HTTPS auto-detected on **any** port, in either order: TLS-first on 31 well-known TLS ports, plaintext-first elsewhere, switching automatically. A plaintext 400 always gets a TLS attempt. |
| TLS | Raw ClientHellos for SSL 3.0, TLS 1.0, 1.1, 1.2 and 1.3, independent of the host's Schannel policy: version matrix, cipher per version, ALPN (HTTP/2), weak-cipher acceptance, leaf certificate. Schannel handshake for the HTTP layer and chain validation. |
| Banners (NULL probe) | SSH, FTP, SMTP, POP3, IMAP, MySQL/MariaDB (handshake v10), VNC, PostgreSQL, Redis, AMQP. |
| SMB (`-Smb`) | SMB2/3 dialect (2.0.2–3.1.1), signing mode, SMBv1 enabled, NetBIOS/DNS names, domain, forest, Windows build; NativeOS/NativeLM on SMBv1. |
| RDP (`-Rdp`) | Selected security protocol (TLS / CredSSP / standard RDP), NLA enforcement, standard-security acceptance, RDP certificate, names, domain, Windows build. |
| SNMP (`-Snmp`) | sysDescr, sysObjectID, sysName, sysLocation over v1/v2c (supplied community) or SNMPv3 USM (MD5 / SHA / SHA-256; DES / AES-128). Without credentials, only SNMPv3 engine discovery. |
| TLS fingerprints (`-TlsFingerprint`) | JARM (10 handshakes) and JA4S (no extra traffic). |
| Rendering (`-Screenshot`) | A PNG of each web service from headless Edge, confined to the scanned origins. |

### 4.2 Products and technologies

| Source | Rules | Notes |
|---|---:|---|
| Built-in (embedded) | 512 | Curated for enterprise estates, in 41 categories. Microsoft stack (IIS/HTTP.sys/WinRM, Exchange, SharePoint, AD FS, RD Web, Windows Admin Center, SSRS, ASP.NET, AD CS Web Enrollment). Edge/VPN (FortiGate, GlobalProtect, Cisco ASA, Ivanti, Citrix, F5, SonicWall, Check Point, Sophos, WatchGuard, pfSense/OPNsense). Out-of-band management (iDRAC, iLO, XClarity, Supermicro, CIMC). Virtualization and storage (ESXi/vCenter/Horizon, Proxmox, Nutanix, NetApp, Synology, QNAP, Veeam). DevOps and monitoring (Jenkins, GitLab, Atlassian, SonarQube, Nexus, Artifactory, Kubernetes, Grafana, Elastic, Splunk, Zabbix, PRTG, SolarWinds, Tenable). CDN/WAF. File transfer (MOVEit, GoAnywhere, Serv-U, CrushFTP). Printers, cameras, phones, building automation. Windows releases from NTLM builds (31 builds, Windows 2000 to Windows 11 25H2 / Server 2025). SNMP sysDescr (Cisco IOS/IOS XE, Junos, Windows, Linux). |
| Rapid7 Recog | 3,098 | HTTP headers, titles, cookies, auth, favicons, certificates, SSH/FTP/SMTP/POP3/IMAP/MySQL banners. v2.3 adds 630 SNMP fingerprints, 81 SMB NativeOS/NativeLM rules and 18 JARM signatures. BSD-2. |
| Wappalyzer (webappanalyzer) | 7,824 | 5,926 technologies: JS libraries, CMS, frameworks, analytics, CDNs, e-commerce. 946 rules capture versions, 1,294 carry CPEs (867 upstream, 427 added by the CPE supplement). Passive HTTP patterns only. GPL-3.0 data. |

Detections carry kind (service / OS / hardware / flag), name, version, category, confidence, CPE 2.3, source rule and evidence. They feed the `Products`, `Technologies`, `Categories`, `CPEs`, `OsHint` and `Hardware` columns.

**CPE coverage (v2.3.1).** 1,327 of the 7,743 product names across the three sources carry an NVD CPE, 598 of them from rules that also capture a version (v2.3.0: 906 and 421). The 715 added rule outputs (149 built-in, 139 Recog, 427 Wappalyzer) come from one reviewed table, `cpe-supplement`; every name in it exists in the NVD CPE Dictionary. Left without a CPE on purpose: plugins whose only candidate is their platform, third-party services a page embeds, generic names, general-purpose operating systems, and rules whose captured "version" is not the product's version (or is a major number or a guess).

### 4.3 Hygiene and exposure flags

Flags are observations, not exploitation results. They land in `Flags`, are highlighted on the console (critical ones in red) and are counted in the HTML report.

| Area | Flags |
|---|---|
| TLS | `WeakTLS:<SSL3/TLS1.0/TLS1.1>`, `WeakCipher:<version:suite>` (RC4, 3DES, DES, NULL, EXPORT, anon), `SchannelIncompatible` |
| Certificate | `CertExpired`, `CertExpiring:<n>d` (`-CertWarnDays`, default 30), `CertNotYetValid`, `SelfSigned`, `WeakSig:<alg>`, `WeakKey:<bits>`, `CertNameMismatch`, `CertUntrusted`, `DefaultCert` |
| HTTP | `CleartextAuth` (Basic/Digest or a login form over HTTP), `PlainHttp`, `RiskyMethods:<list>` (with `-Options`) |
| Exposure (rules) | `MgmtInterface`, `DefaultPage`, `DirectoryListing`, `PhpInfoExposed`, `DevServer`, `APIDocs`, `ShadowIT`, `ADCSWebEnrollment` (relevant to ESC8) |
| Protocols (v2.3) | `SMBv1`, `SMBSigningNotRequired`, `RdpNlaNotRequired`, `RdpStandardSecurity`, `SnmpV1V2c` |
| Version advisories | `PHP2Shell:vulnerable`, `PHP2Shell:eol-branch`, `PHP2Shell:version-hidden`, with the `+mod_php` and `+vendor-build` modifiers. The reasoning goes in `Advisories`. |

### 4.4 Output schema (78 columns, CSV and JSONL)

| Group | Columns |
|---|---|
| Run | `RunId`, `ScanTag`, `ScannedAt` |
| Identity | `Host`, `IP`, `Port`, `ReverseDns`, `Vhost`, `VhostOf`, `State`, `IsWeb`, `Service`, `Scheme`, `Url`, `FinalUrl` |
| HTTP | `StatusCode`, `Title`, `Server`, `PoweredBy`, `Generator`, `ContentType`, `BodyLength`, `BodySha256`, `ResponseMs`, `RedirectChain`, `Auth`, `Cookies`, `CookieFlagIssues`, `MissingSecHeaders`, `HstsMaxAge`, `AltSvc` |
| Fingerprint | `Products`, `Technologies`, `Categories`, `CPEs`, `OsHint`, `Hardware`, `FaviconPath`, `FaviconMmh3`, `FaviconMd5`, `Robots`, `SecurityTxt`, `AllowedMethods`, `RiskyMethods`, `IdentifiedPaths` |
| TLS | `TlsVersion`, `TlsCipher`, `TlsKeyExchange`, `TlsSupported`, `TlsCiphersByVersion`, `TlsWeakCipher`, `Alpn`, `Http2` |
| Certificate | `CertSubject`, `CertIssuer`, `CertSANs`, `CertNotBefore`, `CertNotAfter`, `CertDaysLeft`, `CertSelfSigned`, `CertSigAlg`, `CertKeyAlg`, `CertKeySize`, `CertSerial`, `CertSha1`, `CertSha256`, `CertPolicyErrors`, `CertChainStatus`, `CertSource` |
| Review | `Flags`, `Advisories`, `Banner`, `Notes` |
| v2.3 (appended) | `DeviceName`, `Domain`, `ProtocolInfo`, `Jarm`, `Ja4s` |

The v2.3 columns are appended after `Notes`, so existing CSV consumers keep their column positions. JSONL adds a `Detections` array: each detection's kind, name, version, category, confidence, CPE, source and evidence.

## 5. Capability catalogue: what each capability does and how it is wired

Each entry lists the switches, the code path (PowerShell function → C# class), what it writes, and what it sends.

### A. Discovery core

#### A1. Target input and scope control
- **Does:** accepts IPs, hostnames, URLs, CIDRs, dash ranges, nmap octet ranges, `host:ports`, `[IPv6]:port`, port keywords (`web` 26 ports, `web-extended` 114, `mgmt` 17, `all`), and the `smb://`, `rdp://`, `snmp://` URL forms. All of them work on the command line and in files.
- **Switches:** `-Target`, `-TargetFile`, `-HostFile`, `-Port`, `-PortFile`, `-Exclude`, `-ExcludeFile`, `-Scope`, `-ScopeFile`, `-DropOutOfScope`, `-SkipInvalidInput`, `-AllAddresses`, `-MaxTargets` (65,536 hosts) with `-Force`, `-ListTargets`.
- **Wiring:**
  - `Split-HostPort` / `Get-SpecList` / `Expand-Ports` (20-input) produce range specs, sized before expansion so a mistyped `/8` is refused.
  - Exclusions and scope become `WebInv.RangeSet`s.
  - `WebInv.JobBuilder` expands checks port-major (natural round-robin) and records excluded and out-of-scope targets.
  - Main glues PowerShell's split `host:80,443` tokens back together and refuses bare numerics such as `7.1` and typo'd parameters such as `-Treads`.
- **Writes:** INPUT / SCOPE / DNS errors; the scope summary in the run log. `-ListTargets` prints the plan and sends nothing.

#### A2. Port state (connect scan)
- **Wiring:** `WebInv.Net.Connect` does a non-blocking connect plus `Socket.Select` on the worker's own thread. No thread-pool completions are involved, which removed the false "filtered" results seen under load.
  - If the scanner runs out of local ephemeral ports or buffers, the connect backs off and retries up to 8 times. After that, the check becomes a resumable `error` and the row is marked `incomplete:`.
  - `-Retries` re-tries silent ports.
  - With `-Proxy`, the call branches into `ConnectViaProxy` (see B6).
- **Writes:** `State`; counts in the run summary.

#### A3. Protocol detection
- **Wiring:** `Invoke-Check` step 2 picks TLS-first or plaintext-first from `$TlsHintPorts` and the URL scheme, then falls through to the other order.
  - On non-HTTP ports with no scheme, it waits `-BannerWaitMs` (default 300 ms) for a server-first banner. `Add-BannerObs` classifies the banner and decodes MySQL handshakes through `Util.MySqlVersion`.
  - A plaintext 400 is held while TLS is tried. `Test-TlsMismatch` recognises the nginx, Apache and Go mismatch texts and notes them.
  - Silent listeners (tarpits, SYN-proxy firewalls) are detected, and their raw TLS probes are sent concurrently instead of serially: about 3 timeouts per port instead of 7.
- **Writes:** `Service`, `Scheme`, `Banner`, `Notes`.

#### A4. HTTP collection
- **Wiring:**
  - `Invoke-Fetch` → `WebInv.Net.Probe` sends HTTP/1.1 with `Connection: close`, gzip/identity and the body capped by `-MaxBodyBytes`. `WebInv.Html.Parse` turns the reply into an `HttpResp`.
  - `Get-RedirectChain` follows 301/302/303/307/308 up to `-MaxRedirects` (default 5), on the same host only. Off-host redirects need `-FollowOffHost` and are re-checked against scope and exclusions.
  - `Set-HttpFields` reads every hop: Server, X-Powered-By, `WWW-Authenticate` and realm, password forms, cookie `Secure`/`HttpOnly` gaps, missing CSP / X-Frame-Options / X-Content-Type-Options / HSTS, HSTS max-age and Alt-Svc.
  - `Html.AddWeb` loads headers, cookies, title, body, meta, script sources, location, auth, status and URL into the `Observation`.
- **Writes:** the HTTP column group; the `CleartextAuth` and `PlainHttp` inputs.

#### A5. Favicon fingerprint
- **Switch:** on by default, `-NoFavicon` to skip.
- **Wiring:** tries `<link rel=icon>` first, then `/favicon.ico`. It decodes `data:` URIs inline and fetches same-host icons only. `Hash.FaviconHash` computes the Shodan-compatible mmh3 and `Hash.Md5Hex` the MD5; MD5 is a managed implementation, so it also works on FIPS-enforced hosts.
- **Writes:** `FaviconPath`, `FaviconMmh3`, `FaviconMd5`; observation fields `favicon.mmh3` and `favicon.md5` (537 Recog rules match on the favicon MD5).

#### A6. Safe extras
- **Switch:** on by default, `-NoExtras` to skip.
- **Wiring:** sends GET `/robots.txt`, GET `/.well-known/security.txt` (RFC 9116 `Contact`) and one random-path 404 probe (`/wi-<random>.html`, after nmap's FourOhFourRequest). Error pages expose Tomcat, IIS, nginx and Apache versions, and a catch-all 200 is noted.
- **Writes:** `Robots`, `SecurityTxt`, `Notes`; extra `body`/`header` observations.

#### A7. HTTP methods (opt-in)
- **Switch:** `-Options`.
- **Wiring:** one `OPTIONS /` request. The `Allow` and `Public` headers are parsed; anything beyond GET/HEAD/POST/OPTIONS is risky.
- **Writes:** `AllowedMethods`, `RiskyMethods`; flag `RiskyMethods:`.

#### A8. Identification paths (opt-in)
- **Switch:** `-IdentifyPaths`.
- **Wiring:** sends GET to the fixed `$IdentifyPathList`:
  - `/owa/auth/logon.aspx`, `/certsrv/`, `/adfs/ls/idpinitiatedsignon.aspx`, `/RDWeb/`
  - `/remote/login`, `/global-protect/login.esp`, `/+CSCOE+/logon.html`, `/dana-na/auth/url_default/welcome.cgi`, `/vpn/index.html`
  - `/version`, `/api/health`, `/api/v1/status/buildinfo`, `/rest/applinks/1.0/manifest`
  - `/.well-known/openid-configuration`, `/manager/html`, `/v2/`

  Each response is added as `path:<path>.<field>` observations for rules that confirm product and version.
- **Writes:** `IdentifiedPaths` (`path=status` for every non-404).

#### A9. TLS posture and certificates
- **Switch:** on by default, `-NoTlsScan` to skip the raw probes.
- **Wiring:**
  - **Schannel.** The HTTPS fetch gives the negotiated version, cipher, key exchange and chain validation. The protocol set is explicit on Windows PowerShell: TLS 1.0–1.2, plus 1.3 with .NET 4.8 on Server 2022 / Windows 11.
  - **Raw probes.** `WebInv.Tls.Scan` sends five raw ClientHellos (TLS 1.3 → SSL 3.0) and one weak-suite hello, stopping each handshake after ServerHello/Certificate.
  - **Certificate source.** The leaf comes from Schannel when it connected, otherwise from the raw handshake (`CertSource` = `schannel` or `raw-<version>`).
  - **Parsing.** `WebInv.Der` parses SANs (DNS, IPv4/IPv6, email, URI) without the locale-dependent `Format()` and writes subject and issuer in Go DN format for Recog.
  - **Analysis.** `Set-TlsFields` computes days left, self-signed, signature and key strength, and hostname coverage including wildcards.
  - **Warm-up.** The chain engine is initialised once before the workers start, which prevents handshake stalls under load.
- **Writes:** the TLS and certificate column groups; `cert.subject` / `cert.issuer` / `cert.san` / `alpn` observations; the TLS and certificate flags.

#### A10. SAN virtual hosts (opt-in)
- **Switches:** `-ProbeSans`, `-MaxSans` (default 10).
- **Wiring:** each non-wildcard DNS SAN that resolves to the **same IP** and passes scope/exclusions is requested with that Host/SNI. A synchronized `VhostSeen` table emits each vhost once per IP:port across jobs. A row is kept only when status, title or body hash differs from the base site.
- **Writes:** extra rows with `Vhost` = true and `VhostOf`.

#### A11. Names
- **Switches:** `-ReverseDns`, `-AllAddresses`.
- **Wiring:** `Net.ReverseLookup` results are cached per IP in a synchronized table shared by all workers. Forward resolution uses `Net.ResolveMany`, a sliding window of 32 lookups each on its own timeout. `-AllAddresses` scans every A/AAAA record of a name.
- **Writes:** `ReverseDns`; DNS failures go to the error log, and an unresolved name is not fatal.

#### A12. Fingerprinting engine
- **Wiring:** `Complete-Row` → `WebInv.Matcher.Evaluate(Observation)`.
  - **Prefilter.** Each rule regex is reduced to the literal text a match must contain (an OR of AND-sets, via `Lit`). An Aho-Corasick pass over each value then runs only the rules whose literals are present; a 120 KB page matches in about 8 ms.
  - **Regex.** Every rule regex has a 200 ms timeout (ReDoS guard), and timeouts are counted in the summary.
  - **Rule logic.** AND/NOT conditions, port scoping, version capture, CPE 2.3 templates, `implies` / `excludes` / `requires` / `requiresCategory`.
  - **Merging.** `Matcher.Aggregate` merges detections across sources in three passes: by key, by kind and name (different CPE spellings), and by CPE product plus version (different vendor spellings).
  - **CPE supplement.** `Matcher.ApplyCpeSupplement` gives an imported rule output the reviewed CPE for its product when it has none (never for a rule that writes a fixed version), and replaces a known-wrong upstream CPE only while the rule still carries exactly that CPE. The built-in rules carry their CPEs directly.
  - **Output.** Detections below `-MinConfidence` (default 50) are dropped. Categories in `$MgmtCategories` raise `MgmtInterface`.
- **Rule packs:** `Initialize-Rules` loads the embedded pack, every `WebInventory.rules.*.json` next to the script, and any `-RulesFile`. It logs each pack's version, load count and SHA-256. `-NoCompanionRules` skips the packs next to the script. All 11,434 rules load in about 0.6 s.

#### A13. Passive version advisories
- **Wiring:** `$Advisories` is a data table: product, CVEs, version regex, fixed releases, oldest fixed branch and a high-risk configuration pattern. `Complete-Row` reads the versions the server itself advertises in Server and X-Powered-By and calls `WebInv.Advisory.Status`. A product detected without a version yields `version-hidden`.
- **Ships with:** PHP2Shell (CVE-2026-109618 / CVE-2026-109619). Fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; 8.1 and older count as an EOL branch; a PHP token in an Apache `Server` header means mod_php.
- **Writes:** `Advisories` (the reasoning, including "fixed" results, so coverage can be audited) and the PHP2Shell flags. The HTML report shows an "Advisory exposures" card, and the column is tracked in the baseline delta.

### B. Opt-in probes (v2.3)

All six capabilities in this section load the extras block through `Initialize-Extras`. `Extras.BindEngine` binds a `TcpConnector` delegate to `WebInv.Net.Connect`, so every probe connection inherits proxy tunnelling and local-exhaustion handling. The protocol probes (B2–B4) also share these traits:
- Main's `JobBuilder` queues their jobs first, so they own their host:port, and a plain check of 445/3389/161 from `-Port` is skipped.
- `New-ProtoRow` gives the rows `Service`/`Scheme` = `smb`, `rdp` or `snmp`, and they print even without `-ShowNonWeb`.
- NTLM CHALLENGE fields go through `Set-NtlmFields` into `DeviceName` / `Domain` and the `ntlm.*` observations.

#### B1. TLS fingerprints: JARM and JA4S
- **Switches:** `-TlsFingerprint`; `-NoJa4s` for JARM only.
- **Wiring:**
  - **JARM.** `Add-TlsFingerprint` → `WebInv.Jarm.Compute`, a C# port of `jarm.py`: the same 10 ClientHellos (cipher order, GREASE, ALPN, supported_versions and extension order), the same ServerHello parsing (including Python slicing quirks) and the same 62-character fuzzy hash. A timeout in any probe yields 62 zeros, as in jarm.py; the set is retried once first.
  - **JA4S.** `WebInv.Ja4s.FromHelloInfo` works from `TlsScanResult.HelloInfo`, the first accepted ServerHello of the raw TLS scan (version | cipher | extension list | ALPN), so it adds no traffic. Format: `t<ver><ext count><alpn>_<cipher>_<sha256(ext list)[:12]>`.
- **Writes:** `Jarm`, `Ja4s`; `tls.jarm` (matched by 18 Recog JARM signatures) and `tls.ja4s` observations. In the store, both are gated fields: `tlsFingerprint` and `ja4s`.
- **Cost:** 10 extra connections per TLS service (20 if retried). JA4S is free.

#### B2. SMB
- **Switch:** `-Smb` (TCP 445; `smb://host:port` for other ports).
- **Wiring:** `Invoke-SmbCheck` → `WebInv.Smb.Probe`:
  - **SMB2 connection.** NEGOTIATE offering dialects 2.0.2–3.1.1 with preauth-integrity and encryption contexts. Then one SESSION_SETUP carrying SPNEGO NTLMSSP NEGOTIATE; `Ntlm.ParseChallenge` reads the CHALLENGE's target info: NetBIOS and DNS computer and domain, forest, and the OS version.
  - **SMBv1 connection.** "NT LM 0.12" only. When accepted with extended security, one session-setup leg returns NativeOS and NativeLM.
  - **No authentication** is attempted at any point.
- **Writes:**
  - Columns: `DeviceName`, `Domain`, `ProtocolInfo` (`dialect`, `signing`, `smbv1`, `osBuild`).
  - Flags: `SMBv1`, `SMBSigningNotRequired`.
  - Observations: `ntlm.version` (31 built-in Windows-build rules feeding `OsHint`), `smb.nativeos` / `smb.nativelm` (81 Recog rules).
- **Cost:** 2–3 connections per host with 445 open.

#### B3. RDP
- **Switch:** `-Rdp` (TCP 3389; `rdp://host:port`).
- **Wiring:** `Invoke-RdpCheck` → `WebInv.Rdp.Probe`:
  - **Negotiation.** An X.224 Connection Request offering SSL, HYBRID and HYBRID_EX shows the protocol the server selects.
  - **TLS.** An `SslStream` (Schannel) handshake captures the RDP certificate.
  - **CredSSP.** A TSRequest carrying NTLM NEGOTIATE returns the CHALLENGE.
  - **NLA check.** A TLS-only request answered with failure 5, HYBRID_REQUIRED_BY_SERVER, means NLA is enforced.
  - **Standard security.** A standard-RDP request shows whether legacy RDP security is still accepted. RDP-only servers are recognised, and negotiation failures are reported by name.
- **Writes:**
  - Every certificate column and flag (`CertSource` = `rdp`), plus `TlsVersion`.
  - `DeviceName`, `Domain`, `ProtocolInfo` (selected protocol, NLA, standard security, `osBuild`).
  - Flags: `RdpNlaNotRequired`, `RdpStandardSecurity`.
- **Cost:** 2–3 connections.
- **Limit:** the handshake uses Schannel, so a TLS 1.0-only RDP server yields no certificate on a hardened scanner host.

#### B4. SNMP
- **Switches:** `-Snmp` with `-SnmpCommunity` (v1/v2c), or `-SnmpCredential` (v3 user and auth password) plus optional `-SnmpPrivPassword`. Algorithms: `-SnmpAuthProtocol` MD5 | SHA | SHA256, `-SnmpPrivProtocol` DES | AES. `-SnmpVersion` 1 | 2c | 3.
- **Guard rails (60-main, before anything is sent):**
  - A community string is never guessed.
  - v1/v2c requires a community string.
  - With no credential at all, only the unauthenticated SNMPv3 engine discovery is sent.
  - SNMPv3 passwords must be at least 8 characters (RFC 3414), and privacy requires authentication.
  - SNMP options without `-Snmp`, or `-Snmp` together with `-Proxy` (UDP), are refused.
- **Wiring:** `Invoke-SnmpCheck` (dispatched before the TCP connect) → `WebInv.Snmp.Query` with the four system OIDs (sysDescr, sysObjectID, sysName, sysLocation):
  - **Encoding.** A BER encoder/decoder.
  - **v1/v2c.** A GET with the supplied community.
  - **v3 USM.** Engine discovery, then an authenticated GET: RFC 3414 key localisation, HMAC-MD5-96 / HMAC-SHA-96 / HMAC-SHA-256-192, and DES-CBC or AES-128-CFB.
  - **States.** No answer is `filtered` (no row); an ICMP port-unreachable is `closed`.
- **Writes:**
  - `Banner` = sysDescr, `DeviceName` = sysName.
  - `ProtocolInfo`: version, sysObjectID, location, engine ID.
  - Flag `SnmpV1V2c` (cleartext community).
  - Observations: `snmp.sysdescr` / `snmp.sysobjid` (5 built-in rules plus 630 Recog fingerprints).
- **Cost:** one UDP request, plus one for v3 discovery, retried `-Retries` times on silence.

#### B5. Screenshots
- **Switches:** `-Screenshot`, `-BrowserPath` (any Chromium; default is Edge from Program Files), `-BrowserArgument`, `-ScreenshotThreads` (4), `-ScreenshotSize` (1366x768), `-ScreenshotTimeoutSec` (30).
- **Wiring:** `Invoke-Screenshots` runs after the scan loop on the finished CSV.
  1. **Allow-list.** It builds a per-IP map: every scanned origin (`host:port` and `ip:port`) maps to the scanned IP.
  2. **Canary.** A `WebInv.ScopeProxy` with an empty allow-list plus a capture of `http://wi-proxy-check.invalid/` must see the browser's request. If an enterprise policy forces another proxy or blocks headless mode or remote debugging, no screenshots are taken and the error log says why.
  3. **Browser.** For each page, `Start-Browser` launches headless Edge with a fresh temporary profile, privacy and anti-chatter flags, `--proxy-server` pointing at a per-page `ScopeProxy` on loopback, `--proxy-bypass-list=<-loopback>` and DevTools on 127.0.0.1 with a random port.
  4. **Capture.** `WebInv.CdpCapture` drives the page over the DevTools WebSocket: `Page.enable` / `Network.enable` → `Emulation.setDeviceMetricsOverride` → `Page.navigate` → wait for `loadEventFired` → `Page.captureScreenshot` → `document.title`. `Network.requestWillBeSent` records what the page asked for.
  5. **Scope.** `ScopeProxy` forwards CONNECT and absolute-URI HTTP only to allowed origins, always to the IP the scanner used, through `Extras.Connect` (and so through `-Proxy` when set). Everything else gets a 403.
  6. **Cleanup.** Process trees and profiles are removed after each page. On a rerun, captures already marked `ok` are kept.
- **Writes:**
  - PNGs in `WebInventory_<RunId>_screenshots\`.
  - Index `WebInventory_<RunId>_screenshots.csv`: `Url`, `Host`, `IP`, `Port`, `File`, `Sha256`, `Bytes`, `Status`, `PageTitle`, `PageRequests`, `BlockedOrigins`, `ProxyRefused`, `Ms`.
  - Manifest entries with relative paths, and the image in the HTML report's row details. Screenshots are not archived in the store.
- **Note:** certificate errors are ignored for rendering (internal self-signed sites). Pages behind HTTP Basic authentication are recorded as failed.

#### B6. Jump-host proxy (HTTP CONNECT)
- **Switches:** `-Proxy http://host:port`, `-ProxyCredential` (Basic).
- **Wiring:**
  - **Pre-flight (60-main).** The URL must be `http://`, with credentials in `-ProxyCredential` rather than the URL. The proxy is resolved once and its reachability is tested. Then `WebInv.Net.ProxyIp` / `ProxyPort` / `ProxyAuthorization` are set, and one CONNECT to the first check catches an unexpected 407 before scanning starts.
  - **In scan.** `Net.Connect` → `ConnectViaProxy` handles every TCP connection: the connect test, HTTP, Schannel, raw TLS, JARM, SMB, RDP and screenshots. Port state is taken from the proxy's answer:

    | Proxy answer | State |
    |---|---|
    | 200 | open |
    | 502/503 | closed, or filtered when Squid's `X-Squid-Error` errno is ETIMEDOUT/EHOSTUNREACH |
    | 504 or no answer | filtered |
    | 400/403/405/407/other | refusal: logged as a `PROXY` error and left unfinished for `-Resume` |
- **Writes:** a refusal counter, the last refusal reason and the proxy line in the run summary; `settings.proxy` in `run.json`.
- **Limits:** names resolve on the scanning host. The proxy must answer CONNECT only after it reaches the target (Squid, tinyproxy and Apache `mod_proxy_connect` do). UDP (`-Snmp`) cannot be proxied.

### C. Run control, output and evidence

#### C1. Pace, dispatch and resilience
- **Switches:** `-Pace Polite|Normal|Fast`, `-Threads`, `-MaxPerHost`, `-TimeoutMs`, `-Retries`, `-DelayMs`, `-JitterMs`, `-BannerWaitMs`, `-MaxRuntimeMinutes`, `-Resume`.
- **Presets** (explicit parameters always win):

  | Preset | Threads | Per host | Timeout | Delay + jitter | Retries |
  |---|---:|---:|---:|---|---:|
  | Polite | 16 | 2 | 4,000 ms | 100 + 0–250 ms | 1 |
  | Normal (default) | 64 | 4 | 3,000 ms | none | 1 |
  | Fast | 192 | 8 | 1,500 ms | none (banner wait 150 ms) | 0 |
- **Wiring:**
  - **Workers.** The worker functions are registered once in an `InitialSessionState`. `-Threads` long-lived runspaces pull work from `WebInv.Sched` (C#: per-host cap, round-robin) and return results on a signalled queue; there is no per-check PowerShell instance and no polling.
  - **Watchdog.** Each check gets a budget derived from the enabled probes and timeouts. A worker that overruns it, or crashes, is stopped and replaced, and the check is logged.
  - **Time limit.** `-MaxRuntimeMinutes` stops dispatching cleanly.
  - **Resume.** The progress file (`host|ip|port` per completed check) lets `-Resume` skip finished checks and append to the same CSV/JSONL. `run.json` records each session.

#### C2. Outputs
| File (in `-OutputDir`; logs in the current folder) | Content |
|---|---|
| `WebInventory_<RunId>.csv` | 78 columns, UTF-8 BOM for Excel, streamed while scanning (`WebInv.Out.CsvLine`) |
| `WebInventory_<RunId>.jsonl` | The same fields plus `Detections` with confidence, source and evidence (`Out.JsonLine`, HTML-sensitive characters escaped) |
| `WebInventory_<RunId>.html` | Self-contained offline report: summary cards, top products/flags/categories, free-text filter, web/TLS/non-web selector, sortable table, row drill-down, screenshots, light/dark, phone width |
| `_delta.csv` (`-BaselineCsv <file>` or `auto`) | NEW / REMOVED / CHANGED per `Host\|Port` over 12 fields (IP, Scheme, StatusCode, Title, Server, Products, CertSha256, CertNotAfter, TlsSupported, FaviconMmh3, Flags, Advisories) |
| `_run.json` | When, by whom, on which host; probe profile; settings (pace, threads, ports, proxy, SNMP mode); sessions; completeness |
| `_progress.txt` | Completed checks, for `-Resume` and for the store's absence logic |
| `_manifest.txt` | SHA-256 and size of every output and both logs |
| `_run.log`, `_error.log` | Preflight, effective parameters (defaults marked, secrets redacted), per-check debug, summary; categorised errors (`INPUT`, `SCOPE`, `DNS`, `NET`, `PROXY`, `TLS`, `WORKER`, `IO`, `RULES`, `SNMP`, `SCREENSHOT`, `SELFTEST`, `FATAL`) |
| `-PassThru` | Row objects on the pipeline (scan and store queries) |

Exit codes: `0` clean · `1` fatal / refused to start · `2` completed with logged errors (or a failed store ingest, or failed verification) · `3` interrupted or time limit hit.

#### C3. Preflight and hostile-content handling
- **Preflight (logged):** .NET release, FIPS policy, Schannel client protocol registry, the effective `SslProtocols`, SHA-256 provider, execution policy, the script's Authenticode status and the SHA-256 of every rule pack. The run refuses to start on .NET older than 4.7.2, or if the mmh3 self-check fails.
- **Hostile content:** scanned hosts control titles and headers, so:
  - CSV cells starting with `= + - @` get a `'` prefix (`-NoCsvSanitize` turns this off).
  - Control characters and ANSI escapes are stripped before console output.
  - The HTML report never uses `innerHTML` for data, and its embedded JSON is escaped.
- **Settings file:** `-ConfigFile` takes a data-only `.psd1` read with `Import-PowerShellDataFile`. Unknown keys are refused and the command line wins. PSCredential and SecureString secrets can only be passed on the command line.

### D. Inventory store

#### D1. Architecture
- **Switches:** `-Store <folder>`, `-StoreEngine Auto|Esent|File`, `-NoStore`, `-RetireAfter` (3).
- **Layout:**
  ```
  <Store>\STORE.json   identity, engine, schema, retire threshold, snapshot/anchor options
  <Store>\LOCK         held while a process has the store open (a second one waits 30 s)
  <Store>\store.log    what the store did, append-only
  <Store>\db\          working database: ESENT inventory.edb + logs, or inventory.kv (disposable)
  <Store>\archive\ledger.jsonl                      one line per run / correction / rebase, chained by SHA-256
  <Store>\archive\runs\yyyy\MM\<RunId>\             results.jsonl.gz, results.csv.gz, report.html.gz, checked.txt.gz,
                                                    run.json, logs, manifest, INPUTS.json + changes.jsonl.gz, state.jsonl.gz
  <Store>\archive\corrections\<seq>-<op>\           correction.json + derived changes
  <Store>\archive\rebase\<seq>\<pos>\               derived files of a replay in a new order
  <Store>\archive\anchors\<seq>.p7s                 detached ledger signatures (optional)
  ```
- **Wiring:**
  - **Ingest timing.** 60-main checks before scanning that the store can take the run (engine available, matching engine). Ingest starts only after the manifest is final: `Invoke-StoreIngest` → `Initialize-StoreEngine` (compiles the store block) → `InventoryStore.Open` → `Ingest(RunSources)`.
  - **Ingest steps.** Each run is archived, then appended to the ledger: the SHA-256 of every archived file and of the previous line, plus the derived digests. It is then applied to the database.
  - **Engines.** `EsentKv` calls `esent.dll` directly through P/Invoke, with no ManagedEsent DLL. It gives transactions, crash recovery and keyed lookups: one lookup and one small last-seen update per sighting. `FileKv` is the portable engine, held in memory and saved atomically.
  - **Key schema.** `m` meta · `r/<seq>` run · `ri/<runId>` · `k/<sha(natural key)>` → entity · `e/<eid>` · `v/<eid>/<ver>` version · `c/<seq>/<eid>` change · `x/<eid>/<seq>` per-entity index.
- **Property:** the database is a deterministic function of the archive. Delete `db\` and the next open rebuilds it. On Windows, `-SelfTest` requires ESENT and the portable engine to produce byte-identical digests.

#### D2. Change model
- **Identity:** `Host` + `IP` + `Port` (+ vhost). Address moves are paired only when unambiguous, and show up as `Rekeyed` with the rule and both addresses. The signature must be held by exactly one disappeared and one new service, and by no other service seen in the run. The three pairing rules:
  - **R1:** same DNS name and port.
  - **R2:** same reverse-DNS name and port.
  - **R3:** same certificate SHA-256, port, title, server and products.
- **Versions:** 65 fingerprint fields (`InvSchema.Material`) define a version. Per-sighting values never create one: `ScannedAt`, `VhostOf`, `BodyLength`, `BodySha256`, `ResponseMs`, `CertDaysLeft`, `Notes`, `ScanTag`. Banner clock/date text and the `CertExpiring` day count are normalised before comparing.
- **Probe gating:** a run without a probe keeps the previous values of the fields only that probe collects. The gated probes are TLS scan, favicon, extras, options, identify paths, reverse DNS, TLS fingerprint and JA4S. When a newly enabled probe fills previously empty fields, the event is `Enriched`, not `Changed` (`InvSchema.IsEnrichment`).
- **Absence:** a service is `Missing` only if the run actually checked its host:port (`checked.txt`). SAN vhosts go missing only in `-ProbeSans` runs. After `-RetireAfter` consecutive in-scope misses a service is `Retired`; if it returns it is `Reappeared`, with the diff.
- **Event types:** `Added`, `Changed`, `Enriched`, `Missing`, `Retired`, `Reappeared`, `Rekeyed`, `Merged`, `Split`.
- **Run order:** runs apply in start order. A run that is incomplete (interrupted, time limit) is not added unless imported as partial with `-Force`. An older run is refused unless `-Backfill` is given.

#### D3. Queries
- **Switches:** `-StoreQuery Inventory|Changes|History|Runs|Vulnerabilities`, `-Filter`, `-Status`, `-ChangeType`, `-Since`, `-Until`, `-WithinDays`, `-AsOf`, `-PassThru`.
- **Wiring:** `InventoryStore.Query` with a `RowFilter`, applied while reading, so a filtered Inventory query on a 200,000-service test store took 9.3 s and 745 MB instead of 34 s and 1.6 GB.
- **Filter syntax:** `Field<op>Value`; all clauses must match.
  - `=` matches the whole value or one `;` item, and a flag name matches its detail.
  - `~` means contains; `!=` and `!~` negate.
  - `< <= > >=` compare numbers, then dates, then text. `Any~` searches every column.
  - `CertDaysLeft` is recomputed at query time, or relative to `-AsOf`.
- **Writes:** `WebInventory_store_<query>_<stamp>[_n].csv` (Inventory also gets the HTML report). Names get a `_2`, `_3` suffix, so queries in the same second never overwrite each other.
- **Inventory columns:** status, identity, the 65 fingerprint fields, `FirstSeen`, `LastSeen`, `LastChange`, `Versions`, `MissingSince`, `MissingRuns`, `RetiredAt`, `FirstRun`, `LastRun`, `EntityId` and the last sighting's details. Changes and History list one row per changed field, plus `Rule`/`OldKey` for moves and `Note` for corrections.

#### D4. Corrections: manual merge and split
- **Switches:** `-StoreMerge <idA>,<idB> -Reason`, `-StoreSplit <id> [-SplitAt <RunId>] -Reason`.
- **Wiring:** `InventoryStore.Correct`:
  1. Dry-run validation. A merge of services seen in the same run is refused, and a split is refused when something has since been seen at the old address.
  2. `archive\corrections\<seq>-<op>\correction.json` records who, when and why.
  3. The correction is applied live, its derived changes are recorded, and a `correction` ledger line is appended. An interrupted correction is completed by `Reconcile` on the next open.
- **Merge:** the earlier entity keeps its id; the later one's history becomes a `Rekeyed` event with rule `manual-merge`; the earlier one's absences from that point are dropped.
- **Split:** the original goes back to its old address, with its absences recomputed from the archived check lists.
- **Property:** a correction is a ledger entry, never a rewrite. It is replayed at its position by `-RebuildStore` and `-VerifyStore`. `Merged` and `Split` events carry the reason in `Note`.

#### D5. Backfill (older runs)
- **Switch:** `-ImportRun <runs> -Backfill`.
- **Wiring:** `InventoryStore.Backfill` archives the older run(s) and appends a `rebase` ledger entry. The entry records the new plan, with runs ordered by start time and each correction kept right after the run it followed, plus every position's digests. The working database is then replayed in that order. Nothing already in the ledger changes. A correction whose services no longer exist in the new order is recorded as void.
- **Cost:** a full replay, about the time of `-RebuildStore`.

#### D6. Archive growth: snapshot thinning
- **Switch:** `-SnapshotEvery N`, kept in `STORE.json`.
- **Wiring:** a full `state.jsonl.gz` is kept for the first run and every N-th run; the other runs keep their change log. `-AsOf` on a run without a snapshot replays history in memory from the nearest snapshot, using a shadow `FileKv`. State digests are still recorded for every run, so verification is unchanged.
- **Scale:** a full snapshot is about 13 MB per 50,000-service run.

#### D7. Ledger anchoring
- **Switches:** `-AnchorEventLog` (+ `-RegisterEventSource` once, elevated) and `-AnchorCertificate <thumbprint>`. Both are kept in `STORE.json`, so scheduled runs keep anchoring without the switches; `-AnchorEventLog:$false` and `-AnchorCertificate ''` turn them off.
- **Wiring:** `Invoke-StoreAnchors` runs after every ledger append (ingest, correction, backfill, rebuild).
  - **Event log.** Each new head goes to the Application log as source `WebInventory`, event 4100.
  - **Signing.** Each new ledger line is signed with a detached CMS/PKCS#7 SHA-256 signature, using a certificate with a private key from `CurrentUser\My` or `LocalMachine\My`, saved as `archive\anchors\<seq>.p7s`.
  - **Verification.** `Test-StoreAnchors`, run by `-VerifyStore`, checks every signature against its line, flags lines since signing began that have none, and compares event-log entries with the ledger. A seq the ledger no longer has, or a different head, fails verification.

#### D8. Verify and rebuild
- **Switches:** `-VerifyStore`, `-RebuildStore` (+ `-StoreEngine` to switch engines).
- **Wiring:**
  - `Verify` walks the ledger chain, checks every archived file's SHA-256, replays the whole history in memory (original order and every rebase), compares each position's change and state digests, then compares the live database.
  - `Rebuild` recreates `db\` from the archive and checks every digest against the ledger.
- **Operation:** back up `archive\` and `STORE.json`; it is append-only, so `robocopy /E /XO` works. `-VerifyStore` runs on a copy, even on another machine without `db\`. ESENT needs a local NTFS volume and is tied to its Windows installation, so on a new machine rebuild instead of copying it.

### E. Offline vulnerability correlation

- **Switches:** `-StoreQuery Vulnerabilities -NvdFeed <files|folders> [-KevFile <json|csv>] [-EpssFile <csv[.gz]>]`, plus the usual `-Filter` / `-Status`.
- **Wiring:** `InventoryStore.Vulnerabilities` → `WebInv.Vulns.Run`:
  1. **Services.** The current inventory's services and their CPE 2.3 strings are collected. `Vulns.SetAliases` loads the CPE supplement's alias groups and platform list; each CPE is then also compared under every other NVD name of its product (renames such as `pulsesecure` → `ivanti`, `nginx:nginx` → `f5:nginx`, software vs firmware entries; 183 groups). Retired names that encode a version or model are never aliases.
  2. **NVD.** NVD JSON 2.0 feeds (`.json` or `.json.gz`) are read by a streaming record reader. A vendor:product prefilter skips records that name nothing in the inventory without parsing them. When a CVE appears in several feeds, the most recently modified record wins; rejected CVEs are skipped.
  3. **Versions.** `VersionCmp` compares versions numerically, including the NVD update field (`9.3:p1` = `9.3p1`) and `versionStart*/versionEnd*` ranges. Pre-release words sort before the release, vendor letters after it, and `2.4` = `2.4.0`.
  4. **Configurations.** AND configurations whose platform part the service's other CPEs do not satisfy are marked `(platform not verified)`.
  5. **Enrichment.** KEV (date added, due date, ransomware use) and EPSS (score and percentile) are joined. Rows are sorted KEV first, then EPSS, then CVSS.
  6. **Provenance.** `TeeHashStream` hashes each feed while it is read. The sidecar also records the supplement version, how many alias names were compared and how many OS KEV rows were held back.
- **Writes:**
  - `WebInventory_store_vulnerabilities_<stamp>.csv` with 21 columns: `Host`, `IP`, `Port`, `Url`, `Status`, `Products`, `Cpe`, `Cve`, `Kev`, `KevDateAdded`, `KevDueDate`, `KevRansomware`, `Epss`, `EpssPercentile`, `CvssScore`, `CvssSeverity`, `CvssVersion`, `Published`, `Match`, `EntityId`, `Description`.
  - A `.provenance.json` sidecar: each feed's name, SHA-256 and record count, the KEV catalog version, and the EPSS model version and score date.
- **Match confidence:**

  | `Match` | Meaning |
  |---|---|
  | `version` | The service's version is listed as affected |
  | `range` | The service's version falls inside an affected range |
  | `all-versions` | The NVD entry names the product with no version limit |
  | `... (platform not verified)` | The configuration also needs a platform the service's other CPEs do not show |
  | `product-only` | The service hides its version; listed for KEV CVEs only, and the rest are counted in the summary. Not listed at all for general-purpose operating systems (36 names: Windows, macOS, Linux kernel, distributions), whose patch level is not visible remotely; those are counted instead |
  | `... (as vendor:product)` | Found under another NVD name of the same product, e.g. `range (as concretecms:concrete_cms)` |
- **Measured:** 447,034 NVD records (2002–2026 plus the modified feed, 253 MB compressed) in about 50 s on 2 vCPU (lab store: 48.7 s in v2.3.0, 50.0 s in v2.3.1 with aliases); KEV 1,766 entries; EPSS 398,142 rows. On the lab store, v2.3.1 lists 936 rows (107 KEV) where v2.3.0 listed 1,347 (518 KEV): 453 product-only KEV rows from `(Ubuntu)` / `(Debian)` `Server` tokens are held back (counted) and 42 FortiOS KEV rows are new.
- **Limits:**
  - Distribution packages with backported fixes report the upstream version, so they can still match.
  - Services fingerprinted without a CPE and version cannot match. 729 of the 1,327 products with a CPE come from rules that do not capture a version, so they match only `all-versions` entries and KEV-listed CVEs.

### F. Rule management

| Task | Switches | Wiring |
|---|---|---|
| Import Recog or webappanalyzer | `-ImportRules <dir>`, `-ImportFormat Auto\|Recog\|Wappalyzer`, `-ImportOutput` | `Convert-RecogRules` (Ruby regex → .NET, `Matcher.FromRuby`) and `Convert-WappalyzerRules` (JS regex → .NET, `Matcher.FromJs`). Whole-value anchors, implies/excludes/requires, `requiresCategory`. Rules that don't compile, or that fail their own published example, are dropped and listed. The embedded CPE supplement is applied (`Matcher.ApplyCpeSupplement`) and noted in the pack's `source`, so a regenerated pack keeps the reviewed CPEs. The upstream git commit is recorded in the pack. |
| Export the embedded pack | `-ExportRules <file>` | Writes the 512 built-in rules; rename to `WebInventory.rules.<name>.json` to auto-load |
| Load packs | `-RulesFile`, `-NoCompanionRules`, `-MinConfidence` | `Initialize-Rules` → `Matcher.Load` |
| Test rules | `-TestRules` | Every rule with an `ex` example must match it and yield `exv` |
| Write rules | JSON keys `id f r o n c v p k ex exv and ports out im xs rq rc flag` | Fields: `header:<name>`, `title`, `body`, `meta:<name>`, `scriptsrc`, `cookiename`, `cookie:<name>`, `setcookie`, `auth`, `location`, `status`, `url`, `favicon.mmh3`, `favicon.md5`, `cert.subject`, `cert.issuer`, `cert.san`, `alpn`, `banner[.ssh\|ftp\|smtp\|pop3\|imap\|mysql]`, `robots`, `path:<path>.<field>`. v2.3 adds `ntlm.version`/`.computer`/`.domain`/`.dnscomputer`/`.dnsdomain`/`.forest`, `smb.nativeos`, `smb.nativelm`, `snmp.sysdescr`, `snmp.sysobjid`, `tls.jarm`, `tls.ja4s`. |

## 6. Network footprint per check

| Probe | Default | Requests / connections per service |
|---|---|---|
| Connect test | on | 1 connection (+ `-Retries` on silence) |
| Protocol detection, `GET /` | on | 1–2 requests (+ up to `-MaxRedirects` same-host hops) |
| Favicon | on | 0–2 GETs |
| robots.txt, security.txt, 404 probe | on | 3 GETs |
| Raw TLS probes | on (TLS services) | 5 version hellos + 1 weak-suite hello |
| `-Options` | off | 1 OPTIONS |
| `-IdentifyPaths` | off | 16 GETs |
| `-ProbeSans` | off | up to `-MaxSans` (10) GETs + redirects, same IP only |
| `-ReverseDns` | off | 1 PTR lookup per IP (cached) |
| `-TlsFingerprint` | off | 10 TLS connections (JARM; 20 if retried); JA4S 0 |
| `-Smb` | off | 2–3 connections per host with 445 open |
| `-Rdp` | off | 2–3 connections |
| `-Snmp` | off | 1 UDP request (+1 for v3 discovery), retried on silence |
| `-Screenshot` | off | One browser per page (4 in parallel), restricted to the scanned origins; 2–4 s per page in the lab |

Every HTTP request carries the User-Agent `... WebInventory/2.0 (authorized asset inventory)`, which you can change with `-UserAgent`. `-DelayMs` and `-JitterMs` are applied before each request and each protocol probe.

## 7. Performance (measured)

| Benchmark (2 vCPU, PowerShell 7.4, Linux) | v2.0.2 | v2.1.0+ |
|---|---:|---:|
| 200 web services on 50 hosts | 39.7 s, results differ from reference | 12.4 s, identical |
| Same at 20 ms RTT | 41.9 s | 13.0 s |
| 4,000 closed ports | 139 s, 2.8 GB | 12.1 s, 0.46 GB |
| 40 silent listeners (tarpit) | 12.9 s | 8.1 s |
| Target expansion, /18 × 26 ports (425,984 checks) | 3.1 s | 0.7 s |

- **v2.3 vs v2.2, new switches off:** identical results in 12 of 12 comparisons. Startup is 0.1–0.2 s slower (larger script and Recog pack) and the 200-service farm 0.3–0.6 s slower, within v2.2's own run-to-run spread.
- **Store ingest (portable engine):** 50,000 services in 18 s on the first run and 17 s on the next; 200,000 services in 70 s and 56 s.
- **Rule matching:** 11,434 rules load in about 0.6 s; a 120 KB page matches in about 8 ms (110 ms in v2.0.2).

These figures were measured under PowerShell 7.4 on Linux. Before quoting them for Windows PowerShell 5.1, re-run `tests/perf` or a lab-VLAN comparison on the scanner host.

## 8. Validation status

| Check | Result | Where |
|---|---|---|
| C# 5 compile of all three blocks against .NET Framework 4.7.2 reference assemblies | 0 errors, 0 warnings | Linux workspace |
| PSScriptAnalyzer, Windows PowerShell 5.1 compatibility profiles | Clean, apart from deliberate empty `catch` blocks and the explicitly loaded `System.Security.Cryptography.Pkcs` types | Linux workspace |
| `-SelfTest` | 125/125 (132 expected on Windows with ESENT) | PowerShell 7.4 |
| Lab regression scenarios | 25/25 | Local lab |
| Store scenarios | v2.2: 40/40 · v2.3: 34/34 (v2.3.1 adds alias, platform-check and OS-suppression cases) · Enriched gating: 4/4 | Portable engine |
| Interleaved A/B against v2.2.0 | Identical in 12/12 | Lab and 200-service farm |
| Crash safety | `kill -9` at four points of a 50,000-service ingest: byte-identical digests after reopen | Portable engine |
| JARM against `jarm.py` | Identical on 6 TLS services | Lab |
| JA4S against FoxIO `ja4.py` | Identical (2 ports directly, 2 from tshark-decoded ServerHellos) | Lab |
| SMB against impacket (SMB1 and SMB2 servers) | Correct dialect, signing, names and build; packets decode cleanly in Wireshark | Lab |
| RDP against a lab listener (NLA, TLS-only, legacy, standard-only) | All four modes identified | Lab |
| SNMP against a pysnmp agent (10 modes, including wrong credentials and discovery-only) | All correct; secrets absent from logs and `run.json` | Lab |
| Proxy | Same 26 rows as the direct scan; Basic auth; a missing-auth 407 stops the run; refusals left for `-Resume` | Lab CONNECT proxy |
| Screenshots (headless Chromium, Edge's DevTools path) | HTTP/HTTPS, direct and proxied; every third-party request and the browser's own background traffic refused | Lab |
| Vulnerabilities on real feeds | Expected CVEs present (Apache 2.4.49 → CVE-2021-41773/42013; Confluence 7.13.0 → CVE-2022-26134; OpenSSH 9.3p1 → CVE-2023-38408); fixed ones absent (CVE-2021-26084 for 7.13.0) | NVD 2002–2026, KEV, EPSS |
| v2.2 stores under v2.3 | Open, verify and ingest with identical digests | Portable engine |
| v2.3.1 CPE supplement | Every fill, replace, alias and platform name exists in the NVD CPE Dictionary; regenerated Recog and Wappalyzer packs identical to v2.3.0 apart from CPEs | NVD CPE Dictionary 2026-11-04 |
| v2.3.1 A/B lab scan against v2.3.0 | Identical apart from the `CPEs` column (FortiOS on 2 rows) and evidence order; scan times within run-to-run spread | Lab and 200-service farm |
| v2.3.1 vulnerabilities on real feeds | Newly matched: Serv-U 15.2.3 → CVE-2021-35211, TeamCity 2023.05.3 → CVE-2023-42793, Ivanti Connect Secure 9.1R8 → CVE-2021-22893 (as `pulsesecure`), Contact Form 7 5.3.1 → CVE-2020-35489; concrete5 8.5.4 0 → 133 rows and nginx 1.16.1 0 → 7 through aliases | NVD 2002–2026, KEV, EPSS |

**Still to run on the Windows scanner host:**
- Windows PowerShell 5.1 itself: `-SelfTest`, expecting 132.
- ESENT: `Test-WebInventoryStore.ps1`, which runs the self-test, compares ESENT with the portable engine, hard-kills ESENT ingests, verifies and rebuilds across engines, and tests backfill on ESENT and event-log anchoring.
- Edge headless policy: one interactive `-Screenshot`; the canary reports a blocking policy.
- Schannel for the RDP probe against real Windows hosts.

## 9. Requirements and deployment

- **Host:**
  - Windows PowerShell 5.1 with .NET Framework 4.7.2+ (4.8 + Server 2022 / Windows 11 for TLS 1.3 via Schannel).
  - ESENT is built into Windows.
  - Edge (or another Chromium browser) is needed only for `-Screenshot`.
  - Event-log anchoring needs a one-time `-RegisterEventSource` from an elevated prompt.
- **Placement:** sign the script (`Set-AuthenticodeSignature`), run it under AllSigned or RemoteSigned, and keep it and the packs in a write-protected folder. The run log records the signature status and the pack hashes.
- **Scheduled operation:**
  - Use `-ConfigFile` with `-Quiet -NoProgress` (see `WebInventory.example.psd1`).
  - Alert on exit codes 1 and 3; review exit code 2.
  - Add `-Store` for history, `-SnapshotEvery` to limit archive growth, and `-AnchorEventLog` / `-AnchorCertificate` for external evidence.
- **Evidence package per run:**
  - Scope file mirroring the written authorisation.
  - Run log, error log and manifest.
  - With `-Store`, the archived run and its ledger line, plus the printed ledger head; record that head outside the store, or anchor it automatically.
- **Network sign-off:** register the scanner host with the SOC. The User-Agent identifies an authorised asset inventory.
- **Air-gapped enclaves:** slow HTTPS handshakes there usually mean Windows is trying to fetch intermediate certificates (AIA). The raw TLS probe is unaffected.

## 10. Licensing and third-party components

| Component | Licence | Notes |
|---|---|---|
| Recog rule pack | BSD-2-Clause (Rapid7) | Converted from upstream commit `1714aaed`; regenerate with `-ImportRules .\recog\xml` |
| Wappalyzer (webappanalyzer) rule pack | GPL-3.0 (data) | From commit `d91f7e51`. No obligations for internal use; keep `LICENSE-GPL-3.0.txt` and the notice with the pack if you distribute it outside your organisation. The script reads it as data. |
| Favicon hash | MurmurHash3 x86_32, public domain | Re-implemented in C# |
| JARM | BSD-3-Clause (Salesforce) | Method re-implemented in C#; checked against `jarm.py` |
| JA4S | FoxIO License 1.1 | Internal, non-monetised use is permitted. Using JA4+ to provide value to paying customers needs a FoxIO OEM licence, and FoxIO states the JA4+ methods are patent pending. `-NoJa4s` keeps JARM and drops JA4S. |

Full texts are in `THIRD-PARTY-NOTICES.txt` and `LICENSE-GPL-3.0.txt`. This summary is a plain reading of those licences, not legal advice.

## 11. Limits and non-goals

**Not included, by design:**
- Directory brute-forcing.
- Non-detection Nuclei templates.
- Default-credential checks.
- WhatWeb level 3+ aggression.
- Authenticated scanning beyond the SNMP credential you supply.
- Share listing.
- Exploitability testing.

**Known limits:**
- Version-based findings (CPEs, advisories, vulnerability matches) cannot see distribution backports.
- Wappalyzer's JavaScript-variable (`js`) and DOM (`dom`) checks need a browser and are skipped.
- RDP certificates from TLS 1.0-only servers are unreadable on hardened scanner hosts (Schannel).
- Names resolve on the scanning host even with `-Proxy`.
- Screenshots are not archived in the store.
- One process opens a store at a time.
- ESENT requires a local NTFS volume.

**Recommended next steps** (not implemented):
- Archive and diff screenshots in the store.
- Read RDP certificates with a raw ClientHello after the X.224 exchange.
- Widen version capture: 729 of the 1,327 products with a CPE come from rules that capture no version (most Wappalyzer technologies), so they can only match `all-versions` and KEV entries.
- Refresh the CPE supplement with `tools/cpe/` when the NVD dictionary or the upstream rule data moves on; only names nobody has reviewed come up.

## 12. Parameter reference (103 parameters)

| Group | Parameters (defaults in parentheses) |
|---|---|
| Targets | `-Target` (positional), `-TargetFile`, `-HostFile`, `-Port` (`web`), `-PortFile`, `-Exclude`, `-ExcludeFile`, `-Scope`, `-ScopeFile`, `-DropOutOfScope`, `-SkipInvalidInput`, `-AllAddresses`, `-MaxTargets` (65536), `-Force` |
| Pace | `-Pace` (Normal), `-Threads` (64), `-TimeoutMs` (3000), `-Retries` (1), `-MaxPerHost` (4), `-DelayMs` (0), `-JitterMs` (0), `-MaxRedirects` (5), `-MaxBodyBytes` (262144), `-BannerWaitMs` (300), `-MaxRuntimeMinutes` (0 = none) |
| Probes | `-NoFavicon`, `-NoExtras`, `-NoTlsScan`, `-Options`, `-IdentifyPaths`, `-ProbeSans`, `-MaxSans` (10), `-ReverseDns`, `-FollowOffHost`, `-UserAgent`, `-CertWarnDays` (30) |
| v2.3 probes | `-TlsFingerprint`, `-NoJa4s`, `-Smb`, `-Rdp`, `-Snmp`, `-SnmpCommunity`, `-SnmpVersion` (2c with a community, else 3), `-SnmpCredential`, `-SnmpAuthProtocol` (SHA), `-SnmpPrivProtocol` (AES when a privacy password is given), `-SnmpPrivPassword` |
| Screenshots | `-Screenshot`, `-BrowserPath` (Edge), `-BrowserArgument`, `-ScreenshotThreads` (4), `-ScreenshotSize` (1366x768), `-ScreenshotTimeoutSec` (30) |
| Network path | `-Proxy`, `-ProxyCredential` |
| Rules | `-RulesFile`, `-NoCompanionRules`, `-MinConfidence` (50) |
| Output | `-OutputDir` (current folder), `-Tag`, `-BaselineCsv` (file or `auto`), `-NoHtml`, `-NoCsvSanitize`, `-PassThru`, `-Quiet`, `-NoProgress`, `-ShowNonWeb` |
| Modes | `-ListTargets`, `-Resume`, `-ConfigFile`, `-SelfTest`, `-ImportRules`, `-ImportFormat` (Auto), `-ImportOutput`, `-ExportRules`, `-TestRules` |
| Store | `-Store`, `-NoStore`, `-StoreEngine` (Auto), `-RetireAfter` (3), `-ImportRun`, `-Backfill`, `-SnapshotEvery` (1), `-VerifyStore`, `-RebuildStore` |
| Store queries | `-StoreQuery`, `-Filter`, `-Status` (Inventory: Active,Missing), `-ChangeType`, `-Since`, `-Until`, `-WithinDays`, `-AsOf`, `-NvdFeed`, `-KevFile`, `-EpssFile` |
| Corrections and anchoring | `-StoreMerge`, `-StoreSplit`, `-SplitAt`, `-Reason`, `-AnchorEventLog`, `-AnchorCertificate`, `-RegisterEventSource` |

## 13. Release contents

| File | Purpose |
|---|---|
| `Invoke-WebInventory.ps1` | The tool: one file with the engines, the 512 built-in rules and the CPE supplement embedded. SHA-256 in `SHA256SUMS.txt` |
| `WebInventory.rules.recog.json` | 3,098 Recog rules (auto-loaded) |
| `WebInventory.rules.wappalyzer.json` | 7,824 Wappalyzer rules (auto-loaded) |
| `WebInventory.example.psd1` | Settings template for scheduled runs |
| `Test-WebInventoryStore.ps1` | One-off store validation on the scanner host |
| `README.md`, `PERFORMANCE.md` | Operator guide; measured performance and A/B records |
| `THIRD-PARTY-NOTICES.txt`, `LICENSE-GPL-3.0.txt` | Licences and upstream provenance |
| `SHA256SUMS.txt` | Hashes of the files above |

The dev suite (`WebInventory-v2.3.1-dev-suite.zip`, and the GitHub repository) adds the sources (`src/`, including `cpe-supplement.json`), `build.py`, the lab fixtures (web, TLS, proxy, RDP, SNMP, screenshot pages), the test harnesses (regressions, store scenarios, performance A/B) and `tools/cpe/` (rebuilds the CPE supplement from a newer NVD dictionary).

## 14. Quick start

```powershell
.\Invoke-WebInventory.ps1 -SelfTest                                     # offline checks (132 on Windows with ESENT)
.\Invoke-WebInventory.ps1 10.0.0.0/24 -ListTargets                      # expand + scope-check only; sends nothing
.\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -ScopeFile .\authorized.txt -Pace Polite -BaselineCsv auto
.\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -Smb -Rdp -TlsFingerprint -Screenshot -Store D:\WebInventoryStore
.\Invoke-WebInventory.ps1 -HostFile .\dmz.txt -Proxy http://jump01:3128 -ProxyCredential (Get-Credential)
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Changes -WithinDays 7 -ChangeType Added,Retired
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Vulnerabilities -NvdFeed D:\feeds\nvd `
    -KevFile D:\feeds\known_exploited_vulnerabilities.json -EpssFile D:\feeds\epss_scores-current.csv.gz -Filter 'Kev=Yes'
.\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -VerifyStore
```
