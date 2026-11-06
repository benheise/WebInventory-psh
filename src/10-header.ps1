<#
.SYNOPSIS
    Invoke-WebInventory.ps1 v2.4.0 - non-intrusive web service discovery and fingerprinting (CMDB-lite).

.DESCRIPTION
    TCP connect scan -> HTTP/HTTPS auto-detection on any port -> GET / (+ same-host redirects) ->
    favicon, robots.txt, security.txt and one random-path 404 probe -> raw TLS ClientHello probes
    (version matrix, ALPN/HTTP2, weak-cipher acceptance, certificate even when Schannel cannot connect) ->
    rule-based fingerprinting (embedded rules + optional Recog / webappanalyzer rule packs).

    Discovery and identification only. No exploits, no brute force, no credentials, no path
    enumeration. The optional -IdentifyPaths switch requests a fixed list of 16 public product
    landing/version pages; the optional -VersionPaths switch requests a product's documented version URL only
    after that product was detected without a version. Both are off by default.

    Console output shows positive hits only (nmap --open behaviour). A run log and an error log are
    written to the CURRENT directory; results go to CSV + JSONL (+ HTML report) in -OutputDir.

    With -Store, each complete run is also added to an inventory store: first/last seen, versions and change
    events per service, kept in an ESENT working database (esent.dll, part of Windows; nothing to install) that
    is rebuilt on demand from an append-only archive of every run's files and a hash-chained ledger.

.PARAMETER Target
    One or more targets: IP, hostname, CIDR (10.0.0.0/24), dash range (10.0.0.1-10.0.0.50 or 10.0.0.1-50),
    nmap octet range ('192.168.0-3.1-254'), host:ports ('web01:80,443,8000-8100'), [IPv6]:port or a URL.
    Quote anything containing commas.
.PARAMETER TargetFile
    File with one target per line (same syntax as -Target). '#' starts a comment.
.PARAMETER HostFile
    File of hosts/ranges; ports come from -Port / -PortFile. (-TargetFile and -HostFile may be combined.)
.PARAMETER Port
    Ports for targets without an explicit port. Lists/ranges plus keywords: web (26 common web ports), web-extended (114),
    mgmt (BMC/appliance/admin consoles), all (1-65535). Default: web.
.PARAMETER Exclude
    Hosts to skip: IPs, CIDRs, ranges, octet ranges, hostnames (nmap --exclude). -ExcludeFile reads a file.
.PARAMETER Scope
    Authorised scope (IPs/CIDRs/ranges/hostnames). When set, any target outside it stops the run before a
    single packet is sent (fail-closed) unless -DropOutOfScope. Redirects and SAN vhosts are also held to it.
.PARAMETER Pace
    Polite | Normal | Fast presets for Threads/MaxPerHost/TimeoutMs/DelayMs/JitterMs/Retries.
    Explicit parameters always win.
.PARAMETER IdentifyPaths
    Opt-in: request a fixed list of public product pages (OWA logon, /certsrv/, AD FS, RD Web, VPN portals,
    /version, Grafana /api/health, Atlassian applinks manifest, OIDC discovery...) to confirm product/version.
.PARAMETER VersionPaths
    Opt-in: after fingerprinting, when a product is detected without a version and its version is published at a fixed
    URL of the same service (Netdata /api/v1/info, Apache Flink /config, Plex /identity, Argo CD /api/version,
    Vaultwarden /api/version, Mailman 2 /mailman/listinfo, Sitecore /sitecore/shell/sitecore.version.xml), one GET to
    that URL (same scheme, host and port; no redirects followed, no login). At most 4 per service; the requests and
    their status codes are listed in the VersionPaths column.
.PARAMETER ProbeSans
    For HTTPS services, re-request / using each certificate SAN that resolves to the SAME IP as Host/SNI and
    record distinct virtual hosts as extra rows.
.PARAMETER TlsFingerprint
    Opt-in: JARM (10 extra TLS handshakes per TLS port) and JA4S (from the ClientHello the TLS scan already sends) server
    fingerprints, in the Jarm and Ja4s columns. JA4S is the FoxIO JA4+ method (FoxIO License 1.1).
.PARAMETER NoJa4s
    With -TlsFingerprint: JARM only. JA4S is licensed under the FoxIO License 1.1 (internal, non-monetised use; the
    JA4+ methods are patent pending); use this switch when results serve paying customers without a FoxIO OEM licence.
.PARAMETER Smb
    Also check TCP 445 on every target host: SMB dialect, signing, SMBv1, and the server's NetBIOS/DNS names, domain and
    Windows build from the first (unauthenticated) NTLM challenge. No login, no null session, no share listing.
.PARAMETER Rdp
    Also check TCP 3389: security protocols offered (TLS / CredSSP), whether NLA is enforced, the RDP certificate, and
    the server names and Windows build from the NTLM challenge. No login.
.PARAMETER Snmp
    Also query UDP 161 for sysDescr, sysObjectID, sysName and sysLocation. Needs -SnmpCommunity (v1/v2c) or
    -SnmpCredential (v3); a community is never guessed. With neither, only SNMPv3 engine discovery is sent (no credentials).
.PARAMETER SnmpCredential
    SNMPv3 user (user name + authentication password; empty password = noAuthNoPriv). See -SnmpAuthProtocol,
    -SnmpPrivProtocol, -SnmpPrivPassword. Secrets are never written to logs, run.json or the store.
.PARAMETER Screenshot
    After the scan, capture each web service's page with the Edge (Chromium) already on the host, headless, through a
    loopback proxy that only lets the browser reach the scanned origin. Index: WebInventory_<RunId>_screenshots.csv.
.PARAMETER BrowserPath
    msedge.exe / chrome.exe for -Screenshot (default: Edge from Program Files).
.PARAMETER Proxy
    http://host:port of an HTTP CONNECT proxy (for example on a jump host): every TCP connection of the scan goes
    through it. Names still resolve locally. The proxy must answer CONNECT only after it reached the target (Squid,
    tinyproxy, Apache mod_proxy_connect do). UDP (-Snmp) cannot be proxied.
.PARAMETER ProxyCredential
    Basic authentication for -Proxy.
.PARAMETER Resume
    Path to a WebInventory_<RunId>_progress.txt from an interrupted run. Re-run with the same target
    arguments plus -Resume; completed checks are skipped and results append to the original CSV/JSONL.
.PARAMETER ConfigFile
    .psd1 of parameter values (data only, parsed with Import-PowerShellDataFile). Command line wins.
.PARAMETER BaselineCsv
    Previous results CSV to diff against ('auto' = newest WebInventory_*.csv in -OutputDir).
.PARAMETER ImportRules
    Convert a Rapid7 Recog xml directory or a webappanalyzer 'src' directory into a rule pack and exit.
.PARAMETER Store
    Inventory store folder (created on first use). A complete scan run is archived and applied to it after the
    scan finishes. Also the target of -ImportRun / -StoreQuery / -VerifyStore / -RebuildStore.
.PARAMETER StoreEngine
    Auto (ESENT on Windows, File elsewhere) | Esent | File. The engine is fixed per store; -RebuildStore switches it.
.PARAMETER RetireAfter
    A service missing from this many consecutive runs that checked its host:port is marked Retired (default 3,
    stored with the store; earlier runs keep the value they were ingested with).
.PARAMETER ImportRun
    Add earlier runs to the store: output folders or any of a run's files (wildcards allowed), oldest first.
    The run's _progress.txt is required. Incomplete runs need -Force (imported as partial).
.PARAMETER StoreQuery
    Inventory | Changes | History | Runs | Vulnerabilities. Writes WebInventory_store_<query>_<stamp>.csv (+ HTML for Inventory) to
    -OutputDir; -PassThru also returns the rows. Narrow with -Filter, -Status, -ChangeType, -Since/-Until/-WithinDays, -AsOf.
.PARAMETER Filter
    'Field<op>Value' clauses, all must match; several clauses as an array or joined with ' -and '. Ops: = (whole
    value or one ';' list item; a flag name matches 'Flag:detail'), != , ~ (contains), !~ , < <= > >= (numbers,
    dates, text). Field Any searches every column.
.PARAMETER Status
    Inventory/History: Active, Missing, Retired or All (comma list accepted). Inventory default: Active,Missing.
.PARAMETER ChangeType
    Changes/History: Added, Changed, Enriched, Missing, Retired, Reappeared, Rekeyed, Merged, Split (comma list accepted).
.PARAMETER NvdFeed
    -StoreQuery Vulnerabilities: NVD CVE JSON 2.0 feed files or folders (nvdcve-2.0-*.json[.gz]); matched offline against
    the CPEs of the current inventory, version-aware. -KevFile adds CISA KEV (JSON or CSV), -EpssFile FIRST EPSS (CSV[.gz]).
.PARAMETER StoreMerge
    Two entity ids (from Inventory/History queries) that are the same service: the later one is folded into the earlier,
    recorded as a correction in the ledger (nothing is rewritten). -Reason is required.
.PARAMETER StoreSplit
    Entity id whose latest (or -SplitAt RunId) address-move pairing was wrong: the history is split again at that run.
.PARAMETER Backfill
    With -ImportRun: allow runs older than the newest run in the store. The ledger records the new order and the
    working database is replayed in run order.
.PARAMETER SnapshotEvery
    Keep the full inventory snapshot (state.jsonl.gz) only every N runs (default 1 = every run). Other runs keep their
    change log; -AsOf replays from the nearest snapshot.
.PARAMETER AnchorEventLog
    Write each new ledger head to the Windows Application event log (source WebInventory; create it once, as
    administrator, with -RegisterEventSource). -VerifyStore checks the ledger against those events.
.PARAMETER AnchorCertificate
    Thumbprint of a code-signing / document-signing certificate (CurrentUser or LocalMachine\My) used to sign each
    ledger entry (detached CMS, archive\anchors). -VerifyStore checks every signature.
.PARAMETER AsOf
    Inventory as it stood after the last run that started at or before this time (read from the archive).
.EXAMPLE
    .\Invoke-WebInventory.ps1 10.0.0.5
.EXAMPLE
    .\Invoke-WebInventory.ps1 -Target 10.0.0.0/24,'10.0.1.1-50',web01:8443 -Port web -Exclude 10.0.0.1 -Scope 10.0.0.0/16
.EXAMPLE
    .\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -PortFile .\ports.txt -Pace Polite -ScopeFile .\authorized.txt -BaselineCsv auto
.EXAMPLE
    .\Invoke-WebInventory.ps1 -TargetFile .\hostports.txt -IdentifyPaths -ProbeSans -ReverseDns -Tag 'Weekly-DMZ'
.EXAMPLE
    .\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -ListTargets          # expand + validate scope; sends nothing
.EXAMPLE
    .\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -Store D:\WebInventoryStore          # scan, then add the run to the store
.EXAMPLE
    .\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Changes -WithinDays 7 -ChangeType Added,Retired
.EXAMPLE
    .\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Inventory -Filter 'Technologies=Jenkins','CertDaysLeft<30'
.EXAMPLE
    .\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -VerifyStore
.EXAMPLE
    .\Invoke-WebInventory.ps1 -HostFile .\hosts.txt -Smb -Rdp -Snmp -SnmpCredential (Get-Credential inventory) -SnmpPrivPassword (Read-Host -AsSecureString)
.EXAMPLE
    .\Invoke-WebInventory.ps1 -HostFile .\dmz.txt -Proxy http://jump01:3128 -TlsFingerprint -Screenshot
.EXAMPLE
    .\Invoke-WebInventory.ps1 -Store D:\WebInventoryStore -StoreQuery Vulnerabilities -NvdFeed D:\feeds\nvd -KevFile D:\feeds\known_exploited_vulnerabilities.json -EpssFile D:\feeds\epss_scores-current.csv.gz
.EXAMPLE
    .\Invoke-WebInventory.ps1 -SelfTest
.EXAMPLE
    .\Invoke-WebInventory.ps1 -ImportRules .\recog\xml                     # builds WebInventory.rules.recog.json
.NOTES
    Version 2.4.0. Windows PowerShell 5.1 + .NET Framework 4.7.2+ (4.8 for TLS 1.3 via Schannel). Also runs on PowerShell 7.
    Exit codes: 0 = clean; 1 = fatal / refused to start; 2 = completed, errors logged (or the store ingest failed, see
    store.log; or -VerifyStore found a problem); 3 = interrupted or -MaxRuntimeMinutes hit.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    # ---- Targets
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)][string[]]$Target,
    [string]$TargetFile,
    [string]$HostFile,
    [string]$Port = 'web',
    [string]$PortFile,
    [string[]]$Exclude,
    [string]$ExcludeFile,
    [string[]]$Scope,
    [string]$ScopeFile,
    [switch]$DropOutOfScope,
    [switch]$SkipInvalidInput,
    [switch]$AllAddresses,
    [ValidateRange(1, 16777216)][int]$MaxTargets = 65536,
    [switch]$Force,
    # ---- Pace / politeness
    [ValidateSet('Polite', 'Normal', 'Fast')][string]$Pace = 'Normal',
    [ValidateRange(1, 512)][int]$Threads = 64,
    [ValidateRange(200, 60000)][int]$TimeoutMs = 3000,
    [ValidateRange(0, 3)][int]$Retries = 1,
    [ValidateRange(1, 64)][int]$MaxPerHost = 4,
    [ValidateRange(0, 60000)][int]$DelayMs = 0,
    [ValidateRange(0, 60000)][int]$JitterMs = 0,
    [ValidateRange(0, 10)][int]$MaxRedirects = 5,
    [ValidateRange(4096, 4194304)][int]$MaxBodyBytes = 262144,
    [ValidateRange(0, 5000)][int]$BannerWaitMs = 300,
    [ValidateRange(0, 10080)][int]$MaxRuntimeMinutes = 0,
    # ---- Probes
    [switch]$NoFavicon,
    [switch]$NoExtras,
    [switch]$NoTlsScan,
    [switch]$Options,
    [switch]$IdentifyPaths,
    [switch]$VersionPaths,
    [switch]$ProbeSans,
    [ValidateRange(1, 50)][int]$MaxSans = 10,
    [switch]$ReverseDns,
    [switch]$FollowOffHost,
    [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebInventory/2.0 (authorized asset inventory)',
    [ValidateRange(1, 3650)][int]$CertWarnDays = 30,
    [switch]$TlsFingerprint,
    [switch]$NoJa4s,
    [switch]$Smb,
    [switch]$Rdp,
    [switch]$Snmp,
    [string]$SnmpCommunity,
    [ValidateSet('1', '2c', '3')][string]$SnmpVersion,
    [pscredential]$SnmpCredential,
    [ValidateSet('MD5', 'SHA', 'SHA256')][string]$SnmpAuthProtocol = 'SHA',
    [ValidateSet('None', 'DES', 'AES')][string]$SnmpPrivProtocol,
    [securestring]$SnmpPrivPassword,
    # ---- Screenshots (after the scan)
    [switch]$Screenshot,
    [string]$BrowserPath,
    [string[]]$BrowserArgument,
    [ValidateRange(1, 16)][int]$ScreenshotThreads = 4,
    [ValidatePattern('^\d{3,4}x\d{3,4}$')][string]$ScreenshotSize = '1366x768',
    [ValidateRange(5, 300)][int]$ScreenshotTimeoutSec = 30,
    # ---- Network path
    [string]$Proxy,
    [pscredential]$ProxyCredential,
    # ---- Rules
    [string[]]$RulesFile,
    [switch]$NoCompanionRules,
    [ValidateRange(1, 100)][int]$MinConfidence = 50,
    # ---- Output
    [string]$OutputDir = (Get-Location).ProviderPath,
    [string]$Tag,
    [string]$BaselineCsv,
    [switch]$NoHtml,
    [switch]$NoCsvSanitize,
    [switch]$PassThru,
    [switch]$Quiet,
    [switch]$NoProgress,
    [switch]$ShowNonWeb,
    # ---- Modes
    [switch]$ListTargets,
    [string]$Resume,
    [string]$ConfigFile,
    [switch]$SelfTest,
    [string]$ImportRules,
    [ValidateSet('Auto', 'Recog', 'Wappalyzer')][string]$ImportFormat = 'Auto',
    [string]$ImportOutput,
    [string]$ExportRules,
    [switch]$TestRules,
    # ---- Inventory store (history across runs)
    [string]$Store,
    [switch]$NoStore,
    [ValidateSet('Auto', 'Esent', 'File')][string]$StoreEngine = 'Auto',
    [ValidateRange(1, 1000)][int]$RetireAfter = 3,
    [string[]]$ImportRun,
    [ValidateSet('Inventory', 'Changes', 'History', 'Runs', 'Vulnerabilities')][string]$StoreQuery,
    [string[]]$Filter,
    [string[]]$Status,
    [string[]]$ChangeType,
    [Nullable[datetime]]$Since,
    [Nullable[datetime]]$Until,
    [ValidateRange(1, 36500)][int]$WithinDays,
    [Nullable[datetime]]$AsOf,
    [string[]]$NvdFeed,
    [string]$KevFile,
    [string]$EpssFile,
    [string[]]$StoreMerge,
    [string]$StoreSplit,
    [string]$SplitAt,
    [string]$Reason,
    [switch]$Backfill,
    [ValidateRange(1, 1000)][int]$SnapshotEvery = 1,
    [switch]$AnchorEventLog,
    [string]$AnchorCertificate,
    [switch]$RegisterEventSource,
    [switch]$VerifyStore,
    [switch]$RebuildStore
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '2.4.0'
$script:ScriptStart = Get-Date
$script:ExitCode = 0

#region ---------- Logging (run log + error log in the CURRENT directory) ----------
$script:Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogDir = (Get-Location).ProviderPath
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:Utf8Bom = New-Object System.Text.UTF8Encoding($true)
$RunLogPath = Join-Path $LogDir ("WebInventory_{0}_run.log" -f $script:Stamp)
$ErrLogPath = Join-Path $LogDir ("WebInventory_{0}_error.log" -f $script:Stamp)
try {
    $script:RunLog = New-Object System.IO.StreamWriter($RunLogPath, $true, $script:Utf8NoBom); $script:RunLog.AutoFlush = $true
    $script:ErrLog = New-Object System.IO.StreamWriter($ErrLogPath, $true, $script:Utf8NoBom); $script:ErrLog.AutoFlush = $true
}
catch { Write-Host "FATAL: cannot create log files in '$LogDir': $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
$script:ErrCounts = @{}
$script:ErrTotal = 0

function Write-RunLog {
    param([string]$Message, [string]$Level = 'INFO')
    if ($script:RunLog) { $script:RunLog.WriteLine(('{0} [{1,-5}] {2}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffzzz'), $Level, $Message)) }
}
function Write-ErrLog {
    param([string]$Category, [string]$Target, [string]$Message)
    $script:ErrTotal++
    if ($script:ErrCounts.ContainsKey($Category)) { $script:ErrCounts[$Category]++ } else { $script:ErrCounts[$Category] = 1 }
    if ($script:ErrLog) {
        $script:ErrLog.WriteLine(('{0} [ERROR] [{1}] {2} | {3}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffzzz'), $Category, $Target, ($Message -replace '[\r\n]+', ' ')))
    }
}
function Close-Logs {
    foreach ($n in 'RunLog', 'ErrLog') {
        $w = Get-Variable -Name $n -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($w) { try { $w.Flush(); $w.Dispose() } catch { } }
        Set-Variable -Name $n -Scope Script -Value $null
    }
}
function Stop-Fatal {
    param([string]$Message)
    Write-ErrLog 'FATAL' '-' $Message
    Write-RunLog "FATAL: $Message" 'FATAL'
    Write-Host "FATAL: $Message" -ForegroundColor Red
    Write-Host "Logs: $RunLogPath ; $ErrLogPath" -ForegroundColor DarkGray
    Close-Logs
    exit 1
}
#endregion

#region ---------- Config file + pace presets ----------
$Explicit = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($k in $PSBoundParameters.Keys) { [void]$Explicit.Add($k) }
if ($ConfigFile) {
    try { $conf = Import-PowerShellDataFile -LiteralPath $ConfigFile } catch { Stop-Fatal "Config file '$ConfigFile' could not be parsed: $($_.Exception.Message)" }
    $knownParams = $MyInvocation.MyCommand.Parameters
    foreach ($k in @($conf.Keys)) {
        if ($k -eq 'ConfigFile') { continue }
        if (-not $knownParams.ContainsKey($k)) { Stop-Fatal "Unknown setting '$k' in config file '$ConfigFile'" }
        if ($Explicit.Contains($k)) { continue }          # command line wins
        try { Set-Variable -Name $k -Value $conf[$k] } catch { Stop-Fatal "Invalid value for '$k' in config file: $($_.Exception.Message)" }
        [void]$Explicit.Add($k)
    }
}
$PaceTable = @{
    Polite = @{ Threads = 16; MaxPerHost = 2; TimeoutMs = 4000; DelayMs = 100; JitterMs = 250; Retries = 1 }
    Normal = @{}
    Fast   = @{ Threads = 192; MaxPerHost = 8; TimeoutMs = 1500; Retries = 0; BannerWaitMs = 150 }
}
foreach ($kv in $PaceTable[$Pace].GetEnumerator()) { if (-not $Explicit.Contains($kv.Key)) { Set-Variable -Name $kv.Key -Value $kv.Value } }
#endregion

#region ---------- Engine (inline C#, C# 5 / .NET Framework 4.7.2 compatible) ----------
$EngineSource = @'
__ENGINE_CS__
'@
try {
    if ('WebInv.Util' -as [type]) {
        if ([WebInv.Util]::EngineVersion -ne $ScriptVersion) {
            Stop-Fatal ("WebInv engine v{0} is already loaded in this PowerShell session (script is v{1}). Open a new PowerShell window." -f [WebInv.Util]::EngineVersion, $ScriptVersion)
        }
    }
    else {
        # Add-Type treats compiler warnings as errors; a newer .NET marking an API obsolete must not stop the tool from starting
        # (CI compiles every block with warnings as errors on Windows PowerShell 5.1: .github/workflows/check.yml)
        $addType = @{ TypeDefinition = $EngineSource; ErrorAction = 'Stop'; IgnoreWarnings = $true }
        if ($PSVersionTable.PSEdition -ne 'Core') { $addType.ReferencedAssemblies = @('System.Core', 'System.Security', 'System.Runtime.Serialization', 'System.Xml') }
        Add-Type @addType
    }
}
catch { Stop-Fatal "Engine compile failed: $($_.Exception.Message)" }
#endregion

#region ---------- Embedded rule pack ----------
$BuiltinRulesJson = @'
__BUILTIN_RULES__
'@
# Reviewed NVD CPE names: completes rule CPEs when a Recog/Wappalyzer pack is imported (fill/replace) and tells the
# offline vulnerability join which NVD names denote the same product (aliases). Data only; see THIRD-PARTY-NOTICES.
$CpeSupplementJson = @'
__CPE_SUPPLEMENT__
'@
#endregion
