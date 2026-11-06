<#
.SYNOPSIS
    Invoke-WebInventory.ps1 v2.3.1 - non-intrusive web service discovery and fingerprinting (CMDB-lite).

.DESCRIPTION
    TCP connect scan -> HTTP/HTTPS auto-detection on any port -> GET / (+ same-host redirects) ->
    favicon, robots.txt, security.txt and one random-path 404 probe -> raw TLS ClientHello probes
    (version matrix, ALPN/HTTP2, weak-cipher acceptance, certificate even when Schannel cannot connect) ->
    rule-based fingerprinting (embedded rules + optional Recog / webappanalyzer rule packs).

    Discovery and identification only. No exploits, no brute force, no credentials, no path
    enumeration. The optional -IdentifyPaths switch requests a fixed list of 16 public product
    landing/version pages; it is off by default.

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
    Version 2.3.1. Windows PowerShell 5.1 + .NET Framework 4.7.2+ (4.8 for TLS 1.3 via Schannel). Also runs on PowerShell 7.
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
$ScriptVersion = '2.3.1'
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
// ============================================================================
// WebInv engine - C# 5 / .NET Framework 4.7.2 compatible (also runs on .NET 8)
// Sockets, HTTP read, raw TLS ClientHello probing, DER helpers, hashing,
// fingerprint rule engine. No external dependencies.
// ============================================================================
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace WebInv
{
    // ------------------------------------------------------------------ HTTP / TCP
    public class RawResponse
    {
        public string State;
        public bool TlsOk;
        public string TlsError;
        public string TlsProtocol;
        public string Cipher;
        public int CipherBits;
        public string Hash;
        public string KeyExchange;
        public X509Certificate2 Cert;
        public string CertPolicyErrors;
        public string ChainStatus;
        public byte[] Raw = new byte[0];
        public bool ServerFirst;
        public string Error;
        public long Ms;
        public long ConnectMs;
        public long BytesIn;        // bytes received from the server (TLS: including handshake records)
        public bool TimedOut;       // the last read ended on the receive timeout (silence), not on close/reset
    }

    // Counts bytes read through it (lets the caller tell a silent listener from one that answered and then failed)
    public class CountingStream : Stream
    {
        readonly Stream inner;
        public long BytesRead;
        public CountingStream(Stream inner) { this.inner = inner; }
        public override bool CanRead { get { return inner.CanRead; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return inner.CanWrite; } }
        public override bool CanTimeout { get { return inner.CanTimeout; } }
        public override int ReadTimeout { get { return inner.ReadTimeout; } set { inner.ReadTimeout = value; } }
        public override int WriteTimeout { get { return inner.WriteTimeout; } set { inner.WriteTimeout = value; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { inner.Flush(); }
        public override int Read(byte[] buffer, int offset, int count) { int n = inner.Read(buffer, offset, count); if (n > 0) BytesRead += n; return n; }
        public override void Write(byte[] buffer, int offset, int count) { inner.Write(buffer, offset, count); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }

    public static class Net
    {
        // Connect scan semantics (nmap -sT): RST => closed; timeout/unreachable => filtered.
        // Non-blocking connect + Socket.Select on the calling thread: no thread-pool completion is involved, so a busy or
        // starved thread pool can never turn a fast RST into a false "filtered" (seen with BeginConnect at high rates).
        public static bool SelectConnect = true;   // false = legacy BeginConnect path (benchmark A/B only)
        public static long LocalWaits;             // connects delayed by local socket exhaustion (ephemeral ports / buffers)
        public static long LocalFailures;          // connects that still could not get a local socket after backing off

        // Running out of local ephemeral ports or socket buffers is a scanner-side condition, not a property of the
        // target: back off and retry instead of reporting the port as filtered; give up as "error" (resumable).
        static bool IsLocalExhaustion(SocketError e)
        {
            return e == SocketError.AddressAlreadyInUse || e == SocketError.AddressNotAvailable || e == SocketError.NoBufferSpaceAvailable || e == SocketError.TooManyOpenSockets;
        }

        // HTTP CONNECT proxy (scanning from a jump host): when set, every TCP connection of every probe is a tunnel
        // through the proxy and the port state comes from the proxy's answer (see ConnectViaProxy).
        public static string ProxyIp;               // proxy address (resolved once, before the scan)
        public static int ProxyPort;
        public static string ProxyAuthorization;    // "Basic ..." or null
        public static long ProxyRefusals;           // CONNECTs the proxy refused by policy/authentication (state "error")
        public static string ProxyLastRefusal = "";

        public static TcpClient Connect(string ip, int port, int timeoutMs, out string state)
        {
            if (ProxyIp != null) return ConnectViaProxy(ip, port, timeoutMs, out state);
            return ConnectDirect(ip, port, timeoutMs, out state);
        }

        static TcpClient ConnectDirect(string ip, int port, int timeoutMs, out string state)
        {
            IPAddress addr;
            if (!SelectConnect || !IPAddress.TryParse(ip, out addr)) return ConnectAsyncWait(ip, port, timeoutMs, out state);
            for (int attempt = 0; ; attempt++)
            {
                SocketError local;
                TcpClient c = ConnectOnce(addr, port, timeoutMs, out state, out local);
                if (state != "local") return c;
                if (attempt >= 8) { System.Threading.Interlocked.Increment(ref LocalFailures); state = "error"; return null; }
                System.Threading.Interlocked.Increment(ref LocalWaits);
                System.Threading.Thread.Sleep(250 * (attempt + 1));
            }
        }

        // CONNECT ip:port through the proxy. 200 => open (the socket is returned positioned after the proxy's header);
        // 502/503 => closed (or filtered when Squid's X-Squid-Error carries ETIMEDOUT/EHOSTUNREACH); 504 or no answer
        // within the timeout => filtered; 400/403/405/407 and anything else => "error" (refused by the proxy, never
        // recorded as a port state, so -Resume retries it). The proxy itself unreachable => "error".
        static TcpClient ConnectViaProxy(string ip, int port, int timeoutMs, out string state)
        {
            Stopwatch sw = Stopwatch.StartNew();
            string pst;
            TcpClient c = ConnectDirect(ProxyIp, ProxyPort, timeoutMs, out pst);
            if (c == null) { state = "error"; NoteRefusal("proxy " + ProxyIp + ":" + ProxyPort + " not reachable (" + pst + ")"); return null; }
            try
            {
                int left = (int)Math.Max(200, timeoutMs - sw.ElapsedMilliseconds);
                c.ReceiveTimeout = left; c.SendTimeout = left;
                string target = (ip.IndexOf(':') >= 0 ? "[" + ip + "]" : ip) + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);
                StringBuilder rq = new StringBuilder();
                rq.Append("CONNECT ").Append(target).Append(" HTTP/1.1\r\nHost: ").Append(target).Append("\r\n");
                if (ProxyAuthorization != null) rq.Append("Proxy-Authorization: ").Append(ProxyAuthorization).Append("\r\n");
                rq.Append("\r\n");
                byte[] b = Encoding.ASCII.GetBytes(rq.ToString());
                NetworkStream ns = c.GetStream();
                ns.Write(b, 0, b.Length);
                // read the header byte by byte: anything after it belongs to the tunnelled service
                StringBuilder hdr = new StringBuilder();
                int one;
                while (hdr.Length < 16384)
                {
                    try { one = ns.ReadByte(); }
                    catch (IOException) { state = "filtered"; SafeClose(c); return null; }   // proxy still waiting on the target
                    if (one < 0) break;
                    hdr.Append((char)one);
                    if (hdr.Length >= 4 && hdr[hdr.Length - 1] == '\n' && hdr.ToString(hdr.Length - 4, 4) == "\r\n\r\n") break;
                }
                string h = hdr.ToString();
                Match m = Regex.Match(h, @"^HTTP/1\.[01] (\d{3})");
                if (!m.Success) { state = "error"; NoteRefusal("proxy answered " + (h.Length == 0 ? "nothing" : "'" + h.Split('\r')[0] + "'") + " to CONNECT " + target); SafeClose(c); return null; }
                int code = int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
                if (code == 200) { c.ReceiveTimeout = 0; c.SendTimeout = 0; state = "open"; return c; }
                SafeClose(c);
                if (code == 502 || code == 503)
                {
                    Match sq = Regex.Match(h, @"(?im)^X-Squid-Error:\s*\S+\s+(\d+)");
                    int errno = sq.Success ? int.Parse(sq.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) : 0;
                    state = (errno == 110 || errno == 113 || errno == 101 || errno == 10060 || errno == 10065) ? "filtered" : "closed";
                    return null;
                }
                if (code == 504) { state = "filtered"; return null; }
                state = "error";
                NoteRefusal("proxy refused CONNECT " + target + ": " + h.Split('\r')[0]);
                return null;
            }
            catch (Exception ex) { state = "error"; NoteRefusal("proxy CONNECT failed: " + Flatten(ex)); SafeClose(c); return null; }
        }
        static void NoteRefusal(string why) { System.Threading.Interlocked.Increment(ref ProxyRefusals); ProxyLastRefusal = why; }

        static TcpClient ConnectOnce(IPAddress addr, int port, int timeoutMs, out string state, out SocketError local)
        {
            local = SocketError.Success;
            Socket s;
            try { s = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp); }
            catch (SocketException se) { local = se.SocketErrorCode; state = IsLocalExhaustion(se.SocketErrorCode) ? "local" : "error"; return null; }
            try
            {
                s.NoDelay = true;
                s.Blocking = false;
                try { s.Connect(new IPEndPoint(addr, port)); }
                catch (SocketException se)
                {
                    if (se.SocketErrorCode != SocketError.WouldBlock && se.SocketErrorCode != SocketError.InProgress && se.SocketErrorCode != SocketError.AlreadyInProgress)
                    {
                        local = se.SocketErrorCode;
                        state = IsLocalExhaustion(se.SocketErrorCode) ? "local" : se.SocketErrorCode == SocketError.ConnectionRefused ? "closed" : "filtered";
                        s.Close(); return null;
                    }
                    System.Collections.ArrayList w = new System.Collections.ArrayList(), e = new System.Collections.ArrayList();
                    w.Add(s); e.Add(s);
                    Socket.Select(null, w, e, (int)Math.Min(int.MaxValue, Math.Max(1, timeoutMs) * 1000L));
                    if (w.Count == 0 && e.Count == 0) { state = "filtered"; s.Close(); return null; }   // no answer within the timeout
                    int err = (int)s.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error);
                    if (err != 0 || e.Count > 0)
                    {
                        state = (err == (int)SocketError.ConnectionRefused || err == 111 || err == 61) ? "closed"
                              : IsLocalExhaustion((SocketError)err) || err == 99 || err == 98 ? "local" : "filtered";
                        s.Close(); return null;
                    }
                }
                s.Blocking = true;
                TcpClient c = new TcpClient(addr.AddressFamily);
                Socket orig = c.Client;
                c.Client = s;
                try { orig.Close(); } catch { }
                state = "open";
                return c;
            }
            catch (SocketException se)
            {
                local = se.SocketErrorCode;
                state = IsLocalExhaustion(se.SocketErrorCode) ? "local" : "filtered";
                try { s.Close(); } catch { }
                return null;
            }
            catch (Exception)
            {
                state = "filtered";
                try { s.Close(); } catch { }
                return null;
            }
        }

        static TcpClient ConnectAsyncWait(string ip, int port, int timeoutMs, out string state)
        {
            IPAddress addr;
            AddressFamily fam = AddressFamily.InterNetwork;
            if (IPAddress.TryParse(ip, out addr)) fam = addr.AddressFamily;
            TcpClient c = new TcpClient(fam);
            c.NoDelay = true;
            try
            {
                IAsyncResult ar = c.BeginConnect(ip, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) { state = "filtered"; SafeClose(c); return null; }
                c.EndConnect(ar);
                state = "open";
                return c;
            }
            catch (SocketException se)
            {
                state = (se.SocketErrorCode == SocketError.ConnectionRefused) ? "closed" : "filtered";
                SafeClose(c);
                return null;
            }
            catch (Exception)
            {
                state = "filtered";
                SafeClose(c);
                return null;
            }
        }

        public static void SafeClose(TcpClient c) { try { if (c != null) c.Close(); } catch { } }

        public static RawResponse Probe(string ip, int port, bool tls, string sni, byte[] request,
                                        int timeoutMs, int maxBytes, int sslProtocols, int bannerWaitMs)
        {
            RawResponse r = new RawResponse();
            Stopwatch sw = Stopwatch.StartNew();
            string st;
            TcpClient c = Connect(ip, port, timeoutMs, out st);
            r.State = st;
            r.ConnectMs = sw.ElapsedMilliseconds;
            if (c == null) { r.Ms = sw.ElapsedMilliseconds; return r; }
            try
            {
                c.ReceiveTimeout = timeoutMs;
                c.SendTimeout = timeoutMs;
                Stream s = c.GetStream();
                CountingStream counted = null;
                if (!tls && bannerWaitMs > 0)
                {
                    // nmap-style NULL probe: speak-first services (SSH/FTP/SMTP/MySQL...) send a banner unprompted
                    if (c.Client.Poll(bannerWaitMs * 1000, SelectMode.SelectRead) && c.Client.Available > 0)
                    {
                        r.ServerFirst = true;
                        r.Raw = ReadBanner(s, c, 4096, timeoutMs);
                        r.Ms = sw.ElapsedMilliseconds;
                        return r;
                    }
                }
                if (tls)
                {
                    X509Certificate2 captured = null; string pol = null; string chainSt = null;
                    counted = new CountingStream(s);
                    // Per-connection callback: accept any certificate FOR INVENTORY ONLY, record it and its policy errors.
                    SslStream ssl = new SslStream(counted, false, delegate(object o, X509Certificate cert, X509Chain ch, SslPolicyErrors e)
                    {
                        try
                        {
                            if (cert != null) captured = new X509Certificate2(cert);
                            pol = e.ToString();
                            if (ch != null && ch.ChainStatus != null)
                            {
                                StringBuilder sb = new StringBuilder();
                                foreach (X509ChainStatus cs in ch.ChainStatus)
                                {
                                    if (cs.Status == X509ChainStatusFlags.NoError) continue;
                                    if (sb.Length > 0) sb.Append(',');
                                    sb.Append(cs.Status.ToString());
                                }
                                chainSt = sb.ToString();
                            }
                        }
                        catch { }
                        return true;
                    });
                    try { ssl.AuthenticateAsClient(sni, null, (SslProtocols)sslProtocols, false); }
                    catch (Exception ex)
                    {
                        r.TlsError = Flatten(ex); r.Cert = captured; r.CertPolicyErrors = pol; r.ChainStatus = chainSt;
                        r.TimedOut = IsTimeout(ex); r.BytesIn = counted.BytesRead;
                        r.Ms = sw.ElapsedMilliseconds; SafeClose(c); return r;
                    }
                    r.TlsOk = true; r.Cert = captured; r.CertPolicyErrors = pol; r.ChainStatus = chainSt;
                    r.TlsProtocol = ProtoName((int)ssl.SslProtocol);
                    try
                    {
                        r.Cipher = ssl.CipherAlgorithm.ToString(); r.CipherBits = ssl.CipherStrength;
                        r.Hash = ssl.HashAlgorithm.ToString(); r.KeyExchange = ssl.KeyExchangeAlgorithm.ToString();
                    }
                    catch { }
                    s = ssl;
                }
                s.Write(request, 0, request.Length);
                s.Flush();
                bool to; long got;
                r.Raw = Read(s, maxBytes, timeoutMs, sw, out to, out got);
                r.TimedOut = to; r.BytesIn += got;
                if (counted != null) r.BytesIn = counted.BytesRead;
            }
            catch (Exception ex) { r.Error = Flatten(ex); }
            finally { SafeClose(c); }
            r.Ms = sw.ElapsedMilliseconds;
            return r;
        }

        public static string ProtoName(int p)
        {
            switch (p)
            {
                case 12288: return "TLS1.3";
                case 3072: return "TLS1.2";
                case 768: return "TLS1.1";
                case 192: return "TLS1.0";
                case 48: return "SSL3";
                case 12: return "SSL2";
                default: return p.ToString();
            }
        }

        static byte[] ReadBanner(Stream s, TcpClient c, int maxBytes, int timeoutMs)
        {
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[4096];
            try
            {
                int n = s.Read(buf, 0, buf.Length);
                if (n > 0) ms.Write(buf, 0, n);
                // multi-line banners (FTP "220-") arrive in pieces; give them a moment
                Stopwatch sw = Stopwatch.StartNew();
                while (ms.Length < maxBytes && sw.ElapsedMilliseconds < Math.Min(750, timeoutMs))
                {
                    if (!c.Client.Poll(150 * 1000, SelectMode.SelectRead) || c.Client.Available == 0) break;
                    n = s.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    ms.Write(buf, 0, n);
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (SocketException) { }
            return ms.ToArray();
        }

        static byte[] Read(Stream s, int maxBytes, int timeoutMs, Stopwatch sw, out bool timedOut, out long got)
        {
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[16384];
            long deadline = sw.ElapsedMilliseconds + timeoutMs * 3L;
            timedOut = false;
            try
            {
                while (ms.Length < maxBytes && sw.ElapsedMilliseconds < deadline)
                {
                    int n = s.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    ms.Write(buf, 0, n);
                    if (Complete(ms.GetBuffer(), (int)ms.Length)) break;
                }
            }
            catch (IOException ex) { timedOut = IsTimeout(ex); }
            catch (ObjectDisposedException) { }
            catch (SocketException ex) { timedOut = ex.SocketErrorCode == SocketError.TimedOut; }
            got = ms.Length;
            byte[] all = ms.ToArray();
            if (all.Length > maxBytes) Array.Resize(ref all, maxBytes);
            return all;
        }

        public static int HeaderEnd(byte[] b, int len)
        {
            for (int i = 0; i + 3 < len; i++)
                if (b[i] == 13 && b[i + 1] == 10 && b[i + 2] == 13 && b[i + 3] == 10) return i;
            return -1;
        }

        static bool Complete(byte[] b, int len)
        {
            if (len < 5) return false;
            if (!(b[0] == 'H' && b[1] == 'T' && b[2] == 'T' && b[3] == 'P')) return true;   // non-HTTP: stop after first chunk
            int he = HeaderEnd(b, len);
            if (he < 0) return false;
            string head = Encoding.ASCII.GetString(b, 0, he).ToLowerInvariant();
            int bodyLen = len - (he + 4);
            // 1xx/204/304 have no body
            if (head.Length > 12 && (head.Substring(9, 3) == "204" || head.Substring(9, 3) == "304")) return true;
            int ci = head.IndexOf("\ncontent-length:");
            if (ci >= 0)
            {
                int eol = head.IndexOf('\r', ci + 1); if (eol < 0) eol = head.Length;
                long cl;
                if (long.TryParse(head.Substring(ci + 16, eol - ci - 16).Trim(), out cl)) return bodyLen >= cl;
            }
            if (head.Contains("transfer-encoding: chunked") || head.Contains("transfer-encoding:chunked"))
                return len >= 5 && b[len - 5] == '0' && b[len - 4] == 13 && b[len - 3] == 10 && b[len - 2] == 13 && b[len - 1] == 10;
            return false;
        }

        public static byte[] Body(byte[] raw, out string head)
        {
            Encoding latin1 = Encoding.GetEncoding(28591);
            int he = HeaderEnd(raw, raw.Length);
            if (he < 0) { head = latin1.GetString(raw); return new byte[0]; }
            head = latin1.GetString(raw, 0, he);
            byte[] body = new byte[raw.Length - he - 4];
            Buffer.BlockCopy(raw, he + 4, body, 0, body.Length);
            string lh = head.ToLowerInvariant();
            if (lh.Contains("transfer-encoding: chunked") || lh.Contains("transfer-encoding:chunked")) body = Dechunk(body);
            if (lh.Contains("content-encoding: gzip") || lh.Contains("content-encoding:gzip"))
            {
                try
                {
                    using (GZipStream gz = new GZipStream(new MemoryStream(body), CompressionMode.Decompress))
                    using (MemoryStream o = new MemoryStream()) { gz.CopyTo(o); body = o.ToArray(); }
                }
                catch { }
            }
            return body;
        }

        static byte[] Dechunk(byte[] b)
        {
            MemoryStream ms = new MemoryStream();
            int i = 0;
            while (i < b.Length)
            {
                int eol = -1;
                for (int j = i; j < b.Length - 1; j++) if (b[j] == 13 && b[j + 1] == 10) { eol = j; break; }
                if (eol < 0) break;
                string line = Encoding.ASCII.GetString(b, i, eol - i);
                int semi = line.IndexOf(';'); if (semi >= 0) line = line.Substring(0, semi);
                int size;
                if (!int.TryParse(line.Trim(), System.Globalization.NumberStyles.HexNumber, null, out size)) break;
                i = eol + 2;
                if (size == 0) break;
                int n = Math.Min(size, b.Length - i);
                if (n <= 0) break;
                ms.Write(b, i, n);
                i += n + 2;
            }
            return ms.ToArray();
        }

        public static bool IsTimeout(Exception ex)
        {
            for (Exception e = ex; e != null; e = e.InnerException)
            {
                SocketException se = e as SocketException;
                if (se != null && se.SocketErrorCode == SocketError.TimedOut) return true;
                if (e is TimeoutException) return true;
            }
            return false;
        }

        public static string Flatten(Exception ex)
        {
            StringBuilder sb = new StringBuilder();
            while (ex != null)
            {
                if (sb.Length > 0) sb.Append(" -> ");
                sb.Append(ex.GetType().Name + ": " + ex.Message);
                ex = ex.InnerException;
            }
            return sb.ToString();
        }

        // ---- DNS (parallel, bounded, with timeout) ----
        // Sliding window: up to `parallel` lookups in flight; each name gets its own timeout from its own start, and a
        // slow name no longer holds back the rest of a batch.
        public static Func<string, Task<IPAddress[]>> Resolver;   // test hook; null = Dns.GetHostAddressesAsync
        public static bool SlidingDns = true;                       // false = legacy fixed batches (benchmark A/B only)
        public static Dictionary<string, string[]> ResolveMany(string[] names, int timeoutMs, int parallel, Dictionary<string, string> errors)
        {
            if (!SlidingDns) return ResolveBatched(names, timeoutMs, parallel, errors);
            Dictionary<string, string[]> res = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            if (parallel < 1) parallel = 1;
            Stopwatch sw = Stopwatch.StartNew();
            List<Task<IPAddress[]>> live = new List<Task<IPAddress[]>>();
            List<string> liveName = new List<string>();
            List<long> liveDue = new List<long>();
            int next = 0;
            while (next < names.Length || live.Count > 0)
            {
                while (live.Count < parallel && next < names.Length)
                {
                    string nm = names[next++];
                    Task<IPAddress[]> t;
                    try { t = Resolver != null ? Resolver(nm) : Dns.GetHostAddressesAsync(nm); }
                    catch (Exception ex) { errors[nm] = Flatten(ex); continue; }
                    live.Add(t); liveName.Add(nm); liveDue.Add(sw.ElapsedMilliseconds + timeoutMs);
                }
                if (live.Count == 0) continue;
                long due = long.MaxValue;
                foreach (long d in liveDue) if (d < due) due = d;
                int wait = (int)Math.Max(0, Math.Min(int.MaxValue, due - sw.ElapsedMilliseconds));
                try { Task.WaitAny(live.ToArray(), wait); } catch (Exception) { }
                long now = sw.ElapsedMilliseconds;
                for (int i = live.Count - 1; i >= 0; i--)
                {
                    Task<IPAddress[]> t = live[i];
                    if (!t.IsCompleted && now < liveDue[i]) continue;
                    Harvest(liveName[i], t, timeoutMs, res, errors);
                    live.RemoveAt(i); liveName.RemoveAt(i); liveDue.RemoveAt(i);
                }
            }
            return res;
        }

        static void Harvest(string nm, Task<IPAddress[]> t, int timeoutMs, Dictionary<string, string[]> res, Dictionary<string, string> errors)
        {
            if (t.Status == TaskStatus.RanToCompletion)
            {
                List<string> a = new List<string>();
                foreach (IPAddress ip in t.Result) a.Add(ip.ToString());
                if (a.Count > 0) res[nm] = a.ToArray(); else errors[nm] = "no addresses";
            }
            else if (t.IsFaulted)
            {
                Exception ex = t.Exception != null ? t.Exception.GetBaseException() : null;
                errors[nm] = ex != null ? ex.Message : "lookup failed";
            }
            else errors[nm] = "DNS timeout after " + timeoutMs + "ms";
        }

        static Dictionary<string, string[]> ResolveBatched(string[] names, int timeoutMs, int parallel, Dictionary<string, string> errors)
        {
            Dictionary<string, string[]> res = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            if (parallel < 1) parallel = 1;
            for (int i = 0; i < names.Length; i += parallel)
            {
                int n = Math.Min(parallel, names.Length - i);
                Task<IPAddress[]>[] ts = new Task<IPAddress[]>[n];
                for (int j = 0; j < n; j++)
                {
                    try { ts[j] = Resolver != null ? Resolver(names[i + j]) : Dns.GetHostAddressesAsync(names[i + j]); }
                    catch (Exception ex) { errors[names[i + j]] = Flatten(ex); ts[j] = null; }
                }
                List<Task> live = new List<Task>();
                foreach (Task t in ts) if (t != null) live.Add(t);
                try { Task.WaitAll(live.ToArray(), timeoutMs); } catch (AggregateException) { } catch (Exception) { }
                for (int j = 0; j < n; j++) if (ts[j] != null) Harvest(names[i + j], ts[j], timeoutMs, res, errors);
            }
            return res;
        }

        // benchmark helper: a resolver whose latency is pctSlow% slowMs, otherwise fastMs (deterministic per name)
        public static Func<string, Task<IPAddress[]>> FakeResolver(int pctSlow, int slowMs, int fastMs)
        {
            return delegate(string name)
            {
                int h = 0; foreach (char c in name) h = unchecked(h * 31 + c);
                int ms = (Math.Abs(h % 100) < pctSlow) ? slowMs : fastMs;
                return Task.Delay(ms).ContinueWith(delegate(Task x) { return new IPAddress[] { IPAddress.Loopback }; });
            };
        }

        // Pre-initialise the certificate chain engine and TLS types before many workers hit them at once
        public static long WarmUp(byte[] certDer)
        {
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                using (X509Certificate2 c = new X509Certificate2(certDer))
                using (X509Chain ch = new X509Chain())
                {
                    ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    ch.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
                    ch.Build(c);
                }
                Tls.BuildClientHello("tls12", "warmup.invalid");
            }
            catch { }
            return sw.ElapsedMilliseconds;
        }

        public static string ReverseLookup(string ip, int timeoutMs)
        {
            try
            {
                IPAddress a;
                if (!IPAddress.TryParse(ip, out a)) return null;
                Task<IPHostEntry> t = Dns.GetHostEntryAsync(a);
                if (t.Wait(timeoutMs) && t.Status == TaskStatus.RanToCompletion && t.Result != null)
                {
                    string h = t.Result.HostName;
                    if (string.IsNullOrEmpty(h) || h == ip) return null;
                    return h;
                }
            }
            catch { }
            return null;
        }
    }

    // ------------------------------------------------------------------ Hashing
    public static class Hash
    {
        // MurmurHash3 x86_32, seed 0, signed (Python mmh3.hash compatible)
        public static int Mmh3(byte[] d)
        {
            const uint c1 = 0xcc9e2d51, c2 = 0x1b873593;
            uint h1 = 0;
            int len = d.Length, nb = len / 4;
            for (int i = 0; i < nb; i++)
            {
                int o = i * 4;
                uint k1 = (uint)(d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24));
                k1 *= c1; k1 = (k1 << 15) | (k1 >> 17); k1 *= c2;
                h1 ^= k1; h1 = (h1 << 13) | (h1 >> 19); h1 = h1 * 5 + 0xe6546b64;
            }
            uint k = 0; int t = nb * 4;
            switch (len & 3)
            {
                case 3: k ^= (uint)d[t + 2] << 16; goto case 2;
                case 2: k ^= (uint)d[t + 1] << 8; goto case 1;
                case 1: k ^= d[t]; k *= c1; k = (k << 15) | (k >> 17); k *= c2; h1 ^= k; break;
            }
            h1 ^= (uint)len; h1 ^= h1 >> 16; h1 *= 0x85ebca6b; h1 ^= h1 >> 13; h1 *= 0xc2b2ae35; h1 ^= h1 >> 16;
            return unchecked((int)h1);
        }

        // Shodan/httpx/runZero favicon hash: mmh3 over Python base64.encodebytes() output
        // (newline every 76 chars AND a trailing newline)
        public static int FaviconHash(byte[] d)
        {
            string b = Convert.ToBase64String(d);
            StringBuilder sb = new StringBuilder(b.Length + b.Length / 76 + 2);
            for (int i = 0; i < b.Length; i += 76) { sb.Append(b, i, Math.Min(76, b.Length - i)); sb.Append('\n'); }
            return Mmh3(Encoding.ASCII.GetBytes(sb.ToString()));
        }

        // Managed MD5 (RFC 1321). Used only for content fingerprint matching (Recog/Nmap favicon DBs),
        // never for security. Works on hosts with the Windows FIPS policy enforced.
        static readonly int[] S = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                                    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };
        static readonly uint[] K = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

        public static string Md5Hex(byte[] msg)
        {
            uint a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
            long bitLen = (long)msg.Length * 8;
            int padLen = ((msg.Length + 8) / 64 + 1) * 64;
            byte[] m = new byte[padLen];
            Buffer.BlockCopy(msg, 0, m, 0, msg.Length);
            m[msg.Length] = 0x80;
            for (int i = 0; i < 8; i++) m[padLen - 8 + i] = (byte)(bitLen >> (8 * i));
            uint[] M = new uint[16];
            for (int off = 0; off < padLen; off += 64)
            {
                for (int i = 0; i < 16; i++)
                {
                    int o = off + i * 4;
                    M[i] = (uint)(m[o] | (m[o + 1] << 8) | (m[o + 2] << 16) | (m[o + 3] << 24));
                }
                uint A = a0, B = b0, C = c0, D = d0;
                for (int i = 0; i < 64; i++)
                {
                    uint F; int g;
                    if (i < 16) { F = (B & C) | (~B & D); g = i; }
                    else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
                    else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
                    else { F = C ^ (B | ~D); g = (7 * i) % 16; }
                    F = F + A + K[i] + M[g];
                    A = D; D = C; C = B;
                    B = B + ((F << S[i]) | (F >> (32 - S[i])));
                }
                a0 += A; b0 += B; c0 += C; d0 += D;
            }
            byte[] o16 = new byte[16];
            uint[] w = { a0, b0, c0, d0 };
            for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) o16[i * 4 + j] = (byte)(w[i] >> (8 * j));
            return Hex(o16);
        }

        // SHA-256 via the platform provider (CNG on Windows). If the platform refuses (policy), fall back to a managed
        // implementation: these hashes are content identifiers for inventory/diffing, not security controls.
        public static string Sha256Provider = "";
        public static string Sha256Hex(byte[] d)
        {
            if (Sha256Provider != "managed")
            {
                try
                {
                    using (IncrementalHash h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                    {
                        h.AppendData(d);
                        Sha256Provider = "platform";
                        return Hex(h.GetHashAndReset());
                    }
                }
                catch (Exception) { Sha256Provider = "managed"; }
            }
            return Hex(Sha256Managed(d));
        }

        static readonly uint[] K256 = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

        static uint Rotr(uint x, int n) { return (x >> n) | (x << (32 - n)); }

        public static byte[] Sha256Managed(byte[] msg)
        {
            uint[] H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
            long bitLen = (long)msg.Length * 8;
            int padLen = ((msg.Length + 8) / 64 + 1) * 64;
            byte[] m = new byte[padLen];
            Buffer.BlockCopy(msg, 0, m, 0, msg.Length);
            m[msg.Length] = 0x80;
            for (int i = 0; i < 8; i++) m[padLen - 1 - i] = (byte)(bitLen >> (8 * i));
            uint[] w = new uint[64];
            for (int off = 0; off < padLen; off += 64)
            {
                for (int i = 0; i < 16; i++)
                {
                    int o = off + i * 4;
                    w[i] = ((uint)m[o] << 24) | ((uint)m[o + 1] << 16) | ((uint)m[o + 2] << 8) | m[o + 3];
                }
                for (int i = 16; i < 64; i++)
                {
                    uint s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                    uint s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }
                uint a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
                for (int i = 0; i < 64; i++)
                {
                    uint S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
                    uint ch = (e & f) ^ (~e & g);
                    uint t1 = h + S1 + ch + K256[i] + w[i];
                    uint S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
                    uint maj = (a & b) ^ (a & c) ^ (b & c);
                    uint t2 = S0 + maj;
                    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
                }
                H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
            }
            byte[] outb = new byte[32];
            for (int i = 0; i < 8; i++) { outb[i * 4] = (byte)(H[i] >> 24); outb[i * 4 + 1] = (byte)(H[i] >> 16); outb[i * 4 + 2] = (byte)(H[i] >> 8); outb[i * 4 + 3] = (byte)H[i]; }
            return outb;
        }

        public static string Hex(byte[] h)
        {
            StringBuilder sb = new StringBuilder(h.Length * 2);
            foreach (byte x in h) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }
    }

    // ------------------------------------------------------------------ DER helpers
    public static class Der
    {
        public static bool Tlv(byte[] d, int pos, int end, out int tag, out int hdrLen, out int len)
        {
            tag = 0; hdrLen = 0; len = 0;
            if (d == null || pos < 0 || pos + 2 > end) return false;
            tag = d[pos];
            int p = pos + 1;
            int b = d[p++];
            if (b < 0x80) len = b;
            else
            {
                int n = b & 0x7f;
                if (n == 0 || n > 3 || p + n > end) return false;
                for (int i = 0; i < n; i++) len = (len << 8) | d[p++];
            }
            hdrLen = p - pos;
            return len >= 0 && pos + hdrLen + len <= end;
        }

        public static string[] SubjectAltNames(X509Certificate2 c)
        {
            try
            {
                foreach (X509Extension e in c.Extensions)
                    if (e.Oid != null && e.Oid.Value == "2.5.29.17") return ParseSan(e.RawData).ToArray();
            }
            catch { }
            return new string[0];
        }

        // Locale-independent SAN parse (X509Extension.Format() output varies by OS language)
        public static List<string> ParseSan(byte[] d)
        {
            List<string> o = new List<string>();
            int tag, hl, len;
            if (d == null || !Tlv(d, 0, d.Length, out tag, out hl, out len) || tag != 0x30) return o;
            int p = hl, end = hl + len;
            while (p < end)
            {
                if (!Tlv(d, p, end, out tag, out hl, out len)) break;
                int cs = p + hl;
                switch (tag)
                {
                    case 0x82: o.Add("DNS:" + Encoding.ASCII.GetString(d, cs, len)); break;
                    case 0x81: o.Add("EMAIL:" + Encoding.ASCII.GetString(d, cs, len)); break;
                    case 0x86: o.Add("URI:" + Encoding.ASCII.GetString(d, cs, len)); break;
                    case 0x87:
                        if (len == 4 || len == 16)
                        {
                            byte[] ip = new byte[len]; Buffer.BlockCopy(d, cs, ip, 0, len);
                            o.Add("IP:" + new IPAddress(ip).ToString());
                        }
                        break;
                }
                p = cs + len;
            }
            return o;
        }

        static string Oid(byte[] d, int p, int len)
        {
            StringBuilder sb = new StringBuilder();
            long v = 0; bool first = true;
            for (int i = 0; i < len; i++)
            {
                v = (v << 7) | (long)(d[p + i] & 0x7f);
                if ((d[p + i] & 0x80) == 0)
                {
                    if (first)
                    {
                        long a = v < 40 ? 0 : (v < 80 ? 1 : 2);
                        sb.Append(a).Append('.').Append(v - a * 40);
                        first = false;
                    }
                    else sb.Append('.').Append(v);
                    v = 0;
                }
            }
            return sb.ToString();
        }

        static string DecodeString(int tag, byte[] d, int p, int len, out bool isString)
        {
            isString = true;
            switch (tag)
            {
                case 0x0c: return Encoding.UTF8.GetString(d, p, len);
                case 0x13: case 0x16: case 0x12: case 0x1a: return Encoding.ASCII.GetString(d, p, len);
                case 0x14: return Encoding.GetEncoding(28591).GetString(d, p, len);
                case 0x1e: return Encoding.BigEndianUnicode.GetString(d, p, len);
                case 0x1c: return new UTF32Encoding(true, false).GetString(d, p, len);
            }
            isString = false;
            return null;
        }

        static readonly Dictionary<string, string> GoNames = new Dictionary<string, string> {
            { "2.5.4.6", "C" }, { "2.5.4.10", "O" }, { "2.5.4.11", "OU" }, { "2.5.4.3", "CN" }, { "2.5.4.5", "SERIALNUMBER" },
            { "2.5.4.7", "L" }, { "2.5.4.8", "ST" }, { "2.5.4.9", "STREET" }, { "2.5.4.17", "POSTALCODE" } };
        // Go pkix.Name.String() order (reverse of ToRDNSequence)
        static readonly string[] GoOrder = { "2.5.4.5", "2.5.4.3", "2.5.4.11", "2.5.4.10", "2.5.4.17", "2.5.4.9", "2.5.4.7", "2.5.4.8", "2.5.4.6" };

        static string GoEscape(string v)
        {
            StringBuilder sb = new StringBuilder();
            for (int k = 0; k < v.Length; k++)
            {
                char c = v[k]; bool esc = false;
                switch (c)
                {
                    case ',': case '+': case '"': case '\\': case '<': case '>': case ';': esc = true; break;
                    case ' ': esc = (k == 0 || k == v.Length - 1); break;
                    case '#': esc = (k == 0); break;
                }
                if (esc) sb.Append('\\');
                sb.Append(c);
            }
            return sb.ToString();
        }

        static bool GoPrintable(string s)
        {
            foreach (char c in s)
            {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                          (c >= '\'' && c <= ')') || (c >= '+' && c <= '/') || c == ' ' || c == ':' || c == '=' || c == '?';
                if (!ok) return false;
            }
            return true;
        }

        static byte[] DerEncode(int tag, byte[] content)
        {
            MemoryStream ms = new MemoryStream();
            ms.WriteByte((byte)tag);
            int l = content.Length;
            if (l < 0x80) ms.WriteByte((byte)l);
            else if (l < 0x100) { ms.WriteByte(0x81); ms.WriteByte((byte)l); }
            else if (l < 0x10000) { ms.WriteByte(0x82); ms.WriteByte((byte)(l >> 8)); ms.WriteByte((byte)l); }
            else { ms.WriteByte(0x83); ms.WriteByte((byte)(l >> 16)); ms.WriteByte((byte)(l >> 8)); ms.WriteByte((byte)l); }
            ms.Write(content, 0, content.Length);
            return ms.ToArray();
        }

        // Distinguished name formatted exactly like Go's pkix.Name.String() - the format Recog x509 rules use.
        public static string GoName(byte[] d)
        {
            try
            {
                List<string[]> atvs = new List<string[]>(); // {oid, goValueString}
                int tag, hl, len;
                if (!Tlv(d, 0, d.Length, out tag, out hl, out len) || tag != 0x30) return "";
                int p = hl, end = hl + len;
                while (p < end)
                {
                    int t2, h2, l2;
                    if (!Tlv(d, p, end, out t2, out h2, out l2) || t2 != 0x31) break;
                    int sp = p + h2, se = sp + l2;
                    while (sp < se)
                    {
                        int t3, h3, l3;
                        if (!Tlv(d, sp, se, out t3, out h3, out l3) || t3 != 0x30) break;
                        int ap = sp + h3, ae = ap + l3;
                        int t4, h4, l4;
                        if (!Tlv(d, ap, ae, out t4, out h4, out l4) || t4 != 0x06) break;
                        string oid = Oid(d, ap + h4, l4);
                        int vp = ap + h4 + l4;
                        int t5, h5, l5;
                        if (!Tlv(d, vp, ae, out t5, out h5, out l5)) break;
                        bool isStr;
                        string val = DecodeString(t5, d, vp + h5, l5, out isStr);
                        string goVal;
                        if (GoNames.ContainsKey(oid)) goVal = isStr ? GoEscape(val) : "#" + Hash.Hex(Slice(d, vp, h5 + l5));
                        else if (isStr)
                        {
                            byte[] content = Encoding.UTF8.GetBytes(val);
                            goVal = "#" + Hash.Hex(DerEncode(GoPrintable(val) ? 0x13 : 0x0c, content));
                        }
                        else goVal = "#" + Hash.Hex(Slice(d, vp, h5 + l5));
                        atvs.Add(new string[] { oid, goVal });
                        sp = ae;
                    }
                    p = se;
                }
                List<string> parts = new List<string>();
                foreach (string o in GoOrder)
                {
                    List<string> vals = new List<string>();
                    foreach (string[] a in atvs) if (a[0] == o) vals.Add(GoNames[o] + "=" + a[1]);
                    if (vals.Count > 0) parts.Add(string.Join("+", vals.ToArray()));
                }
                for (int i = atvs.Count - 1; i >= 0; i--)
                    if (!GoNames.ContainsKey(atvs[i][0])) parts.Add(atvs[i][0] + "=" + atvs[i][1]);
                return string.Join(",", parts.ToArray());
            }
            catch { return ""; }
        }

        static byte[] Slice(byte[] d, int p, int n) { byte[] o = new byte[n]; Buffer.BlockCopy(d, p, o, 0, n); return o; }
    }

    // ------------------------------------------------------------------ Raw TLS probing
    public class TlsHello
    {
        public bool Connected;
        public bool IsTls;          // a TLS record came back
        public bool NotTls;         // something non-TLS came back (e.g. plaintext HTTP)
        public int Version;         // negotiated (0x0304 for TLS1.3)
        public int Cipher = -1;
        public string Alpn;
        public byte[] CertDer;
        public int Alert = -1;
        public string Error;
        public string ServerExts = "";   // ServerHello extension types in order, 4 hex digits, comma separated
    }

    public class TlsScanResult
    {
        public bool IsTls;
        public string Versions = "";
        public string CipherByVersion = "";
        public string Alpn = "";
        public bool Http2;
        public string WeakCipher = "";
        public byte[] CertDer;
        public string CertSourceVersion = "";
        public string Errors = "";
        public int Probes;
        // the first ServerHello of the scan (the TLS 1.3 probe when it is answered): version|cipher|extensions|alpn
        public string HelloInfo = "";
    }

    public static class Tls
    {
        public static readonly Dictionary<int, string> Names = new Dictionary<int, string> {
            {0x1301,"TLS_AES_128_GCM_SHA256"},{0x1302,"TLS_AES_256_GCM_SHA384"},{0x1303,"TLS_CHACHA20_POLY1305_SHA256"},
            {0xC02B,"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},{0xC02C,"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
            {0xC02F,"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},{0xC030,"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
            {0xCCA8,"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},{0xCCA9,"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
            {0xC023,"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},{0xC024,"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
            {0xC027,"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},{0xC028,"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
            {0xC009,"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},{0xC00A,"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
            {0xC013,"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},{0xC014,"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
            {0x009E,"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},{0x009F,"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"},
            {0xCCAA,"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},{0x0067,"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"},
            {0x006B,"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"},{0x0033,"TLS_DHE_RSA_WITH_AES_128_CBC_SHA"},{0x0039,"TLS_DHE_RSA_WITH_AES_256_CBC_SHA"},
            {0x009C,"TLS_RSA_WITH_AES_128_GCM_SHA256"},{0x009D,"TLS_RSA_WITH_AES_256_GCM_SHA384"},
            {0x003C,"TLS_RSA_WITH_AES_128_CBC_SHA256"},{0x003D,"TLS_RSA_WITH_AES_256_CBC_SHA256"},
            {0x002F,"TLS_RSA_WITH_AES_128_CBC_SHA"},{0x0035,"TLS_RSA_WITH_AES_256_CBC_SHA"},
            {0x0041,"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"},{0x0084,"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"},
            {0xC012,"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},{0xC008,"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"},
            {0x0016,"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},{0x000A,"TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
            {0xC011,"TLS_ECDHE_RSA_WITH_RC4_128_SHA"},{0xC007,"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
            {0x0005,"TLS_RSA_WITH_RC4_128_SHA"},{0x0004,"TLS_RSA_WITH_RC4_128_MD5"},
            {0x0009,"TLS_RSA_WITH_DES_CBC_SHA"},{0x0015,"TLS_DHE_RSA_WITH_DES_CBC_SHA"},
            {0x0003,"TLS_RSA_EXPORT_WITH_RC4_40_MD5"},{0x0006,"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"},
            {0x0008,"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"},{0x0014,"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
            {0x0062,"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"},{0x0064,"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"},
            {0x0001,"TLS_RSA_WITH_NULL_MD5"},{0x0002,"TLS_RSA_WITH_NULL_SHA"},{0x003B,"TLS_RSA_WITH_NULL_SHA256"},
            {0xC010,"TLS_ECDHE_RSA_WITH_NULL_SHA"},{0xC006,"TLS_ECDHE_ECDSA_WITH_NULL_SHA"},
            {0x0018,"TLS_DH_anon_WITH_RC4_128_MD5"},{0x001B,"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"},
            {0x0034,"TLS_DH_anon_WITH_AES_128_CBC_SHA"},{0x003A,"TLS_DH_anon_WITH_AES_256_CBC_SHA"},
            {0xC018,"TLS_ECDH_anon_WITH_AES_128_CBC_SHA"},{0xC019,"TLS_ECDH_anon_WITH_AES_256_CBC_SHA"},
            {0xC016,"TLS_ECDH_anon_WITH_RC4_128_SHA"} };

        static readonly int[] Tls13Suites = { 0x1301, 0x1302, 0x1303 };
        static readonly int[] ModernSuites = { 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009E, 0x009F, 0xCCAA, 0xC023, 0xC027, 0xC024, 0xC028,
                                               0xC009, 0xC013, 0xC00A, 0xC014, 0x0067, 0x006B, 0x0033, 0x0039, 0x009C, 0x009D, 0x003C, 0x003D,
                                               0x002F, 0x0035, 0x0041, 0x0084, 0xC012, 0xC008, 0x0016, 0x000A, 0xC011, 0xC007, 0x0005, 0x0004 };
        static readonly int[] WeakSuites = { 0xC011, 0xC007, 0x0005, 0x0004, 0xC012, 0xC008, 0x0016, 0x000A, 0x0009, 0x0015, 0x0003, 0x0006, 0x0008,
                                             0x0014, 0x0062, 0x0064, 0x0001, 0x0002, 0x003B, 0xC010, 0xC006, 0x0018, 0x001B, 0x0034, 0x003A,
                                             0xC018, 0xC019, 0xC016 };

        public static string SuiteName(int id)
        {
            string n;
            if (Names.TryGetValue(id, out n)) return n;
            return "0x" + id.ToString("X4");
        }

        public static string VersionName(int v)
        {
            switch (v)
            {
                case 0x0304: return "TLS1.3";
                case 0x0303: return "TLS1.2";
                case 0x0302: return "TLS1.1";
                case 0x0301: return "TLS1.0";
                case 0x0300: return "SSL3";
                default: return "0x" + v.ToString("X4");
            }
        }

        public static bool IsWeakSuite(int id)
        {
            string n = SuiteName(id);
            return n.Contains("_NULL_") || n.Contains("EXPORT") || n.Contains("_anon_") || n.Contains("RC4") ||
                   n.Contains("_DES_") || n.Contains("3DES") || n.Contains("RC2");
        }

        static void U16(MemoryStream m, int v) { m.WriteByte((byte)(v >> 8)); m.WriteByte((byte)v); }
        static void U24(MemoryStream m, int v) { m.WriteByte((byte)(v >> 16)); m.WriteByte((byte)(v >> 8)); m.WriteByte((byte)v); }
        static void Ext(MemoryStream exts, int type, byte[] body) { U16(exts, type); U16(exts, body.Length); exts.Write(body, 0, body.Length); }

        // mode: "tls13" | "tls12" | "tls11" | "tls10" | "ssl3" | "weak"
        public static byte[] BuildClientHello(string mode, string sni)
        {
            int ver; int[] suites; bool exts = true, tls13 = false, alpn = false, sigalgs = true;
            switch (mode)
            {
                case "tls13": ver = 0x0303; tls13 = true; alpn = true; suites = Concat(Tls13Suites, ModernSuites); break;
                case "tls12": ver = 0x0303; alpn = true; suites = ModernSuites; break;
                case "tls11": ver = 0x0302; sigalgs = false; suites = ModernSuites; break;
                case "tls10": ver = 0x0301; sigalgs = false; suites = ModernSuites; break;
                case "ssl3": ver = 0x0300; exts = false; sigalgs = false; suites = ModernSuites; break;
                case "weak": ver = 0x0303; suites = WeakSuites; break;
                default: throw new ArgumentException("mode");
            }
            Random rnd = new Random(Guid.NewGuid().GetHashCode());
            MemoryStream body = new MemoryStream();
            U16(body, ver);
            byte[] random = new byte[32]; rnd.NextBytes(random); body.Write(random, 0, 32);
            byte[] sid = new byte[32]; rnd.NextBytes(sid);
            if (mode == "ssl3") body.WriteByte(0); else { body.WriteByte(32); body.Write(sid, 0, 32); }
            int nSuites = suites.Length + (mode == "ssl3" ? 0 : 1);
            U16(body, nSuites * 2);
            foreach (int s in suites) U16(body, s);
            if (mode != "ssl3") U16(body, 0x00FF);              // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            body.WriteByte(1); body.WriteByte(0);               // compression: null
            if (exts)
            {
                MemoryStream e = new MemoryStream();
                IPAddress tmp;
                if (!string.IsNullOrEmpty(sni) && !IPAddress.TryParse(sni, out tmp))
                {
                    byte[] h = Encoding.ASCII.GetBytes(sni.TrimEnd('.'));
                    MemoryStream sn = new MemoryStream(); U16(sn, h.Length + 3); sn.WriteByte(0); U16(sn, h.Length); sn.Write(h, 0, h.Length);
                    Ext(e, 0x0000, sn.ToArray());
                }
                Ext(e, 0x000a, new byte[] { 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00 }); // groups
                Ext(e, 0x000b, new byte[] { 0x01, 0x00 });                                                               // ec_point_formats
                if (sigalgs)
                    Ext(e, 0x000d, new byte[] { 0x00, 0x1a, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
                                                0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01, 0x04, 0x02, 0x02, 0x02 });
                if (alpn)
                    Ext(e, 0x0010, new byte[] { 0x00, 0x0c, 0x02, (byte)'h', (byte)'2', 0x08, (byte)'h', (byte)'t', (byte)'t', (byte)'p',
                                                (byte)'/', (byte)'1', (byte)'.', (byte)'1' });
                Ext(e, 0x0017, new byte[0]);                    // extended_master_secret
                Ext(e, 0xff01, new byte[] { 0x00 });            // renegotiation_info
                if (tls13)
                {
                    Ext(e, 0x002b, new byte[] { 0x02, 0x03, 0x04 });          // supported_versions: TLS1.3 only
                    Ext(e, 0x002d, new byte[] { 0x01, 0x01 });                // psk_key_exchange_modes
                    byte[] ks = new byte[32]; rnd.NextBytes(ks);              // any 32 bytes is a valid x25519 public value
                    MemoryStream k = new MemoryStream(); U16(k, 36); U16(k, 0x001d); U16(k, 32); k.Write(ks, 0, 32);
                    Ext(e, 0x0033, k.ToArray());
                }
                byte[] eb = e.ToArray();
                U16(body, eb.Length); body.Write(eb, 0, eb.Length);
            }
            byte[] b = body.ToArray();
            MemoryStream hs = new MemoryStream();
            hs.WriteByte(0x01); U24(hs, b.Length); hs.Write(b, 0, b.Length);
            byte[] h2 = hs.ToArray();
            MemoryStream rec = new MemoryStream();
            rec.WriteByte(0x16); U16(rec, mode == "ssl3" ? 0x0300 : 0x0301); U16(rec, h2.Length); rec.Write(h2, 0, h2.Length);
            return rec.ToArray();
        }

        static int[] Concat(int[] a, int[] b) { int[] o = new int[a.Length + b.Length]; a.CopyTo(o, 0); b.CopyTo(o, a.Length); return o; }

        static bool ReadExact(Stream s, byte[] buf, int n)
        {
            int got = 0;
            while (got < n) { int r = s.Read(buf, got, n - got); if (r <= 0) return false; got += r; }
            return true;
        }

        public static TlsHello Hello(string ip, int port, string sni, string mode, int timeoutMs, bool wantCert)
        {
            TlsHello h = new TlsHello();
            string st;
            TcpClient c = Net.Connect(ip, port, timeoutMs, out st);
            if (c == null) { h.Error = "connect " + st; return h; }
            h.Connected = true;
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                byte[] ch = BuildClientHello(mode, sni);
                s.Write(ch, 0, ch.Length);
                MemoryStream hsBuf = new MemoryStream();
                byte[] hdr = new byte[5];
                int total = 0; bool haveHello = false;
                while (total < 262144)
                {
                    if (!ReadExact(s, hdr, 5)) break;
                    int ct = hdr[0];
                    if (ct < 20 || ct > 23 || hdr[1] > 3)
                    {
                        if (!h.IsTls) h.NotTls = true;
                        break;
                    }
                    int rl = (hdr[3] << 8) | hdr[4];
                    if (rl > 18432) { h.Error = "oversized record"; break; }
                    byte[] frag = new byte[rl];
                    if (!ReadExact(s, frag, rl)) break;
                    total += rl + 5;
                    h.IsTls = true;
                    if (ct == 21) { if (rl >= 2) h.Alert = frag[1]; break; }
                    if (ct == 20 || ct == 23) { if (haveHello) break; continue; }
                    if (ct != 22) break;
                    hsBuf.Write(frag, 0, frag.Length);
                    byte[] hb = hsBuf.ToArray();
                    int p = 0; bool done = false;
                    while (p + 4 <= hb.Length)
                    {
                        int mt = hb[p]; int ml = (hb[p + 1] << 16) | (hb[p + 2] << 8) | hb[p + 3];
                        if (p + 4 + ml > hb.Length) break;
                        int b = p + 4;
                        if (mt == 2) { ParseServerHello(hb, b, ml, h); haveHello = true; if (h.Version == 0x0304 || !wantCert) done = true; }
                        else if (mt == 11 && ml >= 6)
                        {
                            int cl = (hb[b + 3] << 16) | (hb[b + 4] << 8) | hb[b + 5];
                            if (cl > 0 && b + 6 + cl <= b + ml) { h.CertDer = new byte[cl]; Buffer.BlockCopy(hb, b + 6, h.CertDer, 0, cl); }
                            done = true;
                        }
                        else if (mt == 14) done = true;
                        p += 4 + ml;
                    }
                    if (p > 0) { MemoryStream rest = new MemoryStream(); rest.Write(hb, p, hb.Length - p); hsBuf = rest; }
                    if (done) break;
                }
            }
            catch (Exception ex) { h.Error = Net.Flatten(ex); }
            finally { Net.SafeClose(c); }
            return h;
        }

        static void ParseServerHello(byte[] d, int p, int len, TlsHello h)
        {
            int end = p + len;
            if (len < 38) return;
            h.Version = (d[p] << 8) | d[p + 1];
            int q = p + 2 + 32;
            int sl = d[q]; q += 1 + sl;
            if (q + 3 > end) return;
            h.Cipher = (d[q] << 8) | d[q + 1]; q += 3;
            if (q + 2 > end) return;
            int el = (d[q] << 8) | d[q + 1]; q += 2;
            int ee = Math.Min(end, q + el);
            StringBuilder exts = new StringBuilder();
            while (q + 4 <= ee)
            {
                int et = (d[q] << 8) | d[q + 1]; int len2 = (d[q + 2] << 8) | d[q + 3]; int eb = q + 4;
                if (exts.Length > 0) exts.Append(',');
                exts.Append(et.ToString("x4"));
                h.ServerExts = exts.ToString();
                if (eb + len2 > ee) break;
                if (et == 0x002b && len2 == 2) h.Version = (d[eb] << 8) | d[eb + 1];
                if (et == 0x0010 && len2 >= 3) { int pl = d[eb + 2]; if (eb + 3 + pl <= eb + len2) h.Alpn = Encoding.ASCII.GetString(d, eb + 3, pl); }
                q = eb + len2;
            }
        }

        static readonly string[][] Plan = {
            new string[] { "tls13", "TLS1.3" }, new string[] { "tls12", "TLS1.2" }, new string[] { "tls11", "TLS1.1" },
            new string[] { "tls10", "TLS1.0" }, new string[] { "ssl3", "SSL3" } };

        // Version support matrix + ALPN/h2 + weak-cipher acceptance + leaf certificate (from a TLS<=1.2 handshake),
        // all independent of the scanning host's Schannel configuration. Handshakes stop after ServerHello/Certificate.
        public static TlsScanResult Scan(string ip, int port, string sni, int timeoutMs, bool weakProbe) { return Scan(ip, port, sni, timeoutMs, weakProbe, false); }

        // parallel: send the version probes concurrently (used for listeners that stayed silent to HTTP and to Schannel,
        // where serial probes would each wait the full timeout); results are combined in the same order and with the
        // same rules as the serial scan, so the outcome is identical.
        public static TlsScanResult Scan(string ip, int port, string sni, int timeoutMs, bool weakProbe, bool parallel)
        {
            TlsScanResult r = new TlsScanResult();
            List<string> vers = new List<string>(); List<string> ciphers = new List<string>(); List<string> errs = new List<string>();
            TlsHello[] pre = null;
            if (parallel)
            {
                pre = new TlsHello[Plan.Length];
                Task[] ts = new Task[Plan.Length];
                for (int i = 0; i < Plan.Length; i++)
                {
                    int k = i;
                    ts[i] = Task.Factory.StartNew(delegate { pre[k] = Hello(ip, port, sni, Plan[k][0], timeoutMs, true); }, TaskCreationOptions.LongRunning);
                }
                Task.WaitAll(ts);
            }
            for (int pi = 0; pi < Plan.Length; pi++)
            {
                string[] step = Plan[pi];
                TlsHello h = parallel ? pre[pi] : Hello(ip, port, sni, step[0], timeoutMs, true);
                r.Probes++;
                if (!h.Connected) { errs.Add(step[1] + ":" + h.Error); if (step[0] == "tls13") break; continue; }
                if (h.NotTls && !r.IsTls) { errs.Add("not TLS"); break; }
                if (h.IsTls) r.IsTls = true;
                if (r.HelloInfo.Length == 0 && h.Cipher >= 0 && h.Version > 0)
                    r.HelloInfo = h.Version.ToString("x4") + "|" + h.Cipher.ToString("x4") + "|" + h.ServerExts + "|" + (h.Alpn ?? "");
                if (h.Cipher >= 0 && h.Version > 0 && VersionName(h.Version) == step[1])
                {
                    vers.Add(step[1]);
                    ciphers.Add(step[1] + "=" + SuiteName(h.Cipher));
                    if (!string.IsNullOrEmpty(h.Alpn) && string.IsNullOrEmpty(r.Alpn)) r.Alpn = h.Alpn;
                    if (h.CertDer != null && r.CertDer == null) { r.CertDer = h.CertDer; r.CertSourceVersion = step[1]; }
                }
                else if (h.Error != null) errs.Add(step[1] + ":" + h.Error);
                else if (h.Alert >= 0) errs.Add(step[1] + ":alert" + h.Alert);
            }
            if (parallel) r.Probes = Plan.Length;
            if (r.IsTls && weakProbe)
            {
                TlsHello w = Hello(ip, port, sni, "weak", timeoutMs, false);
                r.Probes++;
                if (w.Cipher >= 0 && IsWeakSuite(w.Cipher)) r.WeakCipher = VersionName(w.Version) + ":" + SuiteName(w.Cipher);
            }
            r.Versions = string.Join(";", vers.ToArray());
            r.CipherByVersion = string.Join(";", ciphers.ToArray());
            r.Http2 = r.Alpn == "h2";
            r.Errors = string.Join(";", errs.ToArray());
            return r;
        }
    }

    // ------------------------------------------------------------------ Fingerprint rules
    [DataContract]
    public class CondDef
    {
        [DataMember(Name = "f")] public string F;
        [DataMember(Name = "r")] public string R;
        [DataMember(Name = "o", EmitDefaultValue = false)] public string O;
        [DataMember(Name = "not", EmitDefaultValue = false)] public bool Not;
    }

    [DataContract]
    public class OutDef
    {
        [DataMember(Name = "t", EmitDefaultValue = false)] public string T;    // service|os|hw|flag
        [DataMember(Name = "n", EmitDefaultValue = false)] public string N;    // display name
        [DataMember(Name = "c", EmitDefaultValue = false)] public string C;    // category
        [DataMember(Name = "v", EmitDefaultValue = false)] public string V;    // version template e.g. "{1}"
        [DataMember(Name = "p", EmitDefaultValue = false)] public string P;    // CPE template ({v} = version)
        [DataMember(Name = "k", EmitDefaultValue = false)] public int K;       // confidence 1-100
        [DataMember(Name = "im", EmitDefaultValue = false)] public string[] Im;
        [DataMember(Name = "xs", EmitDefaultValue = false)] public string[] Xs;
        [DataMember(Name = "rq", EmitDefaultValue = false)] public string[] Rq;
        [DataMember(Name = "rc", EmitDefaultValue = false)] public string[] Rc;   // requires a detection in one of these categories
        [DataMember(Name = "flag", EmitDefaultValue = false)] public string Flag;
        [DataMember(Name = "h", EmitDefaultValue = false)] public string H;    // host name template
    }

    [DataContract]
    public class RuleDef
    {
        [DataMember(Name = "id", EmitDefaultValue = false)] public string Id;
        [DataMember(Name = "f")] public string F;
        [DataMember(Name = "r")] public string R;
        [DataMember(Name = "o", EmitDefaultValue = false)] public string O;    // i=ignorecase s=dot-all
        [DataMember(Name = "and", EmitDefaultValue = false)] public CondDef[] And;
        [DataMember(Name = "ports", EmitDefaultValue = false)] public int[] Ports;
        [DataMember(Name = "src", EmitDefaultValue = false)] public string Src;
        [DataMember(Name = "out", EmitDefaultValue = false)] public OutDef[] Out;
        // single-output shorthand
        [DataMember(Name = "t", EmitDefaultValue = false)] public string T;
        [DataMember(Name = "n", EmitDefaultValue = false)] public string N;
        [DataMember(Name = "c", EmitDefaultValue = false)] public string C;
        [DataMember(Name = "v", EmitDefaultValue = false)] public string V;
        [DataMember(Name = "p", EmitDefaultValue = false)] public string P;
        [DataMember(Name = "k", EmitDefaultValue = false)] public int K;
        [DataMember(Name = "im", EmitDefaultValue = false)] public string[] Im;
        [DataMember(Name = "xs", EmitDefaultValue = false)] public string[] Xs;
        [DataMember(Name = "rq", EmitDefaultValue = false)] public string[] Rq;
        [DataMember(Name = "rc", EmitDefaultValue = false)] public string[] Rc;
        [DataMember(Name = "flag", EmitDefaultValue = false)] public string Flag;
        // self-test vector
        [DataMember(Name = "ex", EmitDefaultValue = false)] public string Ex;
        [DataMember(Name = "exv", EmitDefaultValue = false)] public string Exv;
    }

    [DataContract]
    public class RulePack
    {
        [DataMember(Name = "name")] public string Name;
        [DataMember(Name = "version", EmitDefaultValue = false)] public string Version;
        [DataMember(Name = "source", EmitDefaultValue = false)] public string Source;
        [DataMember(Name = "license", EmitDefaultValue = false)] public string License;
        [DataMember(Name = "generated", EmitDefaultValue = false)] public string Generated;
        [DataMember(Name = "rules")] public RuleDef[] Rules;
    }

    public class Rule
    {
        public string Id; public string Field; public Regex Re; public Cond[] And; public int[] Ports; public string Src; public OutDef[] Out;
        public string Ex; public string Exv;
        public string[][] Lits; public int[][] LitIds;   // requirement formula (OR of AND-sets of folded literals) + ids in the field automaton
    }

    // ------------------------------------------------------------------ Literal prefilter (Aho-Corasick)
    // A rule regex is only run on a value that contains the rule's required literal. Literals are ASCII and compared after
    // case folding, so the filter is a necessary condition for a match under both case-sensitive and IgnoreCase regexes.
    public static class Lit
    {
        public static readonly char[] FoldMap = BuildFold();
        static char[] BuildFold()
        {
            char[] f = new char[65536];
            for (int i = 0; i < 65536; i++)
            {
                char c = (char)i;
                if (c < 128) { f[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; continue; }
                // anything that case-maps onto an ASCII letter (Kelvin sign, long s, dotted I...) folds onto it,
                // so the filter can only be more permissive than the regex engine's IgnoreCase equivalences
                char l = char.ToLowerInvariant(c), u = char.ToUpperInvariant(c);
                if (l < 128) f[i] = (l >= 'A' && l <= 'Z') ? (char)(l + 32) : l;
                else if (u < 128) f[i] = (u >= 'A' && u <= 'Z') ? (char)(u + 32) : u;
                else f[i] = c;
            }
            return f;
        }
        public static string Fold(string s)
        {
            char[] a = s.ToCharArray();
            for (int i = 0; i < a.Length; i++) a[i] = FoldMap[a[i]];
            return new string(a);
        }

        static readonly Regex FreeSpacing = new Regex(@"\(\?[imnsx\-]*x[imnsx\-]*[:)]", RegexOptions.CultureInvariant);

        // Requirement formula of a pattern: an OR of AND-sets of folded literals (each >= 3 chars) such that every match
        // of the pattern satisfies at least one AND-set. null = no requirement (the rule always runs). Built by a small
        // recursive-descent pass over the pattern; anything not understood, and any blow-up past the size caps, only
        // ever weakens the formula (drops literals or whole terms), so it stays a necessary condition for a match.
        public const int MaxTerms = 16, MaxLitsPerTerm = 6;

        public static string[][] Requirement(string p)
        {
            if (string.IsNullOrEmpty(p) || FreeSpacing.IsMatch(p)) return null;
            try
            {
                int i = 0;
                List<List<string>> d = Alt(p, ref i, 0);
                if (i != p.Length || d == null) return null;
                string[][] o = new string[d.Count][];
                for (int k = 0; k < d.Count; k++) { if (d[k].Count == 0) return null; o[k] = d[k].ToArray(); }
                return o;
            }
            catch (FormatException) { return null; }
        }

        // longest single literal of the formula (diagnostics / spot checks)
        public static string Required(string p)
        {
            string[][] d = Requirement(p);
            if (d == null || d.Length != 1) return null;
            string best = null;
            foreach (string l in d[0]) if (best == null || l.Length > best.Length) best = l;
            return best;
        }

        // does the folded text satisfy the formula?
        public static bool Satisfies(string[][] dnf, string folded)
        {
            if (dnf == null) return true;
            foreach (string[] t in dnf)
            {
                bool all = true;
                foreach (string l in t) if (folded.IndexOf(l, StringComparison.Ordinal) < 0) { all = false; break; }
                if (all) return true;
            }
            return false;
        }

        static List<List<string>> Alt(string p, ref int i, int depth)
        {
            if (depth > 24) throw new FormatException();
            List<List<string>> r = Concat(p, ref i, depth);
            while (i < p.Length && p[i] == '|') { i++; r = Or(r, Concat(p, ref i, depth)); }
            return r;
        }

        static List<List<string>> Concat(string p, ref int i, int depth)
        {
            int n = p.Length;
            List<List<string>> r = null;                       // TRUE
            StringBuilder cur = new StringBuilder();
            while (i < n && p[i] != '|' && p[i] != ')')
            {
                char c = p[i];
                bool lit = false, isGroup = false;
                List<List<string>> g = null;
                if (c == '\\')
                {
                    if (i + 1 >= n) throw new FormatException();
                    char e = p[i + 1];
                    if (e >= 0x20 && e < 0x7F && !char.IsLetterOrDigit(e) && e != '_') { cur.Append(FoldMap[e]); lit = true; i += 2; }
                    else
                    {
                        r = Run(r, cur);
                        i += 2;
                        if ((e == 'p' || e == 'P') && i < n && p[i] == '{') { int j = p.IndexOf('}', i); if (j < 0) throw new FormatException(); i = j + 1; }
                        else if (e == 'k' && i < n && (p[i] == '<' || p[i] == '\'')) { int j = p.IndexOf(p[i] == '<' ? '>' : '\'', i + 1); if (j < 0) throw new FormatException(); i = j + 1; }
                        else if (e == 'x') i += 2;
                        else if (e == 'u') i += 4;
                        else if (e == 'c') i += 1;
                        else if (char.IsDigit(e)) { while (i < n && char.IsDigit(p[i])) i++; }
                        if (i > n) throw new FormatException();
                    }
                }
                else if (c == '[') { r = Run(r, cur); int j = SkipClass(p, i); if (j < 0) throw new FormatException(); i = j; }
                else if (c == '(')
                {
                    r = Run(r, cur);
                    int j = i + 1; bool opaque = false;
                    if (j < n && p[j] == '?')
                    {
                        if (j + 1 >= n) throw new FormatException();
                        char k = p[j + 1];
                        if (k == '#') { int e2 = p.IndexOf(')', j); if (e2 < 0) throw new FormatException(); i = e2 + 1; continue; }
                        if (k == '=' || k == '!' || k == '(' || (k == '<' && j + 2 < n && (p[j + 2] == '=' || p[j + 2] == '!'))) opaque = true;
                        else if (k == ':' || k == '>') j += 2;
                        else if (k == '<' || k == '\'') { int e2 = p.IndexOf(k == '<' ? '>' : '\'', j + 2); if (e2 < 0) throw new FormatException(); j = e2 + 1; }
                        else
                        {
                            int q = j + 1;
                            while (q < n && "imnsx-".IndexOf(p[q]) >= 0) q++;
                            if (q < n && p[q] == ')') { i = q + 1; continue; }        // inline option setter: no content
                            if (q < n && p[q] == ':') j = q + 1; else throw new FormatException();
                        }
                    }
                    if (opaque) { i = SkipGroup(p, i); g = null; }
                    else
                    {
                        i = j;
                        g = Alt(p, ref i, depth + 1);
                        if (i >= n || p[i] != ')') throw new FormatException();
                        i++;
                    }
                    isGroup = true;
                }
                else if (c == '*' || c == '+' || c == '?') throw new FormatException();
                else if (c == '.' || c == '^' || c == '$' || c == '{' || c == '}' || c < 0x20 || c >= 0x7F) { r = Run(r, cur); i++; }
                else { cur.Append(FoldMap[c]); lit = true; i++; }
                int qmin, ql = Quant(p, i, out qmin);
                if (ql > 0)
                {
                    if (lit && qmin == 0) cur.Length--;
                    r = Run(r, cur);
                    if (isGroup && qmin == 0) g = null;
                    i += ql;
                }
                if (isGroup) r = And(r, g);
            }
            return Run(r, cur);
        }

        static List<List<string>> Run(List<List<string>> r, StringBuilder cur)
        {
            if (cur.Length >= 3)
            {
                List<List<string>> one = new List<List<string>>();
                one.Add(new List<string>(new string[] { cur.ToString() }));
                r = And(r, one);
            }
            cur.Length = 0;
            return r;
        }

        static List<List<string>> And(List<List<string>> a, List<List<string>> b)
        {
            if (a == null) return b;
            if (b == null) return a;
            if (a.Count * b.Count > MaxTerms) return a.Count <= b.Count ? a : b;    // weaken: keep one side
            List<List<string>> o = new List<List<string>>();
            foreach (List<string> x in a)
                foreach (List<string> y in b)
                {
                    List<string> t = new List<string>(x);
                    foreach (string l in y) if (!t.Contains(l)) t.Add(l);
                    if (t.Count > MaxLitsPerTerm) { t.Sort(delegate(string u, string v) { return v.Length.CompareTo(u.Length); }); t.RemoveRange(MaxLitsPerTerm, t.Count - MaxLitsPerTerm); }
                    o.Add(t);
                }
            return o;
        }

        static List<List<string>> Or(List<List<string>> a, List<List<string>> b)
        {
            if (a == null || b == null) return null;                                 // TRUE absorbs
            if (a.Count + b.Count > MaxTerms) return null;                            // weaken to TRUE
            List<List<string>> o = new List<List<string>>(a); o.AddRange(b);
            return o;
        }

        static int SkipGroup(string p, int i)
        {
            int depth = 1, j = i + 1;
            while (j < p.Length && depth > 0)
            {
                if (p[j] == '\\') { j += 2; continue; }
                if (p[j] == '[') { int k = SkipClass(p, j); if (k < 0) throw new FormatException(); j = k; continue; }
                if (p[j] == '(') depth++;
                else if (p[j] == ')') depth--;
                j++;
            }
            if (depth > 0) throw new FormatException();
            return j;
        }

        static int SkipClass(string p, int i)
        {
            int j = i + 1, n = p.Length;
            if (j < n && p[j] == '^') j++;
            if (j < n && p[j] == ']') j++;
            while (j < n && p[j] != ']')
            {
                if (p[j] == '\\') { j += 2; continue; }
                if (p[j] == '[' ) return -1;   // class subtraction or nested bracket: give up
                j++;
            }
            return j < n ? j + 1 : -1;
        }

        static int Quant(string p, int i, out int min)
        {
            min = 1;
            if (i >= p.Length) return 0;
            int len = 0;
            char c = p[i];
            if (c == '*' || c == '?') { min = 0; len = 1; }
            else if (c == '+') { min = 1; len = 1; }
            else if (c == '{')
            {
                int j = i + 1; int a = 0; bool digits = false;
                while (j < p.Length && char.IsDigit(p[j])) { a = Math.Min(100000, a * 10 + (p[j] - '0')); j++; digits = true; }
                if (!digits) return 0;
                if (j < p.Length && p[j] == ',') { j++; while (j < p.Length && char.IsDigit(p[j])) j++; }
                if (j >= p.Length || p[j] != '}') return 0;
                min = a; len = j - i + 1;
            }
            else return 0;
            if (i + len < p.Length && p[i + len] == '?') len++;   // lazy
            return len;
        }
    }

    public class AhoCorasick
    {
        readonly Dictionary<long, int> go = new Dictionary<long, int>();
        readonly int[] rootGo = new int[128];
        readonly List<int> fail = new List<int>();
        readonly List<int> outId = new List<int>();
        readonly List<int> dict = new List<int>();
        readonly List<List<KeyValuePair<char, int>>> kids = new List<List<KeyValuePair<char, int>>>();
        public int Count;
        public AhoCorasick() { NewNode(); }
        int NewNode() { fail.Add(0); outId.Add(-1); dict.Add(0); kids.Add(null); return fail.Count - 1; }
        static long K(int node, char c) { return ((long)node << 16) | c; }
        public void Add(string lit, int id)
        {
            int node = 0;
            foreach (char c in lit)
            {
                int nx;
                if (!go.TryGetValue(K(node, c), out nx))
                {
                    nx = NewNode(); go[K(node, c)] = nx;
                    if (kids[node] == null) kids[node] = new List<KeyValuePair<char, int>>();
                    kids[node].Add(new KeyValuePair<char, int>(c, nx));
                }
                node = nx;
            }
            outId[node] = id;
            if (id + 1 > Count) Count = id + 1;
        }
        public void Build()
        {
            Queue<int> q = new Queue<int>();
            if (kids[0] != null) foreach (KeyValuePair<char, int> kv in kids[0]) { fail[kv.Value] = 0; dict[kv.Value] = 0; q.Enqueue(kv.Value); if (kv.Key < 128) rootGo[kv.Key] = kv.Value; }
            while (q.Count > 0)
            {
                int u = q.Dequeue();
                if (kids[u] == null) continue;
                foreach (KeyValuePair<char, int> kv in kids[u])
                {
                    int v = kv.Value, f = fail[u], t;
                    while (true)
                    {
                        if (go.TryGetValue(K(f, kv.Key), out t)) break;
                        if (f == 0) { t = 0; break; }
                        f = fail[f];
                    }
                    fail[v] = t == v ? 0 : t;
                    dict[v] = outId[fail[v]] >= 0 ? fail[v] : dict[fail[v]];
                    q.Enqueue(v);
                }
            }
            kids.Clear();
        }
        // marks every literal id that occurs in s[0..len) (after case folding)
        public bool[] Scan(string s, int len)
        {
            bool[] hit = new bool[Count];
            char[] fm = Lit.FoldMap;
            int node = 0;
            for (int i = 0; i < len; i++)
            {
                char c = fm[s[i]];
                if (c >= 128) { node = 0; continue; }
                while (true)
                {
                    int nx;
                    if (node == 0) { node = rootGo[c]; break; }
                    if (go.TryGetValue(K(node, c), out nx)) { node = nx; break; }
                    node = fail[node];
                }
                int t = outId[node] >= 0 ? node : dict[node];
                while (t != 0) { hit[outId[t]] = true; t = dict[t]; }
            }
            return hit;
        }
    }

    public class Cond { public string Field; public Regex Re; public bool Not; }

    public class Detection
    {
        public string Kind = "service";
        public string Name;
        public string Version = "";
        public string Category = "";
        public int Confidence;
        public string Cpe = "";
        public string Source = "";
        public string Field = "";
        public string Evidence = "";
        public string Flag = "";
        public string HostName = "";
        public string[] Implies;
        public string[] Excludes;
        public string[] Requires;
        public string[] RequiresCategory;
        public override string ToString() { return Name + (string.IsNullOrEmpty(Version) ? "" : " " + Version); }
    }

    public class Observation
    {
        public Dictionary<string, List<string>> F = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        public int Port;
        public void Add(string key, string value)
        {
            if (string.IsNullOrEmpty(key) || value == null) return;
            List<string> l;
            if (!F.TryGetValue(key, out l)) { l = new List<string>(); F[key] = l; }
            l.Add(value);
        }
        public bool Has(string key) { return F.ContainsKey(key); }
    }

    public static class Matcher
    {
        static List<Rule> rules = new List<Rule>();
        static Dictionary<string, List<Rule>> byField = new Dictionary<string, List<Rule>>(StringComparer.OrdinalIgnoreCase);
        // first literal definition of each technology name: lets implied detections inherit kind/category/CPE
        static Dictionary<string, OutDef> nameInfo = new Dictionary<string, OutDef>(StringComparer.OrdinalIgnoreCase);
        // per-field literal prefilter (fields with enough literal-bearing rules); see Lit / AhoCorasick
        static Dictionary<string, AhoCorasick> fieldAc = new Dictionary<string, AhoCorasick>(StringComparer.OrdinalIgnoreCase);
        public static bool Prefilter = true;
        public static int PrefilterMinRules = 8;
        public static int PrefilteredRules { get { int n = 0; foreach (Rule r in rules) if (r.LitIds != null) n++; return n; } }
        public static int RegexTimeoutMs = 200;
        public static int MaxValueChars = 131072;
        static long timeouts;
        static readonly object sync = new object();
        public static long Timeouts { get { return System.Threading.Interlocked.Read(ref timeouts); } }
        public static int Count { get { return rules.Count; } }

        public static void Clear() { lock (sync) { rules = new List<Rule>(); byField = new Dictionary<string, List<Rule>>(StringComparer.OrdinalIgnoreCase); nameInfo = new Dictionary<string, OutDef>(StringComparer.OrdinalIgnoreCase); fieldAc = new Dictionary<string, AhoCorasick>(StringComparer.OrdinalIgnoreCase); } }

        public static RulePack ReadPack(string json)
        {
            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(RulePack));
            using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json))) return (RulePack)ser.ReadObject(ms);
        }

        public static string WritePack(RulePack p)
        {
            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(RulePack));
            using (MemoryStream ms = new MemoryStream()) { ser.WriteObject(ms, p); return Encoding.UTF8.GetString(ms.ToArray()); }
        }

        public static RegexOptions Opts(string o)
        {
            // default: ^/$ match at line breaks (Ruby/Recog semantics). 'a' = absolute anchors (JavaScript/Wappalyzer semantics).
            RegexOptions ro = RegexOptions.CultureInvariant;
            if (string.IsNullOrEmpty(o) || o.IndexOf('a') < 0) ro |= RegexOptions.Multiline;
            if (!string.IsNullOrEmpty(o))
            {
                if (o.IndexOf('i') >= 0) ro |= RegexOptions.IgnoreCase;
                if (o.IndexOf('s') >= 0) ro |= RegexOptions.Singleline;
            }
            return ro;
        }

        // Returns number of rules loaded; compile failures are appended to errors (rule skipped, never fatal).
        public static int Load(RulePack pack, List<string> errors)
        {
            int n = 0;
            if (pack == null || pack.Rules == null) return 0;
            List<Rule> add = new List<Rule>();
            int idx = 0;
            foreach (RuleDef d in pack.Rules)
            {
                idx++;
                if (d == null || string.IsNullOrEmpty(d.F) || d.R == null) { errors.Add(pack.Name + "#" + idx + ": missing field or pattern"); continue; }
                Rule r = new Rule();
                r.Id = string.IsNullOrEmpty(d.Id) ? pack.Name + "#" + idx : d.Id;
                r.Field = d.F.Trim();
                r.Src = string.IsNullOrEmpty(d.Src) ? pack.Name : d.Src;
                r.Ports = d.Ports;
                r.Ex = d.Ex; r.Exv = d.Exv;
                try { r.Re = new Regex(d.R, Opts(d.O), TimeSpan.FromMilliseconds(RegexTimeoutMs)); }
                catch (Exception ex) { errors.Add(r.Id + ": regex compile failed: " + ex.Message); continue; }
                try { r.Lits = Lit.Requirement(d.R); } catch { r.Lits = null; }
                if (d.And != null)
                {
                    List<Cond> cs = new List<Cond>(); bool bad = false;
                    foreach (CondDef cd in d.And)
                    {
                        try
                        {
                            Cond c = new Cond(); c.Field = cd.F; c.Not = cd.Not;
                            c.Re = new Regex(cd.R ?? "", Opts(cd.O), TimeSpan.FromMilliseconds(RegexTimeoutMs));
                            cs.Add(c);
                        }
                        catch (Exception ex) { errors.Add(r.Id + ": condition regex failed: " + ex.Message); bad = true; }
                    }
                    if (bad) continue;
                    r.And = cs.ToArray();
                }
                if (d.Out != null && d.Out.Length > 0) r.Out = d.Out;
                else
                {
                    OutDef o = new OutDef();
                    o.T = d.T; o.N = d.N; o.C = d.C; o.V = d.V; o.P = d.P; o.K = d.K; o.Im = d.Im; o.Xs = d.Xs; o.Rq = d.Rq; o.Rc = d.Rc; o.Flag = d.Flag;
                    r.Out = new OutDef[] { o };
                }
                bool any = false;
                foreach (OutDef o in r.Out) if (!string.IsNullOrEmpty(o.N) || !string.IsNullOrEmpty(o.Flag)) any = true;
                if (!any) { errors.Add(r.Id + ": no output name/flag"); continue; }
                add.Add(r); n++;
            }
            lock (sync)
            {
                List<Rule> nr = new List<Rule>(rules); nr.AddRange(add);
                Dictionary<string, OutDef> ni = new Dictionary<string, OutDef>(nameInfo, StringComparer.OrdinalIgnoreCase);
                foreach (Rule r in add)
                    foreach (OutDef o in r.Out)
                        if (!string.IsNullOrEmpty(o.N) && o.N.IndexOf('{') < 0 && !ni.ContainsKey(o.N) && (!string.IsNullOrEmpty(o.C) || !string.IsNullOrEmpty(o.T))) ni[o.N] = o;
                nameInfo = ni;
                Dictionary<string, List<Rule>> nb = new Dictionary<string, List<Rule>>(StringComparer.OrdinalIgnoreCase);
                foreach (Rule r in nr)
                {
                    List<Rule> l;
                    if (!nb.TryGetValue(r.Field, out l)) { l = new List<Rule>(); nb[r.Field] = l; }
                    l.Add(r);
                }
                // literal prefilter automata, one per field (literal ids are per field)
                Dictionary<string, AhoCorasick> na = new Dictionary<string, AhoCorasick>(StringComparer.OrdinalIgnoreCase);
                foreach (KeyValuePair<string, List<Rule>> kv in nb)
                {
                    int withLit = 0;
                    foreach (Rule r in kv.Value) { r.LitIds = null; if (r.Lits != null) withLit++; }
                    if (withLit < PrefilterMinRules) continue;
                    AhoCorasick ac = new AhoCorasick();
                    Dictionary<string, int> ids = new Dictionary<string, int>(StringComparer.Ordinal);
                    foreach (Rule r in kv.Value)
                    {
                        if (r.Lits == null) continue;
                        int[][] li = new int[r.Lits.Length][];
                        for (int t = 0; t < r.Lits.Length; t++)
                        {
                            li[t] = new int[r.Lits[t].Length];
                            for (int q = 0; q < r.Lits[t].Length; q++)
                            {
                                string l = r.Lits[t][q]; int id;
                                if (!ids.TryGetValue(l, out id)) { id = ids.Count; ids[l] = id; ac.Add(l, id); }
                                li[t][q] = id;
                            }
                        }
                        r.LitIds = li;
                    }
                    ac.Build();
                    na[kv.Key] = ac;
                }
                rules = nr; byField = nb; fieldAc = na;
            }
            return n;
        }

        static Match SafeMatch(Regex re, string v)
        {
            try
            {
                if (v.Length > MaxValueChars) v = v.Substring(0, MaxValueChars);
                return re.Match(v);
            }
            catch (RegexMatchTimeoutException) { System.Threading.Interlocked.Increment(ref timeouts); return null; }
        }

        static bool CondsOk(Rule r, Observation obs)
        {
            if (r.And == null) return true;
            foreach (Cond c in r.And)
            {
                bool hit = false;
                List<string> vals;
                if (obs.F.TryGetValue(c.Field, out vals))
                    foreach (string v in vals) { Match m = SafeMatch(c.Re, v); if (m != null && m.Success) { hit = true; break; } }
                if (hit == c.Not) return false;
            }
            return true;
        }

        static readonly Regex Tpl = new Regex(@"\{(\w+)\}", RegexOptions.CultureInvariant);

        public static string Expand(string tpl, Match m)
        {
            if (string.IsNullOrEmpty(tpl)) return "";
            string s = Tpl.Replace(tpl, delegate(Match t)
            {
                string k = t.Groups[1].Value;
                int gi;
                if (int.TryParse(k, out gi)) return gi < m.Groups.Count && m.Groups[gi].Success ? m.Groups[gi].Value : "";
                if (k == "v") return t.Value;  // CPE placeholder, resolved later
                Group g = m.Groups[k];
                return (g != null && g.Success) ? g.Value : "";
            });
            return s.Trim();
        }

        // cpe:/a:vendor:product:ver  or  cpe:2.3:a:vendor:product:ver:...  -> CPE 2.3 formatted string
        public static string NormalizeCpe(string cpe, string version)
        {
            if (string.IsNullOrEmpty(cpe)) return "";
            string ver = string.IsNullOrEmpty(version) ? "*" : version.Replace(" ", "_").Replace(":", "\\:");
            cpe = cpe.Replace("{v}", ver);
            string[] parts;
            if (cpe.StartsWith("cpe:/")) parts = ("2.3:" + cpe.Substring(5)).Split(':');
            else if (cpe.StartsWith("cpe:2.3:")) parts = cpe.Substring(4).Split(':');
            else return cpe;
            string[] o = new string[12];
            for (int i = 0; i < 12; i++) o[i] = (i < parts.Length && parts[i].Length > 0) ? parts[i] : "*";
            if ((o[4] == "*" || o[4] == "-") && ver != "*") o[4] = ver;
            if (o[4] == "-" ) o[4] = "*";
            return "cpe:" + string.Join(":", o);
        }

        // "part:vendor:product" (lower case, escapes removed) of a CPE 2.3 formatted string or a cpe:/ URI; "" otherwise
        public static string CpeKey(string cpe)
        {
            if (string.IsNullOrEmpty(cpe)) return "";
            List<string> f = new List<string>();
            if (cpe.StartsWith("cpe:2.3:", StringComparison.OrdinalIgnoreCase))
            {
                StringBuilder cur = new StringBuilder();
                for (int i = 8; i < cpe.Length && f.Count < 3; i++)
                {
                    char c = cpe[i];
                    if (c == '\\' && i + 1 < cpe.Length) { cur.Append(cpe[++i]); continue; }
                    if (c == ':') { f.Add(cur.ToString()); cur.Length = 0; continue; }
                    cur.Append(c);
                }
                if (f.Count < 3) f.Add(cur.ToString());
            }
            else if (cpe.StartsWith("cpe:/", StringComparison.OrdinalIgnoreCase)) f.AddRange(Uri.UnescapeDataString(cpe.Substring(5)).Split(':'));
            if (f.Count < 3) return "";
            return (f[0] + ":" + f[1] + ":" + f[2]).ToLowerInvariant();
        }

        // Completes rule CPEs from the reviewed supplement (src/cpe-supplement.json, embedded in the script) when a pack is
        // imported: "fill" gives products whose rules carry no CPE their NVD name; "replace" corrects a known-wrong upstream
        // CPE, and only while the rule still carries exactly that one. Returns { filled, replaced }.
        public static int[] ApplyCpeSupplement(RulePack pack, string supplementJson)
        {
            int filled = 0, replaced = 0;
            Dictionary<string, object> root = Json.Parse(supplementJson) as Dictionary<string, object>;
            Dictionary<string, string> fill = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, string[]> repl = new Dictionary<string, string[]>(StringComparer.Ordinal);
            object o;
            if (root != null && root.TryGetValue("fill", out o) && o is List<object>)
                foreach (object e in (List<object>)o)
                {
                    Dictionary<string, object> d = e as Dictionary<string, object>;
                    if (d != null) fill[Convert.ToString(d["t"]) + "|" + Convert.ToString(d["n"])] = Convert.ToString(d["p"]);
                }
            if (root != null && root.TryGetValue("replace", out o) && o is List<object>)
                foreach (object e in (List<object>)o)
                {
                    Dictionary<string, object> d = e as Dictionary<string, object>;
                    if (d != null) repl[Convert.ToString(d["n"])] = new[] { Convert.ToString(d["was"]), Convert.ToString(d["p"]) };
                }
            if (pack == null || pack.Rules == null) return new[] { 0, 0 };
            foreach (RuleDef r in pack.Rules)
            {
                if (r == null) continue;
                if (r.Out != null && r.Out.Length > 0)
                {
                    foreach (OutDef od in r.Out)
                    {
                        if (od == null) continue;
                        string p = od.P;
                        int how = Supplement(od.T, od.N, od.V, ref p, fill, repl);
                        if (how != 0) { od.P = p; if (how == 1) filled++; else replaced++; }
                    }
                }
                else
                {
                    string p = r.P;
                    int how = Supplement(r.T, r.N, r.V, ref p, fill, repl);
                    if (how != 0) { r.P = p; if (how == 1) filled++; else replaced++; }
                }
            }
            return new[] { filled, replaced };
        }

        static int Supplement(string kind, string name, string version, ref string cpe, Dictionary<string, string> fill, Dictionary<string, string[]> repl)
        {
            if (string.IsNullOrEmpty(name) || name.IndexOf('{') >= 0) return 0;
            // a version written into the rule ("11" for an IOS login realm) is a guess, not an observation: no CPE is added,
            // because the CPE would carry it into the vulnerability join
            if (string.IsNullOrEmpty(cpe) && !string.IsNullOrEmpty(version) && version.IndexOf('{') < 0) return 0;
            string[] rp;
            if (!string.IsNullOrEmpty(cpe))
            {
                if (repl.TryGetValue(name, out rp) && CpeKey(cpe) == rp[0]) { cpe = rp[1].Length > 0 ? rp[1] : null; return 2; }
                return 0;
            }
            string fp;
            if (fill.TryGetValue((string.IsNullOrEmpty(kind) ? "service" : kind) + "|" + name, out fp)) { cpe = fp; return 1; }
            return 0;
        }

        static string MergeKey(Detection d)
        {
            if (!string.IsNullOrEmpty(d.Cpe))
            {
                string[] p = d.Cpe.Split(':');
                if (p.Length > 5) return d.Kind + "|" + p[2] + ":" + p[3] + ":" + p[4];
            }
            return d.Kind + "|" + (d.Name ?? d.Flag ?? "").ToLowerInvariant();
        }

        public static List<Detection> Evaluate(Observation obs)
        {
            List<Detection> raw = new List<Detection>();
            Dictionary<string, List<Rule>> bf = byField;
            Dictionary<string, AhoCorasick> fa = fieldAc;
            bool pre = Prefilter;
            foreach (KeyValuePair<string, List<string>> kv in obs.F)
            {
                List<Rule> list;
                if (!bf.TryGetValue(kv.Key, out list)) continue;
                AhoCorasick ac = null;
                if (pre) fa.TryGetValue(kv.Key, out ac);
                bool[][] present = ac != null ? new bool[kv.Value.Count][] : null;
                foreach (Rule r in list)
                {
                    if (r.Ports != null && r.Ports.Length > 0 && Array.IndexOf(r.Ports, obs.Port) < 0) continue;
                    for (int vi = 0; vi < kv.Value.Count; vi++)
                    {
                        string v = kv.Value[vi];
                        if (v == null) continue;
                        if (ac != null && r.LitIds != null)
                        {
                            // a value that does not satisfy the rule's literal requirement cannot match: skip the regex (identical outcome)
                            bool[] h = present[vi];
                            if (h == null) { h = ac.Scan(v, Math.Min(v.Length, MaxValueChars)); present[vi] = h; }
                            bool ok = false;
                            foreach (int[] t in r.LitIds)
                            {
                                bool all = true;
                                foreach (int id in t) if (!h[id]) { all = false; break; }
                                if (all) { ok = true; break; }
                            }
                            if (!ok) continue;
                        }
                        Match m = SafeMatch(r.Re, v);
                        if (m == null || !m.Success) continue;
                        if (!CondsOk(r, obs)) break;
                        foreach (OutDef o in r.Out)
                        {
                            Detection d = new Detection();
                            d.Kind = string.IsNullOrEmpty(o.T) ? (string.IsNullOrEmpty(o.N) ? "flag" : "service") : o.T;
                            d.Name = Expand(o.N, m);
                            d.Flag = o.Flag ?? "";
                            if (string.IsNullOrEmpty(d.Name) && d.Kind != "flag") continue;
                            d.Version = Expand(o.V, m);
                            d.Category = o.C ?? "";
                            d.Confidence = o.K > 0 ? Math.Min(100, o.K) : 85;
                            d.Cpe = NormalizeCpe(Expand(o.P, m), d.Version);
                            d.Source = r.Src;
                            d.Field = kv.Key;
                            string ev = m.Value; if (ev.Length > 120) ev = ev.Substring(0, 120);
                            d.Evidence = kv.Key + "=" + ev;
                            d.HostName = Expand(o.H, m);
                            d.Implies = o.Im; d.Excludes = o.Xs; d.Requires = o.Rq; d.RequiresCategory = o.Rc;
                            raw.Add(d);
                        }
                        break;
                    }
                }
            }
            return Aggregate(raw);
        }

        public static List<Detection> Aggregate(List<Detection> raw)
        {
            Dictionary<string, Detection> m0 = new Dictionary<string, Detection>(StringComparer.OrdinalIgnoreCase);
            List<string> order0 = new List<string>();
            foreach (Detection d in raw) MergeInto(m0, order0, d);
            // second pass: same kind+name reached via different CPE spellings (e.g. microsoft:iis vs microsoft:internet_information_services)
            Dictionary<string, Detection> m = new Dictionary<string, Detection>(StringComparer.OrdinalIgnoreCase);
            List<string> order = new List<string>();
            foreach (string k0 in order0)
            {
                Detection d = m0[k0];
                string nk = d.Kind + "|" + (d.Name ?? d.Flag ?? "").ToLowerInvariant();
                Detection e;
                if (m.TryGetValue(nk, out e)) Merge(e, d); else { m[nk] = d; order.Add(nk); }
            }
            // third pass: same CPE product + same version from different vendor spellings (mortbay:jetty vs eclipse:jetty)
            Dictionary<string, Detection> m3 = new Dictionary<string, Detection>(StringComparer.OrdinalIgnoreCase);
            List<string> order3 = new List<string>();
            foreach (string k in order)
            {
                Detection d = m[k];
                string key = k;
                if (!string.IsNullOrEmpty(d.Cpe) && !string.IsNullOrEmpty(d.Version))
                {
                    string[] cp = d.Cpe.Split(':');
                    if (cp.Length > 5) key = d.Kind + "|cpeprod|" + cp[4] + "|" + d.Version;
                }
                Detection e;
                if (m3.TryGetValue(key, out e)) Merge(e, d); else { m3[key] = d; order3.Add(key); }
            }
            m = m3; order = order3;
            // implies (bounded fan-out)
            for (int pass = 0; pass < 4; pass++)
            {
                bool added = false;
                foreach (string key in new List<string>(order))
                {
                    Detection d = m[key];
                    if (d.Implies == null) continue;
                    foreach (string im in d.Implies)
                    {
                        if (string.IsNullOrEmpty(im)) continue;
                        Detection x = new Detection(); x.Name = im; x.Confidence = d.Confidence; x.Source = "implied:" + d.Name; x.Field = "implies";
                        OutDef info;
                        if (nameInfo.TryGetValue(im, out info))
                        {
                            if (!string.IsNullOrEmpty(info.T)) x.Kind = info.T;
                            x.Category = info.C ?? "";
                            if (!string.IsNullOrEmpty(info.P) && info.P.IndexOf('{') < 0) x.Cpe = NormalizeCpe(info.P, "");
                            else if (!string.IsNullOrEmpty(info.P)) x.Cpe = NormalizeCpe(Tpl.Replace(info.P, "*"), "");
                        }
                        string k2 = MergeKey(x);
                        if (!m.ContainsKey(k2) && !NameExists(m, im)) { MergeInto(m, order, x); added = true; }
                    }
                }
                if (!added) break;
            }
            // excludes / requires
            HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Detection d in m.Values) names.Add(d.Name ?? "");
            HashSet<string> cats = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Detection d in m.Values) if (!string.IsNullOrEmpty(d.Category) && d.RequiresCategory == null) cats.Add(d.Category);
            HashSet<string> drop = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Detection d in m.Values)
            {
                if (d.Excludes != null) foreach (string x in d.Excludes) if (!string.IsNullOrEmpty(x)) drop.Add(x);
                if (d.Requires != null) foreach (string q in d.Requires) if (!string.IsNullOrEmpty(q) && !names.Contains(q)) drop.Add(d.Name);
                if (d.RequiresCategory != null && d.RequiresCategory.Length > 0)
                {
                    bool ok = false;
                    foreach (string c in d.RequiresCategory) if (!string.IsNullOrEmpty(c) && cats.Contains(c)) { ok = true; break; }
                    if (!ok) drop.Add(d.Name);
                }
            }
            List<Detection> outl = new List<Detection>();
            foreach (string k in order) { Detection d = m[k]; if (!drop.Contains(d.Name ?? "")) outl.Add(d); }
            outl.Sort(delegate(Detection a, Detection b)
            {
                int c = b.Confidence.CompareTo(a.Confidence);
                return c != 0 ? c : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
            });
            return outl;
        }

        static bool NameExists(Dictionary<string, Detection> m, string name)
        {
            foreach (Detection d in m.Values) if (string.Equals(d.Name, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        static void MergeInto(Dictionary<string, Detection> m, List<string> order, Detection d)
        {
            string k = MergeKey(d);
            Detection e;
            if (!m.TryGetValue(k, out e)) { m[k] = d; order.Add(k); return; }
            Merge(e, d);
        }

        static void Merge(Detection e, Detection d)
        {
            if (d.Confidence > e.Confidence)
            {
                e.Confidence = d.Confidence;
                if (!string.IsNullOrEmpty(d.Name)) e.Name = d.Name;
                if (!string.IsNullOrEmpty(d.Cpe)) e.Cpe = d.Cpe;
                if (!string.IsNullOrEmpty(d.Category)) e.Category = d.Category;
            }
            if (!string.IsNullOrEmpty(d.Version) && (string.IsNullOrEmpty(e.Version) || d.Version.Length > e.Version.Length))
            {
                e.Version = d.Version;
                if (!string.IsNullOrEmpty(d.Cpe)) e.Cpe = d.Cpe;
            }
            if (string.IsNullOrEmpty(e.Cpe)) e.Cpe = d.Cpe;
            if (string.IsNullOrEmpty(e.Category)) e.Category = d.Category;
            if (!string.IsNullOrEmpty(d.Flag))
            {
                if (string.IsNullOrEmpty(e.Flag)) e.Flag = d.Flag;
                else if ((";" + e.Flag + ";").IndexOf(";" + d.Flag + ";", StringComparison.OrdinalIgnoreCase) < 0) e.Flag += ";" + d.Flag;
            }
            if (string.IsNullOrEmpty(e.HostName)) e.HostName = d.HostName;
            if (!string.IsNullOrEmpty(d.Source) && e.Source.IndexOf(d.Source, StringComparison.OrdinalIgnoreCase) < 0) e.Source += "+" + d.Source;
            if (!string.IsNullOrEmpty(d.Evidence) && e.Evidence.Length < 400 && e.Evidence.IndexOf(d.Evidence, StringComparison.Ordinal) < 0) e.Evidence += " | " + d.Evidence;
            e.Implies = Union(e.Implies, d.Implies); e.Excludes = Union(e.Excludes, d.Excludes); e.Requires = Union(e.Requires, d.Requires);
            // the gate only survives a merge if every contributing rule was gated
            if (e.RequiresCategory != null && d.RequiresCategory == null) e.RequiresCategory = null;
            // a version-bearing CPE is never overwritten by a version-less one
            if (!string.IsNullOrEmpty(e.Cpe) && !string.IsNullOrEmpty(e.Version)) e.Cpe = NormalizeCpe(e.Cpe, e.Version);
        }

        static string[] Union(string[] a, string[] b)
        {
            if (a == null) return b; if (b == null) return a;
            List<string> l = new List<string>(a); foreach (string x in b) if (!l.Contains(x)) l.Add(x); return l.ToArray();
        }

        // Self-test of the loaded rule packs: every rule that carries an example must match it (and yield the expected version).
        public static List<string> TestExamples(out int tested)
        {
            List<string> fails = new List<string>();
            tested = 0;
            foreach (Rule r in rules)
            {
                if (r.Ex == null) continue;
                tested++;
                Match mm = SafeMatch(r.Re, r.Ex);
                if (mm == null || !mm.Success) { fails.Add(r.Id + ": example did not match: " + r.Ex); continue; }
                // the prefilter must never hide a match: the required literal has to occur in every matching example
                if (r.Lits != null && !Lit.Satisfies(r.Lits, Lit.Fold(r.Ex))) fails.Add(r.Id + ": prefilter requirement not met by its matching example");
                if (!string.IsNullOrEmpty(r.Exv))
                {
                    string v = "";
                    foreach (OutDef o in r.Out) { string vv = Expand(o.V, mm); if (!string.IsNullOrEmpty(vv)) { v = vv; break; } }
                    if (v != r.Exv) fails.Add(r.Id + ": version '" + v + "' != expected '" + r.Exv + "'");
                }
            }
            return fails;
        }

        // JavaScript (Wappalyzer) regex dialect -> .NET: JS treats \<letter> it does not know as that letter; [^] is "any char"
        // escapes JavaScript itself understands (all of which mean the same in .NET); any other \<letter> is a literal letter in JS
        const string NetEscapes = "bBcdDfknpPrsStuvwWx0123456789";
        public static string FromJs(string p)
        {
            if (p == null) return null;
            StringBuilder sb = new StringBuilder(p.Length + 8);
            for (int i = 0; i < p.Length; i++)
            {
                char c = p[i];
                if (c == '[' && i + 2 < p.Length && p[i + 1] == '^' && p[i + 2] == ']') { sb.Append(@"[\s\S]"); i += 2; continue; }
                if (c != '\\' || i + 1 >= p.Length) { sb.Append(c); continue; }
                char n = p[++i];
                if ((char.IsLetter(n) || n == '_') && NetEscapes.IndexOf(n) < 0) sb.Append(n);
                else sb.Append('\\').Append(n);
            }
            return sb.ToString();
        }

        // Ruby (Recog) regex dialect -> .NET
        static readonly Regex InlineFlags = new Regex(@"\(\?([imx]*)(?:-([imx]*))?(:|\))", RegexOptions.CultureInvariant);
        public static string FromRuby(string p)
        {
            if (p == null) return null;
            // escape scanner: Ruby accepts escapes of word characters that .NET rejects (\_ etc.)
            StringBuilder sb = new StringBuilder(p.Length + 16);
            bool inClass = false;
            for (int i = 0; i < p.Length; i++)
            {
                char c = p[i];
                if (c != '\\' || i + 1 >= p.Length)
                {
                    if (c == '[' && !inClass) inClass = true;
                    else if (c == ']' && inClass && i > 0 && p[i - 1] != '[' && p[i - 1] != '^') inClass = false;
                    sb.Append(c);
                    continue;
                }
                char n = p[++i];
                switch (n)
                {
                    case 'h': sb.Append(inClass ? "0-9A-Fa-f" : "[0-9A-Fa-f]"); break;
                    case 'H': sb.Append(inClass ? @"\H" : "[^0-9A-Fa-f]"); break;
                    case 'R': sb.Append(@"(?:\r\n|[\n\v\f\r\x85" + "\\" + "u2028" + "\\" + "u2029])"); break;
                    case '_': sb.Append('_'); break;
                    default: sb.Append('\\').Append(n); break;
                }
            }
            string s = sb.ToString();
            s = s.Replace("[:alpha:]", "a-zA-Z").Replace("[:digit:]", "0-9").Replace("[:alnum:]", "a-zA-Z0-9").Replace("[:space:]", @"\s")
                 .Replace("[:upper:]", "A-Z").Replace("[:lower:]", "a-z").Replace("[:xdigit:]", "0-9A-Fa-f").Replace("[:print:]", @"\x20-\x7E")
                 .Replace("[:punct:]", @"!-/:-@\[-`{-~").Replace("[:word:]", @"\w").Replace("[:blank:]", @" \t").Replace("[:cntrl:]", @"\x00-\x1F");
            // Ruby (?m) == .NET (?s); Ruby ^/$ are always line-anchored (we always set Multiline)
            s = InlineFlags.Replace(s, delegate(Match m)
            {
                string on = m.Groups[1].Value.Replace('m', 's');
                string off = m.Groups[2].Success ? m.Groups[2].Value.Replace('m', 's') : null;
                return "(?" + on + (off != null ? "-" + off : "") + m.Groups[3].Value;
            });
            return s;
        }
    }

    // ------------------------------------------------------------------ Minimal JSON reader (case-sensitive keys; for rule import)
    public static class Json
    {
        public static object Parse(string s) { int i = 0; object v = Value(s, ref i); Ws(s, ref i); if (i != s.Length) throw new FormatException("trailing data at " + i); return v; }
        static void Ws(string s, ref int i) { while (i < s.Length && char.IsWhiteSpace(s[i])) i++; }
        static object Value(string s, ref int i)
        {
            Ws(s, ref i);
            if (i >= s.Length) throw new FormatException("unexpected end");
            char c = s[i];
            if (c == '{')
            {
                Dictionary<string, object> d = new Dictionary<string, object>(StringComparer.Ordinal);
                i++; Ws(s, ref i);
                if (i < s.Length && s[i] == '}') { i++; return d; }
                while (true)
                {
                    Ws(s, ref i); string k = Str(s, ref i); Ws(s, ref i);
                    if (i >= s.Length || s[i] != ':') throw new FormatException("expected ':' at " + i);
                    i++; d[k] = Value(s, ref i); Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    if (i < s.Length && s[i] == '}') { i++; return d; }
                    throw new FormatException("expected ',' or '}' at " + i);
                }
            }
            if (c == '[')
            {
                List<object> l = new List<object>();
                i++; Ws(s, ref i);
                if (i < s.Length && s[i] == ']') { i++; return l; }
                while (true)
                {
                    l.Add(Value(s, ref i)); Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    if (i < s.Length && s[i] == ']') { i++; return l; }
                    throw new FormatException("expected ',' or ']' at " + i);
                }
            }
            if (c == '"') return Str(s, ref i);
            if (string.CompareOrdinal(s, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (string.CompareOrdinal(s, i, "false", 0, 5) == 0) { i += 5; return false; }
            if (string.CompareOrdinal(s, i, "null", 0, 4) == 0) { i += 4; return null; }
            int st = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (st == i) throw new FormatException("unexpected character at " + i);
            return double.Parse(s.Substring(st, i - st), System.Globalization.CultureInfo.InvariantCulture);
        }
        static string Str(string s, ref int i)
        {
            if (s[i] != '"') throw new FormatException("expected string at " + i);
            i++;
            StringBuilder sb = new StringBuilder();
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                char e = s[i++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 't': sb.Append('\t'); break;
                    case 'r': sb.Append('\r'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u': sb.Append((char)Convert.ToInt32(s.Substring(i, 4), 16)); i += 4; break;
                    default: sb.Append(e); break;
                }
            }
            throw new FormatException("unterminated string");
        }
    }

    // ------------------------------------------------------------------ Version advisories (passive, version-based)
    public static class Advisory
    {
        // "8.3.10" -> [8,3,10]; null if not numeric
        public static int[] Parse(string v)
        {
            if (string.IsNullOrEmpty(v)) return null;
            string[] p = v.Split('.');
            int[] o = new int[Math.Max(3, p.Length)];
            for (int i = 0; i < p.Length; i++) { int x; if (!int.TryParse(p[i], out x) || x < 0) return null; o[i] = x; }
            return o;
        }

        public static int Compare(int[] a, int[] b)
        {
            int n = Math.Max(a.Length, b.Length);
            for (int i = 0; i < n; i++)
            {
                int x = i < a.Length ? a[i] : 0, y = i < b.Length ? b[i] : 0;
                if (x != y) return x < y ? -1 : 1;
            }
            return 0;
        }

        // fixed: first fixed release per maintained branch (e.g. 8.5.12, 8.4.27, 8.3.36, 8.2.35); minBranch: oldest branch that got a fix.
        // Returns: vulnerable | eol | fixed | newer | unknown
        public static string Status(string version, string[] fixedVersions, string minBranch)
        {
            int[] v = Parse(version);
            if (v == null) return "unknown";
            int[] mb = Parse(minBranch);
            if (mb != null && (v[0] < mb[0] || (v[0] == mb[0] && v[1] < mb[1]))) return "eol";
            int[] newest = null;
            foreach (string f in fixedVersions)
            {
                int[] fv = Parse(f);
                if (fv == null) continue;
                if (newest == null || Compare(fv, newest) > 0) newest = fv;
                if (fv[0] == v[0] && fv[1] == v[1]) return Compare(v, fv) < 0 ? "vulnerable" : "fixed";
            }
            // a branch between fixed branches with no listed fix (e.g. unreleased) is treated as unknown; above all fixed branches = newer
            if (newest != null && (v[0] > newest[0] || (v[0] == newest[0] && v[1] > newest[1]))) return "newer";
            return "unknown";
        }
    }

    // ------------------------------------------------------------------ Scope / exclusion sets
    // ------------------------------------------------------------------ HTTP response parsing / HTML extraction
    // Ports of the worker's PowerShell parsing with the same regexes and options (PowerShell's -match is IgnoreCase in the
    // current culture; [regex]::Match uses the pattern's inline options only), so results are identical, just faster.
    public class HttpResp
    {
        public bool IsHttp;
        public int Code;
        public System.Collections.Hashtable Headers = new System.Collections.Hashtable(StringComparer.OrdinalIgnoreCase);
        public List<string[]> List = new List<string[]>();
        public byte[] Body = new byte[0];
        public string Text = "";
        public string Banner = "";
        string title; List<string[]> metas; List<string> scripts;
        public string Title { get { if (title == null) title = Html.Title(Text); return title; } }
        public List<string[]> Metas { get { if (metas == null) metas = Html.Metas(Text); return metas; } }
        public List<string> Scripts { get { if (scripts == null) scripts = Html.ScriptSrcs(Text); return scripts; } }
    }

    public static class Html
    {
        static readonly Regex StatusRe = new Regex(@"^HTTP/\d(?:\.\d)?\s+(\d{3})", RegexOptions.IgnoreCase);
        static readonly Regex CtCharset = new Regex("charset\\s*=\\s*\"?([\\w\\-]+)", RegexOptions.IgnoreCase);
        static readonly Regex MetaCharset = new Regex("<meta[^>]+charset\\s*=\\s*[\"']?([\\w\\-]+)", RegexOptions.IgnoreCase);
        static readonly Regex TitleRe = new Regex(@"(?is)<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase);
        static readonly Regex Ws = new Regex(@"\s+", RegexOptions.IgnoreCase);
        static readonly Regex MetaTag = new Regex(@"(?is)<meta\s[^>]*>");
        static readonly Regex MetaName = new Regex("(?is)\\b(?:name|property|http-equiv)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))");
        static readonly Regex MetaContent = new Regex("(?is)\\bcontent\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))");
        static readonly Regex ScriptSrc = new Regex("(?is)<script[^>]+\\bsrc\\s*=\\s*[\"']?([^\"'\\s>]+)");

        public static HttpResp Parse(byte[] raw)
        {
            HttpResp o = new HttpResp();
            if (raw != null && raw.Length >= 5 && raw[0] == 72 && raw[1] == 84 && raw[2] == 84 && raw[3] == 80 && raw[4] == 47)
            {
                string head;
                o.Body = Net.Body(raw, out head);
                string[] lines = Regex.Split(head, "\r?\n");
                o.IsHttp = true;
                Match m = StatusRe.Match(lines[0]);
                if (m.Success) o.Code = int.Parse(m.Groups[1].Value);
                for (int i = 1; i < lines.Length; i++)
                {
                    string l = lines[i]; int ix = l.IndexOf(':');
                    if (ix <= 0) continue;
                    string k = l.Substring(0, ix).Trim().ToLowerInvariant(), v = l.Substring(ix + 1).Trim();
                    o.List.Add(new string[] { k, v });
                    if (o.Headers.ContainsKey(k)) o.Headers[k] = (string)o.Headers[k] + "\n" + v; else o.Headers[k] = v;
                }
                o.Text = BodyText(o.Body, (string)o.Headers["content-type"] ?? "");
            }
            else if (raw != null && raw.Length > 0) o.Banner = Util.BannerText(raw, 512);
            return o;
        }

        public static string BodyText(byte[] body, string contentType)
        {
            if (body == null || body.Length == 0) return "";
            Encoding enc = null;
            Match m = CtCharset.Match(contentType ?? "");
            if (m.Success) { try { enc = Encoding.GetEncoding(m.Groups[1].Value); } catch { enc = null; } }
            if (enc == null)
            {
                string sniff = Encoding.ASCII.GetString(body, 0, Math.Min(2048, body.Length));
                Match mm = MetaCharset.Match(sniff);
                if (mm.Success) { try { enc = Encoding.GetEncoding(mm.Groups[1].Value); } catch { enc = null; } }
            }
            if (enc == null) enc = Encoding.UTF8;
            return enc.GetString(body);
        }

        public static string Title(string html)
        {
            if (string.IsNullOrEmpty(html)) return "";
            Match m = TitleRe.Match(html);
            if (!m.Success) return "";
            string t = WebUtility.HtmlDecode(Ws.Replace(m.Groups[1].Value, " ").Trim());
            if (t.Length > 200) t = t.Substring(0, 200);
            return t;
        }

        public static List<string[]> Metas(string html)
        {
            List<string[]> o = new List<string[]>();
            if (string.IsNullOrEmpty(html)) return o;
            int n = 0;
            foreach (Match m in MetaTag.Matches(html))
            {
                if (++n > 64) break;
                string tag = m.Value;
                Match nm = MetaName.Match(tag), ct = MetaContent.Match(tag);
                if (!nm.Success || !ct.Success) continue;
                o.Add(new string[] { (nm.Groups[1].Value + nm.Groups[2].Value + nm.Groups[3].Value).ToLowerInvariant(),
                                     WebUtility.HtmlDecode(ct.Groups[1].Value + ct.Groups[2].Value + ct.Groups[3].Value) });
            }
            return o;
        }

        public static List<string> ScriptSrcs(string html)
        {
            List<string> o = new List<string>();
            if (string.IsNullOrEmpty(html)) return o;
            foreach (Match m in ScriptSrc.Matches(html)) { if (o.Count >= 64) break; o.Add(m.Groups[1].Value); }
            return o;
        }

        // Add-HeaderObs
        public static void AddHeader(Observation obs, string prefix, string name, string value)
        {
            obs.Add(prefix + "header:" + name, value);
            if (string.Equals(name, "set-cookie", StringComparison.OrdinalIgnoreCase))
            {
                obs.Add(prefix + "setcookie", value);
                string nv = (value ?? "").Split(';')[0]; int eq = nv.IndexOf('=');
                if (eq > 0)
                {
                    string cn = nv.Substring(0, eq).Trim();
                    obs.Add(prefix + "cookiename", cn);
                    obs.Add(prefix + "cookie:" + cn.ToLowerInvariant(), nv.Substring(eq + 1));
                }
            }
            else if (string.Equals(name, "www-authenticate", StringComparison.OrdinalIgnoreCase)) obs.Add(prefix + "auth", value);
        }

        // Add-BodyObs (identification paths)
        public static void AddBody(Observation obs, string prefix, HttpResp r)
        {
            obs.Add(prefix + "status", r.Code.ToString());
            foreach (string[] h in r.List) AddHeader(obs, prefix, h[0], h[1]);
            if (!string.IsNullOrEmpty(r.Text))
            {
                obs.Add(prefix + "body", r.Text);
                string t = r.Title; if (!string.IsNullOrEmpty(t)) obs.Add(prefix + "title", t);
            }
        }

        // Add-WebObs: headers of every hop, redirect locations, final status/url/body/title/meta/script sources
        public static void AddWeb(Observation obs, HttpResp[] hops, IEnumerable<string> locations, string finalUrl)
        {
            foreach (HttpResp h in hops) foreach (string[] p in h.List) AddHeader(obs, "", p[0], p[1]);
            foreach (string l in locations) obs.Add("location", l);
            HttpResp fin = hops[hops.Length - 1];
            obs.Add("status", fin.Code.ToString());
            obs.Add("url", finalUrl);
            if (!string.IsNullOrEmpty(fin.Text))
            {
                obs.Add("body", fin.Text);
                string t = fin.Title; if (!string.IsNullOrEmpty(t)) obs.Add("title", t);
                foreach (string[] mp in fin.Metas) obs.Add("meta:" + mp[0], mp[1]);
                foreach (string s in fin.Scripts) obs.Add("scriptsrc", s);
            }
        }
    }

    // ------------------------------------------------------------------ Result rows -> CSV / JSONL
    public static class Out
    {
        static readonly Regex Nl = new Regex("[\r\n]+");
        public static string CsvLine(object[] values, bool sanitize)
        {
            StringBuilder sb = new StringBuilder(1024);
            for (int i = 0; i < values.Length; i++)
            {
                if (i > 0) sb.Append(',');
                object v = Unwrap(values[i]);
                if (v == null) { sb.Append("\"\""); continue; }
                string s = Nl.Replace(Str(v), " ");
                if (sanitize) s = Util.CsvSafe(s);
                sb.Append('"').Append(s.Replace("\"", "\"\"")).Append('"');
            }
            return sb.ToString();
        }

        // PowerShell's [string] conversion of the scalar types rows hold (bool -> True/False, numbers invariant)
        static string Str(object v)
        {
            if (v is string) return (string)v;
            if (v is bool) return (bool)v ? "True" : "False";
            IFormattable f = v as IFormattable;
            if (f != null) return f.ToString(null, System.Globalization.CultureInfo.InvariantCulture);
            return v.ToString();
        }

        // PSObject wrappers (no compile-time reference to System.Management.Automation)
        public static object Unwrap(object v)
        {
            for (int i = 0; i < 4 && v != null; i++)
            {
                Type t = v.GetType();
                if (t.FullName != "System.Management.Automation.PSObject") break;
                System.Reflection.PropertyInfo p = t.GetProperty("BaseObject");
                if (p == null) break;
                object b = p.GetValue(v, null);
                if (b == null || ReferenceEquals(b, v) || b.GetType().FullName == "System.Management.Automation.PSCustomObject") break;
                v = b;
            }
            return v;
        }

        public static string JsonLine(string[] names, object[] values)
        {
            StringBuilder sb = new StringBuilder(4096);
            sb.Append('{');
            for (int i = 0; i < names.Length; i++)
            {
                if (i > 0) sb.Append(',');
                Str(sb, names[i]); sb.Append(':'); Value(sb, values[i], 0);
            }
            sb.Append('}');
            return sb.ToString();
        }

        static void Value(StringBuilder sb, object v, int depth)
        {
            v = Unwrap(v);
            if (v == null) { sb.Append("null"); return; }
            if (v is string) { Str(sb, (string)v); return; }
            if (v is bool) { sb.Append((bool)v ? "true" : "false"); return; }
            if (v is int || v is long || v is short || v is byte || v is sbyte || v is uint || v is ulong || v is ushort)
            { sb.Append(((IFormattable)v).ToString(null, System.Globalization.CultureInfo.InvariantCulture)); return; }
            if (v is double || v is float || v is decimal)
            { sb.Append(((IFormattable)v).ToString("R", System.Globalization.CultureInfo.InvariantCulture)); return; }
            if (v is Enum) { sb.Append(Convert.ToInt64(v).ToString(System.Globalization.CultureInfo.InvariantCulture)); return; }
            if (depth >= 5) { Str(sb, v.ToString()); return; }
            System.Collections.IDictionary d = v as System.Collections.IDictionary;
            if (d != null)
            {
                sb.Append('{'); bool first = true;
                foreach (System.Collections.DictionaryEntry e in d)
                {
                    if (!first) sb.Append(','); first = false;
                    Str(sb, Convert.ToString(e.Key, System.Globalization.CultureInfo.InvariantCulture)); sb.Append(':'); Value(sb, e.Value, depth + 1);
                }
                sb.Append('}'); return;
            }
            System.Collections.IEnumerable en = v as System.Collections.IEnumerable;
            if (en != null)
            {
                sb.Append('['); bool first = true;
                foreach (object x in en) { if (!first) sb.Append(','); first = false; Value(sb, x, depth + 1); }
                sb.Append(']'); return;
            }
            Str(sb, v.ToString());
        }

        // JSON string; HTML-sensitive characters escaped as \u00XX (as Windows PowerShell's ConvertTo-Json does)
        static void Str(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append('\\').Append('"'); break;
                    case '\\': sb.Append('\\').Append('\\'); break;
                    case '\n': sb.Append('\\').Append('n'); break;
                    case '\r': sb.Append('\\').Append('r'); break;
                    case '\t': sb.Append('\\').Append('t'); break;
                    case '\b': sb.Append('\\').Append('b'); break;
                    case '\f': sb.Append('\\').Append('f'); break;
                    default:
                        if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == '\'' || c == (char)0x2028 || c == (char)0x2029)
                            sb.Append('\\').Append('u').Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
    }

    // ------------------------------------------------------------------ Target expansion -> job lines
    // Same semantics as the PowerShell loop it replaces: ranges then names per entry, exclusions and scope applied per
    // host, port-major job order, de-duplicated on host|ip|port (case-insensitive).
    public class JobBuilder
    {
        readonly RangeSet ex, scope;
        readonly System.Collections.IDictionary resolved;
        readonly bool allAddresses;
        readonly HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Jobs = new List<string>();
        public readonly HashSet<string> Hosts = new HashSet<string>();
        public readonly List<string> OutOfScope = new List<string>();
        public int Excluded;

        public JobBuilder(RangeSet exclude, RangeSet scope, System.Collections.IDictionary resolved, bool allAddresses)
        { ex = exclude; this.scope = scope; this.resolved = resolved; this.allAddresses = allAddresses; }

        public void Add(System.Collections.IEnumerable ranges, System.Collections.IEnumerable names, int[] ports, string scheme, string src)
        {
            List<string[]> pairs = new List<string[]>();
            if (ranges != null)
                foreach (object o in ranges)
                {
                    long[] rg = (long[])Out.Unwrap(o);
                    for (long n = rg[0]; n <= rg[1]; n++) { string ip = Util.Ip4ToString(n); pairs.Add(new string[] { ip, ip }); }
                }
            if (names != null)
                foreach (object o in names)
                {
                    string nm = (string)Out.Unwrap(o);
                    IPAddress tmp;
                    if (IPAddress.TryParse(nm, out tmp)) { pairs.Add(new string[] { nm, tmp.ToString() }); continue; }
                    if (ex.ContainsName(nm)) { Excluded++; continue; }
                    if (resolved == null || !resolved.Contains(nm)) continue;
                    List<string> addrs = new List<string>();
                    object rv = Out.Unwrap(resolved[nm]);
                    if (rv is string) addrs.Add((string)rv);
                    else foreach (object a in (System.Collections.IEnumerable)rv) addrs.Add(Convert.ToString(Out.Unwrap(a)));
                    if (addrs.Count == 0) continue;
                    if (allAddresses) { foreach (string a in addrs) pairs.Add(new string[] { nm, a }); continue; }
                    string pick = null;
                    foreach (string a in addrs) if (a.IndexOf(':') < 0) { pick = a; break; }
                    pairs.Add(new string[] { nm, pick ?? addrs[0] });
                }
            List<string[]> keep = new List<string[]>();
            foreach (string[] pr in pairs)
            {
                if (ex.Contains(pr[1], pr[0])) { Excluded++; continue; }
                if (!scope.IsEmpty && !scope.Contains(pr[1], pr[0])) { OutOfScope.Add(pr[0] + " (" + pr[1] + ") from " + src); continue; }
                keep.Add(pr);
            }
            string sch = scheme ?? "";
            foreach (int port in ports)
            {
                string ps = port.ToString(System.Globalization.CultureInfo.InvariantCulture);
                foreach (string[] pr in keep)
                    if (seen.Add(pr[0] + "|" + pr[1] + "|" + ps)) { Jobs.Add(pr[0] + "\t" + pr[1] + "\t" + ps + "\t" + sch); Hosts.Add(pr[1]); }
            }
        }

        // -ListTargets lines: "ip:port" or "name (ip):port"
        public static string[] Format(List<string> jobs)
        {
            string[] o = new string[jobs.Count];
            for (int i = 0; i < o.Length; i++)
            {
                string[] p = jobs[i].Split('\t');
                o[i] = p[0] == p[1] ? p[1] + ":" + p[2] : p[0] + " (" + p[1] + "):" + p[2];
                if (p.Length > 3 && (p[3] == "smb" || p[3] == "rdp" || p[3] == "snmp")) o[i] += p[3] == "snmp" ? " (snmp, udp)" : " (" + p[3] + ")";
            }
            return o;
        }
    }

    // ------------------------------------------------------------------ Job scheduler (long-lived workers)
    // Workers block in Take() until a check is available whose host is below the per-host cap; results go to a
    // concurrent queue the dispatcher waits on (no polling). Per-host queues are served round-robin, preserving each
    // host's job order. A watchdog can Abandon() a worker slot; a late Done() for an abandoned slot is discarded.
    public class Sched
    {
        readonly object gate = new object();
        readonly Dictionary<string, Queue<string>> byHost = new Dictionary<string, Queue<string>>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, int> active = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        readonly LinkedList<string> ready = new LinkedList<string>();
        readonly HashSet<string> inReady = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly int maxPerHost;
        readonly string[] slotJob;
        readonly long[] slotStart;
        readonly Stopwatch clock = Stopwatch.StartNew();
        readonly System.Threading.AutoResetEvent signal = new System.Threading.AutoResetEvent(false);
        int queued, running;
        bool stopped;
        public readonly System.Collections.Concurrent.ConcurrentQueue<object[]> Results = new System.Collections.Concurrent.ConcurrentQueue<object[]>();

        public Sched(string[] jobs, int maxPerHost, int slots)
        {
            this.maxPerHost = Math.Max(1, maxPerHost);
            slotJob = new string[Math.Max(1, slots)];
            slotStart = new long[slotJob.Length];
            foreach (string j in jobs)
            {
                string h = HostOf(j);
                Queue<string> q;
                if (!byHost.TryGetValue(h, out q)) { q = new Queue<string>(); byHost[h] = q; active[h] = 0; ready.AddLast(h); inReady.Add(h); }
                q.Enqueue(j); queued++;
            }
        }

        // job line = host \t ip \t port \t scheme; the per-host cap is keyed on the IP
        public static string HostOf(string job)
        {
            int a = job.IndexOf('\t'); if (a < 0) return job;
            int b = job.IndexOf('\t', a + 1); if (b < 0) b = job.Length;
            return job.Substring(a + 1, b - a - 1);
        }

        public string Take(int slot)
        {
            lock (gate)
            {
                while (true)
                {
                    if (stopped) return null;
                    if (ready.Count > 0)
                    {
                        string h = ready.First.Value; ready.RemoveFirst(); inReady.Remove(h);
                        Queue<string> q = byHost[h];
                        string j = q.Dequeue(); queued--; running++;
                        int a = active[h] + 1; active[h] = a;
                        if (q.Count > 0 && a < maxPerHost) { ready.AddLast(h); inReady.Add(h); }
                        slotJob[slot] = j; slotStart[slot] = clock.ElapsedMilliseconds;
                        return j;
                    }
                    if (queued == 0) return null;
                    System.Threading.Monitor.Wait(gate);
                }
            }
        }

        void Release(int slot)
        {
            string j = slotJob[slot];
            slotJob[slot] = null; running--;
            string h = HostOf(j);
            int a = active[h] - 1; active[h] = a;
            if (byHost[h].Count > 0 && a < maxPerHost && !inReady.Contains(h)) { ready.AddLast(h); inReady.Add(h); }
            System.Threading.Monitor.PulseAll(gate);
        }

        // false when the slot was abandoned meanwhile (watchdog): the late result is discarded
        public bool Done(int slot, string job, object result)
        {
            lock (gate)
            {
                if (!string.Equals(slotJob[slot], job, StringComparison.Ordinal)) return false;
                Release(slot);
            }
            Results.Enqueue(new object[] { job, result });
            signal.Set();
            return true;
        }

        public string Abandon(int slot)
        {
            lock (gate)
            {
                string j = slotJob[slot];
                if (j != null) Release(slot);
                return j;
            }
        }

        // stop dispatching; returns how many queued checks will not run
        public int Stop()
        {
            int n;
            lock (gate) { n = stopped ? 0 : queued; stopped = true; System.Threading.Monitor.PulseAll(gate); }
            signal.Set();
            return n;
        }

        public bool Wait(int ms) { return signal.WaitOne(ms); }
        // next finished check as { jobLine, result }, or null when none is waiting (avoids [ref] on generic out params in PowerShell)
        public object[] NextResult() { object[] r; return Results.TryDequeue(out r) ? r : null; }
        public int Queued { get { lock (gate) return queued; } }
        public int Running { get { lock (gate) return running; } }
        public bool Stopped { get { lock (gate) return stopped; } }
        public string Current(int slot) { lock (gate) return slotJob[slot]; }

        public int[] Overdue(long budgetMs)
        {
            List<int> o = new List<int>();
            lock (gate)
            {
                long now = clock.ElapsedMilliseconds;
                for (int i = 0; i < slotJob.Length; i++) if (slotJob[i] != null && now - slotStart[i] > budgetMs) o.Add(i);
            }
            return o.ToArray();
        }
    }

    public class RangeSet
    {
        readonly List<long[]> ranges = new List<long[]>();
        readonly HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public int RangeCount { get { return ranges.Count; } }
        public int NameCount { get { return names.Count; } }
        public bool IsEmpty { get { return ranges.Count == 0 && names.Count == 0; } }
        public void AddRange(long a, long b) { ranges.Add(new long[] { Math.Min(a, b), Math.Max(a, b) }); }
        public void AddName(string n)
        {
            if (string.IsNullOrEmpty(n)) return;
            IPAddress ip;
            if (IPAddress.TryParse(n, out ip)) names.Add(ip.ToString()); else names.Add(n.TrimEnd('.'));
        }
        public bool ContainsName(string n) { return !string.IsNullOrEmpty(n) && names.Contains(n.TrimEnd('.')); }
        public bool ContainsIp(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            if (names.Contains(ip)) return true;
            long v = Util.Ip4(ip);
            if (v < 0) return false;
            foreach (long[] r in ranges) if (v >= r[0] && v <= r[1]) return true;
            return false;
        }
        public bool Contains(string ip, string name) { return ContainsName(name) || ContainsIp(ip); }
    }

    // ------------------------------------------------------------------ Misc helpers
    public static class Util
    {
        public const string EngineVersion = "2.3.1";

        // strict dotted-quad IPv4 -> 0..2^32-1, or -1
        public static long Ip4(string s)
        {
            if (string.IsNullOrEmpty(s)) return -1;
            string[] p = s.Split('.');
            if (p.Length != 4) return -1;
            long v = 0;
            foreach (string x in p)
            {
                int o;
                if (x.Length == 0 || x.Length > 3 || !int.TryParse(x, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out o) || o > 255) return -1;
                v = (v << 8) | (uint)o;
            }
            return v;
        }

        public static string Ip4ToString(long v)
        {
            return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
        }

        // CSV/Excel formula-injection guard: scanned hosts control titles/headers
        public static string CsvSafe(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            char c = s[0];
            if (c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r') return "'" + s;
            return s;
        }

        // Strip control characters (incl. ANSI escapes) before printing attacker-controlled text to a console
        public static string Printable(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            StringBuilder sb = new StringBuilder(Math.Min(s.Length, max));
            foreach (char c in s)
            {
                if (sb.Length >= max) break;
                if (c == '\t') sb.Append(' ');
                else if (c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0)) sb.Append('.');
                else sb.Append(c);
            }
            return sb.ToString();
        }

        public static string Html(string s) { return string.IsNullOrEmpty(s) ? "" : WebUtility.HtmlEncode(s); }

        public static int KeySize(X509Certificate2 c)
        {
            try { using (RSA r = c.GetRSAPublicKey()) { if (r != null) return r.KeySize; } } catch { }
            try { using (ECDsa e = c.GetECDsaPublicKey()) { if (e != null) return e.KeySize; } } catch { }
            try { using (DSA d = c.GetDSAPublicKey()) { if (d != null) return d.KeySize; } } catch { }
            return 0;
        }

        public static string BannerText(byte[] raw, int max)
        {
            if (raw == null || raw.Length == 0) return "";
            int n = Math.Min(raw.Length, max);
            StringBuilder sb = new StringBuilder(n);
            for (int i = 0; i < n; i++) { byte b = raw[i]; sb.Append(b >= 0x20 && b < 0x7f ? (char)b : (b == 10 || b == 13 ? '\n' : '.')); }
            return sb.ToString();
        }

        // MySQL/MariaDB initial handshake: [3-byte len][seq][0x0a protocol][version NUL]...
        public static string MySqlVersion(byte[] raw)
        {
            if (raw == null || raw.Length < 6 || raw[4] != 0x0a) return null;
            int e = Array.IndexOf(raw, (byte)0, 5);
            if (e < 6 || e - 5 > 64) return null;
            string v = Encoding.ASCII.GetString(raw, 5, e - 5);
            foreach (char c in v) if (c < 0x20 || c > 0x7e) return null;
            return v;
        }
    }
}
'@
try {
    if ('WebInv.Util' -as [type]) {
        if ([WebInv.Util]::EngineVersion -ne $ScriptVersion) {
            Stop-Fatal ("WebInv engine v{0} is already loaded in this PowerShell session (script is v{1}). Open a new PowerShell window." -f [WebInv.Util]::EngineVersion, $ScriptVersion)
        }
    }
    else {
        $addType = @{ TypeDefinition = $EngineSource; ErrorAction = 'Stop' }
        if ($PSVersionTable.PSEdition -ne 'Core') { $addType.ReferencedAssemblies = @('System.Core', 'System.Security', 'System.Runtime.Serialization', 'System.Xml') }
        Add-Type @addType
    }
}
catch { Stop-Fatal "Engine compile failed: $($_.Exception.Message)" }
#endregion

#region ---------- Embedded rule pack ----------
$BuiltinRulesJson = @'
{"name":"builtin","version":"2.3.1","source":"WebInventory curated rules (Recog/Wappalyzer/Nmap-inspired; patterns written for this tool)","license":"Same as script","rules":[
{"id":"b:iis","f":"header:server","r":"^Microsoft-IIS/([\\d.]+)","out":[{"n":"Microsoft IIS","c":"Web server","v":"{1}","p":"cpe:2.3:a:microsoft:internet_information_services:{v}","k":95},{"t":"os","n":"Microsoft Windows","c":"OS","k":80}],"ex":"Microsoft-IIS/10.0","exv":"10.0"},
{"id":"b:httpapi","f":"header:server","r":"^Microsoft-HTTPAPI/([\\d.]+)","out":[{"n":"Microsoft HTTP.sys","c":"Web server","v":"{1}","k":90},{"t":"os","n":"Microsoft Windows","c":"OS","k":80}]},
{"id":"b:winrm","f":"header:server","r":"^Microsoft-HTTPAPI/","ports":[5985,5986],"n":"Microsoft WinRM","c":"Remote access","k":85,"flag":"MgmtInterface"},
{"id":"b:apache","f":"header:server","r":"^Apache(?:/([\\d.]+))?(?:\\s|$)","n":"Apache HTTP Server","c":"Web server","v":"{1}","p":"cpe:2.3:a:apache:http_server:{v}","k":95,"ex":"Apache/2.4.41 (Ubuntu)","exv":"2.4.41"},
{"id":"b:os-ubuntu","f":"header:server","r":"\\(Ubuntu\\)","t":"os","n":"Ubuntu Linux","c":"OS","k":70,"p":"cpe:2.3:o:canonical:ubuntu_linux:*"},
{"id":"b:os-debian","f":"header:server","r":"\\(Debian\\)","t":"os","n":"Debian Linux","c":"OS","k":70,"p":"cpe:2.3:o:debian:debian_linux:*"},
{"id":"b:os-rhel","f":"header:server","r":"\\((?:Red Hat|Red Hat Enterprise Linux)\\)","t":"os","n":"Red Hat Enterprise Linux","c":"OS","k":70,"p":"cpe:2.3:o:redhat:enterprise_linux:*"},
{"id":"b:os-centos","f":"header:server","r":"\\(CentOS\\)","t":"os","n":"CentOS Linux","c":"OS","k":70},
{"id":"b:os-rocky","f":"header:server","r":"\\((Rocky Linux|AlmaLinux|Fedora|Oracle Linux)\\)","t":"os","n":"{1}","c":"OS","k":70},
{"id":"b:os-win","f":"header:server","r":"\\(Win(?:32|64)\\)","t":"os","n":"Microsoft Windows","c":"OS","k":70},
{"id":"b:os-suse","f":"header:server","r":"\\(Linux/SUSE\\)|\\(SUSE\\)","t":"os","n":"SUSE Linux","c":"OS","k":70},
{"id":"b:os-freebsd","f":"header:server","r":"\\(FreeBSD\\)","t":"os","n":"FreeBSD","c":"OS","k":70},
{"id":"b:openssl-comp","f":"header:server","r":"OpenSSL/([\\d.]+[a-z]?)","n":"OpenSSL","c":"Library","v":"{1}","p":"cpe:2.3:a:openssl:openssl:{v}","k":85,"ex":"Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips","exv":"1.0.2k"},
{"id":"b:modssl-comp","f":"header:server","r":"mod_ssl/([\\d.]+)","n":"mod_ssl","c":"Library","v":"{1}","k":80,"p":"cpe:2.3:a:modssl:mod_ssl:{v}"},
{"id":"b:php-comp","f":"header:server","r":"PHP/([\\d.]+)","n":"PHP","c":"Language","v":"{1}","p":"cpe:2.3:a:php:php:{v}","k":85},
{"id":"b:nginx","f":"header:server","r":"^nginx(?:/([\\d.]+))?","n":"nginx","c":"Web server","v":"{1}","p":"cpe:2.3:a:f5:nginx:{v}","k":95,"ex":"nginx/1.18.0 (Ubuntu)","exv":"1.18.0"},
{"id":"b:openresty","f":"header:server","r":"^openresty(?:/([\\d.]+))?","n":"OpenResty","c":"Web server","v":"{1}","p":"cpe:2.3:a:openresty:openresty:{v}","im":["nginx"],"k":95},
{"id":"b:tengine","f":"header:server","r":"^Tengine(?:/([\\d.]+))?","n":"Tengine","c":"Web server","v":"{1}","k":90,"p":"cpe:2.3:a:alibaba:tengine:{v}"},
{"id":"b:litespeed","f":"header:server","r":"^(?:Open)?LiteSpeed(?:/([\\d.]+))?","n":"LiteSpeed Web Server","c":"Web server","v":"{1}","p":"cpe:2.3:a:litespeedtech:litespeed_web_server:{v}","k":90},
{"id":"b:caddy","f":"header:server","r":"^Caddy","n":"Caddy","c":"Web server","p":"cpe:2.3:a:caddyserver:caddy:*","k":90},
{"id":"b:lighttpd","f":"header:server","r":"^lighttpd(?:/([\\d.]+))?","n":"lighttpd","c":"Web server","v":"{1}","p":"cpe:2.3:a:lighttpd:lighttpd:{v}","k":90},
{"id":"b:kestrel","f":"header:server","r":"^Kestrel","n":"Kestrel","c":"App server","im":["ASP.NET Core"],"k":90},
{"id":"b:coyote","f":"header:server","r":"^Apache-Coyote/","n":"Apache Tomcat","c":"App server","p":"cpe:2.3:a:apache:tomcat:*","k":80},
{"id":"b:jetty","f":"header:server","r":"Jetty\\(([^)]+)\\)","n":"Eclipse Jetty","c":"App server","v":"{1}","p":"cpe:2.3:a:eclipse:jetty:{v}","k":90,"ex":"Jetty(9.4.43.v20210629)","exv":"9.4.43.v20210629"},
{"id":"b:gunicorn","f":"header:server","r":"^gunicorn(?:/([\\d.]+))?","n":"Gunicorn","c":"App server","v":"{1}","p":"cpe:2.3:a:gunicorn:gunicorn:{v}","im":["Python"],"k":90},
{"id":"b:werkzeug","f":"header:server","r":"^Werkzeug/([\\d.]+)","n":"Werkzeug","c":"App server","v":"{1}","p":"cpe:2.3:a:palletsprojects:werkzeug:{v}","im":["Python"],"k":90,"flag":"DevServer"},
{"id":"b:python","f":"header:server","r":"\\bPython/([\\d.]+)","n":"Python","c":"Language","v":"{1}","p":"cpe:2.3:a:python:python:{v}","k":85},
{"id":"b:pyhttp","f":"header:server","r":"^(?:SimpleHTTP|BaseHTTP)/","n":"Python http.server","c":"Web server","k":95,"flag":"DevServer"},
{"id":"b:uvicorn","f":"header:server","r":"^uvicorn","n":"Uvicorn","c":"App server","im":["Python"],"k":90,"p":"cpe:2.3:a:encode:uvicorn:{v}"},
{"id":"b:tornado","f":"header:server","r":"^TornadoServer/([\\d.]+)","n":"Tornado","c":"App server","v":"{1}","im":["Python"],"k":90,"p":"cpe:2.3:a:tornadoweb:tornado:{v}"},
{"id":"b:cherrypy","f":"header:server","r":"^CherryPy/([\\d.]+)","n":"CherryPy","c":"App server","v":"{1}","im":["Python"],"k":90,"p":"cpe:2.3:a:cherrypy:cherrypy:{v}"},
{"id":"b:cowboy","f":"header:server","r":"^Cowboy","n":"Cowboy","c":"App server","k":85},
{"id":"b:ohs","f":"header:server","r":"^Oracle-HTTP-Server","n":"Oracle HTTP Server","c":"Web server","p":"cpe:2.3:a:oracle:http_server:*","k":90},
{"id":"b:weblogic-hdr","f":"header:server","r":"WebLogic(?: Server)? ?([\\d.]+)?","n":"Oracle WebLogic Server","c":"App server","v":"{1}","p":"cpe:2.3:a:oracle:weblogic_server:{v}","k":90},
{"id":"b:ibmhttp","f":"header:server","r":"^IBM_HTTP_Server(?:/([\\d.]+))?","n":"IBM HTTP Server","c":"Web server","v":"{1}","p":"cpe:2.3:a:ibm:http_server:{v}","k":90},
{"id":"b:websphere","f":"header:server","r":"WebSphere Application Server/([\\d.]+)","n":"IBM WebSphere Application Server","c":"App server","v":"{1}","p":"cpe:2.3:a:ibm:websphere_application_server:{v}","k":90},
{"id":"b:webseal","f":"header:server","r":"^WebSEAL/([\\d.]+)","n":"IBM Security Verify Access (WebSEAL)","c":"Identity","v":"{1}","k":90,"p":"cpe:2.3:a:ibm:security_verify_access:{v}"},
{"id":"b:glassfish","f":"header:server","r":"GlassFish Server[^/\\d]*([\\d.]+)?","n":"Eclipse GlassFish","c":"App server","v":"{1}","p":"cpe:2.3:a:eclipse:glassfish:{v}","k":90},
{"id":"b:payara","f":"header:server","r":"^Payara","n":"Payara Server","c":"App server","k":90,"p":"cpe:2.3:a:payara:payara:{v}"},
{"id":"b:wildfly-srv","f":"header:server","r":"^WildFly/(\\d+)","n":"WildFly","c":"App server","v":"{1}","p":"cpe:2.3:a:redhat:wildfly:{v}","k":90},
{"id":"b:resin","f":"header:server","r":"^Resin/([\\d.]+)","n":"Caucho Resin","c":"App server","v":"{1}","k":90,"p":"cpe:2.3:a:caucho:resin:{v}"},
{"id":"b:sapnw","f":"header:server","r":"SAP NetWeaver Application Server|SAP J2EE Engine","n":"SAP NetWeaver Application Server","c":"App server","p":"cpe:2.3:a:sap:netweaver_application_server:*","k":90},
{"id":"b:prtg","f":"header:server","r":"^PRTG/([\\d.]+)","n":"Paessler PRTG Network Monitor","c":"Monitoring","v":"{1}","p":"cpe:2.3:a:paessler:prtg_network_monitor:{v}","k":95,"flag":"MgmtInterface"},
{"id":"b:splunkd","f":"header:server","r":"^Splunkd","n":"Splunk","c":"SIEM","p":"cpe:2.3:a:splunk:splunk:*","k":95},
{"id":"b:nessus-srv","f":"header:server","r":"^NessusWWW","n":"Tenable Nessus","c":"Security","p":"cpe:2.3:a:tenable:nessus:*","k":95},
{"id":"b:couchdb","f":"header:server","r":"^CouchDB/([\\d.]+)","n":"Apache CouchDB","c":"Database","v":"{1}","p":"cpe:2.3:a:apache:couchdb:{v}","k":95},
{"id":"b:minio","f":"header:server","r":"^MinIO","n":"MinIO","c":"Storage","p":"cpe:2.3:a:minio:minio:*","k":95},
{"id":"b:docker-api","f":"header:server","r":"^Docker/([\\d.]+)","n":"Docker Engine API","c":"Container platform","v":"{1}","p":"cpe:2.3:a:docker:docker:{v}","k":95,"flag":"MgmtInterface"},
{"id":"b:nexus","f":"header:server","r":"^Nexus/([\\d.\\-]+)","n":"Sonatype Nexus Repository","c":"DevOps","v":"{1}","p":"cpe:2.3:a:sonatype:nexus_repository_manager:{v}","k":95},
{"id":"b:webmin","f":"header:server","r":"^MiniServ/([\\d.]+)","n":"Webmin","c":"Admin panel","v":"{1}","p":"cpe:2.3:a:webmin:webmin:{v}","k":95,"flag":"MgmtInterface"},
{"id":"b:cpanel","f":"header:server","r":"^cpsrvd(?:/([\\d.]+))?","n":"cPanel","c":"Admin panel","v":"{1}","p":"cpe:2.3:a:cpanel:cpanel:{v}","k":95,"flag":"MgmtInterface"},
{"id":"b:screenconnect","f":"header:server","r":"^ScreenConnect/([\\d.]+)","n":"ConnectWise ScreenConnect","c":"Remote access","v":"{1}","p":"cpe:2.3:a:connectwise:screenconnect:{v}","k":95,"flag":"MgmtInterface"},
{"id":"b:servu","f":"header:server","r":"^Serv-U/([\\d.]+)","n":"SolarWinds Serv-U","c":"File transfer","v":"{1}","p":"cpe:2.3:a:solarwinds:serv-u:{v}","k":95},
{"id":"b:crushftp","f":"header:server","r":"CrushFTP","n":"CrushFTP","c":"File transfer","p":"cpe:2.3:a:crushftp:crushftp:*","k":90},
{"id":"b:wingftp","f":"header:server","r":"^Wing FTP Server","n":"Wing FTP Server","c":"File transfer","k":90,"p":"cpe:2.3:a:wftpserver:wing_ftp_server:{v}"},
{"id":"b:akamai","f":"header:server","r":"^AkamaiGHost","n":"Akamai","c":"CDN/WAF","k":95},
{"id":"b:cloudflare","f":"header:server","r":"^cloudflare","n":"Cloudflare","c":"CDN/WAF","k":95},
{"id":"b:sucuri","f":"header:server","r":"^Sucuri/Cloudproxy","n":"Sucuri","c":"CDN/WAF","k":95},
{"id":"b:s3","f":"header:server","r":"^AmazonS3","n":"Amazon S3","c":"Storage","k":95},
{"id":"b:awselb","f":"header:server","r":"^awselb/([\\d.]+)","n":"AWS Elastic Load Balancing","c":"Load balancer","k":95},
{"id":"b:azappgw","f":"header:server","r":"^Microsoft-Azure-Application-Gateway","n":"Azure Application Gateway","c":"Load balancer","k":95},
{"id":"b:bigip-srv","f":"header:server","r":"^BIG-?IP","o":"i","n":"F5 BIG-IP","c":"Load balancer","p":"cpe:2.3:a:f5:big-ip_local_traffic_manager:*","k":90},
{"id":"b:fortios","f":"header:server","r":"^xxxxxxxx-xxxxx$","out":[{"n":"Fortinet FortiOS","c":"Firewall","p":"cpe:2.3:o:fortinet:fortios:*","k":95},{"t":"hw","n":"Fortinet FortiGate","c":"Firewall","k":85}]},
{"id":"b:sonicwall-srv","f":"header:server","r":"^SonicWALL","o":"i","n":"SonicWall SonicOS","c":"Firewall","p":"cpe:2.3:o:sonicwall:sonicos:*","k":90},
{"id":"b:checkpoint-srv","f":"header:server","r":"^Check Point SVN foundation","n":"Check Point Gaia","c":"Firewall","k":85,"p":"cpe:2.3:o:checkpoint:gaia_os:{v}"},
{"id":"b:ciscoios","f":"header:server","r":"^cisco-IOS","o":"i","t":"os","n":"Cisco IOS","c":"Network device","p":"cpe:2.3:o:cisco:ios:*","k":90},
{"id":"b:appweb","f":"header:server","r":"^(?:Mbedthis|Embedthis)-(?:Appweb|http)(?:/([\\d.]+))?","n":"Embedthis Appweb","c":"Embedded web server","v":"{1}","k":90,"p":"cpe:2.3:a:embedthis:appweb:{v}"},
{"id":"b:goahead","f":"header:server","r":"^GoAhead","n":"GoAhead","c":"Embedded web server","k":90,"p":"cpe:2.3:a:embedthis:goahead:{v}"},
{"id":"b:boa","f":"header:server","r":"^Boa/([\\d.]+)","n":"Boa","c":"Embedded web server","v":"{1}","k":90,"p":"cpe:2.3:a:boa:boa:{v}"},
{"id":"b:lwip","f":"header:server","r":"^lwIP","n":"lwIP","c":"Embedded web server","k":90,"p":"cpe:2.3:a:lwip_project:lwip:{v}"},
{"id":"b:minihttpd","f":"header:server","r":"^mini_httpd(?:/([\\d.]+))?","n":"mini_httpd","c":"Embedded web server","v":"{1}","k":90,"p":"cpe:2.3:a:acme:mini_httpd:{v}"},
{"id":"b:thttpd","f":"header:server","r":"^thttpd(?:/([\\d.]+\\w*))?","n":"thttpd","c":"Embedded web server","v":"{1}","k":90,"p":"cpe:2.3:a:acme:thttpd:{v}"},
{"id":"b:rompager","f":"header:server","r":"RomPager/([\\d.]+)","n":"Allegro RomPager","c":"Embedded web server","v":"{1}","p":"cpe:2.3:a:allegrosoft:rompager:{v}","k":90},
{"id":"b:emweb","f":"header:server","r":"^Virata-EmWeb/R([\\d_]+)","n":"Virata EmWeb","c":"Embedded web server","v":"{1}","k":90},
{"id":"b:hp-ews","f":"header:server","r":"HP HTTP Server|HP-ChaiSOE|HP-ChaiServer","out":[{"n":"HP Embedded Web Server","c":"Printer","k":85},{"t":"hw","n":"HP printer","c":"Printer","k":80}]},
{"id":"b:xerox-srv","f":"header:server","r":"^Xerox_MicroServer","t":"hw","n":"Xerox printer","c":"Printer","k":90},
{"id":"b:canon-srv","f":"header:server","r":"^CANON HTTP Server","t":"hw","n":"Canon printer","c":"Printer","k":90},
{"id":"b:brother-srv","f":"header:server","r":"^debut/([\\d.]+)","t":"hw","n":"Brother printer","c":"Printer","k":80},
{"id":"b:konica-srv","f":"header:server","r":"^KM-MFP-http","t":"hw","n":"Konica Minolta MFP","c":"Printer","k":90},
{"id":"b:cups","f":"header:server","r":"^CUPS/([\\d.]+)","n":"CUPS","c":"Printer","v":"{1}","p":"cpe:2.3:a:apple:cups:{v}","k":95},
{"id":"b:hikvision-srv","f":"header:server","r":"^(?:App-webs/|DNVRS-Webs|Hikvision-Webs)","t":"hw","n":"Hikvision camera/NVR","c":"Camera/IoT","k":85},
{"id":"b:xiongmai","f":"header:server","r":"^uc-httpd","t":"hw","n":"Xiongmai DVR/NVR","c":"Camera/IoT","k":85},
{"id":"b:niagara","f":"header:server","r":"^Niagara Web Server(?:/([\\d.]+))?","n":"Tridium Niagara","c":"Building automation","v":"{1}","p":"cpe:2.3:a:tridium:niagara:{v}","k":95,"flag":"MgmtInterface"},
{"id":"b:polycom","f":"header:server","r":"^Polycom","t":"hw","n":"Polycom phone","c":"VoIP","k":85},
{"id":"b:wince","f":"header:server","r":"^Microsoft-WinCE/([\\d.]+)","t":"os","n":"Windows CE","c":"OS","v":"{1}","k":85},
{"id":"b:squid-srv","f":"header:server","r":"^squid(?:/([\\d.]+))?","n":"Squid","c":"Proxy","v":"{1}","p":"cpe:2.3:a:squid-cache:squid:{v}","k":90},
{"id":"b:ats","f":"header:server","r":"^ATS/([\\d.]+)","n":"Apache Traffic Server","c":"Proxy","v":"{1}","p":"cpe:2.3:a:apache:traffic_server:{v}","k":90},
{"id":"b:varnish-srv","f":"header:server","r":"^Varnish","n":"Varnish","c":"Proxy","k":90,"p":"cpe:2.3:a:varnish-software:varnish_cache:{v}"},
{"id":"b:envoy","f":"header:server","r":"^envoy$","n":"Envoy","c":"Proxy","p":"cpe:2.3:a:envoyproxy:envoy:*","k":95},
{"id":"b:istio","f":"header:server","r":"^istio-envoy","n":"Istio","c":"Container platform","im":["Envoy"],"k":95,"p":"cpe:2.3:a:istio:istio:{v}"},
{"id":"b:kong-srv","f":"header:server","r":"^kong/([\\d.]+)","n":"Kong Gateway","c":"Proxy","v":"{1}","p":"cpe:2.3:a:konghq:kong_gateway:{v}","k":95},
{"id":"b:jboss-srv","f":"header:server","r":"^JBoss","n":"JBoss","c":"App server","k":85},
{"id":"b:aspnet-xpb","f":"header:x-powered-by","r":"^ASP\\.NET","n":"ASP.NET","c":"Framework","p":"cpe:2.3:a:microsoft:asp.net:*","k":90},
{"id":"b:aspnet-ver","f":"header:x-aspnet-version","r":"([\\d.]+)","n":"ASP.NET","c":"Framework","v":"{1}","p":"cpe:2.3:a:microsoft:asp.net:{v}","k":95},
{"id":"b:aspnetmvc","f":"header:x-aspnetmvc-version","r":"([\\d.]+)","n":"ASP.NET MVC","c":"Framework","v":"{1}","p":"cpe:2.3:a:microsoft:asp.net_model_view_controller:{v}","im":["ASP.NET"],"k":95},
{"id":"b:php-xpb","f":"header:x-powered-by","r":"PHP/([\\d.]+)","n":"PHP","c":"Language","v":"{1}","p":"cpe:2.3:a:php:php:{v}","k":95,"ex":"PHP/7.4.3","exv":"7.4.3"},
{"id":"b:express","f":"header:x-powered-by","r":"^Express$","n":"Express","c":"Framework","p":"cpe:2.3:a:expressjs:express:*","im":["Node.js"],"k":95},
{"id":"b:nextjs-xpb","f":"header:x-powered-by","r":"^Next\\.js ?([\\d.]+)?","n":"Next.js","c":"Framework","v":"{1}","p":"cpe:2.3:a:vercel:next.js:{v}","im":["React","Node.js"],"k":95},
{"id":"b:servlet","f":"header:x-powered-by","r":"Servlet/([\\d.]+)","n":"Java Servlet","c":"Language","v":"{1}","im":["Java"],"k":85},
{"id":"b:jsf","f":"header:x-powered-by","r":"JSF/([\\d.]+)","n":"JavaServer Faces","c":"Framework","v":"{1}","im":["Java"],"k":85},
{"id":"b:plesk-xpb","f":"header:x-powered-by","r":"^Plesk(?:Lin|Win)","n":"Plesk","c":"Admin panel","p":"cpe:2.3:a:plesk:plesk:*","k":95,"flag":"MgmtInterface"},
{"id":"b:passenger","f":"header:x-powered-by","r":"Phusion Passenger(?: \\(mod_rails/mod_rack\\))? ?([\\d.]+)?","n":"Phusion Passenger","c":"App server","v":"{1}","k":90,"p":"cpe:2.3:a:phusionpassenger:phusion_passenger:{v}"},
{"id":"b:undertow","f":"header:x-powered-by","r":"Undertow(?:/([\\d.]+))?","n":"Undertow","c":"App server","v":"{1}","k":90},
{"id":"b:jboss-xpb","f":"header:x-powered-by","r":"JBoss(?:-|AS-?)?([\\d.]+)?|WildFly/?(\\d+)?","n":"JBoss/WildFly","c":"App server","v":"{1}","k":85},
{"id":"b:drupal-gen","f":"header:x-generator","r":"Drupal ?(\\d+)?","n":"Drupal","c":"CMS","v":"{1}","p":"cpe:2.3:a:drupal:drupal:{v}","im":["PHP"],"k":95},
{"id":"b:drupal-cache","f":"header:x-drupal-cache","r":"","n":"Drupal","c":"CMS","p":"cpe:2.3:a:drupal:drupal:*","im":["PHP"],"k":90},
{"id":"b:jenkins","f":"header:x-jenkins","r":"([\\d.]+)","n":"Jenkins","c":"CI/CD","v":"{1}","p":"cpe:2.3:a:jenkins:jenkins:{v}","im":["Java"],"k":100,"ex":"2.401.3","exv":"2.401.3"},
{"id":"b:hudson","f":"header:x-hudson","r":"","n":"Jenkins","c":"CI/CD","p":"cpe:2.3:a:jenkins:jenkins:*","k":90},
{"id":"b:owa-ver","f":"header:x-owa-version","r":"([\\d.]+)","n":"Microsoft Exchange Server","c":"Mail","v":"{1}","p":"cpe:2.3:a:microsoft:exchange_server:*","k":100},
{"id":"b:exch-fe","f":"header:x-feserver","r":"","n":"Microsoft Exchange Server","c":"Mail","p":"cpe:2.3:a:microsoft:exchange_server:*","k":85},
{"id":"b:sp-hdr","f":"header:microsoftsharepointteamservices","r":"([\\d.]+)","n":"Microsoft SharePoint","c":"Collaboration","v":"{1}","p":"cpe:2.3:a:microsoft:sharepoint_server:*","k":100},
{"id":"b:sp-guid","f":"header:sprequestguid","r":"","n":"Microsoft SharePoint","c":"Collaboration","p":"cpe:2.3:a:microsoft:sharepoint_server:*","k":90},
{"id":"b:sp-health","f":"header:x-sharepointhealthscore","r":"","n":"Microsoft SharePoint","c":"Collaboration","p":"cpe:2.3:a:microsoft:sharepoint_server:*","k":90},
{"id":"b:confluence-hdr","f":"header:x-confluence-request-time","r":"","n":"Atlassian Confluence","c":"Collaboration","p":"cpe:2.3:a:atlassian:confluence_server:*","k":95},
{"id":"b:atl-areq","f":"header:x-arequestid","r":"","n":"Atlassian application","c":"Collaboration","k":60},
{"id":"b:kbn-ver","f":"header:kbn-version","r":"([\\d.]+)","n":"Kibana","c":"Monitoring","v":"{1}","p":"cpe:2.3:a:elastic:kibana:{v}","k":100},
{"id":"b:kbn-name","f":"header:kbn-name","r":"","n":"Kibana","c":"Monitoring","p":"cpe:2.3:a:elastic:kibana:*","k":95},
{"id":"b:elastic-prod","f":"header:x-elastic-product","r":"^Elasticsearch","n":"Elasticsearch","c":"Search","p":"cpe:2.3:a:elastic:elasticsearch:*","k":100},
{"id":"b:kong-hdr","f":"header:x-kong-proxy-latency","r":"","n":"Kong Gateway","c":"Proxy","k":90,"p":"cpe:2.3:a:konghq:kong_gateway:{v}"},
{"id":"b:envoy-hdr","f":"header:x-envoy-upstream-service-time","r":"","n":"Envoy","c":"Proxy","p":"cpe:2.3:a:envoyproxy:envoy:*","k":90},
{"id":"b:cf-ray","f":"header:cf-ray","r":"","n":"Cloudflare","c":"CDN/WAF","k":95},
{"id":"b:cloudfront","f":"header:x-amz-cf-id","r":"","n":"Amazon CloudFront","c":"CDN/WAF","k":95},
{"id":"b:cloudfront-via","f":"header:via","r":"CloudFront","o":"i","n":"Amazon CloudFront","c":"CDN/WAF","k":90},
{"id":"b:afd","f":"header:x-azure-ref","r":"","n":"Azure Front Door","c":"CDN/WAF","k":90},
{"id":"b:imperva-hdr","f":"header:x-iinfo","r":"","n":"Imperva","c":"CDN/WAF","k":95},
{"id":"b:sucuri-hdr","f":"header:x-sucuri-id","r":"","n":"Sucuri","c":"CDN/WAF","k":95},
{"id":"b:fastly","f":"header:x-fastly-request-id","r":"","n":"Fastly","c":"CDN/WAF","k":95},
{"id":"b:akamai-hdr","f":"header:x-akamai-transformed","r":"","n":"Akamai","c":"CDN/WAF","k":90},
{"id":"b:varnish-hdr","f":"header:x-varnish","r":"","n":"Varnish","c":"Proxy","k":90,"p":"cpe:2.3:a:varnish-software:varnish_cache:{v}"},
{"id":"b:varnish-via","f":"header:via","r":"varnish","o":"i","n":"Varnish","c":"Proxy","k":85,"p":"cpe:2.3:a:varnish-software:varnish_cache:{v}"},
{"id":"b:squid-via","f":"header:via","r":"\\(squid/([\\d.]+)\\)","n":"Squid","c":"Proxy","v":"{1}","p":"cpe:2.3:a:squid-cache:squid:{v}","k":90},
{"id":"b:netscaler-via","f":"header:via","r":"NS-CACHE","n":"Citrix NetScaler ADC","c":"Load balancer","k":85,"p":"cpe:2.3:a:citrix:netscaler_application_delivery_controller:{v}"},
{"id":"b:artifactory-id","f":"header:x-artifactory-id","r":"","n":"JFrog Artifactory","c":"DevOps","p":"cpe:2.3:a:jfrog:artifactory:*","k":95},
{"id":"b:jfrog-ver","f":"header:x-jfrog-version","r":"Artifactory/([\\d.]+)","n":"JFrog Artifactory","c":"DevOps","v":"{1}","p":"cpe:2.3:a:jfrog:artifactory:{v}","k":100},
{"id":"b:docker-reg","f":"header:docker-distribution-api-version","r":"registry/","n":"Docker Registry","c":"Container platform","k":100},
{"id":"b:gitlab-meta","f":"header:x-gitlab-meta","r":"","n":"GitLab","c":"CI/CD","p":"cpe:2.3:a:gitlab:gitlab:*","k":95},
{"id":"b:gitlab-fc","f":"header:x-gitlab-feature-category","r":"","n":"GitLab","c":"CI/CD","p":"cpe:2.3:a:gitlab:gitlab:*","k":95},
{"id":"b:plex","f":"header:x-plex-protocol","r":"","n":"Plex Media Server","c":"Media","k":95,"flag":"ShadowIT","p":"cpe:2.3:a:plex:media_server:{v}"},
{"id":"b:graylog-hdr","f":"header:x-graylog-node-id","r":"","n":"Graylog","c":"SIEM","k":95,"p":"cpe:2.3:a:graylog:graylog:{v}"},
{"id":"b:teamcity","f":"header:teamcity-node-id","r":"","n":"JetBrains TeamCity","c":"CI/CD","p":"cpe:2.3:a:jetbrains:teamcity:*","k":85},
{"id":"b:datapower","f":"header:x-backside-transport","r":"^(?:OK|FAIL)","n":"IBM DataPower Gateway","c":"Proxy","k":85,"p":"cpe:2.3:a:ibm:datapower_gateway:{v}"},
{"id":"b:oracle-ecid","f":"header:x-oracle-dms-ecid","r":"","n":"Oracle Fusion Middleware","c":"App server","k":80,"p":"cpe:2.3:a:oracle:fusion_middleware:{v}"},
{"id":"b:litespeed-cache","f":"header:x-litespeed-cache","r":"","n":"LiteSpeed Web Server","c":"Web server","k":85,"p":"cpe:2.3:a:litespeedtech:litespeed_web_server:{v}"},
{"id":"b:wp-redirect","f":"header:x-redirect-by","r":"^WordPress","n":"WordPress","c":"CMS","p":"cpe:2.3:a:wordpress:wordpress:*","im":["PHP"],"k":95},
{"id":"b:wp-pingback","f":"header:x-pingback","r":"xmlrpc\\.php","n":"WordPress","c":"CMS","p":"cpe:2.3:a:wordpress:wordpress:*","im":["PHP"],"k":90},
{"id":"b:wp-link","f":"header:link","r":"rel=\"https://api\\.w\\.org/\"","n":"WordPress","c":"CMS","p":"cpe:2.3:a:wordpress:wordpress:*","im":["PHP"],"k":95},
{"id":"b:t-iis-default","f":"title","r":"^(?:IIS Windows Server|IIS Windows|IIS7|IIS8|Microsoft Internet Information Services \\d+)$","n":"Microsoft IIS","c":"Web server","p":"cpe:2.3:a:microsoft:internet_information_services:*","k":90,"flag":"DefaultPage"},
{"id":"b:t-apache-default","f":"title","r":"^Apache2 (Ubuntu|Debian) Default Page","out":[{"n":"Apache HTTP Server","c":"Web server","p":"cpe:2.3:a:apache:http_server:*","k":90,"flag":"DefaultPage"},{"t":"os","n":"{1} Linux","c":"OS","k":70}]},
{"id":"b:t-apache-test","f":"title","r":"^(?:Test Page for the (?:Apache )?HTTP Server|HTTP Server Test Page)","n":"Apache HTTP Server","c":"Web server","p":"cpe:2.3:a:apache:http_server:*","k":85,"flag":"DefaultPage"},
{"id":"b:t-nginx-default","f":"title","r":"^Welcome to nginx!?$","n":"nginx","c":"Web server","p":"cpe:2.3:a:f5:nginx:*","k":90,"flag":"DefaultPage"},
{"id":"b:t-openresty-default","f":"title","r":"^Welcome to OpenResty!?$","n":"OpenResty","c":"Web server","k":90,"flag":"DefaultPage","p":"cpe:2.3:a:openresty:openresty:{v}"},
{"id":"b:t-tomcat","f":"title","r":"^Apache Tomcat(?:/([\\d.]+))?","n":"Apache Tomcat","c":"App server","v":"{1}","p":"cpe:2.3:a:apache:tomcat:{v}","k":95,"flag":"DefaultPage","ex":"Apache Tomcat/9.0.65","exv":"9.0.65"},
{"id":"b:t-wildfly","f":"title","r":"^Welcome to (?:WildFly|JBoss)","n":"JBoss/WildFly","c":"App server","k":90,"flag":"DefaultPage"},
{"id":"b:t-distro-default","f":"title","r":"^Welcome to (?:CentOS|AlmaLinux|Rocky Linux|Fedora|Red Hat Enterprise Linux)","flag":"DefaultPage","k":80},
{"id":"b:t-dirlist","f":"title","r":"^(?:Index of /|Directory listing for /|Directory Listing For /)","o":"i","flag":"DirectoryListing","k":95},
{"id":"b:t-phpinfo","f":"title","r":"^phpinfo\\(\\)","flag":"PhpInfoExposed","k":95},
{"id":"b:t-swagger","f":"title","r":"^Swagger UI","n":"Swagger UI","c":"Web application","k":95,"flag":"APIDocs","p":"cpe:2.3:a:smartbear:swagger_ui:{v}"},
{"id":"b:t-owa","f":"title","r":"^Outlook(?: Web App)?$","n":"Microsoft Exchange Server","c":"Mail","p":"cpe:2.3:a:microsoft:exchange_server:*","k":80},
{"id":"b:t-adcs","f":"title","r":"Microsoft Active Directory Certificate Services","n":"AD CS Web Enrollment","c":"Identity","k":100,"flag":"ADCSWebEnrollment"},
{"id":"b:t-rdweb","f":"title","r":"^(?:RD Web Access|RemoteApp and Desktop Connection|Work Resources)$","n":"Microsoft RD Web Access","c":"Remote access","k":90},
{"id":"b:t-wac","f":"title","r":"^Windows Admin Center","n":"Windows Admin Center","c":"Admin panel","p":"cpe:2.3:a:microsoft:windows_admin_center:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-ssrs","f":"title","r":"SQL Server Reporting Services|^Report Viewer$|^Reporting Services","n":"Microsoft SQL Server Reporting Services","c":"Web application","k":90,"p":"cpe:2.3:a:microsoft:sql_server_reporting_services:{v}"},
{"id":"b:t-pbirs","f":"title","r":"^Power BI Report Server","n":"Power BI Report Server","c":"Web application","k":95,"p":"cpe:2.3:a:microsoft:power_bi_report_server:{v}"},
{"id":"b:t-jenkins","f":"title","r":"\\[Jenkins\\]$|^Jenkins$","n":"Jenkins","c":"CI/CD","p":"cpe:2.3:a:jenkins:jenkins:*","k":90},
{"id":"b:t-gitlab","f":"title","r":"(?:^|· )GitLab$","n":"GitLab","c":"CI/CD","p":"cpe:2.3:a:gitlab:gitlab:*","k":90},
{"id":"b:t-gitea","f":"title","r":"Gitea(?:: Git with a cup of tea)?$","n":"Gitea","c":"CI/CD","p":"cpe:2.3:a:gitea:gitea:*","k":85},
{"id":"b:t-gogs","f":"title","r":"\\bGogs\\b","n":"Gogs","c":"CI/CD","k":85,"p":"cpe:2.3:a:gogs:gogs:{v}"},
{"id":"b:t-jira","f":"title","r":"\\b(?:JIRA|Jira)\\b","n":"Atlassian Jira","c":"Collaboration","p":"cpe:2.3:a:atlassian:jira:*","k":75},
{"id":"b:t-confluence","f":"title","r":"\\bConfluence\\b","n":"Atlassian Confluence","c":"Collaboration","p":"cpe:2.3:a:atlassian:confluence_server:*","k":75},
{"id":"b:t-bitbucket","f":"title","r":"\\bBitbucket\\b","n":"Atlassian Bitbucket","c":"CI/CD","p":"cpe:2.3:a:atlassian:bitbucket:*","k":75},
{"id":"b:t-bamboo","f":"title","r":"\\bBamboo\\b","n":"Atlassian Bamboo","c":"CI/CD","k":70,"p":"cpe:2.3:a:atlassian:bamboo:{v}"},
{"id":"b:t-teamcity","f":"title","r":"\\bTeamCity\\b","n":"JetBrains TeamCity","c":"CI/CD","p":"cpe:2.3:a:jetbrains:teamcity:*","k":85},
{"id":"b:t-sonarqube","f":"title","r":"\\bSonarQube\\b","n":"SonarQube","c":"DevOps","p":"cpe:2.3:a:sonarsource:sonarqube:*","k":90},
{"id":"b:t-nexus","f":"title","r":"Nexus Repository","n":"Sonatype Nexus Repository","c":"DevOps","k":90,"p":"cpe:2.3:a:sonatype:nexus_repository_manager:{v}"},
{"id":"b:t-artifactory","f":"title","r":"\\bArtifactory\\b|^JFrog","n":"JFrog Artifactory","c":"DevOps","k":85,"p":"cpe:2.3:a:jfrog:artifactory:{v}"},
{"id":"b:t-awx","f":"title","r":"^(?:Ansible (?:Tower|AWX)|AWX|Ansible Automation Platform)","n":"Ansible AWX/Tower","c":"DevOps","k":90,"flag":"MgmtInterface"},
{"id":"b:t-foreman","f":"title","r":"^Foreman$|Red Hat Satellite","n":"Foreman/Red Hat Satellite","c":"DevOps","k":85,"flag":"MgmtInterface"},
{"id":"b:t-puppet","f":"title","r":"Puppet Enterprise","n":"Puppet Enterprise","c":"DevOps","k":90,"p":"cpe:2.3:a:puppet:puppet_enterprise:{v}"},
{"id":"b:t-grafana","f":"title","r":"^Grafana$","n":"Grafana","c":"Monitoring","p":"cpe:2.3:a:grafana:grafana:*","k":90},
{"id":"b:t-kibana","f":"title","r":"^(?:Kibana|Elastic)$","n":"Kibana","c":"Monitoring","p":"cpe:2.3:a:elastic:kibana:*","k":85},
{"id":"b:t-prometheus","f":"title","r":"^Prometheus(?: Time Series Collection and Processing Server)?$","n":"Prometheus","c":"Monitoring","p":"cpe:2.3:a:prometheus:prometheus:*","k":90},
{"id":"b:t-alertmanager","f":"title","r":"^Alertmanager$","n":"Prometheus Alertmanager","c":"Monitoring","k":90,"p":"cpe:2.3:a:prometheus:alertmanager:{v}"},
{"id":"b:t-zabbix","f":"title","r":"\\bZabbix\\b","n":"Zabbix","c":"Monitoring","p":"cpe:2.3:a:zabbix:zabbix:*","k":85,"flag":"MgmtInterface"},
{"id":"b:t-nagios","f":"title","r":"^Nagios","n":"Nagios","c":"Monitoring","p":"cpe:2.3:a:nagios:nagios:*","k":85},
{"id":"b:t-icinga","f":"title","r":"^Icinga Web","n":"Icinga Web","c":"Monitoring","k":90,"p":"cpe:2.3:a:icinga:icinga_web_2:{v}"},
{"id":"b:t-cacti","f":"title","r":"^Login to Cacti","n":"Cacti","c":"Monitoring","p":"cpe:2.3:a:cacti:cacti:*","k":95},
{"id":"b:t-librenms","f":"title","r":"\\bLibreNMS\\b","n":"LibreNMS","c":"Monitoring","k":90,"p":"cpe:2.3:a:librenms:librenms:{v}"},
{"id":"b:t-observium","f":"title","r":"\\bObservium\\b","n":"Observium","c":"Monitoring","k":90,"p":"cpe:2.3:a:observium:observium:{v}"},
{"id":"b:t-checkmk","f":"title","r":"\\bCheckmk\\b|Check_MK","n":"Checkmk","c":"Monitoring","k":90,"p":"cpe:2.3:a:checkmk:checkmk:{v}"},
{"id":"b:t-whatsup","f":"title","r":"WhatsUp Gold","n":"Progress WhatsUp Gold","c":"Monitoring","p":"cpe:2.3:a:progress:whatsup_gold:*","k":95},
{"id":"b:t-orion","f":"title","r":"SolarWinds Orion|Orion Platform","n":"SolarWinds Orion","c":"Monitoring","p":"cpe:2.3:a:solarwinds:orion_platform:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-kuma","f":"title","r":"^Uptime Kuma","n":"Uptime Kuma","c":"Monitoring","k":90,"p":"cpe:2.3:a:uptime.kuma:uptime_kuma:{v}"},
{"id":"b:t-netdata","f":"title","r":"^netdata","o":"i","n":"Netdata","c":"Monitoring","k":85,"p":"cpe:2.3:a:netdata:netdata:{v}"},
{"id":"b:t-cadvisor","f":"title","r":"^cAdvisor","n":"cAdvisor","c":"Monitoring","k":90},
{"id":"b:t-graylog","f":"title","r":"^Graylog","n":"Graylog","c":"SIEM","k":90,"p":"cpe:2.3:a:graylog:graylog:{v}"},
{"id":"b:t-splunk","f":"title","r":"\\bSplunk\\b","n":"Splunk","c":"SIEM","p":"cpe:2.3:a:splunk:splunk:*","k":85},
{"id":"b:t-wazuh","f":"title","r":"\\bWazuh\\b","n":"Wazuh","c":"SIEM","k":90,"p":"cpe:2.3:a:wazuh:wazuh:{v}"},
{"id":"b:t-nessus","f":"title","r":"^Nessus","n":"Tenable Nessus","c":"Security","p":"cpe:2.3:a:tenable:nessus:*","k":90},
{"id":"b:t-tenablesc","f":"title","r":"Tenable\\.sc|SecurityCenter","n":"Tenable.sc","c":"Security","k":90,"p":"cpe:2.3:a:tenable:tenable.sc:{v}"},
{"id":"b:t-nexpose","f":"title","r":"Nexpose|InsightVM","n":"Rapid7 Nexpose/InsightVM","c":"Security","p":"cpe:2.3:a:rapid7:nexpose:*","k":90},
{"id":"b:t-gsa","f":"title","r":"Greenbone Security Assistant|\\bOpenVAS\\b","n":"Greenbone/OpenVAS","c":"Security","k":90},
{"id":"b:t-idrac","f":"title","r":"iDRAC ?(\\d+)?|Integrated Dell Remote Access Controller","out":[{"n":"Dell iDRAC","c":"Out-of-band mgmt","v":"{1}","k":95,"flag":"MgmtInterface"},{"t":"hw","n":"Dell PowerEdge server","c":"Server hardware","k":70}]},
{"id":"b:t-ilo","f":"title","r":"\\biLO ?(\\d)?\\b|Integrated Lights-Out","out":[{"n":"HPE iLO","c":"Out-of-band mgmt","v":"{1}","k":90,"flag":"MgmtInterface"},{"t":"hw","n":"HPE ProLiant server","c":"Server hardware","k":70}]},
{"id":"b:t-xcc","f":"title","r":"XClarity Controller|Lenovo XClarity","n":"Lenovo XClarity Controller","c":"Out-of-band mgmt","k":90,"flag":"MgmtInterface","p":"cpe:2.3:a:lenovo:xclarity_controller:{v}"},
{"id":"b:t-supermicro","f":"title","r":"Supermicro","n":"Supermicro BMC","c":"Out-of-band mgmt","k":80,"flag":"MgmtInterface"},
{"id":"b:t-cimc","f":"title","r":"Cisco Integrated Management Controller|^Cisco IMC","n":"Cisco IMC","c":"Out-of-band mgmt","k":90,"flag":"MgmtInterface","p":"cpe:2.3:a:cisco:integrated_management_controller:{v}"},
{"id":"b:t-esxi","f":"title","r":"VMware ESXi","n":"VMware ESXi","c":"Virtualization","p":"cpe:2.3:o:vmware:esxi:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-vcenter","f":"title","r":"vSphere|ID_VC_Welcome|VMware vCenter","n":"VMware vCenter Server","c":"Virtualization","p":"cpe:2.3:a:vmware:vcenter_server:*","k":85,"flag":"MgmtInterface"},
{"id":"b:t-horizon","f":"title","r":"^VMware Horizon","n":"VMware Horizon","c":"Remote access","p":"cpe:2.3:a:vmware:horizon:*","k":95},
{"id":"b:t-proxmox","f":"title","r":"Proxmox Virtual Environment|Proxmox Backup Server","n":"Proxmox","c":"Virtualization","k":95,"flag":"MgmtInterface"},
{"id":"b:t-nutanix","f":"title","r":"\\bNutanix\\b","n":"Nutanix Prism","c":"Virtualization","k":85,"flag":"MgmtInterface"},
{"id":"b:t-xen","f":"title","r":"XenServer|Citrix Hypervisor|XenCenter","n":"Citrix Hypervisor","c":"Virtualization","k":85,"flag":"MgmtInterface","p":"cpe:2.3:o:citrix:hypervisor:{v}"},
{"id":"b:t-portainer","f":"title","r":"^Portainer","n":"Portainer","c":"Container platform","p":"cpe:2.3:a:portainer:portainer:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-k8sdash","f":"title","r":"Kubernetes Dashboard","n":"Kubernetes Dashboard","c":"Container platform","k":95,"flag":"MgmtInterface"},
{"id":"b:t-argocd","f":"title","r":"^Argo CD","n":"Argo CD","c":"Container platform","p":"cpe:2.3:a:linuxfoundation:argo-cd:*","k":95},
{"id":"b:t-rancher","f":"title","r":"^Rancher$","n":"Rancher","c":"Container platform","k":90,"flag":"MgmtInterface","p":"cpe:2.3:a:suse:rancher:{v}"},
{"id":"b:t-harbor","f":"title","r":"^Harbor$","n":"Harbor","c":"Container platform","k":90,"p":"cpe:2.3:a:linuxfoundation:harbor:{v}"},
{"id":"b:t-openshift","f":"title","r":"OpenShift","n":"Red Hat OpenShift","c":"Container platform","k":85,"p":"cpe:2.3:a:redhat:openshift:{v}"},
{"id":"b:t-traefik","f":"title","r":"^Traefik","n":"Traefik","c":"Proxy","k":90,"p":"cpe:2.3:a:traefik:traefik:{v}"},
{"id":"b:t-consul","f":"title","r":"Consul by HashiCorp","n":"HashiCorp Consul","c":"DevOps","k":95,"p":"cpe:2.3:a:hashicorp:consul:{v}"},
{"id":"b:t-vault","f":"title","r":"^Vault$","n":"HashiCorp Vault","c":"Security","k":80,"p":"cpe:2.3:a:hashicorp:vault:{v}"},
{"id":"b:t-nomad","f":"title","r":"^Nomad$","n":"HashiCorp Nomad","c":"Container platform","k":80,"p":"cpe:2.3:a:hashicorp:nomad:{v}"},
{"id":"b:t-minio","f":"title","r":"MinIO Console|^MinIO$","n":"MinIO","c":"Storage","k":90,"p":"cpe:2.3:a:minio:minio:{v}"},
{"id":"b:t-pma","f":"title","r":"phpMyAdmin","n":"phpMyAdmin","c":"Admin panel","p":"cpe:2.3:a:phpmyadmin:phpmyadmin:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-adminer","f":"title","r":"\\bAdminer\\b","n":"Adminer","c":"Admin panel","k":90,"flag":"MgmtInterface","p":"cpe:2.3:a:adminer:adminer:{v}"},
{"id":"b:t-pgadmin","f":"title","r":"pgAdmin","n":"pgAdmin","c":"Admin panel","k":90,"flag":"MgmtInterface","p":"cpe:2.3:a:pgadmin:pgadmin_4:{v}"},
{"id":"b:t-mongoexpress","f":"title","r":"Mongo Express","n":"mongo-express","c":"Admin panel","k":95,"flag":"MgmtInterface","p":"cpe:2.3:a:mongo-express_project:mongo-express:{v}"},
{"id":"b:t-rabbitmq","f":"title","r":"RabbitMQ Management","n":"RabbitMQ","c":"Messaging","p":"cpe:2.3:a:vmware:rabbitmq:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-activemq","f":"title","r":"Apache ActiveMQ","n":"Apache ActiveMQ","c":"Messaging","p":"cpe:2.3:a:apache:activemq:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-solr","f":"title","r":"Solr Admin","n":"Apache Solr","c":"Search","p":"cpe:2.3:a:apache:solr:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-airflow","f":"title","r":"\\bAirflow\\b","n":"Apache Airflow","c":"DevOps","p":"cpe:2.3:a:apache:airflow:*","k":85},
{"id":"b:t-nifi","f":"title","r":"^NiFi$","n":"Apache NiFi","c":"DevOps","p":"cpe:2.3:a:apache:nifi:*","k":90},
{"id":"b:t-jupyter","f":"title","r":"^(?:Jupyter(?:Lab| Notebook|Hub)?|Home Page - Select or create a notebook)","n":"Jupyter","c":"DevOps","k":90,"flag":"ShadowIT"},
{"id":"b:t-rstudio","f":"title","r":"^RStudio","n":"RStudio Server","c":"DevOps","k":90},
{"id":"b:t-mlflow","f":"title","r":"^MLflow","n":"MLflow","c":"DevOps","k":90,"p":"cpe:2.3:a:lfprojects:mlflow:{v}"},
{"id":"b:t-roundcube","f":"title","r":"Roundcube Webmail","n":"Roundcube Webmail","c":"Mail","p":"cpe:2.3:a:roundcube:webmail:*","k":95},
{"id":"b:t-zimbra","f":"title","r":"\\bZimbra\\b","n":"Zimbra Collaboration","c":"Mail","p":"cpe:2.3:a:zimbra:collaboration:*","k":90},
{"id":"b:t-nextcloud","f":"title","r":"\\bNextcloud\\b","n":"Nextcloud","c":"Collaboration","p":"cpe:2.3:a:nextcloud:nextcloud_server:*","k":90},
{"id":"b:t-owncloud","f":"title","r":"\\bownCloud\\b","n":"ownCloud","c":"Collaboration","k":90,"p":"cpe:2.3:a:owncloud:owncloud:{v}"},
{"id":"b:t-mattermost","f":"title","r":"\\bMattermost\\b","n":"Mattermost","c":"Messaging","k":90},
{"id":"b:t-rocketchat","f":"title","r":"Rocket\\.Chat","n":"Rocket.Chat","c":"Messaging","k":90,"p":"cpe:2.3:a:rocket.chat:rocket.chat:{v}"},
{"id":"b:t-redmine","f":"title","r":"\\bRedmine\\b","n":"Redmine","c":"Collaboration","p":"cpe:2.3:a:redmine:redmine:*","k":85},
{"id":"b:t-bugzilla","f":"title","r":"\\bBugzilla\\b","n":"Bugzilla","c":"Collaboration","k":85,"p":"cpe:2.3:a:mozilla:bugzilla:{v}"},
{"id":"b:t-keycloak","f":"title","r":"\\bKeycloak\\b","n":"Keycloak","c":"Identity","p":"cpe:2.3:a:redhat:keycloak:*","k":90},
{"id":"b:t-pvwa","f":"title","r":"Password Vault|PasswordVault","n":"CyberArk PVWA","c":"Identity","k":85},
{"id":"b:t-secretserver","f":"title","r":"\\bSecret Server\\b","n":"Delinea Secret Server","c":"Identity","k":85,"p":"cpe:2.3:a:delinea:secret_server:{v}"},
{"id":"b:t-manageengine","f":"title","r":"\\bManageEngine ([\\w ]+?)(?:\\s*[-|]|$)","n":"ManageEngine {1}","c":"Admin panel","k":80},
{"id":"b:t-moveit","f":"title","r":"MOVEit Transfer","n":"Progress MOVEit Transfer","c":"File transfer","p":"cpe:2.3:a:progress:moveit_transfer:*","k":95},
{"id":"b:t-goanywhere","f":"title","r":"GoAnywhere","n":"Fortra GoAnywhere MFT","c":"File transfer","p":"cpe:2.3:a:fortra:goanywhere_managed_file_transfer:*","k":90},
{"id":"b:t-guac","f":"title","r":"Guacamole","n":"Apache Guacamole","c":"Remote access","p":"cpe:2.3:a:apache:guacamole:*","k":90},
{"id":"b:t-openvpnas","f":"title","r":"OpenVPN Access Server|^OpenVPN","n":"OpenVPN Access Server","c":"VPN","k":85,"p":"cpe:2.3:a:openvpn:openvpn_access_server:{v}"},
{"id":"b:t-nodered","f":"title","r":"^Node-RED","n":"Node-RED","c":"DevOps","k":90,"flag":"MgmtInterface","p":"cpe:2.3:a:nodered:node-red:{v}"},
{"id":"b:t-odoo","f":"title","r":"\\bOdoo\\b","n":"Odoo","c":"Web application","k":85,"p":"cpe:2.3:a:odoo:odoo:{v}"},
{"id":"b:t-veeam","f":"title","r":"Veeam Backup","n":"Veeam Backup & Replication","c":"Backup","k":90,"flag":"MgmtInterface","p":"cpe:2.3:a:veeam:veeam_backup_\\&_replication:{v}"},
{"id":"b:t-netapp","f":"title","r":"NetApp|ONTAP System Manager|OnCommand System Manager","n":"NetApp ONTAP","c":"Storage","k":85,"flag":"MgmtInterface","p":"cpe:2.3:a:netapp:ontap:{v}"},
{"id":"b:t-synology","f":"title","r":"\\bSynology\\b|DiskStation","n":"Synology DSM","c":"Storage","p":"cpe:2.3:o:synology:diskstation_manager:*","k":85,"flag":"MgmtInterface"},
{"id":"b:t-qnap","f":"title","r":"\\bQNAP\\b","n":"QNAP QTS","c":"Storage","k":85,"flag":"MgmtInterface","p":"cpe:2.3:o:qnap:qts:{v}"},
{"id":"b:t-unisphere","f":"title","r":"\\bUnisphere\\b","n":"Dell EMC Unisphere","c":"Storage","k":85,"flag":"MgmtInterface"},
{"id":"b:t-pure","f":"title","r":"Pure Storage","n":"Pure Storage","c":"Storage","k":85,"flag":"MgmtInterface"},
{"id":"b:t-pfsense","f":"title","r":"\\bpfSense\\b","n":"Netgate pfSense","c":"Firewall","p":"cpe:2.3:a:netgate:pfsense:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-opnsense","f":"title","r":"\\bOPNsense\\b","n":"OPNsense","c":"Firewall","p":"cpe:2.3:a:opnsense:opnsense:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-forti","f":"title","r":"\\bForti(Gate|Web|Mail|Manager|Analyzer|ADC|Authenticator|SIEM|NAC|Proxy|Sandbox)\\b","n":"Fortinet Forti{1}","c":"Firewall","k":90,"flag":"MgmtInterface"},
{"id":"b:t-sonicwall","f":"title","r":"SonicWall|SonicWALL","n":"SonicWall SonicOS","c":"Firewall","p":"cpe:2.3:o:sonicwall:sonicos:*","k":85},
{"id":"b:t-sophos","f":"title","r":"\\bSophos\\b","n":"Sophos Firewall","c":"Firewall","k":80,"p":"cpe:2.3:o:sophos:sfos:{v}"},
{"id":"b:t-watchguard","f":"title","r":"Fireware XTM|WatchGuard","n":"WatchGuard Firebox","c":"Firewall","k":85,"p":"cpe:2.3:o:watchguard:fireware:{v}"},
{"id":"b:t-zyxel","f":"title","r":"ZyWALL|\\bZyxel\\b|ZyXEL","n":"Zyxel","c":"Network device","k":80},
{"id":"b:t-globalprotect","f":"title","r":"GlobalProtect","n":"Palo Alto GlobalProtect","c":"VPN","p":"cpe:2.3:o:paloaltonetworks:pan-os:*","k":95},
{"id":"b:t-citrixgw","f":"title","r":"Citrix Gateway|NetScaler Gateway|NetScaler AAA|Citrix ADC","n":"Citrix Gateway","c":"VPN","k":90,"p":"cpe:2.3:a:citrix:netscaler_gateway:{v}"},
{"id":"b:t-storefront","f":"title","r":"Citrix StoreFront|Citrix Receiver","n":"Citrix StoreFront","c":"Remote access","k":90,"p":"cpe:2.3:a:citrix:storefront_server:{v}"},
{"id":"b:t-bigip","f":"title","r":"BIG-IP|F5 Networks","n":"F5 BIG-IP","c":"Load balancer","k":85,"p":"cpe:2.3:a:f5:big-ip_local_traffic_manager:{v}"},
{"id":"b:t-barracuda","f":"title","r":"\\bBarracuda\\b","n":"Barracuda","c":"Firewall","k":80},
{"id":"b:t-gaia","f":"title","r":"\\bGaia\\b|Check Point","n":"Check Point Gaia","c":"Firewall","k":80,"p":"cpe:2.3:o:checkpoint:gaia_os:{v}"},
{"id":"b:t-snx","f":"title","r":"SSL Network Extender","n":"Check Point Mobile Access","c":"VPN","k":90},
{"id":"b:t-ivanti","f":"title","r":"Pulse Connect Secure|Ivanti Connect Secure|Pulse Secure","n":"Ivanti Connect Secure","c":"VPN","p":"cpe:2.3:a:ivanti:connect_secure:*","k":95},
{"id":"b:t-asa","f":"title","r":"SSL VPN Service|Cisco ASDM","n":"Cisco ASA","c":"VPN","k":75,"p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:{v}"},
{"id":"b:t-ise","f":"title","r":"Identity Services Engine","n":"Cisco ISE","c":"Identity","p":"cpe:2.3:a:cisco:identity_services_engine:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-cucm","f":"title","r":"Cisco Unified (?:Communications|CM)","n":"Cisco Unified Communications Manager","c":"VoIP","k":90,"p":"cpe:2.3:a:cisco:unified_communications_manager:{v}"},
{"id":"b:t-ciscoprime","f":"title","r":"Cisco Prime","n":"Cisco Prime","c":"Network device","k":90,"flag":"MgmtInterface"},
{"id":"b:t-unifi","f":"title","r":"UniFi Network|UniFi OS|^UniFi","n":"Ubiquiti UniFi","c":"Network device","k":90,"flag":"MgmtInterface","p":"cpe:2.3:a:ui:unifi:{v}"},
{"id":"b:t-routeros","f":"title","r":"RouterOS","out":[{"t":"os","n":"MikroTik RouterOS","c":"Network device","p":"cpe:2.3:o:mikrotik:routeros:*","k":90},{"n":"MikroTik WebFig","c":"Network device","k":85,"flag":"MgmtInterface"}]},
{"id":"b:t-jweb","f":"title","r":"J-Web|Juniper Networks Web Management","n":"Juniper J-Web","c":"Network device","k":90,"flag":"MgmtInterface","p":"cpe:2.3:o:juniper:junos:{v}"},
{"id":"b:t-aruba","f":"title","r":"\\bAruba\\b","n":"Aruba","c":"Network device","k":70},
{"id":"b:t-ruckus","f":"title","r":"\\bRuckus\\b","n":"Ruckus","c":"Network device","k":70},
{"id":"b:t-luci","f":"title","r":"\\bLuCI\\b|OpenWrt","n":"OpenWrt LuCI","c":"Network device","k":85,"p":"cpe:2.3:a:openwrt:luci:{v}"},
{"id":"b:t-ricoh","f":"title","r":"Web Image Monitor","t":"hw","n":"Ricoh printer","c":"Printer","k":90},
{"id":"b:t-lexmark","f":"title","r":"\\bLexmark\\b","t":"hw","n":"Lexmark printer","c":"Printer","k":85},
{"id":"b:t-kyocera","f":"title","r":"Kyocera Command Center|KYOCERA","t":"hw","n":"Kyocera printer","c":"Printer","k":85},
{"id":"b:t-xerox","f":"title","r":"\\bXerox\\b|XEROX","t":"hw","n":"Xerox printer","c":"Printer","k":80},
{"id":"b:t-hpprinter","f":"title","r":"LaserJet|OfficeJet|DesignJet|PageWide","t":"hw","n":"HP printer","c":"Printer","k":90},
{"id":"b:t-canon","f":"title","r":"Remote UI","t":"hw","n":"Canon printer","c":"Printer","k":70},
{"id":"b:t-brother","f":"title","r":"^Brother ","t":"hw","n":"Brother printer","c":"Printer","k":75},
{"id":"b:t-epson","f":"title","r":"\\bEPSON\\b|\\bEpson\\b","t":"hw","n":"Epson printer","c":"Printer","k":70},
{"id":"b:t-axis","f":"title","r":"^AXIS\\b|AXIS .*Network Camera","t":"hw","n":"Axis camera","c":"Camera/IoT","k":85},
{"id":"b:t-hikvision","f":"title","r":"\\bHikvision\\b","t":"hw","n":"Hikvision camera/NVR","c":"Camera/IoT","k":80},
{"id":"b:t-polycom","f":"title","r":"^Polycom","t":"hw","n":"Polycom phone","c":"VoIP","k":85},
{"id":"b:t-apc","f":"title","r":"^APC \\||Network Management Card","t":"hw","n":"APC UPS (NMC)","c":"Power","k":85},
{"id":"b:t-metasys","f":"title","r":"\\bMetasys\\b","n":"Johnson Controls Metasys","c":"Building automation","k":90,"flag":"MgmtInterface","p":"cpe:2.3:a:johnsoncontrols:metasys:{v}"},
{"id":"b:t-niagara","f":"title","r":"\\bNiagara\\b","n":"Tridium Niagara","c":"Building automation","k":75,"p":"cpe:2.3:a:tridium:niagara:{v}"},
{"id":"b:t-simatic","f":"title","r":"\\bSIMATIC\\b","n":"Siemens SIMATIC","c":"Building automation","k":85,"flag":"MgmtInterface"},
{"id":"b:body-k8s","f":"body","r":"\"kind\"\\s*:\\s*\"Status\"[\\s\\S]{0,300}\"apiVersion\"|system:anonymous","n":"Kubernetes API","c":"Container platform","p":"cpe:2.3:a:kubernetes:kubernetes:*","k":90,"flag":"MgmtInterface"},
{"id":"b:body-es","f":"body","r":"\"number\"\\s*:\\s*\"([\\d.]+)\"","and":[{"f":"body","r":"You Know, for Search"}],"n":"Elasticsearch","c":"Search","v":"{1}","p":"cpe:2.3:a:elastic:elasticsearch:{v}","k":100},
{"id":"b:body-es2","f":"body","r":"You Know, for Search","n":"Elasticsearch","c":"Search","p":"cpe:2.3:a:elastic:elasticsearch:*","k":95},
{"id":"b:body-mongo","f":"body","r":"trying to access MongoDB over HTTP on the native driver port","n":"MongoDB","c":"Database","p":"cpe:2.3:a:mongodb:mongodb:*","k":100},
{"id":"b:body-spring","f":"body","r":"Whitelabel Error Page","n":"Spring Boot","c":"Framework","p":"cpe:2.3:a:vmware:spring_boot:*","im":["Java"],"k":95},
{"id":"b:body-confluence-ver","f":"body","r":"name=\"ajs-version-number\" content=\"([\\d.]+)\"","and":[{"f":"body","r":"confluence","o":"i"}],"n":"Atlassian Confluence","c":"Collaboration","v":"{1}","p":"cpe:2.3:a:atlassian:confluence_server:{v}","k":95},
{"id":"b:body-jira-ver","f":"body","r":"data-name=\"jira\" data-version=\"([\\d.]+)\"","n":"Atlassian Jira","c":"Collaboration","v":"{1}","p":"cpe:2.3:a:atlassian:jira:{v}","k":95},
{"id":"b:body-owa","f":"body","r":"/owa/auth/","n":"Microsoft Exchange Server","c":"Mail","p":"cpe:2.3:a:microsoft:exchange_server:*","k":85},
{"id":"b:body-gp","f":"body","r":"global-protect/login\\.esp|GlobalProtect Portal","n":"Palo Alto GlobalProtect","c":"VPN","p":"cpe:2.3:o:paloaltonetworks:pan-os:*","k":95},
{"id":"b:body-citrixgw","f":"body","r":"/vpn/index\\.html|/logon/LogonPoint/","n":"Citrix Gateway","c":"VPN","k":85,"p":"cpe:2.3:a:citrix:netscaler_gateway:{v}"},
{"id":"b:body-ivanti","f":"body","r":"/dana-na/","n":"Ivanti Connect Secure","c":"VPN","p":"cpe:2.3:a:ivanti:connect_secure:*","k":90},
{"id":"b:body-asa","f":"body","r":"/\\+CSCOE\\+/","n":"Cisco ASA","c":"VPN","p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:*","k":90},
{"id":"b:body-fortivpn","f":"body","r":"/remote/login|/remote/logincheck|ftnt-fortinet","n":"Fortinet FortiOS","c":"Firewall","p":"cpe:2.3:o:fortinet:fortios:*","k":85},
{"id":"b:body-next","f":"body","r":"__NEXT_DATA__","n":"Next.js","c":"Framework","im":["React"],"k":90,"p":"cpe:2.3:a:vercel:next.js:{v}"},
{"id":"b:body-nuxt","f":"body","r":"window\\.__NUXT__","n":"Nuxt.js","c":"Framework","im":["Vue.js"],"k":90,"p":"cpe:2.3:a:nuxt:nuxt:{v}"},
{"id":"b:body-angular","f":"body","r":"ng-version=\"([\\d.]+)\"","n":"Angular","c":"JavaScript libraries","v":"{1}","k":95,"p":"cpe:2.3:a:angular:angular:{v}"},
{"id":"b:body-wp","f":"body","r":"/wp-content/|/wp-includes/","n":"WordPress","c":"CMS","p":"cpe:2.3:a:wordpress:wordpress:*","im":["PHP"],"k":85},
{"id":"b:body-django","f":"body","r":"csrfmiddlewaretoken","n":"Django","c":"Framework","p":"cpe:2.3:a:djangoproject:django:*","im":["Python"],"k":90},
{"id":"b:body-tomcat","f":"body","r":"Apache Tomcat/([\\d.]+)","n":"Apache Tomcat","c":"App server","v":"{1}","p":"cpe:2.3:a:apache:tomcat:{v}","k":95,"ex":"<h3>Apache Tomcat/9.0.65</h3>","exv":"9.0.65"},
{"id":"b:body-apache-addr","f":"body","r":"<address>Apache/([\\d.]+)[^<]*Server at","n":"Apache HTTP Server","c":"Web server","v":"{1}","p":"cpe:2.3:a:apache:http_server:{v}","k":95},
{"id":"b:body-nginx-err","f":"body","r":"<center>nginx/([\\d.]+)</center>","n":"nginx","c":"Web server","v":"{1}","p":"cpe:2.3:a:f5:nginx:{v}","k":95,"ex":"<hr><center>nginx/1.24.0</center>","exv":"1.24.0"},
{"id":"b:body-iis-detail","f":"body","r":"IIS ([\\d.]+) Detailed Error","n":"Microsoft IIS","c":"Web server","v":"{1}","p":"cpe:2.3:a:microsoft:internet_information_services:{v}","k":95},
{"id":"b:body-weblogic","f":"body","r":"<TITLE>Error 404--Not Found</TITLE>","n":"Oracle WebLogic Server","c":"App server","p":"cpe:2.3:a:oracle:weblogic_server:*","k":85},
{"id":"b:body-grafana-ver","f":"body","r":"\"buildInfo\"\\s*:\\s*\\{[^}]*\"version\"\\s*:\\s*\"([\\d.]+)","and":[{"f":"body","r":"grafanaBootData"}],"n":"Grafana","c":"Monitoring","v":"{1}","p":"cpe:2.3:a:grafana:grafana:{v}","k":100},
{"id":"b:body-zabbix","f":"body","r":"content=\"Zabbix SIA\"","n":"Zabbix","c":"Monitoring","p":"cpe:2.3:a:zabbix:zabbix:*","k":90},
{"id":"b:body-viewstate","f":"body","r":"name=\"__VIEWSTATE\"","n":"ASP.NET Web Forms","c":"Framework","im":["ASP.NET"],"k":90},
{"id":"b:body-reqtoken","f":"body","r":"name=\"__RequestVerificationToken\"","n":"ASP.NET MVC","c":"Framework","im":["ASP.NET"],"k":70,"p":"cpe:2.3:a:microsoft:asp.net_model_view_controller:{v}"},
{"id":"b:body-swagger","f":"body","r":"swagger-ui(?:-bundle)?\\.js|id=\"swagger-ui\"","n":"Swagger UI","c":"Web application","k":90,"flag":"APIDocs","p":"cpe:2.3:a:smartbear:swagger_ui:{v}"},
{"id":"b:body-azappgw","f":"body","r":"Microsoft-Azure-Application-Gateway","n":"Azure Application Gateway","c":"Load balancer","k":90},
{"id":"b:js-jquery","f":"scriptsrc","r":"jquery[.-]([\\d]+\\.[\\d]+\\.[\\d]+)(?:\\.slim)?(?:\\.min)?\\.js","o":"i","n":"jQuery","c":"JavaScript libraries","v":"{1}","p":"cpe:2.3:a:jquery:jquery:{v}","k":95,"ex":"/static/js/jquery-3.5.1.min.js","exv":"3.5.1"},
{"id":"b:js-jquery-ver","f":"scriptsrc","r":"jquery(?:\\.min)?\\.js\\?ver=([\\d.]+)","o":"i","n":"jQuery","c":"JavaScript libraries","v":"{1}","p":"cpe:2.3:a:jquery:jquery:{v}","k":85},
{"id":"b:js-jqueryui","f":"scriptsrc","r":"jquery-ui[.-]([\\d]+\\.[\\d]+\\.[\\d]+)(?:\\.min)?\\.js","o":"i","n":"jQuery UI","c":"JavaScript libraries","v":"{1}","p":"cpe:2.3:a:jqueryui:jquery_ui:{v}","k":95},
{"id":"b:js-angularjs","f":"scriptsrc","r":"angular(?:js)?/([\\d.]+)/angular(?:\\.min)?\\.js","n":"AngularJS","c":"JavaScript libraries","v":"{1}","p":"cpe:2.3:a:angularjs:angular.js:{v}","k":95},
{"id":"b:js-bootstrap","f":"scriptsrc","r":"bootstrap(?:\\.bundle)?(?:\\.min)?\\.js(?:\\?v(?:er)?=([\\d.]+))?","n":"Bootstrap","c":"JavaScript libraries","v":"{1}","k":75,"p":"cpe:2.3:a:getbootstrap:bootstrap:{v}"},
{"id":"b:js-wp","f":"scriptsrc","r":"/wp-(?:content|includes)/","n":"WordPress","c":"CMS","p":"cpe:2.3:a:wordpress:wordpress:*","im":["PHP"],"k":90},
{"id":"b:meta-wp","f":"meta:generator","r":"^WordPress ?([\\d.]+)?","n":"WordPress","c":"CMS","v":"{1}","p":"cpe:2.3:a:wordpress:wordpress:{v}","im":["PHP"],"k":100,"ex":"WordPress 6.4.2","exv":"6.4.2"},
{"id":"b:meta-joomla","f":"meta:generator","r":"^Joomla!? ?([\\d.]+)?","n":"Joomla","c":"CMS","v":"{1}","im":["PHP"],"k":100,"p":"cpe:2.3:a:joomla:joomla\\!:{v}"},
{"id":"b:meta-drupal","f":"meta:generator","r":"^Drupal ?(\\d+)?","n":"Drupal","c":"CMS","v":"{1}","p":"cpe:2.3:a:drupal:drupal:{v}","im":["PHP"],"k":100},
{"id":"b:meta-mediawiki","f":"meta:generator","r":"^MediaWiki ?([\\d.]+)?","n":"MediaWiki","c":"CMS","v":"{1}","p":"cpe:2.3:a:mediawiki:mediawiki:{v}","im":["PHP"],"k":100},
{"id":"b:meta-sharepoint","f":"meta:generator","r":"Microsoft SharePoint","n":"Microsoft SharePoint","c":"Collaboration","p":"cpe:2.3:a:microsoft:sharepoint_server:*","k":95},
{"id":"b:meta-typo3","f":"meta:generator","r":"TYPO3 ?(?:CMS)? ?([\\d.]+)?","n":"TYPO3","c":"CMS","v":"{1}","p":"cpe:2.3:a:typo3:typo3:{v}","k":95},
{"id":"b:meta-hugo","f":"meta:generator","r":"^Hugo ([\\d.]+)","n":"Hugo","c":"CMS","v":"{1}","k":95,"p":"cpe:2.3:a:gohugo:hugo:{v}"},
{"id":"b:meta-jekyll","f":"meta:generator","r":"^Jekyll v([\\d.]+)","n":"Jekyll","c":"CMS","v":"{1}","k":95,"p":"cpe:2.3:a:jekyllrb:jekyll:{v}"},
{"id":"b:meta-dokuwiki","f":"meta:generator","r":"DokuWiki","n":"DokuWiki","c":"CMS","im":["PHP"],"k":95,"p":"cpe:2.3:a:dokuwiki:dokuwiki:{v}"},
{"id":"b:meta-ghost","f":"meta:generator","r":"^Ghost ([\\d.]+)","n":"Ghost","c":"CMS","v":"{1}","k":95,"p":"cpe:2.3:a:ghost:ghost:{v}"},
{"id":"b:meta-plone","f":"meta:generator","r":"^Plone","n":"Plone","c":"CMS","k":95,"p":"cpe:2.3:a:plone:plone:{v}"},
{"id":"b:meta-docusaurus","f":"meta:generator","r":"^Docusaurus v([\\d.]+)","n":"Docusaurus","c":"CMS","v":"{1}","k":95},
{"id":"b:meta-mkdocs","f":"meta:generator","r":"^mkdocs-([\\d.]+)","o":"i","n":"MkDocs","c":"CMS","v":"{1}","k":95,"p":"cpe:2.3:a:mkdocs:mkdocs:{v}"},
{"id":"b:meta-moodle","f":"meta:generator","r":"Moodle","n":"Moodle","c":"Web application","im":["PHP"],"k":95,"p":"cpe:2.3:a:moodle:moodle:{v}"},
{"id":"b:meta-confluence","f":"meta:generator","r":"Confluence","n":"Atlassian Confluence","c":"Collaboration","k":90,"p":"cpe:2.3:a:atlassian:confluence_server:{v}"},
{"id":"b:meta-appname-jira","f":"meta:application-name","r":"^JIRA$","n":"Atlassian Jira","c":"Collaboration","p":"cpe:2.3:a:atlassian:jira:*","k":95},
{"id":"b:c-aspnet","f":"cookiename","r":"^ASP\\.NET_SessionId$","n":"ASP.NET","c":"Framework","p":"cpe:2.3:a:microsoft:asp.net:*","k":90},
{"id":"b:c-aspnetcore","f":"cookiename","r":"^\\.AspNetCore\\.","n":"ASP.NET Core","c":"Framework","k":90,"p":"cpe:2.3:a:microsoft:asp.net_core:{v}"},
{"id":"b:c-asp","f":"cookiename","r":"^ASPSESSIONID","n":"Classic ASP","c":"Framework","k":90},
{"id":"b:c-php","f":"cookiename","r":"^PHPSESSID$","n":"PHP","c":"Language","p":"cpe:2.3:a:php:php:*","k":85},
{"id":"b:c-java","f":"cookiename","r":"^JSESSIONID$","n":"Java","c":"Language","k":70},
{"id":"b:c-coldfusion","f":"cookiename","r":"^(?:CFID|CFTOKEN)$","n":"Adobe ColdFusion","c":"App server","p":"cpe:2.3:a:adobe:coldfusion:*","k":90},
{"id":"b:c-laravel","f":"cookiename","r":"^laravel_session$","n":"Laravel","c":"Framework","im":["PHP"],"k":95,"p":"cpe:2.3:a:laravel:laravel:{v}"},
{"id":"b:c-codeigniter","f":"cookiename","r":"^ci_session$","n":"CodeIgniter","c":"Framework","im":["PHP"],"k":90,"p":"cpe:2.3:a:codeigniter:codeigniter:{v}"},
{"id":"b:c-django","f":"cookiename","r":"^csrftoken$","n":"Django","c":"Framework","im":["Python"],"k":60,"p":"cpe:2.3:a:djangoproject:django:{v}"},
{"id":"b:c-gitlab","f":"cookiename","r":"^_gitlab_session$","n":"GitLab","c":"CI/CD","p":"cpe:2.3:a:gitlab:gitlab:*","k":95},
{"id":"b:c-gitea","f":"cookiename","r":"^i_like_gitea$","n":"Gitea","c":"CI/CD","p":"cpe:2.3:a:gitea:gitea:*","k":95},
{"id":"b:c-gogs","f":"cookiename","r":"^i_like_gogs$","n":"Gogs","c":"CI/CD","k":95,"p":"cpe:2.3:a:gogs:gogs:{v}"},
{"id":"b:c-redmine","f":"cookiename","r":"^_redmine_session$","n":"Redmine","c":"Collaboration","k":95,"p":"cpe:2.3:a:redmine:redmine:{v}"},
{"id":"b:c-moodle","f":"cookiename","r":"^MoodleSession","n":"Moodle","c":"Web application","k":95,"p":"cpe:2.3:a:moodle:moodle:{v}"},
{"id":"b:c-roundcube","f":"cookiename","r":"^roundcube_sessid$","n":"Roundcube Webmail","c":"Mail","k":95,"p":"cpe:2.3:a:roundcube:webmail:{v}"},
{"id":"b:c-zimbra","f":"cookiename","r":"^ZM_(?:TEST|AUTH_TOKEN)$","n":"Zimbra Collaboration","c":"Mail","k":95,"p":"cpe:2.3:a:zimbra:collaboration:{v}"},
{"id":"b:c-jira","f":"cookiename","r":"^atlassian\\.xsrf\\.token$","n":"Atlassian Jira","c":"Collaboration","k":80,"p":"cpe:2.3:a:atlassian:jira:{v}"},
{"id":"b:c-bigip","f":"cookiename","r":"^BIGipServer","n":"F5 BIG-IP","c":"Load balancer","p":"cpe:2.3:a:f5:big-ip_local_traffic_manager:*","k":95},
{"id":"b:c-f5apm","f":"cookiename","r":"^(?:MRHSession|LastMRH_Session|F5_ST|F5_fullWT)$","n":"F5 BIG-IP APM","c":"VPN","p":"cpe:2.3:a:f5:big-ip_access_policy_manager:*","k":95},
{"id":"b:c-netscaler","f":"cookiename","r":"^NSC_|^citrix_ns_id","n":"Citrix NetScaler ADC","c":"Load balancer","k":95,"p":"cpe:2.3:a:citrix:netscaler_application_delivery_controller:{v}"},
{"id":"b:c-awselb","f":"cookiename","r":"^AWSALB|^AWSELB","n":"AWS Elastic Load Balancing","c":"Load balancer","k":95},
{"id":"b:c-arr","f":"cookiename","r":"^ARRAffinity","n":"Microsoft Application Request Routing","c":"Load balancer","k":85},
{"id":"b:c-imperva","f":"cookiename","r":"^(?:incap_ses_|visid_incap_|nlbi_)","n":"Imperva","c":"CDN/WAF","k":95},
{"id":"b:c-cloudflare","f":"cookiename","r":"^(?:__cfduid|__cf_bm|cf_clearance)$","n":"Cloudflare","c":"CDN/WAF","k":95},
{"id":"b:c-barracuda","f":"cookiename","r":"^barra_counter_session","n":"Barracuda WAF","c":"CDN/WAF","k":95,"p":"cpe:2.3:a:barracuda:web_application_firewall:{v}"},
{"id":"b:c-f5asm","f":"cookiename","r":"^TS[0-9a-f]{6,8}$","n":"F5 Advanced WAF (ASM)","c":"CDN/WAF","k":70,"p":"cpe:2.3:a:f5:big-ip_application_security_manager:{v}"},
{"id":"b:c-akamaibm","f":"cookiename","r":"^(?:ak_bmsc|bm_sv|bm_sz)$","n":"Akamai Bot Manager","c":"CDN/WAF","k":90},
{"id":"b:c-asavpn","f":"cookiename","r":"^webvpn","n":"Cisco ASA","c":"VPN","p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:*","k":90},
{"id":"b:c-ivanti","f":"cookiename","r":"^(?:DSSignInURL|DSID|DSLastAccess|DSFirstAccess)$","n":"Ivanti Connect Secure","c":"VPN","p":"cpe:2.3:a:ivanti:connect_secure:*","k":95},
{"id":"b:c-fortivpn","f":"cookiename","r":"^(?:SVPNCOOKIE|SVPNNETWORKCOOKIE)$","n":"Fortinet FortiOS","c":"Firewall","p":"cpe:2.3:o:fortinet:fortios:*","k":95},
{"id":"b:c-nexpose","f":"cookiename","r":"^nexposeCCSessionID","n":"Rapid7 Nexpose/InsightVM","c":"Security","k":95,"p":"cpe:2.3:a:rapid7:nexpose:{v}"},
{"id":"b:c-splunk","f":"cookiename","r":"^splunkweb_csrf_token_","n":"Splunk","c":"SIEM","p":"cpe:2.3:a:splunk:splunk:*","k":95},
{"id":"b:c-grafana","f":"cookiename","r":"^grafana_session$","n":"Grafana","c":"Monitoring","p":"cpe:2.3:a:grafana:grafana:*","k":95},
{"id":"b:c-zabbix","f":"cookiename","r":"^zbx_session(?:id)?$","n":"Zabbix","c":"Monitoring","k":95,"p":"cpe:2.3:a:zabbix:zabbix:{v}"},
{"id":"b:c-owa","f":"cookiename","r":"^(?:X-OWA-CANARY|X-BackEndCookie)$","n":"Microsoft Exchange Server","c":"Mail","p":"cpe:2.3:a:microsoft:exchange_server:*","k":90},
{"id":"b:c-adfs","f":"cookiename","r":"^MSIS","n":"Microsoft AD FS","c":"Identity","k":90},
{"id":"b:c-rdweb","f":"cookiename","r":"^TSWA","n":"Microsoft RD Web Access","c":"Remote access","k":85},
{"id":"b:c-siteminder","f":"cookiename","r":"^SMSESSION$","n":"Broadcom SiteMinder","c":"Identity","k":90,"p":"cpe:2.3:a:broadcom:siteminder:{v}"},
{"id":"b:c-webseal","f":"cookiename","r":"^PD-[SH]-SESSION-ID$","n":"IBM Security Verify Access (WebSEAL)","c":"Identity","k":90,"p":"cpe:2.3:a:ibm:security_verify_access:{v}"},
{"id":"b:c-oam","f":"cookiename","r":"^(?:ObSSOCookie|OAMAuthnCookie)","n":"Oracle Access Manager","c":"Identity","k":90,"p":"cpe:2.3:a:oracle:access_manager:{v}"},
{"id":"b:c-keycloak","f":"cookiename","r":"^(?:KEYCLOAK_|AUTH_SESSION_ID$)","n":"Keycloak","c":"Identity","k":85,"p":"cpe:2.3:a:redhat:keycloak:{v}"},
{"id":"b:c-sap","f":"cookiename","r":"^(?:sap-usercontext|MYSAPSSO2|SAP_SESSIONID)","n":"SAP NetWeaver Application Server","c":"App server","k":90,"p":"cpe:2.3:a:sap:netweaver_application_server:{v}"},
{"id":"b:c-peoplesoft","f":"cookiename","r":"^PS_(?:TOKEN|LOGINLIST|DEVICEFEATURES)$","n":"Oracle PeopleSoft","c":"Web application","k":90,"p":"cpe:2.3:a:oracle:peoplesoft_enterprise_peopletools:{v}"},
{"id":"b:c-rack","f":"cookiename","r":"^rack\\.session$","n":"Ruby Rack","c":"Framework","k":70,"p":"cpe:2.3:a:rack:rack:{v}"},
{"id":"b:c-connectsid","f":"cookiename","r":"^connect\\.sid$","n":"Express","c":"Framework","im":["Node.js"],"k":75,"p":"cpe:2.3:a:expressjs:express:{v}"},
{"id":"b:c-wp","f":"cookiename","r":"^(?:wordpress_|wp-settings-)","n":"WordPress","c":"CMS","im":["PHP"],"k":90,"p":"cpe:2.3:a:wordpress:wordpress:{v}"},
{"id":"b:c-drupal","f":"cookiename","r":"^S?SESS[0-9a-f]{32}$","n":"Drupal","c":"CMS","im":["PHP"],"k":70,"p":"cpe:2.3:a:drupal:drupal:{v}"},
{"id":"b:a-tomcatmgr","f":"auth","r":"realm=\"Tomcat Manager Application\"","n":"Apache Tomcat Manager","c":"Admin panel","im":["Apache Tomcat"],"k":100,"flag":"MgmtInterface"},
{"id":"b:a-nagios","f":"auth","r":"realm=\"Nagios Access\"","n":"Nagios","c":"Monitoring","k":95,"p":"cpe:2.3:a:nagios:nagios:{v}"},
{"id":"b:a-jmx","f":"auth","r":"realm=\"JBoss JMX Console\"","n":"JBoss JMX Console","c":"Admin panel","k":100,"flag":"MgmtInterface"},
{"id":"b:l-ivanti","f":"location","r":"/dana-na/","n":"Ivanti Connect Secure","c":"VPN","p":"cpe:2.3:a:ivanti:connect_secure:*","k":95},
{"id":"b:l-asa","f":"location","r":"/\\+CSCOE\\+/","n":"Cisco ASA","c":"VPN","p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:*","k":95},
{"id":"b:l-fortivpn","f":"location","r":"/remote/login","n":"Fortinet FortiOS","c":"Firewall","p":"cpe:2.3:o:fortinet:fortios:*","k":90},
{"id":"b:l-gp","f":"location","r":"/global-protect/","n":"Palo Alto GlobalProtect","c":"VPN","p":"cpe:2.3:o:paloaltonetworks:pan-os:*","k":95},
{"id":"b:l-owa","f":"location","r":"/owa/?(?:$|[?#])|/owa/auth/","o":"i","n":"Microsoft Exchange Server","c":"Mail","p":"cpe:2.3:a:microsoft:exchange_server:*","k":85},
{"id":"b:l-ecp","f":"location","r":"/ecp/","o":"i","n":"Microsoft Exchange Server","c":"Mail","k":80,"p":"cpe:2.3:a:microsoft:exchange_server:{v}"},
{"id":"b:l-adfs","f":"location","r":"/adfs/ls","o":"i","n":"Microsoft AD FS","c":"Identity","k":90},
{"id":"b:l-rdweb","f":"location","r":"/RDWeb","o":"i","n":"Microsoft RD Web Access","c":"Remote access","k":90},
{"id":"b:l-storefront","f":"location","r":"/Citrix/\\w+Web","o":"i","n":"Citrix StoreFront","c":"Remote access","k":90,"p":"cpe:2.3:a:citrix:storefront_server:{v}"},
{"id":"b:l-citrixgw","f":"location","r":"/vpn/index\\.html|/logon/LogonPoint","n":"Citrix Gateway","c":"VPN","k":90,"p":"cpe:2.3:a:citrix:netscaler_gateway:{v}"},
{"id":"b:l-f5apm","f":"location","r":"/my\\.policy|/my\\.logon\\.php","n":"F5 BIG-IP APM","c":"VPN","k":90,"p":"cpe:2.3:a:f5:big-ip_access_policy_manager:{v}"},
{"id":"b:l-tmui","f":"location","r":"/tmui/","n":"F5 BIG-IP TMUI","c":"Load balancer","k":95,"flag":"MgmtInterface"},
{"id":"b:l-pvwa","f":"location","r":"/PasswordVault","o":"i","n":"CyberArk PVWA","c":"Identity","k":95},
{"id":"b:l-ssrs","f":"location","r":"/Reports/|/ReportServer","o":"i","n":"Microsoft SQL Server Reporting Services","c":"Web application","k":85,"p":"cpe:2.3:a:microsoft:sql_server_reporting_services:{v}"},
{"id":"b:l-certsrv","f":"location","r":"/certsrv","o":"i","n":"AD CS Web Enrollment","c":"Identity","k":85,"flag":"ADCSWebEnrollment"},
{"id":"b:l-prom","f":"location","r":"^/graph$|/graph$","n":"Prometheus","c":"Monitoring","k":75,"p":"cpe:2.3:a:prometheus:prometheus:{v}"},
{"id":"b:l-vcenter","f":"location","r":"/websso/SAML2/SSO/","n":"VMware vCenter Server","c":"Virtualization","p":"cpe:2.3:a:vmware:vcenter_server:*","k":90,"flag":"MgmtInterface"},
{"id":"b:l-hik","f":"location","r":"/doc/page/login\\.asp","t":"hw","n":"Hikvision camera/NVR","c":"Camera/IoT","k":85},
{"id":"b:l-luci","f":"location","r":"/cgi-bin/luci","n":"OpenWrt LuCI","c":"Network device","k":90,"p":"cpe:2.3:a:openwrt:luci:{v}"},
{"id":"b:l-webfig","f":"location","r":"/webfig/","n":"MikroTik WebFig","c":"Network device","k":90,"flag":"MgmtInterface"},
{"id":"b:x-sonicwall","f":"cert.subject","r":"HTTPS Management Certificate for SonicWALL","n":"SonicWall SonicOS","c":"Firewall","k":95,"p":"cpe:2.3:o:sonicwall:sonicos:{v}"},
{"id":"b:x-asa","f":"cert.subject","r":"CN=ASA Temporary Self Signed Certificate","n":"Cisco ASA","c":"VPN","k":95,"p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:{v}"},
{"id":"b:x-splunk","f":"cert.subject","r":"CN=SplunkServerDefaultCert|O=SplunkUser","n":"Splunk","c":"SIEM","k":95,"flag":"DefaultCert","p":"cpe:2.3:a:splunk:splunk:{v}"},
{"id":"b:x-nessus","f":"cert.subject","r":"O=Nessus Users United","n":"Tenable Nessus","c":"Security","k":95,"flag":"DefaultCert","p":"cpe:2.3:a:tenable:nessus:{v}"},
{"id":"b:x-pfsense","f":"cert.subject","r":"pfSense webConfigurator Self-Signed","n":"Netgate pfSense","c":"Firewall","k":95,"flag":"DefaultCert","p":"cpe:2.3:a:netgate:pfsense:{v}"},
{"id":"b:x-proxmox","f":"cert.issuer","r":"CN=Proxmox Virtual Environment|O=PVE Cluster Manager CA","n":"Proxmox","c":"Virtualization","k":95},
{"id":"b:x-wac","f":"cert.subject","r":"CN=Windows Admin Center","n":"Windows Admin Center","c":"Admin panel","k":95,"flag":"MgmtInterface","p":"cpe:2.3:a:microsoft:windows_admin_center:{v}"},
{"id":"b:x-k8s","f":"cert.issuer","r":"CN=(?:kubernetes|kube-ca)(?:,|$)","n":"Kubernetes","c":"Container platform","k":85,"p":"cpe:2.3:a:kubernetes:kubernetes:{v}"},
{"id":"b:x-vmware","f":"cert.issuer","r":"OU=VMware Engineering|O=VMware Installer","n":"VMware ESXi","c":"Virtualization","k":80,"flag":"DefaultCert","p":"cpe:2.3:o:vmware:esxi:{v}"},
{"id":"b:x-idrac","f":"cert.subject","r":"OU=Remote Access Group,O=Dell Inc\\.","n":"Dell iDRAC","c":"Out-of-band mgmt","k":90,"flag":"MgmtInterface"},
{"id":"b:x-ilo","f":"cert.subject","r":"CN=ILO","o":"i","n":"HPE iLO","c":"Out-of-band mgmt","k":80,"flag":"MgmtInterface"},
{"id":"b:x-supermicro","f":"cert.subject","r":"O=Super Micro Computer","n":"Supermicro BMC","c":"Out-of-band mgmt","k":90,"flag":"MgmtInterface"},
{"id":"b:x-synology","f":"cert.subject","r":"O=Synology Inc\\.","n":"Synology DSM","c":"Storage","k":85,"p":"cpe:2.3:o:synology:diskstation_manager:{v}"},
{"id":"b:x-ubiquiti","f":"cert.subject","r":"O=Ubiquiti","n":"Ubiquiti","c":"Network device","k":85},
{"id":"b:x-paloalto","f":"cert.subject","r":"O=Palo Alto Networks","n":"Palo Alto Networks PAN-OS","c":"Firewall","k":80,"p":"cpe:2.3:o:paloaltonetworks:pan-os:{v}"},
{"id":"b:x-fortinet","f":"cert.subject","r":"O=Fortinet","n":"Fortinet FortiOS","c":"Firewall","k":85,"p":"cpe:2.3:o:fortinet:fortios:{v}"},
{"id":"b:x-opensslde","f":"cert.subject","r":"O=Internet Widgits Pty Ltd","flag":"DefaultCert","k":95},
{"id":"b:x-modssl","f":"cert.subject","r":"O=SomeOrganization|OU=SomeOrganizationalUnit","flag":"DefaultCert","k":95},
{"id":"b:x-plesk","f":"cert.subject","r":"CN=Plesk","n":"Plesk","c":"Admin panel","k":85,"p":"cpe:2.3:a:plesk:plesk:{v}"},
{"id":"b:bn-openssh","f":"banner.ssh","r":"^OpenSSH_([\\w.]+)","n":"OpenSSH","c":"Remote access","v":"{1}","p":"cpe:2.3:a:openbsd:openssh:{v}","k":95,"ex":"OpenSSH_8.9p1 Ubuntu-3ubuntu0.6","exv":"8.9p1"},
{"id":"b:bn-ssh","f":"banner","r":"^SSH-([\\d.]+)-","n":"SSH server","c":"Remote access","k":45},
{"id":"b:bn-vnc","f":"banner","r":"^RFB (\\d{3}\\.\\d{3})","n":"VNC","c":"Remote access","v":"{1}","k":95,"flag":"MgmtInterface"},
{"id":"b:bn-postgres","f":"banner","r":"unsupported frontend protocol|SFATAL.{0,40}C0A000","n":"PostgreSQL","c":"Database","p":"cpe:2.3:a:postgresql:postgresql:*","k":90},
{"id":"b:bn-redis","f":"banner","r":"^-(?:ERR wrong number of arguments for 'get' command|DENIED Redis|NOAUTH)","n":"Redis","c":"Database","p":"cpe:2.3:a:redis:redis:*","k":90},
{"id":"b:bn-amqp","f":"banner","r":"^AMQP","n":"AMQP broker","c":"Messaging","k":90},
{"id":"b:bn-rsync","f":"banner","r":"^@RSYNCD: ([\\d.]+)","n":"rsync","c":"File transfer","v":"{1}","k":95},
{"id":"b:bn-mariadb","f":"banner.mysql","r":"^(?:5\\.5\\.5-)?([\\d.]+)-MariaDB","n":"MariaDB","c":"Database","v":"{1}","p":"cpe:2.3:a:mariadb:mariadb:{v}","k":95,"ex":"5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1","exv":"10.6.12"},
{"id":"b:bn-mysql","f":"banner.mysql","r":"^(\\d+\\.\\d+\\.\\d+)(?!.*MariaDB)","n":"MySQL","c":"Database","v":"{1}","p":"cpe:2.3:a:oracle:mysql:{v}","k":85,"ex":"8.0.36-0ubuntu0.22.04.1","exv":"8.0.36"},
{"id":"b:bn-ftp","f":"banner.ftp","r":"","n":"FTP server","c":"File transfer","k":45},
{"id":"b:bn-smtp","f":"banner.smtp","r":"E?SMTP","n":"SMTP server","c":"Mail","k":45},
{"id":"b:p-owa","f":"path:/owa/auth/logon.aspx.header:x-owa-version","r":"([\\d.]+)","n":"Microsoft Exchange Server","c":"Mail","v":"{1}","p":"cpe:2.3:a:microsoft:exchange_server:*","k":100},
{"id":"b:p-owa2","f":"path:/owa/auth/logon.aspx.body","r":"/owa/auth/","n":"Microsoft Exchange Server","c":"Mail","k":90,"p":"cpe:2.3:a:microsoft:exchange_server:{v}"},
{"id":"b:p-certsrv-t","f":"path:/certsrv/.title","r":"Microsoft Active Directory Certificate Services","n":"AD CS Web Enrollment","c":"Identity","k":100,"flag":"ADCSWebEnrollment"},
{"id":"b:p-certsrv-401","f":"path:/certsrv/.status","r":"^401$","and":[{"f":"status","r":"^401$","not":true},{"f":"path:/certsrv/.auth","r":"^(?:NTLM|Negotiate)"}],"n":"AD CS Web Enrollment","c":"Identity","k":85,"flag":"ADCSWebEnrollment"},
{"id":"b:p-adfs","f":"path:/adfs/ls/idpinitiatedsignon.aspx.body","r":"/adfs/portal/|AD FS|idpinitiatedsignon","o":"i","n":"Microsoft AD FS","c":"Identity","k":90},
{"id":"b:p-rdweb","f":"path:/RDWeb/.body","r":"RD Web Access|TSWA|RDWeb","o":"i","n":"Microsoft RD Web Access","c":"Remote access","k":90},
{"id":"b:p-fortivpn","f":"path:/remote/login.body","r":"fgt_lang|ftnt|/remote/logincheck|FortiToken","o":"i","n":"Fortinet FortiOS","c":"Firewall","p":"cpe:2.3:o:fortinet:fortios:*","k":90},
{"id":"b:p-gp","f":"path:/global-protect/login.esp.body","r":"GlobalProtect","n":"Palo Alto GlobalProtect","c":"VPN","p":"cpe:2.3:o:paloaltonetworks:pan-os:*","k":95},
{"id":"b:p-asa","f":"path:/+CSCOE+/logon.html.body","r":"webvpn|CSCOE|SSL VPN Service","o":"i","n":"Cisco ASA","c":"VPN","p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:*","k":90},
{"id":"b:p-ivanti","f":"path:/dana-na/auth/url_default/welcome.cgi.body","r":"dana-na|Pulse Secure|Ivanti","o":"i","n":"Ivanti Connect Secure","c":"VPN","p":"cpe:2.3:a:ivanti:connect_secure:*","k":90},
{"id":"b:p-citrixgw","f":"path:/vpn/index.html.body","r":"Citrix|NetScaler","o":"i","n":"Citrix Gateway","c":"VPN","k":85,"p":"cpe:2.3:a:citrix:netscaler_gateway:{v}"},
{"id":"b:p-k8s","f":"path:/version.body","r":"\"gitVersion\"\\s*:\\s*\"v?([\\w.+-]+)\"","n":"Kubernetes","c":"Container platform","v":"{1}","p":"cpe:2.3:a:kubernetes:kubernetes:{v}","k":100,"flag":"MgmtInterface"},
{"id":"b:p-docker","f":"path:/version.body","r":"\"Version\"\\s*:\\s*\"([\\d.]+)\"","and":[{"f":"path:/version.body","r":"\"ApiVersion\""}],"n":"Docker Engine API","c":"Container platform","v":"{1}","p":"cpe:2.3:a:docker:docker:{v}","k":100,"flag":"MgmtInterface"},
{"id":"b:p-grafana","f":"path:/api/health.body","r":"\"version\"\\s*:\\s*\"([\\d.]+)","and":[{"f":"path:/api/health.body","r":"\"database\""}],"n":"Grafana","c":"Monitoring","v":"{1}","p":"cpe:2.3:a:grafana:grafana:{v}","k":100},
{"id":"b:p-prom","f":"path:/api/v1/status/buildinfo.body","r":"\"version\"\\s*:\\s*\"([\\d.]+)","and":[{"f":"path:/api/v1/status/buildinfo.body","r":"\"goVersion\""}],"n":"Prometheus","c":"Monitoring","v":"{1}","p":"cpe:2.3:a:prometheus:prometheus:{v}","k":100},
{"id":"b:p-atl-jira","f":"path:/rest/applinks/1.0/manifest.body","r":"<version>([\\d.]+)</version>","and":[{"f":"path:/rest/applinks/1.0/manifest.body","r":"<typeId>jira</typeId>"}],"n":"Atlassian Jira","c":"Collaboration","v":"{1}","p":"cpe:2.3:a:atlassian:jira:{v}","k":100},
{"id":"b:p-atl-conf","f":"path:/rest/applinks/1.0/manifest.body","r":"<version>([\\d.]+)</version>","and":[{"f":"path:/rest/applinks/1.0/manifest.body","r":"<typeId>confluence</typeId>"}],"n":"Atlassian Confluence","c":"Collaboration","v":"{1}","p":"cpe:2.3:a:atlassian:confluence_server:{v}","k":100},
{"id":"b:p-atl-bb","f":"path:/rest/applinks/1.0/manifest.body","r":"<version>([\\d.]+)</version>","and":[{"f":"path:/rest/applinks/1.0/manifest.body","r":"<typeId>stash</typeId>"}],"n":"Atlassian Bitbucket","c":"CI/CD","v":"{1}","p":"cpe:2.3:a:atlassian:bitbucket:{v}","k":100},
{"id":"b:p-atl-bamboo","f":"path:/rest/applinks/1.0/manifest.body","r":"<version>([\\d.]+)</version>","and":[{"f":"path:/rest/applinks/1.0/manifest.body","r":"<typeId>bamboo</typeId>"}],"n":"Atlassian Bamboo","c":"CI/CD","v":"{1}","p":"cpe:2.3:a:atlassian:bamboo:{v}","k":100},
{"id":"b:p-atl-crowd","f":"path:/rest/applinks/1.0/manifest.body","r":"<version>([\\d.]+)</version>","and":[{"f":"path:/rest/applinks/1.0/manifest.body","r":"<typeId>crowd</typeId>"}],"n":"Atlassian Crowd","c":"Identity","v":"{1}","p":"cpe:2.3:a:atlassian:crowd:{v}","k":100},
{"id":"b:p-oidc","f":"path:/.well-known/openid-configuration.body","r":"\"issuer\"\\s*:\\s*\"[^\"]+\"","n":"OpenID Connect provider","c":"Identity","k":90},
{"id":"b:p-oidc-kc","f":"path:/.well-known/openid-configuration.body","r":"\"issuer\"\\s*:\\s*\"[^\"]*/realms/","n":"Keycloak","c":"Identity","k":90,"p":"cpe:2.3:a:redhat:keycloak:{v}"},
{"id":"b:p-oidc-adfs","f":"path:/.well-known/openid-configuration.body","r":"\"issuer\"\\s*:\\s*\"[^\"]*/adfs","o":"i","n":"Microsoft AD FS","c":"Identity","k":95},
{"id":"b:p-tomcatmgr","f":"path:/manager/html.auth","r":"realm=\"Tomcat Manager Application\"","n":"Apache Tomcat Manager","c":"Admin panel","im":["Apache Tomcat"],"k":100,"flag":"MgmtInterface"},
{"id":"b:p-registry","f":"path:/v2/.header:docker-distribution-api-version","r":"registry/","n":"Docker Registry","c":"Container platform","k":100},
{"id":"b:ntlm-5-0-2195","f":"ntlm.version","r":"^5\\.0\\.2195$","out":[{"t":"os","n":"Microsoft Windows 2000","c":"OS","k":90}],"ex":"5.0.2195"},
{"id":"b:ntlm-5-1-2600","f":"ntlm.version","r":"^5\\.1\\.2600$","out":[{"t":"os","n":"Microsoft Windows XP","c":"OS","k":90}],"ex":"5.1.2600"},
{"id":"b:ntlm-5-2-3790","f":"ntlm.version","r":"^5\\.2\\.3790$","out":[{"t":"os","n":"Microsoft Windows Server 2003","c":"OS","k":90}],"ex":"5.2.3790"},
{"id":"b:ntlm-6-0-6000","f":"ntlm.version","r":"^6\\.0\\.6000$","out":[{"t":"os","n":"Microsoft Windows Vista","c":"OS","k":90}],"ex":"6.0.6000"},
{"id":"b:ntlm-6-0-6001","f":"ntlm.version","r":"^6\\.0\\.6001$","out":[{"t":"os","n":"Microsoft Windows Vista SP1 / Server 2008","c":"OS","k":90}],"ex":"6.0.6001"},
{"id":"b:ntlm-6-0-6002","f":"ntlm.version","r":"^6\\.0\\.6002$","out":[{"t":"os","n":"Microsoft Windows Vista SP2 / Server 2008 SP2","c":"OS","k":90}],"ex":"6.0.6002"},
{"id":"b:ntlm-6-1-7600","f":"ntlm.version","r":"^6\\.1\\.7600$","out":[{"t":"os","n":"Microsoft Windows 7 / Server 2008 R2","c":"OS","k":90}],"ex":"6.1.7600"},
{"id":"b:ntlm-6-1-7601","f":"ntlm.version","r":"^6\\.1\\.7601$","out":[{"t":"os","n":"Microsoft Windows 7 SP1 / Server 2008 R2 SP1","c":"OS","k":90}],"ex":"6.1.7601"},
{"id":"b:ntlm-6-2-9200","f":"ntlm.version","r":"^6\\.2\\.9200$","out":[{"t":"os","n":"Microsoft Windows 8 / Server 2012","c":"OS","k":90}],"ex":"6.2.9200"},
{"id":"b:ntlm-6-3-9600","f":"ntlm.version","r":"^6\\.3\\.9600$","out":[{"t":"os","n":"Microsoft Windows 8.1 / Server 2012 R2","c":"OS","k":90}],"ex":"6.3.9600"},
{"id":"b:ntlm-10-0-10240","f":"ntlm.version","r":"^10\\.0\\.10240$","out":[{"t":"os","n":"Microsoft Windows 10 1507","c":"OS","k":90}],"ex":"10.0.10240"},
{"id":"b:ntlm-10-0-10586","f":"ntlm.version","r":"^10\\.0\\.10586$","out":[{"t":"os","n":"Microsoft Windows 10 1511","c":"OS","k":90}],"ex":"10.0.10586"},
{"id":"b:ntlm-10-0-14393","f":"ntlm.version","r":"^10\\.0\\.14393$","out":[{"t":"os","n":"Microsoft Windows 10 1607 / Server 2016","c":"OS","k":90}],"ex":"10.0.14393"},
{"id":"b:ntlm-10-0-15063","f":"ntlm.version","r":"^10\\.0\\.15063$","out":[{"t":"os","n":"Microsoft Windows 10 1703","c":"OS","k":90}],"ex":"10.0.15063"},
{"id":"b:ntlm-10-0-16299","f":"ntlm.version","r":"^10\\.0\\.16299$","out":[{"t":"os","n":"Microsoft Windows 10 1709 / Server 1709","c":"OS","k":90}],"ex":"10.0.16299"},
{"id":"b:ntlm-10-0-17134","f":"ntlm.version","r":"^10\\.0\\.17134$","out":[{"t":"os","n":"Microsoft Windows 10 1803 / Server 1803","c":"OS","k":90}],"ex":"10.0.17134"},
{"id":"b:ntlm-10-0-17763","f":"ntlm.version","r":"^10\\.0\\.17763$","out":[{"t":"os","n":"Microsoft Windows 10 1809 / Server 2019","c":"OS","k":90}],"ex":"10.0.17763"},
{"id":"b:ntlm-10-0-18362","f":"ntlm.version","r":"^10\\.0\\.18362$","out":[{"t":"os","n":"Microsoft Windows 10 1903","c":"OS","k":90}],"ex":"10.0.18362"},
{"id":"b:ntlm-10-0-18363","f":"ntlm.version","r":"^10\\.0\\.18363$","out":[{"t":"os","n":"Microsoft Windows 10 1909 / Server 1909","c":"OS","k":90}],"ex":"10.0.18363"},
{"id":"b:ntlm-10-0-19041","f":"ntlm.version","r":"^10\\.0\\.19041$","out":[{"t":"os","n":"Microsoft Windows 10 2004 / Server 2004","c":"OS","k":90}],"ex":"10.0.19041"},
{"id":"b:ntlm-10-0-19042","f":"ntlm.version","r":"^10\\.0\\.19042$","out":[{"t":"os","n":"Microsoft Windows 10 20H2 / Server 20H2","c":"OS","k":90}],"ex":"10.0.19042"},
{"id":"b:ntlm-10-0-19043","f":"ntlm.version","r":"^10\\.0\\.19043$","out":[{"t":"os","n":"Microsoft Windows 10 21H1","c":"OS","k":90}],"ex":"10.0.19043"},
{"id":"b:ntlm-10-0-19044","f":"ntlm.version","r":"^10\\.0\\.19044$","out":[{"t":"os","n":"Microsoft Windows 10 21H2","c":"OS","k":90}],"ex":"10.0.19044"},
{"id":"b:ntlm-10-0-19045","f":"ntlm.version","r":"^10\\.0\\.19045$","out":[{"t":"os","n":"Microsoft Windows 10 22H2","c":"OS","k":90}],"ex":"10.0.19045"},
{"id":"b:ntlm-10-0-20348","f":"ntlm.version","r":"^10\\.0\\.20348$","out":[{"t":"os","n":"Microsoft Windows Server 2022","c":"OS","k":90}],"ex":"10.0.20348"},
{"id":"b:ntlm-10-0-22000","f":"ntlm.version","r":"^10\\.0\\.22000$","out":[{"t":"os","n":"Microsoft Windows 11 21H2","c":"OS","k":90}],"ex":"10.0.22000"},
{"id":"b:ntlm-10-0-22621","f":"ntlm.version","r":"^10\\.0\\.22621$","out":[{"t":"os","n":"Microsoft Windows 11 22H2","c":"OS","k":90}],"ex":"10.0.22621"},
{"id":"b:ntlm-10-0-22631","f":"ntlm.version","r":"^10\\.0\\.22631$","out":[{"t":"os","n":"Microsoft Windows 11 23H2","c":"OS","k":90}],"ex":"10.0.22631"},
{"id":"b:ntlm-10-0-25398","f":"ntlm.version","r":"^10\\.0\\.25398$","out":[{"t":"os","n":"Microsoft Windows Server 23H2","c":"OS","k":90}],"ex":"10.0.25398"},
{"id":"b:ntlm-10-0-26100","f":"ntlm.version","r":"^10\\.0\\.26100$","out":[{"t":"os","n":"Microsoft Windows 11 24H2 / Server 2025","c":"OS","k":90}],"ex":"10.0.26100"},
{"id":"b:ntlm-10-0-26200","f":"ntlm.version","r":"^10\\.0\\.26200$","out":[{"t":"os","n":"Microsoft Windows 11 25H2","c":"OS","k":90}],"ex":"10.0.26200"},
{"id":"b:ntlm-windows","f":"ntlm.version","r":"^(?!(?:5\\.0\\.2195|5\\.1\\.2600|5\\.2\\.3790|6\\.0\\.6000|6\\.0\\.6001|6\\.0\\.6002|6\\.1\\.7600|6\\.1\\.7601|6\\.2\\.9200|6\\.3\\.9600|10\\.0\\.10240|10\\.0\\.10586|10\\.0\\.14393|10\\.0\\.15063|10\\.0\\.16299|10\\.0\\.17134|10\\.0\\.17763|10\\.0\\.18362|10\\.0\\.18363|10\\.0\\.19041|10\\.0\\.19042|10\\.0\\.19043|10\\.0\\.19044|10\\.0\\.19045|10\\.0\\.20348|10\\.0\\.22000|10\\.0\\.22621|10\\.0\\.22631|10\\.0\\.25398|10\\.0\\.26100|10\\.0\\.26200)$)((?:5|6|10)\\.\\d\\.\\d{4,5})$","out":[{"t":"os","n":"Microsoft Windows","c":"OS","v":"{1}","k":70}],"ex":"10.0.27000","exv":"10.0.27000"},
{"id":"b:snmp-cisco-ios","f":"snmp.sysdescr","r":"Cisco IOS Software.*?Version ([\\w.()]+)","out":[{"t":"os","n":"Cisco IOS","c":"OS","v":"{1}","p":"cpe:2.3:o:cisco:ios:{v}","k":90}],"ex":"Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8, RELEASE SOFTWARE (fc1)","exv":"15.2(7)E8"},
{"id":"b:snmp-cisco-iosxe","f":"snmp.sysdescr","r":"Cisco IOS[ -]XE Software.*?Version ([\\w.()]+)","out":[{"t":"os","n":"Cisco IOS XE","c":"OS","v":"{1}","p":"cpe:2.3:o:cisco:ios_xe:{v}","k":90}],"ex":"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc5) Cisco IOS-XE Software, Version 17.09.04a","exv":"17.09.04a"},
{"id":"b:snmp-windows","f":"snmp.sysdescr","r":"^Hardware: .*Software: Windows Version (\\d+\\.\\d+) \\(Build (\\d+)","out":[{"t":"os","n":"Microsoft Windows","c":"OS","v":"{1}.{2}","k":85}],"ex":"Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)","exv":"6.3.17763"},
{"id":"b:snmp-linux","f":"snmp.sysdescr","r":"^Linux \\S+ (\\d+\\.\\d+[\\w.\\-+]*)","out":[{"t":"os","n":"Linux","c":"OS","v":"{1}","p":"cpe:2.3:o:linux:linux_kernel:{v}","k":80}],"ex":"Linux nas01 5.10.60+ #1 SMP Tue Jan 1 00:00:00 UTC 2024 x86_64","exv":"5.10.60+"},
{"id":"b:snmp-junos","f":"snmp.sysdescr","r":"Juniper Networks, Inc\\. (\\S+) .*JUNOS (\\d[\\w.\\-]+)","out":[{"t":"os","n":"Juniper Junos OS","c":"OS","v":"{2}","p":"cpe:2.3:o:juniper:junos:{v}","k":90},{"t":"hw","n":"Juniper {1}","c":"Network device","k":85}],"ex":"Juniper Networks, Inc. ex4300-48p Ethernet Switch, kernel JUNOS 21.4R3-S5.4, Build date: 2023-06-01","exv":"21.4R3-S5.4"}
]}
'@
# Reviewed NVD CPE names: completes rule CPEs when a Recog/Wappalyzer pack is imported (fill/replace) and tells the
# offline vulnerability join which NVD names denote the same product (aliases). Data only; see THIRD-PARTY-NOTICES.
$CpeSupplementJson = @'
{"name":"cpe-supplement","version":"2026.11.06",
"source":"Product names from the built-in, Recog and Wappalyzer rules mapped to NVD CPE names, checked against the NVD CPE Dictionary 2.0 feed (lastModified 2026-11-04T23:50:02-05:00, sha256 af94a9dbb31583557931b5e3740fe76394ad3fe102934497265218acfb58c4bd) and reviewed by hand",
"notice":"This product uses data from the NVD API but is not endorsed or certified by the NVD.",
"fill":[
{"t":"service","n":"a-blog cms","p":"cpe:2.3:a:appleple:a-blog_cms:{v}"},
{"t":"service","n":"AbanteCart","p":"cpe:2.3:a:abantecart:abantecart:{v}"},
{"t":"service","n":"AddToAny Share Buttons","p":"cpe:2.3:a:addtoany:addtoany_share_buttons:{v}"},
{"t":"service","n":"AdGuard Home","p":"cpe:2.3:a:adguard:adguardhome:{v}"},
{"t":"service","n":"Adminer","p":"cpe:2.3:a:adminer:adminer:{v}"},
{"t":"service","n":"Advanced Custom Fields","p":"cpe:2.3:a:advancedcustomfields:advanced_custom_fields:{v}"},
{"t":"service","n":"Akismet","p":"cpe:2.3:a:automattic:akismet:{v}"},
{"t":"service","n":"Allegro Software RomPager","p":"cpe:2.3:a:allegrosoft:rompager:{v}"},
{"t":"service","n":"Amiro.CMS","p":"cpe:2.3:a:amiro:amiro.cms:{v}"},
{"t":"service","n":"Ampache","p":"cpe:2.3:a:ampache:ampache:{v}"},
{"t":"service","n":"Angular","p":"cpe:2.3:a:angular:angular:{v}"},
{"t":"service","n":"Animate It","p":"cpe:2.3:a:eleopard:animate_it\\!:{v}"},
{"t":"service","n":"Apache APISIX","p":"cpe:2.3:a:apache:apisix:{v}"},
{"t":"service","n":"AquilaCMS","p":"cpe:2.3:a:aquila-cms:aquilacms:{v}"},
{"t":"os","n":"Arista EOS","p":"cpe:2.3:o:arista:eos:{v}"},
{"t":"os","n":"Aruba AOS-10","p":"cpe:2.3:o:arubanetworks:arubaos:{v}"},
{"t":"os","n":"Aruba AOS-8","p":"cpe:2.3:o:arubanetworks:arubaos:{v}"},
{"t":"service","n":"Asgaros Forum","p":"cpe:2.3:a:asgaros:asgaros_forum:{v}"},
{"t":"service","n":"ASP.NET Core","p":"cpe:2.3:a:microsoft:asp.net_core:{v}"},
{"t":"service","n":"ASP.NET MVC","p":"cpe:2.3:a:microsoft:asp.net_model_view_controller:{v}"},
{"t":"service","n":"Astra","p":"cpe:2.3:a:brainstormforce:astra:{v}"},
{"t":"service","n":"Astro","p":"cpe:2.3:a:astro:astro:{v}"},
{"t":"service","n":"Atlassian Bamboo","p":"cpe:2.3:a:atlassian:bamboo:{v}"},
{"t":"service","n":"Atlassian Confluence","p":"cpe:2.3:a:atlassian:confluence_server:{v}"},
{"t":"service","n":"Atlassian Crowd","p":"cpe:2.3:a:atlassian:crowd:{v}"},
{"t":"service","n":"Atlassian Jira","p":"cpe:2.3:a:atlassian:jira:{v}"},
{"t":"service","n":"Auberge","p":"cpe:2.3:a:webmandesign:auberge_theme:{v}"},
{"t":"service","n":"Aurelia","p":"cpe:2.3:a:bluespire:aurelia_framework:{v}"},
{"t":"service","n":"Auth0 Lock","p":"cpe:2.3:a:auth0:lock:{v}"},
{"t":"service","n":"Autoptimize","p":"cpe:2.3:a:autoptimize:autoptimize:{v}"},
{"t":"service","n":"Azuriom","p":"cpe:2.3:a:azuriom:azuriom:{v}"},
{"t":"service","n":"Bagisto","p":"cpe:2.3:a:webkul:bagisto:{v}"},
{"t":"service","n":"Barracuda WAF","p":"cpe:2.3:a:barracuda:web_application_firewall:{v}"},
{"t":"service","n":"Batflat","p":"cpe:2.3:a:batflat:batflat:{v}"},
{"t":"service","n":"BeTheme","p":"cpe:2.3:a:muffingroup:betheme:{v}"},
{"t":"service","n":"Bitweaver","p":"cpe:2.3:a:bitweaver:bitweaver:{v}"},
{"t":"service","n":"Blesta","p":"cpe:2.3:a:phillipsdata:blesta:{v}"},
{"t":"service","n":"Blocksy","p":"cpe:2.3:a:creativethemes:blocksy:{v}"},
{"t":"service","n":"Blocksy Companion","p":"cpe:2.3:a:creativethemes:blocksy_companion:{v}"},
{"t":"service","n":"Bludit","p":"cpe:2.3:a:bludit:bludit:{v}"},
{"t":"service","n":"Boa","p":"cpe:2.3:a:boa:boa:{v}"},
{"t":"service","n":"BoidCMS","p":"cpe:2.3:a:boidcms:boidcms:{v}"},
{"t":"service","n":"Bold Page Builder","p":"cpe:2.3:a:bold-themes:bold_page_builder:{v}"},
{"t":"service","n":"Bookly","p":"cpe:2.3:a:booking-wp-plugin:bookly:{v}"},
{"t":"service","n":"Bootbox.js","p":"cpe:2.3:a:bootboxjs:bootbox:{v}"},
{"t":"service","n":"Bootstrap","p":"cpe:2.3:a:getbootstrap:bootstrap:{v}"},
{"t":"service","n":"Bootstrap Table","p":"cpe:2.3:a:bootstrap-table:bootstrap_table:{v}"},
{"t":"service","n":"Bricks","p":"cpe:2.3:a:bricksbuilder:bricks:{v}"},
{"t":"service","n":"Brizy WordPress","p":"cpe:2.3:a:brizy:brizy:{v}"},
{"t":"service","n":"Broadcom SiteMinder","p":"cpe:2.3:a:broadcom:siteminder:{v}"},
{"t":"service","n":"Bugzilla","p":"cpe:2.3:a:mozilla:bugzilla:{v}"},
{"t":"service","n":"Burst","p":"cpe:2.3:a:burst-statistics:burst_statistics:{v}"},
{"t":"service","n":"CakePHP","p":"cpe:2.3:a:cakephp:cakephp:{v}"},
{"t":"service","n":"Caldera Forms","p":"cpe:2.3:a:calderaforms:caldera_forms:{v}"},
{"t":"service","n":"Carnegie Mellon University Cyrus POP","p":"cpe:2.3:a:cmu:cyrus_imap_server:{v}"},
{"t":"service","n":"Caucho Resin","p":"cpe:2.3:a:caucho:resin:{v}"},
{"t":"service","n":"cgit","p":"cpe:2.3:a:lars_hjemli:cgit:{v}"},
{"t":"service","n":"Check Point Gaia","p":"cpe:2.3:o:checkpoint:gaia_os:{v}"},
{"t":"service","n":"Checkmk","p":"cpe:2.3:a:checkmk:checkmk:{v}"},
{"t":"service","n":"CherryPy","p":"cpe:2.3:a:cherrypy:cherrypy:{v}"},
{"t":"service","n":"Chosen","p":"cpe:2.3:a:getharvest:chosen:{v}"},
{"t":"os","n":"Cisco Adaptive Security Appliance","p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:{v}"},
{"t":"service","n":"Cisco ASA","p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:{v}"},
{"t":"os","n":"Cisco Firepower Threat Defense","p":"cpe:2.3:a:cisco:secure_firewall_threat_defense:{v}"},
{"t":"hw","n":"Cisco IMC","p":"cpe:2.3:a:cisco:integrated_management_controller:{v}"},
{"t":"os","n":"Cisco IMC","p":"cpe:2.3:a:cisco:integrated_management_controller:{v}"},
{"t":"service","n":"Cisco IMC","p":"cpe:2.3:a:cisco:integrated_management_controller:{v}"},
{"t":"service","n":"Cisco IOS","p":"cpe:2.3:o:cisco:ios:{v}"},
{"t":"os","n":"Cisco IOS-XE","p":"cpe:2.3:o:cisco:ios_xe:{v}"},
{"t":"os","n":"Cisco IOS-XR","p":"cpe:2.3:o:cisco:ios_xr:{v}"},
{"t":"service","n":"Cisco Unified Communications Manager","p":"cpe:2.3:a:cisco:unified_communications_manager:{v}"},
{"t":"service","n":"Citrix Gateway","p":"cpe:2.3:a:citrix:netscaler_gateway:{v}"},
{"t":"service","n":"Citrix Hypervisor","p":"cpe:2.3:o:citrix:hypervisor:{v}"},
{"t":"service","n":"Citrix NetScaler ADC","p":"cpe:2.3:a:citrix:netscaler_application_delivery_controller:{v}"},
{"t":"service","n":"Citrix StoreFront","p":"cpe:2.3:a:citrix:storefront_server:{v}"},
{"t":"service","n":"Ckan","p":"cpe:2.3:a:okfn:ckan:{v}"},
{"t":"service","n":"CodeIgniter","p":"cpe:2.3:a:codeigniter:codeigniter:{v}"},
{"t":"service","n":"Colorlib Activello","p":"cpe:2.3:a:colorlib:activello:{v}"},
{"t":"service","n":"Colorlib Illdy","p":"cpe:2.3:a:colorlib:illdy:{v}"},
{"t":"service","n":"Colorlib Shapely","p":"cpe:2.3:a:colorlib:shapely:{v}"},
{"t":"service","n":"ColorMag","p":"cpe:2.3:a:themegrill:colormag:{v}"},
{"t":"service","n":"CometD","p":"cpe:2.3:a:cometd:cometd:{v}"},
{"t":"service","n":"Complianz","p":"cpe:2.3:a:really-simple-plugins:complianz:{v}"},
{"t":"service","n":"Composite Products","p":"cpe:2.3:a:woocommerce:composite_products:{v}"},
{"t":"service","n":"Contact Form 7","p":"cpe:2.3:a:rocklobster:contact_form_7:{v}"},
{"t":"service","n":"Contensis","p":"cpe:2.3:a:zengenti:contensis:{v}"},
{"t":"service","n":"ContentViews","p":"cpe:2.3:a:contentviewspro:content_views:{v}"},
{"t":"service","n":"Covenant","p":"cpe:2.3:a:cobbr:covenant:{v}"},
{"t":"service","n":"Craft Commerce","p":"cpe:2.3:a:craftcms:craft_commerce:{v}"},
{"t":"service","n":"Crayon Syntax Highlighter","p":"cpe:2.3:a:crayon_syntax_highlighter_project:crayon_syntax_highlighter:{v}"},
{"t":"service","n":"Creativ.eMail","p":"cpe:2.3:a:constantcontact:creative_mail:{v}"},
{"t":"service","n":"Croogo","p":"cpe:2.3:a:croogo:croogo:{v}"},
{"t":"service","n":"Cryout Creations Fluida","p":"cpe:2.3:a:cryoutcreations:fluida:{v}"},
{"t":"service","n":"Cryout Creations Mantra","p":"cpe:2.3:a:cryoutcreations:mantra:{v}"},
{"t":"service","n":"Cryout Creations Parabola","p":"cpe:2.3:a:cryoutcreations:parabola:{v}"},
{"t":"service","n":"crypto-js","p":"cpe:2.3:a:crypto-js_project:crypto-js:{v}"},
{"t":"service","n":"CS Cart","p":"cpe:2.3:a:cs-cart:cs-cart:{v}"},
{"t":"service","n":"Custom Fonts","p":"cpe:2.3:a:brainstormforce:custom_fonts:{v}"},
{"t":"service","n":"Custom Twitter Feeds","p":"cpe:2.3:a:smashballoon:custom_twitter_feeds:{v}"},
{"t":"service","n":"CyberChimps Responsive","p":"cpe:2.3:a:cyberchimps:responsive:{v}"},
{"t":"service","n":"Danneo CMS","p":"cpe:2.3:a:danneo:danneo_cms:{v}"},
{"t":"service","n":"Daphne","p":"cpe:2.3:a:djangoproject:daphne:{v}"},
{"t":"service","n":"Delinea Secret Server","p":"cpe:2.3:a:delinea:secret_server:{v}"},
{"t":"service","n":"DESTOON","p":"cpe:2.3:a:destoon:destoon_b2b:{v}"},
{"t":"service","n":"Dexie.js","p":"cpe:2.3:a:dexie:dexie:{v}"},
{"t":"service","n":"Discuz! X","p":"cpe:2.3:a:discuz:discuzx:{v}"},
{"t":"service","n":"Django","p":"cpe:2.3:a:djangoproject:django:{v}"},
{"t":"service","n":"Django CMS","p":"cpe:2.3:a:django-cms:django_cms:{v}"},
{"t":"service","n":"DokuWiki","p":"cpe:2.3:a:dokuwiki:dokuwiki:{v}"},
{"t":"service","n":"Download Monitor","p":"cpe:2.3:a:wpchill:download_monitor:{v}"},
{"t":"service","n":"Drupal","p":"cpe:2.3:a:drupal:drupal:{v}"},
{"t":"service","n":"DSpace","p":"cpe:2.3:a:duraspace:dspace:{v}"},
{"t":"service","n":"Easy Accordion","p":"cpe:2.3:a:techearty:easy_accordion:{v}"},
{"t":"service","n":"EasyDigitalDownloads","p":"cpe:2.3:a:awesomemotive:easy_digital_downloads:{v}"},
{"t":"service","n":"ECharts","p":"cpe:2.3:a:apache:echarts:{v}"},
{"t":"service","n":"eDirectory","p":"cpe:2.3:a:arcasolutions:edirectory:{v}"},
{"t":"service","n":"Edwiser Bridge","p":"cpe:2.3:a:edwiser:bridge:{v}"},
{"t":"service","n":"Elastic Search","p":"cpe:2.3:a:elastic:elasticsearch:{v}"},
{"t":"service","n":"Elcom","p":"cpe:2.3:a:elcom:elcom_cms:{v}"},
{"t":"service","n":"Elementor","p":"cpe:2.3:a:elementor:website_builder:{v}"},
{"t":"service","n":"Elementor Addon Elements","p":"cpe:2.3:a:webtechstreet:elementor_addon_elements:{v}"},
{"t":"service","n":"ELOG","p":"cpe:2.3:a:elog_project:elog:{v}"},
{"t":"service","n":"Email Encoder for Wordpress","p":"cpe:2.3:a:onlineoptimisation:email_encoder:{v}"},
{"t":"service","n":"Embed Any Document","p":"cpe:2.3:a:awsm:embed_any_document:{v}"},
{"t":"service","n":"EmbedPress","p":"cpe:2.3:a:wpdeveloper:embedpress:{v}"},
{"t":"service","n":"Embedthis Appweb","p":"cpe:2.3:a:embedthis:appweb:{v}"},
{"t":"service","n":"EPrints","p":"cpe:2.3:a:eprints:eprints:{v}"},
{"t":"service","n":"Erxes","p":"cpe:2.3:a:erxes:erxes:{v}"},
{"t":"service","n":"Essential Addons for Elementor","p":"cpe:2.3:a:wpdeveloper:essential_addons_for_elementor:{v}"},
{"t":"service","n":"Essential Blocks","p":"cpe:2.3:a:wpdeveloper:essential_blocks:{v}"},
{"t":"service","n":"eSyndiCat","p":"cpe:2.3:a:intelliants:esyndicat:{v}"},
{"t":"service","n":"Etherpad","p":"cpe:2.3:a:etherpad:etherpad:{v}"},
{"t":"service","n":"EWWW Image Optimizer","p":"cpe:2.3:a:ewww:image_optimizer:{v}"},
{"t":"service","n":"ExactMetrics","p":"cpe:2.3:a:monsterinsights:exactmetrics:{v}"},
{"t":"service","n":"Express","p":"cpe:2.3:a:expressjs:express:{v}"},
{"t":"service","n":"ExtendThemes Calliope","p":"cpe:2.3:a:extendthemes:calliope:{v}"},
{"t":"service","n":"ExtendThemes EmpowerWP","p":"cpe:2.3:a:extendthemes:empowerwp:{v}"},
{"t":"service","n":"ExtendThemes Materialis","p":"cpe:2.3:a:extendthemes:materialis:{v}"},
{"t":"service","n":"ExtendThemes Mesmerize","p":"cpe:2.3:a:extendthemes:mesmerize:{v}"},
{"t":"os","n":"Extreme Networks XOS","p":"cpe:2.3:o:extremenetworks:extremexos:{v}"},
{"t":"service","n":"EyouCMS","p":"cpe:2.3:a:eyoucms:eyoucms:{v}"},
{"t":"service","n":"F5 Advanced WAF (ASM)","p":"cpe:2.3:a:f5:big-ip_application_security_manager:{v}"},
{"t":"service","n":"F5 BIG-IP","p":"cpe:2.3:a:f5:big-ip_local_traffic_manager:{v}"},
{"t":"service","n":"F5 BIG-IP APM","p":"cpe:2.3:a:f5:big-ip_access_policy_manager:{v}"},
{"t":"service","n":"Faveo","p":"cpe:2.3:a:ladybirdweb:faveo_helpdesk:{v}"},
{"t":"service","n":"Firefly Media Server","p":"cpe:2.3:a:fireflymediaserver:firefly_media_server:{v}"},
{"t":"service","n":"Flyspray","p":"cpe:2.3:a:flyspray:flyspray:{v}"},
{"t":"service","n":"Forgejo","p":"cpe:2.3:a:forgejo:forgejo:{v}"},
{"t":"service","n":"Fortinet FortiOS","p":"cpe:2.3:o:fortinet:fortios:{v}"},
{"t":"service","n":"frp","p":"cpe:2.3:a:fatedier:frp:{v}"},
{"t":"service","n":"Gallery","p":"cpe:2.3:a:menalto:gallery:{v}"},
{"t":"service","n":"Gambio","p":"cpe:2.3:a:gambio:gambio:{v}"},
{"t":"service","n":"GDPR Cookie Consent Plugin by Webtoffee","p":"cpe:2.3:a:webtoffee:gdpr_cookie_consent:{v}"},
{"t":"service","n":"GeneratePress","p":"cpe:2.3:a:generatepress:generatepress:{v}"},
{"t":"service","n":"Genesis blocks","p":"cpe:2.3:a:wpengine:genesis_blocks:{v}"},
{"t":"service","n":"Gerrit","p":"cpe:2.3:a:google:gerrit:{v}"},
{"t":"service","n":"GFI Kerio Connect","p":"cpe:2.3:a:gfi:kerio_connect:{v}"},
{"t":"service","n":"Ghost","p":"cpe:2.3:a:ghost:ghost:{v}"},
{"t":"service","n":"GiveWP","p":"cpe:2.3:a:givewp:givewp:{v}"},
{"t":"service","n":"GoAhead","p":"cpe:2.3:a:embedthis:goahead:{v}"},
{"t":"service","n":"GoAnywhere","p":"cpe:2.3:a:fortra:goanywhere_managed_file_transfer:{v}"},
{"t":"service","n":"GoDaddy CoBlocks","p":"cpe:2.3:a:godaddy:coblocks:{v}"},
{"t":"service","n":"Gogs","p":"cpe:2.3:a:gogs:gogs:{v}"},
{"t":"service","n":"Google Tag Manager for WordPress","p":"cpe:2.3:a:gtm4wp:google_tag_manager:{v}"},
{"t":"service","n":"GPT AI Power","p":"cpe:2.3:a:gptaipower:gpt_ai_power:{v}"},
{"t":"service","n":"GrandNode","p":"cpe:2.3:a:grandnode:grandnode:{v}"},
{"t":"service","n":"Gravity Forms","p":"cpe:2.3:a:rocketgenius:gravityforms:{v}"},
{"t":"service","n":"Graylog","p":"cpe:2.3:a:graylog:graylog:{v}"},
{"t":"service","n":"Greyd.Suite","p":"cpe:2.3:a:greyd:greyd.suite:{v}"},
{"t":"service","n":"GuppY","p":"cpe:2.3:a:freeguppy:guppy:{v}"},
{"t":"service","n":"Gutenberg","p":"cpe:2.3:a:wordpress:gutenberg:{v}"},
{"t":"service","n":"H2O","p":"cpe:2.3:a:dena:h2o:{v}"},
{"t":"service","n":"h5ai","p":"cpe:2.3:a:h5ai_project:h5ai:{v}"},
{"t":"service","n":"Halo","p":"cpe:2.3:a:halo:halo:{v}"},
{"t":"service","n":"Handsontable","p":"cpe:2.3:a:handsontable:handsontable:{v}"},
{"t":"service","n":"HAProxy","p":"cpe:2.3:a:haproxy:haproxy:{v}"},
{"t":"service","n":"Harbor","p":"cpe:2.3:a:linuxfoundation:harbor:{v}"},
{"t":"service","n":"HashiCorp Consul","p":"cpe:2.3:a:hashicorp:consul:{v}"},
{"t":"service","n":"HashiCorp Nomad","p":"cpe:2.3:a:hashicorp:nomad:{v}"},
{"t":"service","n":"HashiCorp Vault","p":"cpe:2.3:a:hashicorp:vault:{v}"},
{"t":"service","n":"HashThemes Total","p":"cpe:2.3:a:hashthemes:total:{v}"},
{"t":"service","n":"HCL Commerce","p":"cpe:2.3:a:hcltechsw:hcl_commerce:{v}"},
{"t":"service","n":"Hiawatha","p":"cpe:2.3:a:hiawatha-webserver:hiawatha:{v}"},
{"t":"service","n":"Highlight.js","p":"cpe:2.3:a:highlightjs:highlight.js:{v}"},
{"t":"service","n":"HikaShop","p":"cpe:2.3:a:hikashop:hikashop:{v}"},
{"t":"os","n":"HipServ","p":"cpe:2.3:o:axentra:hipserv:{v}"},
{"t":"service","n":"Hono","p":"cpe:2.3:a:hono:hono:{v}"},
{"t":"service","n":"Hotaru CMS","p":"cpe:2.3:a:hotarucms:hotarucms:{v}"},
{"t":"service","n":"HP iLO","p":"cpe:2.3:h:hp:integrated_lights-out:{v}"},
{"t":"service","n":"HT Mega","p":"cpe:2.3:a:hasthemes:ht_mega:{v}"},
{"t":"service","n":"Hugo","p":"cpe:2.3:a:gohugo:hugo:{v}"},
{"t":"service","n":"IBM DataPower Gateway","p":"cpe:2.3:a:ibm:datapower_gateway:{v}"},
{"t":"service","n":"IBM HTTPD","p":"cpe:2.3:a:ibm:http_server:{v}"},
{"t":"service","n":"IBM Security Verify Access (WebSEAL)","p":"cpe:2.3:a:ibm:security_verify_access:{v}"},
{"t":"os","n":"IBM VIOS","p":"cpe:2.3:o:ibm:vios:{v}"},
{"t":"service","n":"Icegram","p":"cpe:2.3:a:icegram:icegram_engage:{v}"},
{"t":"service","n":"Icinga Web","p":"cpe:2.3:a:icinga:icinga_web_2:{v}"},
{"t":"service","n":"Imagely NextGEN Gallery","p":"cpe:2.3:a:imagely:nextgen_gallery:{v}"},
{"t":"service","n":"Imunify360","p":"cpe:2.3:a:cloudlinux:imunify360:{v}"},
{"t":"service","n":"Indico","p":"cpe:2.3:a:cern:indico:{v}"},
{"t":"service","n":"Inductive Automation Ignition Gateway","p":"cpe:2.3:a:inductiveautomation:ignition_gateway:{v}"},
{"t":"service","n":"Intel(R) Active Management Technology","p":"cpe:2.3:o:intel:active_management_technology_firmware:{v}"},
{"t":"service","n":"Invision Community","p":"cpe:2.3:a:invisioncommunity:invisioncommunity:{v}"},
{"t":"service","n":"Invision Power Board","p":"cpe:2.3:a:invisioncommunity:invision_power_board:{v}"},
{"t":"service","n":"Istio","p":"cpe:2.3:a:istio:istio:{v}"},
{"t":"service","n":"iThemes Security","p":"cpe:2.3:a:ithemes:security:{v}"},
{"t":"service","n":"Ivory Search","p":"cpe:2.3:a:ivorysearch:ivory_search:{v}"},
{"t":"service","n":"Jekyll","p":"cpe:2.3:a:jekyllrb:jekyll:{v}"},
{"t":"service","n":"JetEngine","p":"cpe:2.3:a:crocoblock:jetengine:{v}"},
{"t":"service","n":"Jetpack","p":"cpe:2.3:a:automattic:jetpack:{v}"},
{"t":"service","n":"Jetpack Boost","p":"cpe:2.3:a:automattic:jetpack_boost:{v}"},
{"t":"service","n":"JFrog Artifactory","p":"cpe:2.3:a:jfrog:artifactory:{v}"},
{"t":"service","n":"Jive","p":"cpe:2.3:a:jivesoftware:jive:{v}"},
{"t":"service","n":"JobberBase","p":"cpe:2.3:a:jobberbase:jobberbase:{v}"},
{"t":"service","n":"Johnson Controls Metasys","p":"cpe:2.3:a:johnsoncontrols:metasys:{v}"},
{"t":"service","n":"Joomla","p":"cpe:2.3:a:joomla:joomla\\!:{v}"},
{"t":"service","n":"Joomla!","p":"cpe:2.3:a:joomla:joomla\\!:{v}"},
{"t":"service","n":"jPlayer","p":"cpe:2.3:a:happyworm:jplayer:{v}"},
{"t":"service","n":"jsPDF","p":"cpe:2.3:a:parall:jspdf:{v}"},
{"t":"service","n":"Juniper J-Web","p":"cpe:2.3:o:juniper:junos:{v}"},
{"t":"service","n":"Kadence WP Blocks","p":"cpe:2.3:a:kadencewp:gutenberg_blocks_with_ai:{v}"},
{"t":"service","n":"KaTeX","p":"cpe:2.3:a:katex:katex:{v}"},
{"t":"service","n":"Kendo UI","p":"cpe:2.3:a:progress:kendo_ui:{v}"},
{"t":"service","n":"Keycloak","p":"cpe:2.3:a:redhat:keycloak:{v}"},
{"t":"service","n":"Kong Gateway","p":"cpe:2.3:a:konghq:kong_gateway:{v}"},
{"t":"service","n":"Kubernetes","p":"cpe:2.3:a:kubernetes:kubernetes:{v}"},
{"t":"service","n":"Laravel","p":"cpe:2.3:a:laravel:laravel:{v}"},
{"t":"service","n":"Leaflet","p":"cpe:2.3:a:leafletjs:leaflet:{v}"},
{"t":"service","n":"Lenovo XClarity Controller","p":"cpe:2.3:a:lenovo:xclarity_controller:{v}"},
{"t":"service","n":"LibreNMS","p":"cpe:2.3:a:librenms:librenms:{v}"},
{"t":"service","n":"libupnp","p":"cpe:2.3:a:libupnp_project:libupnp:{v}"},
{"t":"service","n":"LifterLMS","p":"cpe:2.3:a:lifterlms:lifterlms:{v}"},
{"t":"service","n":"LimeSurvey","p":"cpe:2.3:a:limesurvey:limesurvey:{v}"},
{"t":"service","n":"LiteSpeed Cache","p":"cpe:2.3:a:litespeedtech:litespeed_cache:{v}"},
{"t":"service","n":"Litespeed Cache","p":"cpe:2.3:a:litespeedtech:litespeed_cache:{v}"},
{"t":"service","n":"LiteSpeed Web Server","p":"cpe:2.3:a:litespeedtech:litespeed_web_server:{v}"},
{"t":"service","n":"Livewire","p":"cpe:2.3:a:laravel:livewire:{v}"},
{"t":"service","n":"Lotus-Domino","p":"cpe:2.3:a:ibm:lotus_domino:{v}"},
{"t":"service","n":"lwIP","p":"cpe:2.3:a:lwip_project:lwip:{v}"},
{"t":"service","n":"Lychee","p":"cpe:2.3:a:lycheeorg:lychee:{v}"},
{"t":"service","n":"MachoThemes NewsMag","p":"cpe:2.3:a:machothemes:newsmag:{v}"},
{"t":"service","n":"Macromedia Breeze","p":"cpe:2.3:a:macromedia:breeze:{v}"},
{"t":"service","n":"Mahara","p":"cpe:2.3:a:mahara:mahara:{v}"},
{"t":"service","n":"MailChimp for WooCommerce","p":"cpe:2.3:a:mailchimp:mailchimp_for_woocommerce:{v}"},
{"t":"service","n":"Mailman","p":"cpe:2.3:a:gnu:mailman:{v}"},
{"t":"service","n":"MailOptin","p":"cpe:2.3:a:mailoptin:mailoptin:{v}"},
{"t":"service","n":"Mapbox.js","p":"cpe:2.3:a:mapbox:mapbox.js:{v}"},
{"t":"service","n":"MariaDB MaxScale","p":"cpe:2.3:a:mariadb:maxscale:{v}"},
{"t":"service","n":"Mastodon","p":"cpe:2.3:a:joinmastodon:mastodon:{v}"},
{"t":"service","n":"math.js","p":"cpe:2.3:a:mathjs:mathjs:{v}"},
{"t":"service","n":"Max Mega Menu","p":"cpe:2.3:a:megamenu:max_mega_menu:{v}"},
{"t":"service","n":"MaxSite CMS","p":"cpe:2.3:a:max-3000:maxsite_cms:{v}"},
{"t":"service","n":"Mbedthis Software Appweb","p":"cpe:2.3:a:embedthis:appweb:{v}"},
{"t":"service","n":"mdBook","p":"cpe:2.3:a:rust-lang:mdbook:{v}"},
{"t":"service","n":"Mercury Mail Transport System","p":"cpe:2.3:a:pmail:mercury_mail_transport_system:{v}"},
{"t":"service","n":"Mermaid","p":"cpe:2.3:a:mermaid_project:mermaid:{v}"},
{"t":"hw","n":"Mersive SolsticePod","p":"cpe:2.3:h:mersive:solstice_pod:{v}"},
{"t":"service","n":"Mesmerize Companion","p":"cpe:2.3:a:extendthemes:mesmerize_companion:{v}"},
{"t":"service","n":"MetaSlider","p":"cpe:2.3:a:matchalabs:metaslider:{v}"},
{"t":"service","n":"Meteor","p":"cpe:2.3:a:meteor:meteor:{v}"},
{"t":"service","n":"Microsoft Exchange Server","p":"cpe:2.3:a:microsoft:exchange_server:{v}"},
{"t":"service","n":"Microsoft SQL Server Reporting Services","p":"cpe:2.3:a:microsoft:sql_server_reporting_services:{v}"},
{"t":"os","n":"MikroTik RouterOS","p":"cpe:2.3:o:mikrotik:routeros:{v}"},
{"t":"service","n":"mini_httpd","p":"cpe:2.3:a:acme:mini_httpd:{v}"},
{"t":"service","n":"MiniDLNA","p":"cpe:2.3:a:minidlna_project:minidlna:{v}"},
{"t":"service","n":"MinIO","p":"cpe:2.3:a:minio:minio:{v}"},
{"t":"service","n":"MkDocs","p":"cpe:2.3:a:mkdocs:mkdocs:{v}"},
{"t":"service","n":"MLflow","p":"cpe:2.3:a:lfprojects:mlflow:{v}"},
{"t":"service","n":"mod_jk","p":"cpe:2.3:a:apache:tomcat_jk_connector:{v}"},
{"t":"service","n":"mod_ssl","p":"cpe:2.3:a:modssl:mod_ssl:{v}"},
{"t":"service","n":"MoinMoin","p":"cpe:2.3:a:moinmo:moinmoin:{v}"},
{"t":"service","n":"mongo-express","p":"cpe:2.3:a:mongo-express_project:mongo-express:{v}"},
{"t":"service","n":"Monkey HTTP Server","p":"cpe:2.3:a:monkey-project:monkey:{v}"},
{"t":"service","n":"Moodle","p":"cpe:2.3:a:moodle:moodle:{v}"},
{"t":"service","n":"MyCred","p":"cpe:2.3:a:wpexperts:mycred:{v}"},
{"t":"service","n":"n8n","p":"cpe:2.3:a:n8n:n8n:{v}"},
{"t":"service","n":"Nagios","p":"cpe:2.3:a:nagios:nagios:{v}"},
{"t":"service","n":"Nagios Log Server","p":"cpe:2.3:a:nagios:log_server:{v}"},
{"t":"service","n":"Nagios Network Analyzer","p":"cpe:2.3:a:nagios:network_analyzer:{v}"},
{"t":"service","n":"NcFTPd Server","p":"cpe:2.3:a:ncftp:ncftpd_server:{v}"},
{"t":"service","n":"Neos CMS","p":"cpe:2.3:a:neos:neos_cms:{v}"},
{"t":"service","n":"NetApp ONTAP","p":"cpe:2.3:a:netapp:ontap:{v}"},
{"t":"service","n":"Netdata","p":"cpe:2.3:a:netdata:netdata:{v}"},
{"t":"service","n":"Netgate pfSense","p":"cpe:2.3:a:netgate:pfsense:{v}"},
{"t":"service","n":"Next.js","p":"cpe:2.3:a:vercel:next.js:{v}"},
{"t":"service","n":"NextAuth.js","p":"cpe:2.3:a:nextauth.js:next-auth:{v}"},
{"t":"service","n":"Ninja Forms","p":"cpe:2.3:a:ninjaforms:ninja_forms:{v}"},
{"t":"service","n":"Node-RED","p":"cpe:2.3:a:nodered:node-red:{v}"},
{"t":"service","n":"Northstar Club Management","p":"cpe:2.3:a:globalnorthstar:northstar_club_management:{v}"},
{"t":"service","n":"Nucleus CMS","p":"cpe:2.3:a:nucleuscms:nucleus_cms:{v}"},
{"t":"service","n":"Nukeviet CMS","p":"cpe:2.3:a:nukeviet:nukeviet:{v}"},
{"t":"service","n":"Nuxt.js","p":"cpe:2.3:a:nuxt:nuxt:{v}"},
{"t":"os","n":"NVIDIA Onyx","p":"cpe:2.3:o:nvidia:onyx:{v}"},
{"t":"service","n":"Oat++","p":"cpe:2.3:a:oatpp:oat\\+\\+:{v}"},
{"t":"service","n":"Observium","p":"cpe:2.3:a:observium:observium:{v}"},
{"t":"service","n":"OceanWP","p":"cpe:2.3:a:oceanwp:oceanwp:{v}"},
{"t":"service","n":"October CMS","p":"cpe:2.3:a:octobercms:october:{v}"},
{"t":"service","n":"Octopus Deploy","p":"cpe:2.3:a:octopus:octopus_deploy:{v}"},
{"t":"service","n":"Odoo","p":"cpe:2.3:a:odoo:odoo:{v}"},
{"t":"service","n":"OpenGrok","p":"cpe:2.3:a:oracle:opengrok:{v}"},
{"t":"service","n":"OpenResty","p":"cpe:2.3:a:openresty:openresty:{v}"},
{"t":"service","n":"OpenUI5","p":"cpe:2.3:a:sap:openui5:{v}"},
{"t":"service","n":"OpenVPN Access Server","p":"cpe:2.3:a:openvpn:openvpn_access_server:{v}"},
{"t":"service","n":"OpenWrt LuCI","p":"cpe:2.3:a:openwrt:luci:{v}"},
{"t":"service","n":"OpnForm","p":"cpe:2.3:a:jhumanj:opnform:{v}"},
{"t":"service","n":"OptinMonster plugin","p":"cpe:2.3:a:optinmonster:optinmonster:{v}"},
{"t":"service","n":"Oracle Access Manager","p":"cpe:2.3:a:oracle:access_manager:{v}"},
{"t":"service","n":"Oracle Fusion Middleware","p":"cpe:2.3:a:oracle:fusion_middleware:{v}"},
{"t":"service","n":"Oracle PeopleSoft","p":"cpe:2.3:a:oracle:peoplesoft_enterprise_peopletools:{v}"},
{"t":"service","n":"Otter Blocks","p":"cpe:2.3:a:themeisle:otter_blocks:{v}"},
{"t":"service","n":"ownCloud","p":"cpe:2.3:a:owncloud:owncloud:{v}"},
{"t":"service","n":"OXID eShop","p":"cpe:2.3:a:oxid-esales:eshop:{v}"},
{"t":"service","n":"Oxygen","p":"cpe:2.3:a:soflyy:oxygen:{v}"},
{"t":"service","n":"PageLayer","p":"cpe:2.3:a:pagelayer:pagelayer:{v}"},
{"t":"service","n":"Palo Alto Networks PAN-OS","p":"cpe:2.3:o:paloaltonetworks:pan-os:{v}"},
{"t":"service","n":"Pannellum","p":"cpe:2.3:a:pannellum:pannellum:{v}"},
{"t":"service","n":"Parallels Plesk","p":"cpe:2.3:a:parallels:parallels_plesk_panel:{v}"},
{"t":"service","n":"Payara Server","p":"cpe:2.3:a:payara:payara:{v}"},
{"t":"service","n":"Payload CMS","p":"cpe:2.3:a:payloadcms:payload:{v}"},
{"t":"service","n":"pdfmake","p":"cpe:2.3:a:pdfmake:pdfmake:{v}"},
{"t":"service","n":"Peel","p":"cpe:2.3:a:peel:peel_shopping:{v}"},
{"t":"service","n":"PeerTube","p":"cpe:2.3:a:framasoft:peertube:{v}"},
{"t":"service","n":"Perfex CRM","p":"cpe:2.3:a:perfexcrm:perfex_crm:{v}"},
{"t":"service","n":"Perl","p":"cpe:2.3:a:perl:perl:{v}"},
{"t":"service","n":"pgAdmin","p":"cpe:2.3:a:pgadmin:pgadmin_4:{v}"},
{"t":"service","n":"Phabricator","p":"cpe:2.3:a:phacility:phabricator:{v}"},
{"t":"service","n":"Phlox","p":"cpe:2.3:a:averta:phlox:{v}"},
{"t":"service","n":"Phoenix","p":"cpe:2.3:a:phoenixframework:phoenix:{v}"},
{"t":"service","n":"Phoenix Cart","p":"cpe:2.3:a:phoenixcart:ce_phoenix_cart:{v}"},
{"t":"service","n":"Photo Gallery","p":"cpe:2.3:a:10web:photo_gallery:{v}"},
{"t":"service","n":"PHP","p":"cpe:2.3:a:php:php:{v}"},
{"t":"service","n":"phpwcms","p":"cpe:2.3:a:phpwcms:phpwcms:{v}"},
{"t":"service","n":"Phusion Passenger","p":"cpe:2.3:a:phusionpassenger:phusion_passenger:{v}"},
{"t":"service","n":"Plain Black WebGUI","p":"cpe:2.3:a:plainblack:webgui:{v}"},
{"t":"service","n":"Planet","p":"cpe:2.3:a:planet:planet:{v}"},
{"t":"service","n":"Plesk","p":"cpe:2.3:a:plesk:plesk:{v}"},
{"t":"service","n":"Plex Media Server","p":"cpe:2.3:a:plex:media_server:{v}"},
{"t":"service","n":"Pligg","p":"cpe:2.3:a:pligg:pligg_cms:{v}"},
{"t":"service","n":"Plone","p":"cpe:2.3:a:plone:plone:{v}"},
{"t":"service","n":"Poll Maker","p":"cpe:2.3:a:ays-pro:poll_maker:{v}"},
{"t":"service","n":"Popup Maker","p":"cpe:2.3:a:code-atlantic:popup_maker:{v}"},
{"t":"service","n":"Post Affiliate Pro","p":"cpe:2.3:a:qualityunit:post_affiliate_pro:{v}"},
{"t":"service","n":"Power BI Report Server","p":"cpe:2.3:a:microsoft:power_bi_report_server:{v}"},
{"t":"service","n":"Premio Chaty","p":"cpe:2.3:a:premio:chaty:{v}"},
{"t":"service","n":"Press Customizr","p":"cpe:2.3:a:presscustomizr:customizr:{v}"},
{"t":"service","n":"Press Hueman","p":"cpe:2.3:a:presscustomizr:hueman:{v}"},
{"t":"service","n":"prettyPhoto","p":"cpe:2.3:a:no-margin-for-errors:prettyphoto:{v}"},
{"t":"service","n":"Prism","p":"cpe:2.3:a:prismjs:prism:{v}"},
{"t":"service","n":"ProjectPier","p":"cpe:2.3:a:projectpier:projectpier:{v}"},
{"t":"service","n":"Prometheus","p":"cpe:2.3:a:prometheus:prometheus:{v}"},
{"t":"service","n":"Prometheus Alertmanager","p":"cpe:2.3:a:prometheus:alertmanager:{v}"},
{"t":"service","n":"PRTG Network Monitor","p":"cpe:2.3:a:paessler:prtg_network_monitor:{v}"},
{"t":"service","n":"Pterodactyl Panel","p":"cpe:2.3:a:pterodactyl:panel:{v}"},
{"t":"service","n":"Public CMS","p":"cpe:2.3:a:publiccms:publiccms:{v}"},
{"t":"service","n":"Pulse CMS","p":"cpe:2.3:a:pulsecms:pulse_cms:{v}"},
{"t":"os","n":"Pulse Connect Secure","p":"cpe:2.3:a:ivanti:connect_secure:{v}"},
{"t":"service","n":"Pulse Connect Secure","p":"cpe:2.3:a:ivanti:connect_secure:{v}"},
{"t":"service","n":"Puppet Enterprise","p":"cpe:2.3:a:puppet:puppet_enterprise:{v}"},
{"t":"service","n":"QNAP QTS","p":"cpe:2.3:o:qnap:qts:{v}"},
{"t":"service","n":"QTSS","p":"cpe:2.3:a:apple:quicktime_streaming_server:{v}"},
{"t":"service","n":"Qualcomm Qpopper","p":"cpe:2.3:a:qualcomm:qpopper:{v}"},
{"t":"service","n":"Quick.Cart","p":"cpe:2.3:a:opensolution:quick.cart:{v}"},
{"t":"service","n":"RafflePress","p":"cpe:2.3:a:seedprod:rafflepress:{v}"},
{"t":"service","n":"RainLoop","p":"cpe:2.3:a:rainloop:webmail:{v}"},
{"t":"service","n":"Rancher","p":"cpe:2.3:a:suse:rancher:{v}"},
{"t":"service","n":"Raneto","p":"cpe:2.3:a:raneto_project:raneto:{v}"},
{"t":"service","n":"RankMath SEO","p":"cpe:2.3:a:rankmath:seo:{v}"},
{"t":"service","n":"Rapid7 (NeXpose)","p":"cpe:2.3:a:rapid7:nexpose:{v}"},
{"t":"service","n":"Rapid7 Nexpose/InsightVM","p":"cpe:2.3:a:rapid7:nexpose:{v}"},
{"t":"service","n":"React Router","p":"cpe:2.3:a:shopify:react-router:{v}"},
{"t":"service","n":"Red Hat OpenShift","p":"cpe:2.3:a:redhat:openshift:{v}"},
{"t":"service","n":"Redmine","p":"cpe:2.3:a:redmine:redmine:{v}"},
{"t":"service","n":"ReDoc","p":"cpe:2.3:a:redocly:redoc:{v}"},
{"t":"service","n":"Redux Framework","p":"cpe:2.3:a:redux:gutenberg_template_library_\\&_redux_framework:{v}"},
{"t":"service","n":"Responsive Lightbox & Gallery","p":"cpe:2.3:a:dfactory:responsive_lightbox:{v}"},
{"t":"service","n":"Reveal.js","p":"cpe:2.3:a:revealjs:reveal.js:{v}"},
{"t":"service","n":"Revel","p":"cpe:2.3:a:revel:revel:{v}"},
{"t":"service","n":"Rhino Software Serv-U","p":"cpe:2.3:a:solarwinds:serv-u:{v}"},
{"t":"service","n":"Rhymix","p":"cpe:2.3:a:rhymix:rhymix:{v}"},
{"t":"service","n":"Rocket.Chat","p":"cpe:2.3:a:rocket.chat:rocket.chat:{v}"},
{"t":"service","n":"RockRMS","p":"cpe:2.3:a:sparkdevnetwork:rock_rms:{v}"},
{"t":"service","n":"Roundcube Webmail","p":"cpe:2.3:a:roundcube:webmail:{v}"},
{"t":"service","n":"Ruby Rack","p":"cpe:2.3:a:rack:rack:{v}"},
{"t":"hw","n":"Ruckus Zone Director","p":"cpe:2.3:h:ruckus:zonedirector:{v}"},
{"t":"service","n":"Sangoma Switchvox","p":"cpe:2.3:a:sangoma:switchvox:{v}"},
{"t":"service","n":"SAP Message Server","p":"cpe:2.3:a:sap:message_server:{v}"},
{"t":"service","n":"SAP NetWeaver Application Server","p":"cpe:2.3:a:sap:netweaver_application_server:{v}"},
{"t":"service","n":"Sassy Social Share","p":"cpe:2.3:a:heateor:sassy_social_share:{v}"},
{"t":"service","n":"Sawmill","p":"cpe:2.3:a:sawmill:sawmill:{v}"},
{"t":"os","n":"SCO OpenServer","p":"cpe:2.3:o:sco:openserver:{v}"},
{"t":"service","n":"Scully","p":"cpe:2.3:a:scully:scully:{v}"},
{"t":"service","n":"Seattle Labs SLMail","p":"cpe:2.3:a:seattlelab:slmail:{v}"},
{"t":"service","n":"SEOmatic","p":"cpe:2.3:a:nystudio107:seomatic:{v}"},
{"t":"service","n":"SEOPress","p":"cpe:2.3:a:seopress:seopress:{v}"},
{"t":"service","n":"Serendipity","p":"cpe:2.3:a:s9y:serendipity:{v}"},
{"t":"service","n":"ShellInABox","p":"cpe:2.3:a:shellinabox_project:shellinabox:{v}"},
{"t":"service","n":"ShopSite","p":"cpe:2.3:a:shopsite:shopsite:{v}"},
{"t":"service","n":"Shortcodes Ultimate","p":"cpe:2.3:a:getshortcodes:shortcodes_ultimate:{v}"},
{"t":"service","n":"Showdown","p":"cpe:2.3:a:showdownjs:showdown:{v}"},
{"t":"service","n":"Siebel CRM","p":"cpe:2.3:a:oracle:siebel_crm:{v}"},
{"t":"service","n":"Silex","p":"cpe:2.3:a:silexlabs:silex:{v}"},
{"t":"service","n":"Site Kit","p":"cpe:2.3:a:google:site_kit:{v}"},
{"t":"service","n":"SiteOrigin Page Builder","p":"cpe:2.3:a:siteorigin:page_builder:{v}"},
{"t":"service","n":"SiteOrigin Widgets Bundle","p":"cpe:2.3:a:siteorigin:siteorigin_widgets_bundle:{v}"},
{"t":"service","n":"Slider Revolution","p":"cpe:2.3:a:themepunch:slider_revolution:{v}"},
{"t":"service","n":"Smart Slider 3","p":"cpe:2.3:a:nextendweb:smart_slider_3:{v}"},
{"t":"service","n":"Smartstore biz","p":"cpe:2.3:a:smartstore:smartstore:{v}"},
{"t":"service","n":"sNews","p":"cpe:2.3:a:snewscms:snews:{v}"},
{"t":"service","n":"SonarQube","p":"cpe:2.3:a:sonarsource:sonarqube:{v}"},
{"t":"service","n":"SonarQubes","p":"cpe:2.3:a:sonarsource:sonarqube:{v}"},
{"t":"service","n":"Sonarr","p":"cpe:2.3:a:sonarr:sonarr:{v}"},
{"t":"service","n":"Sonatype Nexus Repository","p":"cpe:2.3:a:sonatype:nexus_repository_manager:{v}"},
{"t":"service","n":"SonicWall SonicOS","p":"cpe:2.3:o:sonicwall:sonicos:{v}"},
{"t":"service","n":"Sophos Email Appliance","p":"cpe:2.3:a:sophos:email_appliance:{v}"},
{"t":"service","n":"Sophos Firewall","p":"cpe:2.3:o:sophos:sfos:{v}"},
{"t":"service","n":"SOPlanning","p":"cpe:2.3:a:soplanning:soplanning:{v}"},
{"t":"service","n":"Spectra","p":"cpe:2.3:a:brainstormforce:spectra:{v}"},
{"t":"service","n":"SpeedyCache","p":"cpe:2.3:a:softaculous:speedycache:{v}"},
{"t":"service","n":"Spiceworks Help Desk Server","p":"cpe:2.3:a:spiceworks:help_desk_server:{v}"},
{"t":"service","n":"Splunk","p":"cpe:2.3:a:splunk:splunk:{v}"},
{"t":"service","n":"Splunkd","p":"cpe:2.3:a:splunk:splunk:{v}"},
{"t":"service","n":"SQL Buddy","p":"cpe:2.3:a:sqlbuddy:sql_buddy:{v}"},
{"t":"service","n":"SSH Secure Shell","p":"cpe:2.3:a:ssh:secure_shell:{v}"},
{"t":"service","n":"Starlet","p":"cpe:2.3:a:kazuho:starlet:{v}"},
{"t":"service","n":"status.net","p":"cpe:2.3:a:status:statusnet:{v}"},
{"t":"service","n":"Streamlit","p":"cpe:2.3:a:snowflake:streamlit:{v}"},
{"t":"service","n":"Subrion","p":"cpe:2.3:a:intelliants:subrion:{v}"},
{"t":"service","n":"SuiteCRM","p":"cpe:2.3:a:salesagility:suitecrm:{v}"},
{"t":"service","n":"Summernote","p":"cpe:2.3:a:summernote:summernote:{v}"},
{"t":"service","n":"Super Socializer","p":"cpe:2.3:a:heateor:super_socializer:{v}"},
{"t":"service","n":"SVG Support","p":"cpe:2.3:a:benbodhi:svg_support:{v}"},
{"t":"service","n":"Swagger UI","p":"cpe:2.3:a:smartbear:swagger_ui:{v}"},
{"t":"service","n":"Swiper","p":"cpe:2.3:a:swiperjs:swiper:{v}"},
{"t":"service","n":"Synology DSM","p":"cpe:2.3:o:synology:diskstation_manager:{v}"},
{"t":"service","n":"Taobao Tengine","p":"cpe:2.3:a:alibaba:tengine:{v}"},
{"t":"service","n":"TeamCity","p":"cpe:2.3:a:jetbrains:teamcity:{v}"},
{"t":"service","n":"Tenable Nessus","p":"cpe:2.3:a:tenable:nessus:{v}"},
{"t":"service","n":"Tenable Security Center","p":"cpe:2.3:a:tenable:security_center:{v}"},
{"t":"service","n":"Tenable.sc","p":"cpe:2.3:a:tenable:tenable.sc:{v}"},
{"t":"service","n":"Tendenci","p":"cpe:2.3:a:tendenci:tendenci:{v}"},
{"t":"service","n":"Tengine","p":"cpe:2.3:a:alibaba:tengine:{v}"},
{"t":"service","n":"Terminalfour","p":"cpe:2.3:a:terminalfour:terminalfour:{v}"},
{"t":"service","n":"The Events Calendar","p":"cpe:2.3:a:stellarwp:the_events_calendar:{v}"},
{"t":"service","n":"Theme Horse NewsCard","p":"cpe:2.3:a:themehorse:newscard:{v}"},
{"t":"service","n":"ThemeGrill ColorMag","p":"cpe:2.3:a:themegrill:colormag:{v}"},
{"t":"service","n":"Themify Builder","p":"cpe:2.3:a:themify:builder:{v}"},
{"t":"service","n":"ThimPress LearnPress","p":"cpe:2.3:a:thimpress:learnpress:{v}"},
{"t":"service","n":"Thrive Apprentice","p":"cpe:2.3:a:thrivethemes:thrive_apprentice:{v}"},
{"t":"service","n":"Thrive Comments","p":"cpe:2.3:a:thrivethemes:thrive_comments:{v}"},
{"t":"service","n":"Thrive Quiz Builder","p":"cpe:2.3:a:thrivethemes:thrive_quiz_builder:{v}"},
{"t":"service","n":"thttpd","p":"cpe:2.3:a:acme:thttpd:{v}"},
{"t":"service","n":"Tickera","p":"cpe:2.3:a:tickera:tickera:{v}"},
{"t":"service","n":"TiddlyWiki","p":"cpe:2.3:a:tiddlywiki:tiddlywiki5:{v}"},
{"t":"service","n":"Tiki Wiki CMS Groupware","p":"cpe:2.3:a:tiki:tikiwiki_cms\\/groupware:{v}"},
{"t":"service","n":"Tornado","p":"cpe:2.3:a:tornadoweb:tornado:{v}"},
{"t":"service","n":"TornadoServer","p":"cpe:2.3:a:tornadoweb:tornado:{v}"},
{"t":"service","n":"total.js","p":"cpe:2.3:a:totaljs:total.js:{v}"},
{"t":"service","n":"Totara","p":"cpe:2.3:a:totara:totara:{v}"},
{"t":"service","n":"Trac","p":"cpe:2.3:a:edgewall:trac:{v}"},
{"t":"service","n":"Traefik","p":"cpe:2.3:a:traefik:traefik:{v}"},
{"t":"service","n":"Translate WordPress","p":"cpe:2.3:a:gtranslate:translate_wordpress_with_gtranslate:{v}"},
{"t":"service","n":"Tridium Niagara","p":"cpe:2.3:a:tridium:niagara:{v}"},
{"t":"service","n":"Twilight CMS","p":"cpe:2.3:a:twilightcms:twilight_cms:{v}"},
{"t":"service","n":"TwistedWeb","p":"cpe:2.3:a:twistedmatrix:twistedweb:{v}"},
{"t":"service","n":"TYPO3 CMS","p":"cpe:2.3:a:typo3:typo3:{v}"},
{"t":"service","n":"Ubercart","p":"cpe:2.3:a:ubercart:ubercart:{v}"},
{"t":"service","n":"Ubiquiti UniFi","p":"cpe:2.3:a:ui:unifi:{v}"},
{"t":"service","n":"Ultimate Bulletin Board","p":"cpe:2.3:a:infopop:ultimate_bulletin_board:{v}"},
{"t":"service","n":"Ultimate Tables","p":"cpe:2.3:a:webpsilon:ultimate_tables:{v}"},
{"t":"service","n":"UMI.CMS","p":"cpe:2.3:a:umi-cms:umi.cms:{v}"},
{"t":"service","n":"Underscore.js","p":"cpe:2.3:a:underscorejs:underscore:{v}"},
{"t":"service","n":"uPortal","p":"cpe:2.3:a:apereo:uportal:{v}"},
{"t":"service","n":"Uptime Kuma","p":"cpe:2.3:a:uptime.kuma:uptime_kuma:{v}"},
{"t":"service","n":"Ushahidi","p":"cpe:2.3:a:ushahidi:ushahidi:{v}"},
{"t":"service","n":"Uvicorn","p":"cpe:2.3:a:encode:uvicorn:{v}"},
{"t":"service","n":"Vanilla","p":"cpe:2.3:a:vanillaforums:vanilla:{v}"},
{"t":"service","n":"Varnish","p":"cpe:2.3:a:varnish-software:varnish_cache:{v}"},
{"t":"service","n":"Vaultwarden","p":"cpe:2.3:a:dani-garcia:vaultwarden:{v}"},
{"t":"service","n":"Veeam Backup & Replication","p":"cpe:2.3:a:veeam:veeam_backup_\\&_replication:{v}"},
{"t":"service","n":"VideoJS","p":"cpe:2.3:a:videojs:video.js:{v}"},
{"t":"service","n":"Virtuoso","p":"cpe:2.3:a:openlinksw:virtuoso:{v}"},
{"t":"service","n":"Visual Composer","p":"cpe:2.3:a:visualcomposer:visual_composer_website_builder:{v}"},
{"t":"service","n":"VMware ESXi","p":"cpe:2.3:o:vmware:esxi:{v}"},
{"t":"service","n":"Vvveb CMS","p":"cpe:2.3:a:vvveb:vvveb:{v}"},
{"t":"service","n":"W3 Total Cache","p":"cpe:2.3:a:boldgrid:w3_total_cache:{v}"},
{"t":"service","n":"Washington University WU-FTPD","p":"cpe:2.3:a:wuftpd:wu-ftpd:{v}"},
{"t":"service","n":"WatchGuard Firebox","p":"cpe:2.3:o:watchguard:fireware:{v}"},
{"t":"service","n":"Wazuh","p":"cpe:2.3:a:wazuh:wazuh:{v}"},
{"t":"service","n":"Weaver Xtreme","p":"cpe:2.3:a:weavertheme:weaver_xtreme_theme:{v}"},
{"t":"service","n":"Web Wiz Forums","p":"cpe:2.3:a:webwiz:web_wiz_forums:{v}"},
{"t":"service","n":"WebGUI","p":"cpe:2.3:a:plainblack:webgui:{v}"},
{"t":"service","n":"Weblate","p":"cpe:2.3:a:weblate:weblate:{v}"},
{"t":"service","n":"Windows Admin Center","p":"cpe:2.3:a:microsoft:windows_admin_center:{v}"},
{"t":"service","n":"Wing FTP Server","p":"cpe:2.3:a:wftpserver:wing_ftp_server:{v}"},
{"t":"service","n":"Winter CMS","p":"cpe:2.3:a:wintercms:winter:{v}"},
{"t":"service","n":"Wolf CMS","p":"cpe:2.3:a:wolfcms:wolf_cms:{v}"},
{"t":"service","n":"WooCommerce Stripe Payment Gateway","p":"cpe:2.3:a:woocommerce:stripe_payment_gateway:{v}"},
{"t":"service","n":"WooCommerce Subscriptions","p":"cpe:2.3:a:woocommerce:subscriptions:{v}"},
{"t":"service","n":"WordPress","p":"cpe:2.3:a:wordpress:wordpress:{v}"},
{"t":"service","n":"WP Fastest Cache","p":"cpe:2.3:a:wpfastestcache:wp_fastest_cache:{v}"},
{"t":"service","n":"WP Job Openings","p":"cpe:2.3:a:awsm:wp_job_openings:{v}"},
{"t":"service","n":"WP Maintenance Mode","p":"cpe:2.3:a:designmodo:wp_maintenance_mode:{v}"},
{"t":"service","n":"WP Portfolio","p":"cpe:2.3:a:themehorse:wp_portfolio:{v}"},
{"t":"service","n":"WP Rocket","p":"cpe:2.3:a:wp-rocket:wp-rocket:{v}"},
{"t":"service","n":"WP-Optimize","p":"cpe:2.3:a:updraftplus:wp-optimize:{v}"},
{"t":"service","n":"WP-Statistics","p":"cpe:2.3:a:veronalabs:wp_statistics:{v}"},
{"t":"service","n":"WPMU DEV Smush","p":"cpe:2.3:a:wpmudev:smush_image_compression_and_optimization:{v}"},
{"t":"service","n":"XAMPP","p":"cpe:2.3:a:apachefriends:xampp:{v}"},
{"t":"service","n":"Xerox DocuShare","p":"cpe:2.3:a:xerox:docushare:{v}"},
{"t":"hw","n":"Xerox WorkCentre","p":"cpe:2.3:h:xerox:workcentre:{v}"},
{"t":"hw","n":"Xerox WorkCentre Pro","p":"cpe:2.3:h:xerox:workcentre_pro:{v}"},
{"t":"service","n":"Xlight FTP Server","p":"cpe:2.3:a:xlightftpd:xlight_ftp_server:{v}"},
{"t":"service","n":"XMB","p":"cpe:2.3:a:xmbforum2:xmb:{v}"},
{"t":"service","n":"XOOPS","p":"cpe:2.3:a:xoops:xoops:{v}"},
{"t":"service","n":"xtCommerce","p":"cpe:2.3:a:xt-commerce:xt-commerce:{v}"},
{"t":"service","n":"YesWiki","p":"cpe:2.3:a:yeswiki:yeswiki:{v}"},
{"t":"service","n":"Yoast SEO","p":"cpe:2.3:a:yoast:yoast_seo:{v}"},
{"t":"service","n":"YouTrack","p":"cpe:2.3:a:jetbrains:youtrack:{v}"},
{"t":"service","n":"Zabbix","p":"cpe:2.3:a:zabbix:zabbix:{v}"},
{"t":"service","n":"Zen Cart","p":"cpe:2.3:a:zen-cart:zen_cart:{v}"},
{"t":"service","n":"Zimbra Collaboration","p":"cpe:2.3:a:zimbra:collaboration:{v}"},
{"t":"service","n":"Zope","p":"cpe:2.3:a:zope:zope:{v}"},
{"t":"service","n":"Zulip","p":"cpe:2.3:a:zulip:zulip_server:{v}"}
],"replace":[
{"n":"Mattermost","was":"a:jenkins:mattermost","p":"cpe:2.3:a:mattermost:mattermost_server:{v}"},
{"n":"AWS Certificate Manager","was":"a:awstats:awstats","p":""},
{"n":"Sitecore","was":"a:sitecore:*","p":"cpe:2.3:a:sitecore:experience_platform:{v}"},
{"n":"Okta","was":"a:okta:*","p":""},
{"n":"Salesforce","was":"a:salesforce:*","p":""}
],"aliases":[
["a:10web:photo_gallery","a:web-dorado:photo_gallery"],
["a:acquia:mautic","a:mautic:mautic"],
["a:advisto:peel_shopping","a:peel:peel_shopping"],
["a:aiohttp:aiohttp","a:aiohttp_project:aiohttp"],
["a:alpinelinux:alpine_linux","o:alpinelinux:alpine_linux"],
["a:amazon:amazon_simple_storage_service","a:amazon:web_services_simple_storage_service"],
["a:amazon:elastic_load_balancing","a:amazon:elastic_load_balancing_api_tools"],
["a:apache:guacamole","a:guac-dev:guacamole"],
["a:apache:incubator_superset","a:apache:superset"],
["a:apache:mod_jk","a:apache:tomcat_connectors","a:apache:tomcat_jk_connector","a:apache:tomcat_jk_web_server_connector"],
["a:apache_friends:xampp","a:apachefriends:xampp"],
["a:apereo:uportal","a:jasig:uportal"],
["a:argoproj:argo_cd","a:linuxfoundation:argo-cd"],
["a:atlassian:confluence","a:atlassian:confluence_data_center","a:atlassian:confluence_server"],
["a:atlassian:jira_service_management","a:atlassian:jira_service_management_server_and_data_center"],
["a:awesomemotive:easy_digital_downloads","a:easydigitaldownloads:easy_digital_downloads","a:sandhillsdev:easy_digital_downloads"],
["a:boldgrid:w3_total_cache","a:w3-edge:total_cache"],
["a:bolt:bolt","a:boltcms:bolt"],
["a:booking-wp-plugin:bookly","a:bookly_project:bookly"],
["a:bootstrap-table:bootstrap_table","a:bootstrap_table_project:bootstrap_table"],
["a:brizy:brizy","a:brizy:brizy-page_builder"],
["a:broadcom:siteminder","a:ca:siteminder"],
["a:buddypress:buddypress","a:buddypress:buddypress_plugin"],
["a:cakefoundation:cakephp","a:cakephp:cakephp"],
["a:calderaforms:caldera_forms","a:calderalabs:caldera_forms"],
["a:calibre-web_project:calibre-web","a:janeczku:calibre-web"],
["a:canonical:ubuntu_linux","a:cononical:ubuntu","o:canonical:ubuntu_linux"],
["a:centos-webpanel:centos_web_panel","a:control-webpanel:webpanel"],
["a:cgit_project:cgit","a:jason_a_donenfeld:cgit","a:lars_hjemli:cgit"],
["a:check_mk_project:check_mk","a:checkmk:checkmk","a:tribe29:checkmk"],
["a:cisco:adaptive_security_appliance_software","o:cisco:adaptive_security_appliance_software"],
["a:cisco:firepower_threat_defense","a:cisco:firepower_threat_defense_software","a:cisco:secure_firewall_threat_defense","o:cisco:firepower_threat_defense"],
["a:cisco:ios","h:cisco:ios","o:cisco:ios"],
["a:cisco:ios_xe","o:cisco:ios_xe"],
["a:cisco:nx-os","o:cisco:nx-os"],
["a:cisco:wireless_lan_controller","o:cisco:wireless_lan_controller","o:cisco:wireless_lan_controller_software"],
["a:citrix:application_delivery_controller","a:citrix:netscaler_application_delivery_controller","o:citrix:application_delivery_controller_firmware","o:citrix:netscaler_application_delivery_controller_firmware"],
["a:citrix:gateway","a:citrix:netscaler_gateway","o:citrix:gateway_firmware","o:citrix:netscaler_gateway_firmware"],
["a:citrix:xenserver","o:citrix:hypervisor"],
["a:cncf:envoy","a:envoyproxy:envoy"],
["a:cncf:harbor","a:goharbor:harbor","a:linuxfoundation:harbor"],
["a:code-atlantic:popup_maker","a:wppopupmaker:popup_maker"],
["a:collne:welcart","a:welcart:welcart"],
["a:comsenz:discuzx","a:discuz:discuzx"],
["a:concrete5:concrete5","a:concretecms:concrete_cms"],
["a:containous:traefik","a:traefik:traefik"],
["a:couchbase:couchbase_server","a:couchbase:server"],
["a:crocoblock:jetengine","a:crocoblock:jetengine_for_elementor"],
["a:cs-cart:cs-cart","a:cs-cart:cs-cart."],
["a:darkhttpd_project:darkhttpd","a:unix4lyfe:darkhttpd"],
["a:dave_thomas:rdoc","a:ruby-lang:rdoc"],
["a:delinea:secret_server","a:thycotic:secret_server"],
["a:dena:h2o","a:h2o_project:h2o"],
["a:django_project:django","a:djangoproject:django"],
["a:dnnsoftware:dotnetnuke","a:dotnetnuke:dotnetnuke"],
["a:dropbear_project:dropbear","a:dropbear_ssh_project:dropbear_ssh","a:matt_johnston:dropbear_ssh_server"],
["a:edwiser:bridge","a:wisdmlabs:edwiser_bridge"],
["a:elastic:elasticsearch","a:elasticsearch:elasticsearch"],
["a:elastic:kibana","a:elasticsearch:kibana"],
["a:elegant_themes:divi","a:elegantthemes:divi"],
["a:elementor:elementor","a:elementor:elementor_page_builder","a:elementor:website_builder"],
["a:enhancesoft:osticket","a:osticket:osticket"],
["a:erlang:erlang/otp","a:erlang:otp"],
["a:expressjs:express","a:openjsf:express"],
["a:f5:big-ip","o:f5:tmos"],
["a:f5:nginx","a:nginx:nginx"],
["a:fit2cloud:halo","a:halo:halo","a:halo_project:halo"],
["a:flowerfire:sawmill","a:sawmill:sawmill"],
["a:fork-cms:fork","a:fork-cms:fork_cms","a:fork-cms:forkcms"],
["a:fortra:goanywhere_managed_file_transfer","a:helpsystems:goanywhere_managed_file_transfer"],
["a:freebsd:freebsd","o:freebsd:freebsd"],
["a:gfi:kerio_connect","a:kerio:connect"],
["a:givewp:give","a:givewp:givewp","a:impress:givewp"],
["a:google:kubernetes","a:kubernetes:kubernetes"],
["a:google:site_kit","a:google:site_kit_by_google"],
["a:gravityforms:gravity_forms","a:rocketgenius:gravityforms"],
["a:grin-tech:grin","a:grin:grin"],
["a:hasthemes:ht_mega","a:hasthemes:ht_mega_-_absolute_addons_for_elementor_page_builder"],
["a:hcltech:digital_experience","a:ibm:websphere_portal"],
["a:hcltech:domino","a:ibm:domino","a:ibm:lotus_domino"],
["a:hp:integrated_lights_out","h:hp:integrated_lights-out"],
["a:hp:openvms","o:hp:openvms"],
["a:ibm:security_access_manager","a:ibm:security_verify_access"],
["a:ibm:vios","o:ibm:vios"],
["a:icegram:icegram","a:icegram:icegram_engage"],
["a:inductiveautomation:ignition","a:inductiveautomation:ignition_gateway"],
["a:intel:active_management_technology","a:intel:active_management_technology_firmware","h:intel:active_management_technology","o:intel:active_management_technology","o:intel:active_management_technology_firmware"],
["a:intelliants:subrion","a:subrion:cms"],
["a:invisioncommunity:invision_power_board","a:invisioncommunity:invisioncommunity","a:invisioncommunity:ips_community_suite","a:invisionpower:invision_power_board"],
["a:ipswitch:whatsup_gold","a:progress:whatsup_gold","a:progress:whatsupgold"],
["a:ithemes:ithemes_security","a:ithemes:security"],
["a:ivanti:connect_secure","a:pulsesecure:connect_secure","a:pulsesecure:pulse_connect_secure"],
["a:jannisthuemmig:email_encoder","a:onlineoptimisation:email_encoder"],
["a:jivochat:jivochat","a:jivochat:live_chat"],
["a:jquery:jquery_ui","a:jqueryui:jquery_ui"],
["a:juniper:j-web","a:juniper:junos","o:juniper:junos"],
["a:kentico:kentico","a:kentico:kentico_experience_cms","a:kentico:xperience"],
["a:lightbend:play_framework","a:playframework:play_framework"],
["a:linux:linux_kernel","o:kernel:linux_kernel","o:linux:kernel","o:linux:linux_kernel"],
["a:manageengine:opmanager","a:zohocorp:manageengine_opmanager"],
["a:mariadb:mariadb","a:mariadb_project:mariadb"],
["a:mathjs:math.js","a:mathjs:mathjs"],
["a:matomo:matomo","a:piwik:piwik"],
["a:mattermost:mattermost","a:mattermost:mattermost_server","a:mattermost:server"],
["a:microsoft:asp.net_model_view_controller","a:microsoft:asp.net_mvc","a:microsoft:microsoft.aspnetcore.mvc","a:microsoft:microsoft.aspnetcore.mvc.core"],
["a:microsoft:exchange_server","a:microsoft:exchange_srv"],
["a:microsoft:media_player","a:microsoft:windows_media_player"],
["a:mikejolley:download_monitor","a:never5:download_monitor","a:wpchill:download_monitor"],
["a:monkey-project:monkey","a:monkey-project:monkey_http_daemon"],
["a:morbtay:jetty","a:mortbay:jetty"],
["a:mybb:mybb","a:mybboard:mybb"],
["a:mycred:mycred","a:wpexperts:mycred"],
["a:ninjaforms:ninja_forms","a:ninjaforms:ninjaforms"],
["a:novell:netware","o:novell:netware"],
["a:octobercms:october","a:octobercms:october_cms","a:octobercms:octobercms"],
["a:openbsd:openbsd","o:openbsd:openbsd"],
["a:openbsd:openssh","a:openssh:openssh"],
["a:opensolution:quick.cart","a:opensolution:quick_cart"],
["a:openx:openx","a:openx:openx_source"],
["a:oracle:peoplesoft_enterprise_people_tools","a:oracle:peoplesoft_enterprise_peopletools"],
["a:oracle:solaris","a:oracle:solaris_operating_system","o:oracle:solaris"],
["a:oxid-esales:eshop","a:oxidforge:oxid_eshop"],
["a:paessler:network_monitor","a:paessler:prtg","a:paessler:prtg_network_monitor","a:paessler_ag:prtg_network_monitor"],
["a:pagerduty:rundeck","a:rundeck:rundeck"],
["a:pdfmake:pdfmake","a:pdfmake_project:pdfmake"],
["a:pgadmin:pgadmin","a:pgadmin:pgadmin_4","a:postgresql:pgadmin_4"],
["a:php-nuke:php-nuke","a:phpnuke:php-nuke","a:phpnuke:phpnuke"],
["a:pivotal_software:spring_boot","a:vmware:spring_boot"],
["a:pivotal_software:spring_framework","a:springsource:spring_framework","a:vmware:spring_framework"],
["a:plex:media_server","a:plex:plex_media_server"],
["a:profilepress:profilepress","a:properfraction:profilepress"],
["a:progress:ipswitch_ws_ftp_server","a:progress:ws_ftp_server"],
["a:progress:sitefinity","a:telerik:sitefinity_cms"],
["a:projectpier:projectpier","a:projectpier_project:projectpier"],
["a:proxmov:virtual_environment","a:proxmox:virtual_environment"],
["a:puppet:puppet_enterprise","a:puppetlabs:puppet_enterprise","a:puppetlabs:puppet_enterprise_users"],
["a:python:cpython","a:python:python"],
["a:qnap:qts","o:qnap:qts"],
["a:qualiteam:x-cart","a:x-cart:x-cart"],
["a:rafflepress:rafflepress","a:seedprod:rafflepress"],
["a:rancher:rancher","a:suse:rancher"],
["a:rankmath:rankmath","a:rankmath:seo"],
["a:redhat:linux","o:redhat:linux"],
["a:roundcube:roundcube","a:roundcube:roundcube_webmail","a:roundcube:webmail"],
["a:salesagility:suitcrm","a:salesagility:suitecrm","a:suitecrm:suitecrm"],
["a:sap:netweaver_abap","a:sap:netweaver_application_server_abap","a:sap:netweaver_application_server_for_abap"],
["a:sitecore:cms","a:sitecore:experience_manager","a:sitecore:experience_platform"],
["a:snowflake:streamlit","a:streamlit:streamlit"],
["a:solarwinds:serv-u","a:solarwinds:serv-u_file_server","a:solarwinds:serv-u_ftp_server","a:solarwinds:serv-u_managed_file_transfer","a:solarwinds:serv-u_mft_server"],
["a:sophos:firewall","o:sophos:firewall_firmware","o:sophos:sfos","o:sophos:xg_firewall_firmware"],
["a:stellarwp:the_events_calendar","a:tri:the_events_calendar"],
["a:synology:diskstation_manager","o:synology:diskstation_manager"],
["a:tableau:server","a:tableau:tableau_server"],
["a:tenable:security_center","a:tenable:securitycenter","a:tenable:tenable.sc"],
["a:themify:builder","a:themify:themify_builder"],
["a:tiny.cloud:tinymce","a:tiny:tinymce"],
["a:tridium:niagara_ax","a:tridium:niagra_ax_framework"],
["a:twisted:twisted","a:twistedmatrix:twisted","a:twistedmatrix:twistedweb"],
["a:ubnt:unifi","a:ui:unifi"],
["a:ubnt:unifi_video","a:ui:unifi_video"],
["a:umbraco:umbraco","a:umbraco:umbraco_cms"],
["a:uptime-kuma_project:uptime-kuma","a:uptime.kuma:uptime_kuma","a:uptime_kuma_project:uptime_kuma"],
["a:vanillaforums:vanilla","a:vanillaforums:vanilla_forums"],
["a:veeam:backup_&_replication","a:veeam:backup_and_replication","a:veeam:veeam_backup_&_replication"],
["a:vmware:esx_server","o:vmware:esx"],
["a:vmware:vcenter_server","a:vmware:vsphere_server"],
["a:wolfcms:wolf_cms","a:wolfcms:wolfcms"],
["a:xt-commerce:xt-commerce","a:xt-commerce:xt:commerce"],
["h:cisco:ios_xr","o:cisco:ios_xr"],
["h:cisco:pix_firewall","o:cisco:pix_firewall_software"],
["h:d-link:dcs-825l","h:dlink:dcs-825l"],
["h:hp:integrated_lights_out","o:hp:integrated_lights-out_firmware"],
["o:apple:mac_os","o:apple:macos"],
["o:broadcom:fabric_operating_system","o:brocade:fabric_operating_system"],
["o:checkpoint:gaia","o:checkpoint:gaia_os"],
["o:cisco:mds_9000","o:cisco:mds_9000_san-os"],
["o:cisco:vpn_3000_concentrator","o:cisco:vpn_3000_concentrator_series_software"],
["o:dell:sonicwall_sonicos","o:sonicwall:sonicos"],
["o:extremenetworks:exos","o:extremenetworks:extremexos"],
["o:fedoraproject:fedora_core","o:redhat:fedora_core"],
["o:microsoft:windows-ce","o:microsoft:windows_ce","o:microsoft:windows_embedded_compact"],
["o:microsoft:windows_vista","o:microsoft:windowst"],
["o:serenityos:serenity","o:serenityos:serenityos"]
],"platforms":["o:canonical:ubuntu_linux","o:debian:debian_linux","o:redhat:enterprise_linux","o:redhat:linux","o:centos:centos","o:fedoraproject:fedora","o:fedoraproject:fedora_core","o:suse:linux","o:suse:suse_linux","o:suse:linux_enterprise_server","o:opensuse:leap","o:oracle:linux","o:almalinux:almalinux","o:rockylinux:rocky_linux","o:resf:rocky_linux","o:gentoo:linux","o:mandriva:linux","o:conectiva:linux","o:trustix:secure_linux","o:alpinelinux:alpine_linux","o:amazon:linux_2","o:linux:linux_kernel","o:microsoft:windows*","o:apple:mac_os_x*","o:apple:macos","o:freebsd:freebsd","o:netbsd:netbsd","o:openbsd:openbsd","o:oracle:solaris","o:sun:solaris","o:sun:sunos","o:oracle:sunos","o:ibm:aix","o:hp:hp-ux","o:google:android","o:google:chrome_os"]}
'@
#endregion


#region ---------- Port sets and protocol hints ----------
$PortSets = @{
    'web'          = @(80, 81, 443, 591, 2082, 2083, 2086, 2087, 3000, 4443, 5000, 5601, 7001, 7443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9443, 10000)
    'web-extended' = @(80, 81, 82, 88, 280, 300, 443, 444, 591, 593, 800, 832, 981, 1010, 1080, 1311, 2000, 2082, 2083, 2086, 2087, 2095, 2096, 2381, 2480,
        3000, 3001, 3128, 3333, 4000, 4243, 4443, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5480, 5601, 5800, 5985, 5986, 6443, 6543,
        7000, 7001, 7080, 7396, 7443, 7474, 8000, 8001, 8002, 8006, 8008, 8009, 8010, 8042, 8060, 8069, 8080, 8081, 8082, 8083, 8086, 8088, 8089,
        8090, 8091, 8118, 8123, 8172, 8180, 8181, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8530, 8531, 8834, 8880, 8888, 8983, 9000, 9001, 9043,
        9060, 9080, 9090, 9091, 9100, 9200, 9443, 9800, 9981, 10000, 10250, 10443, 12443, 15672, 16080, 18080, 18091, 18092, 20720, 28017)
    'mgmt'         = @(80, 443, 1311, 2381, 4443, 5480, 5985, 5986, 6443, 8006, 8080, 8443, 8834, 9090, 9443, 10000, 10443)
}
# TLS-first on these; plaintext-first everywhere else (auto-switch either way)
$TlsHintPorts = @(443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 1311, 2083, 2087, 2381, 3269, 4443, 5061, 5480, 5986, 6443, 7443,
    8006, 8443, 8531, 8834, 9043, 9443, 10250, 10443, 12443)
# HTTP servers never speak first: skip the NULL-probe banner wait on these
$HttpPorts = @(80, 81, 443, 591, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090)
# Passive version advisories: evaluated against versions the server itself advertises (Server / X-Powered-By).
# Status is "likely exposed by version", never a test of exploitability; vendor builds may carry backported fixes.
$Advisories = @(
    @{
        Id = 'PHP2Shell'; Product = 'PHP'; Cves = 'CVE-2026-109618, CVE-2026-109619'
        Regex = '(?i)\bPHP/(\d+\.\d+\.\d+)([^\s;,)]*)'      # group1 = version, group2 = vendor/package suffix
        Fixed = @('8.5.12', '8.4.27', '8.3.36', '8.2.35')    # PHP security releases of 2026-10-21
        MinBranch = '8.2'                                    # 8.1 and older: no upstream release (source backports / vendor packages only)
        HighRisk = '(?i)^Apache\b.*\bPHP/'                   # PHP token in an Apache Server header => mod_php (highest-risk SAPI per PHP)
        HighRiskLabel = 'mod_php'
        Note = 'Fixed in 8.5.12/8.4.27/8.3.36/8.2.35 (2026-10-21); <=8.1 needs a vendor/backported build. Follow-on CVE-2026-115560 (session upload progress) awaits a later release; interim mitigation session.upload_progress.enabled=0.'
    }
)
# Detections in these categories raise the MgmtInterface flag
$MgmtCategories = @('Out-of-band mgmt', 'Admin panel', 'Virtualization', 'Firewall', 'Network device', 'Load balancer', 'Storage', 'Backup', 'Building automation', 'Power')
# -IdentifyPaths: fixed list of public landing/version endpoints used ONLY to confirm product identity/version
$IdentifyPathList = @(
    '/owa/auth/logon.aspx', '/certsrv/', '/adfs/ls/idpinitiatedsignon.aspx', '/RDWeb/', '/remote/login', '/global-protect/login.esp',
    '/+CSCOE+/logon.html', '/dana-na/auth/url_default/welcome.cgi', '/vpn/index.html', '/version', '/api/health', '/api/v1/status/buildinfo',
    '/rest/applinks/1.0/manifest', '/.well-known/openid-configuration', '/manager/html', '/v2/')
#endregion

#region ---------- Target / port / exclusion parsing (nmap-compatible syntax) ----------
function Read-ListFile {
    param([string]$Path, [string]$What)
    if (-not $Path) { return @() }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$What file not found: $Path" }
    $n = 0
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($line in [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $Path).ProviderPath)) {
        $n++
        $t = ($line -replace '#.*$', '').Trim()
        if (-not $t) { continue }
        foreach ($tok in ($t -split '\s+')) { if ($tok) { $out.Add([pscustomobject]@{ Text = $tok; Src = ('{0}:{1}' -f (Split-Path -Leaf $Path), $n) }) } }
    }
    $out.ToArray()
}

function Expand-Ports {
    param([string]$Spec)
    $set = New-Object 'System.Collections.Generic.SortedSet[int]'
    foreach ($p in ($Spec -split '[,\s]+' | Where-Object { $_ })) {
        $pl = $p.ToLowerInvariant()
        if ($PortSets.ContainsKey($pl)) { foreach ($x in $PortSets[$pl]) { [void]$set.Add($x) } }
        elseif ($pl -eq 'all') { for ($x = 1; $x -le 65535; $x++) { [void]$set.Add($x) } }
        elseif ($p -match '^(\d{1,5})-(\d{1,5})$') {
            $a = [int]$Matches[1]; $b = [int]$Matches[2]
            if ($a -lt 1 -or $b -gt 65535 -or $a -gt $b) { throw "Bad port range '$p'" }
            for ($x = $a; $x -le $b; $x++) { [void]$set.Add($x) }
        }
        elseif ($p -match '^\d{1,5}$' -and [int]$p -ge 1 -and [int]$p -le 65535) { [void]$set.Add([int]$p) }
        else { throw "Bad port '$p' (use numbers, ranges or: web, web-extended, mgmt, all)" }
    }
    if ($set.Count -eq 0) { throw "Empty port specification '$Spec'" }
    , @($set)
}

function Expand-Octet {
    param([string]$Octet)
    $set = New-Object 'System.Collections.Generic.SortedSet[int]'
    foreach ($part in $Octet.Split(',')) {
        if ($part -match '^(\d*)-(\d*)$') {
            $a = if ($Matches[1]) { [int]$Matches[1] } else { 0 }
            $b = if ($Matches[2]) { [int]$Matches[2] } else { 255 }
            if ($a -gt $b -or $b -gt 255) { throw "Bad octet range '$part'" }
            for ($x = $a; $x -le $b; $x++) { [void]$set.Add($x) }
        }
        elseif ($part -match '^\d{1,3}$' -and [int]$part -le 255) { [void]$set.Add([int]$part) }
        else { throw "Bad octet '$part'" }
    }
    , @($set)
}

# Returns @{ Ranges = List[long[]]; Names = List[string]; Count = long } without expanding addresses
function Get-SpecRanges {
    param([string]$Spec)
    $Spec = $Spec.Trim()
    $out = @{ Ranges = (New-Object System.Collections.Generic.List[object]); Names = (New-Object System.Collections.Generic.List[string]); Count = [long]0 }
    $ipRx = '\d{1,3}(?:\.\d{1,3}){3}'
    if ($Spec -match "^($ipRx)/(\d{1,2})$") {
        $base = [WebInv.Util]::Ip4($Matches[1]); $bits = [int]$Matches[2]
        if ($base -lt 0 -or $bits -gt 32) { throw "Bad CIDR '$Spec'" }
        $size = [long]1 -shl (32 - $bits)
        $start = $base - ($base % $size)
        $out.Ranges.Add([long[]]@($start, ($start + $size - 1))); $out.Count = $size
    }
    elseif ($Spec -match "^($ipRx)-($ipRx)$") {
        $a = [WebInv.Util]::Ip4($Matches[1]); $b = [WebInv.Util]::Ip4($Matches[2])
        if ($a -lt 0 -or $b -lt 0 -or $a -gt $b) { throw "Bad range '$Spec'" }
        $out.Ranges.Add([long[]]@($a, $b)); $out.Count = $b - $a + 1
    }
    elseif ($Spec -match '^[\d,\-]+(?:\.[\d,\-]+){3}$') {
        $o = @(); foreach ($part in $Spec.Split('.')) { $o += , (Expand-Octet $part) }
        $count = [long]$o[0].Count * $o[1].Count * $o[2].Count * $o[3].Count
        $out.Count = $count
        if ($count -gt $MaxTargets -and -not $Force) { throw "Spec '$Spec' expands to $count hosts (> -MaxTargets $MaxTargets). Narrow it or use -Force." }
        foreach ($a in $o[0]) { foreach ($b in $o[1]) { foreach ($c in $o[2]) {
            # coalesce contiguous last-octet runs into ranges
            $runStart = -1; $prev = -2
            foreach ($d in $o[3]) {
                if ($d -ne $prev + 1) {
                    if ($runStart -ge 0) { $out.Ranges.Add([long[]]@(([long]$a * 16777216 + $b * 65536 + $c * 256 + $runStart), ([long]$a * 16777216 + $b * 65536 + $c * 256 + $prev))) }
                    $runStart = $d
                }
                $prev = $d
            }
            if ($runStart -ge 0) { $out.Ranges.Add([long[]]@(([long]$a * 16777216 + $b * 65536 + $c * 256 + $runStart), ([long]$a * 16777216 + $b * 65536 + $c * 256 + $prev))) }
        } } }
    }
    elseif ($Spec -match '^[\d.]+$') {
        # never hand a partial numeric to the resolver: '7.1' would become 7.0.0.1 and '443' 0.0.1.187
        throw "Ambiguous numeric target '$Spec' (not a full IPv4 address). If it came from 'host:80,443' or an octet range like '10.0.3-5,7.1', quote the whole value."
    }
    elseif ($Spec -match '^[A-Za-z0-9_](?:[A-Za-z0-9_.\-]*[A-Za-z0-9_])?\.?$' -or $Spec -match '^[0-9A-Fa-f:.]+(%\w+)?$') {
        $ip6 = $null
        if ($Spec.Contains(':') -and -not [Net.IPAddress]::TryParse($Spec, [ref]$ip6)) { throw "Bad IPv6 address '$Spec'" }
        $out.Names.Add($Spec.TrimEnd('.')); $out.Count = 1
    }
    else { throw "Unrecognised host specification '$Spec'" }
    $out
}

# A single token may hold a comma-separated list ('10.0.0.1,10.0.0.9'); nmap octet specs ('192.168.3-5,7.1') are tried whole first
function Get-SpecList {
    param([string]$Text)
    try { return , @(Get-SpecRanges $Text) }
    catch {
        if (-not $Text.Contains(',')) { throw }
        $first = $_
        $list = @()
        foreach ($piece in ($Text -split ',' | Where-Object { $_ })) {
            try { $list += , (Get-SpecRanges $piece) } catch { throw $first }
        }
        return , $list
    }
}

function Split-HostPort {
    param([string]$Entry)
    $e = $Entry.Trim()
    if ($e -match '^(https?)://') {
        try { $u = [Uri]$e } catch { throw "Bad URL '$e'" }
        return @{ Spec = $u.Host.Trim('[', ']'); Ports = "$($u.Port)"; Scheme = $u.Scheme }
    }
    if ($e -match '^(smb|rdp|snmp)://([^/]+)/?$') {
        # protocol URL: the service on a non-standard port (default 445 / 3389 / 161)
        $sch = $Matches[1].ToLowerInvariant(); $auth = $Matches[2]
        $dflt = @{ smb = '445'; rdp = '3389'; snmp = '161' }[$sch]
        if ($auth -match '^\[([^\]]+)\](?::(\d{1,5}))?$') { return @{ Spec = $Matches[1]; Ports = $(if ($Matches[2]) { $Matches[2] } else { $dflt }); Scheme = $sch } }
        if ($auth -match '^([^:\[\]]+)(?::(\d{1,5}))?$') { return @{ Spec = $Matches[1]; Ports = $(if ($Matches[2]) { $Matches[2] } else { $dflt }); Scheme = $sch } }
        throw "Bad URL '$e'"
    }
    if ($e -match '^\[([0-9a-fA-F:.%\w]+)\](?::([\d,\-]+))?$') { return @{ Spec = $Matches[1]; Ports = $Matches[2]; Scheme = '' } }
    if (($e.Split(':')).Count -gt 2) { return @{ Spec = $e; Ports = $null; Scheme = '' } }                       # bare IPv6
    if ($e -match '^([^:\s]+):([\w,\-]+)$') { return @{ Spec = $Matches[1]; Ports = $Matches[2]; Scheme = '' } }
    @{ Spec = $e; Ports = $null; Scheme = '' }
}

function Add-SpecToSet {
    param([WebInv.RangeSet]$Set, [string]$Spec)
    $r = Get-SpecRanges $Spec
    foreach ($x in $r.Ranges) { $Set.AddRange($x[0], $x[1]) }
    foreach ($n in $r.Names) { $Set.AddName($n) }
}

function Format-UriHost { param([string]$H) if ($H.Contains(':')) { "[$H]" } else { $H } }
#endregion


#region ---------- Worker (runs inside the RunspacePool; one invocation per host:port) ----------
# Long-lived worker: one per thread. Helper functions are defined once; each check runs in Invoke-Check, whose locals
# ($J, $TargetId, $logs, $errs, $rows, $stats, $notes) the helpers read through PowerShell's dynamic scoping.
$WorkerScript = {
    param($Sched, [hashtable]$Cfg, [int]$WorkerId)
    $ErrorActionPreference = 'Stop'

    function Add-Err([string]$Cat, [string]$Msg) { [void]$errs.Add(@($Cat, $TargetId, $Msg)) }
    function Add-Log([string]$Msg) { [void]$logs.Add(('{0} {1}' -f $TargetId, $Msg)) }
    function Wait-Pace {
        if ($Cfg.DelayMs -gt 0 -or $Cfg.JitterMs -gt 0) {
            $ms = $Cfg.DelayMs; if ($Cfg.JitterMs -gt 0) { $ms += Get-Random -Minimum 0 -Maximum ($Cfg.JitterMs + 1) }
            if ($ms -gt 0) { Start-Sleep -Milliseconds $ms }
        }
    }
    function Get-HostHdr([string]$H, [int]$P, [bool]$Tls) {
        if ($H.Contains(':')) { $H = "[$H]" }
        if (($Tls -and $P -eq 443) -or (-not $Tls -and $P -eq 80)) { $H } else { '{0}:{1}' -f $H, $P }
    }
    function Format-UriHost([string]$H) { if ($H.Contains(':')) { "[$H]" } else { $H } }
    function New-Req([string]$Method, [string]$Path, [string]$HostHdr) {
        [Text.Encoding]::ASCII.GetBytes(("{0} {1} HTTP/1.1`r`nHost: {2}`r`nUser-Agent: {3}`r`nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`r`nAccept-Encoding: gzip, identity`r`nConnection: close`r`n`r`n" -f $Method, $Path, $HostHdr, $Cfg.UserAgent))
    }
    # response parsing and HTML extraction are in the C# engine (WebInv.Html): same regexes, no interpreter loops
    function ConvertFrom-Raw([byte[]]$Raw) { [WebInv.Html]::Parse($Raw) }
    function Invoke-Fetch([bool]$Tls, [string]$Method, [string]$Path, [string]$HostHdr, [string]$Ip, [int]$Port, [string]$Sni, [int]$BannerWait) {
        Wait-Pace
        $stats.Requests++
        $r = [WebInv.Net]::Probe($Ip, $Port, $Tls, $Sni, (New-Req $Method $Path $HostHdr), $Cfg.TimeoutMs, $Cfg.MaxBodyBytes, $Cfg.SslProto, $BannerWait)
        if ($r.State -eq 'error') {
            Add-Err 'NET' ('{0} {1} not sent: local socket resources exhausted (ephemeral ports or buffers) even after backing off' -f $Method, $Path)
            [void]$notes.Add('incomplete: local socket resources exhausted, some requests not sent')
        }
        if ($r.TlsError) { Add-Log ('TLS handshake failed ({0}): {1}' -f $Path, $r.TlsError) }
        if ($r.Error) { Add-Log ('I/O ({0} {1}): {2}' -f $Method, $Path, $r.Error) }
        @{ Raw = $r; Resp = (ConvertFrom-Raw $r.Raw); Tls = $Tls; Ip = $Ip; Port = $Port; Sni = $Sni; HostHdr = $HostHdr }
    }
    function Test-TlsMismatch([string]$Text) {
        if (-not $Text) { return $false }
        $t = if ($Text.Length -gt 4096) { $Text.Substring(0, 4096) } else { $Text }
        foreach ($m in $Cfg.MismatchStrings) { if ($t.IndexOf($m, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
        $false
    }
    function Resolve-One([string]$Name) {
        $ip = $null
        if ([Net.IPAddress]::TryParse($Name, [ref]$ip)) { return $ip.ToString() }
        $e = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $r = [WebInv.Net]::ResolveMany([string[]]@($Name), $Cfg.TimeoutMs, 1, $e)
        if ($r.ContainsKey($Name)) {
            foreach ($a in $r[$Name]) { if ($a -notmatch ':') { return $a } }
            return $r[$Name][0]
        }
        $null
    }
    function Test-Allowed([string]$Ip, [string]$Name) {
        if ($Cfg.Exclude.Contains($Ip, $Name)) { return $false }
        if (-not $Cfg.Scope.IsEmpty -and -not $Cfg.Scope.Contains($Ip, $Name)) { return $false }
        $true
    }
    function Add-HeaderObs($Obs, [string]$Prefix, [string]$Name, [string]$Value) { [WebInv.Html]::AddHeader($Obs, $Prefix, $Name, $Value) }
    function Add-BodyObs($Obs, [string]$Prefix, $Resp) { [WebInv.Html]::AddBody($Obs, $Prefix, $Resp) }

    # ---------- Redirect chain (same host by default; off-host only with -FollowOffHost and only if in scope) ----------
    function Get-RedirectChain($First, [string]$HostName) {
        $hops = New-Object System.Collections.Generic.List[object]; [void]$hops.Add($First)
        $chain = New-Object System.Collections.Generic.List[string]
        $locs = New-Object System.Collections.Generic.List[string]
        $scheme = if ($First.Tls) { 'https' } else { 'http' }
        $url = '{0}://{1}:{2}/' -f $scheme, (Format-UriHost $HostName), $J.Port
        $cur = $First; $curUrl = $url
        for ($i = 0; $i -lt $Cfg.MaxRedirects; $i++) {
            if (@(301, 302, 303, 307, 308) -notcontains $cur.Resp.Code) { break }
            $loc = [string]$cur.Resp.Headers['location']
            if (-not $loc) { break }
            $loc = ($loc -split "`n")[0].Trim()
            [void]$locs.Add($loc)
            try { $next = New-Object System.Uri((New-Object System.Uri $curUrl), $loc) } catch { [void]$notes.Add("unparseable Location '$loc'"); break }
            if ($next.Scheme -ne 'http' -and $next.Scheme -ne 'https') { [void]$notes.Add("non-HTTP redirect ($($next.Scheme))"); break }
            [void]$chain.Add(('{0}->{1}' -f $cur.Resp.Code, $next.AbsoluteUri))
            $nh = $next.Host.Trim('[', ']')
            $nip = $null
            if ($nh -eq $HostName -or $nh -eq $J.Ip -or $nh -eq $J.Host) { $nip = $J.Ip }
            elseif ($Cfg.FollowOffHost) {
                $nip = Resolve-One $nh
                if (-not $nip) { [void]$notes.Add("redirect host $nh did not resolve"); break }
                if (-not (Test-Allowed $nip $nh)) { Add-Err 'SCOPE' ("redirect to {0} ({1}) not followed: excluded or outside -Scope" -f $nh, $nip); break }
            }
            else { [void]$notes.Add("off-host redirect not followed: $nh"); break }
            $nt = ($next.Scheme -eq 'https')
            $hh = if ($next.IsDefaultPort) { $next.Host } else { '{0}:{1}' -f $next.Host, $next.Port }
            $n = Invoke-Fetch $nt 'GET' $next.PathAndQuery $hh $nip $next.Port $nh 0
            if (-not $n.Resp.IsHttp) { [void]$notes.Add("redirect target $($next.Authority) gave no HTTP response"); break }
            [void]$hops.Add($n); $cur = $n; $curUrl = $next.AbsoluteUri
        }
        @{ Hops = $hops; Final = $cur; Url = $url; FinalUrl = $curUrl; Chain = $chain; Locations = $locs }
    }

    function New-Row {
        $r = [ordered]@{}
        foreach ($c in $Cfg.Columns) { $r[$c] = '' }
        $r.RunId = $Cfg.RunId; $r.ScanTag = $Cfg.Tag; $r.ScannedAt = (Get-Date).ToString('s')
        $r.Host = $J.Host; $r.IP = $J.Ip; $r.Port = $J.Port; $r.State = 'open'; $r.IsWeb = $false; $r.Vhost = $false
        $r._Detections = @()
        $r
    }

    function Set-TlsFields($Row, $Sch, $RawTls, $Cert, [string]$CertSource, [string]$HostName) {
        if ($Sch -and $Sch.TlsOk) {
            $Row.TlsVersion = $Sch.TlsProtocol
            $Row.TlsCipher = '{0}-{1} {2}' -f $Sch.Cipher, $Sch.CipherBits, $Sch.Hash
            $Row.TlsKeyExchange = [string]$Sch.KeyExchange
        }
        if ($RawTls) {
            $Row.TlsSupported = $RawTls.Versions
            $Row.TlsCiphersByVersion = $RawTls.CipherByVersion
            $Row.TlsWeakCipher = $RawTls.WeakCipher
            $Row.Alpn = $RawTls.Alpn
            $Row.Http2 = $RawTls.Http2
        }
        if ($Cert) {
            $sans = @([WebInv.Der]::SubjectAltNames($Cert))
            $Row.CertSubject = $Cert.Subject; $Row.CertIssuer = $Cert.Issuer
            $Row.CertSANs = ($sans -join ';')
            $Row.CertNotBefore = $Cert.NotBefore.ToString('s'); $Row.CertNotAfter = $Cert.NotAfter.ToString('s')
            $Row.CertDaysLeft = [int][Math]::Floor(($Cert.NotAfter - (Get-Date)).TotalDays)
            $Row.CertSelfSigned = ($Cert.SubjectName.RawData.Length -gt 0 -and [Convert]::ToBase64String($Cert.SubjectName.RawData) -eq [Convert]::ToBase64String($Cert.IssuerName.RawData))
            $Row.CertSigAlg = $Cert.SignatureAlgorithm.FriendlyName
            $Row.CertKeyAlg = $Cert.PublicKey.Oid.FriendlyName
            $Row.CertKeySize = [WebInv.Util]::KeySize($Cert)
            $Row.CertSerial = $Cert.SerialNumber; $Row.CertSha1 = $Cert.Thumbprint
            $Row.CertSha256 = [WebInv.Hash]::Sha256Hex($Cert.RawData)
            $Row.CertSource = $CertSource
            if ($Sch -and $Sch.Cert) { $Row.CertPolicyErrors = [string]$Sch.CertPolicyErrors; $Row.CertChainStatus = [string]$Sch.ChainStatus }
            # hostname coverage (only meaningful when we were given a DNS name)
            $ipTmp = $null
            if (-not [Net.IPAddress]::TryParse($HostName, [ref]$ipTmp)) {
                $names = @($sans | Where-Object { $_ -like 'DNS:*' } | ForEach-Object { $_.Substring(4) })
                if ($names.Count -eq 0 -and $Cert.Subject -match 'CN=([^,]+)') { $names = @($Matches[1].Trim()) }
                $ok = $false
                foreach ($n in $names) {
                    if ($n -eq $HostName) { $ok = $true; break }
                    if ($n.StartsWith('*.') -and $HostName.EndsWith($n.Substring(1)) -and ($HostName.Split('.').Count -eq $n.Split('.').Count)) { $ok = $true; break }
                }
                $Row._CertNameOk = $ok
            }
            else { $Row._CertNameOk = $true }
        }
    }

    function Set-HttpFields($Row, $Web) {
        $first = $Web.Hops[0]; $fin = $Web.Final; $h = $fin.Resp.Headers
        $Row.IsWeb = $true
        $Row.Service = if ($first.Tls) { 'https' } else { 'http' }
        $Row.Scheme = $Row.Service
        $Row.Url = $Web.Url; $Row.FinalUrl = $Web.FinalUrl
        $Row.StatusCode = $fin.Resp.Code
        $Row.ResponseMs = $first.Raw.Ms
        $Row.ContentType = [string]$h['content-type']
        $servers = New-Object System.Collections.Generic.List[string]; $xpb = New-Object System.Collections.Generic.List[string]
        $authL = New-Object System.Collections.Generic.List[string]; $cnames = New-Object System.Collections.Generic.List[string]; $cflags = New-Object System.Collections.Generic.List[string]
        foreach ($hop in $Web.Hops) {
            foreach ($pair in $hop.Resp.List) {
                $k = $pair[0]; $v = $pair[1]
                switch ($k) {
                    'server' { if (-not $servers.Contains($v)) { [void]$servers.Add($v) } }
                    'x-powered-by' { if (-not $xpb.Contains($v)) { [void]$xpb.Add($v) } }
                    'www-authenticate' {
                        $s = ($v -split '\s+')[0]
                        if (-not $hop.Tls -and $s -match '^(?:Basic|Digest)$') { $Row._CleartextAuth = $true }
                        if ($v -match 'realm="([^"]*)"') { $s = '{0}(realm={1})' -f $s, $Matches[1] }
                        if (-not $authL.Contains($s)) { [void]$authL.Add($s) }
                    }
                    'set-cookie' {
                        $nm = (($v -split ';')[0] -split '=')[0].Trim()
                        if ($nm -and -not $cnames.Contains($nm)) {
                            [void]$cnames.Add($nm)
                            if ($hop.Tls -and $v -notmatch ';\s*secure\b') { [void]$cflags.Add(('{0}:no-Secure' -f $nm)) }
                            if ($v -notmatch ';\s*httponly\b') { [void]$cflags.Add(('{0}:no-HttpOnly' -f $nm)) }
                        }
                    }
                }
            }
        }
        $Row.Server = ($servers -join ' | '); $Row.PoweredBy = ($xpb -join ' | ')
        $text = $fin.Resp.Text
        $Row.Title = $fin.Resp.Title
        foreach ($mp in $fin.Resp.Metas) { if ($mp[0] -eq 'generator') { $Row.Generator = $mp[1]; break } }
        $Row.BodyLength = $fin.Resp.Body.Length
        $Row.BodySha256 = [WebInv.Hash]::Sha256Hex($fin.Resp.Body)
        $Row.RedirectChain = ($Web.Chain -join ' | ')
        if ($text -match '(?is)<input[^>]+type\s*=\s*["'']?password') {
            [void]$authL.Add('Form')
            # a login form is cleartext if the page or its form target is plain HTTP
            $act = if ($text -match '(?is)<form[^>]+action\s*=\s*["'']?([^"''\s>]+)') { $Matches[1] } else { '' }
            if ($act -like 'http:*' -or (-not $fin.Tls -and $act -notlike 'https:*')) { $Row._CleartextAuth = $true }
        }
        $Row.Auth = ($authL -join ';')
        $Row.Cookies = ($cnames -join ';'); $Row.CookieFlagIssues = ($cflags -join ';')
        $want = @('content-security-policy', 'x-frame-options', 'x-content-type-options')
        if ($fin.Tls) { $want += 'strict-transport-security' }
        $Row.MissingSecHeaders = (@($want | Where-Object { -not $h.ContainsKey($_) }) -join ';')
        if ($h['strict-transport-security'] -match 'max-age\s*=\s*"?(\d+)') { $Row.HstsMaxAge = $Matches[1] }
        $Row.AltSvc = [string]$h['alt-svc']
    }

    function Add-WebObs($Obs, $Web) {
        $hr = [WebInv.HttpResp[]]@(foreach ($hop in $Web.Hops) { $hop.Resp })
        [WebInv.Html]::AddWeb($Obs, $hr, [string[]]@($Web.Locations), [string]$Web.FinalUrl)
    }

    function Add-BannerObs($Obs, $Row, [string]$Banner, [byte[]]$BannerRaw) {
        if (-not $Banner) { return }
        $Obs.Add('banner', $Banner)
        $l1 = ($Banner -split "`n")[0].Trim()
        $svc = 'unknown'
        if ($l1 -match '^SSH-[\d.]+-(.+)$') { $Obs.Add('banner.ssh', $Matches[1].Trim()); $svc = 'ssh' }
        elseif ($l1 -match '^220[ -](.*)$') { $Obs.Add('banner.ftp', $Matches[1].Trim()); $Obs.Add('banner.smtp', $Matches[1].Trim()); $svc = if ($l1 -match 'SMTP|ESMTP|Postfix|Exim|Sendmail|mail') { 'smtp' } else { 'ftp' } }
        elseif ($l1 -match '^\+OK ?(.*)$') { $Obs.Add('banner.pop3', $Matches[1].Trim()); $svc = 'pop3' }
        elseif ($l1 -match '^\* OK ?(.*)$') { $Obs.Add('banner.imap', $Matches[1].Trim()); $svc = 'imap' }
        elseif ($l1 -match '^RFB \d{3}\.\d{3}') { $svc = 'vnc' }
        elseif ($l1 -match '^AMQP') { $svc = 'amqp' }
        elseif ($l1 -match '^-(?:ERR|DENIED|NOAUTH)') { $svc = 'redis?' }
        elseif ($Banner -match 'unsupported frontend protocol') { $svc = 'postgresql' }
        $mv = [WebInv.Util]::MySqlVersion($BannerRaw)
        $Row.Banner = [WebInv.Util]::Printable((($Banner -replace "`n+", ' | ').Trim(' ', '|')), 200)
        if ($mv) { $Obs.Add('banner.mysql', $mv); $svc = 'mysql'; $Row.Banner = 'MySQL handshake v10: ' + [WebInv.Util]::Printable($mv, 100) }
        $Row.Service = $svc
    }

    function Add-CertObs($Obs, $Cert, $RawTls) {
        if ($Cert) {
            $Obs.Add('cert.subject', [WebInv.Der]::GoName($Cert.SubjectName.RawData))
            $Obs.Add('cert.issuer', [WebInv.Der]::GoName($Cert.IssuerName.RawData))
            foreach ($s in [WebInv.Der]::SubjectAltNames($Cert)) { $Obs.Add('cert.san', $s) }
        }
        if ($RawTls -and $RawTls.Alpn) { $Obs.Add('alpn', $RawTls.Alpn) }
    }

    function Complete-Row($Row, $Obs) {
        $dets = [WebInv.Matcher]::Evaluate($Obs)
        $svc = New-Object System.Collections.Generic.List[string]; $tech = New-Object System.Collections.Generic.List[string]
        $cats = New-Object System.Collections.Generic.List[string]; $cpes = New-Object System.Collections.Generic.List[string]
        $os = New-Object System.Collections.Generic.List[string]; $hw = New-Object System.Collections.Generic.List[string]
        $flags = New-Object System.Collections.Generic.List[string]
        $detOut = New-Object System.Collections.Generic.List[object]
        foreach ($d in $dets) {
            if ($d.Flag) { foreach ($f in $d.Flag.Split(';')) { if ($f -and -not $flags.Contains($f)) { [void]$flags.Add($f) } } }
            if ($d.Kind -eq 'flag' -or $d.Confidence -lt $Cfg.MinConfidence -or -not $d.Name) { continue }
            $label = $d.ToString()
            switch ($d.Kind) {
                'os' { if (-not $os.Contains($label)) { [void]$os.Add($label) } }
                'hw' { if (-not $hw.Contains($label)) { [void]$hw.Add($label) } }
                default { if (-not $svc.Contains($label)) { [void]$svc.Add($label) }; if (-not $tech.Contains($d.Name)) { [void]$tech.Add($d.Name) } }
            }
            if ($d.Category -and -not $cats.Contains($d.Category)) { [void]$cats.Add($d.Category) }
            if ($d.Cpe -and -not $cpes.Contains($d.Cpe)) { [void]$cpes.Add($d.Cpe) }
            if ($Cfg.MgmtCategories -contains $d.Category -and -not $flags.Contains('MgmtInterface')) { [void]$flags.Add('MgmtInterface') }
            [void]$detOut.Add([ordered]@{ Kind = $d.Kind; Name = $d.Name; Version = $d.Version; Category = $d.Category; Confidence = $d.Confidence; Cpe = $d.Cpe; Source = $d.Source; Evidence = $d.Evidence })
        }
        $Row.Products = ($svc -join '; '); $Row.Technologies = ($tech -join ';'); $Row.Categories = ($cats -join ';')
        $Row.CPEs = ($cpes -join ';'); $Row.OsHint = ($os -join '; '); $Row.Hardware = ($hw -join '; ')
        $Row._Detections = $detOut.ToArray()

        # ---- hygiene / risk flags (observations, not exploitation) ----
        if ($Row._ExtraFlags) { foreach ($f in $Row._ExtraFlags.ToArray()) { if ($f -and -not $flags.Contains($f)) { [void]$flags.Add($f) } } }
        $weak = @(); foreach ($v in 'SSL3', 'TLS1.0', 'TLS1.1') { if ((';' + $Row.TlsSupported + ';').Contains(";$v;") -or $Row.TlsVersion -eq $v) { $weak += $v } }
        if ($weak.Count) { [void]$flags.Add('WeakTLS:' + ($weak -join '+')) }
        if ($Row.TlsWeakCipher) { [void]$flags.Add('WeakCipher:' + $Row.TlsWeakCipher) }
        if ($Row._SchannelIncompatible) { [void]$flags.Add('SchannelIncompatible') }
        if ($Row.CertSha256) {
            if ($Row.CertDaysLeft -lt 0) { [void]$flags.Add('CertExpired') } elseif ($Row.CertDaysLeft -le $Cfg.CertWarnDays) { [void]$flags.Add(('CertExpiring:{0}d' -f $Row.CertDaysLeft)) }
            if ([datetime]$Row.CertNotBefore -gt (Get-Date)) { [void]$flags.Add('CertNotYetValid') }
            if ($Row.CertSelfSigned) { [void]$flags.Add('SelfSigned') }
            if ($Row.CertSigAlg -match 'sha1|md5|md2') { [void]$flags.Add('WeakSig:' + $Row.CertSigAlg) }
            if ($Row.CertKeyAlg -eq 'RSA' -and $Row.CertKeySize -gt 0 -and $Row.CertKeySize -lt 2048) { [void]$flags.Add('WeakKey:' + $Row.CertKeySize) }
            if ($Row._CertNameOk -eq $false) { [void]$flags.Add('CertNameMismatch') }
            if ($Row.CertPolicyErrors -match 'RemoteCertificateChainErrors' -and -not $Row.CertSelfSigned) { [void]$flags.Add('CertUntrusted') }
        }
        if ($Row.IsWeb) {
            if ($Row._CleartextAuth) { [void]$flags.Add('CleartextAuth') }
            if ($Row.FinalUrl -like 'http:*' -and [int]$Row.StatusCode -ge 200 -and [int]$Row.StatusCode -lt 300) { [void]$flags.Add('PlainHttp') }
            if ($Row.RiskyMethods) { [void]$flags.Add('RiskyMethods:' + $Row.RiskyMethods) }
        }
        # ---- passive version advisories (e.g. PHP2Shell): version the server advertises vs. first fixed release ----
        $advOut = New-Object System.Collections.Generic.List[string]
        if ($Row.IsWeb -and $Cfg.Advisories) {
            $hdrs = @(([string]$Row.PoweredBy -split ' \| ') + ([string]$Row.Server -split ' \| ') | Where-Object { $_ })
            foreach ($adv in $Cfg.Advisories) {
                $hit = $null
                foreach ($h in $hdrs) { if ($h -match $adv.Regex) { $hit = @{ Ver = $Matches[1]; Suffix = $Matches[2]; Header = $h }; break } }
                $high = @($hdrs | Where-Object { $_ -match $adv.HighRisk }).Count -gt 0
                $status = $null
                if ($hit) { $status = [WebInv.Advisory]::Status($hit.Ver, [string[]]$adv.Fixed, $adv.MinBranch) }
                elseif (@($dets | Where-Object { $_.Name -eq $adv.Product -and $_.Kind -ne 'flag' }).Count) { $status = 'version-hidden' }
                if (-not $status -or $status -eq 'unknown') { continue }
                $mods = ''
                if ($high -and $status -ne 'version-hidden') { $mods += '+' + $adv.HighRiskLabel }
                if ($hit -and $hit.Suffix -and ($status -eq 'vulnerable' -or $status -eq 'eol')) { $mods += '+vendor-build' }
                switch ($status) {
                    'vulnerable' { [void]$flags.Add(('{0}:vulnerable{1}' -f $adv.Id, $mods)); $why = '{0} {1}{2} is below the fixed release for its branch' -f $adv.Product, $hit.Ver, $hit.Suffix }
                    'eol' { [void]$flags.Add(('{0}:eol-branch{1}' -f $adv.Id, $mods)); $why = '{0} {1}{2} is on a branch with no upstream fix (requires a vendor/backported build)' -f $adv.Product, $hit.Ver, $hit.Suffix }
                    'version-hidden' { [void]$flags.Add(('{0}:version-hidden' -f $adv.Id)); $why = '{0} detected but its version is not advertised; verify on the host' -f $adv.Product }
                    default { $why = '{0} {1}{2} is at or above the fixed release ({3})' -f $adv.Product, $hit.Ver, $hit.Suffix, $status }
                }
                if ($mods -like '*vendor-build*') { $why += '; vendor build suffix present - confirm the package changelog includes the fix' }
                if ($high -and $status -ne 'version-hidden') { $why += '; ' + $adv.HighRiskLabel + ' (highest-risk configuration)' }
                [void]$advOut.Add(('{0} [{1}] {2}: {3}' -f $adv.Id, $adv.Cves, $status, $why))
            }
        }
        $Row.Advisories = ($advOut -join ' || ')
        $Row.Flags = ($flags -join ';')
        if ($notes.Count) { $Row.Notes = (($notes | Select-Object -Unique) -join '; ') }
    }


    # ================================== opt-in protocol probes (WebInv extras) ==================================
    function Set-ReverseDns($RowList) {
        if (-not $Cfg.ReverseDns) { return }
        $ptr = $null
        if ($Cfg.RdnsCache.ContainsKey($J.Ip)) { $ptr = $Cfg.RdnsCache[$J.Ip] }
        else { $ptr = [WebInv.Net]::ReverseLookup($J.Ip, $Cfg.TimeoutMs); $Cfg.RdnsCache[$J.Ip] = $ptr }
        foreach ($r in $RowList) { $r.ReverseDns = [string]$ptr }
    }
    function New-ProtoRow([string]$Scheme) {
        $row = New-Row
        $row.Service = $Scheme; $row.Scheme = $Scheme
        $row.Url = '{0}://{1}:{2}' -f $Scheme, (Format-UriHost $J.Host), $J.Port
        $row._ExtraFlags = New-Object System.Collections.Generic.List[string]
        $row
    }
    # NTLM CHALLENGE target info: names, domain and the Windows build the server reports (first, unauthenticated leg)
    function Set-NtlmFields($Row, $Obs, $N) {
        if (-not $N -or -not $N.Ok) { return }
        $Row.DeviceName = if ($N.DnsComputer) { $N.DnsComputer } else { $N.NbComputer }
        $Row.Domain = if ($N.DnsDomain) { $N.DnsDomain } else { $N.NbDomain }
        foreach ($kv in @(@('ntlm.version', $N.Version), @('ntlm.computer', $N.NbComputer), @('ntlm.domain', $N.NbDomain), @('ntlm.dnscomputer', $N.DnsComputer), @('ntlm.dnsdomain', $N.DnsDomain), @('ntlm.forest', $N.DnsTree))) {
            if ($kv[1]) { $Obs.Add($kv[0], [string]$kv[1]) }
        }
        return ('ntlm: {0}' -f $N.Summary())
    }
    function Join-Info([string[]]$Parts) { (@($Parts | Where-Object { $_ }) -join '; ') }

    function Invoke-SmbCheck {
        Wait-Pace
        $r = [WebInv.Smb]::Probe($J.Ip, $J.Port, $Cfg.TimeoutMs)
        $stats.Requests += $r.Probes
        $obs = New-Object WebInv.Observation; $obs.Port = $J.Port
        $row = New-ProtoRow 'smb'
        if (-not $r.Smb2 -and $r.Smb1 -ne 'enabled') {
            $row.Service = 'unknown'; $row.Scheme = 'unknown'; $row.Url = 'tcp://{0}:{1}' -f (Format-UriHost $J.Host), $J.Port
            [void]$notes.Add(('no SMB answer ({0})' -f $r.Error))
            Add-Log ('smb: {0}' -f $r.Error)
        }
        else {
            $ntlm = Set-NtlmFields $row $obs $r.Ntlm
            if ($r.NativeOs) { $obs.Add('smb.nativeos', $r.NativeOs) }
            if ($r.NativeLm) { $obs.Add('smb.nativelm', $r.NativeLm) }
            $osb = if ($r.Ntlm.Ok -and $r.Ntlm.Version) { 'osBuild=' + $r.Ntlm.Version } else { '' }
            $row.ProtocolInfo = Join-Info @($r.Summary(), $osb)
            if ($r.Smb1 -eq 'enabled') { [void]$row._ExtraFlags.Add('SMBv1') }
            if (-not $r.SigningRequired) { [void]$row._ExtraFlags.Add('SMBSigningNotRequired') }
            if ($ntlm) { Add-Log $ntlm }
            if ($r.Error) { Add-Log ('smb: {0}' -f $r.Error) }
        }
        Complete-Row $row $obs
        [void]$rows.Add($row)
    }

    function Invoke-RdpCheck {
        Wait-Pace
        $r = [WebInv.Rdp]::Probe($J.Ip, $J.Port, $J.Host, $Cfg.TimeoutMs, $(if ($Cfg.SslProto) { $Cfg.SslProto } else { 0 }))
        $stats.Requests += $r.Probes
        $obs = New-Object WebInv.Observation; $obs.Port = $J.Port
        $row = New-ProtoRow 'rdp'
        if (-not $r.IsRdp) {
            $row.Service = 'unknown'; $row.Scheme = 'unknown'; $row.Url = 'tcp://{0}:{1}' -f (Format-UriHost $J.Host), $J.Port
            [void]$notes.Add(('no RDP answer ({0})' -f $r.Error))
        }
        else {
            $cert = $null
            if ($r.CertDer) {
                try { $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$r.CertDer) } catch { Add-Log ('rdp certificate parse failed: {0}' -f $_.Exception.Message) }
            }
            if ($cert) {
                Set-TlsFields $row $null $null $cert 'rdp' $J.Host
                $row.CertPolicyErrors = $r.PolicyErrors; $row.CertChainStatus = $r.ChainStatus
                Add-CertObs $obs $cert $null
            }
            if ($r.TlsProtocol) { $row.TlsVersion = ($r.TlsProtocol -replace '^Tls13$', 'TLS1.3' -replace '^Tls12$', 'TLS1.2' -replace '^Tls11$', 'TLS1.1' -replace '^Tls$', 'TLS1.0' -replace '^Ssl3$', 'SSL3') }
            $ntlm = Set-NtlmFields $row $obs $r.Ntlm
            $osb = if ($r.Ntlm.Ok -and $r.Ntlm.Version) { 'osBuild=' + $r.Ntlm.Version } else { '' }
            $row.ProtocolInfo = Join-Info @($r.Summary(), $osb)
            if ($r.Nla -eq 'not required') { [void]$row._ExtraFlags.Add('RdpNlaNotRequired') }
            if ($r.StandardRdp -eq 'accepted') { [void]$row._ExtraFlags.Add('RdpStandardSecurity') }
            if ($ntlm) { Add-Log $ntlm }
            if ($r.Error) { Add-Log ('rdp: {0}' -f $r.Error) }
        }
        Complete-Row $row $obs
        [void]$rows.Add($row)
    }

    function Invoke-SnmpCheck {
        Wait-Pace
        $r = [WebInv.Snmp]::Query($J.Ip, $J.Port, $Cfg.TimeoutMs, $Cfg.Retries, $Cfg.Snmp, [WebInv.Snmp]::SystemOids)
        $stats.Requests += $r.Probes
        $result.State = $r.State
        if ($r.State -ne 'open') { if ($r.Error -and $r.State -eq 'error') { Add-Err 'SNMP' $r.Error }; return }
        $obs = New-Object WebInv.Observation; $obs.Port = $J.Port
        $row = New-ProtoRow 'snmp'
        $descr = $r.Get('1.3.6.1.2.1.1.1.0'); $oid = $r.Get('1.3.6.1.2.1.1.2.0'); $name = $r.Get('1.3.6.1.2.1.1.5.0'); $loc = $r.Get('1.3.6.1.2.1.1.6.0')
        if ($descr) { $obs.Add('snmp.sysdescr', $descr); $row.Banner = [WebInv.Util]::Printable(($descr -replace '\s*[\r\n]+\s*', ' | '), 300) }
        if ($oid) { $obs.Add('snmp.sysobjid', $oid) }
        if ($name) { $row.DeviceName = [WebInv.Util]::Printable($name, 200) }
        $ver = if ($r.Version -eq '3') { 'v3' } else { 'v' + $r.Version }
        $eng = if ($r.EngineId) { 'engineId=' + $r.EngineId } else { '' }
        $row.ProtocolInfo = Join-Info @(('version=' + $ver), $(if ($oid) { 'sysObjectID=' + $oid }), $(if ($loc) { 'location=' + [WebInv.Util]::Printable($loc, 200) }), $eng)
        if ($r.Error) { [void]$notes.Add(('snmp: {0}' -f $r.Error)); Add-Err 'SNMP' ('agent answered, query failed: {0}' -f $r.Error) }
        if ($r.Version -ne '3') { [void]$row._ExtraFlags.Add('SnmpV1V2c') }
        Complete-Row $row $obs
        [void]$rows.Add($row)
    }

    # JARM (10 handshakes, retried once if one of them timed out) + JA4S from the raw TLS scan's first ServerHello
    function Add-TlsFingerprint($Row, $Obs, $RawTls) {
        if ($Cfg.Ja4s -and $RawTls -and $RawTls.HelloInfo) {
            $Row.Ja4s = [WebInv.Ja4s]::FromHelloInfo($RawTls.HelloInfo)
            if ($Row.Ja4s) { $Obs.Add('tls.ja4s', $Row.Ja4s) }
        }
        $raw = $null; $n = 0; $jarm = ''
        for ($a = 0; $a -lt 2; $a++) {
            Wait-Pace
            $jarm = [WebInv.Jarm]::Compute($J.Ip, $J.Port, $J.Host, $Cfg.TimeoutMs, [ref]$raw, [ref]$n)
            $stats.Requests += $n
            if ($raw -ne [WebInv.Jarm]::Empty) { break }
        }
        $Row.Jarm = $jarm
        if ($raw -eq [WebInv.Jarm]::Empty) { Add-Log 'jarm: a probe timed out (twice); JARM is all zeros as defined by JARM' }
        else { $Obs.Add('tls.jarm', $jarm) }
    }

    # ================================== one check ==================================
    function Invoke-Check([string]$JobLine) {
    $jp = $JobLine.Split("`t")
    $J = @{ Host = $jp[0]; Ip = $jp[1]; Port = [int]$jp[2]; Scheme = $jp[3] }
    $TargetId = '{0}({1}):{2}' -f $J.Host, $J.Ip, $J.Port
    $logs = New-Object System.Collections.Generic.List[string]
    $errs = New-Object System.Collections.Generic.List[object]
    $rows = New-Object System.Collections.Generic.List[object]
    $stats = @{ Requests = 0 }
    $notes = New-Object System.Collections.Generic.List[string]
    $result = @{ State = 'error'; Target = $TargetId; Rows = $rows; Logs = $logs; Errors = $errs; Requests = 0; Ms = 0 }   # helpers read $TargetId via dynamic scope
    $swJob = [Diagnostics.Stopwatch]::StartNew()
    try {
        if ($J.Scheme -eq 'snmp') { Invoke-SnmpCheck; Set-ReverseDns $rows; return $result }
        # ---- 1. port state: TCP connect with retries on silence (filtered) ----
        $state = 'filtered'
        for ($a = 0; $a -le $Cfg.Retries; $a++) {
            $st = $null
            $c = [WebInv.Net]::Connect($J.Ip, $J.Port, $Cfg.TimeoutMs, [ref]$st)
            [WebInv.Net]::SafeClose($c)
            $state = $st
            if ($st -ne 'filtered') { break }
        }
        $result.State = $state
        if ($state -eq 'error') {
            if ($Cfg.Proxy) { Add-Err 'PROXY' 'the proxy refused or failed the CONNECT (reason in the run log summary); check not completed, re-run with -Resume' }
            else { Add-Err 'NET' 'connect not attempted: local socket resources exhausted (ephemeral ports or buffers) even after backing off; re-run with -Resume' }
        }
        if ($state -ne 'open') { return $result }
        if ($J.Scheme -eq 'smb' -or $J.Scheme -eq 'rdp') {
            if ($J.Scheme -eq 'smb') { Invoke-SmbCheck } else { Invoke-RdpCheck }
            Set-ReverseDns $rows
            $result.State = 'open'
            return $result
        }

        # ---- 2. protocol detection ----
        $tlsHint = $Cfg.TlsPorts -contains $J.Port
        $tlsFirst = ($J.Scheme -eq 'https') -or ($tlsHint -and $J.Scheme -ne 'http')
        $bw = 0
        if ($Cfg.BannerWaitMs -gt 0 -and -not ($Cfg.HttpPorts -contains $J.Port) -and -not $J.Scheme) { $bw = $Cfg.BannerWaitMs }
        $order = if ($tlsFirst) { @($true, $false) } else { @($false, $true) }
        if ($J.Scheme -eq 'https') { $order = @($true) } elseif ($J.Scheme -eq 'http') { $order = @($false) }
        $final = $null; $sch = $null; $fb400 = $null; $banner = ''; $bannerRaw = $null; $serverFirst = $false; $tlsHsFail = $false; $silentN = 0
        foreach ($t in $order) {
            $f = Invoke-Fetch $t 'GET' '/' (Get-HostHdr $J.Host $J.Port $t) $J.Ip $J.Port $J.Host $(if ($t) { 0 } else { $bw })
            # silence: the listener accepted but sent nothing at all before the receive timeout (tarpit / SYN-proxy firewall)
            if ($f.Raw.State -eq 'open' -and $f.Raw.TimedOut -and $f.Raw.BytesIn -eq 0 -and -not $f.Raw.ServerFirst -and ($t -eq [bool]$f.Raw.TlsError)) { $silentN++ }
            if ($t) {
                if ($f.Raw.TlsOk -and -not ($sch -and $sch.TlsOk)) { $sch = $f.Raw }
                elseif (-not $sch -and $f.Raw.Cert) { $sch = $f.Raw }
                if ($f.Raw.State -eq 'open' -and $f.Raw.TlsError) { $tlsHsFail = $true }
            }
            if (-not $t -and $f.Raw.ServerFirst) { $serverFirst = $true; $bannerRaw = $f.Raw.Raw; $banner = $f.Resp.Banner; break }
            if ($f.Resp.IsHttp) {
                # A plaintext 400 is often a TLS listener complaining (nginx/Apache/Go strings) - always try TLS before settling for it
                if (-not $t -and $f.Resp.Code -eq 400 -and $order.Count -gt 1) {
                    if (Test-TlsMismatch $f.Resp.Text) { [void]$notes.Add('plain-HTTP-to-TLS-port 400; switched to TLS') }
                    $fb400 = $f; continue
                }
                $final = $f; break
            }
            if (-not $t -and $f.Resp.Banner) { $banner = $f.Resp.Banner; $bannerRaw = $f.Raw.Raw }
        }
        if (-not $final -and $fb400) { $final = $fb400 }

        # ---- 3. raw TLS handshakes (independent of local Schannel policy) ----
        $rawTls = $null
        $plainWeb = ($final -and -not $final.Tls -and -not $tlsHsFail)
        # silent to both plain HTTP and Schannel: still send every raw TLS probe, but concurrently (1 timeout instead of 5)
        $silent = ($order.Count -ge 2 -and $silentN -eq $order.Count)
        if ($silent) { Add-Log 'silent listener (no bytes to HTTP or TLS before timeout); raw TLS probes sent in parallel' }
        if (-not $Cfg.NoTlsScan -and -not $serverFirst -and -not $plainWeb -and (($sch -and $sch.TlsOk) -or $tlsHsFail)) {
            Wait-Pace
            $rawTls = [WebInv.Tls]::Scan($J.Ip, $J.Port, $J.Host, $Cfg.TimeoutMs, $true, $silent)
            $stats.Requests += $rawTls.Probes
            if ($rawTls.Errors) { Add-Log ('tls-scan: {0}' -f $rawTls.Errors) }
            if ($rawTls.Errors -match ':connect error') { [void]$notes.Add('incomplete: local socket resources exhausted, some requests not sent'); Add-Err 'NET' 'raw TLS probe not sent: local socket resources exhausted' }
        }
        $cert = $null; $certSource = ''
        if ($sch -and $sch.Cert) { $cert = $sch.Cert; $certSource = 'schannel' }
        elseif ($rawTls -and $rawTls.CertDer) {
            try { $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$rawTls.CertDer); $certSource = 'raw-' + $rawTls.CertSourceVersion }
            catch { Add-Log ('raw certificate parse failed: {0}' -f $_.Exception.Message) }
        }
        $schOk = ($sch -and $sch.TlsOk)
        $isTls = $schOk -or ($rawTls -and $rawTls.IsTls)

        # ---- 4. build row ----
        $row = New-Row
        $row._SchannelIncompatible = (-not $schOk -and $rawTls -and $rawTls.IsTls -and $rawTls.Versions)
        Set-TlsFields $row $sch $rawTls $cert $certSource $J.Host
        $obs = New-Object WebInv.Observation
        $obs.Port = $J.Port
        $web = $null
        if ($final) {
            $web = Get-RedirectChain $final $J.Host
            Set-HttpFields $row $web
            Add-WebObs $obs $web
            $fin = $web.Final
            $origin = New-Object System.Uri $web.FinalUrl
            $oTls = ($origin.Scheme -eq 'https')
            $oIp = $fin.Ip; $oPort = $origin.Port; $oSni = $fin.Sni; $oHost = $fin.HostHdr

            # ---- 5. favicon: <link rel=icon> first, then /favicon.ico; data: URIs decoded inline; same host only ----
            if (-not $Cfg.NoFavicon) {
                $icoBytes = $null; $href = '/favicon.ico'
                foreach ($m in [regex]::Matches($fin.Resp.Text, '(?is)<link\b[^>]*>')) {
                    if ($m.Value -match '(?is)\brel\s*=\s*["'']?[^"''>]*\bicon\b' -and $m.Value -match '(?is)\bhref\s*=\s*["'']?([^"''\s>]+)') { $href = [Net.WebUtility]::HtmlDecode($Matches[1]); break }
                }
                if ($href -like 'data:*;base64,*') {
                    try { $icoBytes = [Convert]::FromBase64String($href.Substring($href.IndexOf(',') + 1)); $row.FaviconPath = 'data-uri' } catch { }
                }
                else {
                    foreach ($cand in (@($href, '/favicon.ico') | Select-Object -Unique)) {
                        try { $u = New-Object System.Uri($origin, $cand) } catch { continue }
                        if ($u.Host -ne $origin.Host -or $u.Port -ne $origin.Port) { [void]$notes.Add("favicon on other host not fetched ($($u.Authority))"); continue }
                        $fv = Invoke-Fetch ($u.Scheme -eq 'https') 'GET' $u.PathAndQuery $oHost $oIp $u.Port $oSni 0
                        if ($fv.Resp.Code -eq 200 -and $fv.Resp.Body.Length -gt 0 -and [string]$fv.Resp.Headers['content-type'] -notmatch 'text/html') { $icoBytes = $fv.Resp.Body; $row.FaviconPath = $u.AbsolutePath; break }
                    }
                }
                if ($icoBytes -and $icoBytes.Length -gt 0) {
                    $row.FaviconMmh3 = [WebInv.Hash]::FaviconHash($icoBytes)
                    $row.FaviconMd5 = [WebInv.Hash]::Md5Hex($icoBytes)
                    $obs.Add('favicon.mmh3', [string]$row.FaviconMmh3); $obs.Add('favicon.md5', $row.FaviconMd5)
                }
            }

            # ---- 6. small safe extras: robots.txt, security.txt (RFC 9116), one random-path 404 (nmap FourOhFourRequest) ----
            if (-not $Cfg.NoExtras) {
                $rb = Invoke-Fetch $oTls 'GET' '/robots.txt' $oHost $oIp $oPort $oSni 0
                if ($rb.Resp.Code -eq 200 -and $rb.Resp.Text -match '(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:') {
                    $row.Robots = 'disallow={0};sitemap={1}' -f ([regex]::Matches($rb.Resp.Text, '(?im)^\s*disallow\s*:')).Count, ($rb.Resp.Text -match '(?im)^\s*sitemap\s*:')
                    $obs.Add('robots', $(if ($rb.Resp.Text.Length -gt 8192) { $rb.Resp.Text.Substring(0, 8192) } else { $rb.Resp.Text }))
                }
                $sx = Invoke-Fetch $oTls 'GET' '/.well-known/security.txt' $oHost $oIp $oPort $oSni 0
                if ($sx.Resp.Code -eq 200 -and $sx.Resp.Text -match '(?im)^\s*Contact\s*:\s*(.+)$') { $row.SecurityTxt = [WebInv.Util]::Printable($Matches[1].Trim(), 200) }
                $rnd = '/wi-{0}.html' -f ([guid]::NewGuid().ToString('N').Substring(0, 10))
                $nf = Invoke-Fetch $oTls 'GET' $rnd $oHost $oIp $oPort $oSni 0
                if ($nf.Resp.IsHttp) {
                    if ($nf.Resp.Code -eq 200) { [void]$notes.Add('catch-all 200 for unknown paths') }
                    foreach ($pair in $nf.Resp.List) { if ($pair[0] -eq 'server' -or $pair[0] -eq 'x-powered-by') { Add-HeaderObs $obs '' $pair[0] $pair[1] } }
                    if ($nf.Resp.Text) { $obs.Add('body', $(if ($nf.Resp.Text.Length -gt 32768) { $nf.Resp.Text.Substring(0, 32768) } else { $nf.Resp.Text })) }
                }
            }

            # ---- 7. optional OPTIONS (nmap http-methods equivalent) ----
            if ($Cfg.Options) {
                $op = Invoke-Fetch $oTls 'OPTIONS' '/' $oHost $oIp $oPort $oSni 0
                $allow = (@($op.Resp.Headers['allow'], $op.Resp.Headers['public']) | Where-Object { $_ }) -join ','
                $m = @($allow -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique)
                $row.AllowedMethods = ($m -join ','); $row.RiskyMethods = (@($m | Where-Object { @('GET', 'HEAD', 'POST', 'OPTIONS') -notcontains $_ }) -join ',')
            }

            # ---- 8. optional identification paths (fixed list, GET only) ----
            if ($Cfg.IdentifyPaths) {
                $hits = New-Object System.Collections.Generic.List[string]
                foreach ($p in $Cfg.PathList) {
                    $pr = Invoke-Fetch $oTls 'GET' $p $oHost $oIp $oPort $oSni 0
                    if (-not $pr.Resp.IsHttp) { continue }
                    Add-BodyObs $obs ('path:{0}.' -f $p) $pr.Resp
                    if ($pr.Resp.Code -ne 404) { [void]$hits.Add(('{0}={1}' -f $p, $pr.Resp.Code)) }
                }
                $row.IdentifiedPaths = ($hits -join ';')
            }
        }
        elseif ($banner) { Add-BannerObs $obs $row $banner $bannerRaw }
        elseif ($isTls) { $row.Service = 'tls'; $row.Scheme = 'tls' }
        else { $row.Service = 'unknown'; $row.Scheme = 'unknown' }
        if (-not $row.Url) { $row.Url = '{0}://{1}:{2}' -f $(if ($row.Scheme) { $row.Scheme } else { 'tcp' }), (Format-UriHost $J.Host), $J.Port }
        if ($row._SchannelIncompatible) {
            [void]$notes.Add(("TLS handshake refused by this host's Schannel policy; server supports {0}" -f $rawTls.Versions))
            Add-Err 'TLS' ("Schannel could not negotiate (server offers {0}); HTTP layer not inspected. {1}" -f $rawTls.Versions, $sch.TlsError)
        }
        Add-CertObs $obs $cert $rawTls
        if ($Cfg.TlsFingerprint -and $isTls) { Add-TlsFingerprint $row $obs $rawTls }
        Complete-Row $row $obs
        [void]$rows.Add($row)

        # ---- 9. optional SAN virtual-host probing (same IP only => stays inside scope) ----
        if ($Cfg.ProbeSans -and $row.IsWeb -and $cert) {
            $base = '{0}|{1}|{2}' -f $row.StatusCode, $row.Title, $row.BodySha256
            $cands = New-Object System.Collections.Generic.List[string]
            foreach ($s in [WebInv.Der]::SubjectAltNames($cert)) {
                if ($s -notlike 'DNS:*') { continue }
                $n = $s.Substring(4).TrimEnd('.')
                if ($n.StartsWith('*') -or $n -eq $J.Host -or $cands.Contains($n)) { continue }
                [void]$cands.Add($n)
                if ($cands.Count -ge $Cfg.MaxSans) { break }
            }
            foreach ($n in $cands) {
                $vip = Resolve-One $n
                if ($vip -ne $J.Ip) { continue }
                if (-not (Test-Allowed $vip $n)) { continue }
                # the same vhost is reachable from several jobs (IP target + hostname target): emit it once per IP:port
                $vk = '{0}|{1}|{2}' -f $n.ToLowerInvariant(), $J.Ip, $J.Port
                $claimed = $false
                [System.Threading.Monitor]::Enter($Cfg.VhostSeen.SyncRoot)
                try { if (-not $Cfg.VhostSeen.ContainsKey($vk)) { $Cfg.VhostSeen[$vk] = $true; $claimed = $true } }
                finally { [System.Threading.Monitor]::Exit($Cfg.VhostSeen.SyncRoot) }
                if (-not $claimed) { continue }
                $vtls = ($row.Scheme -eq 'https')
                $vf = Invoke-Fetch $vtls 'GET' '/' (Get-HostHdr $n $J.Port $vtls) $J.Ip $J.Port $n 0
                if (-not $vf.Resp.IsHttp) { continue }
                $vweb = Get-RedirectChain $vf $n
                $vrow = New-Row
                $vrow.Host = $n; $vrow.Vhost = $true; $vrow.VhostOf = $J.Host
                $vcert = if ($vf.Raw.Cert) { $vf.Raw.Cert } else { $cert }
                Set-TlsFields $vrow $vf.Raw $rawTls $vcert $(if ($vf.Raw.Cert) { 'schannel' } else { $certSource }) $n
                Set-HttpFields $vrow $vweb
                $sig = '{0}|{1}|{2}' -f $vrow.StatusCode, $vrow.Title, $vrow.BodySha256
                if ($sig -eq $base) { continue }
                $vobs = New-Object WebInv.Observation; $vobs.Port = $J.Port
                Add-WebObs $vobs $vweb
                Add-CertObs $vobs $vcert $rawTls
                Complete-Row $vrow $vobs
                [void]$rows.Add($vrow)
            }
        }

        # ---- 10. optional reverse DNS (cached across workers) ----
        Set-ReverseDns $rows
        $result.State = 'open'
    }
    catch {
        Add-Err 'WORKER' ('unhandled: {0} @ line {1}' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber)
        $result.State = 'error'
    }
    finally {
        $result.Requests = $stats.Requests
        $result.Ms = $swJob.ElapsedMilliseconds
    }
    $result
    }

    # ================================== worker loop ==================================
    while ($true) {
        $jl = $Sched.Take($WorkerId)
        if ($null -eq $jl) { break }
        $res = $null
        try { foreach ($o in @(Invoke-Check $jl)) { if ($o -is [hashtable] -and $o.ContainsKey('Rows')) { $res = $o } } }
        catch { $res = $null; $crash = $_.Exception.Message }
        if (-not $res) {
            $p = $jl.Split("`t")
            $res = @{ State = 'error'; Rows = @(); Logs = @(); Requests = 0; Ms = 0
                Errors = @(, @('WORKER', ('{0}({1}):{2}' -f $p[0], $p[1], $p[2]), ('worker failed: {0}' -f $(if ($crash) { $crash } else { 'no result' })))) }
        }
        $crash = $null
        [void]$Sched.Done($WorkerId, $jl, $res)
    }
}
#endregion


#region ---------- Extras: opt-in probes and screenshots (compiled only when a run uses one of them) ----------
$ExtrasSource = @'

// ============================================================================
// WebInv extras - opt-in identification probes, compiled only when a run enables one of them
// (-TlsFingerprint, -Smb, -Rdp, -Snmp, -Screenshot). C# 5 / .NET Framework 4.7.2. No credentials are ever guessed:
// SMB and RDP stop after the server's NTLM challenge (the first, unauthenticated leg); SNMP uses only the community
// or v3 user the operator supplies.
//   JARM  - port of salesforce/jarm 1.0 (BSD 3-Clause, Copyright (c) 2020 salesforce.com, inc.)
//   JA4S  - FoxIO JA4+ method (FoxIO License 1.1: internal, non-monetised use; https://github.com/FoxIO-LLC/ja4)
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;

    public delegate TcpClient TcpConnector(string ip, int port, int timeoutMs, out string state);

    public static class Extras
    {
        public const string Version = "2.3.1";
        // set to WebInv.Net.Connect, so these probes share the scanner's connect semantics and its CONNECT proxy
        public static TcpConnector Connect;
        static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        // binds Connect to WebInv.Net.Connect of the scan engine loaded in this AppDomain (no compile-time reference:
        // the engine is an in-memory Add-Type assembly)
        public static bool BindEngine()
        {
            foreach (System.Reflection.Assembly a in AppDomain.CurrentDomain.GetAssemblies())
            {
                Type t;
                try { t = a.GetType("WebInv.Net", false); } catch (Exception) { continue; }
                if (t == null) continue;
                System.Reflection.MethodInfo mi = t.GetMethod("Connect", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static, null,
                    new Type[] { typeof(string), typeof(int), typeof(int), typeof(string).MakeByRefType() }, null);
                if (mi == null) continue;
                Connect = (TcpConnector)Delegate.CreateDelegate(typeof(TcpConnector), mi);
                return true;
            }
            return false;
        }

        internal static TcpClient Open(string ip, int port, int timeoutMs, out string state)
        {
            if (Connect != null) return Connect(ip, port, timeoutMs, out state);
            TcpClient c = new TcpClient(ip.IndexOf(':') >= 0 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
            try
            {
                IAsyncResult ar = c.BeginConnect(ip, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) { state = "filtered"; c.Close(); return null; }
                c.EndConnect(ar); state = "open"; return c;
            }
            catch (SocketException se) { state = se.SocketErrorCode == SocketError.ConnectionRefused ? "closed" : "filtered"; c.Close(); return null; }
        }
        internal static void Close(TcpClient c) { try { if (c != null) c.Close(); } catch { } }
        internal static byte[] Random(int n) { byte[] b = new byte[n]; lock (Rng) Rng.GetBytes(b); return b; }
        internal static bool ReadExact(Stream s, byte[] b, int off, int n)
        {
            while (n > 0) { int r = s.Read(b, off, n); if (r <= 0) return false; off += r; n -= r; }
            return true;
        }
        internal static string Hex(byte[] b, int off, int n)
        {
            StringBuilder sb = new StringBuilder(n * 2);
            for (int i = 0; i < n && off + i < b.Length; i++) sb.Append(b[off + i].ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }
        internal static string Sha256Hex(string s)
        {
            byte[] d = Encoding.UTF8.GetBytes(s);
            try { using (IncrementalHash h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)) { h.AppendData(d); return Hex(h.GetHashAndReset(), 0, 32); } }
            catch (Exception) { using (HashAlgorithm h = (HashAlgorithm)CryptoConfig.CreateFromName("System.Security.Cryptography.SHA256CryptoServiceProvider")) return Hex(h.ComputeHash(d), 0, 32); }
        }
        internal static ushort U16(byte[] b, int o) { return (ushort)(b[o] | (b[o + 1] << 8)); }
        internal static uint U32(byte[] b, int o) { return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)); }
        internal static void W16(MemoryStream m, int v) { m.WriteByte((byte)v); m.WriteByte((byte)(v >> 8)); }
        internal static void W32(MemoryStream m, uint v) { m.WriteByte((byte)v); m.WriteByte((byte)(v >> 8)); m.WriteByte((byte)(v >> 16)); m.WriteByte((byte)(v >> 24)); }
        internal static void WB(MemoryStream m, byte[] b) { m.Write(b, 0, b.Length); }
        internal static int IndexOf(byte[] hay, byte[] needle, int start)
        {
            for (int i = Math.Max(0, start); i + needle.Length <= hay.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }
        // reads whatever arrives within the timeout, up to max bytes, stopping early once 'enough' says so
        internal static byte[] ReadSome(Stream s, int max, int timeoutMs, Func<byte[], int, bool> enough, out bool timedOut)
        {
            byte[] buf = new byte[max]; int n = 0; timedOut = false;
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                while (n < max)
                {
                    int r = s.Read(buf, n, max - n);
                    if (r <= 0) break;
                    n += r;
                    if (enough != null && enough(buf, n)) break;
                    if (sw.ElapsedMilliseconds > timeoutMs) break;
                }
            }
            catch (IOException) { timedOut = n == 0; }
            catch (ObjectDisposedException) { }
            byte[] o = new byte[n]; Buffer.BlockCopy(buf, 0, o, 0, n); return o;
        }
    }

    // ------------------------------------------------------------------ JARM (10 ClientHellos, fuzzy hash of the replies)
    public static class Jarm
    {
        static readonly ushort[] AllCiphers = { 0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a,
            0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301, 0xcc14, 0xc007, 0xc012, 0xc013,
            0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304, 0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0,
            0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005 };
        static readonly ushort[] No13Ciphers = { 0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a,
            0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f,
            0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1,
            0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005 };
        static readonly ushort[] HashOrder = { 0x0004, 0x0005, 0x0007, 0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039, 0x003c, 0x003d, 0x0041, 0x0045, 0x0067, 0x006b, 0x0084,
            0x0088, 0x009a, 0x009c, 0x009d, 0x009e, 0x009f, 0x00ba, 0x00be, 0x00c0, 0x00c4, 0xc007, 0xc008, 0xc009, 0xc00a, 0xc011, 0xc012, 0xc013, 0xc014, 0xc023, 0xc024,
            0xc027, 0xc028, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xc060, 0xc061, 0xc072, 0xc073, 0xc076, 0xc077, 0xc09c, 0xc09d, 0xc09e, 0xc09f, 0xc0a0, 0xc0a1, 0xc0a2, 0xc0a3,
            0xc0ac, 0xc0ad, 0xc0ae, 0xc0af, 0xcc13, 0xcc14, 0xcca8, 0xcca9, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305 };
        static readonly string[] AlpnAll = { "http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq" };
        static readonly string[] AlpnRare = { "http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq" };
        // version, cipher list, cipher order, grease, alpn, supported_versions, extension order (jarm.py main())
        static readonly string[][] Queue = {
            new[] { "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE" },
            new[] { "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD" },
            new[] { "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD" },
            new[] { "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD" },
            new[] { "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE" },
            new[] { "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD" },
            new[] { "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE" },
            new[] { "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD" },
            new[] { "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD" },
            new[] { "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE" } };
        static readonly ushort[] Grease = { 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa };
        public const string Empty = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||";

        public static List<T> Mung<T>(List<T> c, string req)
        {
            List<T> o = new List<T>();
            int n = c.Count;
            if (req == "REVERSE") { for (int i = n - 1; i >= 0; i--) o.Add(c[i]); }
            else if (req == "BOTTOM_HALF") { for (int i = (n % 2 == 1) ? n / 2 + 1 : n / 2; i < n; i++) o.Add(c[i]); }
            else if (req == "TOP_HALF") { if (n % 2 == 1) o.Add(c[n / 2]); o.AddRange(Mung(Mung(c, "REVERSE"), "BOTTOM_HALF")); }
            else if (req == "MIDDLE_OUT")
            {
                int m = n / 2;
                if (n % 2 == 1) { o.Add(c[m]); for (int i = 1; i <= m; i++) { o.Add(c[m + i]); o.Add(c[m - i]); } }
                else for (int i = 1; i <= m; i++) { o.Add(c[m - 1 + i]); o.Add(c[m - i]); }
            }
            else o.AddRange(c);
            return o;
        }

        static void U16(MemoryStream m, int v) { m.WriteByte((byte)(v >> 8)); m.WriteByte((byte)v); }

        public static byte[] Build(string[] d, string host)
        {
            string ver = d[0];
            MemoryStream ch = new MemoryStream();
            int rec, hello;
            if (ver == "TLS_1.3") { rec = 0x0301; hello = 0x0303; } else if (ver == "TLS_1.1") { rec = 0x0302; hello = 0x0302; } else { rec = 0x0303; hello = 0x0303; }
            U16(ch, hello);
            Extras.WB(ch, Extras.Random(32));
            byte[] sid = Extras.Random(32);
            ch.WriteByte(32); Extras.WB(ch, sid);
            bool grease = d[3] == "GREASE";
            List<ushort> cs = new List<ushort>(d[1] == "ALL" ? AllCiphers : No13Ciphers);
            if (d[2] != "FORWARD") cs = Mung(cs, d[2]);
            if (grease) cs.Insert(0, PickGrease());
            U16(ch, cs.Count * 2);
            foreach (ushort c in cs) U16(ch, c);
            ch.WriteByte(1); ch.WriteByte(0);
            byte[] ext = Extensions(d, host, grease);
            U16(ch, ext.Length); Extras.WB(ch, ext);
            byte[] body = ch.ToArray();
            MemoryStream hs = new MemoryStream();
            hs.WriteByte(1); hs.WriteByte(0); U16(hs, body.Length); Extras.WB(hs, body);
            byte[] hsb = hs.ToArray();
            MemoryStream p = new MemoryStream();
            p.WriteByte(0x16); U16(p, rec); U16(p, hsb.Length); Extras.WB(p, hsb);
            return p.ToArray();
        }
        static ushort PickGrease() { return Grease[Extras.Random(1)[0] % Grease.Length]; }

        static byte[] Extensions(string[] d, string host, bool grease)
        {
            MemoryStream e = new MemoryStream();
            if (grease) { U16(e, PickGrease()); U16(e, 0); }
            byte[] h = Encoding.UTF8.GetBytes(host ?? "");
            U16(e, 0x0000); U16(e, h.Length + 5); U16(e, h.Length + 3); e.WriteByte(0); U16(e, h.Length); Extras.WB(e, h);
            Extras.WB(e, new byte[] { 0x00, 0x17, 0x00, 0x00 });                       // extended_master_secret
            Extras.WB(e, new byte[] { 0x00, 0x01, 0x00, 0x01, 0x01 });                 // max_fragment_length
            Extras.WB(e, new byte[] { 0xff, 0x01, 0x00, 0x01, 0x00 });                 // renegotiation_info
            Extras.WB(e, new byte[] { 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19 });   // supported_groups
            Extras.WB(e, new byte[] { 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 });           // ec_point_formats
            Extras.WB(e, new byte[] { 0x00, 0x23, 0x00, 0x00 });                       // session_ticket
            List<string> alpns = new List<string>(d[4] == "RARE_APLN" ? AlpnRare : AlpnAll);
            if (d[6] != "FORWARD") alpns = Mung(alpns, d[6]);
            MemoryStream al = new MemoryStream();
            foreach (string a in alpns) { byte[] ab = Encoding.ASCII.GetBytes(a); al.WriteByte((byte)ab.Length); Extras.WB(al, ab); }
            byte[] alb = al.ToArray();
            U16(e, 0x0010); U16(e, alb.Length + 2); U16(e, alb.Length); Extras.WB(e, alb);
            Extras.WB(e, new byte[] { 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01 });
            MemoryStream ks = new MemoryStream();
            if (grease) { U16(ks, PickGrease()); Extras.WB(ks, new byte[] { 0x00, 0x01, 0x00 }); }
            U16(ks, 0x001d); U16(ks, 32); Extras.WB(ks, Extras.Random(32));
            byte[] ksb = ks.ToArray();
            U16(e, 0x0033); U16(e, ksb.Length + 2); U16(e, ksb.Length); Extras.WB(e, ksb);
            Extras.WB(e, new byte[] { 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01 });           // psk_key_exchange_modes
            if (d[0] == "TLS_1.3" || d[5] == "1.2_SUPPORT")
            {
                List<ushort> tv = new List<ushort>(d[5] == "1.2_SUPPORT" ? new ushort[] { 0x0301, 0x0302, 0x0303 } : new ushort[] { 0x0301, 0x0302, 0x0303, 0x0304 });
                if (d[6] != "FORWARD") tv = Mung(tv, d[6]);
                MemoryStream vs = new MemoryStream();
                if (grease) U16(vs, PickGrease());
                foreach (ushort v in tv) U16(vs, v);
                byte[] vsb = vs.ToArray();
                U16(e, 0x002b); U16(e, vsb.Length + 1); e.WriteByte((byte)vsb.Length); Extras.WB(e, vsb);
            }
            return e.ToArray();
        }

        // Python slicing never throws; indexing a single byte past the end does (the reference then returns "|||")
        static byte[] Slice(byte[] d, int a, int b) { a = Math.Max(0, Math.Min(a, d.Length)); b = Math.Max(a, Math.Min(b, d.Length)); byte[] r = new byte[b - a]; Buffer.BlockCopy(d, a, r, 0, b - a); return r; }
        static int Idx(byte[] d, int i) { if (i < 0 || i >= d.Length) throw new IndexOutOfRangeException(); return d[i]; }
        static int ParseHex(byte[] two) { if (two.Length == 0) throw new FormatException(); int v = 0; foreach (byte x in two) v = (v << 8) | x; return v; }

        public static string Read(byte[] data)
        {
            try
            {
                if (data == null) return "|||";
                if (Idx(data, 0) == 21) return "|||";
                if (Idx(data, 0) == 22 && Idx(data, 5) == 2)
                {
                    int shl = ParseHex(Slice(data, 3, 5));
                    int counter = Idx(data, 43);
                    string cipher = Extras.Hex(Slice(data, counter + 44, counter + 46), 0, 2);
                    string version = Extras.Hex(Slice(data, 9, 11), 0, 2);
                    return cipher + "|" + version + "|" + ExtInfo(data, counter, shl);
                }
                return "|||";
            }
            catch (Exception) { return "|||"; }
        }

        static string ExtInfo(byte[] data, int counter, int shl)
        {
            List<byte[]> types = new List<byte[]>(); List<byte[]> values = new List<byte[]>();
            try
            {
                if (Idx(data, counter + 47) == 11) return "|";
                byte[] a = Slice(data, counter + 50, counter + 53), b = Slice(data, 82, 85);
                if ((a.Length == 3 && a[0] == 0x0e && a[1] == 0xac && a[2] == 0x0b) || (b.Length == 3 && b[0] == 0x0f && b[1] == 0xf0 && b[2] == 0x0b)) return "|";
                if (counter + 42 >= shl) return "|";
                int count = 49 + counter;
                int length = ParseHex(Slice(data, counter + 47, counter + 49));   // FormatException escapes to Read => "|||"
                int maximum = length + (count - 1);
                while (count < maximum)
                {
                    types.Add(Slice(data, count, count + 2));
                    int el = ParseHex(Slice(data, count + 2, count + 4));
                    if (el == 0) { count += 4; values.Add(null); }
                    else { values.Add(Slice(data, count + 4, count + 4 + el)); count += el + 4; }
                }
            }
            catch (IndexOutOfRangeException) { return "|"; }
            string alpn = "";
            for (int i = 0; i < types.Count; i++)
                if (types[i].Length == 2 && types[i][0] == 0x00 && types[i][1] == 0x10)
                {
                    if (values[i] == null) throw new FormatException();          // reference: str has no decode() => "|||"
                    byte[] v = Slice(values[i], 3, values[i].Length);
                    alpn = new UTF8Encoding(false, true).GetString(v);
                    break;
                }
            StringBuilder sb = new StringBuilder(alpn).Append('|');
            for (int i = 0; i < types.Count; i++) { if (i > 0) sb.Append('-'); sb.Append(Extras.Hex(types[i], 0, types[i].Length)); }
            return sb.ToString();
        }

        public static string Hash(string raw)
        {
            if (raw == Empty) return new string('0', 62);
            StringBuilder fuzzy = new StringBuilder(); StringBuilder ae = new StringBuilder();
            foreach (string hs in raw.Split(','))
            {
                string[] c = hs.Split('|');
                fuzzy.Append(CipherByte(c[0])).Append(VersionByte(c[1]));
                ae.Append(c[2]).Append(c[3]);
            }
            return fuzzy.ToString() + Extras.Sha256Hex(ae.ToString()).Substring(0, 32);
        }
        static string CipherByte(string c)
        {
            if (c.Length == 0) return "00";
            int count = 1;
            foreach (ushort x in HashOrder) { if (c == x.ToString("x4", CultureInfo.InvariantCulture)) break; count++; }
            return count.ToString("x2", CultureInfo.InvariantCulture);
        }
        static string VersionByte(string v)
        {
            if (v.Length == 0) return "0";
            return "abcdef"[int.Parse(v.Substring(3, 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture)].ToString();
        }

        // One probe: connect, send, read the reply (up to 1,484 bytes as the reference does). Timeout => null + timedOut.
        static byte[] Send(string ip, int port, int timeoutMs, byte[] pkt, out bool timedOut)
        {
            string st; timedOut = false;
            TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
            if (c == null) { timedOut = st == "filtered"; return null; }
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                s.Write(pkt, 0, pkt.Length);
                bool to;
                byte[] d = Extras.ReadSome(s, 1484, timeoutMs, delegate(byte[] b, int n) { return n >= 5 && n >= Math.Min(1484, 5 + ((b[3] << 8) | b[4])); }, out to);
                if (to && d.Length == 0) { timedOut = true; return null; }
                return d;
            }
            catch (Exception) { return null; }
            finally { Extras.Close(c); }
        }

        public static string Compute(string ip, int port, string host, int timeoutMs, out string raw, out int probes)
        {
            List<string> parts = new List<string>();
            probes = 0;
            foreach (string[] q in Queue)
            {
                probes++;
                bool to;
                byte[] reply = Send(ip, port, timeoutMs, Build(q, host), out to);
                if (to) { raw = Empty; return Hash(raw); }
                parts.Add(Read(reply));
            }
            raw = string.Join(",", parts.ToArray());
            return Hash(raw);
        }
    }

    // ------------------------------------------------------------------ JA4S (from the scanner's TLS 1.3 ClientHello reply)
    public static class Ja4s
    {
        // info = version|cipher|ext,ext,...|alpn as recorded by the raw TLS probe (WebInv.TlsScanResult.HelloInfo)
        public static string FromHelloInfo(string info)
        {
            if (string.IsNullOrEmpty(info)) return "";
            string[] p = info.Split('|');
            if (p.Length < 4) return "";
            string ver;
            switch (p[0].ToLowerInvariant()) { case "0304": ver = "13"; break; case "0303": ver = "12"; break; case "0302": ver = "11"; break; case "0301": ver = "10"; break; case "0300": ver = "s3"; break; case "0002": ver = "s2"; break; default: ver = "00"; break; }
            List<string> exts = new List<string>();
            foreach (string e in p[2].Split(',')) if (e.Length > 0) exts.Add(e.ToLowerInvariant());
            string alpn = "00";
            if (p[3].Length > 0)
            {
                char f = p[3][0], l = p[3][p[3].Length - 1];
                alpn = (f < 128 ? f.ToString() : "9") + (l < 128 ? l.ToString() : "9");
            }
            string hash = exts.Count > 0 ? Extras.Sha256Hex(string.Join(",", exts.ToArray())).Substring(0, 12) : "000000000000";
            return "t" + ver + Math.Min(exts.Count, 99).ToString("D2", CultureInfo.InvariantCulture) + alpn + "_" + p[1].ToLowerInvariant() + "_" + hash;
        }
    }

    // ------------------------------------------------------------------ NTLM challenge (server names and OS version)
    public sealed class NtlmInfo
    {
        public string NbComputer = "", NbDomain = "", DnsComputer = "", DnsDomain = "", DnsTree = "", Version = "";
        public int Major, Minor, Build;
        public bool Ok;
        public string Summary()
        {
            List<string> p = new List<string>();
            if (DnsComputer.Length > 0) p.Add("dnsComputer=" + DnsComputer);
            if (NbComputer.Length > 0) p.Add("computer=" + NbComputer);
            if (DnsDomain.Length > 0) p.Add("dnsDomain=" + DnsDomain);
            if (NbDomain.Length > 0) p.Add("domain=" + NbDomain);
            if (DnsTree.Length > 0 && DnsTree != DnsDomain) p.Add("forest=" + DnsTree);
            if (Version.Length > 0) p.Add("ntlmVersion=" + Version);
            return string.Join("; ", p.ToArray());
        }
    }

    public static class Ntlm
    {
        static readonly byte[] Sig = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 };
        // NEGOTIATE (type 1): unicode, request target, NTLM, always sign, extended session security, target info, version, 128/56
        public static byte[] Negotiate()
        {
            MemoryStream m = new MemoryStream();
            Extras.WB(m, Sig); Extras.W32(m, 1);
            Extras.W32(m, 0xE2088297);
            Extras.WB(m, new byte[16]);
            Extras.WB(m, new byte[] { 10, 0, 0x63, 0x45, 0, 0, 0, 15 });   // client version 10.0.17763, NTLM revision 15
            return m.ToArray();
        }
        public static NtlmInfo ParseChallenge(byte[] buf)
        {
            NtlmInfo n = new NtlmInfo();
            if (buf == null) return n;
            int o = Extras.IndexOf(buf, Sig, 0);
            if (o < 0 || o + 48 > buf.Length || Extras.U32(buf, o + 8) != 2) return n;
            uint flags = Extras.U32(buf, o + 20);
            int tiLen = Extras.U16(buf, o + 40), tiOff = (int)Extras.U32(buf, o + 44);
            int tnOff = (int)Extras.U32(buf, o + 16);
            bool hasVersion = (flags & 0x02000000) != 0 || (tnOff >= 56 && (tiOff >= 56 || tiLen == 0));
            if (hasVersion && o + 56 <= buf.Length && buf[o + 48] > 0)
            {
                n.Major = buf[o + 48]; n.Minor = buf[o + 49]; n.Build = Extras.U16(buf, o + 50);
                n.Version = n.Major + "." + n.Minor + "." + n.Build;
            }
            int p = o + tiOff, end = Math.Min(buf.Length, p + tiLen);
            while (tiLen > 0 && p + 4 <= end)
            {
                int id = Extras.U16(buf, p), len = Extras.U16(buf, p + 2);
                if (id == 0 || p + 4 + len > end) break;
                string v = Encoding.Unicode.GetString(buf, p + 4, len);
                switch (id) { case 1: n.NbComputer = v; break; case 2: n.NbDomain = v; break; case 3: n.DnsComputer = v; break; case 4: n.DnsDomain = v; break; case 5: n.DnsTree = v; break; }
                p += 4 + len;
            }
            n.Ok = n.Version.Length > 0 || n.NbComputer.Length > 0 || n.DnsComputer.Length > 0;
            return n;
        }
        // SPNEGO NegTokenInit offering NTLMSSP only, wrapped in a GSS-API InitialContextToken
        public static byte[] SpnegoInit(byte[] ntlm)
        {
            byte[] mechTok = Der(0xa2, Der(0x04, ntlm));
            byte[] mechTypes = Der(0xa0, Der(0x30, new byte[] { 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a }));
            byte[] init = Der(0xa0, Der(0x30, Cat(mechTypes, mechTok)));
            return Der(0x60, Cat(new byte[] { 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 }, init));
        }
        internal static byte[] Cat(params byte[][] parts) { MemoryStream m = new MemoryStream(); foreach (byte[] p in parts) Extras.WB(m, p); return m.ToArray(); }
        internal static byte[] Der(int tag, byte[] content)
        {
            MemoryStream m = new MemoryStream();
            m.WriteByte((byte)tag);
            int n = content.Length;
            if (n < 128) m.WriteByte((byte)n);
            else if (n < 256) { m.WriteByte(0x81); m.WriteByte((byte)n); }
            else if (n < 65536) { m.WriteByte(0x82); m.WriteByte((byte)(n >> 8)); m.WriteByte((byte)n); }
            else { m.WriteByte(0x83); m.WriteByte((byte)(n >> 16)); m.WriteByte((byte)(n >> 8)); m.WriteByte((byte)n); }
            Extras.WB(m, content);
            return m.ToArray();
        }
    }

    // ------------------------------------------------------------------ SMB: dialect, signing, SMBv1, NTLM server info
    public sealed class SmbResult
    {
        public bool Smb2, SigningEnabled, SigningRequired;
        public string Dialect = "", Smb1 = "", NativeOs = "", NativeLm = "", Error = "", ServerTime = "";
        public NtlmInfo Ntlm = new NtlmInfo();
        public int Probes;
        public string Summary()
        {
            List<string> p = new List<string>();
            if (Dialect.Length > 0) p.Add("dialect=" + Dialect);
            if (Smb2 || Smb1 == "enabled") p.Add("signing=" + (SigningRequired ? "required" : SigningEnabled ? "enabled" : "disabled"));
            if (Smb1.Length > 0) p.Add("smbv1=" + Smb1);
            if (NativeOs.Length > 0) p.Add("nativeOs=" + NativeOs);
            if (NativeLm.Length > 0) p.Add("nativeLm=" + NativeLm);
            return string.Join("; ", p.ToArray());
        }
    }

    public static class Smb
    {
        static byte[] Frame(byte[] smb)
        {
            byte[] f = new byte[smb.Length + 4];
            f[1] = (byte)(smb.Length >> 16); f[2] = (byte)(smb.Length >> 8); f[3] = (byte)smb.Length;
            Buffer.BlockCopy(smb, 0, f, 4, smb.Length);
            return f;
        }
        static byte[] ReadFrame(Stream s)
        {
            byte[] h = new byte[4];
            if (!Extras.ReadExact(s, h, 0, 4)) return null;
            int len = (h[1] << 16) | (h[2] << 8) | h[3];
            if (len <= 0 || len > 1 << 20) return null;
            byte[] b = new byte[len];
            return Extras.ReadExact(s, b, 0, len) ? b : null;
        }
        static byte[] Smb2Header(int command, ulong messageId)
        {
            MemoryStream m = new MemoryStream();
            Extras.WB(m, new byte[] { 0xfe, 0x53, 0x4d, 0x42 });
            Extras.W16(m, 64); Extras.W16(m, 1); Extras.W32(m, 0); Extras.W16(m, command); Extras.W16(m, 31);
            Extras.W32(m, 0); Extras.W32(m, 0);
            Extras.W32(m, (uint)messageId); Extras.W32(m, (uint)(messageId >> 32));
            Extras.W32(m, 0xfeff); Extras.W32(m, 0); Extras.WB(m, new byte[8]); Extras.WB(m, new byte[16]);
            return m.ToArray();
        }
        static byte[] Smb2Negotiate()
        {
            ushort[] dialects = { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 };
            MemoryStream b = new MemoryStream();
            Extras.W16(b, 36); Extras.W16(b, dialects.Length); Extras.W16(b, 1); Extras.W16(b, 0); Extras.W32(b, 0x7f);
            Extras.WB(b, Extras.Random(16));
            int ctxOffset = 64 + 36 + dialects.Length * 2;
            int pad = (8 - ctxOffset % 8) % 8;
            ctxOffset += pad;
            Extras.W32(b, (uint)ctxOffset); Extras.W16(b, 2); Extras.W16(b, 0);
            foreach (ushort d in dialects) Extras.W16(b, d);
            Extras.WB(b, new byte[pad]);
            // PREAUTH_INTEGRITY_CAPABILITIES (SHA-512, 32-byte salt), then ENCRYPTION_CAPABILITIES (AES-128-GCM, AES-128-CCM)
            Extras.W16(b, 1); Extras.W16(b, 38); Extras.W32(b, 0); Extras.W16(b, 1); Extras.W16(b, 32); Extras.W16(b, 1); Extras.WB(b, Extras.Random(32));
            Extras.WB(b, new byte[2]);   // align next context to 8
            Extras.W16(b, 2); Extras.W16(b, 6); Extras.W32(b, 0); Extras.W16(b, 2); Extras.W16(b, 2); Extras.W16(b, 1);
            return Ntlm.Cat(Smb2Header(0, 0), b.ToArray());
        }
        static byte[] Smb2SessionSetup(byte[] blob)
        {
            MemoryStream b = new MemoryStream();
            Extras.W16(b, 25); b.WriteByte(0); b.WriteByte(1); Extras.W32(b, 1); Extras.W32(b, 0);
            Extras.W16(b, 64 + 24); Extras.W16(b, blob.Length); Extras.WB(b, new byte[8]); Extras.WB(b, blob);
            return Ntlm.Cat(Smb2Header(1, 1), b.ToArray());
        }
        static byte[] Smb1Header(byte command, ushort flags2, ushort mid)
        {
            MemoryStream m = new MemoryStream();
            Extras.WB(m, new byte[] { 0xff, 0x53, 0x4d, 0x42, command, 0, 0, 0, 0, 0x18 });
            Extras.W16(m, flags2); Extras.W16(m, 0); Extras.WB(m, new byte[8]); Extras.W16(m, 0); Extras.W16(m, 0xffff); Extras.W16(m, 0xfeff); Extras.W16(m, 0); Extras.W16(m, mid);
            return m.ToArray();
        }

        public static SmbResult Probe(string ip, int port, int timeoutMs)
        {
            SmbResult r = new SmbResult();
            ProbeSmb2(ip, port, timeoutMs, r);
            ProbeSmb1(ip, port, timeoutMs, r);
            return r;
        }

        static void ProbeSmb2(string ip, int port, int timeoutMs, SmbResult r)
        {
            string st;
            r.Probes++;
            TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
            if (c == null) { r.Error = "smb2 connect " + st; return; }
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                byte[] neg = Frame(Smb2Negotiate());
                s.Write(neg, 0, neg.Length);
                byte[] resp = ReadFrame(s);
                if (resp == null || resp.Length < 64 + 65 || resp[0] != 0xfe || resp[1] != 0x53) { r.Error = "no SMB2 negotiate response"; return; }
                uint status = Extras.U32(resp, 8);
                if (status != 0) { r.Error = "SMB2 negotiate status 0x" + status.ToString("x8", CultureInfo.InvariantCulture); return; }
                r.Smb2 = true;
                int b = 64;
                ushort sec = Extras.U16(resp, b + 2), dialect = Extras.U16(resp, b + 4);
                r.SigningEnabled = (sec & 1) != 0; r.SigningRequired = (sec & 2) != 0;
                r.Dialect = DialectName(dialect);
                long ft = (long)(Extras.U32(resp, b + 40) | ((ulong)Extras.U32(resp, b + 44) << 32));
                if (ft > 0) { try { r.ServerTime = DateTime.FromFileTimeUtc(ft).ToString("s", CultureInfo.InvariantCulture) + "Z"; } catch (ArgumentException) { } }
                byte[] ss = Frame(Smb2SessionSetup(Ntlm.SpnegoInit(Ntlm.Negotiate())));
                s.Write(ss, 0, ss.Length);
                byte[] sr = ReadFrame(s);
                if (sr != null && sr.Length > 64) r.Ntlm = Ntlm.ParseChallenge(sr);
            }
            catch (Exception ex) { if (r.Error.Length == 0) r.Error = "smb2: " + ex.Message; }
            finally { Extras.Close(c); }
        }

        static string DialectName(ushort d)
        {
            switch (d) { case 0x0202: return "2.0.2"; case 0x0210: return "2.1"; case 0x0300: return "3.0"; case 0x0302: return "3.0.2"; case 0x0311: return "3.1.1"; case 0x02ff: return "2.??"; }
            return "0x" + d.ToString("x4", CultureInfo.InvariantCulture);
        }

        // SMBv1: a negotiate offering only "NT LM 0.12"; when accepted with extended security, one session-setup leg
        // returns NativeOS / NativeLanMan and the NTLM challenge (no authentication is attempted).
        static void ProbeSmb1(string ip, int port, int timeoutMs, SmbResult r)
        {
            string st;
            r.Probes++;
            TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
            if (c == null) return;
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                byte[] dial = Encoding.ASCII.GetBytes("\u0002NT LM 0.12\0");
                MemoryStream m = new MemoryStream();
                Extras.WB(m, Smb1Header(0x72, 0xc801, 1)); m.WriteByte(0); Extras.W16(m, dial.Length); Extras.WB(m, dial);
                byte[] f = Frame(m.ToArray());
                s.Write(f, 0, f.Length);
                byte[] resp;
                try { resp = ReadFrame(s); } catch (IOException) { resp = null; }
                if (resp == null || resp.Length < 37 || resp[0] != 0xff || resp[1] != 0x53 || resp[4] != 0x72) { r.Smb1 = "disabled"; return; }
                if (Extras.U32(resp, 5) != 0 || resp[32] < 17 || Extras.U16(resp, 33) == 0xffff) { r.Smb1 = "disabled"; return; }
                r.Smb1 = "enabled";
                byte secMode = resp[35];
                if (!r.Smb2) { r.SigningEnabled = (secMode & 4) != 0; r.SigningRequired = (secMode & 8) != 0; r.Dialect = "NT LM 0.12"; }
                uint caps = Extras.U32(resp, 33 + 19);
                if ((caps & 0x80000000) == 0) return;   // no extended security: stop (no null-session login)
                byte[] blob = Ntlm.SpnegoInit(Ntlm.Negotiate());
                MemoryStream q = new MemoryStream();
                Extras.WB(q, Smb1Header(0x73, 0xc807, 2));
                q.WriteByte(12); q.WriteByte(0xff); q.WriteByte(0); Extras.W16(q, 0); Extras.W16(q, 4356); Extras.W16(q, 10); Extras.W16(q, 1);
                Extras.W32(q, 0); Extras.W16(q, blob.Length); Extras.W32(q, 0); Extras.W32(q, 0x8000d05c);
                byte[] tail = Ntlm.Cat(blob, new byte[] { 0, 0, 0, 0, 0 });
                Extras.W16(q, tail.Length); Extras.WB(q, tail);
                byte[] f2 = Frame(q.ToArray());
                s.Write(f2, 0, f2.Length);
                byte[] sr = ReadFrame(s);
                if (sr == null || sr.Length < 41 || sr[4] != 0x73) return;
                if (!r.Ntlm.Ok) r.Ntlm = Ntlm.ParseChallenge(sr);
                int wc = sr[32];
                if (wc != 4) return;
                int blobLen = Extras.U16(sr, 33 + 6);
                int bytesStart = 33 + wc * 2 + 2;
                int p = bytesStart + blobLen;
                if ((p & 1) == 1) p++;   // unicode strings are 2-byte aligned from the SMB header
                r.NativeOs = ReadUnicodeZ(sr, ref p);
                r.NativeLm = ReadUnicodeZ(sr, ref p);
            }
            catch (Exception) { if (r.Smb1.Length == 0) r.Smb1 = "disabled"; }
            finally { Extras.Close(c); }
        }
        static string ReadUnicodeZ(byte[] b, ref int p)
        {
            int start = p;
            while (p + 1 < b.Length && !(b[p] == 0 && b[p + 1] == 0)) p += 2;
            string v = p > start ? Encoding.Unicode.GetString(b, start, p - start) : "";
            p += 2;
            return v.Trim();
        }
    }

    // ------------------------------------------------------------------ RDP: security protocols, certificate, NTLM info
    public sealed class RdpResult
    {
        public string Selected = "", Nla = "", StandardRdp = "", Error = "", TlsProtocol = "", PolicyErrors = "", ChainStatus = "";
        public byte[] CertDer;
        public NtlmInfo Ntlm = new NtlmInfo();
        public int Probes;
        public bool IsRdp;
        public string Summary()
        {
            List<string> p = new List<string>();
            if (Selected.Length > 0) p.Add("security=" + Selected);
            if (Nla.Length > 0) p.Add("nla=" + Nla);
            if (StandardRdp.Length > 0) p.Add("standardRdpSecurity=" + StandardRdp);
            return string.Join("; ", p.ToArray());
        }
    }

    public static class Rdp
    {
        public const int ProtoRdp = 0, ProtoSsl = 1, ProtoHybrid = 2, ProtoHybridEx = 8;
        static byte[] ConnectionRequest(int protocols)
        {
            return new byte[] { 3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, (byte)protocols, (byte)(protocols >> 8), (byte)(protocols >> 16), (byte)(protocols >> 24) };
        }
        // returns: >=0 selected protocol; -1-failureCode on RDP_NEG_FAILURE; -100 no negotiation data (legacy RDP); -200 not RDP
        static int Negotiate(Stream s, int protocols)
        {
            byte[] cr = ConnectionRequest(protocols);
            s.Write(cr, 0, cr.Length);
            byte[] h = new byte[4];
            if (!Extras.ReadExact(s, h, 0, 4) || h[0] != 3) return -200;
            int len = (h[2] << 8) | h[3];
            if (len < 11 || len > 512) return -200;
            byte[] b = new byte[len - 4];
            if (!Extras.ReadExact(s, b, 0, b.Length) || b[1] != 0xd0) return -200;
            if (b.Length < 15) return -100;
            int type = b[7];
            int val = (int)Extras.U32(b, 11);
            if (type == 2) return val;
            if (type == 3) return -1 - val;
            return -100;
        }
        static string ProtoName(int p)
        {
            switch (p) { case ProtoRdp: return "rdp"; case ProtoSsl: return "tls"; case ProtoHybrid: return "hybrid"; case ProtoHybridEx: return "hybrid-ex"; case 4: return "rdstls"; }
            return "0x" + p.ToString("x", CultureInfo.InvariantCulture);
        }

        public static RdpResult Probe(string ip, int port, string sni, int timeoutMs, int sslProtocols)
        {
            RdpResult r = new RdpResult();
            string st;
            r.Probes++;
            TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
            if (c == null) { r.Error = "connect " + st; return r; }
            int sel;
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                sel = Negotiate(s, ProtoSsl | ProtoHybrid | ProtoHybridEx);
                if (sel == -200) { r.Error = "not RDP"; return r; }
                r.IsRdp = true;
                if (sel == -100) { r.Selected = "rdp (legacy, no negotiation)"; r.StandardRdp = "accepted"; return r; }
                if (sel < 0) r.Selected = "tls/hybrid refused (" + FailureName(-1 - sel) + ")";
                else
                {
                    r.Selected = ProtoName(sel);
                    if (sel != ProtoRdp) TlsAndCredSsp(s, sni, timeoutMs, sslProtocols, sel != ProtoSsl, r);
                }
            }
            catch (Exception ex) { r.Error = ex.Message; return r; }
            finally { Extras.Close(c); }
            // NLA enforced? ask for TLS only: HYBRID_REQUIRED_BY_SERVER (5) means yes
            if (sel == ProtoHybrid || sel == ProtoHybridEx)
            {
                int t = Ask(ip, port, timeoutMs, ProtoSsl, r);
                r.Nla = t == ProtoSsl ? "not required" : (t == -6 ? "required" : "");
                if (t == ProtoSsl) { int u = Ask(ip, port, timeoutMs, ProtoRdp, r); r.StandardRdp = u == ProtoRdp ? "accepted" : (u < 0 && u > -100 ? "refused" : ""); }
                else r.StandardRdp = "refused";
            }
            else if (sel == ProtoSsl || sel < 0)
            {
                // TLS without CredSSP, or TLS/CredSSP refused outright: standard RDP security is the remaining option
                int u = Ask(ip, port, timeoutMs, ProtoRdp, r);
                r.StandardRdp = u == ProtoRdp ? "accepted" : (u < 0 && u > -100 ? "refused" : "");
                if (sel == ProtoSsl || u == ProtoRdp) r.Nla = "not required";
                if (sel < 0 && u == ProtoRdp) r.Selected = "rdp only (" + r.Selected + ")";
            }
            return r;
        }
        static string FailureName(int code)
        {
            switch (code)
            {
                case 1: return "SSL_REQUIRED_BY_SERVER"; case 2: return "SSL_NOT_ALLOWED_BY_SERVER"; case 3: return "SSL_CERT_NOT_ON_SERVER";
                case 4: return "INCONSISTENT_FLAGS"; case 5: return "HYBRID_REQUIRED_BY_SERVER"; case 6: return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER";
            }
            return "code " + code.ToString(CultureInfo.InvariantCulture);
        }
        static int Ask(string ip, int port, int timeoutMs, int protocols, RdpResult r)
        {
            string st;
            r.Probes++;
            TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
            if (c == null) return -300;
            try { c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs; return Negotiate(c.GetStream(), protocols); }
            catch (Exception) { return -300; }
            finally { Extras.Close(c); }
        }
        static void TlsAndCredSsp(Stream s, string sni, int timeoutMs, int sslProtocols, bool credssp, RdpResult r)
        {
            SslStream ssl = new SslStream(s, true, delegate(object o, X509Certificate cert, X509Chain ch, SslPolicyErrors e)
            {
                try
                {
                    if (cert != null) r.CertDer = cert.GetRawCertData();
                    r.PolicyErrors = e.ToString();
                    if (ch != null && ch.ChainStatus != null)
                    {
                        List<string> cs = new List<string>();
                        foreach (X509ChainStatus x in ch.ChainStatus) if (x.Status != X509ChainStatusFlags.NoError) cs.Add(x.Status.ToString());
                        r.ChainStatus = string.Join(",", cs.ToArray());
                    }
                }
                catch { }
                return true;
            });
            try
            {
                ssl.AuthenticateAsClient(sni, null, (SslProtocols)sslProtocols, false);
                r.TlsProtocol = TlsName(ssl.SslProtocol);
                if (!credssp) return;
                // CredSSP TSRequest { version 6, negoTokens { { negoToken NTLM NEGOTIATE } } }
                byte[] ts = Ntlm.Der(0x30, Ntlm.Cat(Ntlm.Der(0xa0, new byte[] { 0x02, 0x01, 0x06 }),
                    Ntlm.Der(0xa1, Ntlm.Der(0x30, Ntlm.Der(0x30, Ntlm.Der(0xa0, Ntlm.Der(0x04, Ntlm.Negotiate())))))));
                ssl.Write(ts, 0, ts.Length);
                ssl.Flush();
                bool to;
                byte[] resp = Extras.ReadSome(ssl, 8192, timeoutMs, delegate(byte[] b, int n)
                {
                    if (n < 2 || b[0] != 0x30) return n > 0;
                    int need = b[1] < 0x80 ? 2 + b[1] : (b[1] == 0x81 && n > 2 ? 3 + b[2] : (b[1] == 0x82 && n > 3 ? 4 + ((b[2] << 8) | b[3]) : int.MaxValue));
                    return n >= need;
                }, out to);
                r.Ntlm = Ntlm.ParseChallenge(resp);
            }
            catch (Exception ex) { if (r.Error.Length == 0) r.Error = "tls: " + ex.Message; }
            finally { try { ssl.Dispose(); } catch { } }
        }
        static string TlsName(SslProtocols p)
        {
            switch ((int)p) { case 12288: return "Tls13"; case 3072: return "Tls12"; case 768: return "Tls11"; case 192: return "Tls"; case 48: return "Ssl3"; }
            return p.ToString();
        }
    }

    // ------------------------------------------------------------------ SNMP: v1/v2c (supplied community) and v3 (USM)
    public sealed class SnmpResult
    {
        public string State = "filtered", Version = "", Error = "", EngineId = "";
        public readonly Dictionary<string, string> Values = new Dictionary<string, string>(StringComparer.Ordinal);
        public int Probes;
        public string Get(string oid) { string v; return Values.TryGetValue(oid, out v) ? v : ""; }
    }

    public sealed class SnmpCredential
    {
        public string Version = "2c";        // 1 | 2c | 3
        public string Community = "";
        public string User = "", AuthProtocol = "SHA", AuthPassword = "", PrivProtocol = "AES", PrivPassword = "";
    }

    public static class Snmp
    {
        public static readonly string[] SystemOids = { "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.6.0" };

        // ---- BER
        internal static byte[] Tlv(int tag, byte[] v) { return Ntlm.Der(tag, v); }
        internal static byte[] Int(long v)
        {
            List<byte> b = new List<byte>();
            do { b.Insert(0, (byte)(v & 0xff)); v >>= 8; } while (v != 0 && v != -1);
            if ((v == 0 && (b[0] & 0x80) != 0)) b.Insert(0, 0);
            if ((v == -1 && (b[0] & 0x80) == 0)) b.Insert(0, 0xff);
            return Tlv(0x02, b.ToArray());
        }
        internal static byte[] Oct(byte[] v) { return Tlv(0x04, v ?? new byte[0]); }
        internal static byte[] Oid(string dotted)
        {
            string[] p = dotted.Trim('.').Split('.');
            List<byte> b = new List<byte>();
            b.Add((byte)(int.Parse(p[0], CultureInfo.InvariantCulture) * 40 + int.Parse(p[1], CultureInfo.InvariantCulture)));
            for (int i = 2; i < p.Length; i++)
            {
                ulong n = ulong.Parse(p[i], CultureInfo.InvariantCulture);
                List<byte> t = new List<byte>();
                t.Insert(0, (byte)(n & 0x7f)); n >>= 7;
                while (n > 0) { t.Insert(0, (byte)(0x80 | (n & 0x7f))); n >>= 7; }
                b.AddRange(t);
            }
            return Tlv(0x06, b.ToArray());
        }
        internal static byte[] Seq(params byte[][] parts) { return Tlv(0x30, Ntlm.Cat(parts)); }

        internal sealed class Node { public int Tag; public byte[] Raw; public int Start, Len; public List<Node> Kids; }
        internal static Node Parse(byte[] b, int p, out int next)
        {
            Node n = new Node(); n.Raw = b; n.Tag = b[p];
            int q = p + 1;
            int len = b[q++];
            if ((len & 0x80) != 0) { int k = len & 0x7f; if (k > 4) throw new FormatException("BER length"); len = 0; for (int i = 0; i < k; i++) len = (len << 8) | b[q++]; }
            if (q + len > b.Length) throw new FormatException("BER truncated");
            n.Start = q; n.Len = len; next = q + len;
            if ((n.Tag & 0x20) != 0)
            {
                n.Kids = new List<Node>();
                int c = q;
                while (c < q + len) { int nx; n.Kids.Add(Parse(b, c, out nx)); c = nx; }
            }
            return n;
        }
        internal static byte[] Bytes(Node n) { byte[] o = new byte[n.Len]; Buffer.BlockCopy(n.Raw, n.Start, o, 0, n.Len); return o; }
        internal static long Long(Node n) { long v = (n.Len > 0 && (n.Raw[n.Start] & 0x80) != 0) ? -1 : 0; for (int i = 0; i < n.Len; i++) v = (v << 8) | n.Raw[n.Start + i]; return v; }
        internal static string OidText(Node n)
        {
            if (n.Len == 0) return "";
            StringBuilder sb = new StringBuilder();
            int f = n.Raw[n.Start];
            sb.Append(f / 40).Append('.').Append(f % 40);
            ulong v = 0;
            for (int i = 1; i < n.Len; i++) { byte x = n.Raw[n.Start + i]; v = (v << 7) | (uint)(x & 0x7f); if ((x & 0x80) == 0) { sb.Append('.').Append(v); v = 0; } }
            return sb.ToString();
        }
        static string ValueText(Node v)
        {
            switch (v.Tag)
            {
                case 0x04:
                    byte[] b = Bytes(v);
                    try { return new UTF8Encoding(false, true).GetString(b).TrimEnd('\0'); } catch (DecoderFallbackException) { return Encoding.GetEncoding(28591).GetString(b).TrimEnd('\0'); }
                case 0x06: return OidText(v);
                case 0x02: case 0x41: case 0x42: case 0x43: case 0x46: return Long(v).ToString(CultureInfo.InvariantCulture);
                case 0x40: return v.Len == 4 ? string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3}", v.Raw[v.Start], v.Raw[v.Start + 1], v.Raw[v.Start + 2], v.Raw[v.Start + 3]) : "";
                default: return "";   // NULL, noSuchObject, noSuchInstance, endOfMibView
            }
        }
        static byte[] GetPdu(int requestId, string[] oids, int tag)
        {
            List<byte[]> vbs = new List<byte[]>();
            foreach (string o in oids) vbs.Add(Seq(Oid(o), new byte[] { 0x05, 0x00 }));
            return Tlv(tag, Ntlm.Cat(Int(requestId), Int(0), Int(0), Seq(vbs.ToArray())));
        }
        static void ReadVarbinds(Node pdu, SnmpResult r)
        {
            if (pdu.Kids == null || pdu.Kids.Count < 4) return;
            long err = Long(pdu.Kids[1]);
            if (err != 0) r.Error = "SNMP error-status " + err;
            foreach (Node vb in pdu.Kids[3].Kids)
                if (vb.Kids != null && vb.Kids.Count == 2) { string t = ValueText(vb.Kids[1]); if (t.Length > 0) r.Values[OidText(vb.Kids[0])] = t; }
        }

        // ---- UDP exchange: null on timeout; closed => ICMP port unreachable
        static byte[] Exchange(Socket u, byte[] msg, int timeoutMs, int retries, SnmpResult r, out bool closed)
        {
            closed = false;
            byte[] buf = new byte[65535];
            for (int a = 0; a <= retries; a++)
            {
                r.Probes++;
                try
                {
                    u.Send(msg);
                    if (!u.Poll(timeoutMs * 1000, SelectMode.SelectRead)) continue;
                    int n = u.Receive(buf);
                    byte[] o = new byte[n]; Buffer.BlockCopy(buf, 0, o, 0, n); return o;
                }
                catch (SocketException se)
                {
                    if (se.SocketErrorCode == SocketError.ConnectionReset || se.SocketErrorCode == SocketError.ConnectionRefused) { closed = true; return null; }
                    if (se.SocketErrorCode == SocketError.TimedOut) continue;
                    throw;
                }
            }
            return null;
        }

        public static SnmpResult Query(string ip, int port, int timeoutMs, int retries, SnmpCredential cred, string[] oids)
        {
            SnmpResult r = new SnmpResult();
            r.Version = cred.Version;
            IPAddress addr = IPAddress.Parse(ip);
            using (Socket u = new Socket(addr.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
            {
                try { u.Connect(new IPEndPoint(addr, port)); }
                catch (SocketException se) { r.State = "error"; r.Error = se.Message; return r; }
                try
                {
                    if (cred.Version == "3") QueryV3(u, timeoutMs, retries, cred, oids, r);
                    else QueryV12(u, timeoutMs, retries, cred, oids, r);
                }
                catch (Exception ex) { if (r.State != "open") r.State = "error"; r.Error = ex.Message; }
            }
            return r;
        }

        static void QueryV12(Socket u, int timeoutMs, int retries, SnmpCredential cred, string[] oids, SnmpResult r)
        {
            int rid = BitConverter.ToInt32(Extras.Random(4), 0) & 0x7fffffff;
            byte[] msg = Seq(Int(cred.Version == "1" ? 0 : 1), Oct(Encoding.UTF8.GetBytes(cred.Community)), GetPdu(rid, oids, 0xa0));
            bool closed;
            byte[] resp = Exchange(u, msg, timeoutMs, retries, r, out closed);
            if (closed) { r.State = "closed"; return; }
            if (resp == null) { r.State = "filtered"; return; }   // silence: wrong community, ACL, or nothing listening
            int nx;
            Node m = Parse(resp, 0, out nx);
            if (m.Kids == null || m.Kids.Count < 3 || m.Kids[2].Tag != 0xa2) { r.State = "error"; r.Error = "unexpected SNMP reply"; return; }
            r.State = "open";
            ReadVarbinds(m.Kids[2], r);
        }

        // ---- SNMPv3 USM (RFC 3414; AES-128-CFB RFC 3826; HMAC-SHA-256-192 RFC 7860)
        static HashAlgorithmName AuthHash(string p)
        {
            switch ((p ?? "").ToUpperInvariant()) { case "MD5": return HashAlgorithmName.MD5; case "SHA256": case "SHA-256": return HashAlgorithmName.SHA256; default: return HashAlgorithmName.SHA1; }
        }
        static int MacLen(string p) { return AuthHash(p) == HashAlgorithmName.SHA256 ? 24 : 12; }
        static byte[] Digest(HashAlgorithmName h, byte[] data)
        {
            using (IncrementalHash ih = IncrementalHash.CreateHash(h)) { ih.AppendData(data); return ih.GetHashAndReset(); }
        }
        public static byte[] LocalizeKey(string auth, string password, byte[] engineId)
        {
            HashAlgorithmName h = AuthHash(auth);
            byte[] pw = Encoding.UTF8.GetBytes(password);
            if (pw.Length == 0) throw new ArgumentException("empty SNMPv3 password");
            byte[] ku;
            using (IncrementalHash ih = IncrementalHash.CreateHash(h))
            {
                byte[] block = new byte[64]; int idx = 0;
                for (int count = 0; count < 1048576; count += 64)
                {
                    for (int i = 0; i < 64; i++) block[i] = pw[idx++ % pw.Length];
                    ih.AppendData(block);
                }
                ku = ih.GetHashAndReset();
            }
            return Digest(h, Ntlm.Cat(ku, engineId, ku));
        }
        static byte[] Hmac(string auth, byte[] key, byte[] msg)
        {
            using (IncrementalHash ih = IncrementalHash.CreateHMAC(AuthHash(auth), key)) { ih.AppendData(msg); byte[] f = ih.GetHashAndReset(); byte[] o = new byte[MacLen(auth)]; Buffer.BlockCopy(f, 0, o, 0, o.Length); return o; }
        }
        static byte[] AesCfb(byte[] key16, byte[] iv, byte[] data, bool encrypt)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.Key = key16;
                using (ICryptoTransform ecb = aes.CreateEncryptor())
                {
                    byte[] o = new byte[data.Length]; byte[] fb = (byte[])iv.Clone(); byte[] ks = new byte[16];
                    for (int i = 0; i < data.Length; i += 16)
                    {
                        ecb.TransformBlock(fb, 0, 16, ks, 0);
                        int n = Math.Min(16, data.Length - i);
                        for (int j = 0; j < n; j++) o[i + j] = (byte)(data[i + j] ^ ks[j]);
                        if (n == 16) Buffer.BlockCopy(encrypt ? o : data, i, fb, 0, 16);
                    }
                    return o;
                }
            }
        }
        static byte[] DesCbc(byte[] privKey, byte[] salt, byte[] data, bool encrypt)
        {
            byte[] key = new byte[8], iv = new byte[8];
            Buffer.BlockCopy(privKey, 0, key, 0, 8);
            for (int i = 0; i < 8; i++) iv[i] = (byte)(privKey[8 + i] ^ salt[i]);
            using (DES des = DES.Create())
            {
                des.Mode = CipherMode.CBC; des.Padding = PaddingMode.None; des.Key = key; des.IV = iv;
                byte[] input = data;
                if (encrypt && data.Length % 8 != 0) { input = new byte[(data.Length + 7) / 8 * 8]; Buffer.BlockCopy(data, 0, input, 0, data.Length); }
                using (ICryptoTransform t = encrypt ? des.CreateEncryptor() : des.CreateDecryptor()) return t.TransformFinalBlock(input, 0, input.Length - input.Length % 8);
            }
        }

        static byte[] V3Message(int msgId, byte flags, byte[] engineId, int boots, int time, string user, byte[] authParams, byte[] privParams, byte[] scopedOrEncrypted, out int authOffset)
        {
            byte[] global = Seq(Int(msgId), Int(65507), Oct(new[] { flags }), Int(3));
            byte[] usmInner = Ntlm.Cat(Oct(engineId), Int(boots), Int(time), Oct(Encoding.UTF8.GetBytes(user)), Oct(authParams), Oct(privParams));
            byte[] usm = Tlv(0x30, usmInner);
            byte[] secParams = Oct(usm);
            byte[] body = Ntlm.Cat(Int(3), global, secParams, scopedOrEncrypted);
            byte[] msg = Tlv(0x30, body);
            // offset of the authentication parameters' value: message header + version + global + octet header + USM header + fields
            int hdr = msg.Length - body.Length;
            int secHdr = secParams.Length - usm.Length;
            int usmHdr = usm.Length - usmInner.Length;
            int before = Oct(engineId).Length + Int(boots).Length + Int(time).Length + Oct(Encoding.UTF8.GetBytes(user)).Length;
            int authHdr = Oct(authParams).Length - authParams.Length;
            authOffset = hdr + Int(3).Length + global.Length + secHdr + usmHdr + before + authHdr;
            return msg;
        }

        static void QueryV3(Socket u, int timeoutMs, int retries, SnmpCredential cred, string[] oids, SnmpResult r)
        {
            bool closed;
            int msgId = BitConverter.ToInt32(Extras.Random(4), 0) & 0x7fffffff;
            int ao;
            // 1. discovery: unauthenticated, reportable, empty engine id and user
            byte[] disc = V3Message(msgId, 0x04, new byte[0], 0, 0, "", new byte[0], new byte[0],
                Seq(Oct(new byte[0]), Oct(new byte[0]), GetPdu(msgId, new string[0], 0xa0)), out ao);
            byte[] dr = Exchange(u, disc, timeoutMs, retries, r, out closed);
            if (closed) { r.State = "closed"; return; }
            if (dr == null) { r.State = "filtered"; return; }
            r.State = "open";
            int nx;
            Node dm = Parse(dr, 0, out nx);
            Node dusm = Parse(Bytes(dm.Kids[2]), 0, out nx);
            byte[] engineId = Bytes(dusm.Kids[0]);
            int boots = (int)Long(dusm.Kids[1]), etime = (int)Long(dusm.Kids[2]);
            Stopwatch since = Stopwatch.StartNew();
            r.EngineId = Extras.Hex(engineId, 0, engineId.Length);
            if (engineId.Length == 0) { r.Error = "agent did not report an engine id"; return; }
            if (cred.User.Length == 0) return;   // discovery only: no user was supplied, nothing more is sent
            bool auth = cred.AuthPassword.Length > 0, priv = auth && cred.PrivPassword.Length > 0 && !string.Equals(cred.PrivProtocol, "None", StringComparison.OrdinalIgnoreCase);
            byte[] authKey = auth ? LocalizeKey(cred.AuthProtocol, cred.AuthPassword, engineId) : null;
            byte[] privKey = priv ? LocalizeKey(cred.AuthProtocol, cred.PrivPassword, engineId) : null;
            bool des = string.Equals(cred.PrivProtocol, "DES", StringComparison.OrdinalIgnoreCase);
            for (int attempt = 0; attempt < 2; attempt++)
            {
                int now = etime + (int)(since.ElapsedMilliseconds / 1000);
                int rid = BitConverter.ToInt32(Extras.Random(4), 0) & 0x7fffffff;
                byte[] scoped = Seq(Oct(engineId), Oct(new byte[0]), GetPdu(rid, oids, 0xa0));
                byte[] privParams = new byte[0];
                byte[] data = scoped;
                if (priv)
                {
                    privParams = Extras.Random(8);
                    if (des) { Buffer.BlockCopy(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(boots)), 0, privParams, 0, 4); data = Oct(DesCbc(privKey, privParams, scoped, true)); }
                    else
                    {
                        byte[] iv = new byte[16];
                        iv[0] = (byte)(boots >> 24); iv[1] = (byte)(boots >> 16); iv[2] = (byte)(boots >> 8); iv[3] = (byte)boots;
                        iv[4] = (byte)(now >> 24); iv[5] = (byte)(now >> 16); iv[6] = (byte)(now >> 8); iv[7] = (byte)now;
                        Buffer.BlockCopy(privParams, 0, iv, 8, 8);
                        byte[] k16 = new byte[16]; Buffer.BlockCopy(privKey, 0, k16, 0, 16);
                        data = Oct(AesCfb(k16, iv, scoped, true));
                    }
                }
                byte flags = (byte)(0x04 | (auth ? 1 : 0) | (priv ? 2 : 0));
                byte[] msg = V3Message(msgId + 1 + attempt, flags, engineId, boots, now, cred.User, auth ? new byte[MacLen(cred.AuthProtocol)] : new byte[0], privParams, data, out ao);
                if (auth) { byte[] mac = Hmac(cred.AuthProtocol, authKey, msg); Buffer.BlockCopy(mac, 0, msg, ao, mac.Length); }
                byte[] resp = Exchange(u, msg, timeoutMs, retries, r, out closed);
                if (resp == null) { r.Error = "no reply to the SNMPv3 request (check user and keys)"; return; }
                Node m = Parse(resp, 0, out nx);
                Node usmN = Parse(Bytes(m.Kids[2]), 0, out nx);
                byte rflags = Bytes(m.Kids[1].Kids[2])[0];
                if (auth && (rflags & 1) != 0)
                {
                    byte[] got = Bytes(usmN.Kids[4]);
                    byte[] zeroed = (byte[])resp.Clone();
                    int at = Extras.IndexOf(resp, got, 0);
                    if (at < 0) { r.Error = "SNMPv3 reply authentication parameters not found"; return; }
                    for (int i = 0; i < got.Length; i++) zeroed[at + i] = 0;
                    byte[] want = Hmac(cred.AuthProtocol, authKey, zeroed);
                    if (!ByteEq(want, got)) { r.Error = "SNMPv3 reply failed authentication"; return; }
                }
                byte[] pduBytes;
                Node d = m.Kids[3];
                if (d.Tag == 0x04)
                {
                    if (!priv) { r.Error = "encrypted SNMPv3 reply without a privacy key"; return; }
                    byte[] salt = Bytes(usmN.Kids[5]);
                    int rboots = (int)Long(usmN.Kids[1]), rtime = (int)Long(usmN.Kids[2]);
                    byte[] enc = Bytes(d);
                    if (des) pduBytes = DesCbc(privKey, salt, enc, false);
                    else
                    {
                        byte[] iv = new byte[16];
                        iv[0] = (byte)(rboots >> 24); iv[1] = (byte)(rboots >> 16); iv[2] = (byte)(rboots >> 8); iv[3] = (byte)rboots;
                        iv[4] = (byte)(rtime >> 24); iv[5] = (byte)(rtime >> 16); iv[6] = (byte)(rtime >> 8); iv[7] = (byte)rtime;
                        Buffer.BlockCopy(salt, 0, iv, 8, 8);
                        byte[] k16 = new byte[16]; Buffer.BlockCopy(privKey, 0, k16, 0, 16);
                        pduBytes = AesCfb(k16, iv, enc, false);
                    }
                }
                else pduBytes = ByteRange(resp, d);
                Node sp = Parse(pduBytes, 0, out nx);
                Node pdu = sp.Kids[2];
                if (pdu.Tag == 0xa8)
                {
                    string rep = pdu.Kids.Count >= 4 && pdu.Kids[3].Kids.Count > 0 ? OidText(pdu.Kids[3].Kids[0].Kids[0]) : "";
                    if (rep.StartsWith("1.3.6.1.6.3.15.1.1.2", StringComparison.Ordinal) && attempt == 0)   // usmStatsNotInTimeWindows: resync and retry
                    { boots = (int)Long(usmN.Kids[1]); etime = (int)Long(usmN.Kids[2]); since = Stopwatch.StartNew(); continue; }
                    r.Error = "SNMPv3 report " + ReportName(rep);
                    return;
                }
                ReadVarbinds(pdu, r);
                return;
            }
        }
        static byte[] ByteRange(byte[] all, Node n)
        {
            int hdr = 2; int l = n.Len;
            if (l >= 128) hdr += l < 256 ? 1 : (l < 65536 ? 2 : 3);
            byte[] o = new byte[hdr + l]; Buffer.BlockCopy(all, n.Start - hdr, o, 0, o.Length); return o;
        }
        static bool ByteEq(byte[] a, byte[] b) { if (a.Length != b.Length) return false; int d = 0; for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i]; return d == 0; }
        static string ReportName(string oid)
        {
            switch (oid)
            {
                case "1.3.6.1.6.3.15.1.1.1.0": return "unsupported security level";
                case "1.3.6.1.6.3.15.1.1.2.0": return "not in time window";
                case "1.3.6.1.6.3.15.1.1.3.0": return "unknown user name";
                case "1.3.6.1.6.3.15.1.1.4.0": return "unknown engine id";
                case "1.3.6.1.6.3.15.1.1.5.0": return "wrong digest (authentication password or protocol)";
                case "1.3.6.1.6.3.15.1.1.6.0": return "decryption error (privacy password or protocol)";
            }
            return oid;
        }
    }

    // ------------------------------------------------------------------ Screenshot capture over the DevTools protocol
    // The browser is started by the caller with --remote-debugging-port=0 and a fresh --user-data-dir; it writes its
    // port to <profile>\DevToolsActivePort. One page: set the viewport, navigate, wait for the load event (or the
    // budget), capture a PNG. Runs on its own thread; the caller polls Done.
    public sealed class CdpCapture
    {
        public volatile bool Done;
        public string Status = "", NavError = "", Title = "";
        public long Ms;
        readonly string profile, url, file;
        readonly int width, height, budgetMs;
        System.Net.WebSockets.ClientWebSocket ws;
        int nextId;

        public CdpCapture(string profileDir, string url, string pngFile, int width, int height, int budgetMs)
        {
            profile = profileDir; this.url = url; file = pngFile; this.width = width; this.height = height; this.budgetMs = budgetMs;
        }
        public void Start() { Thread t = new Thread(Run); t.IsBackground = true; t.Start(); }

        void Run()
        {
            Stopwatch sw = Stopwatch.StartNew();
            try { Status = Capture(sw); }
            catch (Exception ex) { Status = "failed: " + (ex.InnerException != null ? ex.InnerException.Message : ex.Message); }
            finally
            {
                try { if (ws != null) ws.Abort(); } catch { }
                Ms = sw.ElapsedMilliseconds; Done = true;
            }
        }

        string Capture(Stopwatch sw)
        {
            string portFile = Path.Combine(profile, "DevToolsActivePort");
            int port = 0;
            while (sw.ElapsedMilliseconds < Math.Min(20000, budgetMs))
            {
                try { if (File.Exists(portFile)) { string[] l = File.ReadAllLines(portFile); if (l.Length > 0 && int.TryParse(l[0].Trim(), out port) && port > 0) break; } } catch (IOException) { }
                Thread.Sleep(100);
            }
            if (port <= 0) return "failed: the browser did not open its DevTools port (headless mode or remote debugging blocked by policy?)";
            string wsUrl = null;
            while (wsUrl == null && sw.ElapsedMilliseconds < Math.Min(25000, budgetMs))
            {
                // the page target appears a moment after the port does
                System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(HttpGet(port, "/json/list"), "\"webSocketDebuggerUrl\"\\s*:\\s*\"(ws://[^\"]+/devtools/page/[^\"]+)\"");
                if (m.Success) wsUrl = m.Groups[1].Value; else Thread.Sleep(150);
            }
            if (wsUrl == null) return "failed: no page target in the browser";
            ws = new System.Net.WebSockets.ClientWebSocket();
            ws.Options.Proxy = null;
            ws.ConnectAsync(new Uri(wsUrl), CancellationToken.None).Wait(10000);
            if (ws.State != System.Net.WebSockets.WebSocketState.Open) return "failed: DevTools connection not open";
            Call("Page.enable", "{}", 10000);
            Call("Network.enable", "{}", 10000);
            Call("Emulation.setDeviceMetricsOverride", "{\"width\":" + width + ",\"height\":" + height + ",\"deviceScaleFactor\":1,\"mobile\":false}", 10000);
            string nav = Call("Page.navigate", "{\"url\":" + JsonStr(url) + "}", 15000);
            System.Text.RegularExpressions.Match ne = System.Text.RegularExpressions.Regex.Match(nav, "\"errorText\"\\s*:\\s*\"([^\"]*)\"");
            if (ne.Success && ne.Groups[1].Value.Length > 0) { NavError = ne.Groups[1].Value; return "failed: " + NavError; }
            bool loaded = WaitEvent("Page.loadEventFired", (int)Math.Max(1000, budgetMs - sw.ElapsedMilliseconds - 3000));
            Thread.Sleep(400);   // let late layout/paint settle
            string shot = Call("Page.captureScreenshot", "{\"format\":\"png\"}", 15000);
            System.Text.RegularExpressions.Match d = System.Text.RegularExpressions.Regex.Match(shot, "\"data\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"");
            if (!d.Success) return "failed: no screenshot data";
            File.WriteAllBytes(file, Convert.FromBase64String(d.Groups[1].Value));
            try
            {
                string t = Call("Runtime.evaluate", "{\"expression\":\"document.title\",\"returnByValue\":true}", 3000);
                System.Text.RegularExpressions.Match tm = System.Text.RegularExpressions.Regex.Match(t, "\"value\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
                if (tm.Success) Title = System.Text.RegularExpressions.Regex.Unescape(tm.Groups[1].Value);
            }
            catch (Exception) { }
            return loaded ? "ok" : "ok-timeout";
        }

        static string JsonStr(string s)
        {
            StringBuilder b = new StringBuilder("\"");
            foreach (char c in s) { if (c == '"' || c == '\\') b.Append('\\').Append(c); else if (c < 32) b.AppendFormat("\\u{0:x4}", (int)c); else b.Append(c); }
            return b.Append('"').ToString();
        }

        static string HttpGet(int port, string path)
        {
            using (TcpClient c = new TcpClient())
            {
                c.Connect(IPAddress.Loopback, port);
                c.ReceiveTimeout = 10000;
                NetworkStream s = c.GetStream();
                byte[] rq = Encoding.ASCII.GetBytes("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nConnection: close\r\n\r\n");
                s.Write(rq, 0, rq.Length);
                // the DevTools HTTP endpoint keeps the connection open: read the header, then Content-Length bytes
                MemoryStream ms = new MemoryStream(); byte[] buf = new byte[8192]; int n, hdrEnd = -1, want = -1;
                while ((n = s.Read(buf, 0, buf.Length)) > 0)
                {
                    ms.Write(buf, 0, n);
                    byte[] all = ms.ToArray();
                    if (hdrEnd < 0)
                    {
                        hdrEnd = Extras.IndexOf(all, new byte[] { 13, 10, 13, 10 }, 0);
                        if (hdrEnd >= 0)
                        {
                            System.Text.RegularExpressions.Match cl = System.Text.RegularExpressions.Regex.Match(Encoding.ASCII.GetString(all, 0, hdrEnd), @"(?im)^Content-Length:\s*(\d+)");
                            want = cl.Success ? int.Parse(cl.Groups[1].Value, CultureInfo.InvariantCulture) : -1;
                        }
                    }
                    if (hdrEnd >= 0 && want >= 0 && all.Length - hdrEnd - 4 >= want) return Encoding.UTF8.GetString(all, hdrEnd + 4, want);
                }
                byte[] r = ms.ToArray();
                return hdrEnd >= 0 ? Encoding.UTF8.GetString(r, hdrEnd + 4, r.Length - hdrEnd - 4) : Encoding.UTF8.GetString(r);
            }
        }

        readonly Queue<string> events = new Queue<string>();
        // every URL the page itself requested (Network.requestWillBeSent): tells page resources from browser chatter
        public readonly List<string> Requests = new List<string>();
        static readonly System.Text.RegularExpressions.Regex ReqUrl = new System.Text.RegularExpressions.Regex("\"request\"\\s*:\\s*\\{\\s*\"url\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        void Note(string msg)
        {
            if (msg.IndexOf("\"Network.requestWillBeSent\"", StringComparison.Ordinal) < 0) return;
            System.Text.RegularExpressions.Match m = ReqUrl.Match(msg);
            if (m.Success) lock (Requests) { if (Requests.Count < 2000) Requests.Add(System.Text.RegularExpressions.Regex.Unescape(m.Groups[1].Value)); }
        }
        string Receive(int timeoutMs)
        {
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[65536];
            while (true)
            {
                System.Threading.Tasks.Task<System.Net.WebSockets.WebSocketReceiveResult> t = ws.ReceiveAsync(new ArraySegment<byte>(buf), CancellationToken.None);
                if (!t.Wait(timeoutMs)) return null;
                if (t.Result.MessageType == System.Net.WebSockets.WebSocketMessageType.Close) throw new IOException("DevTools connection closed");
                ms.Write(buf, 0, t.Result.Count);
                if (t.Result.EndOfMessage) { string msg = Encoding.UTF8.GetString(ms.ToArray()); Note(msg); return msg; }
            }
        }
        string Call(string method, string paramsJson, int timeoutMs)
        {
            int id = ++nextId;
            byte[] b = Encoding.UTF8.GetBytes("{\"id\":" + id + ",\"method\":\"" + method + "\",\"params\":" + paramsJson + "}");
            if (!ws.SendAsync(new ArraySegment<byte>(b), System.Net.WebSockets.WebSocketMessageType.Text, true, CancellationToken.None).Wait(timeoutMs)) throw new TimeoutException(method + " not sent");
            Stopwatch sw = Stopwatch.StartNew();
            string idTag = "\"id\":" + id + ",", idEnd = "\"id\":" + id + "}";
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                string msg = Receive((int)Math.Max(100, timeoutMs - sw.ElapsedMilliseconds));
                if (msg == null) break;
                if (msg.StartsWith("{\"id\":", StringComparison.Ordinal) && (msg.IndexOf(idTag, StringComparison.Ordinal) == 1 || msg.IndexOf(idEnd, StringComparison.Ordinal) == 1)) return msg;
                if (msg.IndexOf("\"method\"", StringComparison.Ordinal) >= 0) events.Enqueue(msg);
            }
            throw new TimeoutException(method + ": no answer");
        }
        bool WaitEvent(string method, int timeoutMs)
        {
            string tag = "\"method\":\"" + method + "\"";
            foreach (string e in events) if (e.IndexOf(tag, StringComparison.Ordinal) >= 0) return true;
            Stopwatch sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                string msg = Receive((int)Math.Max(100, timeoutMs - sw.ElapsedMilliseconds));
                if (msg == null) return false;
                if (msg.IndexOf(tag, StringComparison.Ordinal) >= 0) return true;
            }
            return false;
        }
    }

    // ------------------------------------------------------------------ Screenshot scope proxy (loopback only)
    // The headless browser is pointed at this proxy; it forwards only to the scanned origin(s) - always to the IP the
    // scanner used - and refuses everything else (third-party scripts, fonts, telemetry, other hosts, redirects off
    // the origin). Upstream connections go through Extras.Connect, so a -Proxy jump host is honoured too.
    public sealed class ScopeProxy : IDisposable
    {
        readonly TcpListener listener;
        readonly Dictionary<string, string> allow = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly int timeoutMs;
        volatile bool stopped;
        public int Port { get; private set; }
        public int Allowed, Denied;
        public readonly List<string> DeniedOrigins = new List<string>();

        public ScopeProxy(System.Collections.IDictionary allowed, int timeoutMs)
        {
            foreach (System.Collections.DictionaryEntry e in allowed) allow[Convert.ToString(e.Key, CultureInfo.InvariantCulture).Trim('[', ']')] = Convert.ToString(e.Value, CultureInfo.InvariantCulture);
            this.timeoutMs = timeoutMs;
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start(64);
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            Thread t = new Thread(AcceptLoop); t.IsBackground = true; t.Start();
        }
        void AcceptLoop()
        {
            while (!stopped)
            {
                TcpClient c;
                try { c = listener.AcceptTcpClient(); } catch (Exception) { return; }
                Thread t = new Thread(delegate() { Handle(c); }); t.IsBackground = true; t.Start();
            }
        }
        string Lookup(string hostPort)
        {
            string ip;
            string key = hostPort.ToLowerInvariant();
            int b = key.IndexOf(']');
            if (key.StartsWith("[", StringComparison.Ordinal) && b > 0) key = key.Substring(1, b - 1) + key.Substring(b + 1);
            return allow.TryGetValue(key, out ip) ? ip : null;
        }
        void Refuse(Stream s, string origin)
        {
            Interlocked.Increment(ref Denied);
            lock (DeniedOrigins) { if (DeniedOrigins.Count < 25 && !DeniedOrigins.Contains(origin)) DeniedOrigins.Add(origin); }
            byte[] r = Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            try { s.Write(r, 0, r.Length); } catch { }
        }
        void Handle(TcpClient c)
        {
            TcpClient up = null;
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                MemoryStream head = new MemoryStream();
                int x; int matched = 0;
                while (head.Length < 65536 && (x = s.ReadByte()) >= 0)
                {
                    head.WriteByte((byte)x);
                    matched = (x == '\r' && (matched == 0 || matched == 2)) ? matched + 1 : (x == '\n' && (matched == 1 || matched == 3)) ? matched + 1 : 0;
                    if (matched == 4) break;
                }
                string h = Encoding.ASCII.GetString(head.ToArray());
                string[] lines = h.Split(new[] { "\r\n" }, StringSplitOptions.None);
                string[] first = lines[0].Split(' ');
                if (first.Length < 3) return;
                string method = first[0].ToUpperInvariant(), target = first[1];
                if (method == "CONNECT")
                {
                    int colon = target.LastIndexOf(':');
                    int port = colon > 0 ? int.Parse(target.Substring(colon + 1), CultureInfo.InvariantCulture) : 443;
                    string ip = Lookup(target);
                    if (ip == null) { Refuse(s, target); return; }
                    string st;
                    up = Extras.Open(ip, port, timeoutMs, out st);
                    if (up == null) { byte[] f = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"); s.Write(f, 0, f.Length); return; }
                    Interlocked.Increment(ref Allowed);
                    byte[] ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
                    s.Write(ok, 0, ok.Length);
                    Pipe(s, up.GetStream());
                    return;
                }
                Uri u;
                if (!Uri.TryCreate(target, UriKind.Absolute, out u) || u.Scheme != "http") { Refuse(s, target); return; }
                string origin = u.Host + ":" + u.Port.ToString(CultureInfo.InvariantCulture);
                string uip = Lookup(origin);
                if (uip == null) { Refuse(s, origin); return; }
                string st2;
                up = Extras.Open(uip, u.Port, timeoutMs, out st2);
                if (up == null) { byte[] f = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"); s.Write(f, 0, f.Length); return; }
                Interlocked.Increment(ref Allowed);
                StringBuilder rq = new StringBuilder();
                rq.Append(first[0]).Append(' ').Append(u.PathAndQuery).Append(' ').Append(first[2]).Append("\r\n");
                for (int i = 1; i < lines.Length; i++)
                {
                    string l = lines[i];
                    if (l.Length == 0) continue;
                    string n = l.Split(':')[0].Trim().ToLowerInvariant();
                    if (n == "proxy-connection" || n == "proxy-authorization" || n == "connection" || n == "keep-alive") continue;
                    rq.Append(l).Append("\r\n");
                }
                rq.Append("Connection: close\r\n\r\n");
                byte[] rb = Encoding.ASCII.GetBytes(rq.ToString());
                NetworkStream us = up.GetStream();
                us.Write(rb, 0, rb.Length);
                Pipe(s, us);
            }
            catch (Exception) { }
            finally { Extras.Close(up); try { c.Close(); } catch { } }
        }
        void Pipe(Stream a, Stream b)
        {
            Thread t = new Thread(delegate() { Copy(b, a); }); t.IsBackground = true; t.Start();
            Copy(a, b);
            t.Join(timeoutMs);
        }
        static void Copy(Stream from, Stream to)
        {
            byte[] buf = new byte[16384];
            try { int n; while ((n = from.Read(buf, 0, buf.Length)) > 0) { to.Write(buf, 0, n); to.Flush(); } }
            catch (Exception) { }
            try { to.Close(); } catch { }
        }
        public void Dispose() { stopped = true; try { listener.Stop(); } catch { } }
    }
}
'@

function Initialize-Extras {
    if ('WebInv.Extras' -as [type]) {
        if ([WebInv.Extras]::Version -ne $ScriptVersion) { throw ("WebInv extras v{0} are already loaded in this PowerShell session (script is v{1}). Open a new PowerShell window." -f [WebInv.Extras]::Version, $ScriptVersion) }
    }
    else {
        $swc = [Diagnostics.Stopwatch]::StartNew()
        $addType = @{ TypeDefinition = $ExtrasSource; ErrorAction = 'Stop' }
        if ($PSVersionTable.PSEdition -ne 'Core') { $addType.ReferencedAssemblies = @('System.Core') }
        Add-Type @addType
        Write-RunLog ("Extras compiled in {0} ms" -f $swc.ElapsedMilliseconds) 'DEBUG'
    }
    if (-not [WebInv.Extras]::BindEngine()) { throw 'the extras could not bind to the scan engine (WebInv.Net.Connect)' }
}

# ---------- screenshots: headless Edge/Chromium through a loopback scope proxy ----------
function Find-Browser {
    if ($BrowserPath) {
        if (-not (Test-Path -LiteralPath $BrowserPath -PathType Leaf)) { throw "browser not found: $BrowserPath" }
        return (Resolve-Path -LiteralPath $BrowserPath).ProviderPath
    }
    $cands = @()
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA)) { if ($base) { $cands += (Join-Path $base 'Microsoft\Edge\Application\msedge.exe') } }
    foreach ($c in $cands) { if (Test-Path -LiteralPath $c -PathType Leaf) { return $c } }
    throw 'Microsoft Edge was not found in Program Files; pass -BrowserPath (msedge.exe or another Chromium browser)'
}

function ConvertTo-ArgString([string[]]$List) {
    # Windows command-line quoting (CommandLineToArgvW rules)
    (@(foreach ($a in $List) {
                if ($a -notmatch '[\s"]') { $a; continue }
                '"' + ($a -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
            }) -join ' ')
}

function Stop-ProcessTree($Proc) {
    if (-not $Proc -or $Proc.HasExited) { return }
    try {
        if ($isWindows_) { & taskkill.exe /PID $Proc.Id /T /F 2>&1 | Out-Null }
        elseif ($PSVersionTable.PSEdition -eq 'Core') { $Proc.Kill($true) }
        else { $Proc.Kill() }
    }
    catch { try { $Proc.Kill() } catch { } }
}

# starts the browser headless on about:blank with a fresh profile, the scope proxy and a loopback DevTools port
function Start-Browser {
    param([int]$ProxyPort, [string]$ProfileDir)
    $argv = @('--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-sync',
        '--disable-background-networking', '--disable-component-update', '--disable-default-apps', '--disable-domain-reliability',
        '--disable-client-side-phishing-detection', '--disable-features=Translate,OptimizationHints,MediaRouter,InterestFeedContentSuggestions,AutofillServerCommunication',
        '--metrics-recording-only', '--no-pings', '--mute-audio', '--hide-scrollbars', '--dns-prefetch-disable', '--disable-quic',
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--ignore-certificate-errors',
        ('--user-data-dir=' + $ProfileDir), ('--proxy-server=http://127.0.0.1:{0}' -f $ProxyPort), '--proxy-bypass-list=<-loopback>',
        '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0')
    if ($BrowserArgument) { $argv += @($BrowserArgument) }
    $argv += 'about:blank'
    New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:BrowserExe; $psi.Arguments = ConvertTo-ArgString $argv
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardError = $true; $psi.RedirectStandardOutput = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    # drain the pipes so a chatty browser can never block on a full buffer
    $null = $p.StandardOutput.ReadToEndAsync(); $null = $p.StandardError.ReadToEndAsync()
    $p
}

function Remove-ProfileDir([string]$Dir) {
    for ($i = 0; $i -lt 3; $i++) {
        try { if (Test-Path -LiteralPath $Dir) { Remove-Item -LiteralPath $Dir -Recurse -Force -ErrorAction Stop }; return }
        catch { Start-Sleep -Milliseconds 300 }
    }
    Write-RunLog ("screenshot: temporary browser profile not removed: {0}" -f $Dir) 'WARN'
}

# Captures every web service of this run. The browser only reaches origins this run scanned on the same IP, always at
# the IP the scanner used (the loopback proxy answers 403 for anything else: CDNs, fonts, analytics, other hosts).
function Invoke-Screenshots {
    param([string]$CsvFile)
    $index = @{}
    $rows = @(Import-Csv -LiteralPath $CsvFile | Where-Object { $_.IsWeb -eq 'True' -and $_.Url -match '^https?://' })
    $folderName = 'WebInventory_{0}_screenshots' -f $script:RunId
    $folder = Join-Path $OutputDir $folderName
    $script:ShotIndexPath = Join-Path $OutputDir ('WebInventory_{0}_screenshots.csv' -f $script:RunId)
    if (-not $rows.Count) { Write-RunLog 'Screenshots: no web services in this run'; return $index }
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    $tmpRoot = Join-Path ([IO.Path]::GetTempPath()) ('wi-shot-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null
    $prev = @{}
    if (Test-Path -LiteralPath $script:ShotIndexPath) { foreach ($r in @(Import-Csv -LiteralPath $script:ShotIndexPath)) { if ($r.Status -eq 'ok' -and (Test-Path -LiteralPath (Join-Path $OutputDir $r.File))) { $prev[$r.Url] = $r } } }
    # origins scanned per IP (host:port and ip:port -> scanned IP)
    $byIp = @{}
    foreach ($r in $rows) {
        if (-not $byIp.ContainsKey($r.IP)) { $byIp[$r.IP] = @{} }
        foreach ($u in @($r.Url, $r.FinalUrl)) {
            if (-not $u) { continue }
            try { $uu = [Uri]$u } catch { continue }
            if ($u -eq $r.FinalUrl -and $uu.Host.Trim('[', ']') -ne $r.Host -and $uu.Host.Trim('[', ']') -ne $r.IP) { continue }
            $byIp[$r.IP][('{0}:{1}' -f $uu.Host.Trim('[', ']'), $uu.Port).ToLowerInvariant()] = $r.IP
        }
        $byIp[$r.IP][('{0}:{1}' -f $r.IP, $r.Port).ToLowerInvariant()] = $r.IP
    }
    $out = New-Object System.Collections.Generic.List[object]
    try {
        # canary: the browser must send its traffic to our proxy (an enterprise proxy policy overrides --proxy-server)
        $canary = [WebInv.ScopeProxy]::new([hashtable]@{}, $TimeoutMs)
        $cdir = Join-Path $tmpRoot 'canary'
        $cp = Start-Browser -ProxyPort $canary.Port -ProfileDir $cdir
        $cc = [WebInv.CdpCapture]::new($cdir, 'http://wi-proxy-check.invalid/', (Join-Path $tmpRoot 'canary.png'), 800, 600, [Math]::Min(30, $ScreenshotTimeoutSec) * 1000)
        $cc.Start()
        $csw = [Diagnostics.Stopwatch]::StartNew()
        while (-not $cc.Done -and $csw.Elapsed.TotalSeconds -lt [Math]::Min(35, $ScreenshotTimeoutSec + 5)) { Start-Sleep -Milliseconds 100 }
        Stop-ProcessTree $cp; [void]$cp.WaitForExit(5000)
        $canary.Dispose()
        Remove-ProfileDir $cdir
        Write-RunLog ("screenshot canary: proxy saw {0} request(s); {1}" -f $canary.Denied, $cc.Status) 'DEBUG'
        if ($canary.Denied -lt 1) {
            Write-ErrLog 'SCREENSHOT' '-' ("the browser did not send its traffic to the scope proxy ({0}); a browser policy may force its own proxy or block headless mode / remote debugging. No screenshots taken." -f $cc.Status)
            Write-Host 'Screenshots: skipped - the browser did not use the scope proxy (policy?). See the error log.' -ForegroundColor Yellow
            return $index
        }
        $queue = New-Object System.Collections.Generic.Queue[object]
        $n = 0
        foreach ($r in $rows) {
            $n++
            if ($prev.ContainsKey($r.Url)) { $out.Add($prev[$r.Url]); $index[$r.Url] = ($prev[$r.Url].File -replace '\\', '/'); continue }
            $uh = ([Uri]$r.Url).Host.Trim('[', ']')
            $name = ('{0:D4}_{1}_{2}.png' -f $n, ($uh -replace '[^\w.\-]', '_'), $r.Port)
            $queue.Enqueue([pscustomobject]@{ Row = $r; Name = $name })
        }
        $sw_, $sh_ = $ScreenshotSize.Split('x')
        $running = New-Object System.Collections.Generic.List[object]
        $done = 0; $total = $queue.Count
        while ($queue.Count -or $running.Count) {
            while ($queue.Count -and $running.Count -lt $ScreenshotThreads) {
                $q = $queue.Dequeue()
                $px = [WebInv.ScopeProxy]::new([hashtable]$byIp[$q.Row.IP], $TimeoutMs)
                $pdir = Join-Path $tmpRoot ([guid]::NewGuid().ToString('N').Substring(0, 8))
                $file = Join-Path $folder $q.Name
                try { $proc = Start-Browser -ProxyPort $px.Port -ProfileDir $pdir }
                catch { $px.Dispose(); Write-ErrLog 'SCREENSHOT' $q.Row.Url ("browser did not start: {0}" -f $_.Exception.Message); continue }
                $cap = [WebInv.CdpCapture]::new($pdir, $q.Row.Url, $file, [int]$sw_, [int]$sh_, $ScreenshotTimeoutSec * 1000)
                $cap.Start()
                $running.Add([pscustomobject]@{ Q = $q; Proxy = $px; Proc = $proc; Cap = $cap; Dir = $pdir; File = $file; Sw = [Diagnostics.Stopwatch]::StartNew() })
            }
            Start-Sleep -Milliseconds 100
            foreach ($j in $running.ToArray()) {
                $timedOut = $j.Sw.Elapsed.TotalSeconds -ge ($ScreenshotTimeoutSec + 5)
                if (-not $j.Cap.Done -and -not $timedOut -and -not $j.Proc.HasExited) { continue }
                Stop-ProcessTree $j.Proc; [void]$j.Proc.WaitForExit(5000)
                $j.Proxy.Dispose()
                $status = if ($j.Cap.Done) { $j.Cap.Status } elseif ($j.Proc.HasExited -and -not $timedOut) { 'failed: the browser exited' } else { 'timeout' }
                $sha = ''; $bytes = 0
                if ($status -like 'ok*' -and (Test-Path -LiteralPath $j.File)) { $b = [IO.File]::ReadAllBytes($j.File); $bytes = $b.Length; $sha = [WebInv.Hash]::Sha256Hex($b) }
                elseif (Test-Path -LiteralPath $j.File) { Remove-Item -LiteralPath $j.File -Force -ErrorAction SilentlyContinue }
                # resources the page asked for outside the scanned origins (refused by the proxy); browser chatter is not counted
                $allow = $byIp[$j.Q.Row.IP]
                $denied = New-Object System.Collections.Generic.List[string]
                $pageReq = 0
                foreach ($ru in $j.Cap.Requests.ToArray()) {
                    $u2 = $null
                    if (-not [Uri]::TryCreate($ru, [UriKind]::Absolute, [ref]$u2) -or ($u2.Scheme -ne 'http' -and $u2.Scheme -ne 'https')) { continue }
                    $pageReq++
                    $o2 = ('{0}:{1}' -f $u2.Host.Trim('[', ']'), $u2.Port).ToLowerInvariant()
                    if (-not $allow.ContainsKey($o2) -and -not $denied.Contains($o2)) { $denied.Add($o2) }
                }
                $out.Add([pscustomobject][ordered]@{ Url = $j.Q.Row.Url; Host = $j.Q.Row.Host; IP = $j.Q.Row.IP; Port = $j.Q.Row.Port
                        File = $(if ($bytes) { '{0}/{1}' -f $folderName, $j.Q.Name } else { '' }); Sha256 = $sha; Bytes = $bytes; Status = $status
                        PageTitle = [WebInv.Util]::Printable($j.Cap.Title, 200); PageRequests = $pageReq; BlockedOrigins = ($denied.ToArray() -join ';'); ProxyRefused = $j.Proxy.Denied; Ms = $j.Sw.ElapsedMilliseconds
                    })
                if ($bytes) { $index[$j.Q.Row.Url] = '{0}/{1}' -f $folderName, $j.Q.Name }
                if ($status -notlike 'ok*') { Write-ErrLog 'SCREENSHOT' $j.Q.Row.Url $status }
                Remove-ProfileDir $j.Dir
                [void]$running.Remove($j); $done++
            }
            if (-not $NoProgress) { Write-Progress -Activity 'WebInventory screenshots' -Status ("{0}/{1}" -f $done, $total) -PercentComplete ([int](100 * $done / [Math]::Max(1, $total))) }
        }
    }
    finally {
        if (-not $NoProgress) { Write-Progress -Activity 'WebInventory screenshots' -Completed }
        # (no @() around the List: PowerShell 7.4 throws 'Argument types do not match' for some empty generic lists)
        if ($running) { foreach ($j in $running.ToArray()) { Stop-ProcessTree $j.Proc; try { $j.Proxy.Dispose() } catch { } } }
        Remove-ProfileDir $tmpRoot
        if ($out.Count) {
            $lines = @($out | Sort-Object { [string]$_.File } | ConvertTo-Csv -NoTypeInformation)
            [IO.File]::WriteAllLines($script:ShotIndexPath, [string[]]$lines, $script:Utf8Bom)
        }
    }
    $ok = @($out | Where-Object { $_.Status -like 'ok*' }).Count
    $msg = 'Screenshots: {0} of {1} web services captured -> {2}' -f $ok, $rows.Count, $folder
    Write-RunLog $msg
    if (-not $Quiet) { Write-Host $msg -ForegroundColor Cyan }
    $index
}
#endregion

#region ---------- Extras self-test (part of -SelfTest; offline: vectors from the reference implementations / RFCs) ----------
function Invoke-ExtrasSelfTest {
    $script:ExtrasCompiled = $false
    Assert 'extras: probe block compiles (C# 5) and binds to the scan engine' { Initialize-Extras; $script:ExtrasCompiled = $true; $true }
    if (-not $script:ExtrasCompiled) { return }
    $hex = { param($h) [byte[]]@(for ($i = 0; $i -lt $h.Length; $i += 2) { [Convert]::ToByte($h.Substring($i, 2), 16) }) }
    # JARM: hash and ServerHello parsing compared with salesforce/jarm jarm.py
    Assert 'extras: JARM fuzzy hash (jarm.py vector)' {
        [WebInv.Jarm]::Hash('c02f|0303|h2|ff01-0000-0001-000b-0023-0010-0017,c030|0303|http/1.1|ff01-0000-0001-000b-0023-0017,|||,009c|0302||ff01-0023,1301|0303|h2|002b-0033,|||,1302|0303||002b-0033-0029,c013|0301||,|||,1303|0303|http/1.1|002b') -eq '29d2ad00013c41d00042d21b00043d86875826825ae87406599456ff0754d6' -and
        [WebInv.Jarm]::Hash([WebInv.Jarm]::Empty) -eq ('0' * 62)
    }
    Assert 'extras: JARM ServerHello parsing (jarm.py read_packet vector)' {
        $sh = & $hex '1603030068020000640303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fc02f00001cff0100010000000000000b0002010000100005000302683200170000'
        ([WebInv.Jarm]::Read($sh) -eq 'c02f|0303|h2|ff01-0000-000b-0010-0017') -and ([WebInv.Jarm]::Read([byte[]]@(21, 3, 3, 0, 2, 2, 40)) -eq '|||') -and ([WebInv.Jarm]::Read([byte[]]@()) -eq '|||')
    }
    Assert 'extras: JARM ClientHello (record, version, 69 ciphers, SNI)' {
        $p = [WebInv.Jarm]::Build([string[]]@('TLS_1.2', 'ALL', 'FORWARD', 'NO_GREASE', 'APLN', '1.2_SUPPORT', 'REVERSE'), 'host.example')
        $p[0] -eq 0x16 -and $p[1] -eq 3 -and $p[2] -eq 3 -and $p[5] -eq 1 -and $p[43] -eq 32 -and (($p[76] * 256 + $p[77]) -eq 138) -and ([Text.Encoding]::ASCII.GetString($p) -like '*host.example*')
    }
    Assert 'extras: JA4S from the first ServerHello (FoxIO JA4S method)' {
        ([WebInv.Ja4s]::FromHelloInfo('0304|1301|002b,0033|') -eq 't130200_1301_a56c5b993250') -and ([WebInv.Ja4s]::FromHelloInfo('0303|c02f||h2') -eq 't1200h2_c02f_000000000000')
    }
    Assert 'extras: NTLM CHALLENGE target info and Windows build' {
        $n = [WebInv.Ntlm]::ParseChallenge((& $hex '4e544c4d5353500002000000060006003800000015828ae211111111111111110000000000000000800080003e0000000a007c4f0000000f4c0041004200020006004c00410042000100120052004400500048004f005300540030003100040010006c00610062002e0074006500730074000300240072006400700068006f0073007400300031002e006c00610062002e007400650073007400050010006c00610062002e007400650073007400070008000080209bcb82d80100000000'))
        $n.Ok -and $n.Version -eq '10.0.20348' -and $n.NbComputer -eq 'RDPHOST01' -and $n.NbDomain -eq 'LAB' -and $n.DnsComputer -eq 'rdphost01.lab.test' -and $n.DnsDomain -eq 'lab.test'
    }
    Assert 'extras: NTLM NEGOTIATE / SPNEGO wrapping' {
        $neg = [WebInv.Ntlm]::Negotiate(); $sp = [WebInv.Ntlm]::SpnegoInit($neg)
        $neg.Length -eq 40 -and $sp[0] -eq 0x60 -and ([BitConverter]::ToString($sp) -replace '-', '') -like '*2B0601050502*'
    }
    Assert 'extras: SNMPv3 key localisation (RFC 3414 A.3 vectors, MD5 and SHA)' {
        $eid = & $hex '000000000000000000000002'
        ((([BitConverter]::ToString([WebInv.Snmp]::LocalizeKey('MD5', 'maplesyrup', $eid)) -replace '-', '').ToLowerInvariant()) -eq '526f5eed9fcce26f8964c2930787d82b') -and
        ((([BitConverter]::ToString([WebInv.Snmp]::LocalizeKey('SHA', 'maplesyrup', $eid)) -replace '-', '').ToLowerInvariant()) -eq '6695febc9288e36282235fc7151f128497b38f3f')
    }
    Assert 'extras: protocol URLs (smb://, rdp://, snmp://) and default ports' {
        $a = Split-HostPort 'smb://fs01'; $b = Split-HostPort 'rdp://[fe80::1]:3390'; $c = Split-HostPort 'snmp://10.0.0.1:1161'
        $a.Spec -eq 'fs01' -and $a.Ports -eq '445' -and $a.Scheme -eq 'smb' -and $b.Spec -eq 'fe80::1' -and $b.Ports -eq '3390' -and $b.Scheme -eq 'rdp' -and $c.Ports -eq '1161' -and $c.Scheme -eq 'snmp'
    }
    Assert 'extras: screenshot scope proxy refuses origins outside the scanned set' {
        $px = [WebInv.ScopeProxy]::new([hashtable]@{ '127.0.0.1:9' = '127.0.0.1' }, 2000)
        try {
            $c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', $px.Port)
            $s = $c.GetStream(); $q = [Text.Encoding]::ASCII.GetBytes("GET http://cdn.example.org/x.js HTTP/1.1`r`nHost: cdn.example.org`r`n`r`n"); $s.Write($q, 0, $q.Length)
            $buf = New-Object byte[] 64; $n = $s.Read($buf, 0, 64); $c.Close()
            $c2 = New-Object System.Net.Sockets.TcpClient('127.0.0.1', $px.Port)
            $s2 = $c2.GetStream(); $q2 = [Text.Encoding]::ASCII.GetBytes("CONNECT tracker.example.com:443 HTTP/1.1`r`n`r`n"); $s2.Write($q2, 0, $q2.Length)
            $buf2 = New-Object byte[] 64; $n2 = $s2.Read($buf2, 0, 64); $c2.Close()
            ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -like 'HTTP/1.1 403*') -and ([Text.Encoding]::ASCII.GetString($buf2, 0, $n2) -like 'HTTP/1.1 403*') -and $px.Denied -eq 2
        }
        finally { $px.Dispose() }
    }
}
#endregion


#region ---------- Output schema and writers ----------
$Columns = @(
    'RunId', 'ScanTag', 'ScannedAt', 'Host', 'IP', 'Port', 'ReverseDns', 'Vhost', 'VhostOf', 'State', 'IsWeb', 'Service', 'Scheme', 'Url', 'FinalUrl',
    'StatusCode', 'Title', 'Server', 'PoweredBy', 'Generator', 'ContentType', 'BodyLength', 'BodySha256', 'ResponseMs', 'RedirectChain',
    'Auth', 'Cookies', 'CookieFlagIssues', 'MissingSecHeaders', 'HstsMaxAge', 'AltSvc',
    'Products', 'Technologies', 'Categories', 'CPEs', 'OsHint', 'Hardware',
    'FaviconPath', 'FaviconMmh3', 'FaviconMd5', 'Robots', 'SecurityTxt', 'AllowedMethods', 'RiskyMethods', 'IdentifiedPaths',
    'TlsVersion', 'TlsCipher', 'TlsKeyExchange', 'TlsSupported', 'TlsCiphersByVersion', 'TlsWeakCipher', 'Alpn', 'Http2',
    'CertSubject', 'CertIssuer', 'CertSANs', 'CertNotBefore', 'CertNotAfter', 'CertDaysLeft', 'CertSelfSigned', 'CertSigAlg',
    'CertKeyAlg', 'CertKeySize', 'CertSerial', 'CertSha1', 'CertSha256', 'CertPolicyErrors', 'CertChainStatus', 'CertSource',
    'Flags', 'Advisories', 'Banner', 'Notes',
    # v2.3 (appended so existing CSV consumers keep their column positions)
    'DeviceName', 'Domain', 'ProtocolInfo', 'Jarm', 'Ja4s')

function Open-Outputs {
    param([string]$Dir, [string]$RunId)
    $script:CsvPath = Join-Path $Dir ("WebInventory_{0}.csv" -f $RunId)
    $script:JsonlPath = Join-Path $Dir ("WebInventory_{0}.jsonl" -f $RunId)
    $script:ProgressPath = Join-Path $Dir ("WebInventory_{0}_progress.txt" -f $RunId)
    $newCsv = -not (Test-Path -LiteralPath $script:CsvPath)
    $script:CsvW = New-Object System.IO.StreamWriter($script:CsvPath, $true, $script:Utf8Bom); $script:CsvW.AutoFlush = $true
    if ($newCsv) { $script:CsvW.WriteLine((($Columns | ForEach-Object { '"' + $_ + '"' }) -join ',')) }
    $script:JsonW = New-Object System.IO.StreamWriter($script:JsonlPath, $true, $script:Utf8NoBom); $script:JsonW.AutoFlush = $true
    $script:ProgW = New-Object System.IO.StreamWriter($script:ProgressPath, $true, $script:Utf8NoBom); $script:ProgW.AutoFlush = $true
}

function Close-Outputs {
    foreach ($n in 'CsvW', 'JsonW', 'ProgW') {
        $w = Get-Variable -Name $n -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($w) { try { $w.Flush(); $w.Dispose() } catch { } }
        Set-Variable -Name $n -Scope Script -Value $null
    }
}

function Write-ResultRow {
    # CSV + JSONL lines are built in C# (WebInv.Out): same quoting/flattening/formula guard as v2.0, JSON with the
    # same types as ConvertTo-Json and HTML-sensitive characters escaped
    param($Row)
    $n = $Columns.Count
    $cv = New-Object object[] $n
    for ($i = 0; $i -lt $n; $i++) { $cv[$i] = $Row[$Columns[$i]] }
    $jv = New-Object object[] ($n + 1)
    [Array]::Copy($cv, $jv, $n)
    $jv[$n] = [object[]]@($Row['_Detections'])
    $script:CsvW.WriteLine([WebInv.Out]::CsvLine($cv, -not $NoCsvSanitize))
    $script:JsonW.WriteLine([WebInv.Out]::JsonLine($script:JsonNames, $jv))
}

function Write-Hit {
    param($Row)
    if ($Quiet) { return }
    $P = { param($s, $n) [WebInv.Util]::Printable([string]$s, $n) }
    $tag = '[+]'; $tagColor = 'Green'
    $proto = @('smb', 'rdp', 'snmp') -contains $Row.Scheme
    if (-not $Row.IsWeb -and -not $proto) { if ($Row._SchannelIncompatible) { $tag = '[!]'; $tagColor = 'Yellow' } else { $tag = '[~]'; $tagColor = 'DarkYellow' } }
    $host_ = if ($Row.Vhost) { '{0} (vhost of {1})' -f $Row.Host, $Row.VhostOf } else { '' }
    $tls = ''
    if (($Row.TlsVersion -or $Row.TlsSupported) -and -not $proto) {
        $cn = if ($Row.CertSubject -match 'CN=([^,]+)') { $Matches[1] } else { '' }
        $v = if ($Row.TlsVersion) { $Row.TlsVersion } else { 'raw:' + $Row.TlsSupported }
        $tls = ' [{0}{1} {2} {3}d]' -f $v, $(if ($Row.Http2 -eq $true) { ' h2' } else { '' }), (& $P $cn 40), $Row.CertDaysLeft
    }
    $main = if ($Row.IsWeb) {
        '{0} [{1}] [{2}] [{3}] [{4}]' -f $Row.Url, $Row.StatusCode, (& $P $Row.Server 60), (& $P $Row.Title 70), (& $P $Row.Products 120)
    } elseif ($proto) {
        $what = @($Row.DeviceName, $Row.OsHint, $Row.Products, $(if ($Row.Scheme -eq 'snmp') { $Row.Banner })) | Where-Object { $_ } | Select-Object -Unique
        '{0} [{1}] [{2}] [{3}]' -f $Row.Url, (& $P (($what) -join ' | ') 140), (& $P $Row.ProtocolInfo 120), $(if ($Row.CertSubject -match 'CN=([^,]+)') { 'cert ' + (& $P $Matches[1] 40) + ' ' + $Row.CertDaysLeft + 'd' } else { '-' })
    } else {
        '{0} [{1}] [{2}] [{3}]' -f $Row.Url, $Row.Service, (& $P $Row.Products 100), (& $P $Row.Banner 80)
    }
    Write-Host ($tag + ' ') -ForegroundColor $tagColor -NoNewline
    Write-Host ($main + $tls + $(if ($host_) { " $host_" } else { '' })) -NoNewline
    if ($Row.Flags) {
        $crit = $Row.Flags -match 'CertExpired|WeakCipher|CleartextAuth|ADCSWebEnrollment|DirectoryListing|PhpInfoExposed|SchannelIncompatible|WeakTLS:SSL3|PHP2Shell:(?:vulnerable|eol)|SMBv1|RdpStandardSecurity'
        Write-Host (' !' + (& $P $Row.Flags 160)) -ForegroundColor $(if ($crit) { 'Red' } else { 'Yellow' })
    }
    else { Write-Host '' }
}
#endregion

#region ---------- Baseline delta ----------
function Compare-Baseline {
    param([string]$BaselinePath, [string]$CurrentCsv, [string]$DeltaPath)
    $fields = @('IP', 'Scheme', 'StatusCode', 'Title', 'Server', 'Products', 'CertSha256', 'CertNotAfter', 'TlsSupported', 'FaviconMmh3', 'Flags', 'Advisories')
    $old = @{}; foreach ($r in (Import-Csv -LiteralPath $BaselinePath)) { $old['{0}|{1}' -f $r.Host, $r.Port] = $r }
    $new = @{}; foreach ($r in (Import-Csv -LiteralPath $CurrentCsv)) { $new['{0}|{1}' -f $r.Host, $r.Port] = $r }
    $delta = New-Object System.Collections.Generic.List[object]
    foreach ($k in $new.Keys) {
        if (-not $old.ContainsKey($k)) { $delta.Add([pscustomobject]@{ Change = 'NEW'; Key = $k; Field = ''; Old = ''; New = ('{0} {1}' -f $new[$k].Url, $new[$k].Products) }); continue }
        foreach ($f in $fields) {
            $ov = [string]$old[$k].$f; $nv = [string]$new[$k].$f
            if ($ov -ne $nv) { $delta.Add([pscustomobject]@{ Change = 'CHANGED'; Key = $k; Field = $f; Old = $ov; New = $nv }) }
        }
    }
    foreach ($k in $old.Keys) { if (-not $new.ContainsKey($k)) { $delta.Add([pscustomobject]@{ Change = 'REMOVED'; Key = $k; Field = ''; Old = ('{0} {1}' -f $old[$k].Url, $old[$k].Products); New = '' }) } }
    $delta | Sort-Object Change, Key, Field | Export-Csv -LiteralPath $DeltaPath -NoTypeInformation -Encoding UTF8
    @{ New = @($delta | Where-Object Change -eq 'NEW').Count; Removed = @($delta | Where-Object Change -eq 'REMOVED').Count; Changed = @($delta | Where-Object Change -eq 'CHANGED' | Select-Object -ExpandProperty Key -Unique).Count }
}
#endregion

#region ---------- Integrity manifest (SHA-256 of every output, for audit evidence) ----------
function Write-Manifest {
    param([string[]]$Files, [string]$Path)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('# WebInventory {0} manifest  RunId={1}  created={2}  host={3}  user={4}' -f $ScriptVersion, $script:RunId, (Get-Date).ToString('o'), [Environment]::MachineName, $script:Operator))
    $lines.Add('# sha256  bytes  file')
    foreach ($f in $Files) {
        if (-not $f -or -not (Test-Path -LiteralPath $f)) { continue }
        $b = [IO.File]::ReadAllBytes($f)
        # files in a subfolder of the output folder (screenshots) keep their relative path
        $base = (Split-Path -Parent $Path) + [IO.Path]::DirectorySeparatorChar
        $name = if ($f.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { $f.Substring($base.Length) } else { Split-Path -Leaf $f }
        $lines.Add(('{0}  {1}  {2}' -f [WebInv.Hash]::Sha256Hex($b), $b.Length, $name))
    }
    [IO.File]::WriteAllLines($Path, $lines.ToArray(), $script:Utf8NoBom)
}
#endregion

#region ---------- Self-contained HTML report (offline; no external fonts/scripts) ----------
function New-HtmlReport {
    param([string]$CsvFile, [string]$HtmlFile, [hashtable]$Meta, [hashtable]$Screenshots)
    $rows = @(Import-Csv -LiteralPath $CsvFile)
    $data = @($rows | ForEach-Object {
            [ordered]@{ u = $_.Url; h = $_.Host; ip = $_.IP; p = $_.Port; sv = $_.Service; w = $_.IsWeb; s = $_.StatusCode; t = $_.Title; srv = $_.Server
                pr = $_.Products; c = $_.Categories; os = $_.OsHint; hw = $_.Hardware; tls = $_.TlsVersion; tsup = $_.TlsSupported; h2 = $_.Http2
                cd = $_.CertDaysLeft; cs = $_.CertSubject; ci = $_.CertIssuer; san = $_.CertSANs; f = $_.Flags; fav = $_.FaviconMmh3; cpe = $_.CPEs
                vh = $_.VhostOf; rd = $_.ReverseDns; au = $_.Auth; fu = $_.FinalUrl; rc = $_.RedirectChain; b = $_.Banner; n = $_.Notes; adv = $_.Advisories
                dn = $_.DeviceName; dom = $_.Domain; pi = $_.ProtocolInfo; jarm = $_.Jarm; ja4s = $_.Ja4s
                shot = $(if ($Screenshots -and $Screenshots.ContainsKey([string]$_.Url)) { $Screenshots[[string]$_.Url] } else { '' }) } })
    # strip control characters (ANSI escapes etc. from hostile headers) - they are inert in textContent but unreadable
    foreach ($o in $data) { foreach ($k in @($o.Keys)) { $o[$k] = [WebInv.Util]::Printable([string]$o[$k], 8000) } }
    $json = if ($data.Count) { ConvertTo-Json -InputObject $data -Compress -Depth 3 } else { '[]' }
    # neutralise anything that could terminate the script element or be parsed as markup
    $bs = '\'
    $json = $json.Replace('<', $bs + 'u003c').Replace('>', $bs + 'u003e').Replace('&', $bs + 'u0026')
    $metaJson = (ConvertTo-Json -InputObject $Meta -Compress -Depth 3).Replace('<', $bs + 'u003c').Replace('>', $bs + 'u003e').Replace('&', $bs + 'u0026')
    $html = $script:HtmlTemplate.Replace('__DATA__', $json).Replace('__META__', $metaJson)
    [IO.File]::WriteAllText($HtmlFile, $html, $script:Utf8NoBom)
}

$script:HtmlTemplate = @'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Web Inventory Report</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--ink:#16181d;--muted:#5d6472;--line:#e3e6eb;--accent:#2457c5;--ok:#1f7a4d;--warn:#a15c00;--bad:#b42318;--chip:#eef1f6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1115;--panel:#171a21;--ink:#e7e9ee;--muted:#9aa3b2;--line:#2a2f3a;--accent:#7aa2ff;--ok:#4cc38a;--warn:#f0b35a;--bad:#ff7a6e;--chip:#222734}}
:root[data-theme="dark"]{--bg:#0f1115;--panel:#171a21;--ink:#e7e9ee;--muted:#9aa3b2;--line:#2a2f3a;--accent:#7aa2ff;--ok:#4cc38a;--warn:#f0b35a;--bad:#ff7a6e;--chip:#222734}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
header{padding:20px 24px 8px}h1{margin:0;font-size:20px;font-weight:650}.meta{color:var(--muted);font-size:12.5px;margin-top:4px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;padding:12px 24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.card b{display:block;font-size:22px;font-variant-numeric:tabular-nums}.card span{color:var(--muted);font-size:12px}
.lists{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px;padding:0 24px 12px}
.list{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.list h3{margin:0 0 8px;font-size:13px;color:var(--muted);font-weight:600}
.bar{display:flex;align-items:center;gap:8px;margin:3px 0;font-size:12.5px;cursor:pointer}.bar i{display:block;height:8px;background:var(--accent);border-radius:4px;opacity:.75}.bar em{font-style:normal;color:var(--muted);margin-left:auto;font-variant-numeric:tabular-nums}
.tools{display:flex;gap:8px;flex-wrap:wrap;padding:4px 24px 10px;align-items:center}input,select,button{font:inherit;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:7px 10px}
input{flex:1;min-width:200px}.count{color:var(--muted);font-size:12.5px}
.wrap{padding:0 24px 24px;overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:12.8px}th{position:sticky;top:0;background:var(--panel);cursor:pointer;white-space:nowrap;color:var(--muted);font-weight:600}
tr.r:hover{background:var(--chip)}td.u{min-width:190px;max-width:300px;word-break:break-all}td.t{max-width:260px}.chip{display:inline-block;background:var(--chip);border-radius:6px;padding:1px 6px;margin:1px 2px 1px 0;font-size:11.5px}
.chip.bad{color:var(--bad)}.chip.warn{color:var(--warn)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
tr.d td{background:var(--bg)}pre{margin:0;white-space:pre-wrap;word-break:break-word;font:12px/1.4 ui-monospace,Consolas,monospace}
@media (max-width:640px){header,.cards,.lists,.tools,.wrap{padding-left:16px;padding-right:16px}}
</style></head><body>
<header><h1>Web Inventory Report</h1><div class="meta" id="meta"></div></header>
<section class="cards" id="cards"></section>
<section class="lists"><div class="list"><h3>Top products</h3><div id="lp"></div></div><div class="list"><h3>Flags</h3><div id="lf"></div></div><div class="list"><h3>Categories</h3><div id="lc"></div></div></section>
<div class="tools"><input id="q" placeholder="Filter (host, product, title, flag, CPE...)"><select id="sv"><option value="">All services</option><option value="web">Web only</option><option value="tls">TLS only</option><option value="other">Non-web</option></select><button id="th" type="button">Theme</button><span class="count" id="cnt"></span></div>
<div class="wrap"><table><thead><tr><th data-k="u">URL</th><th data-k="s">Status</th><th data-k="t">Title</th><th data-k="pr">Products</th><th data-k="tls">TLS</th><th data-k="cd">Cert days</th><th data-k="f">Flags</th></tr></thead><tbody id="tb"></tbody></table></div>
<script type="application/json" id="data">__DATA__</script><script type="application/json" id="metadata">__META__</script>
<script>
(function(){
var D=JSON.parse(document.getElementById('data').textContent),M=JSON.parse(document.getElementById('metadata').textContent);
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
var crit=/CertExpired|WeakCipher|CleartextAuth|ADCSWebEnrollment|DirectoryListing|PhpInfoExposed|SchannelIncompatible|SSL3|PHP2Shell:(?:vulnerable|eol)/;
var meta=document.getElementById('meta');meta.textContent='Run '+(M.RunId||'')+(M.Tag?' \u00b7 '+M.Tag:'')+' \u00b7 '+(M.Started||'')+' \u00b7 '+(M.Duration||'')+' \u00b7 '+(M.Operator||'')+' on '+(M.Computer||'')+' \u00b7 v'+(M.Version||'');
var web=D.filter(function(r){return r.w==='True'}),hosts={},tlsN=0,flagged=0,exp=0,mg=0,adv=0;
D.forEach(function(r){hosts[r.ip]=1;if(r.tls||r.tsup)tlsN++;if(r.f)flagged++;var d=parseInt(r.cd,10);if(!isNaN(d)&&d<=30)exp++;if(/MgmtInterface/.test(r.f))mg++;if(/PHP2Shell:(vulnerable|eol)/.test(r.f))adv++});
[['Web services',web.length],['Hosts',Object.keys(hosts).length],['Open services',D.length],['TLS endpoints',tlsN],['Flagged',flagged],['Certs \u2264 30 days',exp],['Mgmt interfaces',mg],['Advisory exposures',adv]].forEach(function(c){var d=el('div','card');d.appendChild(el('b',null,c[1]));d.appendChild(el('span',null,c[0]));document.getElementById('cards').appendChild(d)});
function tally(key,split){var m={};D.forEach(function(r){(r[key]||'').split(split).forEach(function(x){x=x.trim();if(!x)return;if(key==='f')x=x.split(':')[0];m[x]=(m[x]||0)+1})});return Object.keys(m).map(function(k){return[k,m[k]]}).sort(function(a,b){return b[1]-a[1]}).slice(0,12)}
function bars(id,list){var box=document.getElementById(id),max=list.length?list[0][1]:1;list.forEach(function(p){var b=el('div','bar');var i=el('i');i.style.width=Math.max(4,Math.round(120*p[1]/max))+'px';b.appendChild(i);b.appendChild(el('span',null,p[0]));b.appendChild(el('em',null,p[1]));b.onclick=function(){q.value=p[0];render()};box.appendChild(b)});if(!list.length)box.appendChild(el('span','count','none'))}
bars('lp',tally('pr',';'));bars('lf',tally('f',';'));bars('lc',tally('c',';'));
var q=document.getElementById('q'),sv=document.getElementById('sv'),tb=document.getElementById('tb'),sortK='u',sortD=1;
function match(r){var f=q.value.toLowerCase(),s=sv.value;if(s==='web'&&r.w!=='True')return false;if(s==='tls'&&!(r.tls||r.tsup))return false;if(s==='other'&&r.w==='True')return false;if(!f)return true;return Object.keys(r).some(function(k){return(r[k]||'').toLowerCase().indexOf(f)>=0})}
function render(){tb.textContent='';var rows=D.filter(match).sort(function(a,b){var x=a[sortK]||'',y=b[sortK]||'';var nx=parseFloat(x),ny=parseFloat(y);if(!isNaN(nx)&&!isNaN(ny))return(nx-ny)*sortD;return x.localeCompare(y)*sortD});
document.getElementById('cnt').textContent=rows.length+' of '+D.length+' rows';
rows.forEach(function(r){var tr=el('tr','r');var u=el('td','u',r.u+(r.vh?'  (vhost of '+r.vh+')':''));tr.appendChild(u);tr.appendChild(el('td',null,r.s||r.sv));tr.appendChild(el('td','t',r.t||r.b));
var p=el('td');(r.pr||'').split(';').forEach(function(x){if(x.trim())p.appendChild(el('span','chip',x.trim()))});tr.appendChild(p);
tr.appendChild(el('td',null,(r.tls||'')+(r.h2==='True'?' h2':'')+(r.tsup&&!r.tls?' raw:'+r.tsup:'')));
var d=parseInt(r.cd,10),cd=el('td',isNaN(d)?null:(d<0?'bad':(d<=30?'warn':'ok')),r.cd);tr.appendChild(cd);
var fl=el('td');(r.f||'').split(';').forEach(function(x){if(x)fl.appendChild(el('span','chip '+(crit.test(x)?'bad':'warn'),x))});tr.appendChild(fl);
tr.onclick=function(){var n=tr.nextSibling;if(n&&n.className==='d'){n.remove();return}var dr=el('tr','d'),td=el('td');td.colSpan=7;var lines=[['Host',r.h],['IP',r.ip],['Port',r.p],['Reverse DNS',r.rd],['Service',r.sv],['Device name',r.dn],['Domain',r.dom],['Protocol',r.pi],['Final URL',r.fu],['Redirects',r.rc],['Server',r.srv],['Auth',r.au],['Categories',r.c],['OS hint',r.os],['Hardware',r.hw],['CPEs',r.cpe],['TLS supported',r.tsup],['Cert subject',r.cs],['Cert issuer',r.ci],['SANs',r.san],['Favicon mmh3',r.fav],['JARM',r.jarm],['JA4S',r.ja4s],['Advisories',r.adv],['Banner',r.b],['Notes',r.n]].filter(function(x){return x[1]}).map(function(x){return x[0]+': '+x[1]}).join('\n');td.appendChild(el('pre',null,lines));if(r.shot&&/^[\w.\-]+\/[\w.\-]+\.png$/.test(r.shot)){var a=el('a');a.href=r.shot;a.target='_blank';a.rel='noopener';var im=el('img');im.src=r.shot;im.alt='screenshot of '+r.u;im.loading='lazy';im.style.maxWidth='min(100%,960px)';im.style.border='1px solid var(--bd,#888)';a.appendChild(im);td.appendChild(a)}dr.appendChild(td);tr.parentNode.insertBefore(dr,tr.nextSibling)};
tb.appendChild(tr)})}
Array.prototype.forEach.call(document.querySelectorAll('th'),function(th){th.onclick=function(){var k=th.getAttribute('data-k');if(sortK===k)sortD=-sortD;else{sortK=k;sortD=1}render()}});
q.oninput=render;sv.onchange=render;
document.getElementById('th').onclick=function(){var r=document.documentElement,c=r.getAttribute('data-theme');r.setAttribute('data-theme',c==='dark'?'light':(c==='light'?'dark':(matchMedia('(prefers-color-scheme: dark)').matches?'light':'dark')))};
render()})();
</script></body></html>
'@
#endregion

#region ---------- Inventory store: history across runs (ESENT working database + append-only archive) ----------
# Nothing here runs during a scan. After a complete run the finished output files are archived and applied to the
# store; -ImportRun / -StoreQuery / -VerifyStore / -RebuildStore work on the store without scanning.
# The store engine (ESENT interop, history logic) is compiled on first use only, so a scan runs the same engine
# with or without -Store and nothing store-related is loaded until the scan has finished.
$StoreSource = @'

// ============================================================================
// WebInv store - inventory history (first/last seen, versions, change events) kept in a working database
// that is a rebuildable cache of an append-only archive (per-run folders + hash-chained ledger).
//   * ESENT engine: esent.dll (part of Windows) through direct P/Invoke; one process opens a store at a time.
//   * File engine: in-memory ordered map saved atomically to one file; identical semantics (PowerShell 7 on
//     Linux/macOS, and the reference the ESENT engine is checked against).
// C# 5 / .NET Framework 4.7.2. Nothing here runs during a scan: ingest reads the finished run's output files.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.IO.Compression;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;

    // ------------------------------------------------------------------ ESENT interop
    // Declarations follow ManagedEsent (MIT; github.com/microsoft/ManagedEsent): ANSI entry points for ASCII object
    // names, W entry points for paths. JET_INSTANCE/JET_SESID/JET_TABLEID are pointer-sized, JET_DBID/JET_COLUMNID/
    // JET_GRBIT are 32-bit.
    [StructLayout(LayoutKind.Sequential)]
    internal struct JetColumnDef
    {
        public uint cbStruct;
        public uint columnid;
        public uint coltyp;
        public ushort wCountry;
        public ushort langid;
        public ushort cp;
        public ushort wCollate;
        public uint cbMax;
        public uint grbit;
    }

    internal static class EsentNative
    {
        const string Dll = "esent.dll";
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetCreateInstance2W(out IntPtr instance, string szInstanceName, string szDisplayName, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetInit(ref IntPtr instance);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetTerm2(IntPtr instance, uint grbit);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true, EntryPoint = "JetSetSystemParameterW")]
        public static extern int JetSetSystemParameterInstance(ref IntPtr pinstance, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true, EntryPoint = "JetSetSystemParameterW")]
        public static extern int JetSetSystemParameterGlobal(IntPtr pinstanceNull, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetBeginSessionW(IntPtr instance, out IntPtr sesid, string username, string password);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetEndSession(IntPtr sesid, uint grbit);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetCreateDatabaseW(IntPtr sesid, string szFilename, string szConnect, out uint dbid, uint grbit);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetAttachDatabaseW(IntPtr sesid, string szFilename, uint grbit);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetDetachDatabaseW(IntPtr sesid, string szFilename);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetOpenDatabaseW(IntPtr sesid, string szFilename, string szConnect, out uint dbid, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetCloseDatabase(IntPtr sesid, uint dbid, uint grbit);
        [DllImport(Dll, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern int JetCreateTable(IntPtr sesid, uint dbid, string szTableName, int pages, int density, out IntPtr tableid);
        [DllImport(Dll, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern int JetAddColumn(IntPtr sesid, IntPtr tableid, string szColumnName, [In] ref JetColumnDef columndef, [In] byte[] pvDefault, uint cbDefault, out uint columnid);
        [DllImport(Dll, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern int JetCreateIndex(IntPtr sesid, IntPtr tableid, string szIndexName, uint grbit, string szKey, uint cbKey, uint lDensity);
        [DllImport(Dll, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern int JetOpenTable(IntPtr sesid, uint dbid, string szTableName, byte[] pvParameters, uint cbParameters, uint grbit, out IntPtr tableid);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetCloseTable(IntPtr sesid, IntPtr tableid);
        [DllImport(Dll, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern int JetGetTableColumnInfo(IntPtr sesid, IntPtr tableid, string szColumnName, ref JetColumnDef columndef, uint cbMax, uint infoLevel);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetBeginTransaction(IntPtr sesid);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetCommitTransaction(IntPtr sesid, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetRollback(IntPtr sesid, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetMakeKey(IntPtr sesid, IntPtr tableid, byte[] pvData, uint cbData, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetSeek(IntPtr sesid, IntPtr tableid, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetMove(IntPtr sesid, IntPtr tableid, int cRow, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetRetrieveColumn(IntPtr sesid, IntPtr tableid, uint columnid, [Out] byte[] pvData, uint cbData, out uint cbActual, uint grbit, IntPtr pretinfo);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetSetColumn(IntPtr sesid, IntPtr tableid, uint columnid, [In] byte[] pvData, uint cbData, uint grbit, IntPtr psetinfo);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetPrepareUpdate(IntPtr sesid, IntPtr tableid, uint prep);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetUpdate(IntPtr sesid, IntPtr tableid, [Out] byte[] pvBookmark, uint cbBookmark, out uint cbActual);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetDelete(IntPtr sesid, IntPtr tableid);

        // JET_param
        public const uint ParamSystemPath = 0, ParamTempPath = 1, ParamLogFilePath = 2, ParamBaseName = 3, ParamMaxVerPages = 9,
            ParamCircularLog = 17, ParamNoInformationEvent = 50, ParamDatabasePageSize = 64, ParamCreatePathIfNotExist = 100;
        // JET_coltyp, column/index grbits
        public const uint ColtypBinary = 9, ColtypLongBinary = 11, ColumnNotNull = 0x4;
        public const uint IndexUnique = 0x1, IndexPrimary = 0x2, IndexDisallowNull = 0x4;
        // seek / move / makekey / prepare / set / commit / term
        public const uint SeekEQ = 0x1, SeekGE = 0x8, SeekGT = 0x10, NewKey = 0x1;
        public const int MoveFirst = int.MinValue, MoveNext = 1;
        public const uint PrepInsert = 0, PrepReplace = 2, PrepCancel = 3, SetZeroLength = 0x20, CommitLazyFlush = 0x1, TermComplete = 0x1;
        // errors (negative) and warnings (positive) handled explicitly
        public const int ErrRecordNotFound = -1601, ErrNoCurrentRecord = -1603;
        public const int WrnColumnNull = 1004, WrnBufferTruncated = 1006;
    }

    public class EsentException : Exception
    {
        public readonly int Code;
        public EsentException(int code, string call) : base(Describe(code, call)) { Code = code; }
        static string Describe(int code, string call)
        {
            string what;
            switch (code)
            {
                case -550: what = "database was not shut down cleanly and its transaction logs are missing or do not match (rebuild the store from its archive: -RebuildStore)"; break;
                case -1032: what = "access denied to a database or log file (another process may have the store open)"; break;
                case -1215: what = "database file is in use by another process"; break;
                case -1213: what = "database page size does not match this process (another ESENT user in this process?)"; break;
                case -1209: case -514: what = "database or log format is newer than this Windows version supports"; break;
                case -1206: case -1018: case -1121: what = "database corruption detected (rebuild the store from its archive: -RebuildStore)"; break;
                case -1808: case -529: case -1012: what = "disk full"; break;
                case -1069: what = "version store exhausted"; break;
                case -1023: what = "invalid path"; break;
                case -501: case -528: case -543: case -515: what = "transaction log files are missing or corrupt (rebuild the store from its archive: -RebuildStore)"; break;
                default: what = "ESENT error"; break;
            }
            return string.Format(CultureInfo.InvariantCulture, "{0} failed: {1} ({2})", call, what, code);
        }
    }

    // ------------------------------------------------------------------ ordered key-value engines
    // Contract (identical on both engines, enforced by the conformance self-test):
    //  * keys: 1..MaxKey bytes, ordered as unsigned bytes (a prefix sorts before its extensions); values any length
    //  * every Put/Delete inside Begin()..Commit()/Rollback(); one transaction at a time; Rollback undoes everything
    //    since Begin
    //  * ScanPage(prefix, after, max): up to max pairs with the prefix and key > after (after null = from the prefix),
    //    in key order, copied out - callers may modify the store between pages
    //  * Commit(durable: false) may be lost on a crash; Commit(true) and Flush() are durability points
    public abstract class KvEngine : IDisposable
    {
        // ESENT normalises a binary key column in 8-byte chunks plus a count byte (+1 header byte) and the key limit is
        // 255 normalised bytes: 200 raw bytes -> 226 normalised
        public const int MaxKey = 200;
        public abstract string Name { get; }
        public abstract byte[] Get(byte[] key);
        public abstract void Put(byte[] key, byte[] value);
        public abstract bool Delete(byte[] key);
        public abstract List<KeyValuePair<byte[], byte[]>> ScanPage(byte[] prefix, byte[] after, int max);
        public abstract void Begin();
        public abstract void Commit(bool durable);
        public abstract void Rollback();
        public abstract bool InTransaction { get; }
        public virtual void Flush() { }
        public abstract void Dispose();

        public IEnumerable<KeyValuePair<byte[], byte[]>> Scan(byte[] prefix)
        {
            byte[] after = null;
            while (true)
            {
                List<KeyValuePair<byte[], byte[]>> page = ScanPage(prefix, after, 512);
                foreach (KeyValuePair<byte[], byte[]> kv in page) yield return kv;
                if (page.Count < 512) yield break;
                after = page[page.Count - 1].Key;
            }
        }

        protected static void CheckKey(byte[] key)
        {
            if (key == null || key.Length == 0 || key.Length > MaxKey) throw new ArgumentException("key length must be 1.." + MaxKey + " bytes (got " + (key == null ? 0 : key.Length) + ")");
        }
        public static bool StartsWith(byte[] k, byte[] prefix)
        {
            if (k.Length < prefix.Length) return false;
            for (int i = 0; i < prefix.Length; i++) if (k[i] != prefix[i]) return false;
            return true;
        }
    }

    public sealed class ByteOrder : IComparer<byte[]>, IEqualityComparer<byte[]>
    {
        public static readonly ByteOrder Instance = new ByteOrder();
        public int Compare(byte[] a, byte[] b)
        {
            int n = Math.Min(a.Length, b.Length);
            for (int i = 0; i < n; i++) { int d = a[i] - b[i]; if (d != 0) return d; }
            return a.Length - b.Length;
        }
        public bool Equals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }
        public int GetHashCode(byte[] a)
        {
            unchecked { uint h = 2166136261; for (int i = 0; i < a.Length; i++) { h ^= a[i]; h *= 16777619; } return (int)h; }
        }
    }

    // Sorted key index: a list of sorted chunks (bounded inserts, binary-searched lower bound)
    sealed class KeyIndex
    {
        const int Chunk = 512;
        readonly List<List<byte[]>> chunks = new List<List<byte[]>>();
        public int Count;
        static int Lower(List<byte[]> l, byte[] k)
        {
            int lo = 0, hi = l.Count;
            while (lo < hi) { int m = (lo + hi) >> 1; if (ByteOrder.Instance.Compare(l[m], k) < 0) lo = m + 1; else hi = m; }
            return lo;
        }
        int ChunkFor(byte[] k)
        {
            // last chunk whose first key <= k (or 0)
            int lo = 0, hi = chunks.Count - 1, r = 0;
            while (lo <= hi) { int m = (lo + hi) >> 1; if (ByteOrder.Instance.Compare(chunks[m][0], k) <= 0) { r = m; lo = m + 1; } else hi = m - 1; }
            return r;
        }
        public void Add(byte[] k)
        {
            if (chunks.Count == 0) { chunks.Add(new List<byte[]> { k }); Count++; return; }
            int c = ChunkFor(k);
            List<byte[]> l = chunks[c];
            l.Insert(Lower(l, k), k); Count++;
            if (l.Count > 2 * Chunk)
            {
                List<byte[]> tail = l.GetRange(Chunk, l.Count - Chunk);
                l.RemoveRange(Chunk, l.Count - Chunk);
                chunks.Insert(c + 1, tail);
            }
        }
        public void Remove(byte[] k)
        {
            if (chunks.Count == 0) return;
            int c = ChunkFor(k);
            List<byte[]> l = chunks[c];
            int i = Lower(l, k);
            if (i < l.Count && ByteOrder.Instance.Compare(l[i], k) == 0) { l.RemoveAt(i); Count--; if (l.Count == 0) chunks.RemoveAt(c); }
        }
        // keys >= start (or > start when exclusive), in order
        public IEnumerable<byte[]> From(byte[] start, bool exclusive)
        {
            if (chunks.Count == 0) yield break;
            int c = ChunkFor(start);
            int i = Lower(chunks[c], start);
            for (; c < chunks.Count; c++, i = 0)
            {
                List<byte[]> l = chunks[c];
                for (; i < l.Count; i++)
                {
                    if (exclusive && ByteOrder.Instance.Compare(l[i], start) == 0) continue;
                    yield return l[i];
                }
            }
        }
        public IEnumerable<byte[]> All() { foreach (List<byte[]> l in chunks) foreach (byte[] k in l) yield return k; }
        public void Clear() { chunks.Clear(); Count = 0; }
    }

    // Portable engine: ordered map in memory, saved to one file atomically on Flush (path null = memory only)
    public sealed class FileKv : KvEngine
    {
        static readonly byte[] Magic = Encoding.ASCII.GetBytes("WIKV1\n");
        readonly KeyIndex index = new KeyIndex();
        readonly Dictionary<byte[], byte[]> vals = new Dictionary<byte[], byte[]>(ByteOrder.Instance);
        readonly List<KeyValuePair<byte[], byte[]>> journal = new List<KeyValuePair<byte[], byte[]>>();
        readonly HashSet<byte[]> journaled = new HashSet<byte[]>(ByteOrder.Instance);
        readonly string path;
        bool inTx, dirty;
        public FileKv(string path)
        {
            this.path = path;
            if (path != null && File.Exists(path)) Load();
        }
        public override string Name { get { return path == null ? "memory" : "file"; } }
        public int Count { get { return vals.Count; } }
        public override bool InTransaction { get { return inTx; } }
        public override byte[] Get(byte[] key) { CheckKey(key); byte[] v; return vals.TryGetValue(key, out v) ? v : null; }
        void Journal(byte[] key)
        {
            if (!inTx) throw new InvalidOperationException("write outside a transaction");
            if (journaled.Add(key)) { byte[] old; journal.Add(new KeyValuePair<byte[], byte[]>(key, vals.TryGetValue(key, out old) ? old : null)); }
        }
        public override void Put(byte[] key, byte[] value)
        {
            CheckKey(key);
            if (value == null) throw new ArgumentNullException("value");
            key = (byte[])key.Clone();
            Journal(key);
            if (!vals.ContainsKey(key)) index.Add(key);
            vals[key] = (byte[])value.Clone();
            dirty = true;
        }
        public override bool Delete(byte[] key)
        {
            CheckKey(key);
            if (!inTx) throw new InvalidOperationException("write outside a transaction");
            if (!vals.ContainsKey(key)) return false;
            key = (byte[])key.Clone();
            Journal(key);
            vals.Remove(key); index.Remove(key); dirty = true;
            return true;
        }
        public override List<KeyValuePair<byte[], byte[]>> ScanPage(byte[] prefix, byte[] after, int max)
        {
            List<KeyValuePair<byte[], byte[]>> r = new List<KeyValuePair<byte[], byte[]>>();
            IEnumerable<byte[]> seq = (after == null) ? (prefix.Length == 0 ? index.All() : index.From(prefix, false)) : index.From(after, true);
            foreach (byte[] k in seq)
            {
                if (!StartsWith(k, prefix)) break;
                r.Add(new KeyValuePair<byte[], byte[]>((byte[])k.Clone(), vals[k]));
                if (r.Count >= max) break;
            }
            return r;
        }
        public override void Begin() { if (inTx) throw new InvalidOperationException("transaction already open"); inTx = true; }
        public override void Commit(bool durable) { if (!inTx) throw new InvalidOperationException("no transaction"); journal.Clear(); journaled.Clear(); inTx = false; if (durable) Flush(); }
        public override void Rollback()
        {
            if (!inTx) return;
            for (int i = journal.Count - 1; i >= 0; i--)
            {
                byte[] k = journal[i].Key, old = journal[i].Value;
                bool had = vals.ContainsKey(k);
                if (old == null) { if (had) { vals.Remove(k); index.Remove(k); } }
                else { if (!had) index.Add(k); vals[k] = old; }
            }
            journal.Clear(); journaled.Clear(); inTx = false;
        }
        public override void Flush()
        {
            if (path == null || !dirty) return;
            if (inTx) throw new InvalidOperationException("flush inside a transaction");
            string tmp = path + ".tmp";
            using (FileStream fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(Magic, 0, Magic.Length);
                using (GZipStream gz = new GZipStream(fs, CompressionLevel.Fastest, true))
                using (BinaryWriter w = new BinaryWriter(gz))
                using (Sha256Acc h = new Sha256Acc())
                {
                    foreach (byte[] k in index.All())
                    {
                        byte[] v = vals[k];
                        w.Write(k.Length); w.Write(k); w.Write(v.Length); w.Write(v);
                        h.Append(BitConverter.GetBytes(k.Length)); h.Append(k); h.Append(BitConverter.GetBytes(v.Length)); h.Append(v);
                    }
                    w.Write(-1);
                    w.Write(h.Final());
                }
                fs.Flush(true);
            }
            if (File.Exists(path)) File.Replace(tmp, path, null); else File.Move(tmp, path);
            dirty = false;
        }
        void Load()
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] m = new byte[Magic.Length];
                if (fs.Read(m, 0, m.Length) != m.Length || !ByteOrder.Instance.Equals(m, Magic)) throw new InvalidDataException("not a WebInventory store file: " + path);
                using (GZipStream gz = new GZipStream(fs, CompressionMode.Decompress))
                using (BinaryReader r = new BinaryReader(gz))
                using (Sha256Acc h = new Sha256Acc())
                {
                    while (true)
                    {
                        int kl = r.ReadInt32();
                        if (kl == -1) break;
                        if (kl <= 0 || kl > MaxKey) throw new InvalidDataException("corrupt store file (key length) " + path);
                        byte[] k = r.ReadBytes(kl);
                        int vl = r.ReadInt32();
                        if (vl < 0) throw new InvalidDataException("corrupt store file (value length) " + path);
                        byte[] v = r.ReadBytes(vl);
                        if (k.Length != kl || v.Length != vl) throw new InvalidDataException("truncated store file " + path);
                        h.Append(BitConverter.GetBytes(kl)); h.Append(k); h.Append(BitConverter.GetBytes(vl)); h.Append(v);
                        if (!vals.ContainsKey(k)) index.Add(k);
                        vals[k] = v;
                    }
                    byte[] want = r.ReadBytes(32), got = h.Final();
                    if (!ByteOrder.Instance.Equals(want, got)) throw new InvalidDataException("store file checksum mismatch " + path);
                }
            }
        }
        public override void Dispose() { Rollback(); }
    }

    // ESENT engine: one table "kv" (k Binary(255) primary key, v LongBinary)
    public sealed class EsentKv : KvEngine
    {
        IntPtr inst = IntPtr.Zero, ses = IntPtr.Zero, tab = IntPtr.Zero;
        uint dbid, colK, colV;
        bool dbOpen, attached, inTx;
        readonly string dbFile;
        byte[] buf = new byte[65536];
        static int instances;
        public override string Name { get { return "esent"; } }
        public override bool InTransaction { get { return inTx; } }
        public string DatabaseFile { get { return dbFile; } }

        public static bool Available
        {
            get
            {
                if (Environment.OSVersion.Platform != PlatformID.Win32NT) return false;
                return File.Exists(Path.Combine(Environment.SystemDirectory, "esent.dll"));
            }
        }

        static void Check(int err, string call) { if (err < 0) throw new EsentException(err, call); }

        public EsentKv(string dir)
        {
            dir = Path.GetFullPath(dir);
            if (!dir.EndsWith("\\", StringComparison.Ordinal)) dir += "\\";
            Directory.CreateDirectory(dir);
            Directory.CreateDirectory(dir + "tmp");
            dbFile = dir + "inventory.edb";
            // process-wide; fails harmlessly when another instance already set it (then the open reports any mismatch)
            EsentNative.JetSetSystemParameterGlobal(IntPtr.Zero, IntPtr.Zero, EsentNative.ParamDatabasePageSize, (IntPtr)8192, null);
            string name = string.Format(CultureInfo.InvariantCulture, "WebInv-{0}-{1}", System.Diagnostics.Process.GetCurrentProcess().Id, System.Threading.Interlocked.Increment(ref instances));
            Check(EsentNative.JetCreateInstance2W(out inst, name, "WebInventory store", 0), "JetCreateInstance2");
            try
            {
                SetPath(EsentNative.ParamSystemPath, dir);
                SetPath(EsentNative.ParamLogFilePath, dir);
                SetPath(EsentNative.ParamTempPath, dir + "tmp\\");
                SetPath(EsentNative.ParamBaseName, "wiv");
                SetInt(EsentNative.ParamCircularLog, 1);            // the archive is the backup; keep the log set small
                SetInt(EsentNative.ParamNoInformationEvent, 1);
                SetInt(EsentNative.ParamCreatePathIfNotExist, 1);
                SetInt(EsentNative.ParamMaxVerPages, 4096);         // headroom for batched ingest transactions
                Check(EsentNative.JetInit(ref inst), "JetInit");     // soft recovery from the logs happens here
                Check(EsentNative.JetBeginSessionW(inst, out ses, "", ""), "JetBeginSession");
                if (File.Exists(dbFile))
                {
                    Check(EsentNative.JetAttachDatabaseW(ses, dbFile, 0), "JetAttachDatabase"); attached = true;
                    Check(EsentNative.JetOpenDatabaseW(ses, dbFile, null, out dbid, 0), "JetOpenDatabase"); dbOpen = true;
                }
                else
                {
                    Check(EsentNative.JetCreateDatabaseW(ses, dbFile, null, out dbid, 0), "JetCreateDatabase"); attached = true; dbOpen = true;
                    CreateSchema();
                }
                Check(EsentNative.JetOpenTable(ses, dbid, "kv", null, 0, 0, out tab), "JetOpenTable");
                colK = ColumnId("k"); colV = ColumnId("v");
            }
            catch { Dispose(); throw; }
        }
        void SetPath(uint param, string value) { Check(EsentNative.JetSetSystemParameterInstance(ref inst, IntPtr.Zero, param, IntPtr.Zero, value), "JetSetSystemParameter(" + param + ")"); }
        void SetInt(uint param, int value) { Check(EsentNative.JetSetSystemParameterInstance(ref inst, IntPtr.Zero, param, (IntPtr)value, null), "JetSetSystemParameter(" + param + ")"); }
        void CreateSchema()
        {
            IntPtr t;
            Check(EsentNative.JetBeginTransaction(ses), "JetBeginTransaction");
            try
            {
                Check(EsentNative.JetCreateTable(ses, dbid, "kv", 16, 90, out t), "JetCreateTable");
                uint id;
                JetColumnDef ck = new JetColumnDef();
                ck.cbStruct = (uint)Marshal.SizeOf(typeof(JetColumnDef)); ck.coltyp = EsentNative.ColtypBinary; ck.cbMax = 255; ck.grbit = EsentNative.ColumnNotNull;
                Check(EsentNative.JetAddColumn(ses, t, "k", ref ck, null, 0, out id), "JetAddColumn(k)");
                JetColumnDef cv = new JetColumnDef();
                cv.cbStruct = (uint)Marshal.SizeOf(typeof(JetColumnDef)); cv.coltyp = EsentNative.ColtypLongBinary;
                Check(EsentNative.JetAddColumn(ses, t, "v", ref cv, null, 0, out id), "JetAddColumn(v)");
                Check(EsentNative.JetCreateIndex(ses, t, "pk", EsentNative.IndexUnique | EsentNative.IndexPrimary | EsentNative.IndexDisallowNull, "+k\0\0", 4, 90), "JetCreateIndex");
                Check(EsentNative.JetCloseTable(ses, t), "JetCloseTable");
                Check(EsentNative.JetCommitTransaction(ses, 0), "JetCommitTransaction");
            }
            catch { EsentNative.JetRollback(ses, 0); throw; }
        }
        uint ColumnId(string name)
        {
            JetColumnDef d = new JetColumnDef();
            d.cbStruct = (uint)Marshal.SizeOf(typeof(JetColumnDef));
            Check(EsentNative.JetGetTableColumnInfo(ses, tab, name, ref d, d.cbStruct, 0), "JetGetTableColumnInfo(" + name + ")");
            return d.columnid;
        }
        bool SeekEq(byte[] key)
        {
            Check(EsentNative.JetMakeKey(ses, tab, key, (uint)key.Length, EsentNative.NewKey), "JetMakeKey");
            int e = EsentNative.JetSeek(ses, tab, EsentNative.SeekEQ);
            if (e == EsentNative.ErrRecordNotFound) return false;
            Check(e, "JetSeek");
            return true;
        }
        byte[] Retrieve(uint col)
        {
            uint actual;
            int e = EsentNative.JetRetrieveColumn(ses, tab, col, buf, (uint)buf.Length, out actual, 0, IntPtr.Zero);
            if (e == EsentNative.WrnColumnNull) return new byte[0];
            if (e == EsentNative.WrnBufferTruncated)
            {
                byte[] big = new byte[actual];
                uint again;
                Check(EsentNative.JetRetrieveColumn(ses, tab, col, big, actual, out again, 0, IntPtr.Zero), "JetRetrieveColumn");
                if (again == actual) return big;
                byte[] r2 = new byte[again]; Buffer.BlockCopy(big, 0, r2, 0, (int)Math.Min(again, actual)); return r2;
            }
            Check(e, "JetRetrieveColumn");
            byte[] r = new byte[actual];
            Buffer.BlockCopy(buf, 0, r, 0, (int)actual);
            return r;
        }
        public override byte[] Get(byte[] key) { CheckKey(key); return SeekEq(key) ? Retrieve(colV) : null; }
        public override void Put(byte[] key, byte[] value)
        {
            CheckKey(key);
            if (value == null) throw new ArgumentNullException("value");
            if (!inTx) throw new InvalidOperationException("write outside a transaction");
            bool exists = SeekEq(key);
            Check(EsentNative.JetPrepareUpdate(ses, tab, exists ? EsentNative.PrepReplace : EsentNative.PrepInsert), "JetPrepareUpdate");
            try
            {
                if (!exists) Check(EsentNative.JetSetColumn(ses, tab, colK, key, (uint)key.Length, 0, IntPtr.Zero), "JetSetColumn(k)");
                Check(EsentNative.JetSetColumn(ses, tab, colV, value, (uint)value.Length, value.Length == 0 ? EsentNative.SetZeroLength : 0, IntPtr.Zero), "JetSetColumn(v)");
                uint act;
                Check(EsentNative.JetUpdate(ses, tab, null, 0, out act), "JetUpdate");
            }
            catch { EsentNative.JetPrepareUpdate(ses, tab, EsentNative.PrepCancel); throw; }
        }
        public override bool Delete(byte[] key)
        {
            CheckKey(key);
            if (!inTx) throw new InvalidOperationException("write outside a transaction");
            if (!SeekEq(key)) return false;
            Check(EsentNative.JetDelete(ses, tab), "JetDelete");
            return true;
        }
        public override List<KeyValuePair<byte[], byte[]>> ScanPage(byte[] prefix, byte[] after, int max)
        {
            List<KeyValuePair<byte[], byte[]>> r = new List<KeyValuePair<byte[], byte[]>>();
            byte[] start = after ?? prefix;
            int e;
            if (start.Length == 0) e = EsentNative.JetMove(ses, tab, EsentNative.MoveFirst, 0);
            else
            {
                Check(EsentNative.JetMakeKey(ses, tab, start, (uint)start.Length, EsentNative.NewKey), "JetMakeKey");
                e = EsentNative.JetSeek(ses, tab, after != null ? EsentNative.SeekGT : EsentNative.SeekGE);
            }
            if (e == EsentNative.ErrRecordNotFound || e == EsentNative.ErrNoCurrentRecord) return r;
            Check(e, "JetSeek");
            while (r.Count < max)
            {
                byte[] k = Retrieve(colK);
                if (!StartsWith(k, prefix)) break;
                r.Add(new KeyValuePair<byte[], byte[]>(k, Retrieve(colV)));
                int m = EsentNative.JetMove(ses, tab, EsentNative.MoveNext, 0);
                if (m == EsentNative.ErrNoCurrentRecord) break;
                Check(m, "JetMove");
            }
            return r;
        }
        public override void Begin()
        {
            if (inTx) throw new InvalidOperationException("transaction already open");
            Check(EsentNative.JetBeginTransaction(ses), "JetBeginTransaction"); inTx = true;
        }
        public override void Commit(bool durable)
        {
            if (!inTx) throw new InvalidOperationException("no transaction");
            Check(EsentNative.JetCommitTransaction(ses, durable ? 0 : EsentNative.CommitLazyFlush), "JetCommitTransaction"); inTx = false;
        }
        public override void Rollback()
        {
            if (!inTx) return;
            inTx = false;
            Check(EsentNative.JetRollback(ses, 0), "JetRollback");
        }
        public override void Dispose()
        {
            // best effort, in reverse order; JetTerm2(Complete) leaves the database in a clean-shutdown state
            if (ses != IntPtr.Zero)
            {
                if (inTx) { try { EsentNative.JetRollback(ses, 0); } catch { } inTx = false; }
                if (tab != IntPtr.Zero) { EsentNative.JetCloseTable(ses, tab); tab = IntPtr.Zero; }
                if (dbOpen) { EsentNative.JetCloseDatabase(ses, dbid, 0); dbOpen = false; }
                if (attached) { EsentNative.JetDetachDatabaseW(ses, dbFile); attached = false; }
                EsentNative.JetEndSession(ses, 0); ses = IntPtr.Zero;
            }
            if (inst != IntPtr.Zero) { EsentNative.JetTerm2(inst, EsentNative.TermComplete); inst = IntPtr.Zero; }
        }
    }
}

// ============================================================================
// WebInv inventory store logic: archive (per-run folders + hash-chained ledger) -> working database (KvEngine).
// The database is a deterministic function of the archive: rebuilding from the archive reproduces every entity id,
// version, change event and digest. Ingest is idempotent per run, so a crash at any point is repaired by re-applying.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.IO.Compression;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;

    // SHA-256 accumulator: platform provider, or (when policy refuses it) an incremental managed implementation
    public sealed class Sha256Acc : IDisposable
    {
        IncrementalHash ih;
        uint[] H, w;
        byte[] block;
        int blen;
        long total;
        // one reusable accumulator per thread (Final() resets it) for the many small hashes of an ingest
        [ThreadStatic] static Sha256Acc shared;
        public static Sha256Acc Shared { get { if (shared == null) shared = new Sha256Acc(); return shared; } }
        static readonly uint[] K256 = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
        public Sha256Acc() : this(false) { }
        public Sha256Acc(bool managed)
        {
            if (!managed)
            {
                try { ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); }
                catch (Exception) { ih = null; }
            }
            if (ih == null) Reset();
        }
        void Reset()
        {
            H = new uint[] { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
            w = new uint[64]; block = new byte[64]; blen = 0; total = 0;
        }
        public bool Platform { get { return ih != null; } }
        public void Append(byte[] d) { Append(d, 0, d.Length); }
        public void Append(byte[] d, int off, int n)
        {
            if (ih != null) { ih.AppendData(d, off, n); return; }
            total += n;
            while (n > 0)
            {
                int c = Math.Min(64 - blen, n);
                Buffer.BlockCopy(d, off, block, blen, c);
                blen += c; off += c; n -= c;
                if (blen == 64) { Compress(); blen = 0; }
            }
        }
        public byte[] Final()
        {
            if (ih != null) return ih.GetHashAndReset();
            long bits = total * 8;
            byte[] pad = new byte[(blen < 56 ? 56 - blen : 120 - blen) + 8];
            pad[0] = 0x80;
            for (int i = 0; i < 8; i++) pad[pad.Length - 1 - i] = (byte)(bits >> (8 * i));
            Append(pad, 0, pad.Length);
            byte[] o = new byte[32];
            for (int i = 0; i < 8; i++) { o[i * 4] = (byte)(H[i] >> 24); o[i * 4 + 1] = (byte)(H[i] >> 16); o[i * 4 + 2] = (byte)(H[i] >> 8); o[i * 4 + 3] = (byte)H[i]; }
            Reset();
            return o;
        }
        public string FinalHex() { return StoreUtil.Hex(Final()); }
        static uint Rotr(uint x, int n) { return (x >> n) | (x << (32 - n)); }
        void Compress()
        {
            for (int i = 0; i < 16; i++) w[i] = ((uint)block[i * 4] << 24) | ((uint)block[i * 4 + 1] << 16) | ((uint)block[i * 4 + 2] << 8) | block[i * 4 + 3];
            for (int i = 16; i < 64; i++)
            {
                uint s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            uint a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
            for (int i = 0; i < 64; i++)
            {
                uint t1 = h + (Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
                uint t2 = (Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
                h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
        }
        public void Dispose() { if (ih != null) ih.Dispose(); }
    }

    public static class StoreUtil
    {
        public const string Version = "2.3.1";
        public static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
        public static string Hex(byte[] h)
        {
            StringBuilder sb = new StringBuilder(h.Length * 2);
            foreach (byte x in h) sb.Append(x.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }
        public static string Sha256Hex(byte[] d) { Sha256Acc a = Sha256Acc.Shared; a.Append(d); return a.FinalHex(); }
        // a parsed JSON value as text, as the scanner's CSV writer renders it (bool True/False, numbers invariant, null "")
        public static string Scalar(object v)
        {
            if (v == null) return "";
            if (v is string) return (string)v;
            if (v is bool) return (bool)v ? "True" : "False";
            IFormattable f = v as IFormattable;
            if (f != null) return f.ToString(null, CultureInfo.InvariantCulture);
            return v.ToString();
        }
        // JSON string with HTML-sensitive characters escaped (same form as the scanner's JSONL writer)
        public static void JsonString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append('\\').Append('"'); break;
                    case '\\': sb.Append('\\').Append('\\'); break;
                    case '\n': sb.Append('\\').Append('n'); break;
                    case '\r': sb.Append('\\').Append('r'); break;
                    case '\t': sb.Append('\\').Append('t'); break;
                    case '\b': sb.Append('\\').Append('b'); break;
                    case '\f': sb.Append('\\').Append('f'); break;
                    default:
                        if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == '\'' || c == (char)0x2028 || c == (char)0x2029)
                            sb.Append('\\').Append('u').Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
        public static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
        public static byte[] B(string s) { return Utf8.GetBytes(s); }
        public static string S(byte[] b) { return Utf8.GetString(b); }
        public static string Iso(DateTimeOffset t) { return t.ToString("yyyy-MM-dd'T'HH:mm:sszzz", Inv); }
        public static DateTimeOffset ParseIso(string s) { return DateTimeOffset.Parse(s, Inv, DateTimeStyles.AssumeLocal); }
        public static bool TryIso(string s, out DateTimeOffset t) { return DateTimeOffset.TryParse(s, Inv, DateTimeStyles.AssumeLocal, out t); }
        public static string D10(long n) { return n.ToString("D10", Inv); }
        public static string Sha256Hex(string s) { Sha256Acc a = Sha256Acc.Shared; a.Append(B(s)); return a.FinalHex(); }
        public static string FileSha256(string path, out long bytes)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (Sha256Acc a = new Sha256Acc())
            {
                byte[] buf = new byte[1 << 20]; int n; bytes = 0;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0) { a.Append(buf, 0, n); bytes += n; }
                return a.FinalHex();
            }
        }
        // lines of a UTF-8 text file (optionally .gz); BOM tolerant; \r\n or \n
        public static IEnumerable<string> ReadLines(string path)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Stream s = fs;
                GZipStream gz = null;
                if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) { gz = new GZipStream(fs, CompressionMode.Decompress); s = gz; }
                using (StreamReader r = new StreamReader(s, Utf8, true, 1 << 16))
                {
                    string l;
                    while ((l = r.ReadLine()) != null) yield return l;
                }
                if (gz != null) gz.Dispose();
            }
        }
        public static string ReadText(string path)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string l in ReadLines(path)) sb.Append(l).Append('\n');
            return sb.ToString();
        }
        // gzip copy of a file; returns the source SHA-256 and size
        public static string CopyToGz(string src, string dst, out long srcBytes)
        {
            using (FileStream i = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (FileStream o = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None))
            using (Sha256Acc a = new Sha256Acc())
            {
                using (GZipStream gz = new GZipStream(o, CompressionLevel.Optimal, true))
                {
                    byte[] buf = new byte[1 << 20]; int n; srcBytes = 0;
                    while ((n = i.Read(buf, 0, buf.Length)) > 0) { a.Append(buf, 0, n); gz.Write(buf, 0, n); srcBytes += n; }
                }
                o.Flush(true);
                return a.FinalHex();
            }
        }
        public static void WriteAllTextAtomic(string path, string text)
        {
            string tmp = path + ".tmp";
            using (FileStream fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                byte[] b = B(text);
                fs.Write(b, 0, b.Length);
                fs.Flush(true);
            }
            if (File.Exists(path)) File.Replace(tmp, path, null); else File.Move(tmp, path);
        }
        public static bool IsIp(string s) { System.Net.IPAddress a; return System.Net.IPAddress.TryParse(s, out a); }
        public static object Field(Dictionary<string, object> o, string k) { object v; return o != null && o.TryGetValue(k, out v) ? v : null; }
        public static string Str(Dictionary<string, object> o, string k) { return StoreUtil.Scalar(Field(o, k)); }
        public static long Num(Dictionary<string, object> o, string k) { long v; return long.TryParse(Str(o, k), NumberStyles.Integer, Inv, out v) ? v : 0; }
    }

    // JSON reader: objects -> Dictionary<string,object>, arrays -> List<object>, numbers -> double
    public static class StoreJson
    {
        public static object Parse(string s) { int i = 0; object v = Value(s, ref i); Ws(s, ref i); if (i != s.Length) throw new FormatException("trailing data at " + i); return v; }
        static void Ws(string s, ref int i) { while (i < s.Length && char.IsWhiteSpace(s[i])) i++; }
        static object Value(string s, ref int i)
        {
            Ws(s, ref i);
            if (i >= s.Length) throw new FormatException("unexpected end");
            char c = s[i];
            if (c == '{')
            {
                Dictionary<string, object> d = new Dictionary<string, object>(StringComparer.Ordinal);
                i++; Ws(s, ref i);
                if (i < s.Length && s[i] == '}') { i++; return d; }
                while (true)
                {
                    Ws(s, ref i); string k = Str(s, ref i); Ws(s, ref i);
                    if (i >= s.Length || s[i] != ':') throw new FormatException("expected ':' at " + i);
                    i++; d[k] = Value(s, ref i); Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    if (i < s.Length && s[i] == '}') { i++; return d; }
                    throw new FormatException("expected ',' or '}' at " + i);
                }
            }
            if (c == '[')
            {
                List<object> l = new List<object>();
                i++; Ws(s, ref i);
                if (i < s.Length && s[i] == ']') { i++; return l; }
                while (true)
                {
                    l.Add(Value(s, ref i)); Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    if (i < s.Length && s[i] == ']') { i++; return l; }
                    throw new FormatException("expected ',' or ']' at " + i);
                }
            }
            if (c == '"') return Str(s, ref i);
            if (string.CompareOrdinal(s, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (string.CompareOrdinal(s, i, "false", 0, 5) == 0) { i += 5; return false; }
            if (string.CompareOrdinal(s, i, "null", 0, 4) == 0) { i += 4; return null; }
            int st = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (st == i) throw new FormatException("unexpected character at " + i);
            return double.Parse(s.Substring(st, i - st), NumberStyles.Float, CultureInfo.InvariantCulture);
        }
        static string Str(string s, ref int i)
        {
            if (i >= s.Length || s[i] != '"') throw new FormatException("expected string at " + i);
            i++;
            int start = i;
            while (i < s.Length && s[i] != '"' && s[i] != '\\') i++;
            if (i < s.Length && s[i] == '"') { string plain = s.Substring(start, i - start); i++; return plain; }
            StringBuilder sb = new StringBuilder(s, start, i - start, Math.Max(16, (i - start) * 2));
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= s.Length) break;
                char e = s[i++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 't': sb.Append('\t'); break;
                    case 'r': sb.Append('\r'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u':
                        if (i + 4 > s.Length) throw new FormatException("bad \\u escape at " + i);
                        sb.Append((char)Convert.ToInt32(s.Substring(i, 4), 16)); i += 4; break;
                    default: sb.Append(e); break;
                }
            }
            throw new FormatException("unterminated string");
        }
    }

    // Canonical line writer: JSON objects with a fixed key order, LF line ends; SHA-256 digest of the bytes written
    public sealed class DigestWriter : IDisposable
    {
        readonly Sha256Acc acc = new Sha256Acc();
        FileStream fs; GZipStream gz;
        public long Lines;
        public DigestWriter(string gzPath)
        {
            if (gzPath != null) { fs = new FileStream(gzPath, FileMode.Create, FileAccess.Write, FileShare.None); gz = new GZipStream(fs, CompressionLevel.Optimal, true); }
        }
        public void Line(string s)
        {
            byte[] b = StoreUtil.B(s + "\n");
            acc.Append(b);
            if (gz != null) gz.Write(b, 0, b.Length);
            Lines++;
        }
        public string Close()
        {
            if (gz != null) { gz.Dispose(); gz = null; fs.Flush(true); fs.Dispose(); fs = null; }
            return acc.FinalHex();
        }
        public void Dispose() { if (gz != null) gz.Dispose(); if (fs != null) fs.Dispose(); acc.Dispose(); }
    }

    public sealed class JsonObj
    {
        readonly StringBuilder sb = new StringBuilder(256);
        bool first = true;
        public JsonObj() { sb.Append('{'); }
        void Name(string n) { if (!first) sb.Append(','); first = false; StoreUtil.JsonString(sb, n); sb.Append(':'); }
        public JsonObj Str(string n, string v) { Name(n); StoreUtil.JsonString(sb, v ?? ""); return this; }
        public JsonObj StrIf(string n, string v) { if (!string.IsNullOrEmpty(v)) Str(n, v); return this; }
        public JsonObj Num(string n, long v) { Name(n); sb.Append(v.ToString(CultureInfo.InvariantCulture)); return this; }
        public JsonObj Bool(string n, bool v) { Name(n); sb.Append(v ? "true" : "false"); return this; }
        public JsonObj Raw(string n, string json) { Name(n); sb.Append(json); return this; }
        public override string ToString() { return sb.ToString() + "}"; }
    }

    // Ordered string record with a compact binary encoding (the database value format)
    public sealed class Rec
    {
        public readonly List<string> Names = new List<string>();
        readonly Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.Ordinal);
        public string this[string n]
        {
            get { string v; return map.TryGetValue(n, out v) ? v : ""; }
            set { if (value == null) value = ""; if (!map.ContainsKey(n)) Names.Add(n); map[n] = value; }
        }
        public bool Has(string n) { return map.ContainsKey(n); }
        public void Remove(string n) { if (map.Remove(n)) Names.Remove(n); }
        public long Long(string n) { long v; return long.TryParse(this[n], NumberStyles.Integer, CultureInfo.InvariantCulture, out v) ? v : 0; }
        public void SetLong(string n, long v) { this[n] = v.ToString(CultureInfo.InvariantCulture); }
        public void RemovePrefix(string p) { foreach (string n in Names.ToArray()) if (n.StartsWith(p, StringComparison.Ordinal)) Remove(n); }
        public byte[] Encode()
        {
            MemoryStream ms = new MemoryStream(256);
            ms.WriteByte(1);
            Var(ms, Names.Count);
            foreach (string n in Names) { Bytes(ms, n); Bytes(ms, map[n]); }
            return ms.ToArray();
        }
        static void Var(MemoryStream ms, int v) { uint u = (uint)v; while (u >= 0x80) { ms.WriteByte((byte)(u | 0x80)); u >>= 7; } ms.WriteByte((byte)u); }
        static void Bytes(MemoryStream ms, string s) { byte[] b = StoreUtil.B(s); Var(ms, b.Length); ms.Write(b, 0, b.Length); }
        public static Rec Decode(byte[] b)
        {
            if (b == null) return null;
            if (b.Length == 0 || b[0] != 1) throw new InvalidDataException("unknown record format");
            int i = 1;
            int n = ReadVar(b, ref i);
            Rec r = new Rec();
            for (int k = 0; k < n; k++) { string name = ReadStr(b, ref i); r[name] = ReadStr(b, ref i); }
            return r;
        }
        static int ReadVar(byte[] b, ref int i)
        {
            uint v = 0; int shift = 0;
            while (true)
            {
                if (i >= b.Length || shift > 28) throw new InvalidDataException("corrupt record");
                byte x = b[i++]; v |= (uint)(x & 0x7f) << shift;
                if ((x & 0x80) == 0) return (int)v;
                shift += 7;
            }
        }
        static string ReadStr(byte[] b, ref int i)
        {
            int len = ReadVar(b, ref i);
            if (len < 0 || i + len > b.Length) throw new InvalidDataException("corrupt record");
            string s = StoreUtil.Utf8.GetString(b, i, len); i += len; return s;
        }
    }

    // Which result fields define a service version, which are per-observation detail, and which a probe switch controls
    public static class InvSchema
    {
        public const int Version = 1;   // changing Material/Norm changes every hash: bump and migrate, never edit in place
        public static readonly string[] Material = {
            "ReverseDns", "State", "IsWeb", "Service", "Scheme", "Url", "FinalUrl", "StatusCode", "Title", "Server", "PoweredBy", "Generator",
            "ContentType", "RedirectChain", "Auth", "Cookies", "CookieFlagIssues", "MissingSecHeaders", "HstsMaxAge", "AltSvc",
            "Products", "Technologies", "Categories", "CPEs", "OsHint", "Hardware", "FaviconPath", "FaviconMmh3", "FaviconMd5",
            "Robots", "SecurityTxt", "AllowedMethods", "RiskyMethods", "IdentifiedPaths", "TlsVersion", "TlsCipher", "TlsKeyExchange",
            "TlsSupported", "TlsCiphersByVersion", "TlsWeakCipher", "Alpn", "Http2", "CertSubject", "CertIssuer", "CertSANs",
            "CertNotBefore", "CertNotAfter", "CertSelfSigned", "CertSigAlg", "CertKeyAlg", "CertKeySize", "CertSerial", "CertSha1",
            "CertSha256", "CertPolicyErrors", "CertChainStatus", "CertSource", "Flags", "Advisories", "Banner",
            // v2.3: appended (empty values do not enter the hash, so every earlier version keeps its hash)
            "DeviceName", "Domain", "ProtocolInfo", "Jarm", "Ja4s" };
        // recorded with each sighting, never a reason for a new version (response time, dynamic page hashes, scan clock)
        public static readonly string[] Observed = { "ScannedAt", "VhostOf", "BodyLength", "BodySha256", "ResponseMs", "CertDaysLeft", "Notes", "ScanTag" };
        // profile flag -> fields that only that probe collects; a run without the probe keeps the previous values
        public static readonly string[][] Gated = {
            new[] { "tlsScan", "TlsSupported", "TlsCiphersByVersion", "TlsWeakCipher", "Alpn", "Http2" },
            new[] { "favicon", "FaviconPath", "FaviconMmh3", "FaviconMd5" },
            new[] { "extras", "Robots", "SecurityTxt" },
            new[] { "options", "AllowedMethods", "RiskyMethods" },
            new[] { "identifyPaths", "IdentifiedPaths" },
            new[] { "reverseDns", "ReverseDns" },
            new[] { "tlsFingerprint", "Jarm" },
            new[] { "ja4s", "Ja4s" } };
        static readonly HashSet<string> MaterialSet = new HashSet<string>(Material, StringComparer.Ordinal);
        public static bool IsMaterial(string f) { return MaterialSet.Contains(f); }

        static readonly Regex BannerTime = new Regex(@"\b\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d+)?\b", RegexOptions.CultureInvariant);
        static readonly Regex BannerIsoDate = new Regex(@"\b\d{4}-\d{2}-\d{2}\b", RegexOptions.CultureInvariant);
        static readonly Regex BannerDate = new Regex(@"\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s+)?(?:\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}),?\s+\d{4}\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        static readonly Regex FlagDays = new Regex(@"\bCertExpiring:\d+d\b", RegexOptions.CultureInvariant);
        // comparison form: banners lose clock/date text (SMTP/FTP greetings), certificate-expiry flags lose the day count
        public static string Norm(string field, string v)
        {
            if (string.IsNullOrEmpty(v)) return "";
            if (field == "Banner") return BannerTime.Replace(BannerIsoDate.Replace(BannerDate.Replace(v, "<date>"), "<date>"), "<time>");
            if (field == "Flags") return FlagDays.Replace(v, "CertExpiring");
            return v;
        }
        public static string Hash(Rec mat)
        {
            StringBuilder sb = new StringBuilder(2048);
            foreach (string f in Material)
            {
                string v = Norm(f, mat[f]);
                if (v.Length == 0) continue;
                sb.Append(f).Append('\u001f').Append(v).Append('\u001e');
            }
            Sha256Acc a = Sha256Acc.Shared;
            a.Append(StoreUtil.B(sb.ToString()));
            return a.FinalHex().Substring(0, 32);
        }
        public static List<string> Diff(Rec oldm, Rec newm)
        {
            List<string> d = new List<string>();
            foreach (string f in Material) if (Norm(f, oldm == null ? "" : oldm[f]) != Norm(f, newm[f])) d.Add(f);
            return d;
        }
        public static void CarryOver(Rec mat, Rec prev, RunInfo run)
        {
            if (prev == null) return;
            foreach (string[] g in Gated)
            {
                if (run.Collected(g[0])) continue;
                for (int i = 1; i < g.Length; i++) { string v = prev[g[i]]; if (v.Length > 0) mat[g[i]] = v; else mat.Remove(g[i]); }
            }
        }
        // A difference only in fields that a probe newly switched on filled in (previous version made without that probe,
        // previous value empty) is an enrichment, not a change of the service
        public static bool IsEnrichment(List<string> diff, Rec oldm, Rec newm)
        {
            if (diff == null || diff.Count == 0 || oldm == null) return false;
            string prof = oldm["_prof"];
            foreach (string f in diff)
            {
                if (oldm[f].Length > 0 || newm[f].Length == 0) return false;
                string gate = null;
                foreach (string[] g in Gated) for (int i = 1; i < g.Length; i++) if (g[i] == f) gate = g[0];
                if (gate == null || RunInfo.ProfileHas(prof, gate)) return false;
            }
            return true;
        }
        public static Rec MaterialOf(Rec r)
        {
            Rec m = new Rec();
            foreach (string f in Material) { string v = r[f]; if (v.Length > 0) m[f] = v; }
            return m;
        }
    }

    // run.json written by the scanner at the end of each session (or synthesised when importing older output)
    public sealed class RunInfo
    {
        public string RunId = "", StartedAt = "", FinishedAt = "", Tag = "", Scanner = "", Operator = "", Computer = "";
        public bool Complete = true, Synthesized;
        public bool TlsScan = true, Favicon = true, Extras = true, Options, IdentifyPaths, ProbeSans, ReverseDns;
        public bool TlsFingerprint, Ja4s, Smb, Rdp, Snmp;   // v2.3 opt-in probes (appended to Profile only when on)
        public long Checks;
        public bool Collected(string flag)
        {
            switch (flag)
            {
                case "tlsScan": return TlsScan;
                case "favicon": return Favicon;
                case "extras": return Extras;
                case "options": return Options;
                case "identifyPaths": return IdentifyPaths;
                case "reverseDns": return ReverseDns;
                case "probeSans": return ProbeSans;
                case "tlsFingerprint": return TlsFingerprint;
                case "ja4s": return Ja4s;
            }
            return true;
        }
        public bool NeedsCarryOver { get { return !(TlsScan && Favicon && Extras && Options && IdentifyPaths && ReverseDns && TlsFingerprint && Ja4s); } }
        // flag as written in a Profile string ("tls=1 favicon=1 ..."); missing = off (flags added later are appended only when on)
        public static bool ProfileHas(string profile, string flag)
        {
            string key = flag == "tlsScan" ? "tls" : flag;
            if (string.IsNullOrEmpty(profile)) return false;
            foreach (string kvp in profile.Split(' ')) if (kvp == key + "=1") return true;
            return false;
        }
        public string Profile
        {
            get
            {
                return string.Format(CultureInfo.InvariantCulture, "tls={0} favicon={1} extras={2} options={3} identifyPaths={4} probeSans={5} reverseDns={6}",
                    TlsScan ? 1 : 0, Favicon ? 1 : 0, Extras ? 1 : 0, Options ? 1 : 0, IdentifyPaths ? 1 : 0, ProbeSans ? 1 : 0, ReverseDns ? 1 : 0)
                    + (TlsFingerprint ? " tlsFingerprint=1" : "") + (Ja4s ? " ja4s=1" : "") + (Smb ? " smb=1" : "") + (Rdp ? " rdp=1" : "") + (Snmp ? " snmp=1" : "");
            }
        }
        public DateTimeOffset Started { get { return StoreUtil.ParseIso(StartedAt); } }

        static bool Flag(Dictionary<string, object> p, string k, bool dflt)
        {
            object v = StoreUtil.Field(p, k);
            if (v is bool) return (bool)v;
            return dflt;
        }
        public static RunInfo Parse(string json)
        {
            Dictionary<string, object> o = StoreJson.Parse(json) as Dictionary<string, object>;
            if (o == null) throw new InvalidDataException("run.json is not a JSON object");
            RunInfo r = new RunInfo();
            r.RunId = StoreUtil.Str(o, "runId"); r.StartedAt = StoreUtil.Str(o, "startedAt"); r.FinishedAt = StoreUtil.Str(o, "finishedAt");
            r.Tag = StoreUtil.Str(o, "tag"); r.Scanner = StoreUtil.Str(o, "scanner"); r.Operator = StoreUtil.Str(o, "operator"); r.Computer = StoreUtil.Str(o, "computer");
            r.Complete = Flag(o, "complete", true); r.Synthesized = Flag(o, "synthesized", false); r.Checks = StoreUtil.Num(o, "checks");
            Dictionary<string, object> p = StoreUtil.Field(o, "profile") as Dictionary<string, object>;
            if (p != null)
            {
                r.TlsScan = Flag(p, "tlsScan", true); r.Favicon = Flag(p, "favicon", true); r.Extras = Flag(p, "extras", true);
                r.Options = Flag(p, "options", false); r.IdentifyPaths = Flag(p, "identifyPaths", false); r.ProbeSans = Flag(p, "probeSans", false);
                r.ReverseDns = Flag(p, "reverseDns", false);
                r.TlsFingerprint = Flag(p, "tlsFingerprint", false); r.Ja4s = Flag(p, "ja4s", false); r.Smb = Flag(p, "smb", false); r.Rdp = Flag(p, "rdp", false); r.Snmp = Flag(p, "snmp", false);
            }
            if (r.RunId.Length == 0) throw new InvalidDataException("run.json has no runId");
            DateTimeOffset t;
            if (!StoreUtil.TryIso(r.StartedAt, out t)) throw new InvalidDataException("run.json startedAt is not a timestamp: '" + r.StartedAt + "'");
            return r;
        }
        public string ToJson()
        {
            JsonObj p = new JsonObj().Bool("tlsScan", TlsScan).Bool("favicon", Favicon).Bool("extras", Extras).Bool("options", Options)
                .Bool("identifyPaths", IdentifyPaths).Bool("probeSans", ProbeSans).Bool("reverseDns", ReverseDns);
            if (TlsFingerprint) p.Bool("tlsFingerprint", true);
            if (Ja4s) p.Bool("ja4s", true);
            if (Smb) p.Bool("smb", true);
            if (Rdp) p.Bool("rdp", true);
            if (Snmp) p.Bool("snmp", true);
            return new JsonObj().Num("format", 1).Str("runId", RunId).Str("startedAt", StartedAt).Str("finishedAt", FinishedAt).Bool("complete", Complete)
                .Bool("synthesized", Synthesized).Str("scanner", Scanner).Str("tag", Tag).Str("operator", Operator).Str("computer", Computer)
                .Num("checks", Checks).Raw("profile", p.ToString()).ToString();
        }
        // Older output without run.json: start time from the RunId stamp, probe switches inferred from what the rows hold
        public static RunInfo Synthesize(string runId, string jsonlPath, string progressPath)
        {
            RunInfo r = new RunInfo();
            r.RunId = runId; r.Synthesized = true; r.Complete = true; r.Scanner = "unknown (imported)";
            DateTime stamp;
            if (!DateTime.TryParseExact(runId, "yyyyMMdd_HHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out stamp))
                stamp = File.GetLastWriteTime(jsonlPath);
            r.StartedAt = StoreUtil.Iso(new DateTimeOffset(stamp));
            r.FinishedAt = StoreUtil.Iso(new DateTimeOffset(File.GetLastWriteTime(jsonlPath)));
            bool tls = false, anyTlsRow = false, fav = false, anyWeb = false, extras = false;
            foreach (string l in StoreUtil.ReadLines(jsonlPath))
            {
                if (l.Length == 0) continue;
                Dictionary<string, object> o = StoreJson.Parse(l) as Dictionary<string, object>;
                if (o == null) continue;
                if (r.Tag.Length == 0) r.Tag = StoreUtil.Str(o, "ScanTag");
                if (StoreUtil.Str(o, "TlsSupported").Length > 0) tls = true;
                if (StoreUtil.Str(o, "TlsVersion").Length > 0 || StoreUtil.Str(o, "CertSha256").Length > 0) anyTlsRow = true;
                if (StoreUtil.Str(o, "IsWeb") == "True") anyWeb = true;
                if (StoreUtil.Str(o, "FaviconMmh3").Length > 0) fav = true;
                if (StoreUtil.Str(o, "Robots").Length > 0 || StoreUtil.Str(o, "SecurityTxt").Length > 0) extras = true;
                if (StoreUtil.Str(o, "AllowedMethods").Length > 0) r.Options = true;
                if (StoreUtil.Str(o, "IdentifiedPaths").Length > 0) r.IdentifyPaths = true;
                if (StoreUtil.Str(o, "Vhost") == "True") r.ProbeSans = true;
                if (StoreUtil.Str(o, "ReverseDns").Length > 0) r.ReverseDns = true;
                if (StoreUtil.Str(o, "Jarm").Length > 0) r.TlsFingerprint = true;
                if (StoreUtil.Str(o, "Ja4s").Length > 0) r.Ja4s = true;
            }
            // absent evidence on a run that had candidates means the probe was off; no candidates -> assume the default
            r.TlsScan = tls || !anyTlsRow; r.Favicon = fav || !anyWeb; r.Extras = extras || !anyWeb;
            long n = 0; foreach (string l in StoreUtil.ReadLines(progressPath)) if (l.Trim().Length > 0) n++;
            r.Checks = n;
            return r;
        }
    }

    // Source files of one scan run (paths in the scanner's output and log folders)
    public sealed class RunSources
    {
        public string RunId, Jsonl, Progress, RunJson, Csv, Html, Delta, Manifest;
        public readonly List<string> Logs = new List<string>();
    }

    public sealed class QueryResult
    {
        public string[] Columns;
        public readonly List<string[]> Rows = new List<string[]>();
    }

    // -Filter clauses: Field op Value, op one of = != ~ !~ < <= > >= ; all clauses must match
    public sealed class RowFilter
    {
        public string Field, Op, Value;
        static readonly Regex Rx = new Regex(@"^\s*([A-Za-z][A-Za-z0-9]*)\s*(!=|!~|<=|>=|=|~|<|>)\s*(.*?)\s*$", RegexOptions.CultureInvariant);
        public static List<RowFilter> Parse(string[] specs, IEnumerable<string> fields)
        {
            HashSet<string> known = new HashSet<string>(fields, StringComparer.OrdinalIgnoreCase);
            known.Add("Any");
            List<RowFilter> r = new List<RowFilter>();
            if (specs == null) return r;
            foreach (string s in specs)
            {
                if (string.IsNullOrWhiteSpace(s)) continue;
                Match m = Rx.Match(s);
                if (!m.Success) throw new ArgumentException("filter '" + s + "' is not 'Field<op>Value' (ops: = != ~ !~ < <= > >=)");
                if (!known.Contains(m.Groups[1].Value)) throw new ArgumentException("filter '" + s + "': unknown field '" + m.Groups[1].Value + "'");
                RowFilter f = new RowFilter(); f.Field = m.Groups[1].Value; f.Op = m.Groups[2].Value; f.Value = m.Groups[3].Value.Trim('\'', '"');
                r.Add(f);
            }
            return r;
        }
        public static bool All(List<RowFilter> fs, Dictionary<string, string> row)
        {
            foreach (RowFilter f in fs) if (!f.Match(row)) return false;
            return true;
        }
        bool Match(Dictionary<string, string> row)
        {
            if (Field.Equals("Any", StringComparison.OrdinalIgnoreCase))
            {
                // Any: positive operators match when some field matches; != and !~ when no field matches = / ~
                if (Op == "!=") return !AnyField("=", row);
                if (Op == "!~") return !AnyField("~", row);
                return AnyField(Op, row);
            }
            string val; row.TryGetValue(Field, out val);
            return Test(Op, val ?? "");
        }
        bool AnyField(string op, Dictionary<string, string> row)
        {
            foreach (string v in row.Values) if (Test(op, v ?? "")) return true;
            return false;
        }
        bool Test(string op, string v)
        {
            switch (op)
            {
                case "=": return Eq(v);
                case "!=": return !Eq(v);
                case "~": return v.IndexOf(Value, StringComparison.OrdinalIgnoreCase) >= 0;
                case "!~": return v.IndexOf(Value, StringComparison.OrdinalIgnoreCase) < 0;
            }
            if (v.Length == 0) return false;
            int c;
            double a, b; DateTimeOffset ta, tb;
            if (double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out a) && double.TryParse(Value, NumberStyles.Float, CultureInfo.InvariantCulture, out b)) c = a.CompareTo(b);
            else if (StoreUtil.TryIso(v, out ta) && StoreUtil.TryIso(Value, out tb)) c = ta.CompareTo(tb);
            else c = string.Compare(v, Value, StringComparison.OrdinalIgnoreCase);
            switch (op) { case "<": return c < 0; case "<=": return c <= 0; case ">": return c > 0; default: return c >= 0; }
        }
        // whole value, or one ';'-separated item, or a flag name ("CertExpiring" matches "CertExpiring:12d")
        bool Eq(string v)
        {
            if (v.Equals(Value, StringComparison.OrdinalIgnoreCase)) return true;
            if (v.IndexOf(';') < 0 && v.IndexOf(':') < 0) return false;
            foreach (string part in v.Split(';'))
            {
                string p = part.Trim();
                if (p.Equals(Value, StringComparison.OrdinalIgnoreCase)) return true;
                if (p.Length > Value.Length && p[Value.Length] == ':' && p.StartsWith(Value, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }
}

// ============================================================================
// WebInv inventory store
//   <Store>\STORE.json            identity, engine, schema, retire threshold
//   <Store>\LOCK                  held (FileShare.None) while a process has the store open
//   <Store>\store.log             what the store did, append-only
//   <Store>\db\                   working database (ESENT inventory.edb + logs, or inventory.kv) - rebuildable
//   <Store>\archive\ledger.jsonl  one line per run / correction / rebase, each carrying the SHA-256 of the previous line
//   <Store>\archive\corrections\<seq>-<op>\   manual merge/split: correction.json + derived changes
//   <Store>\archive\rebase\<seq>\<pos>\      derived files of a replay in a new order (backfilled runs)
//   <Store>\archive\anchors\<seq>.p7s         optional detached signatures of ledger lines
//   <Store>\archive\runs\yyyy\MM\<RunId>\   immutable inputs (results, checked keys, run.json, CSV, HTML, logs,
//                                 manifest) + INPUTS.json, and derived changes.jsonl.gz / state.jsonl.gz
// Database keys (seq = position in the applied plan; equal to the ledger seq until a rebase): m (meta), r/<seq> run or correction, ri/<runId>, k/<sha(natural key)> -> entity id, e/<eid> entity,
// v/<eid>/<ver> version, c/<seq>/<eid> change event, x/<eid>/<seq> per-entity event index.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Text;

    public sealed class LedgerEntry
    {
        public long Seq;
        public int RetireAfter;
        public bool Snapshot = true, Backfill;
        public string Type = "", RunId = "", RunStarted = "", Path = "", StateDigest = "", ChangesDigest = "", Line = "", Hash = "", Prev = "";
        public Dictionary<string, object> Obj;
    }

    public sealed class IngestSummary
    {
        public string RunId = "", Archive = "", StateDigest = "", ChangesDigest = "", LedgerHead = "", Profile = "";
        public long Seq, Rows, Duplicates, Incomplete, Added, Changed, Enriched, Reappeared, Rekeyed, Missing, Retired, Active, MissingTotal, RetiredTotal;
        public bool AlreadyPresent, Partial;
        public string Void = "";
        public double Seconds;
        public readonly List<string> Phases = new List<string>();
        Stopwatch lap = Stopwatch.StartNew();
        public void Lap(string name) { Phases.Add(name + "=" + lap.Elapsed.TotalSeconds.ToString("0.00", CultureInfo.InvariantCulture)); lap.Restart(); }
        public string Text()
        {
            return string.Format(CultureInfo.InvariantCulture,
                "run {0} (seq {1}): {2} rows -> added {3}, changed {4}, reappeared {5}, rekeyed {6}, missing {7}, retired {8}; inventory now {9} active, {10} missing, {11} retired{12}{13}{15} in {14:0.0}s",
                RunId, Seq, Rows, Added, Changed, Reappeared, Rekeyed, Missing, Retired, Active, MissingTotal, RetiredTotal,
                Duplicates > 0 ? "; " + Duplicates + " duplicate rows ignored" : "", Incomplete > 0 ? "; " + Incomplete + " incomplete observations (no version change)" : "", Seconds,
                Enriched > 0 ? "; " + Enriched + " enriched by newly enabled probes" : "");
        }
    }

    public sealed partial class InventoryStore : IDisposable
    {
        public const int Format = 1;
        public readonly string Root, DbDir, ArchiveDir, RunsDir, LedgerPath, StoreJsonPath, LogPath;
        public string Engine { get; private set; }
        public string StoreId { get; private set; }
        public int RetireAfter { get; private set; }
        public string ScannerVersion = "";
        public readonly List<string> Messages = new List<string>();
        string created = "";
        KvEngine kv;
        FileStream lockFs;
        bool shadow;
        const int Batch = 200;
        // self-test hook: "rows:N" (after the Nth row batch) | "absence" | "derived" - flush what is committed, then fail
        // the way a crash would; the next open must finish the run with identical results
        public static string FailPoint = "";
        void Fail(string point)
        {
            if (FailPoint.Length == 0 || FailPoint != point) return;
            FailPoint = "";
            kv.Flush();
            throw new IOException("failpoint " + point);
        }
        static readonly string Zero64 = new string('0', 64);

        InventoryStore(string root)
        {
            Root = Path.GetFullPath(root);
            DbDir = Path.Combine(Root, "db");
            ArchiveDir = Path.Combine(Root, "archive");
            RunsDir = Path.Combine(ArchiveDir, "runs");
            LedgerPath = Path.Combine(ArchiveDir, "ledger.jsonl");
            StoreJsonPath = Path.Combine(Root, "STORE.json");
            LogPath = Path.Combine(Root, "store.log");
            Engine = ""; StoreId = ""; RetireAfter = 3;
        }

        public static string ResolveEngine(string requested)
        {
            string r = (requested ?? "auto").Trim().ToLowerInvariant();
            if (r.Length == 0 || r == "auto") return EsentKv.Available ? "esent" : "file";
            if (r != "esent" && r != "file") throw new ArgumentException("unknown store engine '" + requested + "' (Auto, Esent or File)");
            if (r == "esent" && !EsentKv.Available) throw new InvalidOperationException("ESENT (esent.dll) is not available on this system; use -StoreEngine File");
            return r;
        }

        // mode: write = create if missing + bring the database up to date with the archive; read = must exist, same
        // catch-up; verify / rebuild = must exist, no catch-up (verify opens an existing database read-mostly, rebuild none)
        public static InventoryStore Open(string root, string engine, int retireAfter, string scannerVersion, string mode, int lockWaitMs)
        {
            InventoryStore s = new InventoryStore(root);
            s.ScannerVersion = scannerVersion ?? "";
            bool exists = File.Exists(s.StoreJsonPath);
            if (!exists && mode != "write") throw new FileNotFoundException("no inventory store at " + s.Root + " (STORE.json not found)");
            try
            {
                Directory.CreateDirectory(s.Root);
                s.AcquireLock(lockWaitMs);
                if (!exists) s.Create(engine, retireAfter);
                else s.Load(engine, retireAfter, mode);
                if (mode == "verify")
                {
                    if (s.DbExists() && (s.Engine != "esent" || EsentKv.Available)) s.kv = s.OpenEngine();
                }
                else if (mode != "rebuild")
                {
                    s.kv = s.OpenEngine();
                    s.Reconcile();
                }
                return s;
            }
            catch { s.Dispose(); throw; }
        }

        bool DbExists() { return File.Exists(Path.Combine(DbDir, Engine == "esent" ? "inventory.edb" : "inventory.kv")); }
        KvEngine OpenEngine()
        {
            Directory.CreateDirectory(DbDir);
            if (Engine == "esent") return new EsentKv(DbDir);
            return new FileKv(Path.Combine(DbDir, "inventory.kv"));
        }

        void AcquireLock(int waitMs)
        {
            string p = Path.Combine(Root, "LOCK");
            DateTime until = DateTime.UtcNow.AddMilliseconds(Math.Max(0, waitMs));
            while (true)
            {
                try { lockFs = new FileStream(p, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); break; }
                catch (IOException)
                {
                    if (DateTime.UtcNow >= until) throw new IOException("the inventory store " + Root + " is in use by another process");
                    System.Threading.Thread.Sleep(250);
                }
            }
            byte[] b = StoreUtil.B(string.Format(CultureInfo.InvariantCulture, "pid={0} host={1} since={2}\n", Process.GetCurrentProcess().Id, Environment.MachineName, StoreUtil.Iso(DateTimeOffset.Now)));
            lockFs.SetLength(0); lockFs.Write(b, 0, b.Length); lockFs.Flush();
        }

        void Log(string m)
        {
            Messages.Add(m);
            if (shadow) return;
            try { File.AppendAllText(LogPath, StoreUtil.Iso(DateTimeOffset.Now) + " " + m + "\r\n", StoreUtil.Utf8); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }

        // ---------------------------------------------------------------- STORE.json
        void Create(string engine, int retireAfter)
        {
            Engine = ResolveEngine(engine);
            RetireAfter = retireAfter > 0 ? retireAfter : 3;
            Directory.CreateDirectory(RunsDir);
            created = StoreUtil.Iso(DateTimeOffset.Now);
            List<string> problems = new List<string>();
            List<LedgerEntry> led = File.Exists(LedgerPath) ? ReadLedger(problems) : new List<LedgerEntry>();
            if (led.Count > 0 && led[0].Type == "genesis")
            {
                StoreId = StoreUtil.Str(led[0].Obj, "storeId");
                created = StoreUtil.Str(led[0].Obj, "created");
                Log("STORE.json was missing; recreated it from the archive ledger (store " + StoreId + ")");
            }
            else
            {
                if (led.Count > 0) throw new InvalidDataException("archive ledger exists but has no genesis line: " + LedgerPath);
                StoreId = Guid.NewGuid().ToString("D");
                AppendLedger(new JsonObj().Num("seq", 0).Str("type", "genesis").Str("storeId", StoreId).Str("created", created).Num("format", Format).Num("schema", InvSchema.Version), Zero64);
                WriteReadme();
                Log(string.Format(CultureInfo.InvariantCulture, "created store {0} at {1} (engine {2}, a service is retired after {3} consecutive in-scope runs without it)", StoreId, Root, Engine, RetireAfter));
            }
            SaveStoreJson();
        }

        void SaveStoreJson()
        {
            JsonObj jo = new JsonObj().Num("format", Format).Num("schema", InvSchema.Version).Str("storeId", StoreId).Str("created", created).Str("engine", Engine)
                .Num("retireAfter", RetireAfter);
            if (SnapshotEvery > 1) jo.Num("snapshotEvery", SnapshotEvery);
            if (AnchorEventLog) jo.Bool("anchorEventLog", true);
            if (AnchorCertificate.Length > 0) jo.Str("anchorCertificate", AnchorCertificate).Num("anchorFrom", AnchorFrom);
            string j = jo.Str("updatedBy", "WebInventory " + ScannerVersion).Str("updated", StoreUtil.Iso(DateTimeOffset.Now)).ToString();
            StoreUtil.WriteAllTextAtomic(StoreJsonPath, j + "\n");
        }

        void Load(string engine, int retireAfter, string mode)
        {
            Dictionary<string, object> o = StoreJson.Parse(File.ReadAllText(StoreJsonPath, StoreUtil.Utf8)) as Dictionary<string, object>;
            if (o == null) throw new InvalidDataException("STORE.json is not a JSON object");
            if (StoreUtil.Num(o, "format") > Format) throw new InvalidDataException("the store was created by a newer WebInventory version (format " + StoreUtil.Str(o, "format") + ")");
            if (StoreUtil.Num(o, "schema") != InvSchema.Version) throw new InvalidDataException("the store uses inventory schema " + StoreUtil.Str(o, "schema") + "; this version uses " + InvSchema.Version);
            StoreId = StoreUtil.Str(o, "storeId"); created = StoreUtil.Str(o, "created"); Engine = StoreUtil.Str(o, "engine");
            int ra = (int)StoreUtil.Num(o, "retireAfter"); RetireAfter = ra > 0 ? ra : 3;
            int se = (int)StoreUtil.Num(o, "snapshotEvery"); SnapshotEvery = se > 0 ? se : 1;
            AnchorEventLog = StoreUtil.Str(o, "anchorEventLog") == "True"; AnchorCertificate = StoreUtil.Str(o, "anchorCertificate"); AnchorFrom = StoreUtil.Num(o, "anchorFrom");
            string req = (engine ?? "auto").Trim().ToLowerInvariant();
            if (mode != "rebuild" && req != "" && req != "auto" && req != Engine)
                throw new InvalidOperationException("the store database uses the " + Engine + " engine; to switch, rebuild it from the archive: -RebuildStore -StoreEngine " + req);
            if (mode != "rebuild" && mode != "verify" && Engine == "esent" && !EsentKv.Available)
                throw new InvalidOperationException("the store database uses ESENT, which this system does not have; -RebuildStore -StoreEngine File builds a portable database from the archive");
            if (retireAfter > 0 && retireAfter != RetireAfter && mode != "verify")
            {
                Log(string.Format(CultureInfo.InvariantCulture, "retire threshold changed from {0} to {1} (applies to runs ingested from now on; earlier runs keep theirs)", RetireAfter, retireAfter));
                RetireAfter = retireAfter;
                SaveStoreJson();
            }
        }

        void WriteReadme()
        {
            string t = "WebInventory inventory store\r\n" +
                "============================\r\n\r\n" +
                "archive\\        the long-term record. Never edit or delete files here.\r\n" +
                "  ledger.jsonl  one JSON line per ingested run; each line holds the SHA-256 of the line before it\r\n" +
                "                (\"prev\"), the SHA-256 of every file archived for the run, and digests of the derived files.\r\n" +
                "  runs\\yyyy\\MM\\<RunId>\\\r\n" +
                "    results.jsonl.gz   the scan's JSONL output, as written      results.csv.gz / report.html.gz  as written\r\n" +
                "    checked.txt.gz     every host|ip|port the run checked (decides what counts as absent)\r\n" +
                "    run.json           when, how (probe switches) and by whom the run was made\r\n" +
                "    INPUTS.json        hashes of the files above (archive copy and original)\r\n" +
                "    changes.jsonl.gz   change events this run produced (added/changed/missing/retired/reappeared/rekeyed)\r\n" +
                "    state.jsonl.gz     the whole inventory after this run (one JSON object per service)\r\n" +
                "db\\             working database (ESENT or file). Disposable: Invoke-WebInventory.ps1 -Store <here> -RebuildStore\r\n" +
                "                recreates it from archive\\ and checks every digest in the ledger.\r\n" +
                "Verify:         Invoke-WebInventory.ps1 -Store <here> -VerifyStore\r\n" +
                "Back up / move: copy archive\\ (and STORE.json). db\\ is tied to this Windows installation.\r\n";
            File.WriteAllText(Path.Combine(Root, "README.txt"), t, StoreUtil.Utf8);
        }

        // ---------------------------------------------------------------- ledger
        public List<LedgerEntry> ReadLedger(List<string> problems)
        {
            List<LedgerEntry> r = new List<LedgerEntry>();
            if (!File.Exists(LedgerPath)) { problems.Add("ledger not found: " + LedgerPath); return r; }
            string prev = Zero64; long expect = 0; int n = 0;
            foreach (string line in StoreUtil.ReadLines(LedgerPath))
            {
                n++;
                LedgerEntry e = new LedgerEntry();
                e.Line = line; e.Hash = StoreUtil.Sha256Hex(line);
                try { e.Obj = StoreJson.Parse(line) as Dictionary<string, object>; }
                catch (Exception ex) { problems.Add("ledger line " + n + " is not valid JSON (" + ex.Message + ")"); break; }
                if (e.Obj == null) { problems.Add("ledger line " + n + " is not a JSON object"); break; }
                e.Seq = StoreUtil.Num(e.Obj, "seq"); e.Type = StoreUtil.Str(e.Obj, "type"); e.Prev = StoreUtil.Str(e.Obj, "prev");
                e.RunId = StoreUtil.Str(e.Obj, "runId"); e.RunStarted = StoreUtil.Str(e.Obj, "runStarted"); e.Path = StoreUtil.Str(e.Obj, "path");
                e.StateDigest = StoreUtil.Str(e.Obj, "stateDigest"); e.ChangesDigest = StoreUtil.Str(e.Obj, "changesDigest");
                e.RetireAfter = (int)StoreUtil.Num(e.Obj, "retireAfter");
                e.Snapshot = StoreUtil.Str(e.Obj, "snapshot") != "False"; e.Backfill = StoreUtil.Str(e.Obj, "backfill") == "True";
                if (e.Prev != prev) problems.Add("ledger line " + n + " (seq " + e.Seq + "): 'prev' does not match the SHA-256 of the line before it");
                if (e.Seq != expect) problems.Add("ledger line " + n + ": seq " + e.Seq + ", expected " + expect);
                if (n == 1 && e.Type != "genesis") problems.Add("ledger line 1 is not the genesis line");
                if (n > 1 && e.Type != "run" && e.Type != "correction" && e.Type != "rebase") problems.Add("ledger line " + n + ": unknown type '" + e.Type + "'");
                prev = e.Hash; expect = e.Seq + 1;
                r.Add(e);
            }
            return r;
        }

        string AppendLedger(JsonObj o, string prev)
        {
            string line = o.Str("prev", prev).ToString();
            byte[] b = StoreUtil.B(line + "\n");
            using (FileStream fs = new FileStream(LedgerPath, FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                fs.Write(b, 0, b.Length);
                fs.Flush(true);
            }
            string h = StoreUtil.Sha256Hex(line);
            Appended.Add(new string[] { StoreUtil.Str(StoreJson.Parse(line) as Dictionary<string, object>, "seq"), h, line });
            return h;
        }

        // a crash while appending can leave a torn final line: drop it (its run folder is then finished again as pending)
        bool RepairLedgerTail()
        {
            byte[] all = File.ReadAllBytes(LedgerPath);
            if (all.Length == 0 || all[all.Length - 1] == (byte)'\n') return false;
            int cut = Array.LastIndexOf(all, (byte)'\n') + 1;
            using (FileStream fs = new FileStream(LedgerPath, FileMode.Open, FileAccess.Write, FileShare.None)) { fs.SetLength(cut); fs.Flush(true); }
            Log("ledger: removed a torn final line (" + (all.Length - cut) + " bytes) left by an interrupted write");
            return true;
        }

        List<LedgerEntry> ReadLedgerStrict()
        {
            List<string> problems = new List<string>();
            List<LedgerEntry> led = ReadLedger(problems);
            if (problems.Count > 0 && !shadow && RepairLedgerTail()) { problems.Clear(); led = ReadLedger(problems); }
            if (problems.Count > 0) throw new InvalidDataException("archive ledger failed its integrity check: " + problems[0] + " (-VerifyStore reports everything)");
            return led;
        }

        public string LedgerHead()
        {
            List<string> problems = new List<string>();
            List<LedgerEntry> led = ReadLedger(problems);
            return led.Count > 0 ? led[led.Count - 1].Hash : "";
        }

        // ---------------------------------------------------------------- keys and records
        static readonly byte[] MetaKey = StoreUtil.B("m\0");
        static byte[] P(string t) { return StoreUtil.B(t + "\0"); }
        static byte[] P(string t, string a) { return StoreUtil.B(t + "\0" + a + "\0"); }
        static byte[] K(string t, string a) { return StoreUtil.B(t + "\0" + a); }
        static byte[] K(string t, string a, string b) { return StoreUtil.B(t + "\0" + a + "\0" + b); }
        static byte[] NkKey(string nk)
        {
            Sha256Acc a = Sha256Acc.Shared;
            a.Append(StoreUtil.B(nk));
            byte[] h = a.Final();
            byte[] k = new byte[18]; k[0] = (byte)'k'; k[1] = 0; Buffer.BlockCopy(h, 0, k, 2, 16);
            return k;
        }
        static byte[] EntKey(string eid) { return K("e", eid); }
        static byte[] VerKey(string eid, long ver) { return K("v", eid, StoreUtil.D10(ver)); }
        static byte[] EvKey(long seq, string eid) { return K("c", StoreUtil.D10(seq), eid); }
        static byte[] XKey(string eid, long seq) { return K("x", eid, StoreUtil.D10(seq)); }
        static byte[] RunKey(long seq) { return K("r", StoreUtil.D10(seq)); }
        static byte[] RunIdKey(string runId) { return K("ri", runId); }
        Rec Get(byte[] k) { return Rec.Decode(kv.Get(k)); }
        void Put(byte[] k, Rec r) { kv.Put(k, r.Encode()); }
        Rec RunByRunId(string runId)
        {
            byte[] s = kv.Get(RunIdKey(runId));
            return s == null ? null : Get(RunKey(long.Parse(StoreUtil.S(s), CultureInfo.InvariantCulture)));
        }
        Rec Ver(string eid, long ver)
        {
            Rec v = Get(VerKey(eid, ver));
            if (v == null) throw new InvalidDataException("entity " + eid + " has no version " + ver);
            return v;
        }

        // ---------------------------------------------------------------- bring the database up to the archive
        // (Reconcile: see invstore2.cs - plan based, handles corrections and rebases)

        // archived run folders (relative paths, '/' separated), oldest first by run start
        List<string> ArchivedFolders()
        {
            List<KeyValuePair<DateTimeOffset, string>> r = new List<KeyValuePair<DateTimeOffset, string>>();
            if (!Directory.Exists(RunsDir)) return new List<string>();
            foreach (string y in Directory.GetDirectories(RunsDir))
                foreach (string m in Directory.GetDirectories(y))
                    foreach (string d in Directory.GetDirectories(m))
                    {
                        DateTimeOffset t = DateTimeOffset.MinValue;
                        string rj = Path.Combine(d, "run.json");
                        try { if (File.Exists(rj)) t = RunInfo.Parse(File.ReadAllText(rj, StoreUtil.Utf8)).Started; } catch (Exception) { }
                        r.Add(new KeyValuePair<DateTimeOffset, string>(t, "runs/" + Path.GetFileName(y) + "/" + Path.GetFileName(m) + "/" + Path.GetFileName(d)));
                    }
            r.Sort(delegate(KeyValuePair<DateTimeOffset, string> a, KeyValuePair<DateTimeOffset, string> b) { int c = a.Key.CompareTo(b.Key); return c != 0 ? c : string.CompareOrdinal(a.Value, b.Value); });
            List<string> o = new List<string>();
            foreach (KeyValuePair<DateTimeOffset, string> kv2 in r) o.Add(kv2.Value);
            return o;
        }
        string AbsRun(string rel) { return Path.Combine(ArchiveDir, rel.Replace('/', Path.DirectorySeparatorChar)); }

        // ---------------------------------------------------------------- ingest a finished scan
        static readonly System.Text.RegularExpressions.Regex RunIdRx = new System.Text.RegularExpressions.Regex(@"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$");

        public IngestSummary Ingest(RunSources src, bool allowPartial)
        {
            if (kv == null || shadow) throw new InvalidOperationException("store not open for writing");
            Stopwatch sw = Stopwatch.StartNew();
            List<LedgerEntry> led = ReadLedgerStrict();
            RunInfo run; LedgerEntry dupEntry, lastRun;
            CheckRun(src, allowPartial, led, out run, out dupEntry, out lastRun);
            if (dupEntry != null)
            {
                IngestSummary dup = new IngestSummary(); dup.RunId = run.RunId; dup.Seq = dupEntry.Seq; dup.AlreadyPresent = true; dup.Archive = dupEntry.Path;
                return dup;
            }
            if (lastRun != null && run.Started < StoreUtil.ParseIso(lastRun.RunStarted))
                throw new InvalidOperationException("run " + run.RunId + " (started " + run.StartedAt + ") is older than the newest run in the store (" + lastRun.RunId + ", " + lastRun.RunStarted + "); add -Backfill to insert it in time order (the database is then replayed)");
            double tValidate, tCopy; long rows;
            string rel = ArchiveRun(src, run, out rows, out tValidate, out tCopy);
            List<PlanItem> plan = BuildPlan(led);
            long seq = plan.Count + 1;
            bool snap = SnapshotFor(plan, true);
            IngestSummary s = ApplyArchived(rel, seq, RetireAfter, AbsRun(rel), snap);
            s.Phases.Insert(0, "validate=" + tValidate.ToString("0.00", CultureInfo.InvariantCulture)); s.Phases.Insert(1, "archive=" + tCopy.ToString("0.00", CultureInfo.InvariantCulture));
            s.LedgerHead = AppendRunLedger(rel, s, RetireAfter, led, snap);
            s.Partial = !run.Complete;
            if (rows != s.Rows + s.Duplicates) throw new InvalidDataException("row count changed while ingesting (" + rows + " vs " + (s.Rows + s.Duplicates) + ")");
            s.Seconds = sw.Elapsed.TotalSeconds;
            Log("ingested " + s.Text() + "; ledger head " + s.LedgerHead);
            Log("ingest phases (s): " + string.Join(" ", s.Phases));
            return s;
        }

        void CheckRun(RunSources src, bool allowPartial, List<LedgerEntry> led, out RunInfo run, out LedgerEntry dup, out LedgerEntry lastRun)
        {
            if (src.RunId == null || !RunIdRx.IsMatch(src.RunId)) throw new ArgumentException("invalid RunId '" + src.RunId + "'");
            if (string.IsNullOrEmpty(src.Jsonl) || !File.Exists(src.Jsonl)) throw new FileNotFoundException("results file not found: " + src.Jsonl);
            if (string.IsNullOrEmpty(src.Progress) || !File.Exists(src.Progress))
                throw new FileNotFoundException("progress file not found: " + src.Progress + " (it lists the checks the run made; without it a missing service cannot be told from one that was not scanned)");
            bool haveRunJson = !string.IsNullOrEmpty(src.RunJson) && File.Exists(src.RunJson);
            run = haveRunJson ? RunInfo.Parse(File.ReadAllText(src.RunJson, StoreUtil.Utf8)) : RunInfo.Synthesize(src.RunId, src.Jsonl, src.Progress);
            if (run.RunId != src.RunId) throw new InvalidDataException("run.json is for run " + run.RunId + ", not " + src.RunId);
            dup = null; lastRun = null;
            DateTimeOffset newest = DateTimeOffset.MinValue;
            foreach (LedgerEntry e in led)
            {
                if (e.Type != "run") continue;
                if (e.RunId == run.RunId) dup = e;
                DateTimeOffset t = StoreUtil.ParseIso(e.RunStarted);
                if (lastRun == null || t >= newest) { lastRun = e; newest = t; }
            }
            if (dup == null && !run.Complete && !allowPartial) throw new InvalidOperationException("run " + run.RunId + " did not complete; finish it with -Resume (or import the partial run with -Force)");
        }

        // validates the run's files and copies them into archive\runs\yyyy\MM\<RunId> (INPUTS.json last)
        string ArchiveRun(RunSources src, RunInfo run, out long rows, out double tValidate, out double tCopy)
        {
            Stopwatch ph = Stopwatch.StartNew();
            rows = ValidateResults(src.Jsonl);
            tValidate = ph.Elapsed.TotalSeconds; ph.Restart();
            foreach (string l in StoreUtil.ReadLines(src.Progress)) { string t = l.Trim(); if (t.Length > 0 && t.Split('|').Length < 3) throw new InvalidDataException("progress file line is not host|ip|port: '" + t + "'"); }
            bool haveRunJson = !string.IsNullOrEmpty(src.RunJson) && File.Exists(src.RunJson);
            DateTimeOffset st = run.Started;
            string rel = "runs/" + st.ToString("yyyy", CultureInfo.InvariantCulture) + "/" + st.ToString("MM", CultureInfo.InvariantCulture) + "/" + run.RunId;
            string dir = AbsRun(rel);
            Directory.CreateDirectory(dir);
            string inputsPath = Path.Combine(dir, "INPUTS.json");
            if (File.Exists(inputsPath)) File.Delete(inputsPath);
            List<string> inputs = new List<string>();
            inputs.Add(CopyIn(src.Jsonl, dir, "results.jsonl.gz", true));
            inputs.Add(CopyIn(src.Progress, dir, "checked.txt.gz", true));
            if (haveRunJson) inputs.Add(CopyIn(src.RunJson, dir, "run.json", false));
            else { File.WriteAllText(Path.Combine(dir, "run.json"), run.ToJson() + "\n", StoreUtil.Utf8); inputs.Add(Describe(dir, "run.json", "(synthesized at import)", "", 0)); }
            if (!string.IsNullOrEmpty(src.Csv) && File.Exists(src.Csv)) inputs.Add(CopyIn(src.Csv, dir, "results.csv.gz", true));
            if (!string.IsNullOrEmpty(src.Html) && File.Exists(src.Html)) inputs.Add(CopyIn(src.Html, dir, "report.html.gz", true));
            if (!string.IsNullOrEmpty(src.Delta) && File.Exists(src.Delta)) inputs.Add(CopyIn(src.Delta, dir, "delta.csv.gz", true));
            if (!string.IsNullOrEmpty(src.Manifest) && File.Exists(src.Manifest)) inputs.Add(CopyIn(src.Manifest, dir, "manifest.txt", false));
            HashSet<string> logNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string lg in src.Logs)
            {
                if (string.IsNullOrEmpty(lg) || !File.Exists(lg)) continue;
                string nm = Path.GetFileName(lg) + ".gz";
                if (!logNames.Add(nm)) continue;
                Directory.CreateDirectory(Path.Combine(dir, "logs"));
                inputs.Add(CopyIn(lg, dir, "logs/" + nm, true));
            }
            StoreUtil.WriteAllTextAtomic(inputsPath, new JsonObj().Str("runId", run.RunId).Raw("files", "[" + string.Join(",", inputs) + "]").ToString() + "\n");
            tCopy = ph.Elapsed.TotalSeconds;
            return rel;
        }

        static long ValidateResults(string path)
        {
            long n = 0, line = 0;
            foreach (string l in StoreUtil.ReadLines(path))
            {
                line++;
                if (l.Length == 0) continue;
                Dictionary<string, object> o;
                try { o = StoreJson.Parse(l) as Dictionary<string, object>; }
                catch (Exception ex) { throw new InvalidDataException("results line " + line + " is not valid JSON: " + ex.Message); }
                if (o == null || StoreUtil.Str(o, "Host").Length == 0 || StoreUtil.Str(o, "Port").Length == 0)
                    throw new InvalidDataException("results line " + line + " has no Host/Port");
                n++;
            }
            return n;
        }

        string CopyIn(string src, string dir, string name, bool gz)
        {
            string dst = Path.Combine(dir, name.Replace('/', Path.DirectorySeparatorChar));
            long srcBytes;
            string srcSha;
            if (gz) srcSha = StoreUtil.CopyToGz(src, dst, out srcBytes);
            else { File.Copy(src, dst, true); srcSha = StoreUtil.FileSha256(dst, out srcBytes); }
            return Describe(dir, name, Path.GetFileName(src), srcSha, srcBytes);
        }
        static string Describe(string dir, string name, string source, string srcSha, long srcBytes)
        {
            long bytes;
            string sha = StoreUtil.FileSha256(Path.Combine(dir, name.Replace('/', Path.DirectorySeparatorChar)), out bytes);
            JsonObj o = new JsonObj().Str("name", name).Str("sha256", sha).Num("bytes", bytes).Str("source", source);
            if (srcSha.Length > 0) o.Str("sourceSha256", srcSha).Num("sourceBytes", srcBytes);
            return o.ToString();
        }

        string AppendRunLedger(string rel, IngestSummary s, int retireAfter, List<LedgerEntry> led, bool snapshot)
        {
            string dir = AbsRun(rel);
            Dictionary<string, object> inputs = StoreJson.Parse(File.ReadAllText(Path.Combine(dir, "INPUTS.json"), StoreUtil.Utf8)) as Dictionary<string, object>;
            List<string> files = new List<string>();
            foreach (object f in (System.Collections.IEnumerable)StoreUtil.Field(inputs, "files"))
            {
                Dictionary<string, object> d = (Dictionary<string, object>)f;
                files.Add(new JsonObj().Str("name", StoreUtil.Str(d, "name")).Str("sha256", StoreUtil.Str(d, "sha256")).Num("bytes", StoreUtil.Num(d, "bytes")).ToString());
            }
            long b;
            files.Add(new JsonObj().Str("name", "INPUTS.json").Str("sha256", StoreUtil.FileSha256(Path.Combine(dir, "INPUTS.json"), out b)).Num("bytes", b).ToString());
            List<string> derived = new List<string>();
            foreach (string n in snapshot ? new[] { "changes.jsonl.gz", "state.jsonl.gz" } : new[] { "changes.jsonl.gz" })
                derived.Add(new JsonObj().Str("name", n).Str("sha256", StoreUtil.FileSha256(Path.Combine(dir, n), out b)).Num("bytes", b).ToString());
            RunInfo run = RunInfo.Parse(File.ReadAllText(Path.Combine(dir, "run.json"), StoreUtil.Utf8));
            JsonObj counts = new JsonObj().Num("rows", s.Rows).Num("duplicates", s.Duplicates).Num("incomplete", s.Incomplete).Num("added", s.Added).Num("changed", s.Changed).Num("enriched", s.Enriched)
                .Num("reappeared", s.Reappeared).Num("rekeyed", s.Rekeyed).Num("missing", s.Missing).Num("retired", s.Retired)
                .Num("active", s.Active).Num("missingTotal", s.MissingTotal).Num("retiredTotal", s.RetiredTotal);
            long lseq = led.Count > 0 ? led[led.Count - 1].Seq + 1 : 1;
            JsonObj o = new JsonObj().Num("seq", lseq).Str("type", "run").Str("runId", s.RunId).Str("runStarted", run.StartedAt).Str("path", rel)
                .Bool("complete", run.Complete).Num("retireAfter", retireAfter).Str("profile", run.Profile).Str("engine", Engine).Str("ingestedBy", "WebInventory " + ScannerVersion)
                .Str("ingestedAt", StoreUtil.Iso(DateTimeOffset.Now)).Raw("files", "[" + string.Join(",", files) + "]").Raw("derived", "[" + string.Join(",", derived) + "]")
                .Str("changesDigest", s.ChangesDigest).Str("stateDigest", s.StateDigest).Raw("counts", counts.ToString());
            if (!snapshot) o.Bool("snapshot", false);
            if (lseq != s.Seq) o.Num("pos", s.Seq);
            string prev = led.Count > 0 ? led[led.Count - 1].Hash : Zero64;
            string head = AppendLedger(o, prev);
            kv.Begin();
            Rec meta = Get(MetaKey) ?? new Rec();
            meta["ledgerHead"] = head; Put(MetaKey, meta);
            kv.Commit(true); kv.Flush();
            return head;
        }

        // ---------------------------------------------------------------- apply one archived run (idempotent)
        sealed class Obs
        {
            public string Nk, Host, Ip, Port, Vh, Url;
            public Rec Mat = new Rec(), Seen = new Rec();
            public bool Incomplete;
            public static Obs From(Dictionary<string, object> o)
            {
                Obs b = new Obs();
                b.Host = StoreUtil.Str(o, "Host"); b.Ip = StoreUtil.Str(o, "IP").ToLowerInvariant(); b.Port = StoreUtil.Str(o, "Port");
                b.Vh = StoreUtil.Str(o, "Vhost") == "True" ? "v" : "";
                b.Nk = b.Host.ToLowerInvariant() + "|" + b.Ip + "|" + b.Port + "|" + b.Vh;
                foreach (string f in InvSchema.Material) { string v = StoreUtil.Str(o, f); if (v.Length > 0) b.Mat[f] = v; }
                foreach (string f in InvSchema.Observed) { string v = StoreUtil.Str(o, f); if (v.Length > 0) b.Seen[f] = v; }
                b.Url = b.Mat["Url"];
                b.Incomplete = b.Seen["Notes"].IndexOf("incomplete:", StringComparison.OrdinalIgnoreCase) >= 0;
                return b;
            }
        }

        IngestSummary ApplyArchived(string rel, long seq, int retireAfter, string derivedDir, bool snapshot)
        {
            bool writeDerived = derivedDir != null;
            if (writeDerived) Directory.CreateDirectory(derivedDir);
            Stopwatch sw = Stopwatch.StartNew();
            string dir = AbsRun(rel);
            CheckInputs(dir);
            RunInfo run = RunInfo.Parse(File.ReadAllText(Path.Combine(dir, "run.json"), StoreUtil.Utf8));
            string at = StoreUtil.Iso(run.Started);
            HashSet<string> hostPort = new HashSet<string>(StringComparer.Ordinal), ipPort = new HashSet<string>(StringComparer.Ordinal);
            foreach (string l in StoreUtil.ReadLines(Path.Combine(dir, "checked.txt.gz")))
            {
                string[] p = l.Trim().Split('|');
                if (p.Length < 3) continue;
                hostPort.Add(p[0].ToLowerInvariant() + "|" + p[2]);
                ipPort.Add(p[1].ToLowerInvariant() + "|" + p[2]);
            }
            Rec rr = RunByRunId(run.RunId);
            if (rr != null && rr.Long("seq") != seq)
                throw new InvalidDataException("run " + run.RunId + " is seq " + rr["seq"] + " in the database but seq " + seq + " in the archive; rebuild the database: -RebuildStore");
            if (rr == null)
            {
                rr = new Rec();
                rr.SetLong("seq", seq); rr["runId"] = run.RunId; rr["state"] = "ingesting"; rr["startedAt"] = run.StartedAt; rr["finishedAt"] = run.FinishedAt;
                rr["tag"] = run.Tag; rr["scanner"] = run.Scanner; rr["complete"] = run.Complete ? "True" : "False"; rr["profile"] = run.Profile;
                rr["archive"] = rel; rr.SetLong("retireAfter", retireAfter); rr["kind"] = "run";
                kv.Begin(); Put(RunKey(seq), rr); kv.Put(RunIdKey(run.RunId), StoreUtil.B(seq.ToString(CultureInfo.InvariantCulture))); kv.Commit(false);
            }
            IngestSummary s = new IngestSummary();
            s.RunId = run.RunId; s.Seq = seq; s.Archive = rel; s.Profile = run.Profile;
            s.Lap("inputs");
            ApplyRows(Path.Combine(dir, "results.jsonl.gz"), run, seq, at, s);
            s.Lap("rows");
            ApplyAbsence(run, seq, at, retireAfter, hostPort, ipPort);
            s.Lap("absence");
            ApplyRekeys(run, seq, at);
            s.Lap("rekey");
            Fail("derived");
            // derived files and counts (deterministic: key order)
            using (DigestWriter cw = new DigestWriter(writeDerived ? Path.Combine(derivedDir, "changes.jsonl.gz") : null))
            {
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("c", StoreUtil.D10(seq))))
                {
                    Rec ev = Rec.Decode(e.Value);
                    switch (ev["type"])
                    {
                        case "merged": case "split": break;
                        case "added": s.Added++; break;
                        case "changed": s.Changed++; break;
                        case "enriched": s.Enriched++; break;
                        case "reappeared": s.Reappeared++; break;
                        case "rekeyed": s.Rekeyed++; break;
                        case "missing": s.Missing++; break;
                        case "retired": s.Retired++; break;
                    }
                    cw.Line(EventJson(ev));
                }
                s.ChangesDigest = cw.Close();
            }
            s.Lap("changes");
            using (DigestWriter stw = new DigestWriter(writeDerived && snapshot ? Path.Combine(derivedDir, "state.jsonl.gz") : null))
            {
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    switch (ent["st"]) { case "active": s.Active++; break; case "missing": s.MissingTotal++; break; default: s.RetiredTotal++; break; }
                    stw.Line(StateJson(InventoryRow(ent, Ver(ent["id"], ent.Long("ver")))));
                }
                s.StateDigest = stw.Close();
            }
            s.Lap("state");
            rr = Get(RunKey(seq));
            rr["state"] = "ingested"; rr["changesDigest"] = s.ChangesDigest; rr["stateDigest"] = s.StateDigest;
            rr.SetLong("rows", s.Rows); rr.SetLong("duplicates", s.Duplicates); rr.SetLong("incomplete", s.Incomplete);
            rr.SetLong("added", s.Added); rr.SetLong("changed", s.Changed); rr.SetLong("enriched", s.Enriched); rr.SetLong("reappeared", s.Reappeared); rr.SetLong("rekeyed", s.Rekeyed);
            rr.SetLong("missing", s.Missing); rr.SetLong("retired", s.Retired); rr.SetLong("active", s.Active); rr.SetLong("missingTotal", s.MissingTotal); rr.SetLong("retiredTotal", s.RetiredTotal);
            kv.Begin();
            Put(RunKey(seq), rr);
            Rec meta = Get(MetaKey) ?? new Rec();
            meta.SetLong("seq", seq); meta["runId"] = run.RunId; meta["stateDigest"] = s.StateDigest;
            Put(MetaKey, meta);
            kv.Commit(true);
            kv.Flush();
            s.Lap("commit");
            s.Seconds = sw.Elapsed.TotalSeconds;
            return s;
        }

        void CheckInputs(string dir)
        {
            string ip = Path.Combine(dir, "INPUTS.json");
            if (!File.Exists(ip)) throw new FileNotFoundException("archive folder has no INPUTS.json: " + dir);
            Dictionary<string, object> o = StoreJson.Parse(File.ReadAllText(ip, StoreUtil.Utf8)) as Dictionary<string, object>;
            System.Collections.IEnumerable files = StoreUtil.Field(o, "files") as System.Collections.IEnumerable;
            if (files == null) throw new InvalidDataException("INPUTS.json lists no files: " + dir);
            foreach (object f in files)
            {
                Dictionary<string, object> d = (Dictionary<string, object>)f;
                string name = StoreUtil.Str(d, "name"), path = Path.Combine(dir, name.Replace('/', Path.DirectorySeparatorChar));
                if (!File.Exists(path)) throw new FileNotFoundException("archived file missing: " + path);
                long bytes;
                if (StoreUtil.FileSha256(path, out bytes) != StoreUtil.Str(d, "sha256")) throw new InvalidDataException("archived file altered (SHA-256 mismatch): " + path);
            }
        }

        void ApplyRows(string results, RunInfo run, long seq, string at, IngestSummary s)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            int n = 0, batches = 0;
            kv.Begin();
            try
            {
                foreach (string line in StoreUtil.ReadLines(results))
                {
                    if (line.Length == 0) continue;
                    Obs ob = Obs.From((Dictionary<string, object>)StoreJson.Parse(line));
                    if (!seen.Add(ob.Nk)) { s.Duplicates++; continue; }
                    s.Rows++;
                    if (ob.Incomplete) s.Incomplete++;
                    Observe(ob, run, seq, at);
                    if (++n >= Batch) { kv.Commit(false); Fail("rows:" + (++batches).ToString(CultureInfo.InvariantCulture)); kv.Begin(); n = 0; }
                }
                kv.Commit(false);
            }
            catch { kv.Rollback(); throw; }
        }

        static string MakeId(string nk, string runId, int n)
        {
            return StoreUtil.Sha256Hex(nk + "\n" + runId + (n > 0 ? "\n" + n.ToString(CultureInfo.InvariantCulture) : "")).Substring(0, 16);
        }

        void Observe(Obs ob, RunInfo run, long seq, string at)
        {
            byte[] idb = kv.Get(NkKey(ob.Nk));
            if (idb == null) { AddEntity(ob, run, seq, at); return; }
            string eid = StoreUtil.S(idb);
            Rec ent = Get(EntKey(eid));
            if (ent == null) throw new InvalidDataException("key index points to a missing entity " + eid);
            if (ent.Long("ap") == seq) return;                  // applied before an interruption
            long curVer = ent.Long("ver");
            Rec cur = null;
            Rec mat = ob.Mat;
            if (run.NeedsCarryOver) { cur = Ver(eid, curVer); InvSchema.CarryOver(mat, cur, run); }
            string h = InvSchema.Hash(mat);
            bool absent = ent["st"] != "active";
            string type = null;
            List<string> diff = null;
            long to = curVer;
            if (!ob.Incomplete && h != ent["h"])
            {
                if (cur == null) cur = Ver(eid, curVer);
                diff = InvSchema.Diff(cur, mat);
                to = curVer + 1;
                PutVersion(eid, to, mat, seq, run, at, h);
                ent.SetLong("ver", to); ent["h"] = h; ent["ca"] = at;
                type = absent ? "reappeared" : (InvSchema.IsEnrichment(diff, cur, mat) ? "enriched" : "changed");
            }
            else if (absent) type = "reappeared";
            if (type != null)
            {
                Rec ev = NewEvent(type, seq, run, at, eid, ob.Host, ob.Ip, ob.Port, ob.Vh, ob.Url != "" ? ob.Url : (cur != null ? cur["Url"] : ""), curVer, to);
                if (diff != null) AddDiff(ev, diff, cur, mat);
                if (diff != null && cur["_prof"] != run.Profile) ev["pd"] = cur["_prof"] + " -> " + run.Profile;
                if (ob.Incomplete) ev["inc"] = "True";
                PutEvent(seq, eid, ev);
            }
            MarkSeen(ent, ob, run, seq, at);
            Put(EntKey(eid), ent);
        }

        void AddEntity(Obs ob, RunInfo run, long seq, string at)
        {
            string eid = null;
            for (int n = 0; n < 100; n++)
            {
                string c = MakeId(ob.Nk, run.RunId, n);
                Rec other = Get(EntKey(c));
                if (other == null || other["nk"] == ob.Nk) { eid = c; break; }
            }
            if (eid == null) throw new InvalidDataException("could not allocate an entity id for " + ob.Nk);
            string h = InvSchema.Hash(ob.Mat);
            PutVersion(eid, 1, ob.Mat, seq, run, at, h);
            Rec ent = new Rec();
            ent["id"] = eid; ent["nk"] = ob.Nk; ent["host"] = ob.Host; ent["ip"] = ob.Ip; ent["port"] = ob.Port; ent["vh"] = ob.Vh;
            ent["fa"] = at; ent["fr"] = run.RunId; ent.SetLong("ver", 1); ent["h"] = h; ent["ca"] = at;
            MarkSeen(ent, ob, run, seq, at);
            Put(EntKey(eid), ent);
            kv.Put(NkKey(ob.Nk), StoreUtil.B(eid));
            PutEvent(seq, eid, NewEvent("added", seq, run, at, eid, ob.Host, ob.Ip, ob.Port, ob.Vh, ob.Url, 0, 1));
        }

        static void MarkSeen(Rec ent, Obs ob, RunInfo run, long seq, string at)
        {
            ent["st"] = "active"; ent["la"] = at; ent["lr"] = run.RunId; ent.SetLong("ap", seq);
            ent.Remove("ms"); ent.Remove("mr"); ent.Remove("ra");
            ent.RemovePrefix("o:");
            foreach (string f in ob.Seen.Names) ent["o:" + f] = ob.Seen[f];
        }

        void PutVersion(string eid, long ver, Rec mat, long seq, RunInfo run, string at, string h)
        {
            Rec v = InvSchema.MaterialOf(mat);
            v.SetLong("_ver", ver); v.SetLong("_seq", seq); v["_run"] = run.RunId; v["_at"] = at; v["_h"] = h; v["_prof"] = run.Profile;
            Put(VerKey(eid, ver), v);
        }

        static Rec NewEvent(string type, long seq, RunInfo run, string at, string eid, string host, string ip, string port, string vh, string url, long from, long to)
        {
            Rec ev = new Rec();
            ev["type"] = type; ev.SetLong("seq", seq); ev["run"] = run.RunId; ev["at"] = at; ev["eid"] = eid;
            ev["host"] = host; ev["ip"] = ip; ev["port"] = port; ev["vh"] = vh; ev["url"] = url;
            ev.SetLong("from", from); ev.SetLong("to", to);
            return ev;
        }
        static void AddDiff(Rec ev, List<string> diff, Rec oldm, Rec newm)
        {
            if (diff.Count == 0) return;
            ev["fields"] = (ev["fields"].Length > 0 ? ev["fields"] + ";" : "") + string.Join(";", diff);
            foreach (string f in diff) { ev["was:" + f] = oldm == null ? "" : oldm[f]; ev["now:" + f] = newm[f]; }
        }
        void PutEvent(long seq, string eid, Rec ev)
        {
            Put(EvKey(seq, eid), ev);
            kv.Put(XKey(eid, seq), StoreUtil.B(ev["type"]));
        }

        // services the run checked (host|port, or for SAN virtual hosts the ip|port they were found on) but did not see
        void ApplyAbsence(RunInfo run, long seq, string at, int retireAfter, HashSet<string> hostPort, HashSet<string> ipPort)
        {
            int n = 0;
            kv.Begin();
            try
            {
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    string st = ent["st"];
                    if (st == "retired" || ent.Long("ap") == seq) continue;
                    bool inScope = ent["vh"] == "v"
                        ? run.ProbeSans && ipPort.Contains(ent["ip"] + "|" + ent["port"])
                        : hostPort.Contains(ent["host"].ToLowerInvariant() + "|" + ent["port"]);
                    if (!inScope) continue;
                    long mr = ent.Long("mr") + 1;
                    ent.SetLong("mr", mr); ent.SetLong("ap", seq);
                    string type = null;
                    if (st == "active") ent["ms"] = at;
                    if (mr >= retireAfter) { ent["st"] = "retired"; ent["ra"] = at; type = "retired"; }
                    else if (st == "active") { ent["st"] = "missing"; type = "missing"; }
                    Put(EntKey(ent["id"]), ent);
                    if (type != null)
                    {
                        long ver = ent.Long("ver");
                        PutEvent(seq, ent["id"], NewEvent(type, seq, run, at, ent["id"], ent["host"], ent["ip"], ent["port"], ent["vh"], Ver(ent["id"], ver)["Url"], ver, ver));
                    }
                    if (++n >= Batch) { kv.Commit(false); kv.Begin(); n = 0; }
                }
                kv.Commit(false);
                Fail("absence");
            }
            catch { kv.Rollback(); throw; }
        }

        // An address change shows up as one service gone and one added in the same run. Pair them only when unambiguous:
        //   R1 same DNS name and port (scanned by name, the address moved)
        //   R2 scanned by address: same reverse-DNS name and port
        //   R3 scanned by address: same certificate (SHA-256), port, title, server and products
        // A signature must be held by exactly one added and one gone service, and by no other service seen in this run.
        sealed class Cand { public string Eid; public Rec Ent, Mat; }
        string Sig(int rule, Cand c)
        {
            string host = c.Ent["host"], port = c.Ent["port"], vh = c.Ent["vh"];
            bool byIp = StoreUtil.IsIp(host);
            switch (rule)
            {
                case 1: return byIp ? null : "1|" + host.ToLowerInvariant() + "|" + port + "|" + vh;
                case 2: return (!byIp || vh != "" || c.Mat["ReverseDns"].Length == 0) ? null : "2|" + c.Mat["ReverseDns"].ToLowerInvariant() + "|" + port;
                default:
                    return (!byIp || vh != "" || c.Mat["CertSha256"].Length == 0) ? null
                        : "3|" + c.Mat["CertSha256"] + "|" + port + "|" + c.Mat["Title"] + "|" + c.Mat["Server"] + "|" + c.Mat["Products"];
            }
        }

        void ApplyRekeys(RunInfo run, long seq, string at)
        {
            // event types come from the per-entity index (no record decoding); candidates are loaded only when both sides exist
            List<string> addedIds = new List<string>(), goneIds = new List<string>();
            string sq = StoreUtil.D10(seq);
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("c", sq)))
            {
                string k = StoreUtil.S(e.Key), eid = k.Substring(k.LastIndexOf('\0') + 1);
                byte[] tb = kv.Get(XKey(eid, seq));
                string t = tb == null ? "" : StoreUtil.S(tb);
                if (t == "added") addedIds.Add(eid); else if (t == "missing" || t == "retired") goneIds.Add(eid);
            }
            if (addedIds.Count == 0 || goneIds.Count == 0) return;
            List<Cand> added = new List<Cand>(), gone = new List<Cand>();
            foreach (string id in addedIds) { Cand c = new Cand(); c.Eid = id; c.Ent = Get(EntKey(id)); c.Mat = Ver(id, c.Ent.Long("ver")); added.Add(c); }
            foreach (string id in goneIds) { Cand c = new Cand(); c.Eid = id; c.Ent = Get(EntKey(id)); c.Mat = Ver(id, c.Ent.Long("ver")); gone.Add(c); }
            HashSet<string> used = new HashSet<string>(StringComparer.Ordinal);
            for (int rule = 1; rule <= 3; rule++)
            {
                Dictionary<string, List<Cand>> A = Group(rule, added, used), G = Group(rule, gone, used);
                List<string> sigs = new List<string>();
                foreach (string k in A.Keys) if (A[k].Count == 1 && G.ContainsKey(k) && G[k].Count == 1) sigs.Add(k);
                if (sigs.Count == 0) continue;
                // no other service seen in this run may share the signature
                HashSet<string> want = new HashSet<string>(sigs, StringComparer.Ordinal), clash = new HashSet<string>(StringComparer.Ordinal);
                HashSet<string> addedSet = new HashSet<string>(addedIds, StringComparer.Ordinal);
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    if (ent["st"] != "active" || ent.Long("ap") != seq || addedSet.Contains(ent["id"])) continue;
                    Cand c = new Cand(); c.Eid = ent["id"]; c.Ent = ent;
                    c.Mat = rule == 1 ? new Rec() : Ver(c.Eid, ent.Long("ver"));
                    string sg = Sig(rule, c);
                    if (sg != null && want.Contains(sg)) clash.Add(sg);
                }
                sigs.Sort(StringComparer.Ordinal);
                foreach (string k in sigs)
                {
                    if (clash.Contains(k)) continue;
                    Merge(G[k][0], A[k][0], rule, run, seq, at);
                    used.Add(G[k][0].Eid); used.Add(A[k][0].Eid);
                }
            }
        }
        Dictionary<string, List<Cand>> Group(int rule, List<Cand> list, HashSet<string> used)
        {
            Dictionary<string, List<Cand>> d = new Dictionary<string, List<Cand>>(StringComparer.Ordinal);
            foreach (Cand c in list)
            {
                if (used.Contains(c.Eid)) continue;
                string s = Sig(rule, c);
                if (s == null) continue;
                List<Cand> l;
                if (!d.TryGetValue(s, out l)) { l = new List<Cand>(); d[s] = l; }
                l.Add(c);
            }
            return d;
        }

        void Merge(Cand g, Cand a, int rule, RunInfo run, long seq, string at)
        {
            kv.Begin();
            try
            {
                Rec gEnt = Get(EntKey(g.Eid)), aEnt = Get(EntKey(a.Eid));
                Rec gCur = Ver(g.Eid, gEnt.Long("ver"));
                string pla = gEnt["la"], plr = gEnt["lr"];
                Rec mat = InvSchema.MaterialOf(Ver(a.Eid, 1));
                if (run.NeedsCarryOver) InvSchema.CarryOver(mat, gCur, run);
                string h = InvSchema.Hash(mat);
                long from = gEnt.Long("ver"), to = from;
                List<string> diff = InvSchema.Diff(gCur, mat);
                if (h != gEnt["h"]) { to = from + 1; PutVersion(g.Eid, to, mat, seq, run, at, h); gEnt.SetLong("ver", to); gEnt["h"] = h; gEnt["ca"] = at; }
                string oldNk = gEnt["nk"], oldHost = gEnt["host"], oldIp = gEnt["ip"];
                kv.Delete(NkKey(oldNk));
                kv.Put(NkKey(aEnt["nk"]), StoreUtil.B(g.Eid));
                gEnt["nk"] = aEnt["nk"]; gEnt["host"] = aEnt["host"]; gEnt["ip"] = aEnt["ip"]; gEnt["port"] = aEnt["port"]; gEnt["vh"] = aEnt["vh"];
                gEnt["st"] = "active"; gEnt["la"] = at; gEnt["lr"] = run.RunId; gEnt.SetLong("ap", seq);
                gEnt.Remove("ms"); gEnt.Remove("mr"); gEnt.Remove("ra");
                gEnt.RemovePrefix("o:");
                foreach (string f in aEnt.Names.ToArray()) if (f.StartsWith("o:", StringComparison.Ordinal)) gEnt[f] = aEnt[f];
                Put(EntKey(g.Eid), gEnt);
                // the added service never existed separately
                kv.Delete(EntKey(a.Eid)); kv.Delete(VerKey(a.Eid, 1)); kv.Delete(EvKey(seq, a.Eid)); kv.Delete(XKey(a.Eid, seq));
                Rec ev = NewEvent("rekeyed", seq, run, at, g.Eid, gEnt["host"], gEnt["ip"], gEnt["port"], gEnt["vh"], mat["Url"], from, to);
                ev["rule"] = rule == 1 ? "same-name" : (rule == 2 ? "same-reverse-dns" : "same-certificate");
                ev["okey"] = oldNk; ev["pla"] = pla; ev["plr"] = plr;
                List<string> keyDiff = new List<string>();
                Rec was = new Rec(), now = new Rec();
                if (oldHost != gEnt["host"]) { keyDiff.Add("Host"); was["Host"] = oldHost; now["Host"] = gEnt["host"]; }
                if (oldIp != gEnt["ip"]) { keyDiff.Add("IP"); was["IP"] = oldIp; now["IP"] = gEnt["ip"]; }
                AddDiff(ev, keyDiff, was, now);
                AddDiff(ev, diff, gCur, mat);
                if (diff.Count > 0 && gCur["_prof"] != run.Profile) ev["pd"] = gCur["_prof"] + " -> " + run.Profile;
                PutEvent(seq, g.Eid, ev);
                kv.Commit(false);
            }
            catch { kv.Rollback(); throw; }
        }

        // ---------------------------------------------------------------- rows, JSON
        static readonly string[] Lifecycle = { "FirstSeen", "LastSeen", "LastChange", "Versions", "MissingSince", "MissingRuns", "RetiredAt", "FirstRun", "LastRun", "EntityId" };
        public static readonly string[] InventoryColumns = Concat(new[] { "Status", "Host", "IP", "Port", "Vhost" }, InvSchema.Material, Lifecycle, InvSchema.Observed);
        public static readonly string[] ChangeColumns = { "At", "RunId", "Change", "Host", "IP", "Port", "Vhost", "Url", "Field", "Old", "New", "Rule", "OldKey", "ProfileChange", "EntityId", "Status", "Note" };
        public static readonly string[] RunColumns = { "Seq", "RunId", "StartedAt", "FinishedAt", "Tag", "Scanner", "Complete", "Rows", "Added", "Changed", "Enriched", "Reappeared", "Rekeyed",
            "Missing", "Retired", "Active", "MissingTotal", "RetiredTotal", "Incomplete", "Duplicates", "RetireAfter", "Profile", "Archive", "StateDigest" };
        static string[] Concat(params string[][] a) { List<string> l = new List<string>(); foreach (string[] x in a) l.AddRange(x); return l.ToArray(); }
        static string Cap(string s) { return s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s.Substring(1); }

        static Dictionary<string, string> InventoryRow(Rec ent, Rec ver)
        {
            Dictionary<string, string> r = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            r["Status"] = Cap(ent["st"]); r["Host"] = ent["host"]; r["IP"] = ent["ip"]; r["Port"] = ent["port"]; r["Vhost"] = ent["vh"] == "v" ? "True" : "False";
            foreach (string f in InvSchema.Material) r[f] = ver[f];
            r["FirstSeen"] = ent["fa"]; r["LastSeen"] = ent["la"]; r["LastChange"] = ent["ca"]; r["Versions"] = ent["ver"];
            r["MissingSince"] = ent["ms"]; r["MissingRuns"] = ent["mr"]; r["RetiredAt"] = ent["ra"]; r["FirstRun"] = ent["fr"]; r["LastRun"] = ent["lr"]; r["EntityId"] = ent["id"];
            foreach (string f in InvSchema.Observed) r[f] = ent["o:" + f];
            return r;
        }
        static string StateJson(Dictionary<string, string> row)
        {
            JsonObj j = new JsonObj();
            foreach (string c in InventoryColumns) { string v; if (row.TryGetValue(c, out v) && !string.IsNullOrEmpty(v)) j.Str(c, v); }
            return j.ToString();
        }
        static string EventJson(Rec ev)
        {
            JsonObj j = new JsonObj().Str("run", ev["run"]).Num("seq", ev.Long("seq")).Str("at", ev["at"]).Str("change", ev["type"]).Str("entity", ev["eid"])
                .Str("host", ev["host"]).Str("ip", ev["ip"]).Str("port", ev["port"]).Bool("vhost", ev["vh"] == "v").StrIf("url", ev["url"])
                .Num("fromVersion", ev.Long("from")).Num("toVersion", ev.Long("to")).StrIf("rule", ev["rule"]).StrIf("oldKey", ev["okey"]).StrIf("profileChange", ev["pd"]).StrIf("note", ev["note"]);
            if (ev["inc"] == "True") j.Bool("incompleteObservation", true);
            if (ev["fields"].Length > 0)
            {
                List<string> fs = new List<string>();
                foreach (string f in ev["fields"].Split(';')) fs.Add(new JsonObj().Str("field", f).Str("old", ev["was:" + f]).Str("new", ev["now:" + f]).ToString());
                j.Raw("fields", "[" + string.Join(",", fs) + "]");
            }
            return j.ToString();
        }

        // ---------------------------------------------------------------- queries
        public QueryResult Query(string kind, string[] filters, string[] statuses, string[] changeTypes, string since, string until, string asOf)
        {
            if (kv == null) throw new InvalidOperationException("store database not open");
            DateTimeOffset? from = OptTime(since, "Since"), to = OptTime(until, "Until"), asof = OptTime(asOf, "AsOf");
            HashSet<string> st = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (statuses != null) foreach (string s in statuses) if (!string.IsNullOrEmpty(s)) st.Add(s);
            if (st.Count == 0) { st.Add("Active"); st.Add("Missing"); }
            bool allStatus = st.Contains("All");
            HashSet<string> ct = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (changeTypes != null) foreach (string c in changeTypes) if (!string.IsNullOrEmpty(c)) ct.Add(c);
            DateTimeOffset now = asof ?? DateTimeOffset.Now;
            switch ((kind ?? "").ToLowerInvariant())
            {
                case "inventory": return Inventory(RowFilter.Parse(filters, InventoryColumns), st, allStatus, from, to, asof, now);
                case "changes": return Changes(filters, ct, from, to, null);
                case "history":
                    {
                        // History: every event of the services matching -Filter/-Status (any status by default), by host and port
                        List<RowFilter> fl = RowFilter.Parse(filters, InventoryColumns);
                        bool anyStatus = allStatus || statuses == null || statuses.Length == 0;
                        List<string[]> hit = new List<string[]>();
                        foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                        {
                            Rec ent = Rec.Decode(e.Value);
                            Dictionary<string, string> row = InventoryRow(ent, Ver(ent["id"], ent.Long("ver")));
                            row["CertDaysLeft"] = DaysLeft(row["CertNotAfter"], now);
                            if ((anyStatus || st.Contains(row["Status"])) && RowFilter.All(fl, row)) hit.Add(new[] { ent["host"], ent["port"], ent["id"] });
                        }
                        hit.Sort(delegate(string[] a, string[] b)
                        {
                            int c = string.Compare(a[0], b[0], StringComparison.OrdinalIgnoreCase);
                            if (c == 0) c = PortNum(a[1]).CompareTo(PortNum(b[1]));
                            return c != 0 ? c : string.CompareOrdinal(a[2], b[2]);
                        });
                        List<string> ids = new List<string>();
                        foreach (string[] h in hit) ids.Add(h[2]);
                        return Changes(null, ct, from, to, ids);
                    }
                case "runs": return Runs(RowFilter.Parse(filters, RunColumns), from, to);
            }
            throw new ArgumentException("unknown query '" + kind + "' (Inventory, Changes, History, Runs, Vulnerabilities)");
        }

        // -StoreQuery Vulnerabilities: current inventory (Active and Missing by default) joined offline with NVD/KEV/EPSS files
        public VulnResult Vulnerabilities(string[] nvd, string kev, string epss, string[] filters, string[] statuses)
        {
            if (kv == null) throw new InvalidOperationException("store database not open");
            HashSet<string> st = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (statuses != null) foreach (string x in statuses) if (!string.IsNullOrEmpty(x)) st.Add(x);
            if (st.Count == 0) { st.Add("Active"); st.Add("Missing"); }
            bool all = st.Contains("All");
            List<RowFilter> fl = RowFilter.Parse(filters, Vulns.Columns);
            List<Vulns.Service> svcs = new List<Vulns.Service>();
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
            {
                Rec ent = Rec.Decode(e.Value);
                if (!all && !st.Contains(Cap(ent["st"]))) continue;
                Rec ver = Ver(ent["id"], ent.Long("ver"));
                string cpes = ver["CPEs"];
                if (cpes.Length == 0) continue;
                Vulns.Service s = new Vulns.Service();
                s.Host = ent["host"]; s.Ip = ent["ip"]; s.Port = ent["port"]; s.Url = ver["Url"]; s.Status = Cap(ent["st"]); s.Products = ver["Products"]; s.EntityId = ent["id"];
                foreach (string c in cpes.Split(';')) { Cpe x = Cpe.Parse(c); if (x != null) s.Cpes.Add(x); }
                if (s.Cpes.Count > 0) svcs.Add(s);
            }
            Rec meta = Get(MetaKey) ?? new Rec();
            VulnResult r = Vulns.Run(svcs, nvd, kev, epss, fl, StoreId, meta["runId"]);
            foreach (string m in r.Messages) Messages.Add(m);
            return r;
        }

        static DateTimeOffset? OptTime(string s, string name)
        {
            if (string.IsNullOrEmpty(s)) return null;
            DateTimeOffset t;
            if (!StoreUtil.TryIso(s, out t)) throw new ArgumentException("-" + name + " is not a date/time: '" + s + "'");
            return t;
        }
        static bool InWindow(string at, DateTimeOffset? from, DateTimeOffset? to)
        {
            if (from == null && to == null) return true;
            DateTimeOffset t;
            if (!StoreUtil.TryIso(at, out t)) return false;
            return (from == null || t >= from.Value) && (to == null || t <= to.Value);
        }
        static string DaysLeft(string notAfter, DateTimeOffset reference)
        {
            DateTime na;
            if (string.IsNullOrEmpty(notAfter) || !DateTime.TryParse(notAfter, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out na)) return "";
            return ((long)Math.Floor((new DateTimeOffset(na) - reference).TotalDays)).ToString(CultureInfo.InvariantCulture);
        }
        static int PortNum(string p) { int n; return int.TryParse(p, NumberStyles.Integer, CultureInfo.InvariantCulture, out n) ? n : 0; }
        static string[] Project(string[] cols, Dictionary<string, string> row)
        {
            string[] a = new string[cols.Length];
            for (int i = 0; i < cols.Length; i++) { string v; a[i] = row.TryGetValue(cols[i], out v) ? (v ?? "") : ""; }
            return a;
        }

        QueryResult Inventory(List<RowFilter> fl, HashSet<string> st, bool allStatus, DateTimeOffset? from, DateTimeOffset? to, DateTimeOffset? asof, DateTimeOffset now)
        {
            QueryResult q = new QueryResult(); q.Columns = InventoryColumns;
            List<Dictionary<string, string>> rows = new List<Dictionary<string, string>>();
            Func<Dictionary<string, string>, bool> keep = delegate(Dictionary<string, string> row)
            {
                if (!allStatus && !st.Contains(row["Status"])) return false;
                if (!InWindow(row["LastSeen"], from, to)) return false;
                row["CertDaysLeft"] = DaysLeft(row["CertNotAfter"], now);
                return RowFilter.All(fl, row);
            };
            if (asof != null)
            {
                // the inventory as it stood after the last run that started at or before -AsOf: its archived state file,
                // or (snapshot thinned out by -SnapshotEvery) the history replayed in memory up to that run
                foreach (Dictionary<string, string> row in AsOfRows(asof.Value)) if (keep(row)) q.Rows.Add(Project(q.Columns, row));
            }
            else
            {
                // rows are filtered as they are read: only matching rows are kept in memory
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    if (!allStatus && !st.Contains(Cap(ent["st"]))) continue;
                    Dictionary<string, string> row = InventoryRow(ent, Ver(ent["id"], ent.Long("ver")));
                    if (keep(row)) q.Rows.Add(Project(q.Columns, row));
                }
            }
            int hi = Array.IndexOf(q.Columns, "Host"), pi = Array.IndexOf(q.Columns, "Port"), ii = Array.IndexOf(q.Columns, "IP"), vi = Array.IndexOf(q.Columns, "Vhost");
            q.Rows.Sort(delegate(string[] a, string[] b)
            {
                int c = string.Compare(a[hi], b[hi], StringComparison.OrdinalIgnoreCase); if (c != 0) return c;
                c = PortNum(a[pi]).CompareTo(PortNum(b[pi])); if (c != 0) return c;
                c = string.CompareOrdinal(a[ii], b[ii]); if (c != 0) return c;
                return string.CompareOrdinal(a[vi], b[vi]);
            });
            return q;
        }

        QueryResult Changes(string[] filters, HashSet<string> ct, DateTimeOffset? from, DateTimeOffset? to, List<string> onlyIds)
        {
            QueryResult q = new QueryResult(); q.Columns = ChangeColumns;
            List<string> known = new List<string>(ChangeColumns); known.AddRange(InventoryColumns);
            List<RowFilter> fl = RowFilter.Parse(filters, known);
            Dictionary<string, Dictionary<string, string>> entCache = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
            List<long> seqs = new List<long>();
            foreach (KeyValuePair<byte[], byte[]> r in kv.Scan(P("r")))
            {
                Rec rr = Rec.Decode(r.Value);
                if (rr["state"] == "ingested" && InWindow(rr["startedAt"], from, to)) seqs.Add(rr.Long("seq"));
            }
            List<KeyValuePair<string, Rec>> evs = new List<KeyValuePair<string, Rec>>();
            if (onlyIds != null)
            {
                HashSet<long> ok = new HashSet<long>(seqs);
                foreach (string id in onlyIds)
                    foreach (KeyValuePair<byte[], byte[]> x in kv.Scan(P("x", id)))
                    {
                        string k = StoreUtil.S(x.Key);
                        long sq = long.Parse(k.Substring(k.LastIndexOf('\0') + 1), CultureInfo.InvariantCulture);
                        if (!ok.Contains(sq)) continue;
                        Rec ev = Get(EvKey(sq, id));
                        if (ev != null) evs.Add(new KeyValuePair<string, Rec>(id, ev));
                    }
            }
            else
                foreach (long sq in seqs)
                    foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("c", StoreUtil.D10(sq))))
                    {
                        Rec ev = Rec.Decode(e.Value);
                        evs.Add(new KeyValuePair<string, Rec>(ev["eid"], ev));
                    }
            // Changes: runs in order, within a run by host and port (History keeps its per-service order)
            if (onlyIds == null)
                evs.Sort(delegate(KeyValuePair<string, Rec> a, KeyValuePair<string, Rec> b)
                {
                    int c = a.Value.Long("seq").CompareTo(b.Value.Long("seq"));
                    if (c == 0) c = string.Compare(a.Value["host"], b.Value["host"], StringComparison.OrdinalIgnoreCase);
                    if (c == 0) c = PortNum(a.Value["port"]).CompareTo(PortNum(b.Value["port"]));
                    return c != 0 ? c : string.CompareOrdinal(a.Key, b.Key);
                });
            foreach (KeyValuePair<string, Rec> pe in evs)
            {
                Rec ev = pe.Value;
                if (ct.Count > 0 && !ct.Contains(ev["type"])) continue;
                Dictionary<string, string> er;
                if (!entCache.TryGetValue(pe.Key, out er))
                {
                    Rec ent = Get(EntKey(pe.Key));
                    er = ent == null ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) : InventoryRow(ent, Ver(pe.Key, ent.Long("ver")));
                    entCache[pe.Key] = er;
                }
                string[] fields = ev["fields"].Length > 0 ? ev["fields"].Split(';') : new[] { "" };
                foreach (string f in fields)
                {
                    Dictionary<string, string> row = new Dictionary<string, string>(er, StringComparer.OrdinalIgnoreCase);
                    row["At"] = ev["at"]; row["RunId"] = ev["run"]; row["Change"] = Cap(ev["type"]); row["Host"] = ev["host"]; row["IP"] = ev["ip"]; row["Port"] = ev["port"];
                    row["Vhost"] = ev["vh"] == "v" ? "True" : "False"; row["Url"] = ev["url"]; row["Field"] = f;
                    row["Old"] = f.Length > 0 ? ev["was:" + f] : ""; row["New"] = f.Length > 0 ? ev["now:" + f] : "";
                    row["Rule"] = ev["rule"]; row["OldKey"] = ev["okey"]; row["ProfileChange"] = ev["pd"]; row["EntityId"] = pe.Key; row["Note"] = ev["note"];
                    string sv; row["Status"] = er.TryGetValue("Status", out sv) ? sv : "";
                    if (!RowFilter.All(fl, row)) continue;
                    q.Rows.Add(Project(q.Columns, row));
                }
            }
            return q;
        }

        QueryResult Runs(List<RowFilter> fl, DateTimeOffset? from, DateTimeOffset? to)
        {
            QueryResult q = new QueryResult(); q.Columns = RunColumns;
            foreach (KeyValuePair<byte[], byte[]> r in kv.Scan(P("r")))
            {
                Rec rr = Rec.Decode(r.Value);
                if (!InWindow(rr["startedAt"], from, to)) continue;
                Dictionary<string, string> row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                row["Seq"] = rr["seq"]; row["RunId"] = rr["runId"]; row["StartedAt"] = rr["startedAt"]; row["FinishedAt"] = rr["finishedAt"]; row["Tag"] = rr["tag"];
                row["Scanner"] = rr["scanner"]; row["Complete"] = rr["complete"]; row["Profile"] = rr["profile"]; row["Archive"] = rr["archive"]; row["StateDigest"] = rr["stateDigest"];
                row["RetireAfter"] = rr["retireAfter"];
                foreach (string c in new[] { "rows", "added", "changed", "enriched", "reappeared", "rekeyed", "missing", "retired", "active", "missingTotal", "retiredTotal", "incomplete", "duplicates" })
                    row[Cap(c)] = rr[c];
                if (rr["state"] != "ingested") row["Complete"] = "ingesting";
                if (!RowFilter.All(fl, row)) continue;
                q.Rows.Add(Project(q.Columns, row));
            }
            return q;
        }

        // ---------------------------------------------------------------- statistics, verification, rebuild
        public Dictionary<string, string> Stats()
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            d["Root"] = Root; d["StoreId"] = StoreId; d["Engine"] = Engine; d["RetireAfter"] = RetireAfter.ToString(CultureInfo.InvariantCulture);
            if (kv == null) return d;
            long a = 0, m = 0, r = 0, runs = 0;
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e"))) { string s = Rec.Decode(e.Value)["st"]; if (s == "active") a++; else if (s == "missing") m++; else r++; }
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("r"))) runs++;
            Rec meta = Get(MetaKey) ?? new Rec();
            d["Active"] = a.ToString(CultureInfo.InvariantCulture); d["Missing"] = m.ToString(CultureInfo.InvariantCulture); d["Retired"] = r.ToString(CultureInfo.InvariantCulture);
            d["Runs"] = runs.ToString(CultureInfo.InvariantCulture); d["LastRun"] = meta["runId"]; d["LedgerHead"] = LedgerHead();
            return d;
        }

        string LiveStateDigest()
        {
            using (DigestWriter w = new DigestWriter(null))
            {
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    w.Line(StateJson(InventoryRow(ent, Ver(ent["id"], ent.Long("ver")))));
                }
                return w.Close();
            }
        }

        // Verify: see invstore2.cs

        public void Rebuild(string engine)
        {
            string req = (engine ?? "auto").Trim().ToLowerInvariant();
            string target = (req == "" || req == "auto") ? ((Engine == "esent" && !EsentKv.Available) ? "file" : (Engine.Length > 0 ? Engine : ResolveEngine("auto"))) : ResolveEngine(req);
            if (kv != null) { kv.Dispose(); kv = null; }
            string prev = DbDir + ".previous";
            if (Directory.Exists(prev)) Directory.Delete(prev, true);
            if (Directory.Exists(DbDir)) Directory.Move(DbDir, prev);
            string was = Engine;
            Engine = target;
            Log("rebuilding the " + target + " database from the archive (previous database kept in db.previous)");
            Stopwatch sw = Stopwatch.StartNew();
            kv = OpenEngine();
            Reconcile();
            SaveStoreJson();
            Log(string.Format(CultureInfo.InvariantCulture, "rebuild complete in {0:0.0}s{1}", sw.Elapsed.TotalSeconds, was != target ? " (engine " + was + " -> " + target + ")" : ""));
        }

        public void Dispose()
        {
            if (kv != null) { try { kv.Dispose(); } catch (Exception) { } kv = null; }
            if (lockFs != null) { try { lockFs.Dispose(); } catch (Exception) { } lockFs = null; }
        }
    }
}

// ============================================================================
// WebInv inventory store, part 2: the applied plan (runs, corrections, rebases), manual merge/split, backfill,
// snapshot thinning, -AsOf replay and verification. Everything here is a deterministic function of the archive:
// a correction is a ledger entry applied at its position, a backfill appends a "rebase" entry with the new order -
// nothing already written is ever rewritten.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Text;

    public sealed class PlanItem
    {
        public LedgerEntry E;
        public long Pos;
        public string ChangesDigest = "", StateDigest = "", Void = "", Derived = "";
        public bool Snapshot = true;
        public bool IsRun { get { return E.Type == "run"; } }
    }

    public sealed partial class InventoryStore
    {
        public int SnapshotEvery = 1;
        public bool AnchorEventLog;
        public string AnchorCertificate = "";
        public long AnchorFrom;
        // ledger lines appended by this process: { seq, sha256 of the line, line } (for event-log / signature anchors)
        public readonly List<string[]> Appended = new List<string[]>();

        static string D6(long n) { return n.ToString("D6", CultureInfo.InvariantCulture); }

        // ---------------------------------------------------------------- plan
        public List<PlanItem> BuildPlan(List<LedgerEntry> led)
        {
            List<PlanItem> plan = new List<PlanItem>();
            Dictionary<long, LedgerEntry> bySeq = new Dictionary<long, LedgerEntry>();
            foreach (LedgerEntry e in led)
            {
                bySeq[e.Seq] = e;
                if (e.Type == "run" || e.Type == "correction")
                {
                    PlanItem it = new PlanItem();
                    it.E = e; it.Pos = plan.Count + 1; it.ChangesDigest = e.ChangesDigest; it.StateDigest = e.StateDigest; it.Snapshot = e.Snapshot && e.Type == "run";
                    it.Void = StoreUtil.Str(e.Obj, "void"); it.Derived = AbsRun(e.Path);
                    plan.Add(it);
                }
                else if (e.Type == "rebase")
                {
                    plan = new List<PlanItem>();
                    List<object> items = StoreUtil.Field(e.Obj, "plan") as List<object>;
                    if (items == null) throw new InvalidDataException("rebase entry seq " + e.Seq + " has no plan");
                    foreach (object o in items)
                    {
                        Dictionary<string, object> d = (Dictionary<string, object>)o;
                        long s = StoreUtil.Num(d, "seq");
                        LedgerEntry src;
                        if (!bySeq.TryGetValue(s, out src)) throw new InvalidDataException("rebase entry seq " + e.Seq + " names unknown ledger seq " + s);
                        PlanItem it = new PlanItem();
                        it.E = src; it.Pos = plan.Count + 1; it.ChangesDigest = StoreUtil.Str(d, "changesDigest"); it.StateDigest = StoreUtil.Str(d, "stateDigest");
                        it.Snapshot = StoreUtil.Str(d, "snapshot") != "False" && src.Type == "run"; it.Void = StoreUtil.Str(d, "void");
                        it.Derived = AbsRun(e.Path + "/" + D6(it.Pos));
                        plan.Add(it);
                    }
                }
            }
            return plan;
        }
        static string LastRebase(List<LedgerEntry> led)
        {
            string r = "";
            foreach (LedgerEntry e in led) if (e.Type == "rebase") r = e.Seq.ToString(CultureInfo.InvariantCulture);
            return r;
        }
        static bool PendingBackfill(List<LedgerEntry> led)
        {
            bool pending = false;
            foreach (LedgerEntry e in led) { if (e.Type == "rebase") pending = false; else if (e.Type == "run" && e.Backfill) pending = true; }
            return pending;
        }
        // first run, then every SnapshotEvery-th run keeps its full state file
        bool SnapshotFor(List<PlanItem> planBefore, bool isRun)
        {
            if (!isRun) return false;
            if (SnapshotEvery <= 1) return true;
            int runs = 1;
            foreach (PlanItem it in planBefore) if (it.IsRun) runs++;
            return runs % SnapshotEvery == 1;
        }
        int RetireOf(LedgerEntry e) { return e.RetireAfter > 0 ? e.RetireAfter : RetireAfter; }

        IngestSummary ApplyItem(PlanItem it, string derivedDir)
        {
            if (it.IsRun) return ApplyArchived(it.E.Path, it.Pos, RetireOf(it.E), derivedDir, it.Snapshot);
            return ApplyCorrection(it.E.Path, it.Pos, derivedDir, false);
        }

        void ResetDb()
        {
            if (kv != null) { kv.Dispose(); kv = null; }
            string prev = DbDir + ".previous";
            if (Directory.Exists(prev)) Directory.Delete(prev, true);
            if (Directory.Exists(DbDir)) Directory.Move(DbDir, prev);
            kv = OpenEngine();
        }

        InventoryStore NewShadow()
        {
            InventoryStore sh = new InventoryStore(Root);
            sh.shadow = true; sh.kv = new FileKv(null); sh.Engine = "memory"; sh.StoreId = StoreId; sh.RetireAfter = RetireAfter; sh.SnapshotEvery = SnapshotEvery;
            return sh;
        }

        // ---------------------------------------------------------------- bring the database up to the archive
        void Reconcile()
        {
            List<LedgerEntry> led = ReadLedgerStrict();
            if (PendingBackfill(led)) { Log("finishing an interrupted backfill: replaying the history in run order"); Rebase(led, "backfill (finished after an interruption)"); led = ReadLedgerStrict(); }
            List<PlanItem> plan = BuildPlan(led);
            string rb = LastRebase(led);
            Rec meta = Get(MetaKey) ?? new Rec();
            if (meta.Long("seq") > 0 && meta["rebase"] != rb)
            {
                Log("the ledger holds a newer replay order (rebase seq " + rb + "); rebuilding the working database");
                ResetDb(); meta = new Rec();
            }
            long dbSeq = meta.Long("seq");
            HashSet<string> ledgered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (LedgerEntry e in led) if (e.Type == "run" || e.Type == "correction") ledgered.Add(e.Path);
            foreach (PlanItem it in plan)
            {
                if (it.Pos <= dbSeq) continue;
                if (it.IsRun)
                {
                    Rec rr = RunByRunId(it.E.RunId);
                    if (rr != null && rr["state"] == "ingested" && rr.Long("seq") == it.Pos && rr["stateDigest"] == it.StateDigest)
                    {
                        kv.Begin(); meta["runId"] = it.E.RunId; meta.SetLong("seq", it.Pos); meta["stateDigest"] = it.StateDigest; meta["rebase"] = rb; Put(MetaKey, meta); kv.Commit(true); kv.Flush();
                        continue;
                    }
                }
                Log("database is behind the archive: applying " + (it.IsRun ? "run " + it.E.RunId : it.E.RunId) + " (position " + it.Pos + ") from archive\\" + it.E.Path.Replace('/', '\\'));
                IngestSummary s = ApplyItem(it, null);
                if (s.StateDigest != it.StateDigest || s.ChangesDigest != it.ChangesDigest)
                    throw new InvalidDataException("re-applying " + it.E.RunId + " from the archive does not reproduce the digests in the ledger (state " + s.StateDigest + " vs " + it.StateDigest + "); the archive or the database has been altered - run -VerifyStore");
                meta = Get(MetaKey) ?? new Rec();
            }
            if (meta["rebase"] != rb) { kv.Begin(); meta["rebase"] = rb; Put(MetaKey, meta); kv.Commit(true); kv.Flush(); }
            // runs archived but not yet in the ledger (an earlier ingest stopped part-way): finish them
            foreach (string rel in ArchivedFolders())
            {
                if (ledgered.Contains(rel)) continue;
                string dir = AbsRun(rel);
                if (!File.Exists(Path.Combine(dir, "INPUTS.json")))
                {
                    Log("WARNING: archive\\" + rel.Replace('/', '\\') + " is incomplete (the copy did not finish); import that run again with -ImportRun");
                    continue;
                }
                long seq = plan.Count + 1;
                bool snap = SnapshotFor(plan, true);
                Log("finishing run archived by an interrupted ingest: archive\\" + rel.Replace('/', '\\') + " (position " + seq + ")");
                IngestSummary s = ApplyArchived(rel, seq, RetireAfter, dir, snap);
                s.LedgerHead = AppendRunLedger(rel, s, RetireAfter, led, snap);
                led = ReadLedgerStrict(); plan = BuildPlan(led);
                Log("ingested " + s.Text());
            }
            // a correction applied to the database whose ledger entry was not written yet
            meta = Get(MetaKey) ?? new Rec();
            string pend = meta["pending"];
            if (pend.Length > 0)
            {
                if (ledgered.Contains(pend)) { kv.Begin(); meta.Remove("pending"); Put(MetaKey, meta); kv.Commit(true); }
                else if (meta.Long("seq") == plan.Count + 1)
                {
                    Log("finishing correction " + pend + " (applied, not yet in the ledger)");
                    IngestSummary s = CorrectionDerived(pend, plan.Count + 1, AbsRun(pend));
                    AppendCorrectionLedger(pend, s, led);
                    meta = Get(MetaKey); meta.Remove("pending"); kv.Begin(); Put(MetaKey, meta); kv.Commit(true); kv.Flush();
                    led = ReadLedgerStrict(); plan = BuildPlan(led);
                }
            }
            string cdir = Path.Combine(ArchiveDir, "corrections");
            if (Directory.Exists(cdir))
                foreach (string d in Directory.GetDirectories(cdir))
                {
                    string rel = "corrections/" + Path.GetFileName(d);
                    if (ledgered.Contains(rel) || rel == pend || rel.EndsWith(".abandoned", StringComparison.Ordinal)) continue;
                    bool inLedger = false;
                    foreach (LedgerEntry e in led) if (e.Path == rel) inLedger = true;
                    if (inLedger) continue;
                    Directory.Move(d, d + ".abandoned");
                    Log("WARNING: correction " + rel + " was never applied (interrupted before the database changed); kept as " + rel + ".abandoned - run the command again");
                }
            meta = Get(MetaKey) ?? new Rec();
            if (meta.Long("seq") > plan.Count)
                throw new InvalidDataException("the database holds runs the archive ledger does not (database position " + meta["seq"] + ", ledger " + plan.Count + "); rebuild it from the archive: -RebuildStore");
        }

        // ---------------------------------------------------------------- corrections (manual merge / split)
        public IngestSummary Correct(string op, string[] ids, string splitAt, string reason, string operatorName)
        {
            if (kv == null || shadow) throw new InvalidOperationException("store not open for writing");
            if (string.IsNullOrWhiteSpace(reason)) throw new ArgumentException("a correction needs -Reason (it is kept in the ledger)");
            op = (op ?? "").ToLowerInvariant();
            if (op == "merge" && (ids == null || ids.Length != 2)) throw new ArgumentException("-StoreMerge takes exactly two entity ids");
            if (op == "split" && (ids == null || ids.Length != 1)) throw new ArgumentException("-StoreSplit takes one entity id");
            if (op != "merge" && op != "split") throw new ArgumentException("unknown correction '" + op + "'");
            List<LedgerEntry> led = ReadLedgerStrict();
            List<PlanItem> plan = BuildPlan(led);
            long pos = plan.Count + 1, lseq = led[led.Count - 1].Seq + 1;
            string at = StoreUtil.Iso(DateTimeOffset.Now), label = "correction-" + lseq.ToString(CultureInfo.InvariantCulture);
            string why = op == "merge" ? DoMerge(ids[0].Trim(), ids[1].Trim(), pos, at, label, reason, true) : DoSplit(ids[0].Trim(), splitAt ?? "", pos, at, label, reason, true);
            if (why.Length > 0) throw new InvalidOperationException(why);
            string rel = "corrections/" + D6(lseq) + "-" + op;
            string dir = AbsRun(rel);
            Directory.CreateDirectory(dir);
            JsonObj c = new JsonObj().Num("seq", lseq).Str("op", op).Str("at", at).Str("operator", operatorName ?? "").Str("reason", reason);
            if (op == "merge") c.Raw("ids", "[" + Q(ids[0].Trim()) + "," + Q(ids[1].Trim()) + "]"); else c.Str("id", ids[0].Trim()).Str("splitAt", splitAt ?? "");
            StoreUtil.WriteAllTextAtomic(Path.Combine(dir, "correction.json"), c.ToString() + "\n");
            IngestSummary s = ApplyCorrection(rel, pos, dir, true);
            Fail("correction");
            s.LedgerHead = AppendCorrectionLedger(rel, s, led);
            Rec meta = Get(MetaKey); meta.Remove("pending"); kv.Begin(); Put(MetaKey, meta); kv.Commit(true); kv.Flush();
            Log(string.Format(CultureInfo.InvariantCulture, "correction {0} ({1}) recorded at position {2}: {3}; ledger head {4}", label, op, pos, reason, s.LedgerHead));
            return s;
        }
        static string Q(string s) { StringBuilder b = new StringBuilder(); StoreUtil.JsonString(b, s); return b.ToString(); }

        IngestSummary ApplyCorrection(string rel, long pos, string derivedDir, bool live)
        {
            string dir = AbsRun(rel);
            Dictionary<string, object> c = StoreJson.Parse(File.ReadAllText(Path.Combine(dir, "correction.json"), StoreUtil.Utf8)) as Dictionary<string, object>;
            string op = StoreUtil.Str(c, "op"), at = StoreUtil.Str(c, "at"), reason = StoreUtil.Str(c, "reason");
            long lseq = StoreUtil.Num(c, "seq");
            string label = "correction-" + lseq.ToString(CultureInfo.InvariantCulture);
            Rec existing = Get(RunKey(pos));
            if (existing != null && existing["runId"] != label) throw new InvalidDataException("position " + pos + " holds " + existing["runId"] + ", not " + label + "; rebuild the database: -RebuildStore");
            string voidWhy = "";
            if (existing == null)
            {
                kv.Begin();
                try
                {
                    if (op == "merge")
                    {
                        List<object> ids = StoreUtil.Field(c, "ids") as List<object>;
                        voidWhy = DoMerge(StoreUtil.Scalar(ids[0]), StoreUtil.Scalar(ids[1]), pos, at, label, reason, false);
                    }
                    else if (op == "split") voidWhy = DoSplit(StoreUtil.Str(c, "id"), StoreUtil.Str(c, "splitAt"), pos, at, label, reason, false);
                    else throw new InvalidDataException("unknown correction op '" + op + "' in " + rel);
                    Rec rr = new Rec();
                    rr.SetLong("seq", pos); rr["runId"] = label; rr["kind"] = "correction"; rr["state"] = "ingested"; rr["startedAt"] = at; rr["finishedAt"] = at;
                    rr["tag"] = op + ": " + reason + (voidWhy.Length > 0 ? " (void: " + voidWhy + ")" : ""); rr["scanner"] = "correction (" + op + ")"; rr["complete"] = "True";
                    rr["profile"] = ""; rr["archive"] = rel; rr["void"] = voidWhy;
                    Put(RunKey(pos), rr); kv.Put(RunIdKey(label), StoreUtil.B(pos.ToString(CultureInfo.InvariantCulture)));
                    Rec meta = Get(MetaKey) ?? new Rec();
                    meta.SetLong("seq", pos); meta["runId"] = label;
                    if (live) meta["pending"] = rel;
                    Put(MetaKey, meta);
                    kv.Commit(true);
                }
                catch { kv.Rollback(); throw; }
            }
            else voidWhy = existing["void"];
            IngestSummary s = CorrectionDerived(rel, pos, derivedDir);
            s.Void = voidWhy;
            return s;
        }

        IngestSummary CorrectionDerived(string rel, long pos, string derivedDir)
        {
            IngestSummary s = new IngestSummary();
            Rec rr = Get(RunKey(pos));
            s.RunId = rr["runId"]; s.Seq = pos; s.Archive = rel; s.Void = rr["void"];
            if (derivedDir != null) Directory.CreateDirectory(derivedDir);
            using (DigestWriter cw = new DigestWriter(derivedDir != null ? Path.Combine(derivedDir, "changes.jsonl.gz") : null))
            {
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("c", StoreUtil.D10(pos)))) cw.Line(EventJson(Rec.Decode(e.Value)));
                s.ChangesDigest = cw.Close();
            }
            s.StateDigest = LiveStateDigest();
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                switch (Rec.Decode(e.Value)["st"]) { case "active": s.Active++; break; case "missing": s.MissingTotal++; break; default: s.RetiredTotal++; break; }
            kv.Begin();
            rr["changesDigest"] = s.ChangesDigest; rr["stateDigest"] = s.StateDigest;
            Put(RunKey(pos), rr);
            Rec meta = Get(MetaKey) ?? new Rec(); meta["stateDigest"] = s.StateDigest; Put(MetaKey, meta);
            kv.Commit(true); kv.Flush();
            return s;
        }

        string AppendCorrectionLedger(string rel, IngestSummary s, List<LedgerEntry> led)
        {
            string dir = AbsRun(rel);
            Dictionary<string, object> c = StoreJson.Parse(File.ReadAllText(Path.Combine(dir, "correction.json"), StoreUtil.Utf8)) as Dictionary<string, object>;
            long b;
            string files = "[" + new JsonObj().Str("name", "correction.json").Str("sha256", StoreUtil.FileSha256(Path.Combine(dir, "correction.json"), out b)).Num("bytes", b) + "]";
            string derived = "[" + new JsonObj().Str("name", "changes.jsonl.gz").Str("sha256", StoreUtil.FileSha256(Path.Combine(dir, "changes.jsonl.gz"), out b)).Num("bytes", b) + "]";
            long lseq = led[led.Count - 1].Seq + 1;
            JsonObj o = new JsonObj().Num("seq", lseq).Str("type", "correction").Str("op", StoreUtil.Str(c, "op")).Str("runId", s.RunId).Str("runStarted", StoreUtil.Str(c, "at"))
                .Str("path", rel).Str("reason", StoreUtil.Str(c, "reason")).Str("operator", StoreUtil.Str(c, "operator")).Bool("snapshot", false)
                .Str("engine", Engine).Str("ingestedBy", "WebInventory " + ScannerVersion).Str("ingestedAt", StoreUtil.Iso(DateTimeOffset.Now))
                .Raw("files", files).Raw("derived", derived).Str("changesDigest", s.ChangesDigest).Str("stateDigest", s.StateDigest);
            if (s.Void.Length > 0) o.Str("void", s.Void);
            if (lseq != s.Seq) o.Num("pos", s.Seq);
            string head = AppendLedger(o, led[led.Count - 1].Hash);
            kv.Begin(); Rec meta = Get(MetaKey) ?? new Rec(); meta["ledgerHead"] = head; Put(MetaKey, meta); kv.Commit(true); kv.Flush();
            return head;
        }

        long PosOfRun(string runId)
        {
            Rec rr = RunByRunId(runId);
            if (rr == null) throw new InvalidDataException("run " + runId + " is not in the database");
            return rr.Long("seq");
        }
        List<long> EventSeqs(string eid, out List<string> types)
        {
            List<long> seqs = new List<long>(); types = new List<string>();
            foreach (KeyValuePair<byte[], byte[]> x in kv.Scan(P("x", eid)))
            {
                string k = StoreUtil.S(x.Key);
                seqs.Add(long.Parse(k.Substring(k.LastIndexOf('\0') + 1), CultureInfo.InvariantCulture));
                types.Add(StoreUtil.S(x.Value));
            }
            return seqs;
        }
        void DropEvent(long seq, string eid) { kv.Delete(EvKey(seq, eid)); kv.Delete(XKey(eid, seq)); }
        static Rec Copy(Rec r) { return Rec.Decode(r.Encode()); }

        // Fold the later service into the earlier one. Allowed only when the earlier one was last seen before the later
        // one first appeared (the case an automatic pairing missed). Returns "" or why the merge cannot be applied.
        string DoMerge(string idA, string idB, long pos, string at, string label, string reason, bool dry)
        {
            if (idA == idB) return "the two entity ids are the same";
            Rec a = Get(EntKey(idA)), b = Get(EntKey(idB));
            if (a == null) return "entity " + idA + " not found (ids come from the EntityId column of an Inventory or History query)";
            if (b == null) return "entity " + idB + " not found (ids come from the EntityId column of an Inventory or History query)";
            long fa = PosOfRun(a["fr"]), fb = PosOfRun(b["fr"]);
            Rec S = (fa < fb || (fa == fb && string.CompareOrdinal(idA, idB) < 0)) ? a : b, O = S == a ? b : a;
            long sLast = PosOfRun(S["lr"]), oFirst = PosOfRun(O["fr"]);
            if (sLast >= oFirst) return "both services were seen in the same run(s) (" + S["id"] + " last seen in " + S["lr"] + ", " + O["id"] + " first seen in " + O["fr"] + "); only a service that ended before the other began can be merged";
            if (dry) return "";
            string sId = S["id"], oId = O["id"];
            long sVer = S.Long("ver"), oVer = O.Long("ver");
            Rec sCur = Ver(sId, sVer);
            Dictionary<long, long> map = new Dictionary<long, long>();
            long next = sVer;
            for (long k = 1; k <= oVer; k++)
            {
                Rec v = Ver(oId, k);
                kv.Delete(VerKey(oId, k));
                if (k == 1 && v["_h"] == sCur["_h"]) { map[k] = sVer; continue; }
                Rec nv = Copy(v); next++; nv.SetLong("_ver", next); Put(VerKey(sId, next), nv); map[k] = next;
            }
            // the earlier service's absences from the moment the later one appeared are replaced by the later one's history
            List<string> types;
            List<long> sSeqs = EventSeqs(sId, out types);
            for (int i = 0; i < sSeqs.Count; i++) if (sSeqs[i] >= oFirst && (types[i] == "missing" || types[i] == "retired")) DropEvent(sSeqs[i], sId);
            List<long> oSeqs = EventSeqs(oId, out types);
            foreach (long sq in oSeqs)
            {
                Rec ev = Get(EvKey(sq, oId));
                DropEvent(sq, oId);
                if (ev == null) continue;
                if (ev["type"] == "added")
                {
                    Rec ne = Copy(ev);
                    ne["type"] = "rekeyed"; ne["eid"] = sId; ne.SetLong("from", sVer); ne.SetLong("to", map[1]);
                    ne["rule"] = "manual-merge"; ne["okey"] = S["nk"]; ne["pla"] = S["la"]; ne["plr"] = S["lr"]; ne["note"] = reason;
                    List<string> keyDiff = new List<string>(); Rec was = new Rec(), now = new Rec();
                    if (S["host"] != ev["host"]) { keyDiff.Add("Host"); was["Host"] = S["host"]; now["Host"] = ev["host"]; }
                    if (S["ip"] != ev["ip"]) { keyDiff.Add("IP"); was["IP"] = S["ip"]; now["IP"] = ev["ip"]; }
                    if (S["port"] != ev["port"]) { keyDiff.Add("Port"); was["Port"] = S["port"]; now["Port"] = ev["port"]; }
                    AddDiff(ne, keyDiff, was, now);
                    if (map[1] != sVer) { Rec v1 = Ver(sId, map[1]); AddDiff(ne, InvSchema.Diff(sCur, v1), sCur, v1); }
                    ev = ne;
                }
                else
                {
                    ev["eid"] = sId;
                    long f = ev.Long("from"), t = ev.Long("to");
                    if (map.ContainsKey(f)) ev.SetLong("from", map[f]);
                    if (map.ContainsKey(t)) ev.SetLong("to", map[t]);
                }
                PutEvent(sq, sId, ev);
            }
            kv.Delete(NkKey(S["nk"]));
            kv.Put(NkKey(O["nk"]), StoreUtil.B(sId));
            foreach (string f in new[] { "nk", "host", "ip", "port", "vh", "st", "la", "lr", "ap", "ms", "mr", "ra" }) { if (O[f].Length > 0) S[f] = O[f]; else S.Remove(f); }
            S.RemovePrefix("o:");
            foreach (string f in O.Names.ToArray()) if (f.StartsWith("o:", StringComparison.Ordinal)) S[f] = O[f];
            S.SetLong("ver", map[oVer]); S["h"] = O["h"];
            if (map[oVer] > sVer) S["ca"] = O["ca"];
            Put(EntKey(sId), S);
            kv.Delete(EntKey(oId));
            Rec me = new Rec();
            me["type"] = "merged"; me.SetLong("seq", pos); me["run"] = label; me["at"] = at; me["eid"] = sId;
            me["host"] = S["host"]; me["ip"] = S["ip"]; me["port"] = S["port"]; me["vh"] = S["vh"]; me["url"] = Ver(sId, S.Long("ver"))["Url"];
            me.SetLong("from", S.Long("ver")); me.SetLong("to", S.Long("ver")); me["rule"] = "manual"; me["okey"] = "entity " + oId; me["note"] = reason;
            PutEvent(pos, sId, me);
            return "";
        }

        // Undo an address-move pairing (automatic or a manual merge): everything from that run on becomes a separate
        // service again; the original goes back to its old address with its absences recomputed from the archive.
        string DoSplit(string id, string splitAt, long pos, string at, string label, string reason, bool dry)
        {
            Rec E = Get(EntKey(id));
            if (E == null) return "entity " + id + " not found (ids come from the EntityId column of an Inventory or History query)";
            List<string> types;
            List<long> seqs = EventSeqs(id, out types);
            long P = -1;
            for (int i = 0; i < seqs.Count; i++)
            {
                if (types[i] != "rekeyed") continue;
                if (splitAt.Length == 0) P = seqs[i];
                else { Rec ev0 = Get(EvKey(seqs[i], id)); if (ev0 != null && ev0["run"] == splitAt) P = seqs[i]; }
            }
            if (P < 0) return "entity " + id + " has no address-move pairing (rekeyed event)" + (splitAt.Length > 0 ? " in run " + splitAt : "") + " to split";
            Rec rk = Get(EvKey(P, id));
            string okey = rk["okey"];
            if (okey.Length == 0 || okey.Split('|').Length != 4) return "the pairing in run " + rk["run"] + " has no previous key recorded";
            byte[] other = kv.Get(NkKey(okey));
            if (other != null && StoreUtil.S(other) != id)
                return "the old address (" + okey + ") has since been seen again as entity " + StoreUtil.S(other) + "; split is not possible (merge that entity instead)";
            if (dry) return "";
            string newNk = rk["host"].ToLowerInvariant() + "|" + rk["ip"] + "|" + rk["port"] + "|" + rk["vh"];
            // versions: the one current at P (or the one P created) starts the new service
            long ev = E.Long("ver"), vb = 0;
            List<long> moved = new List<long>();
            for (long k = 1; k <= ev; k++) { long sq = Ver(id, k).Long("_seq"); if (sq < P) vb = k; else moved.Add(k); }
            if (vb == 0) throw new InvalidDataException("entity " + id + " has no version before the pairing in run " + rk["run"]);
            string nid = null;
            for (int n = 0; n < 100; n++)
            {
                string cand = MakeId(newNk, rk["run"], n);
                if (cand != id && Get(EntKey(cand)) == null) { nid = cand; break; }
            }
            if (nid == null) throw new InvalidDataException("could not allocate an entity id for the split");
            Dictionary<long, long> map = new Dictionary<long, long>();
            long nv = 0;
            if (moved.Count == 0 || Ver(id, moved[0]).Long("_seq") != P)
            {
                Rec v1 = Copy(Ver(id, vb)); v1.SetLong("_ver", 1); v1.SetLong("_seq", P); v1["_run"] = rk["run"]; v1["_at"] = rk["at"];
                Put(VerKey(nid, 1), v1); nv = 1; map[vb] = 1;
            }
            foreach (long k in moved)
            {
                Rec v = Copy(Ver(id, k)); nv++; v.SetLong("_ver", nv); Put(VerKey(nid, nv), v); map[k] = nv;
                kv.Delete(VerKey(id, k));
            }
            // events from P on belong to the new service; the pairing itself becomes its "added"
            for (int i = 0; i < seqs.Count; i++)
            {
                long sq = seqs[i];
                if (sq < P) continue;
                Rec e2 = Get(EvKey(sq, id));
                DropEvent(sq, id);
                if (e2 == null) continue;
                if (sq == P)
                {
                    Rec ad = new Rec();
                    ad["type"] = "added"; ad.SetLong("seq", P); ad["run"] = rk["run"]; ad["at"] = rk["at"]; ad["eid"] = nid;
                    ad["host"] = rk["host"]; ad["ip"] = rk["ip"]; ad["port"] = rk["port"]; ad["vh"] = rk["vh"]; ad["url"] = rk["url"];
                    ad.SetLong("from", 0); ad.SetLong("to", 1);
                    e2 = ad;
                }
                else
                {
                    e2["eid"] = nid;
                    long f = e2.Long("from"), t = e2.Long("to");
                    if (map.ContainsKey(f)) e2.SetLong("from", map[f]);
                    if (map.ContainsKey(t)) e2.SetLong("to", map[t]);
                }
                PutEvent(sq, nid, e2);
            }
            Rec N = new Rec();
            N["id"] = nid;
            foreach (string f in new[] { "nk", "host", "ip", "port", "vh", "st", "la", "lr", "ap", "ms", "mr", "ra" }) if (E[f].Length > 0) N[f] = E[f];
            foreach (string f in E.Names.ToArray()) if (f.StartsWith("o:", StringComparison.Ordinal)) N[f] = E[f];
            N["fa"] = rk["at"]; N["fr"] = rk["run"]; N.SetLong("ver", nv);
            Rec nlast = Ver(nid, nv); N["h"] = nlast["_h"]; N["ca"] = nlast["_at"];
            Put(EntKey(nid), N);
            kv.Put(NkKey(E["nk"]), StoreUtil.B(nid));
            // the original returns to its old key; last seen = its last sighting before the pairing
            string[] ok = okey.Split('|');
            string oldHost = rk["was:Host"].Length > 0 ? rk["was:Host"] : (ok[0] == E["host"].ToLowerInvariant() ? E["host"] : ok[0]);
            E["nk"] = okey; E["host"] = oldHost; E["ip"] = rk["was:IP"].Length > 0 ? rk["was:IP"] : ok[1]; E["port"] = ok[2]; E["vh"] = ok[3];
            Rec vbr = Ver(id, vb);
            E.SetLong("ver", vb); E["h"] = vbr["_h"]; E["ca"] = vbr["_at"];
            E["la"] = rk["pla"].Length > 0 ? rk["pla"] : vbr["_at"]; E["lr"] = rk["plr"].Length > 0 ? rk["plr"] : vbr["_run"];
            E.RemovePrefix("o:");
            kv.Put(NkKey(okey), StoreUtil.B(id));
            RecomputeAbsence(E, PosOfRun(E["lr"]), pos);
            Put(EntKey(id), E);
            foreach (string[] side in new[] { new[] { id, nid }, new[] { nid, id } })
            {
                Rec me = new Rec(); Rec ent = side[0] == id ? E : N;
                me["type"] = "split"; me.SetLong("seq", pos); me["run"] = label; me["at"] = at; me["eid"] = side[0];
                me["host"] = ent["host"]; me["ip"] = ent["ip"]; me["port"] = ent["port"]; me["vh"] = ent["vh"]; me["url"] = Ver(side[0], ent.Long("ver"))["Url"];
                me.SetLong("from", ent.Long("ver")); me.SetLong("to", ent.Long("ver")); me["rule"] = "manual"; me["okey"] = "entity " + side[1]; me["note"] = reason;
                PutEvent(pos, side[0], me);
            }
            return "";
        }

        // absence of one service replayed from the archive: every run after its last sighting that checked its key
        // (same rule as ApplyAbsence, same per-run retire threshold)
        void RecomputeAbsence(Rec ent, long lastSeenPos, long beforePos)
        {
            string id = ent["id"];
            List<string> types;
            List<long> seqs = EventSeqs(id, out types);
            for (int i = 0; i < seqs.Count; i++) if (seqs[i] > lastSeenPos && seqs[i] < beforePos && (types[i] == "missing" || types[i] == "retired")) DropEvent(seqs[i], id);
            string st = "active"; long mr = 0; string ms = "", ra = "";
            long ap = lastSeenPos;
            List<Rec> runs = new List<Rec>();
            foreach (KeyValuePair<byte[], byte[]> r in kv.Scan(P("r"))) runs.Add(Rec.Decode(r.Value));
            foreach (Rec rr in runs)
            {
                long p = rr.Long("seq");
                if (p <= lastSeenPos || p >= beforePos || rr["kind"] == "correction" || rr["state"] != "ingested") continue;
                if (st == "retired") break;
                string dir = AbsRun(rr["archive"]);
                RunInfo run = RunInfo.Parse(File.ReadAllText(Path.Combine(dir, "run.json"), StoreUtil.Utf8));
                bool inScope = false;
                string want = ent["vh"] == "v" ? ent["ip"] + "|" + ent["port"] : ent["host"].ToLowerInvariant() + "|" + ent["port"];
                if (ent["vh"] != "v" || run.ProbeSans)
                    foreach (string l in StoreUtil.ReadLines(Path.Combine(dir, "checked.txt.gz")))
                    {
                        string[] f = l.Trim().Split('|');
                        if (f.Length < 3) continue;
                        string k = ent["vh"] == "v" ? f[1].ToLowerInvariant() + "|" + f[2] : f[0].ToLowerInvariant() + "|" + f[2];
                        if (k == want) { inScope = true; break; }
                    }
                if (!inScope) continue;
                string at = StoreUtil.Iso(run.Started);
                mr++; ap = p;
                string type = null;
                if (st == "active") ms = at;
                long ret = rr.Long("retireAfter") > 0 ? rr.Long("retireAfter") : RetireAfter;
                if (mr >= ret) { st = "retired"; ra = at; type = "retired"; }
                else if (st == "active") { st = "missing"; type = "missing"; }
                if (type != null)
                {
                    long ver = ent.Long("ver");
                    PutEvent(p, id, NewEvent(type, p, run, at, id, ent["host"], ent["ip"], ent["port"], ent["vh"], Ver(id, ver)["Url"], ver, ver));
                }
            }
            ent["st"] = st; ent.SetLong("ap", ap);
            if (mr > 0) ent.SetLong("mr", mr); else ent.Remove("mr");
            if (ms.Length > 0) ent["ms"] = ms; else ent.Remove("ms");
            if (ra.Length > 0) ent["ra"] = ra; else ent.Remove("ra");
        }

        // ---------------------------------------------------------------- backfill: insert older runs, replay in order
        public List<IngestSummary> Backfill(List<RunSources> list, bool allowPartial)
        {
            if (kv == null || shadow) throw new InvalidOperationException("store not open for writing");
            List<IngestSummary> res = new List<IngestSummary>();
            List<LedgerEntry> led = ReadLedgerStrict();
            List<string> added = new List<string>();
            foreach (RunSources src in list)
            {
                RunInfo run; LedgerEntry dup, last;
                CheckRun(src, allowPartial, led, out run, out dup, out last);
                if (dup != null) { IngestSummary d = new IngestSummary(); d.RunId = run.RunId; d.Seq = dup.Seq; d.AlreadyPresent = true; d.Archive = dup.Path; res.Add(d); continue; }
                long rows; double tv, tc;
                string rel = ArchiveRun(src, run, out rows, out tv, out tc);
                string dir = AbsRun(rel);
                Dictionary<string, object> inputs = StoreJson.Parse(File.ReadAllText(Path.Combine(dir, "INPUTS.json"), StoreUtil.Utf8)) as Dictionary<string, object>;
                List<string> files = new List<string>();
                foreach (object f in (System.Collections.IEnumerable)StoreUtil.Field(inputs, "files"))
                {
                    Dictionary<string, object> d = (Dictionary<string, object>)f;
                    files.Add(new JsonObj().Str("name", StoreUtil.Str(d, "name")).Str("sha256", StoreUtil.Str(d, "sha256")).Num("bytes", StoreUtil.Num(d, "bytes")).ToString());
                }
                long b;
                files.Add(new JsonObj().Str("name", "INPUTS.json").Str("sha256", StoreUtil.FileSha256(Path.Combine(dir, "INPUTS.json"), out b)).Num("bytes", b).ToString());
                long lseq = led[led.Count - 1].Seq + 1;
                JsonObj o = new JsonObj().Num("seq", lseq).Str("type", "run").Str("runId", run.RunId).Str("runStarted", run.StartedAt).Str("path", rel)
                    .Bool("complete", run.Complete).Num("retireAfter", RetireAfter).Str("profile", run.Profile).Bool("backfill", true).Str("engine", Engine)
                    .Str("ingestedBy", "WebInventory " + ScannerVersion).Str("ingestedAt", StoreUtil.Iso(DateTimeOffset.Now)).Raw("files", "[" + string.Join(",", files) + "]");
                AppendLedger(o, led[led.Count - 1].Hash);
                led = ReadLedgerStrict();
                added.Add(run.RunId);
                Log("backfill: archived run " + run.RunId + " (started " + run.StartedAt + ")");
            }
            if (added.Count == 0) return res;
            Dictionary<string, IngestSummary> sums = Rebase(led, "backfill of " + string.Join(", ", added.ToArray()));
            foreach (string r in added) { IngestSummary s; if (sums.TryGetValue(r, out s)) res.Add(s); }
            return res;
        }

        // replays the whole history in run order into a fresh working database and appends a "rebase" entry with
        // the new order and every position's digests. Corrections stay right after the run they followed.
        Dictionary<string, IngestSummary> Rebase(List<LedgerEntry> led, string why)
        {
            Stopwatch sw = Stopwatch.StartNew();
            List<PlanItem> old = BuildPlan(led);
            List<PlanItem> runs = new List<PlanItem>();
            Dictionary<PlanItem, List<PlanItem>> after = new Dictionary<PlanItem, List<PlanItem>>();
            PlanItem anchor = null;
            foreach (PlanItem it in old)
            {
                if (it.IsRun) { runs.Add(it); anchor = it; continue; }
                if (anchor == null) throw new InvalidDataException("a correction precedes every run in the ledger");
                List<PlanItem> l; if (!after.TryGetValue(anchor, out l)) { l = new List<PlanItem>(); after[anchor] = l; } l.Add(it);
            }
            runs.Sort(delegate(PlanItem x, PlanItem y)
            {
                int c = StoreUtil.ParseIso(x.E.RunStarted).CompareTo(StoreUtil.ParseIso(y.E.RunStarted));
                return c != 0 ? c : x.E.Seq.CompareTo(y.E.Seq);
            });
            List<PlanItem> plan = new List<PlanItem>();
            foreach (PlanItem r in runs)
            {
                plan.Add(r);
                List<PlanItem> l; if (after.TryGetValue(r, out l)) plan.AddRange(l);
            }
            long R = led[led.Count - 1].Seq + 1;
            string rdir = "rebase/" + D6(R);
            if (Directory.Exists(AbsRun(rdir))) Directory.Delete(AbsRun(rdir), true);
            ResetDb();
            List<string> items = new List<string>(), derived = new List<string>();
            Dictionary<string, IngestSummary> sums = new Dictionary<string, IngestSummary>(StringComparer.Ordinal);
            List<PlanItem> done = new List<PlanItem>();
            foreach (PlanItem src in plan)
            {
                PlanItem it = new PlanItem();
                it.E = src.E; it.Pos = done.Count + 1; it.Snapshot = SnapshotFor(done, src.IsRun);
                string dd = AbsRun(rdir + "/" + D6(it.Pos));
                IngestSummary s = ApplyItem(it, dd);
                it.ChangesDigest = s.ChangesDigest; it.StateDigest = s.StateDigest; it.Void = s.Void;
                done.Add(it);
                sums[it.E.RunId] = s;
                JsonObj io = new JsonObj().Num("seq", it.E.Seq).Str("runId", it.E.RunId).Str("changesDigest", s.ChangesDigest).Str("stateDigest", s.StateDigest);
                if (!it.Snapshot) io.Bool("snapshot", false);
                if (s.Void.Length > 0) io.Str("void", s.Void);
                items.Add(io.ToString());
                long b;
                foreach (string n in it.Snapshot ? new[] { "changes.jsonl.gz", "state.jsonl.gz" } : new[] { "changes.jsonl.gz" })
                    derived.Add(new JsonObj().Str("name", D6(it.Pos) + "/" + n).Str("sha256", StoreUtil.FileSha256(Path.Combine(dd, n), out b)).Num("bytes", b).ToString());
            }
            JsonObj o = new JsonObj().Num("seq", R).Str("type", "rebase").Str("reason", why).Str("path", rdir).Str("engine", Engine)
                .Str("ingestedBy", "WebInventory " + ScannerVersion).Str("ingestedAt", StoreUtil.Iso(DateTimeOffset.Now))
                .Raw("plan", "[" + string.Join(",", items) + "]").Raw("derived", "[" + string.Join(",", derived) + "]");
            string head = AppendLedger(o, led[led.Count - 1].Hash);
            kv.Begin(); Rec meta = Get(MetaKey) ?? new Rec(); meta["rebase"] = R.ToString(CultureInfo.InvariantCulture); meta["ledgerHead"] = head; Put(MetaKey, meta); kv.Commit(true); kv.Flush();
            foreach (IngestSummary s in sums.Values) s.LedgerHead = head;
            Log(string.Format(CultureInfo.InvariantCulture, "rebase seq {0}: {1} runs and {2} corrections replayed in run order in {3:0.0}s ({4}); ledger head {5}",
                R, runs.Count, plan.Count - runs.Count, sw.Elapsed.TotalSeconds, why, head));
            return sums;
        }

        // ---------------------------------------------------------------- -AsOf
        List<Dictionary<string, string>> AsOfRows(DateTimeOffset asof)
        {
            List<Dictionary<string, string>> rows = new List<Dictionary<string, string>>();
            List<LedgerEntry> led = ReadLedgerStrict();
            List<PlanItem> plan = BuildPlan(led);
            PlanItem pick = null;
            foreach (PlanItem it in plan) if (it.IsRun && StoreUtil.ParseIso(it.E.RunStarted) <= asof) pick = it;
            if (pick == null) { Messages.Add("no run in the store started at or before " + StoreUtil.Iso(asof)); return rows; }
            string sf = Path.Combine(pick.Derived, "state.jsonl.gz");
            if (pick.Snapshot && File.Exists(sf))
            {
                Messages.Add("inventory as of run " + pick.E.RunId + " (" + pick.E.RunStarted + ")");
                foreach (string l in StoreUtil.ReadLines(sf))
                {
                    if (l.Length == 0) continue;
                    Dictionary<string, object> o = (Dictionary<string, object>)StoreJson.Parse(l);
                    Dictionary<string, string> row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (string c in InventoryColumns) row[c] = StoreUtil.Str(o, c);
                    rows.Add(row);
                }
                return rows;
            }
            Stopwatch sw = Stopwatch.StartNew();
            InventoryStore sh = NewShadow();
            try
            {
                foreach (PlanItem it in plan) { if (it.Pos > pick.Pos) break; sh.ApplyItem(it, null); }
                foreach (KeyValuePair<byte[], byte[]> e in sh.kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    rows.Add(InventoryRow(ent, sh.Ver(ent["id"], ent.Long("ver"))));
                }
            }
            finally { sh.kv.Dispose(); }
            Messages.Add(string.Format(CultureInfo.InvariantCulture, "inventory as of run {0} ({1}); no snapshot kept for that run, history replayed in memory ({2} positions, {3:0.0}s)",
                pick.E.RunId, pick.E.RunStarted, pick.Pos, sw.Elapsed.TotalSeconds));
            return rows;
        }

        // ---------------------------------------------------------------- options kept in STORE.json
        // snapshotEvery 0 = keep; anchorEventLog -1 = keep, 0 = off, 1 = on; anchorCertificate null = keep, "" = off
        // (PowerShell passes $null to a string parameter as "", hence the explicit setCertificate flag)
        public void SetOptions(int snapshotEvery, int anchorEventLog, bool setCertificate, string anchorCertificate)
        {
            if (!setCertificate) anchorCertificate = null;
            bool dirty = false;
            if (snapshotEvery > 0 && snapshotEvery != SnapshotEvery) { Log(string.Format(CultureInfo.InvariantCulture, "snapshot interval changed from {0} to {1} (runs ingested from now on)", SnapshotEvery, snapshotEvery)); SnapshotEvery = snapshotEvery; dirty = true; }
            if (anchorEventLog >= 0 && (anchorEventLog == 1) != AnchorEventLog) { AnchorEventLog = anchorEventLog == 1; Log("event-log anchoring " + (AnchorEventLog ? "on" : "off")); dirty = true; }
            if (anchorCertificate != null && anchorCertificate != AnchorCertificate)
            {
                AnchorCertificate = anchorCertificate;
                List<string> pr = new List<string>(); List<LedgerEntry> led = ReadLedger(pr);
                AnchorFrom = anchorCertificate.Length > 0 && led.Count > 0 ? led[led.Count - 1].Seq + 1 : 0;
                Log(anchorCertificate.Length > 0 ? "ledger entries from seq " + AnchorFrom + " on are signed with certificate " + anchorCertificate : "ledger signing off");
                dirty = true;
            }
            if (dirty && !shadow) SaveStoreJson();
        }

        public List<string[]> LedgerLines()
        {
            List<string[]> o = new List<string[]>();
            List<string> pr = new List<string>();
            foreach (LedgerEntry e in ReadLedger(pr)) o.Add(new[] { e.Seq.ToString(CultureInfo.InvariantCulture), e.Hash, e.Line, e.Type });
            return o;
        }

        // ---------------------------------------------------------------- verification
        // Ledger chain, archived file hashes, the whole history replayed in memory (every rebase replayed again from
        // scratch) compared position by position with the ledger, and the working database against the last state.
        public bool Verify(List<string> report)
        {
            bool ok = true;
            List<string> problems = new List<string>();
            List<LedgerEntry> led = ReadLedger(problems);
            foreach (string p in problems) { report.Add("FAIL ledger: " + p); ok = false; }
            int runs = 0, corrections = 0, rebases = 0;
            foreach (LedgerEntry e in led) { if (e.Type == "run") runs++; else if (e.Type == "correction") corrections++; else if (e.Type == "rebase") rebases++; }
            if (problems.Count == 0) report.Add(string.Format(CultureInfo.InvariantCulture, "ok   ledger: {0} lines, chain intact, head {1}", led.Count, led.Count > 0 ? led[led.Count - 1].Hash : "-"));
            HashSet<string> ledgered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int filesOk = 0;
            foreach (LedgerEntry e in led)
            {
                if (e.Type == "genesis") continue;
                if (e.Type != "rebase") ledgered.Add(e.Path);
                string dir = AbsRun(e.Path);
                if (!Directory.Exists(dir)) { report.Add("FAIL " + e.Type + " " + e.RunId + ": archive folder missing (" + e.Path + ")"); ok = false; continue; }
                foreach (string arr in new[] { "files", "derived" })
                {
                    if (e.Type == "rebase" && arr == "files") continue;
                    System.Collections.IEnumerable files = StoreUtil.Field(e.Obj, arr) as System.Collections.IEnumerable;
                    if (files == null)
                    {
                        if (arr == "derived" && e.Backfill) continue;
                        report.Add("FAIL " + e.Type + " " + e.RunId + ": ledger entry lists no " + arr); ok = false; continue;
                    }
                    foreach (object f in files)
                    {
                        Dictionary<string, object> d = (Dictionary<string, object>)f;
                        string name = StoreUtil.Str(d, "name"), path = Path.Combine(dir, name.Replace('/', Path.DirectorySeparatorChar));
                        if (!File.Exists(path)) { report.Add("FAIL " + e.Type + " " + e.RunId + " seq " + e.Seq + ": " + name + " missing"); ok = false; continue; }
                        long b;
                        if (StoreUtil.FileSha256(path, out b) != StoreUtil.Str(d, "sha256")) { report.Add("FAIL " + e.Type + " " + e.RunId + " seq " + e.Seq + ": " + name + " altered (SHA-256 differs from the ledger)"); ok = false; }
                        else filesOk++;
                    }
                }
            }
            report.Add(string.Format(CultureInfo.InvariantCulture, "{0} archive: {1} runs, {2} corrections, {3} rebases, {4} files checked against the ledger", ok ? "ok  " : "FAIL", runs, corrections, rebases, filesOk));
            foreach (string rel in ArchivedFolders())
                if (!ledgered.Contains(rel))
                    report.Add("note archive\\" + rel.Replace('/', '\\') + " is not in the ledger yet (" + (File.Exists(Path.Combine(AbsRun(rel), "INPUTS.json")) ? "finished on the next open" : "incomplete copy; re-import the run") + ")");
            // independent replay (portable engine, in memory)
            Stopwatch sw = Stopwatch.StartNew();
            bool rebuildOk = true;
            string lastState = "";
            int applied = 0;
            InventoryStore sh = NewShadow();
            List<PlanItem> cur = new List<PlanItem>();
            try
            {
                foreach (LedgerEntry e in led)
                {
                    if (!rebuildOk) break;
                    if (e.Type == "run" || e.Type == "correction")
                    {
                        PlanItem it = new PlanItem(); it.E = e; it.Pos = cur.Count + 1; it.Snapshot = e.Snapshot && e.Type == "run";
                        cur.Add(it);
                        if (e.Backfill && e.StateDigest.Length == 0) continue;   // placed by the rebase that follows
                        IngestSummary s;
                        try { s = sh.ApplyItem(it, null); applied++; }
                        catch (Exception ex) { report.Add("FAIL replay at " + e.RunId + ": " + ex.Message); rebuildOk = false; break; }
                        if (s.ChangesDigest != e.ChangesDigest) { report.Add("FAIL replay " + e.RunId + ": change events differ from the ledger"); rebuildOk = false; }
                        if (s.StateDigest != e.StateDigest) { report.Add("FAIL replay " + e.RunId + ": inventory state differs from the ledger"); rebuildOk = false; }
                        lastState = e.StateDigest;
                    }
                    else if (e.Type == "rebase")
                    {
                        sh.kv.Dispose(); sh = NewShadow();
                        List<LedgerEntry> upto = new List<LedgerEntry>();
                        foreach (LedgerEntry x in led) { upto.Add(x); if (x == e) break; }
                        cur = BuildPlan(upto);
                        foreach (PlanItem it in cur)
                        {
                            IngestSummary s;
                            try { s = sh.ApplyItem(it, null); applied++; }
                            catch (Exception ex) { report.Add("FAIL replay of rebase seq " + e.Seq + " at " + it.E.RunId + ": " + ex.Message); rebuildOk = false; break; }
                            if (s.ChangesDigest != it.ChangesDigest || s.StateDigest != it.StateDigest) { report.Add("FAIL replay of rebase seq " + e.Seq + " at position " + it.Pos + " (" + it.E.RunId + "): digests differ from the ledger"); rebuildOk = false; }
                            lastState = it.StateDigest;
                        }
                    }
                }
            }
            finally { sh.kv.Dispose(); }
            if (rebuildOk) report.Add(string.Format(CultureInfo.InvariantCulture, "ok   rebuild: {0} positions re-applied from the archive in memory, every change and state digest matches the ledger ({1:0.0}s)", applied, sw.Elapsed.TotalSeconds));
            ok &= rebuildOk;
            if (kv == null) report.Add("note working database not present or not openable here (" + Engine + "); archive checks only");
            else
            {
                Rec meta = Get(MetaKey) ?? new Rec();
                long lastPos = 0;
                try { lastPos = BuildPlan(led).Count; } catch (Exception) { }
                if (meta["rebase"] != LastRebase(led) && meta.Long("seq") > 0) report.Add("note working database predates the latest rebase; it is rebuilt on the next open");
                else if (meta.Long("seq") < lastPos) report.Add("note working database is behind the archive (position " + meta.Long("seq") + " of " + lastPos + "); it catches up on the next open");
                else if (meta.Long("seq") > lastPos) { report.Add("FAIL working database has positions the ledger does not (" + meta.Long("seq") + " vs " + lastPos + "): -RebuildStore"); ok = false; }
                else
                {
                    string live = LiveStateDigest();
                    if (lastPos > 0 && live != lastState) { report.Add("FAIL working database (" + Engine + ") differs from the archive's last state; -RebuildStore recreates it"); ok = false; }
                    else report.Add("ok   working database (" + Engine + ") matches the archive's last state digest");
                }
            }
            return ok;
        }
    }
}

// ============================================================================
// WebInv store: offline vulnerability correlation (-StoreQuery Vulnerabilities)
// The current inventory's CPEs joined with NVD CVE JSON 2.0 feeds (version-aware), CISA KEV and FIRST EPSS - all
// read from files the operator downloaded; nothing is fetched and nothing is sent to a target.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.IO.Compression;
    using System.Text;
    using System.Text.RegularExpressions;

    // CPE 2.3 formatted string, split on unescaped ':'
    public sealed class Cpe
    {
        public string Part = "", Vendor = "", Product = "", Version = "*", Update = "*", Raw = "";
        // set on the copies made for alias names: the service's own CPE, and the NVD name the copy stands for
        public Cpe Origin; public string Alias = "";
        public string Key { get { return Part + ":" + Vendor + ":" + Product; } }
        public Cpe Root { get { return Origin ?? this; } }
        public static Cpe Parse(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;
            s = s.Trim();
            List<string> f = new List<string>();
            if (s.StartsWith("cpe:2.3:", StringComparison.OrdinalIgnoreCase))
            {
                StringBuilder cur = new StringBuilder();
                for (int i = 8; i < s.Length; i++)
                {
                    char c = s[i];
                    if (c == '\\' && i + 1 < s.Length) { cur.Append(s[i + 1]); i++; continue; }
                    if (c == ':') { f.Add(cur.ToString()); cur.Length = 0; continue; }
                    cur.Append(c);
                }
                f.Add(cur.ToString());
            }
            else if (s.StartsWith("cpe:/", StringComparison.OrdinalIgnoreCase)) f.AddRange(s.Substring(5).Split(':'));
            else return null;
            if (f.Count < 3) return null;
            // percent-encoding belongs to the cpe:/ URI form, but some rule data writes it into formatted strings
            // (treck:tcp%2fip, ibm:z%2fos): decode it so the name compares equal to NVD's tcp\/ip
            for (int i = 0; i < f.Count; i++) if (f[i].IndexOf('%') >= 0) f[i] = Uri.UnescapeDataString(f[i]);
            Cpe c2 = new Cpe();
            c2.Raw = s;
            c2.Part = f[0].ToLowerInvariant(); c2.Vendor = f[1].ToLowerInvariant(); c2.Product = f[2].ToLowerInvariant();
            c2.Version = f.Count > 3 && f[3].Length > 0 ? f[3] : "*";
            c2.Update = f.Count > 4 && f[4].Length > 0 ? f[4] : "*";
            return c2;
        }
        public Cpe As(string key)
        {
            string[] k = key.Split(new[] { ':' }, 3);
            Cpe c = new Cpe();
            c.Part = k[0]; c.Vendor = k[1]; c.Product = k[2]; c.Version = Version; c.Update = Update; c.Raw = Raw;
            c.Origin = Root; c.Alias = key;
            return c;
        }
        public static bool Any(string v) { return v == "*" || v == "-" || v.Length == 0; }
        public bool VersionKnown { get { return !Any(Version); } }
        public string Full { get { return Version + (Any(Update) ? "" : Update); } }
    }

    public static class VersionCmp
    {
        static readonly HashSet<string> Pre = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "alpha", "a", "beta", "b", "rc", "pre", "preview", "dev", "m", "snapshot", "cr", "c", "ea" };
        static List<string> Tokens(string v)
        {
            List<string> t = new List<string>();
            StringBuilder cur = new StringBuilder(); int kind = 0;   // 1 digit, 2 letter
            foreach (char ch in v ?? "")
            {
                int k = char.IsDigit(ch) ? 1 : (char.IsLetter(ch) ? 2 : 0);
                if (k != kind && cur.Length > 0) { t.Add(cur.ToString()); cur.Length = 0; }
                kind = k;
                if (k != 0) cur.Append(ch);
            }
            if (cur.Length > 0) t.Add(cur.ToString());
            return t;
        }
        static bool IsNum(string s) { return s.Length > 0 && char.IsDigit(s[0]); }
        static int CmpNum(string a, string b)
        {
            a = a.TrimStart('0'); b = b.TrimStart('0');
            if (a.Length != b.Length) return a.Length.CompareTo(b.Length);
            return string.CompareOrdinal(a, b);
        }
        // numeric runs compare as numbers; a trailing pre-release word (rc, beta...) sorts before the release, other
        // trailing words (p1, k, a vendor letter) after it
        public static int Compare(string x, string y)
        {
            List<string> a = Tokens(x), b = Tokens(y);
            int n = Math.Min(a.Count, b.Count);
            for (int i = 0; i < n; i++)
            {
                bool na = IsNum(a[i]), nb = IsNum(b[i]);
                int c;
                if (na && nb) c = CmpNum(a[i], b[i]);
                else if (!na && !nb) c = string.Compare(a[i], b[i], StringComparison.OrdinalIgnoreCase);
                else c = na ? 1 : -1;
                if (c != 0) return c < 0 ? -1 : 1;
            }
            if (a.Count == b.Count) return 0;
            List<string> longer = a.Count > b.Count ? a : b;
            bool zeros = true;                       // 2.4 == 2.4.0
            for (int i = n; i < longer.Count; i++) if (!IsNum(longer[i]) || longer[i].TrimStart('0').Length > 0) { zeros = false; break; }
            if (zeros) return 0;
            string next = longer[n];
            int sign = (!IsNum(next) && Pre.Contains(next)) ? -1 : 1;
            return a.Count > b.Count ? sign : -sign;
        }
    }

    public sealed class VulnResult
    {
        public string[] Columns;
        public readonly List<string[]> Rows = new List<string[]>();
        public string Provenance = "";
        public readonly List<string> Messages = new List<string>();
    }

    public static class Vulns
    {
        public static readonly string[] Columns = { "Host", "IP", "Port", "Url", "Status", "Products", "Cpe", "Cve", "Kev", "KevDateAdded", "KevDueDate", "KevRansomware",
            "Epss", "EpssPercentile", "CvssScore", "CvssSeverity", "CvssVersion", "Published", "Match", "EntityId", "Description" };

        public sealed class Service
        {
            public string Host, Ip, Port, Url, Status, Products, EntityId;
            public List<Cpe> Cpes = new List<Cpe>();
        }
        sealed class Hit { public Service Svc; public Cpe Cpe; public string Match; }
        sealed class CveInfo
        {
            public string Id, LastModified, Published, Score = "", Severity = "", CvssVersion = "", Description = "";
            public List<Hit> Hits = new List<Hit>();
        }

        // ---------------------------------------------------------------- streaming the NVD feed
        // yields the raw text of every element of the top-level "vulnerabilities" array
        public static IEnumerable<string> FeedRecords(TextReader r)
        {
            int depth = 0; bool inStr = false, esc = false, inArray = false;
            StringBuilder key = new StringBuilder(), rec = null; string lastKey = null; bool readingKey = false;
            int c;
            while ((c = r.Read()) >= 0)
            {
                char ch = (char)c;
                if (rec != null) rec.Append(ch);
                if (inStr)
                {
                    if (esc) esc = false;
                    else if (ch == '\\') esc = true;
                    else if (ch == '"') { inStr = false; if (readingKey) { lastKey = key.ToString(); readingKey = false; } }
                    else if (readingKey) key.Append(ch);
                    continue;
                }
                switch (ch)
                {
                    case '"':
                        inStr = true;
                        if (depth == 1 && !inArray) { readingKey = true; key.Length = 0; }
                        break;
                    case '{':
                        depth++;
                        if (inArray && depth == 3) { rec = new StringBuilder(4096); rec.Append('{'); }
                        break;
                    case '}':
                        depth--;
                        if (inArray && depth == 2 && rec != null) { yield return rec.ToString(); rec = null; }
                        break;
                    case '[':
                        depth++;
                        if (depth == 2 && lastKey == "vulnerabilities") inArray = true;
                        break;
                    case ']':
                        depth--;
                        if (depth == 1 && inArray) inArray = false;
                        break;
                }
            }
        }

        static readonly Regex CritRx = new Regex("\"criteria\"\\s*:\\s*\"(cpe:2\\.3:(?:[^\"\\\\]|\\\\.)*)\"", RegexOptions.CultureInvariant);
        static readonly Regex IdRx = new Regex("\"id\"\\s*:\\s*\"(CVE-[0-9]+-[0-9]+)\"", RegexOptions.CultureInvariant);
        static readonly Regex ModRx = new Regex("\"lastModified\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.CultureInvariant);

        static TextReader OpenText(string path, Sha256Acc acc, out long bytes)
        {
            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
            bytes = fs.Length;
            Stream s = new TeeHashStream(fs, acc);
            if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) s = new GZipStream(s, CompressionMode.Decompress);
            return new StreamReader(s, new UTF8Encoding(false), true, 1 << 16);
        }

        public static List<string> ExpandFeeds(string[] paths)
        {
            List<string> o = new List<string>();
            foreach (string p in paths ?? new string[0])
            {
                if (string.IsNullOrWhiteSpace(p)) continue;
                if (Directory.Exists(p))
                {
                    List<string> l = new List<string>();
                    foreach (string f in Directory.GetFiles(p)) if (Regex.IsMatch(Path.GetFileName(f), @"\.json(\.gz)?$", RegexOptions.IgnoreCase)) l.Add(f);
                    l.Sort(StringComparer.OrdinalIgnoreCase);
                    o.AddRange(l);
                }
                else if (File.Exists(p)) o.Add(p);
                else throw new FileNotFoundException("NVD feed not found: " + p);
            }
            if (o.Count == 0) throw new ArgumentException("no NVD feed files (nvdcve-2.0-*.json[.gz]) were given");
            return o;
        }

        // ---------------------------------------------------------------- matching one CVE record
        static bool Covers(Dictionary<string, object> m, Cpe e, out string how)
        {
            how = null;
            Cpe c = Cpe.Parse(StoreUtil.Str(m, "criteria"));
            if (c == null || c.Part != e.Part || c.Vendor != e.Vendor || c.Product != e.Product) return false;
            string si = StoreUtil.Str(m, "versionStartIncluding"), se = StoreUtil.Str(m, "versionStartExcluding");
            string ei = StoreUtil.Str(m, "versionEndIncluding"), ee = StoreUtil.Str(m, "versionEndExcluding");
            bool ranged = si.Length + se.Length + ei.Length + ee.Length > 0;
            if (!e.VersionKnown) { how = "product-only"; return true; }
            string ev = e.Full;
            if (!Cpe.Any(c.Version))
            {
                if (Cpe.Any(c.Update))
                {
                    // 8.9 with update '*' covers 8.9p1; update '-' means exactly 8.9
                    if (VersionCmp.Compare(ev, c.Version) == 0) { how = "version"; return true; }
                    if (c.Update == "*" && ev.StartsWith(c.Version, StringComparison.OrdinalIgnoreCase) && ev.Length > c.Version.Length && char.IsLetter(ev[c.Version.Length])) { how = "version"; return true; }
                    return false;
                }
                if (VersionCmp.Compare(ev, c.Version + c.Update) == 0 || string.Equals(ev, c.Version + c.Update, StringComparison.OrdinalIgnoreCase)) { how = "version"; return true; }
                return false;
            }
            if (!ranged) { how = "all-versions"; return true; }
            if (si.Length > 0 && VersionCmp.Compare(ev, si) < 0) return false;
            if (se.Length > 0 && VersionCmp.Compare(ev, se) <= 0) return false;
            if (ei.Length > 0 && VersionCmp.Compare(ev, ei) > 0) return false;
            if (ee.Length > 0 && VersionCmp.Compare(ev, ee) >= 0) return false;
            how = "range"; return true;
        }
        static bool Unconstrained(Dictionary<string, object> m)
        {
            Cpe c = Cpe.Parse(StoreUtil.Str(m, "criteria"));
            return c != null && Cpe.Any(c.Version) && StoreUtil.Str(m, "versionStartIncluding").Length + StoreUtil.Str(m, "versionStartExcluding").Length
                + StoreUtil.Str(m, "versionEndIncluding").Length + StoreUtil.Str(m, "versionEndExcluding").Length == 0;
        }
        static int Rank(string how) { switch (how) { case "version": case "range": return 3; case "all-versions": return 2; default: return 1; } }

        static List<object> Arr(Dictionary<string, object> o, string k) { return StoreUtil.Field(o, k) as List<object>; }

        // best match of one service against one CVE's configurations ("" = no match)
        static string Evaluate(Dictionary<string, object> cve, Service s, out Cpe matched)
        {
            matched = null;
            string best = null; int bestRank = 0;
            List<object> configs = Arr(cve, "configurations");
            if (configs == null) return "";
            foreach (object co in configs)
            {
                Dictionary<string, object> conf = co as Dictionary<string, object>;
                List<object> nodes = Arr(conf, "nodes");
                if (nodes == null) continue;
                bool andConf = StoreUtil.Str(conf, "operator").Equals("AND", StringComparison.OrdinalIgnoreCase);
                // the node holding a vulnerable entry this service matches; in an AND configuration the other nodes are
                // platform requirements, checked against this service's other CPEs
                for (int ni = 0; ni < nodes.Count; ni++)
                {
                    Dictionary<string, object> node = nodes[ni] as Dictionary<string, object>;
                    if (node == null || StoreUtil.Str(node, "negate") == "True") continue;
                    List<object> ms = Arr(node, "cpeMatch");
                    if (ms == null) continue;
                    bool nodeAnd = StoreUtil.Str(node, "operator").Equals("AND", StringComparison.OrdinalIgnoreCase);
                    foreach (Cpe e in s.Cpes)
                    {
                        string how = null;
                        foreach (object mo in ms)
                        {
                            Dictionary<string, object> m = mo as Dictionary<string, object>;
                            if (m == null || StoreUtil.Str(m, "vulnerable") != "True") continue;
                            string h;
                            if (Covers(m, e, out h) && (how == null || Rank(h) > Rank(how))) how = h;
                        }
                        if (how == null || nodeAnd) continue;   // an AND node needs every entry: not decidable from one service
                        bool platformOk = true;
                        if (andConf && nodes.Count > 1)
                            for (int nj = 0; nj < nodes.Count; nj++)
                            {
                                if (nj == ni) continue;
                                if (!NodeSatisfied(nodes[nj] as Dictionary<string, object>, s, e)) { platformOk = false; break; }
                            }
                        string label = how + (platformOk ? "" : " (platform not verified)")
                            + (e.Alias.Length > 0 ? " (as " + e.Vendor + ":" + e.Product + ")" : "");
                        int rank = Rank(how) * 2 + (platformOk ? 1 : 0);
                        if (rank > bestRank) { bestRank = rank; best = label; matched = e; }
                    }
                }
            }
            return best ?? "";
        }
        static bool NodeSatisfied(Dictionary<string, object> node, Service s, Cpe exclude)
        {
            List<object> ms = Arr(node, "cpeMatch");
            if (ms == null) return false;
            bool nodeAnd = StoreUtil.Str(node, "operator").Equals("AND", StringComparison.OrdinalIgnoreCase);
            int hits = 0;
            foreach (object mo in ms)
            {
                Dictionary<string, object> m = mo as Dictionary<string, object>;
                bool any = false;
                foreach (Cpe e in s.Cpes)
                {
                    if (exclude != null && e.Root == exclude.Root) continue;   // the matched CPE (or an alias copy of it) is no platform for itself
                    string h;
                    // a platform entry that names no version (windows:-, linux_kernel:*) is met by the product alone
                    if (Covers(m, e, out h) && (h != "product-only" || Unconstrained(m))) { any = true; break; }
                }
                if (any) { hits++; if (!nodeAnd) return true; }
                else if (nodeAnd) return false;
            }
            return nodeAnd && hits == ms.Count && hits > 0;
        }

        static void Metrics(Dictionary<string, object> cve, CveInfo ci)
        {
            Dictionary<string, object> metrics = StoreUtil.Field(cve, "metrics") as Dictionary<string, object>;
            if (metrics == null) return;
            foreach (string[] k in new[] { new[] { "cvssMetricV31", "3.1" }, new[] { "cvssMetricV40", "4.0" }, new[] { "cvssMetricV30", "3.0" }, new[] { "cvssMetricV2", "2.0" } })
            {
                List<object> l = Arr(metrics, k[0]);
                if (l == null || l.Count == 0) continue;
                Dictionary<string, object> pick = null;
                foreach (object o in l) { Dictionary<string, object> d = o as Dictionary<string, object>; if (d != null && StoreUtil.Str(d, "type") == "Primary") { pick = d; break; } }
                if (pick == null) pick = l[0] as Dictionary<string, object>;
                Dictionary<string, object> data = StoreUtil.Field(pick, "cvssData") as Dictionary<string, object>;
                if (data == null) continue;
                ci.Score = StoreUtil.Str(data, "baseScore");
                ci.Severity = StoreUtil.Str(data, "baseSeverity");
                if (ci.Severity.Length == 0) ci.Severity = StoreUtil.Str(pick, "baseSeverity");
                ci.CvssVersion = k[1];
                return;
            }
        }

        // ---------------------------------------------------------------- alias names
        // NVD files one product under several names over time (vendor renames such as pulsesecure -> ivanti, product
        // renames, firmware vs software entries). Each group from the script's CPE supplement is one product: a service's
        // CPE is also compared under the other names of its group, with the same version.
        static Dictionary<string, string[]> aliases = new Dictionary<string, string[]>(StringComparer.Ordinal);
        static string aliasVersion = "";
        // general-purpose operating systems (Ubuntu, Windows Server 2012, ...): their patch level is not visible remotely,
        // so a match without a version would list every KEV entry of the release; such rows are counted, not listed
        static List<string> platforms = new List<string>();
        static bool IsPlatform(Cpe c)
        {
            if (c == null) return false;
            foreach (string k in new[] { c.Key, c.Root.Key })
                foreach (string p in platforms)
                    if (p.EndsWith("*", StringComparison.Ordinal) ? k.StartsWith(p.Substring(0, p.Length - 1), StringComparison.Ordinal) : k == p) return true;
            return false;
        }
        public static int SetAliases(string supplementJson)
        {
            Dictionary<string, string[]> m = new Dictionary<string, string[]>(StringComparer.Ordinal);
            Dictionary<string, object> o = string.IsNullOrEmpty(supplementJson) ? null : StoreJson.Parse(supplementJson) as Dictionary<string, object>;
            List<object> groups = o != null ? StoreUtil.Field(o, "aliases") as List<object> : null;
            if (groups != null)
                foreach (object g in groups)
                {
                    List<object> gl = g as List<object>;
                    if (gl == null || gl.Count < 2) continue;
                    List<string> keys = new List<string>();
                    foreach (object k in gl) { string ks = Convert.ToString(k, CultureInfo.InvariantCulture).ToLowerInvariant(); if (ks.Split(':').Length >= 3 && !keys.Contains(ks)) keys.Add(ks); }
                    foreach (string k in keys)
                    {
                        List<string> others = new List<string>();
                        string[] prev;
                        if (m.TryGetValue(k, out prev)) others.AddRange(prev);
                        foreach (string x in keys) if (x != k && !others.Contains(x)) others.Add(x);
                        m[k] = others.ToArray();
                    }
                }
            List<string> pl = new List<string>();
            List<object> pls = o != null ? StoreUtil.Field(o, "platforms") as List<object> : null;
            if (pls != null) foreach (object x in pls) { string ps = Convert.ToString(x, CultureInfo.InvariantCulture).ToLowerInvariant(); if (ps.Length > 0) pl.Add(ps); }
            aliases = m; platforms = pl;
            aliasVersion = o != null ? StoreUtil.Str(o, "version") : "";
            return m.Count;
        }

        // ---------------------------------------------------------------- the query
        public static VulnResult Run(List<Service> services, string[] nvdPaths, string kevPath, string epssPath, List<RowFilter> filters, string storeId, string lastRun)
        {
            VulnResult res = new VulnResult(); res.Columns = Columns;
            // inventory side: vendor:product -> services
            Dictionary<string, List<Service>> byKey = new Dictionary<string, List<Service>>(StringComparer.Ordinal);
            HashSet<string> vp = new HashSet<string>(StringComparer.Ordinal);
            int withCpe = 0, unversioned = 0, aliasCopies = 0;
            Dictionary<string, string[]> al = aliases;
            foreach (Service s in services)
            {
                if (s.Cpes.Count == 0) continue;
                withCpe++;
                bool anyVer = false;
                List<Cpe> own = new List<Cpe>(s.Cpes);
                HashSet<string> have = new HashSet<string>(StringComparer.Ordinal);
                foreach (Cpe c in own) have.Add(c.Key);
                foreach (Cpe c in own)
                {
                    string[] names;
                    if (!al.TryGetValue(c.Key, out names)) continue;
                    foreach (string a in names) if (have.Add(a)) { s.Cpes.Add(c.As(a)); aliasCopies++; }
                }
                foreach (Cpe c in s.Cpes)
                {
                    if (c.VersionKnown) anyVer = true;
                    List<Service> l;
                    if (!byKey.TryGetValue(c.Key, out l)) { l = new List<Service>(); byKey[c.Key] = l; }
                    if (!l.Contains(s)) l.Add(s);
                    vp.Add(c.Vendor + ":" + c.Product);
                }
                if (!anyVer) unversioned++;
            }
            // feeds
            List<string> files = ExpandFeeds(nvdPaths);
            Dictionary<string, string> lastMod = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, CveInfo> found = new Dictionary<string, CveInfo>(StringComparer.Ordinal);
            List<string> feedProv = new List<string>();
            long records = 0, parsed = 0;
            foreach (string f in files)
            {
                Sha256Acc acc = new Sha256Acc();
                long bytes, n = 0;
                using (TextReader tr = OpenText(f, acc, out bytes))
                {
                    foreach (string rec in FeedRecords(tr))
                    {
                        n++; records++;
                        Match im = IdRx.Match(rec);
                        if (!im.Success) continue;
                        string id = im.Groups[1].Value;
                        Match mm = ModRx.Match(rec);
                        string mod = mm.Success ? mm.Groups[1].Value : "";
                        string seen;
                        if (lastMod.TryGetValue(id, out seen) && string.CompareOrdinal(seen, mod) >= 0) continue;   // an equal or newer copy was read already
                        lastMod[id] = mod;
                        bool cand = false;
                        foreach (Match cm in CritRx.Matches(rec))
                        {
                            Cpe c = Cpe.Parse(cm.Groups[1].Value.Replace("\\\\", "\\"));
                            if (c != null && vp.Contains(c.Vendor + ":" + c.Product)) { cand = true; break; }
                        }
                        if (!cand) { found.Remove(id); continue; }
                        Dictionary<string, object> o = StoreJson.Parse(rec) as Dictionary<string, object>;
                        Dictionary<string, object> cve = StoreUtil.Field(o, "cve") as Dictionary<string, object>;
                        if (cve == null) continue;
                        parsed++;
                        found.Remove(id);
                        if (StoreUtil.Str(cve, "vulnStatus").Equals("Rejected", StringComparison.OrdinalIgnoreCase)) continue;
                        CveInfo ci = new CveInfo();
                        ci.Id = id; ci.LastModified = mod; ci.Published = StoreUtil.Str(cve, "published");
                        HashSet<Service> tried = new HashSet<Service>();
                        foreach (Match cm in CritRx.Matches(rec))
                        {
                            Cpe c = Cpe.Parse(cm.Groups[1].Value.Replace("\\\\", "\\"));
                            List<Service> l;
                            if (c == null || !byKey.TryGetValue(c.Key, out l)) continue;
                            foreach (Service s in l)
                            {
                                if (!tried.Add(s)) continue;
                                Cpe which;
                                string how = Evaluate(cve, s, out which);
                                if (how.Length > 0) { Hit h = new Hit(); h.Svc = s; h.Cpe = which; h.Match = how; ci.Hits.Add(h); }
                            }
                        }
                        if (ci.Hits.Count == 0) continue;
                        Metrics(cve, ci);
                        List<object> descs = Arr(cve, "descriptions");
                        if (descs != null)
                            foreach (object d in descs)
                            {
                                Dictionary<string, object> dd = d as Dictionary<string, object>;
                                if (StoreUtil.Str(dd, "lang") == "en") { ci.Description = StoreUtil.Str(dd, "value"); break; }
                            }
                        found[id] = ci;
                    }
                }
                feedProv.Add(new JsonObj().Str("file", Path.GetFileName(f)).Str("sha256", acc.FinalHex()).Num("bytes", bytes).Num("records", n).ToString());
            }
            // KEV and EPSS
            Dictionary<string, string[]> kev = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            string kevProv = "null", epssProv = "null";
            if (!string.IsNullOrEmpty(kevPath)) kevProv = LoadKev(kevPath, kev);
            Dictionary<string, string[]> epss = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrEmpty(epssPath)) epssProv = LoadEpss(epssPath, found, epss);
            // rows: product-only matches (service version unknown) are kept only for KEV-listed CVEs
            int dropped = 0, droppedOs = 0;
            List<KeyValuePair<double[], string[]>> rows = new List<KeyValuePair<double[], string[]>>();
            foreach (CveInfo ci in found.Values)
            {
                string[] k; kev.TryGetValue(ci.Id, out k);
                string[] ep; epss.TryGetValue(ci.Id, out ep);
                foreach (Hit h in ci.Hits)
                {
                    if (h.Match.StartsWith("product-only", StringComparison.Ordinal) && k == null) { dropped++; continue; }
                    if (h.Match.StartsWith("product-only", StringComparison.Ordinal) && IsPlatform(h.Cpe)) { droppedOs++; continue; }
                    Dictionary<string, string> r = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    r["Host"] = h.Svc.Host; r["IP"] = h.Svc.Ip; r["Port"] = h.Svc.Port; r["Url"] = h.Svc.Url; r["Status"] = h.Svc.Status; r["Products"] = h.Svc.Products;
                    r["Cpe"] = h.Cpe != null ? h.Cpe.Raw : ""; r["Cve"] = ci.Id; r["Kev"] = k != null ? "Yes" : "";
                    r["KevDateAdded"] = k != null ? k[0] : ""; r["KevDueDate"] = k != null ? k[1] : ""; r["KevRansomware"] = k != null ? k[2] : "";
                    r["Epss"] = ep != null ? ep[0] : ""; r["EpssPercentile"] = ep != null ? ep[1] : "";
                    r["CvssScore"] = ci.Score; r["CvssSeverity"] = ci.Severity; r["CvssVersion"] = ci.CvssVersion; r["Published"] = ci.Published.Length >= 10 ? ci.Published.Substring(0, 10) : ci.Published;
                    r["Match"] = h.Match; r["EntityId"] = h.Svc.EntityId;
                    r["Description"] = ci.Description.Length > 400 ? ci.Description.Substring(0, 400) + "..." : ci.Description;
                    if (!RowFilter.All(filters, r)) continue;
                    double ev, sc;
                    double.TryParse(r["Epss"], NumberStyles.Float, CultureInfo.InvariantCulture, out ev);
                    double.TryParse(r["CvssScore"], NumberStyles.Float, CultureInfo.InvariantCulture, out sc);
                    string[] row = new string[Columns.Length];
                    for (int i = 0; i < Columns.Length; i++) { string v; row[i] = r.TryGetValue(Columns[i], out v) ? v : ""; }
                    rows.Add(new KeyValuePair<double[], string[]>(new[] { k != null ? 1.0 : 0.0, ev, sc }, row));
                }
            }
            rows.Sort(delegate(KeyValuePair<double[], string[]> a, KeyValuePair<double[], string[]> b)
            {
                for (int i = 0; i < 3; i++) { int c = b.Key[i].CompareTo(a.Key[i]); if (c != 0) return c; }
                int x = string.Compare(a.Value[0], b.Value[0], StringComparison.OrdinalIgnoreCase); if (x != 0) return x;
                int pa, pb; int.TryParse(a.Value[2], out pa); int.TryParse(b.Value[2], out pb); if (pa != pb) return pa.CompareTo(pb);
                return string.CompareOrdinal(a.Value[7], b.Value[7]);
            });
            foreach (KeyValuePair<double[], string[]> kvp in rows) res.Rows.Add(kvp.Value);
            int kevRows = 0; foreach (string[] r2 in res.Rows) if (r2[8] == "Yes") kevRows++;
            res.Messages.Add(string.Format(CultureInfo.InvariantCulture, "{0} services with a CPE ({1} without a version); {2} NVD records read from {3} files, {4} matched; {5} service/CVE rows ({6} on the KEV list){7}",
                withCpe, unversioned, records, files.Count, found.Count, res.Rows.Count, kevRows,
                (dropped > 0 ? "; " + dropped + " version-unknown matches not listed (only KEV entries are listed when the service hides its version)" : "")
                + (droppedOs > 0 ? "; " + droppedOs + " KEV entries of general-purpose operating systems without a known version not listed (patch level not visible remotely)" : "")));
            res.Provenance = new JsonObj().Str("generated", StoreUtil.Iso(DateTimeOffset.Now)).Str("storeId", storeId).Str("inventoryAfterRun", lastRun)
                .Raw("nvd", "[" + string.Join(",", feedProv) + "]").Raw("kev", kevProv).Raw("epss", epssProv)
                .Raw("counts", new JsonObj().Num("servicesWithCpe", withCpe).Num("servicesWithoutVersion", unversioned).Num("nvdRecords", records).Num("nvdRecordsParsed", parsed)
                    .Num("cvesMatched", found.Count).Num("rows", res.Rows.Count).Num("kevRows", kevRows).Num("versionUnknownNotListed", dropped).Num("osVersionUnknownKevNotListed", droppedOs).Num("aliasNamesCompared", aliasCopies).ToString())
                .Raw("cpeAliases", new JsonObj().Str("supplement", aliasVersion).Num("names", al.Count).Num("platforms", platforms.Count).ToString())
                .Str("method", "CPE 2.3 vendor/product match (plus the other NVD names of the same product from the CPE supplement); version, update and NVD ranges compared numerically; AND configurations check platform nodes against the same service's other CPEs; version-unknown services listed only for KEV CVEs, and not for general-purpose operating systems").ToString();
            return res;
        }

        static string LoadKev(string path, Dictionary<string, string[]> kev)
        {
            long bytes;
            string sha = StoreUtil.FileSha256(path, out bytes);
            string text = StoreUtil.ReadText(path);
            string catalog = "", released = "";
            if (text.TrimStart().StartsWith("{", StringComparison.Ordinal))
            {
                Dictionary<string, object> o = StoreJson.Parse(text) as Dictionary<string, object>;
                catalog = StoreUtil.Str(o, "catalogVersion"); released = StoreUtil.Str(o, "dateReleased");
                List<object> l = StoreUtil.Field(o, "vulnerabilities") as List<object>;
                if (l == null) throw new InvalidDataException("KEV file has no 'vulnerabilities' array: " + path);
                foreach (object x in l)
                {
                    Dictionary<string, object> d = x as Dictionary<string, object>;
                    string id = StoreUtil.Str(d, "cveID");
                    if (id.Length > 0) kev[id] = new[] { StoreUtil.Str(d, "dateAdded"), StoreUtil.Str(d, "dueDate"), StoreUtil.Str(d, "knownRansomwareCampaignUse") };
                }
            }
            else
            {
                string[] head = null;
                foreach (string line in CsvLines(text))
                {
                    string[] f = SplitCsv(line);
                    if (head == null) { head = f; continue; }
                    int ic = Array.IndexOf(head, "cveID"), ia = Array.IndexOf(head, "dateAdded"), idue = Array.IndexOf(head, "dueDate"), ir = Array.IndexOf(head, "knownRansomwareCampaignUse");
                    if (ic < 0) throw new InvalidDataException("KEV CSV has no cveID column: " + path);
                    if (f.Length > ic && f[ic].Length > 0) kev[f[ic]] = new[] { ia >= 0 && f.Length > ia ? f[ia] : "", idue >= 0 && f.Length > idue ? f[idue] : "", ir >= 0 && f.Length > ir ? f[ir] : "" };
                }
            }
            return new JsonObj().Str("file", Path.GetFileName(path)).Str("sha256", sha).Num("bytes", bytes).Str("catalogVersion", catalog).Str("dateReleased", released).Num("entries", kev.Count).ToString();
        }

        static string LoadEpss(string path, Dictionary<string, CveInfo> want, Dictionary<string, string[]> epss)
        {
            long bytes;
            string sha = StoreUtil.FileSha256(path, out bytes);
            string model = "", date = ""; long n = 0;
            int ic = -1, ie = -1, ip = -1;
            foreach (string line in StoreUtil.ReadLines(path))
            {
                if (line.StartsWith("#", StringComparison.Ordinal))
                {
                    Match m1 = Regex.Match(line, @"model_version:([^,]+)"), m2 = Regex.Match(line, @"score_date:([^,\s]+)");
                    if (m1.Success) model = m1.Groups[1].Value.Trim(); if (m2.Success) date = m2.Groups[1].Value.Trim();
                    continue;
                }
                string[] f = line.Split(',');
                if (ic < 0) { ic = Array.IndexOf(f, "cve"); ie = Array.IndexOf(f, "epss"); ip = Array.IndexOf(f, "percentile"); if (ic < 0 || ie < 0) throw new InvalidDataException("EPSS file has no cve/epss header: " + path); continue; }
                n++;
                if (f.Length <= Math.Max(ic, Math.Max(ie, ip)) || !want.ContainsKey(f[ic])) continue;
                epss[f[ic]] = new[] { f[ie], ip >= 0 ? f[ip] : "" };
            }
            return new JsonObj().Str("file", Path.GetFileName(path)).Str("sha256", sha).Num("bytes", bytes).Str("modelVersion", model).Str("scoreDate", date).Num("rows", n).ToString();
        }

        static IEnumerable<string> CsvLines(string text)
        {
            // records may contain quoted newlines
            StringBuilder cur = new StringBuilder(); bool q = false;
            foreach (char ch in text)
            {
                if (ch == '"') q = !q;
                if ((ch == '\n') && !q) { string l = cur.ToString().TrimEnd('\r'); if (l.Length > 0) yield return l; cur.Length = 0; continue; }
                cur.Append(ch);
            }
            if (cur.Length > 0) yield return cur.ToString().TrimEnd('\r');
        }
        static string[] SplitCsv(string line)
        {
            List<string> f = new List<string>(); StringBuilder cur = new StringBuilder(); bool q = false;
            for (int i = 0; i < line.Length; i++)
            {
                char ch = line[i];
                if (q) { if (ch == '"') { if (i + 1 < line.Length && line[i + 1] == '"') { cur.Append('"'); i++; } else q = false; } else cur.Append(ch); }
                else if (ch == '"') q = true;
                else if (ch == ',') { f.Add(cur.ToString()); cur.Length = 0; }
                else cur.Append(ch);
            }
            f.Add(cur.ToString());
            return f.ToArray();
        }
    }

    // read-through stream that hashes every byte it passes on (feed provenance without a second read)
    sealed class TeeHashStream : Stream
    {
        readonly Stream inner; readonly Sha256Acc acc;
        public TeeHashStream(Stream s, Sha256Acc a) { inner = s; acc = a; }
        public override int Read(byte[] buffer, int offset, int count) { int n = inner.Read(buffer, offset, count); if (n > 0) acc.Append(buffer, offset, n); return n; }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return inner.Length; } }
        public override long Position { get { return inner.Position; } set { throw new NotSupportedException(); } }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }
}

// ============================================================================
// Store self-test helpers (used by -SelfTest): key-value engine conformance, SHA-256 accumulator vectors, and a
// synthetic three-run history. On Windows the same checks run against ESENT and the portable engine, and the
// self-test requires both to produce byte-identical change and state digests.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Text;

    public static class StoreSelfTest
    {
        static KvEngine Make(string engine, string dir)
        {
            switch (engine)
            {
                case "memory": return new FileKv(null);
                case "file": Directory.CreateDirectory(dir); return new FileKv(Path.Combine(dir, "inventory.kv"));
                case "esent": return new EsentKv(dir);
            }
            throw new ArgumentException(engine);
        }
        static string Hex(byte[] b) { return StoreUtil.Hex(b); }
        static string Dump(KvEngine kv)
        {
            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(new byte[0])) sb.Append(Hex(e.Key)).Append('=').Append(e.Value.Length).Append(':').Append(StoreUtil.Sha256Hex(e.Value).Substring(0, 8)).Append(';');
            return sb.ToString();
        }
        static bool Throws(Action a) { try { a(); return false; } catch (Exception) { return true; } }

        // returns "" when the engine meets the KvEngine contract, else the first deviation
        public static string KvConformance(string engine, string dir)
        {
            KvEngine kv = Make(engine, dir);
            try
            {
                List<byte[]> keys = new List<byte[]>();
                foreach (string s in new[] { "a", "ab", "b", "a\u0001", "abc", "c" }) keys.Add(StoreUtil.B(s));
                keys.Add(new byte[] { (byte)'a', 0 }); keys.Add(new byte[] { (byte)'a', 0, (byte)'b' }); keys.Add(new byte[] { 0xff });
                keys.Add(new byte[] { 0x00, 0x01 }); keys.Add(new byte[] { 0x7f, 0x80, 0xfe });
                byte[] longKey = new byte[KvEngine.MaxKey]; for (int i = 0; i < longKey.Length; i++) longKey[i] = (byte)(i % 251 + 1);
                keys.Add(longKey);
                byte[] longKey2 = (byte[])longKey.Clone(); longKey2[KvEngine.MaxKey - 1]++;
                keys.Add(longKey2);
                Random rnd = new Random(5);
                Dictionary<byte[], byte[]> model = new Dictionary<byte[], byte[]>(ByteOrder.Instance);
                kv.Begin();
                int n = 0;
                foreach (byte[] k in keys)
                {
                    byte[] v = new byte[n == 3 ? 0 : (n == 5 ? 200000 : rnd.Next(1, 300))];
                    rnd.NextBytes(v);
                    kv.Put(k, v); model[k] = v; n++;
                }
                for (int i = 0; i < 3000; i++)
                {
                    byte[] k = StoreUtil.B("p\0" + rnd.Next(0, 1000000).ToString("D7", CultureInfo.InvariantCulture));
                    byte[] v = StoreUtil.B(i.ToString(CultureInfo.InvariantCulture));
                    kv.Put(k, v); model[k] = v;
                }
                kv.Commit(true);
                List<byte[]> sorted = new List<byte[]>(model.Keys); sorted.Sort(ByteOrder.Instance);
                string want = Expect(sorted, model);
                string got = Dump(kv);
                if (got != want) return "full scan order/content differs from the reference ordering";
                foreach (byte[] k in keys) { byte[] v = kv.Get(k); if (v == null || !ByteOrder.Instance.Equals(v, model[k])) return "Get(" + Hex(k) + ") returned the wrong value"; }
                if (kv.Get(StoreUtil.B("zz")) != null) return "Get of a missing key returned a value";
                // prefix scans and paging after a key
                List<KeyValuePair<byte[], byte[]>> pa = kv.ScanPage(StoreUtil.B("a"), null, 100);
                string pas = Keys(pa);
                string pexp = Keys(Filter(sorted, model, StoreUtil.B("a"), null));
                if (pas != pexp) return "prefix scan 'a' differs: " + pas + " vs " + pexp;
                List<KeyValuePair<byte[], byte[]>> pb = kv.ScanPage(StoreUtil.B("a"), new byte[] { (byte)'a', 0 }, 100);
                if (Keys(pb) != Keys(Filter(sorted, model, StoreUtil.B("a"), new byte[] { (byte)'a', 0 }))) return "scan after a key differs";
                int count = 0; byte[] last = null;
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(StoreUtil.B("p\0")))
                {
                    if (last != null && ByteOrder.Instance.Compare(last, e.Key) >= 0) return "paged scan out of order";
                    last = e.Key; count++;
                }
                int pcount = 0; foreach (byte[] k in sorted) if (KvEngine.StartsWith(k, StoreUtil.B("p\0"))) pcount++;
                if (count != pcount) return "paged scan returned " + count + " of " + pcount + " keys";
                if (kv.ScanPage(StoreUtil.B("q"), null, 10).Count != 0) return "scan of an absent prefix returned rows";
                // rollback restores everything; commit applies
                string before = Dump(kv);
                kv.Begin();
                kv.Put(StoreUtil.B("ab"), new byte[] { 1, 2, 3 }); kv.Delete(StoreUtil.B("b")); kv.Put(StoreUtil.B("new"), new byte[] { 9 }); kv.Delete(StoreUtil.B("new"));
                kv.Put(StoreUtil.B("new2"), new byte[] { 9 });
                kv.Rollback();
                if (Dump(kv) != before) return "rollback did not restore the previous state";
                kv.Begin();
                if (!kv.Delete(new byte[] { (byte)'a', 0, (byte)'b' })) return "Delete of an existing key returned false";
                if (kv.Delete(StoreUtil.B("missing"))) return "Delete of a missing key returned true";
                kv.Put(StoreUtil.B("c"), new byte[0]);
                kv.Commit(true);
                model.Remove(new byte[] { (byte)'a', 0, (byte)'b' }); model[StoreUtil.B("c")] = new byte[0];
                sorted = new List<byte[]>(model.Keys); sorted.Sort(ByteOrder.Instance);
                want = Expect(sorted, model);
                if (Dump(kv) != want) return "state after delete/overwrite differs";
                // contract violations are refused
                KvEngine k2 = kv;
                if (!Throws(delegate { k2.Put(StoreUtil.B("x"), new byte[1]); })) return "write outside a transaction was accepted";
                k2.Begin();
                if (!Throws(delegate { k2.Put(new byte[KvEngine.MaxKey + 1], new byte[1]); })) return "over-long key was accepted";
                if (!Throws(delegate { k2.Put(new byte[0], new byte[1]); })) return "empty key was accepted";
                if (!Throws(delegate { k2.Begin(); })) return "nested transaction was accepted";
                k2.Rollback();
                // durability: reopen
                if (engine != "memory")
                {
                    kv.Dispose();
                    kv = Make(engine, dir);
                    if (Dump(kv) != want) return "state after reopen differs";
                }
                return "";
            }
            catch (Exception ex) { return "exception: " + ex.GetType().Name + ": " + ex.Message; }
            finally { kv.Dispose(); }
        }
        static string Expect(List<byte[]> sorted, Dictionary<byte[], byte[]> model)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte[] k in sorted) sb.Append(Hex(k)).Append('=').Append(model[k].Length).Append(':').Append(StoreUtil.Sha256Hex(model[k]).Substring(0, 8)).Append(';');
            return sb.ToString();
        }
        static List<KeyValuePair<byte[], byte[]>> Filter(List<byte[]> sorted, Dictionary<byte[], byte[]> model, byte[] prefix, byte[] after)
        {
            List<KeyValuePair<byte[], byte[]>> r = new List<KeyValuePair<byte[], byte[]>>();
            foreach (byte[] k in sorted)
                if (KvEngine.StartsWith(k, prefix) && (after == null || ByteOrder.Instance.Compare(k, after) > 0)) r.Add(new KeyValuePair<byte[], byte[]>(k, model[k]));
            return r;
        }
        static string Keys(List<KeyValuePair<byte[], byte[]>> l) { StringBuilder sb = new StringBuilder(); foreach (KeyValuePair<byte[], byte[]> e in l) sb.Append(Hex(e.Key)).Append(','); return sb.ToString(); }

        // SHA-256: known vectors on both paths, then the managed accumulator (fed in random-sized pieces) against the
        // platform provider at every block-boundary length
        public static string HashCheck()
        {
            foreach (bool managed in new[] { false, true })
                using (Sha256Acc a = new Sha256Acc(managed))
                {
                    a.Append(StoreUtil.B("abc"));
                    if (a.FinalHex() != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") return "abc vector (" + (managed ? "managed" : "platform") + ")";
                    if (a.FinalHex() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") return "empty vector after reset (" + (managed ? "managed" : "platform") + ")";
                    a.Append(StoreUtil.B("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
                    if (a.FinalHex() != "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") return "448-bit vector (" + (managed ? "managed" : "platform") + ")";
                }
            Random r = new Random(3);
            foreach (int len in new[] { 0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1000, 70000 })
            {
                byte[] d = new byte[len]; r.NextBytes(d);
                string want;
                using (Sha256Acc p = new Sha256Acc()) { p.Append(d); want = p.FinalHex(); }
                using (Sha256Acc a = new Sha256Acc(true))
                {
                    int i = 0;
                    while (i < len) { int c = Math.Min(r.Next(1, 97), len - i); a.Append(d, i, c); i += c; }
                    if (a.FinalHex() != want) return "managed accumulator differs from the platform at length " + len;
                }
            }
            return "";
        }

        // Three synthetic runs: run 2 changes titles, drops, adds and moves named hosts; run 3 is a -NoTlsScan run that
        // brings some services back. Returns the sources in run order.
        public static RunSources[] WriteRuns(string dir, int n)
        {
            List<RunSources> list = new List<RunSources>();
            string[] ids = { "20260105_080000", "20260106_080000", "20260107_080000" };
            for (int k = 0; k < 3; k++)
            {
                string d = Path.Combine(dir, "run" + (k + 1));
                Directory.CreateDirectory(d);
                string b = Path.Combine(d, "WebInventory_" + ids[k]);
                List<string> rows = new List<string>(), chk = new List<string>();
                for (int i = 0; i < n; i++)
                {
                    bool named = i % 20 == 0;
                    string ip = "10.9." + (i / 250).ToString(CultureInfo.InvariantCulture) + "." + (i % 250 + 1).ToString(CultureInfo.InvariantCulture);
                    if (named && k >= 1 && i % 40 == 0) ip = "10.8." + (i / 250).ToString(CultureInfo.InvariantCulture) + "." + (i % 250 + 1).ToString(CultureInfo.InvariantCulture);   // moved
                    string host = named ? "svc" + i.ToString(CultureInfo.InvariantCulture) + ".test.local" : ip;
                    int port = i % 3 == 0 ? 443 : 80;
                    chk.Add(host + "|" + ip + "|" + port.ToString(CultureInfo.InvariantCulture));
                    bool gone = (k == 1 && i % 33 == 5) || (k == 2 && i % 33 == 5 && i % 2 == 0);
                    if (gone) continue;
                    bool tls = port == 443;
                    JsonObj o = new JsonObj().Str("RunId", ids[k]).Str("ScanTag", "selftest").Str("ScannedAt", "2026-01-0" + (5 + k) + "T08:00:01").Str("Host", host).Str("IP", ip)
                        .Num("Port", port).Bool("Vhost", false).Str("VhostOf", "").Str("State", "open").Bool("IsWeb", true).Str("Service", tls ? "https" : "http")
                        .Str("Scheme", tls ? "https" : "http").Str("Url", (tls ? "https://" : "http://") + host + ":" + port + "/")
                        .Num("StatusCode", 200).Str("Title", "Service " + (i % 17) + (k >= 1 && i % 25 == 1 ? " (updated)" : ""))
                        .Str("Server", "nginx/1." + (i % 9)).Str("Products", "nginx 1." + (i % 9)).Str("Technologies", "nginx").Num("ResponseMs", 10 + (i * 7 + k) % 300)
                        .Str("BodySha256", StoreUtil.Sha256Hex(StoreUtil.B(i + "/" + k)));
                    if (tls)
                    {
                        o.Str("TlsVersion", "Tls12").Str("CertSha256", StoreUtil.Sha256Hex(StoreUtil.B("cert" + i))).Str("CertNotAfter", "2026-02-01T00:00:00").Num("CertDaysLeft", 27 - k)
                         .Str("Flags", "CertExpiring:" + (27 - k) + "d");
                        if (k != 2) o.Str("TlsSupported", "TLS1.2,TLS1.3").Str("Alpn", "h2").Bool("Http2", true);
                    }
                    rows.Add(o.Raw("Detections", "[]").ToString());
                }
                if (k == 1) for (int j = 0; j < n / 50; j++)
                    {
                        string ip = "10.7.0." + (j + 1).ToString(CultureInfo.InvariantCulture);
                        chk.Add(ip + "|" + ip + "|80");
                        rows.Add(new JsonObj().Str("RunId", ids[k]).Str("Host", ip).Str("IP", ip).Num("Port", 80).Bool("Vhost", false).Str("State", "open").Bool("IsWeb", true)
                            .Str("Url", "http://" + ip + ":80/").Str("Title", "New " + j).Raw("Detections", "[]").ToString());
                    }
                File.WriteAllText(b + ".jsonl", string.Join("\n", rows) + "\n", StoreUtil.Utf8);
                File.WriteAllText(b + "_progress.txt", string.Join("\n", chk) + "\n", StoreUtil.Utf8);
                RunInfo ri = new RunInfo();
                ri.RunId = ids[k]; ri.StartedAt = "2026-01-0" + (5 + k) + "T08:00:00+00:00"; ri.FinishedAt = ri.StartedAt; ri.Scanner = "selftest"; ri.Tag = "selftest";
                ri.TlsScan = k != 2; ri.ReverseDns = true; ri.ProbeSans = true; ri.Options = true; ri.IdentifyPaths = true; ri.Checks = chk.Count;
                File.WriteAllText(b + "_run.json", ri.ToJson() + "\n", StoreUtil.Utf8);
                RunSources s = new RunSources(); s.RunId = ids[k]; s.Jsonl = b + ".jsonl"; s.Progress = b + "_progress.txt"; s.RunJson = b + "_run.json";
                list.Add(s);
            }
            return list.ToArray();
        }

        // seq:runId:changes:state for every run in a store's ledger (what must be identical across engines and after repair)
        public static string LedgerDigests(string root)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string l in StoreUtil.ReadLines(Path.Combine(Path.Combine(root, "archive"), "ledger.jsonl")))
            {
                Dictionary<string, object> o = StoreJson.Parse(l) as Dictionary<string, object>;
                string ty = StoreUtil.Str(o, "type");
                if (ty == "rebase")
                {
                    // a rebase restates every position: list its plan instead
                    sb.Append("rebase\n");
                    foreach (object it in (List<object>)StoreUtil.Field(o, "plan"))
                    {
                        Dictionary<string, object> d = (Dictionary<string, object>)it;
                        sb.Append(StoreUtil.Str(d, "runId")).Append(':').Append(StoreUtil.Str(d, "changesDigest")).Append(':').Append(StoreUtil.Str(d, "stateDigest")).Append('\n');
                    }
                    continue;
                }
                if (ty != "run" && ty != "correction") continue;
                sb.Append(StoreUtil.Str(o, "seq")).Append(':').Append(StoreUtil.Str(o, "runId")).Append(':').Append(StoreUtil.Str(o, "changesDigest")).Append(':').Append(StoreUtil.Str(o, "stateDigest")).Append('\n');
            }
            return sb.ToString();
        }
        // digest of the inventory after the last applied position (plan aware)
        public static string FinalState(string root)
        {
            string last = "";
            foreach (string l in StoreUtil.ReadLines(Path.Combine(Path.Combine(root, "archive"), "ledger.jsonl")))
            {
                Dictionary<string, object> o = StoreJson.Parse(l) as Dictionary<string, object>;
                string ty = StoreUtil.Str(o, "type");
                if (ty == "run" || ty == "correction") { if (StoreUtil.Str(o, "stateDigest").Length > 0) last = StoreUtil.Str(o, "stateDigest"); }
                else if (ty == "rebase") { List<object> pl = (List<object>)StoreUtil.Field(o, "plan"); last = StoreUtil.Str((Dictionary<string, object>)pl[pl.Count - 1], "stateDigest"); }
            }
            return last;
        }
        public static string LedgerCounts(string root)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string l in StoreUtil.ReadLines(Path.Combine(Path.Combine(root, "archive"), "ledger.jsonl")))
            {
                Dictionary<string, object> o = StoreJson.Parse(l) as Dictionary<string, object>;
                if (StoreUtil.Str(o, "type") != "run") continue;
                Dictionary<string, object> c = StoreUtil.Field(o, "counts") as Dictionary<string, object>;
                sb.Append(StoreUtil.Str(o, "seq"));
                foreach (string f in new[] { "rows", "added", "changed", "reappeared", "rekeyed", "missing", "retired", "active", "missingTotal", "retiredTotal" })
                    sb.Append(' ').Append(f).Append('=').Append(StoreUtil.Str(c, f));
                sb.Append('\n');
            }
            return sb.ToString();
        }
    
        // offline vulnerability correlation on a hand-made feed: exact, update, range, all-versions, platform (AND),
        // version-unknown (KEV only), rejected records and the newest copy of a record winning
        public static string VulnCheck(string dir)
        {
            List<string> bad = new List<string>();
            string[][] cmp = { new[] { "8.9p1", "9.3", "-1" }, new[] { "9.3p1", "9.3", "1" }, new[] { "2.0rc1", "2.0", "-1" }, new[] { "1.0.2k", "1.0.2", "1" },
                new[] { "2.4.49", "2.4.5", "1" }, new[] { "10.0", "10", "0" }, new[] { "15.2(7)E8", "15.2(7)E10", "-1" }, new[] { "1.18.0", "1.20.0", "-1" } };
            foreach (string[] c in cmp) if (VersionCmp.Compare(c[0], c[1]).ToString(CultureInfo.InvariantCulture) != c[2]) bad.Add("compare " + c[0] + " vs " + c[1]);
            Directory.CreateDirectory(dir);
            Func<string, string, string> rec = delegate(string id, string body) { return "{\"cve\":{\"id\":\"" + id + "\",\"published\":\"2026-01-01T00:00:00.000\",\"lastModified\":\"2026-02-01T00:00:00.000\",\"vulnStatus\":\"Analyzed\",\"descriptions\":[{\"lang\":\"en\",\"value\":\"test " + id + "\"}],\"metrics\":{\"cvssMetricV31\":[{\"type\":\"Primary\",\"cvssData\":{\"baseScore\":9.8,\"baseSeverity\":\"CRITICAL\"}}]},\"configurations\":" + body + "}}"; };
            Func<string, string> one = delegate(string m) { return "[{\"nodes\":[{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[" + m + "]}]}]"; };
            Func<string, string, string> cm = delegate(string crit, string extra) { return "{\"vulnerable\":true,\"criteria\":\"" + crit + "\"" + extra + ",\"matchCriteriaId\":\"X\"}"; };
            string feed = "{\"resultsPerPage\":9,\"format\":\"NVD_CVE\",\"vulnerabilities\":[" + string.Join(",", new[] {
                rec("CVE-2026-0001", one(cm("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", ",\"versionEndExcluding\":\"9.3p2\""))),
                rec("CVE-2026-0002", one(cm("cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*", ""))),
                rec("CVE-2026-0003", one(cm("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", ""))),
                rec("CVE-2026-0004", one(cm("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", ",\"versionStartIncluding\":\"2.4.50\",\"versionEndExcluding\":\"2.4.60\""))),
                rec("CVE-2026-0005", "[{\"operator\":\"AND\",\"nodes\":[{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[" + cm("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", ",\"versionEndExcluding\":\"8.1.29\"") + "]},{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[{\"vulnerable\":false,\"criteria\":\"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*\",\"matchCriteriaId\":\"Y\"}]}]}]"),
                rec("CVE-2026-0006", one(cm("cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*", ",\"versionEndIncluding\":\"2.441\""))),
                rec("CVE-2026-0007", one(cm("cpe:2.3:a:jenkins:jenkins:*:*:*:*:lts:*:*:*", ",\"versionEndIncluding\":\"2.426.2\""))),
                rec("CVE-2026-0008", one(cm("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", ""))).Replace("Analyzed", "Rejected"),
                rec("CVE-2026-0009", one(cm("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", ""))),
                // filed under the product's former NVD name (alias), and percent-encoded rule data (tcp%2fip == tcp\/ip)
                rec("CVE-2026-0010", one(cm("cpe:2.3:a:pulsesecure:pulse_connect_secure:9.1:r8:*:*:*:*:*:*", ""))),
                rec("CVE-2026-0011", one(cm("cpe:2.3:a:treck:tcp\\\\/ip:*:*:*:*:*:*:*:*", ",\"versionEndExcluding\":\"6.0.1.66\""))),
                // an alias copy of the matched CPE must not count as its own platform
                rec("CVE-2026-0012", "[{\"operator\":\"AND\",\"nodes\":[{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[" + cm("cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*", ",\"versionEndExcluding\":\"22.7\"") + "]},{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[{\"vulnerable\":false,\"criteria\":\"cpe:2.3:a:pulsesecure:pulse_connect_secure:-:*:*:*:*:*:*:*\",\"matchCriteriaId\":\"Z\"}]}]}]"),
                // a KEV entry of a general-purpose OS, service version unknown: counted, not listed
                rec("CVE-2026-0013", one(cm("cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*", ",\"versionEndExcluding\":\"12.0\"")))
            }) + "]}";
            // a later copy of CVE-2026-0009 that no longer applies (the newest record decides)
            string mod = "{\"vulnerabilities\":[" + rec("CVE-2026-0009", one(cm("cpe:2.3:a:f5:nginx:1.17.0:*:*:*:*:*:*:*", ""))).Replace("2026-02-01", "2026-03-01") + "]}";
            File.WriteAllText(Path.Combine(dir, "nvdcve-2.0-2026.json"), feed);
            using (FileStream fs = File.Create(Path.Combine(dir, "nvdcve-2.0-modified.json.gz")))
            using (System.IO.Compression.GZipStream gz = new System.IO.Compression.GZipStream(fs, System.IO.Compression.CompressionMode.Compress))
            { byte[] b = Encoding.UTF8.GetBytes(mod); gz.Write(b, 0, b.Length); }
            string kev = Path.Combine(dir, "kev.json");
            File.WriteAllText(kev, "{\"catalogVersion\":\"t\",\"dateReleased\":\"2026-03-01\",\"vulnerabilities\":[{\"cveID\":\"CVE-2026-0006\",\"dateAdded\":\"2026-02-02\",\"dueDate\":\"2026-02-23\",\"knownRansomwareCampaignUse\":\"Known\"},{\"cveID\":\"CVE-2026-0013\",\"dateAdded\":\"2026-02-02\",\"dueDate\":\"2026-02-23\",\"knownRansomwareCampaignUse\":\"Unknown\"}]}");
            string epss = Path.Combine(dir, "epss.csv");
            File.WriteAllText(epss, "#model_version:v2026.06.15,score_date:2026-03-01T00:00:00Z\ncve,epss,percentile\nCVE-2026-0001,0.5,0.9\nCVE-2026-0006,0.9,0.99\n");
            List<Vulns.Service> svcs = new List<Vulns.Service>();
            Func<string, string, Vulns.Service> svc = delegate(string host, string cpes)
            {
                Vulns.Service x = new Vulns.Service(); x.Host = host; x.Ip = "10.0.0.1"; x.Port = "443"; x.Url = ""; x.Status = "Active"; x.Products = ""; x.EntityId = host;
                foreach (string c in cpes.Split(';')) x.Cpes.Add(Cpe.Parse(c));
                svcs.Add(x); return x;
            };
            svc("ssh-a", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*");
            svc("ssh-b", "cpe:2.3:a:openbsd:openssh:9.3p1:*:*:*:*:*:*:*");
            svc("ssh-c", "cpe:2.3:a:openbsd:openssh:9.8p1:*:*:*:*:*:*:*");
            svc("web-a", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
            svc("web-b", "cpe:2.3:a:apache:http_server:2.4.55:*:*:*:*:*:*:*");
            svc("php-win", "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*;cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*");
            svc("php-lin", "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*");
            svc("ci", "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*");
            svc("ngx", "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*");
            svc("vpn", "cpe:2.3:a:ivanti:connect_secure:9.1r8:*:*:*:*:*:*:*");
            svc("iot", "cpe:2.3:a:treck:tcp%2fip:6.0.1.41:*:*:*:*:*:*:*");
            svc("deb", "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*");
            Vulns.SetAliases(null);
            VulnResult r0 = Vulns.Run(svcs, new[] { dir }, kev, epss, new List<RowFilter>(), "t", "t");
            foreach (string[] row in r0.Rows) if (row[7] == "CVE-2026-0010") bad.Add("former-name CVE matched without the alias table");
            bool osRow = false; foreach (string[] row in r0.Rows) if (row[0] == "deb" && row[7] == "CVE-2026-0013") osRow = true;
            if (!osRow) bad.Add("OS KEV entry missing without the platform list");
            Vulns.SetAliases("{\"version\":\"t\",\"aliases\":[[\"a:ivanti:connect_secure\",\"a:pulsesecure:pulse_connect_secure\"]],\"platforms\":[\"o:debian:debian_linux\",\"o:microsoft:windows*\"]}");
            VulnResult r = Vulns.Run(svcs, new[] { dir }, kev, epss, new List<RowFilter>(), "t", "t");
            Vulns.SetAliases(null);
            List<string> got = new List<string>();
            foreach (string[] row in r.Rows) got.Add(row[0] + " " + row[7] + " " + row[18] + (row[8] == "Yes" ? " kev" : "") + (row[12].Length > 0 ? " epss=" + row[12] : ""));
            got.Sort(StringComparer.Ordinal);
            string want = "ci CVE-2026-0006 product-only kev epss=0.9|ci CVE-2026-0007 product-only (dropped)|php-lin CVE-2026-0005 range (platform not verified)|php-win CVE-2026-0005 range|" +
                "ssh-a CVE-2026-0001 range epss=0.5|ssh-b CVE-2026-0001 range epss=0.5|ssh-b CVE-2026-0002 version|web-a CVE-2026-0003 version|web-b CVE-2026-0004 range|" +
                "vpn CVE-2026-0010 version (as pulsesecure:pulse_connect_secure)|iot CVE-2026-0011 range|vpn CVE-2026-0012 range (platform not verified)";
            List<string> w = new List<string>(want.Split('|'));
            w.RemoveAll(delegate(string x) { return x.EndsWith("(dropped)", StringComparison.Ordinal); });
            w.Sort(StringComparer.Ordinal);
            if (string.Join("|", got) != string.Join("|", w)) bad.Add("rows: " + string.Join("|", got));
            return string.Join("; ", bad);
        }
}
}
'@
function Initialize-StoreEngine {
    if ('WebInv.InventoryStore' -as [type]) {
        if ([WebInv.StoreUtil]::Version -ne $ScriptVersion) { throw ("store engine v{0} is already loaded in this PowerShell session (script is v{1}); open a new PowerShell window" -f [WebInv.StoreUtil]::Version, $ScriptVersion) }
        return
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $addType = @{ TypeDefinition = $StoreSource; ErrorAction = 'Stop' }
    if ($PSVersionTable.PSEdition -ne 'Core') { $addType.ReferencedAssemblies = @('System.Core') }
    Add-Type @addType
    if ($script:RunLog) { Write-RunLog ("Store engine compiled in {0} ms" -f $sw.ElapsedMilliseconds) 'DEBUG' }
}
function Resolve-StorePath([string]$Path) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path) }
function Format-Iso([datetime]$T) { ([DateTimeOffset]$T).ToString('yyyy-MM-ddTHH:mm:sszzz', [Globalization.CultureInfo]::InvariantCulture) }

# run.json: when, how (probe switches) and by whom the run was made. The store uses it for timestamps, for keeping
# values a probe that was switched off did not collect, and to refuse incomplete runs.
function Write-RunInfo {
    param([bool]$Complete, [bool]$Interrupted, [bool]$TimeLimit, [int]$Rows)
    $path = Join-Path $OutputDir ("WebInventory_{0}_run.json" -f $script:RunId)
    $started = Format-Iso $script:ScriptStart
    $sessions = New-Object System.Collections.Generic.List[object]
    if (Test-Path -LiteralPath $path) {
        try {
            $old = [IO.File]::ReadAllText($path) | ConvertFrom-Json
            if ($old.startedAt) { $started = [string]$old.startedAt }
            foreach ($s in @($old.sessions)) { if ($s) { $sessions.Add($s) } }
        }
        catch { Write-ErrLog 'IO' 'run.json' ("previous run.json unreadable, rewritten: {0}" -f $_.Exception.Message) }
    }
    elseif ($Resume) {
        $t = [datetime]::MinValue
        if ([datetime]::TryParseExact($script:RunId, 'yyyyMMdd_HHmmss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$t)) { $started = Format-Iso $t }
    }
    $sessions.Add([ordered]@{
            started = (Format-Iso $script:ScriptStart); finished = (Format-Iso (Get-Date)); resumed = [bool]$Resume
            interrupted = $Interrupted; timeLimit = $TimeLimit; rows = $Rows; runLog = $RunLogPath; errorLog = $ErrLogPath
        })
    $checks = 0
    if ($script:ProgressPath -and (Test-Path -LiteralPath $script:ProgressPath)) { foreach ($l in [IO.File]::ReadLines($script:ProgressPath)) { if ($l.Trim()) { $checks++ } } }
    $info = [ordered]@{
        format = 1; runId = $script:RunId; startedAt = $started; finishedAt = (Format-Iso (Get-Date)); complete = $Complete; synthesized = $false
        scanner = "WebInventory $ScriptVersion"; tag = [string]$Tag; operator = $script:Operator; computer = [Environment]::MachineName; checks = $checks
        profile = [ordered]@{
            tlsScan = (-not $NoTlsScan); favicon = (-not $NoFavicon); extras = (-not $NoExtras); options = [bool]$Options
            identifyPaths = [bool]$IdentifyPaths; probeSans = [bool]$ProbeSans; reverseDns = [bool]$ReverseDns
            tlsFingerprint = [bool]$TlsFingerprint; ja4s = ([bool]$TlsFingerprint -and -not $NoJa4s); smb = [bool]$Smb; rdp = [bool]$Rdp; snmp = [bool]$Snmp; screenshot = [bool]$Screenshot
        }
        settings = [ordered]@{ pace = $Pace; threads = $Threads; maxPerHost = $MaxPerHost; timeoutMs = $TimeoutMs; retries = $Retries; ports = $Port; allAddresses = [bool]$AllAddresses
            proxy = $(if ($Proxy) { $proxyLabel } else { '' }); snmp = $(if ($Snmp) { $snmpMode } else { '' })
        }
        sessions = $sessions.ToArray()
    }
    [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $info -Depth 5), $script:Utf8NoBom)
    $path
}

function New-RunSources {
    param([string]$RunId, [string]$Dir, [string[]]$Logs)
    $s = New-Object WebInv.RunSources
    $s.RunId = $RunId
    $b = Join-Path $Dir ("WebInventory_{0}" -f $RunId)
    $s.Jsonl = "$b.jsonl"; $s.Progress = "${b}_progress.txt"; $s.RunJson = "${b}_run.json"; $s.Csv = "$b.csv"
    $s.Html = "$b.html"; $s.Delta = "${b}_delta.csv"; $s.Manifest = "${b}_manifest.txt"
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $add = { param($p) if ($p -and $seen.Add([string]$p)) { $s.Logs.Add([string]$p) } }
    foreach ($l in @($Logs)) { & $add $l }
    if (Test-Path -LiteralPath $s.RunJson) {
        try { foreach ($x in @(([IO.File]::ReadAllText($s.RunJson) | ConvertFrom-Json).sessions)) { if ($x) { & $add $x.runLog; & $add $x.errorLog } } } catch { }
    }
    else {
        # older output: logs named after the RunId, next to the results or in the current folder
        foreach ($d in @($Dir, (Get-Location).ProviderPath)) { foreach ($suffix in '_run.log', '_error.log') { $p = Join-Path $d ("WebInventory_{0}{1}" -f $RunId, $suffix); if (Test-Path -LiteralPath $p) { & $add $p } } }
    }
    $s
}

function Show-StoreMessages($S, [int]$From) {
    if (-not $S) { return $From }
    for ($i = $From; $i -lt $S.Messages.Count; $i++) {
        $m = $S.Messages[$i]
        if ($script:RunLog) { Write-RunLog ("Store: " + $m) }
        # like the scan's own summary line, the ingest summary and warnings print even with -Quiet
        $important = ($m -like 'WARNING*' -or $m -like 'ingested*')
        if ($important -or -not $Quiet) { Write-Host ("Store: " + $m) -ForegroundColor $(if ($m -like 'WARNING*') { 'Yellow' } elseif ($m -like 'ingested*') { 'Cyan' } else { 'DarkCyan' }) }
    }
    $S.Messages.Count
}

function Open-InventoryStore([string]$Mode) {
    $ra = if ($Explicit.Contains('RetireAfter')) { $RetireAfter } else { 0 }
    $s = [WebInv.InventoryStore]::Open($script:StorePath, $StoreEngine, $ra, $ScriptVersion, $Mode, 30000)
    if ($Mode -eq 'write' -or $Mode -eq 'rebuild') {
        try { Set-StoreOptions $s } catch { $s.Dispose(); throw }
    }
    $s
}

# -SnapshotEvery / -AnchorEventLog / -AnchorCertificate are kept in STORE.json (later runs keep them without the switch)
function Set-StoreOptions($S) {
    $se = if ($Explicit.Contains('SnapshotEvery')) { $SnapshotEvery } else { 0 }
    $ael = if ($Explicit.Contains('AnchorEventLog')) { [int][bool]$AnchorEventLog } else { -1 }
    $ac = $null
    if ($Explicit.Contains('AnchorCertificate')) {
        $ac = ([string]$AnchorCertificate -replace '[\s:]', '').ToUpperInvariant()
        if ($ac) { [void](Get-AnchorCertificate $ac) }
    }
    if ($ael -eq 1 -and -not $isWindows_) { throw '-AnchorEventLog needs the Windows event log' }
    $S.SetOptions($se, $ael, $Explicit.Contains('AnchorCertificate'), [string]$ac)
}

function Get-AnchorCertificate([string]$Thumb) {
    foreach ($loc in 'CurrentUser', 'LocalMachine') {
        $st = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', $loc)
        try {
            $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            foreach ($c in $st.Certificates) {
                if ($c.Thumbprint -eq $Thumb) {
                    if (-not $c.HasPrivateKey) { throw "certificate $Thumb ($loc\My) has no private key" }
                    return $c
                }
            }
        }
        catch [System.Security.Cryptography.CryptographicException] { }
        finally { $st.Close() }
    }
    throw "signing certificate $Thumb not found in CurrentUser\My or LocalMachine\My"
}

# anchors every ledger line this process appended: Windows event log entry and/or detached CMS signature
function Invoke-StoreAnchors($S) {
    if (-not $S -or $S.Appended.Count -eq 0 -or -not ($S.AnchorEventLog -or $S.AnchorCertificate)) { return $true }
    $ok = $true
    $cert = $null
    if ($S.AnchorCertificate) { try { $cert = Get-AnchorCertificate $S.AnchorCertificate } catch { Write-Host ("Store: ledger NOT signed: {0}" -f $_.Exception.Message) -ForegroundColor Red; $ok = $false } }
    foreach ($a in $S.Appended) {
        if ($S.AnchorEventLog) {
            try {
                $msg = "WebInventory store {0} ledger seq {1} head {2}" -f $S.StoreId, $a[0], $a[1]
                [System.Diagnostics.EventLog]::WriteEntry('WebInventory', $msg, [System.Diagnostics.EventLogEntryType]::Information, 4100)
                Write-RunLog ("Store anchor: event log <- seq {0} head {1}" -f $a[0], $a[1])
            }
            catch { Write-Host ("Store: event-log anchor failed for seq {0}: {1} (create the source once, as administrator: -RegisterEventSource)" -f $a[0], $_.Exception.Message) -ForegroundColor Red; $ok = $false }
        }
        if ($cert) {
            try {
                if ($PSVersionTable.PSEdition -ne 'Core') { Add-Type -AssemblyName System.Security }
                $ci = New-Object System.Security.Cryptography.Pkcs.ContentInfo (, [byte[]]$script:Utf8NoBom.GetBytes($a[2]))
                $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms ($ci, $true)
                $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner ($cert)
                $signer.DigestAlgorithm = New-Object System.Security.Cryptography.Oid ('2.16.840.1.101.3.4.2.1')
                $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
                [void]$signer.SignedAttributes.Add((New-Object System.Security.Cryptography.Pkcs.Pkcs9SigningTime))
                $cms.ComputeSignature($signer, $true)
                $dir = Join-Path (Join-Path $S.Root 'archive') 'anchors'
                if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                [IO.File]::WriteAllBytes((Join-Path $dir ('{0:D6}.p7s' -f [long]$a[0])), $cms.Encode())
                Write-RunLog ("Store anchor: signed seq {0} with {1}" -f $a[0], $cert.Thumbprint)
            }
            catch { Write-Host ("Store: signing ledger seq {0} failed: {1}" -f $a[0], $_.Exception.Message) -ForegroundColor Red; $ok = $false }
        }
    }
    $S.Appended.Clear()
    $ok
}

# -VerifyStore: signatures in archive\anchors and WebInventory entries in the Application event log against the ledger
function Test-StoreAnchors($S, $Report) {
    $ok = $true
    $lines = @{}; foreach ($l in $S.LedgerLines()) { $lines[[long]$l[0]] = $l }
    $dir = Join-Path (Join-Path $S.Root 'archive') 'anchors'
    $signed = 0
    if (Test-Path -LiteralPath $dir) {
        if ($PSVersionTable.PSEdition -ne 'Core') { Add-Type -AssemblyName System.Security }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.p7s' -File | Sort-Object Name)) {
            $seq = [long]($f.BaseName)
            if (-not $lines.ContainsKey($seq)) { $Report.Add(("FAIL anchors: signature {0} is for ledger seq {1}, which the ledger no longer has (truncated?)" -f $f.Name, $seq)); $ok = $false; continue }
            try {
                $ci = New-Object System.Security.Cryptography.Pkcs.ContentInfo (, [byte[]]$script:Utf8NoBom.GetBytes($lines[$seq][2]))
                $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms ($ci, $true)
                $cms.Decode([IO.File]::ReadAllBytes($f.FullName))
                $cms.CheckSignature($true)
                $signed++
            }
            catch { $Report.Add(("FAIL anchors: ledger seq {0} does not match its signature ({1})" -f $seq, $_.Exception.Message)); $ok = $false }
        }
    }
    if ($S.AnchorCertificate) {
        $missing = @($lines.Keys | Where-Object { $_ -ge $S.AnchorFrom -and -not (Test-Path -LiteralPath (Join-Path $dir ('{0:D6}.p7s' -f $_))) } | Sort-Object)
        if ($missing.Count) { $Report.Add(("FAIL anchors: {0} ledger entries since seq {1} have no signature (first: seq {2})" -f $missing.Count, $S.AnchorFrom, $missing[0])); $ok = $false }
    }
    if ($signed) { $Report.Add(("ok   anchors: {0} ledger entries match their detached signatures" -f $signed)) }
    if ($S.AnchorEventLog -or $isWindows_) {
        $events = @()
        if ($isWindows_) { try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'WebInventory' } -ErrorAction Stop) } catch { $events = @() } }
        $seen = 0; $bad = 0
        foreach ($ev in $events) {
            if ($ev.Message -notmatch ('store {0} ledger seq (\d+) head ([0-9a-f]{{64}})' -f [regex]::Escape($S.StoreId))) { continue }
            $seq = [long]$Matches[1]; $head = $Matches[2]
            if (-not $lines.ContainsKey($seq)) { $Report.Add(("FAIL anchors: event log records ledger seq {0} (written {1:s}), which the ledger no longer has" -f $seq, $ev.TimeCreated)); $bad++; continue }
            if ($lines[$seq][1] -ne $head) { $Report.Add(("FAIL anchors: ledger seq {0} differs from the head recorded in the event log on {1:s}" -f $seq, $ev.TimeCreated)); $bad++; continue }
            $seen++
        }
        if ($bad) { $ok = $false }
        if ($seen) { $Report.Add(("ok   anchors: {0} event-log entries match the ledger" -f $seen)) }
        elseif ($S.AnchorEventLog) { $Report.Add('note anchors: event-log anchoring is on but no WebInventory entries for this store were found in the Application log (rolled over or cleared?)') }
    }
    $ok
}

function Write-IngestSummary($Sum) {
    if ($Sum.AlreadyPresent) { Write-Host ("Store: run {0} is already in the store (seq {1}); nothing to do" -f $Sum.RunId, $Sum.Seq) -ForegroundColor DarkCyan; return }
    if ($Sum.Partial) { Write-Host 'Store: imported as a PARTIAL run (only the checks it completed count towards absence)' -ForegroundColor Yellow }
}

# after a complete scan: archive the run's files and apply them to the store (the scan itself is already finished)
function Invoke-StoreIngest {
    param([string]$RunId, [string]$Dir)
    $sto = $null; $shown = 0
    try {
        Initialize-StoreEngine
        $sto = Open-InventoryStore 'write'
        $shown = Show-StoreMessages $sto 0
        $sum = $sto.Ingest((New-RunSources -RunId $RunId -Dir $Dir -Logs @($RunLogPath, $ErrLogPath)), $false)
        $shown = Show-StoreMessages $sto $shown
        Write-IngestSummary $sum
        Invoke-StoreAnchors $sto
    }
    catch {
        [void](Show-StoreMessages $sto $shown)
        Write-Host ("Store: ingest failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
        Write-Host ("Store: the run's files are unchanged; add it later with -Store '{0}' -ImportRun '{1}'" -f $script:StorePath, $Dir) -ForegroundColor Yellow
        try { [IO.File]::AppendAllText((Join-Path $script:StorePath 'store.log'), ("{0} ingest of run {1} failed: {2}`r`n" -f (Format-Iso (Get-Date)), $RunId, $_.Exception.Message)) } catch { }
        $false
    }
    finally { if ($sto) { $sto.Dispose() } }
}

# -ImportRun: output folders or files of earlier runs -> RunId -> folder, oldest first
function Get-ImportRunList {
    param([string[]]$Paths)
    $runs = @{}
    foreach ($p in $Paths) {
        $items = @(Resolve-Path -Path $p -ErrorAction SilentlyContinue)
        if (-not $items) { throw "-ImportRun: '$p' not found" }
        foreach ($it in $items) {
            $full = $it.ProviderPath
            if (Test-Path -LiteralPath $full -PathType Container) {
                foreach ($f in @(Get-ChildItem -LiteralPath $full -Filter 'WebInventory_*.jsonl' -File)) { if ($f.Name -match '^WebInventory_(.+)\.jsonl$') { $runs[$Matches[1]] = $full } }
            }
            elseif ((Split-Path -Leaf $full) -match '^WebInventory_(.+?)(?:_progress\.txt|_run\.json|_manifest\.txt|_delta\.csv|\.jsonl|\.csv|\.html)$') { $runs[$Matches[1]] = Split-Path -Parent $full }
            else { throw "-ImportRun: '$full' is not a WebInventory results file or folder" }
        }
    }
    $list = foreach ($k in $runs.Keys) {
        $t = [DateTimeOffset]::MinValue
        $rj = Join-Path $runs[$k] ("WebInventory_{0}_run.json" -f $k)
        $parsed = $false
        if (Test-Path -LiteralPath $rj) { try { $t = [DateTimeOffset]::Parse([string](([IO.File]::ReadAllText($rj) | ConvertFrom-Json).startedAt), [Globalization.CultureInfo]::InvariantCulture); $parsed = $true } catch { } }
        if (-not $parsed) { $d = [datetime]::MinValue; if ([datetime]::TryParseExact($k, 'yyyyMMdd_HHmmss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$d)) { $t = [DateTimeOffset]$d } }
        [pscustomobject]@{ RunId = $k; Dir = $runs[$k]; Started = $t }
    }
    @($list | Sort-Object Started, RunId)
}

function Write-QueryCsv {
    param($Q, [string]$Path)
    $w = New-Object System.IO.StreamWriter($Path, $false, $script:Utf8Bom)
    try {
        $w.WriteLine((($Q.Columns | ForEach-Object { '"' + $_ + '"' }) -join ','))
        foreach ($r in $Q.Rows) { $w.WriteLine([WebInv.Out]::CsvLine([object[]]$r, -not $NoCsvSanitize)) }
    }
    finally { $w.Dispose() }
}

function Split-ListParam {
    param([string[]]$Values, [string]$Name, [string[]]$Allowed)
    foreach ($v in @($Values | Where-Object { $_ })) {
        foreach ($x in ($v -split ',')) {
            $t = $x.Trim()
            if (-not $t) { continue }
            $m = @($Allowed | Where-Object { $_ -eq $t })
            if (-not $m) { Stop-Fatal ("-{0}: '{1}' is not one of {2}" -f $Name, $t, ($Allowed -join ', ')) }
            $m[0]
        }
    }
}

function Invoke-StoreMode {
    if ($RegisterEventSource) {
        if (-not $isWindows_) { Stop-Fatal '-RegisterEventSource needs Windows' }
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists('WebInventory')) { [System.Diagnostics.EventLog]::CreateEventSource('WebInventory', 'Application') }
            Write-Host "Event source 'WebInventory' (Application log) is registered; -AnchorEventLog can now write ledger heads." -ForegroundColor Cyan
            $script:ExitCode = 0
        }
        catch { Stop-Fatal ("could not register the event source (run as administrator): {0}" -f $_.Exception.Message) }
        if (-not $Store) { return }
    }
    if (-not $Store) { Stop-Fatal '-ImportRun, -StoreQuery, -StoreMerge, -StoreSplit, -VerifyStore and -RebuildStore need -Store <folder>' }
    $modes = @(([bool]@($ImportRun | Where-Object { $_ }).Count), [bool]$StoreQuery, [bool]$VerifyStore, [bool]$RebuildStore, [bool]@($StoreMerge | Where-Object { $_ }).Count, [bool]$StoreSplit) | Where-Object { $_ }
    if (@($modes).Count -gt 1) { Stop-Fatal 'Use one of -ImportRun, -StoreQuery, -StoreMerge, -StoreSplit, -VerifyStore or -RebuildStore at a time' }
    if ($Backfill -and -not $ImportRun) { Stop-Fatal '-Backfill goes with -ImportRun' }
    if ($SplitAt -and -not $StoreSplit) { Stop-Fatal '-SplitAt goes with -StoreSplit' }
    $script:StorePath = Resolve-StorePath $Store
    try { Initialize-StoreEngine } catch { Stop-Fatal ("Store engine compile failed: {0}" -f $_.Exception.Message) }
    $stray = @($Target | Where-Object { $_ })
    if ($stray.Count) { Stop-Fatal ("Unexpected argument(s) in store mode: {0} (several -Filter clauses: use an array, or join them with ' -and ')" -f ($stray -join ' ')) }
    # comma lists work from -File / scheduled tasks too
    $script:QStatus = @(Split-ListParam $Status 'Status' @('Active', 'Missing', 'Retired', 'All'))
    $script:QChangeType = @(Split-ListParam $ChangeType 'ChangeType' @('Added', 'Changed', 'Enriched', 'Missing', 'Retired', 'Reappeared', 'Rekeyed', 'Merged', 'Split'))
    $script:QFilter = @(foreach ($f in @($Filter | Where-Object { $_ })) { $f -split '\s+-and\s+' | Where-Object { $_.Trim() } })
    $sto = $null; $shown = 0
    try {
        if (@($modes).Count -eq 0) {
            # only store options (-SnapshotEvery / -AnchorEventLog / -AnchorCertificate): record them and stop
            $sto = Open-InventoryStore 'write'
            $shown = Show-StoreMessages $sto $shown
            Write-Host ("Store {0}: snapshot every {1} run(s); event-log anchoring {2}; ledger signing {3}" -f $sto.Root, $sto.SnapshotEvery, $(if ($sto.AnchorEventLog) { 'on' } else { 'off' }), $(if ($sto.AnchorCertificate) { $sto.AnchorCertificate + ' from seq ' + $sto.AnchorFrom } else { 'off' })) -ForegroundColor Cyan
            $script:ExitCode = $(if (Invoke-StoreAnchors $sto) { 0 } else { 2 }); return
        }
        if ($StoreMerge -or $StoreSplit) {
            if (-not $Reason) { Stop-Fatal 'A correction needs -Reason (kept in the ledger with the operator name)' }
            $op = if ($StoreMerge) { 'merge' } else { 'split' }
            $ids = if ($StoreMerge) { [string[]]@(foreach ($m in @($StoreMerge | Where-Object { $_ })) { $m -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }) } else { [string[]]@($StoreSplit.Trim()) }
            $sto = Open-InventoryStore 'write'
            $shown = Show-StoreMessages $sto $shown
            $sum = $sto.Correct($op, $ids, [string]$SplitAt, [string]$Reason, $script:Operator)
            $shown = Show-StoreMessages $sto $shown
            Write-Host ("Store: {0} recorded ({1}) at position {2}; inventory now {3} active, {4} missing, {5} retired; ledger head {6}" -f $sum.RunId, $op, $sum.Seq, $sum.Active, $sum.MissingTotal, $sum.RetiredTotal, $sum.LedgerHead) -ForegroundColor Cyan
            $script:ExitCode = $(if (Invoke-StoreAnchors $sto) { 0 } else { 2 }); return
        }
        if ($RebuildStore) {
            $sto = Open-InventoryStore 'rebuild'
            $sto.Rebuild($StoreEngine)
            $shown = Show-StoreMessages $sto $shown
            [void](Invoke-StoreAnchors $sto)
            $stats = $sto.Stats()
            Write-Host ("Store rebuilt ({0}): {1} runs; {2} active, {3} missing, {4} retired services; ledger head {5}" -f $stats['Engine'], $stats['Runs'], $stats['Active'], $stats['Missing'], $stats['Retired'], $stats['LedgerHead']) -ForegroundColor Cyan
            $script:ExitCode = 0; return
        }
        if ($VerifyStore) {
            $sto = Open-InventoryStore 'verify'
            $report = New-Object System.Collections.Generic.List[string]
            $ok = $sto.Verify($report)
            $ok = (Test-StoreAnchors $sto $report) -and $ok
            $shown = Show-StoreMessages $sto $shown
            foreach ($l in $report) {
                Write-RunLog ("VerifyStore: " + $l)
                Write-Host $l -ForegroundColor $(if ($l.StartsWith('FAIL')) { 'Red' } elseif ($l.StartsWith('ok')) { 'Green' } else { 'DarkGray' })
            }
            Write-Host ("Store {0}: {1}" -f $sto.Root, $(if ($ok) { 'VERIFIED' } else { 'VERIFICATION FAILED' })) -ForegroundColor $(if ($ok) { 'Cyan' } else { 'Red' })
            $script:ExitCode = $(if ($ok) { 0 } else { 2 }); return
        }
        if ($ImportRun) {
            try { $list = Get-ImportRunList $ImportRun } catch { Stop-Fatal $_.Exception.Message }
            if (-not $list) { Write-Host 'Nothing to import (no WebInventory_*.jsonl found)' -ForegroundColor Yellow; $script:ExitCode = 0; return }
            $sto = Open-InventoryStore 'write'
            $shown = Show-StoreMessages $sto $shown
            if ($Backfill) {
                $srcs = New-Object 'System.Collections.Generic.List[WebInv.RunSources]'
                foreach ($r in $list) { $srcs.Add((New-RunSources -RunId $r.RunId -Dir $r.Dir -Logs @())) }
                foreach ($sum in $sto.Backfill($srcs, [bool]$Force)) { Write-IngestSummary $sum }
                $shown = Show-StoreMessages $sto $shown
            }
            else {
                foreach ($r in $list) {
                    $sum = $sto.Ingest((New-RunSources -RunId $r.RunId -Dir $r.Dir -Logs @()), [bool]$Force)
                    $shown = Show-StoreMessages $sto $shown
                    Write-IngestSummary $sum
                }
            }
            $script:ExitCode = $(if (Invoke-StoreAnchors $sto) { 0 } else { 2 }); return
        }
        # -StoreQuery
        $sto = Open-InventoryStore 'read'
        $shown = Show-StoreMessages $sto $shown
        [void](Invoke-StoreAnchors $sto)   # a read can finish an interrupted ingest, which appends to the ledger
        $since = if ($WithinDays) { Format-Iso ((Get-Date).AddDays(-$WithinDays)) } elseif ($Since) { Format-Iso $Since } else { '' }
        $until = if ($Until) { Format-Iso $Until } else { '' }
        $asOf = if ($AsOf) { Format-Iso $AsOf } else { '' }
        $prov = $null
        if ($StoreQuery -eq 'Vulnerabilities') {
            if (-not @($NvdFeed | Where-Object { $_ }).Count) { Stop-Fatal '-StoreQuery Vulnerabilities needs -NvdFeed (NVD CVE JSON 2.0 feed files or a folder of them); -KevFile and -EpssFile are optional' }
            foreach ($f in @($KevFile, $EpssFile)) { if ($f -and -not (Test-Path -LiteralPath $f -PathType Leaf)) { Stop-Fatal "file not found: $f" } }
            $feeds = [string[]]@(foreach ($f in @($NvdFeed | Where-Object { $_ })) { foreach ($x in ($f -split ',')) { if ($x.Trim()) { (Resolve-Path -LiteralPath $x.Trim()).ProviderPath } } })
            # the other NVD names of each product (vendor/product renames, firmware vs software entries)
            [void][WebInv.Vulns]::SetAliases($CpeSupplementJson)
            $q = $sto.Vulnerabilities($feeds, $(if ($KevFile) { (Resolve-Path -LiteralPath $KevFile).ProviderPath } else { '' }), $(if ($EpssFile) { (Resolve-Path -LiteralPath $EpssFile).ProviderPath } else { '' }), [string[]]$script:QFilter, [string[]]$script:QStatus)
            $prov = $q.Provenance
        }
        else { $q = $sto.Query($StoreQuery, [string[]]$script:QFilter, [string[]]$script:QStatus, [string[]]$script:QChangeType, $since, $until, $asOf) }
        $shown = Show-StoreMessages $sto $shown
        if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
        # unique name: two queries of the same kind in the same second must not overwrite each other
        $stem = Join-Path (Resolve-Path -LiteralPath $OutputDir).ProviderPath ("WebInventory_store_{0}_{1}" -f $StoreQuery.ToLowerInvariant(), $script:Stamp)
        $base = $stem; $n = 1
        while ((Test-Path -LiteralPath "$base.csv") -or (Test-Path -LiteralPath "$base.html") -or (Test-Path -LiteralPath "$base.provenance.json")) { $n++; $base = '{0}_{1}' -f $stem, $n }
        Write-QueryCsv $q "$base.csv"
        $files = @("$base.csv")
        if ($prov) { [IO.File]::WriteAllText("$base.provenance.json", $prov + "`n", $script:Utf8NoBom); $files += "$base.provenance.json" }
        if ($StoreQuery -eq 'Inventory' -and -not $NoHtml -and $q.Rows.Count -gt 0) {
            $meta = @{ RunId = 'inventory store'; Tag = $(if ($AsOf) { 'as of ' + $asOf } else { 'current' }); Started = (Get-Date).ToString('yyyy-MM-dd HH:mm'); Duration = ''; Operator = $script:Operator; Computer = [Environment]::MachineName; Version = $ScriptVersion }
            New-HtmlReport -CsvFile "$base.csv" -HtmlFile "$base.html" -Meta $meta
            $files += "$base.html"
        }
        Write-RunLog ("StoreQuery {0}: {1} rows -> {2}" -f $StoreQuery, $q.Rows.Count, ($files -join ' ; '))
        if (-not $Quiet) { Write-Host ("Store query {0}: {1} rows -> {2}" -f $StoreQuery, $q.Rows.Count, ($files -join ' | ')) -ForegroundColor Cyan }
        if ($PassThru) {
            foreach ($r in $q.Rows) { $o = [ordered]@{}; for ($i = 0; $i -lt $q.Columns.Length; $i++) { $o[$q.Columns[$i]] = $r[$i] }; [pscustomobject]$o }
        }
        $script:ExitCode = 0
    }
    catch {
        [void](Show-StoreMessages $sto $shown)
        $ex = $_.Exception
        while ($ex -is [System.Management.Automation.MethodInvocationException] -and $ex.InnerException) { $ex = $ex.InnerException }
        Stop-Fatal ("Store: {0}" -f $ex.Message)
    }
    finally { if ($sto) { $sto.Dispose() } }
}
#endregion

#region ---------- Store self-test (part of -SelfTest; on Windows also validates ESENT against the portable engine) ----------
function Invoke-StoreSelfTest {
    $script:StoreCompiled = $false
    Assert 'store: store engine compiles (C# 5)' { Initialize-StoreEngine; $script:StoreCompiled = $true; $true }
    if (-not $script:StoreCompiled) { return }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('webinv-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void](New-Item -ItemType Directory -Path $tmp)
    $esent = [WebInv.EsentKv]::Available
    $engines = @('file') + $(if ($esent) { @('esent') } else { @() })
    try {
        Assert 'store: SHA-256 accumulator (vectors, block edges, platform = managed)' { [WebInv.StoreSelfTest]::HashCheck() -eq '' }
        $vr = [WebInv.StoreSelfTest]::VulnCheck((Join-Path $tmp 'vuln'))
        Assert "store: offline NVD/KEV/EPSS correlation (versions, updates, ranges, platforms, rejected and superseded records)$(if ($vr) { ': ' + $vr })" { $vr -eq '' }
        foreach ($e in @('memory') + $engines) {
            $r = [WebInv.StoreSelfTest]::KvConformance($e, (Join-Path $tmp "kv-$e"))
            Assert "store: $e key-value engine meets the contract (order, prefix/paged scans, rollback, limits, reopen)$(if ($r) { ': ' + $r })" { $r -eq '' }
        }
        if (-not $esent) { Write-RunLog 'SELFTEST note: esent.dll not present; ESENT engine checks skipped (portable engine only)' }
        $runs = [WebInv.StoreSelfTest]::WriteRuns((Join-Path $tmp 'runs'), 450)
        $dig = @{}
        foreach ($e in $engines) {
            $root = Join-Path $tmp "store-$e"
            $s = [WebInv.InventoryStore]::Open($root, $e, 2, $ScriptVersion, 'write', 0)
            try { foreach ($r in $runs) { [void]$s.Ingest($r, $false) } } finally { $s.Dispose() }
            $dig[$e] = [WebInv.StoreSelfTest]::LedgerDigests($root)
        }
        $counts = [WebInv.StoreSelfTest]::LedgerCounts((Join-Path $tmp 'store-file'))
        Assert 'store: synthetic history counts (adds, changes, moves, absences, retirements, returns)' {
            $counts -eq ("1 rows=450 added=450 changed=0 reappeared=0 rekeyed=0 missing=0 retired=0 active=450 missingTotal=0 retiredTotal=0`n" +
                "2 rows=445 added=9 changed=17 reappeared=0 rekeyed=12 missing=14 retired=0 active=445 missingTotal=14 retiredTotal=0`n" +
                "3 rows=443 added=0 changed=0 reappeared=7 rekeyed=0 missing=0 retired=7 active=452 missingTotal=0 retiredTotal=7`n")
        }
        if ($esent) { Assert 'store: ESENT and portable engines produce identical change and state digests' { $dig['esent'] -eq $dig['file'] } }
        foreach ($e in $engines) {
            foreach ($fp in 'rows:1', 'absence', 'derived') {
                Assert "store: interrupted ingest ($e, at $fp) is finished on the next open with identical results" {
                    $root = Join-Path $tmp ("crash-{0}-{1}" -f $e, ($fp -replace ':', ''))
                    $s = [WebInv.InventoryStore]::Open($root, $e, 2, $ScriptVersion, 'write', 0)
                    $threw = $false
                    try {
                        [void]$s.Ingest($runs[0], $false)
                        [WebInv.InventoryStore]::FailPoint = $fp
                        try { [void]$s.Ingest($runs[1], $false) } catch { $threw = $true }
                    }
                    finally { [WebInv.InventoryStore]::FailPoint = ''; $s.Dispose() }
                    $s = [WebInv.InventoryStore]::Open($root, $e, 2, $ScriptVersion, 'write', 0)
                    try { [void]$s.Ingest($runs[2], $false) } finally { $s.Dispose() }
                    $threw -and ([WebInv.StoreSelfTest]::LedgerDigests($root) -eq $dig[$e])
                }
            }
        }
        $root = Join-Path $tmp 'store-file'
        $verify = {
            $v = [WebInv.InventoryStore]::Open($root, 'auto', 0, $ScriptVersion, 'verify', 0)
            try { $rep = New-Object System.Collections.Generic.List[string]; $v.Verify($rep) } finally { $v.Dispose() }
        }
        Assert 'store: -VerifyStore passes (ledger chain, archive hashes, in-memory rebuild, live database)' { & $verify }
        Assert 'store: an altered archived file fails verification' {
            $f = Get-ChildItem -LiteralPath (Join-Path $root 'archive') -Recurse -Filter 'results.jsonl.gz' | Select-Object -First 1
            $b = [IO.File]::ReadAllBytes($f.FullName); $orig = $b.Clone(); $b[$b.Length - 9] = $b[$b.Length - 9] -bxor 1
            [IO.File]::WriteAllBytes($f.FullName, $b)
            try { $bad = & $verify } finally { [IO.File]::WriteAllBytes($f.FullName, $orig) }
            (-not $bad) -and (& $verify)
        }
        Assert 'store: an edited ledger line breaks the hash chain' {
            $lp = Join-Path $root 'archive/ledger.jsonl'
            $orig = [IO.File]::ReadAllBytes($lp)
            $t = [Text.Encoding]::UTF8.GetString($orig)
            if ($t -notmatch '"changed":17') { throw 'test precondition: ledger line not found' }
            [IO.File]::WriteAllText($lp, ($t -replace '"changed":17', '"changed":16'))
            try { $bad = & $verify } finally { [IO.File]::WriteAllBytes($lp, $orig) }
            (-not $bad) -and (& $verify)
        }
        Assert 'store: a deleted working database is rebuilt from the archive on the next open' {
            Remove-Item -LiteralPath (Join-Path $root 'db') -Recurse -Force
            $s = [WebInv.InventoryStore]::Open($root, 'auto', 0, $ScriptVersion, 'read', 0)
            try { $st = $s.Stats() } finally { $s.Dispose() }
            $st['Active'] -eq '452' -and $st['Retired'] -eq '7' -and (& $verify)
        }
        Assert 'store: queries (inventory filters, status, changes by type, history, runs, as-of)' {
            $s = [WebInv.InventoryStore]::Open($root, 'auto', 0, $ScriptVersion, 'read', 0)
            try {
                $inv = $s.Query('Inventory', $null, $null, $null, '', '', '')
                $ret = $s.Query('Inventory', [string[]]@('Status=Retired'), [string[]]@('All'), $null, '', '', '')
                $tls = $s.Query('Inventory', [string[]]@('Port=443', 'TlsSupported~TLS1.3'), $null, $null, '', '', '')
                $chg = $s.Query('Changes', $null, $null, [string[]]@('Rekeyed'), '', '', '')
                $his = $s.Query('History', [string[]]@('Host=svc40.test.local'), $null, $null, '', '', '')
                $rns = $s.Query('Runs', $null, $null, $null, '', '', '')
                $old = $s.Query('Inventory', $null, $null, $null, '', '', '2026-01-05T12:00:00+00:00')
                $win = $s.Query('Changes', $null, $null, $null, '2026-01-06T00:00:00+00:00', '2026-01-06T23:00:00+00:00', '')
                $bad = $false; try { [void]$s.Query('Inventory', [string[]]@('NoSuchField=1'), $null, $null, '', '', '') } catch { $bad = $true }
            }
            finally { $s.Dispose() }
            $hc = @($his.Rows | ForEach-Object { $_[2] }) -join ','
            $inv.Rows.Count -eq 452 -and $ret.Rows.Count -eq 7 -and $tls.Rows.Count -eq 150 -and $chg.Rows.Count -eq 12 -and $hc -eq 'Added,Rekeyed' -and
            $rns.Rows.Count -eq 3 -and $old.Rows.Count -eq 450 -and (@($win.Rows | ForEach-Object { $_[1] } | Select-Object -Unique) -join ',') -eq '20260106_080000' -and $bad
        }
        Assert 'store: -RebuildStore reproduces every ledger digest' {
            $s = [WebInv.InventoryStore]::Open($root, 'auto', 0, $ScriptVersion, 'rebuild', 0)
            try { $s.Rebuild('auto') } finally { $s.Dispose() }
            ([WebInv.StoreSelfTest]::LedgerDigests($root) -eq $dig['file']) -and (& $verify)
        }
        # ---- v2.3: corrections (both engines must agree), an interrupted correction, backfill, snapshot thinning
        $verifyAt = { param($r) $v = [WebInv.InventoryStore]::Open($r, 'auto', 0, $ScriptVersion, 'verify', 0); try { $rep = New-Object System.Collections.Generic.List[string]; $v.Verify($rep) } finally { $v.Dispose() } }
        $splitOne = {
            param($s)
            $rk = $s.Query('Changes', $null, $null, [string[]]@('Rekeyed'), '', '', '')
            $id = @($rk.Rows | ForEach-Object { $_[14] } | Sort-Object -Unique)[0]
            [void]$s.Correct('split', [string[]]@($id), '', 'self-test split', 'selftest')
            $id
        }
        $cdig = @{}
        foreach ($e in $engines) {
            Assert "store: split of an automatic pairing, then merged back ($e)" {
                $r2 = Join-Path $tmp "corr-$e"
                $s = [WebInv.InventoryStore]::Open($r2, $e, 2, $ScriptVersion, 'write', 0)
                try {
                    foreach ($r in $runs) { [void]$s.Ingest($r, $false) }
                    $before = $s.Stats()
                    $id = & $splitOne $s
                    $mid = $s.Stats()
                    $sp = $s.Query('Changes', $null, $null, [string[]]@('Split'), '', '', '')
                    $nid = @($sp.Rows | ForEach-Object { $_[14] } | Where-Object { $_ -ne $id } | Sort-Object -Unique)[0]
                    [void]$s.Correct('merge', [string[]]@($nid, $id), '', 'self-test merge back', 'selftest')
                    $after = $s.Stats()
                    $refused = $false; try { [void]$s.Correct('merge', [string[]]@($id, $id), '', 'x', 'selftest') } catch { $refused = $true }
                }
                finally { $s.Dispose() }
                $cdig[$e] = [WebInv.StoreSelfTest]::FinalState($r2)   # (change digests carry each correction's own time)
                ([int]$mid['Active'] + [int]$mid['Missing'] + [int]$mid['Retired']) -eq ([int]$before['Active'] + [int]$before['Missing'] + [int]$before['Retired'] + 1) -and
                $after['Active'] -eq $before['Active'] -and $refused -and (& $verifyAt $r2)
            }
        }
        if ($esent) { Assert 'store: corrections give the identical inventory on ESENT and the portable engine' { $cdig['esent'] -eq $cdig['file'] } }
        Assert 'store: a correction interrupted before its ledger line is finished on the next open (same inventory)' {
            $ra = Join-Path $tmp 'corr-ok'; $rb = Join-Path $tmp 'corr-crash'
            foreach ($r2 in $ra, $rb) {
                $s = [WebInv.InventoryStore]::Open($r2, 'file', 2, $ScriptVersion, 'write', 0)
                try {
                    foreach ($r in $runs) { [void]$s.Ingest($r, $false) }
                    if ($r2 -eq $rb) { [WebInv.InventoryStore]::FailPoint = 'correction' }
                    $threw = $false; try { [void](& $splitOne $s) } catch { $threw = $true }
                }
                finally { [WebInv.InventoryStore]::FailPoint = ''; $s.Dispose() }
            }
            $s = [WebInv.InventoryStore]::Open($rb, 'file', 2, $ScriptVersion, 'write', 0); $s.Dispose()
            # (change digests differ: each store's correction carries its own time; the resulting inventory must not)
            $lc = @([IO.File]::ReadAllLines((Join-Path $rb 'archive/ledger.jsonl')) | Where-Object { $_ -like '*"type":"correction"*' }).Count
            $threw -and $lc -eq 1 -and ([WebInv.StoreSelfTest]::FinalState($ra) -eq [WebInv.StoreSelfTest]::FinalState($rb)) -and (& $verifyAt $rb)
        }
        Assert 'store: backfill of an older run replays in run order (final state equals the in-order store)' {
            $rc = Join-Path $tmp 'backfill'
            $s = [WebInv.InventoryStore]::Open($rc, 'file', 2, $ScriptVersion, 'write', 0)
            try {
                [void]$s.Ingest($runs[0], $false); [void]$s.Ingest($runs[2], $false)
                $old = $false; try { [void]$s.Ingest($runs[1], $false) } catch { $old = $_.Exception.Message -like '*Backfill*' }
                $l = New-Object 'System.Collections.Generic.List[WebInv.RunSources]'; $l.Add($runs[1])
                [void]$s.Backfill($l, $false)
            }
            finally { $s.Dispose() }
            $old -and ([WebInv.StoreSelfTest]::FinalState($rc) -eq [WebInv.StoreSelfTest]::FinalState((Join-Path $tmp 'store-file'))) -and (& $verifyAt $rc)
        }
        Assert 'store: -SnapshotEvery thins state files; -AsOf replays a run without one (same rows)' {
            $rd = Join-Path $tmp 'thin'
            $s = [WebInv.InventoryStore]::Open($rd, 'file', 2, $ScriptVersion, 'write', 0)
            try {
                $s.SetOptions(2, -1, $false, '')
                foreach ($r in $runs) { [void]$s.Ingest($r, $false) }
                $q = $s.Query('Inventory', $null, [string[]]@('All'), $null, '', '', '2026-01-06T12:00:00+00:00')
                $msg = $s.Messages -join ' '
            }
            finally { $s.Dispose() }
            $s = [WebInv.InventoryStore]::Open((Join-Path $tmp 'store-file'), 'auto', 0, $ScriptVersion, 'read', 0)
            try { $full = $s.Query('Inventory', $null, [string[]]@('All'), $null, '', '', '2026-01-06T12:00:00+00:00') } finally { $s.Dispose() }
            $states = @(Get-ChildItem -LiteralPath (Join-Path $rd 'archive') -Recurse -Filter 'state.jsonl.gz').Count
            $a = @($q.Rows | ForEach-Object { $_ -join '|' }) -join "`n"; $b = @($full.Rows | ForEach-Object { $_ -join '|' }) -join "`n"
            $states -eq 2 -and $msg -like '*replayed in memory*' -and $a -eq $b -and $q.Rows.Count -gt 0 -and (& $verifyAt $rd)
        }
    }
    finally { try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction Stop } catch { Write-RunLog ("SELFTEST note: temp folder not removed: {0}" -f $tmp) } }
}
#endregion


#region ---------- Rule packs: load / import / export / test ----------
$script:PackInfo = New-Object System.Collections.Generic.List[string]
function Import-RulePack {
    param([string]$Json, [string]$Label, [string]$Path, [bool]$Fatal)
    try { $pack = [WebInv.Matcher]::ReadPack($Json) }
    catch {
        $m = "Rule pack '$Label' is not valid JSON: $($_.Exception.Message)"
        if ($Fatal) { Stop-Fatal $m }
        Write-ErrLog 'RULES' $Label $m; return
    }
    $errs = New-Object 'System.Collections.Generic.List[string]'
    $n = [WebInv.Matcher]::Load($pack, $errs)
    foreach ($e in $errs) { Write-ErrLog 'RULES' $Label $e }
    $bytes = if ($Path) { [IO.File]::ReadAllBytes($Path) } else { [Text.Encoding]::UTF8.GetBytes($Json) }
    $info = "rules '{0}' v{1}: loaded {2}/{3} (skipped {4}) sha256={5} src={6}{7}" -f $pack.Name, $pack.Version, $n, @($pack.Rules).Count, $errs.Count, [WebInv.Hash]::Sha256Hex($bytes), $pack.Source, $(if ($Path) { " file=$Path" } else { '' })
    $script:PackInfo.Add($info)
    Write-RunLog $info
    if ($Fatal -and $n -eq 0) { Stop-Fatal "Rule pack '$Label' loaded zero rules" }
}

function Initialize-Rules {
    [WebInv.Matcher]::Clear()
    Import-RulePack -Json $BuiltinRulesJson -Label 'builtin' -Path '' -Fatal $true
    if (-not $NoCompanionRules -and $PSScriptRoot) {
        foreach ($f in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'WebInventory.rules.*.json' -File -ErrorAction SilentlyContinue)) {
            Import-RulePack -Json ([IO.File]::ReadAllText($f.FullName)) -Label $f.Name -Path $f.FullName -Fatal $false
        }
    }
    foreach ($rf in @($RulesFile | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $rf -PathType Leaf)) { Stop-Fatal "Rules file not found: $rf" }
        $full = (Resolve-Path -LiteralPath $rf).ProviderPath
        Import-RulePack -Json ([IO.File]::ReadAllText($full)) -Label (Split-Path -Leaf $full) -Path $full -Fatal $true
    }
}

# Upstream commit of a git checkout (walks up from the import path); recorded in the pack for provenance / GPL source traceability
function Get-GitCommit {
    param([string]$Path)
    $dir = (Resolve-Path -LiteralPath $Path).ProviderPath
    for ($i = 0; $i -lt 4 -and $dir; $i++) {
        $head = Join-Path $dir '.git/HEAD'
        if (Test-Path -LiteralPath $head) {
            $h = ([IO.File]::ReadAllText($head)).Trim()
            if ($h -notmatch '^ref:\s*(.+)$') { return $h }
            $ref = $Matches[1].Trim()
            $rf = Join-Path $dir ('.git/' + $ref)
            if (Test-Path -LiteralPath $rf) { return ([IO.File]::ReadAllText($rf)).Trim() }
            $packed = Join-Path $dir '.git/packed-refs'
            if (Test-Path -LiteralPath $packed) { foreach ($l in [IO.File]::ReadAllLines($packed)) { if ($l.EndsWith(' ' + $ref)) { return $l.Split(' ')[0] } } }
            return $null
        }
        $dir = Split-Path -Parent $dir
    }
    $null
}

function Get-XmlText($Node) { if ($null -eq $Node) { return $null }; if ($Node -is [string]) { return $Node }; return $Node.InnerText }

# Rapid7 Recog XML -> rule pack (BSD-2-Clause data). Ruby regex dialect converted to .NET.
function Convert-RecogRules {
    param([string]$Path)
    $files = if (Test-Path -LiteralPath $Path -PathType Container) { @(Get-ChildItem -LiteralPath $Path -Filter *.xml -File) } else { @(Get-Item -LiteralPath $Path) }
    $map = @{
        'http_header.server' = @('header:server', 'Web server', 85); 'html_title' = @('title', 'Web application', 85)
        'http_header.cookie' = @('setcookie', 'Web technology', 80); 'http_header.wwwauth' = @('auth', 'Web application', 85)
        'http_header.x-powered-by' = @('header:x-powered-by', 'Web technology', 85); 'favicon.md5' = @('favicon.md5', 'Web application', 90)
        'x509.subject' = @('cert.subject', 'TLS service', 80); 'x509.issuer' = @('cert.issuer', 'TLS service', 70)
        'ssh.banner' = @('banner.ssh', 'Remote access', 90); 'ftp.banner' = @('banner.ftp', 'File transfer', 90)
        'smtp.banner' = @('banner.smtp', 'Mail', 85); 'pop3.banner' = @('banner.pop3', 'Mail', 85); 'imap4.banner' = @('banner.imap', 'Mail', 85)
        'mysql.banners' = @('banner.mysql', 'Database', 85); 'apache_os' = @('header:server', 'OS', 60)
        # v2.3 opt-in probes (-Smb, -Snmp, -TlsFingerprint)
        'smb.native_os' = @('smb.nativeos', 'OS', 85); 'smb.native_lm' = @('smb.nativelm', 'File sharing', 85)
        'snmp.sys_description' = @('snmp.sysdescr', 'Network device', 85); 'snmp.sys_object_id' = @('snmp.sysobjid', 'Network device', 90)
        'tls.jarm' = @('tls.jarm', 'TLS service', 70)
    }
    $rules = New-Object System.Collections.Generic.List[WebInv.RuleDef]
    $stats = @{ Files = 0; Skipped = 0; NoOutput = 0 }
    foreach ($f in $files) {
        try { [xml]$x = [IO.File]::ReadAllText($f.FullName) } catch { Write-ErrLog 'RULES' $f.Name "XML parse failed: $($_.Exception.Message)"; continue }
        $m = [string]$x.fingerprints.matches
        $spec = $null
        if ($map.ContainsKey($m)) { $spec = $map[$m] } elseif ($m -like 'http_header.*') { $spec = @(('header:' + $m.Substring(12).ToLowerInvariant()), 'Web technology', 80) }
        if (-not $spec) { $stats.Skipped++; Write-RunLog "recog: skipping $($f.Name) (matches='$m' has no equivalent observation)"; continue }
        $stats.Files++
        $idx = 0
        foreach ($fp in @($x.fingerprints.fingerprint)) {
            $idx++
            $vals = @{}
            foreach ($p in @($fp.param)) { if ($p -and $p.name) { $vals[$p.name] = @{ Pos = [int]$p.pos; Value = [string]$p.value } } }
            $tpl = {
                param($name)
                if (-not $vals.ContainsKey($name)) { return $null }
                $v = $vals[$name]
                if ($v.Pos -gt 0) { return '{' + $v.Pos + '}' }
                $s = $v.Value
                foreach ($k in @($vals.Keys)) {
                    if ($s -and $s.Contains('{' + $k + '}')) {
                        $rv = if ($vals[$k].Pos -gt 0) { '{' + $vals[$k].Pos + '}' } else { $vals[$k].Value }
                        $s = $s.Replace('{' + $k + '}', $rv)
                    }
                }
                $s
            }
            $outs = New-Object System.Collections.Generic.List[WebInv.OutDef]
            $hwDevice = & $tpl 'hw.device'
            foreach ($pre in 'service', 'service.component', 'os', 'hw') {
                $product = & $tpl "$pre.product"; $vendor = & $tpl "$pre.vendor"; $family = & $tpl "$pre.family"
                $name = $null
                $vFirst = if ($vendor) { ($vendor -split '[\s,]+')[0] } else { '' }
                if ($product) {
                    $redundant = (-not $vendor) -or $product.StartsWith($vFirst, [StringComparison]::OrdinalIgnoreCase) -or ($vendor.IndexOf($product, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or ($product.IndexOf($vendor, [StringComparison]::OrdinalIgnoreCase) -ge 0)
                    $name = if ($redundant) { $product } else { "$vendor $product" }
                }
                elseif ($family -and $pre -ne 'service.component') { $name = if ($vendor -and $family.IndexOf($vendor, [StringComparison]::OrdinalIgnoreCase) -lt 0) { "$vendor $family" } else { $family } }
                if (-not $name) { continue }
                $o = New-Object WebInv.OutDef
                $o.T = switch ($pre) { 'os' { 'os' } 'hw' { 'hw' } default { 'service' } }
                $o.N = $name
                $o.V = & $tpl "$pre.version"
                $o.P = & $tpl "$pre.cpe23"
                $o.C = switch ($pre) { 'os' { 'OS' } 'hw' { if ($hwDevice) { $hwDevice } else { 'Hardware' } } default { if ($hwDevice) { $hwDevice } else { $spec[1] } } }
                $cert = & $tpl "$pre.certainty"
                $k = $spec[2]
                if ($cert) { $d = 0.0; if ([double]::TryParse($cert, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $k = [Math]::Max(10, [int]([Math]::Round($d * 100))) } }
                $o.K = [Math]::Min(100, $k)
                $hn = & $tpl 'host.name'; if ($hn -and $hn.StartsWith('{')) { $o.H = $hn }
                $outs.Add($o)
            }
            if ($outs.Count -eq 0) { $stats.NoOutput++; continue }
            $flags = [string]$fp.flags; $opt = ''
            if ($flags -match 'REG_ICASE') { $opt += 'i' }
            if ($flags -match 'REG_DOT_NEWLINE|REG_MULTILINE') { $opt += 's' }
            $rd = New-Object WebInv.RuleDef
            $rd.Id = 'recog:{0}:{1}' -f $f.BaseName, $idx
            $rd.F = $spec[0]
            $rd.R = [WebInv.Matcher]::FromRuby([string]$fp.pattern)
            if ($opt) { $rd.O = $opt }
            $rd.Src = 'recog'
            $rd.Out = $outs.ToArray()
            $ex = @($fp.example) | Select-Object -First 1
            if ($ex) {
                $txt = Get-XmlText $ex
                if ($ex -isnot [string] -and $ex.GetAttribute('_encoding') -eq 'base64') { try { $txt = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($txt)) } catch { $txt = $null } }
                if ($txt) {
                    $rd.Ex = $txt
                    if ($ex -isnot [string]) {
                        foreach ($o in $rd.Out) {
                            if ($o.V) { $pre = switch ($o.T) { 'os' { 'os' } 'hw' { 'hw' } default { 'service' } }; $ev = $ex.GetAttribute("$pre.version"); if ($ev -and $o.V.StartsWith('{')) { $rd.Exv = $ev }; break }
                        }
                    }
                }
            }
            $rules.Add($rd)
        }
    }
    Write-RunLog ("recog: {0} files converted, {1} skipped, {2} rules, {3} fingerprints without product output" -f $stats.Files, $stats.Skipped, $rules.Count, $stats.NoOutput)
    $pack = New-Object WebInv.RulePack
    $pack.Name = 'recog'; $pack.Version = (Get-Date).ToString('yyyy.MM.dd')
    $commit = Get-GitCommit $Path
    if ($commit) { $pack.Version += '+' + $commit.Substring(0, 12) }
    $pack.Source = 'Rapid7 Recog https://github.com/rapid7/recog' + $(if ($commit) { " commit $commit" } else { '' }) + ' (converted by Invoke-WebInventory.ps1)'
    $pack.License = 'BSD-2-Clause. Copyright 2014, Rapid7, Inc.'
    $pack.Generated = (Get-Date).ToString('o')
    $pack.Rules = $rules.ToArray()
    $pack
}

# webappanalyzer (Wappalyzer fork) technologies/*.json -> rule pack (GPL-3.0 data: keep the pack internal, retain the notice)
function Convert-WappalyzerRules {
    param([string]$Path)
    $techDir = $Path
    if (Test-Path -LiteralPath (Join-Path $Path 'technologies') -PathType Container) { $techDir = Join-Path $Path 'technologies' }
    elseif (Test-Path -LiteralPath (Join-Path $Path 'src/technologies') -PathType Container) { $techDir = Join-Path $Path 'src/technologies' }
    $catFile = @((Join-Path $techDir '../categories.json'), (Join-Path $Path 'categories.json'), (Join-Path $Path 'src/categories.json')) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    function Get-K($D, [string]$K) { if ($D -is [System.Collections.IDictionary] -and $D.ContainsKey($K)) { return $D[$K] }; $null }
    function Get-List($V) { if ($null -eq $V) { return @() }; if ($V -is [string]) { return @($V) }; if ($V -is [System.Collections.IDictionary]) { return @() }; return @($V) }
    $wSep = [regex]::Escape('\' + ';')    # Wappalyzer field separator: backslash + semicolon
    function Get-Names($V) { @(Get-List $V | ForEach-Object { ([string]$_ -split $wSep)[0] } | Where-Object { $_ }) }
    $cats = @{}
    if ($catFile) { foreach ($kv in ([WebInv.Json]::Parse([IO.File]::ReadAllText($catFile))).GetEnumerator()) { $cats[$kv.Key] = [string](Get-K $kv.Value 'name') } }
    $rules = New-Object System.Collections.Generic.List[WebInv.RuleDef]
    $skipped = 0; $script:WordGuarded = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $techDir -Filter *.json -File)) {
        try { $d = [WebInv.Json]::Parse([IO.File]::ReadAllText($f.FullName)) } catch { Write-ErrLog 'RULES' $f.Name "JSON parse failed: $($_.Exception.Message)"; continue }
        foreach ($tp in $d.GetEnumerator()) {
            $name = $tp.Key; $t = $tp.Value
            $cat = ''; foreach ($c in (Get-List (Get-K $t 'cats'))) { $ck = [string]$c; if ($cats.ContainsKey($ck)) { $cat = $cats[$ck]; break } }
            $pairs = New-Object System.Collections.Generic.List[object]
            foreach ($kind in 'headers', 'cookies', 'meta') {
                $obj = Get-K $t $kind
                if (-not ($obj -is [System.Collections.IDictionary])) { continue }
                foreach ($p in $obj.GetEnumerator()) {
                    $key = $p.Key.ToLowerInvariant()
                    foreach ($pat in (Get-List $p.Value)) {
                        switch ($kind) {
                            'headers' { $pairs.Add(@(('header:' + $key), [string]$pat, 90)) }
                            'meta' { $pairs.Add(@(('meta:' + $key), [string]$pat, 90)) }
                            'cookies' {
                                # cookie names are sometimes regex-escaped ('connect\.sid') or globbed ('_ga_*')
                                $lit = $p.Key -replace '\\(.)', '$1'
                                if ($lit.Contains('*')) { $pairs.Add(@('cookiename', ('^' + [regex]::Escape($lit).Replace('\*', '.*') + '$'), 85)) }
                                else { $pairs.Add(@(('cookie:' + $lit.ToLowerInvariant()), [string]$pat, 90)) }
                            }
                        }
                    }
                }
            }
            foreach ($pat in (Get-List (Get-K $t 'scriptSrc'))) { $pairs.Add(@('scriptsrc', [string]$pat, 90)) }
            foreach ($kind in 'html', 'scripts', 'text') { foreach ($pat in (Get-List (Get-K $t $kind))) { $pairs.Add(@('body', [string]$pat, 80)) } }
            foreach ($pat in (Get-List (Get-K $t 'url'))) { $pairs.Add(@('url', [string]$pat, 80)) }
            foreach ($pat in (Get-List (Get-K $t 'certIssuer'))) { $pairs.Add(@('cert.issuer', [string]$pat, 85)) }
            foreach ($pat in (Get-List (Get-K $t 'robots'))) { $pairs.Add(@('robots', [string]$pat, 80)) }
            if ($pairs.Count -eq 0) { $skipped++; continue }
            $cpe = [string](Get-K $t 'cpe')
            $im = Get-Names (Get-K $t 'implies'); $xs = Get-Names (Get-K $t 'excludes'); $rq = Get-Names (Get-K $t 'requires')
            # requiresCategory: only valid when something in that category (e.g. an e-commerce platform) was also detected
            $rcn = @(Get-List (Get-K $t 'requiresCategory') | ForEach-Object { $ck = [string]$_; if ($cats.ContainsKey($ck)) { $cats[$ck] } } | Where-Object { $_ })
            $i = 0
            foreach ($pr in $pairs) {
                $i++
                $parts = $pr[1] -split $wSep
                $o = New-Object WebInv.OutDef
                $o.N = $name; $o.C = $cat; $o.K = $pr[2]
                $o.T = 'service'
                if ($cat -eq 'Operating systems') { $o.T = 'os'; $o.C = 'OS' }
                if ($cpe) { $o.P = $cpe }
                if ($im.Count) { $o.Im = [string[]]$im }
                if ($xs.Count) { $o.Xs = [string[]]$xs }
                if ($rq.Count) { $o.Rq = [string[]]$rq }
                if ($rcn.Count) { $o.Rc = [string[]]$rcn }
                foreach ($extra in ($parts | Select-Object -Skip 1)) {
                    if ($extra -match '^version:(.*)$') {
                        $vt = $Matches[1]
                        if ($vt -match '^\\(\d)\?(.*):(.*)$') { $vt = $Matches[2] }
                        $o.V = [regex]::Replace($vt, '\\(\d)', '{$1}')
                    }
                    elseif ($extra -match '^confidence:(\d+)') { $o.K = [Math]::Min(100, [int]$Matches[1]) }
                }
                $rd = New-Object WebInv.RuleDef
                $rd.Id = 'wappalyzer:{0}:{1}' -f $name, $i
                # JS regex semantics: identity escapes, [^], and ^/$ anchored to the whole value (Wappalyzer compiles with flag 'i' only)
                $rx = [WebInv.Matcher]::FromJs($parts[0])
                # false-positive guard: a bare word in a header pattern must start at a word boundary
                # (upstream 'Bun' otherwise matches 'PHP/8.1.2-1ubuntu2'); prefix matches such as 'Plesk' in 'PleskLin' still work
                if ($pr[0] -like 'header:*' -and $rx -match '^[A-Za-z][A-Za-z0-9 _-]*$') { $rx = '\b' + $rx; $script:WordGuarded++ }
                $rd.F = $pr[0]; $rd.R = $rx; $rd.O = 'ia'; $rd.Src = 'wappalyzer'
                $rd.Out = [WebInv.OutDef[]]@($o)
                $rules.Add($rd)
            }
        }
    }
    Write-RunLog ("wappalyzer: {0} rules from {1}; {2} technologies had no passive HTTP patterns (JS/DOM/DNS only); {3} bare-word header patterns given a leading word boundary" -f $rules.Count, $techDir, $skipped, $script:WordGuarded)
    $commit = Get-GitCommit $Path
    $pack = New-Object WebInv.RulePack
    $pack.Name = 'wappalyzer'; $pack.Version = (Get-Date).ToString('yyyy.MM.dd') + $(if ($commit) { '+' + $commit.Substring(0, 12) } else { '' })
    $pack.Source = 'enthec/webappanalyzer https://github.com/enthec/webappanalyzer' + $(if ($commit) { " commit $commit" } else { '' }) + ' (converted by Invoke-WebInventory.ps1; passive HTTP patterns only)'
    $pack.License = 'GPL-3.0 (source data). Keep this pack with its notice; do not redistribute outside your organisation without reviewing GPL terms.'
    $pack.Generated = (Get-Date).ToString('o')
    $pack.Rules = $rules.ToArray()
    $pack
}

function Invoke-ImportRules {
    $fmt = $ImportFormat
    if ($fmt -eq 'Auto') {
        if (Test-Path -LiteralPath $ImportRules -PathType Container) {
            if (@(Get-ChildItem -LiteralPath $ImportRules -Filter *.xml -File -ErrorAction SilentlyContinue).Count) { $fmt = 'Recog' } else { $fmt = 'Wappalyzer' }
        }
        elseif ($ImportRules -like '*.xml') { $fmt = 'Recog' } else { $fmt = 'Wappalyzer' }
    }
    $pack = if ($fmt -eq 'Recog') { Convert-RecogRules $ImportRules } else { Convert-WappalyzerRules $ImportRules }
    # reviewed NVD CPE names for products the upstream data leaves without one (or with a wrong one)
    $cs = [WebInv.Matcher]::ApplyCpeSupplement($pack, $CpeSupplementJson)
    $sv = [string]([WebInv.Json]::Parse($CpeSupplementJson))['version']
    if ($cs[0] + $cs[1]) { $pack.Source += ('; CPEs completed for {0} rule outputs and corrected for {1} by WebInventory cpe-supplement {2}' -f $cs[0], $cs[1], $sv) }
    Write-RunLog ("cpe-supplement {0}: {1} rule outputs given a CPE, {2} wrong upstream CPEs corrected" -f $sv, $cs[0], $cs[1])
    # validate: compile every rule; drop the ones .NET cannot compile
    [WebInv.Matcher]::Clear()
    $errs = New-Object 'System.Collections.Generic.List[string]'
    [void][WebInv.Matcher]::Load($pack, $errs)
    $tested = 0; $fails = [WebInv.Matcher]::TestExamples([ref]$tested)
    $bad = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($e in $errs) { Write-ErrLog 'RULES' 'import' $e; [void]$bad.Add(($e -split ':\s')[0]) }
    # a rule that cannot match its own published example under .NET (dialect gap or catastrophic backtracking) is dropped
    foreach ($e in $fails) { Write-ErrLog 'RULES' 'import' ("dropped, example check failed: {0}" -f $e); [void]$bad.Add(($e -split ':\s')[0]) }
    $pack.Rules = @($pack.Rules | Where-Object { -not $bad.Contains($_.Id) })
    $out = if ($ImportOutput) { $ImportOutput } else { Join-Path (Get-Location).ProviderPath ("WebInventory.rules.{0}.json" -f $fmt.ToLowerInvariant()) }
    [IO.File]::WriteAllText($out, [WebInv.Matcher]::WritePack($pack), $script:Utf8NoBom)
    $msg = "Imported {0} rules ({1}). Dropped {2} that .NET could not compile and {3} that failed their own example ({4} examples checked). Wrote {5}" -f $pack.Rules.Count, $fmt, $errs.Count, $fails.Count, $tested, $out
    Write-RunLog $msg; Write-Host $msg -ForegroundColor Cyan
    Write-Host "Place the file next to Invoke-WebInventory.ps1 (auto-loaded) or pass it with -RulesFile." -ForegroundColor DarkGray
}

function Invoke-TestRules {
    $tested = 0
    $fails = [WebInv.Matcher]::TestExamples([ref]$tested)
    foreach ($f in $fails) { Write-ErrLog 'RULES' 'example' $f }
    foreach ($i in $script:PackInfo) { Write-Host $i }
    $c = if ($fails.Count) { 'Yellow' } else { 'Green' }
    Write-Host ("{0} rules loaded; {1} carry examples; {2} example mismatches (see error log)" -f [WebInv.Matcher]::Count, $tested, $fails.Count) -ForegroundColor $c
    if ($fails.Count) { $script:ExitCode = 2 }
}
#endregion

#region ---------- Self-test (no network) ----------
function Invoke-SelfTest {
    $script:StPass = 0; $script:StFail = 0
    function Assert([string]$Name, [scriptblock]$Test) {
        $ok = $false; $err = ''
        try { $ok = [bool](& $Test) } catch { $err = $_.Exception.Message }
        if ($ok) { $script:StPass++; Write-RunLog "SELFTEST PASS $Name" }
        else { $script:StFail++; Write-RunLog "SELFTEST FAIL $Name $err" 'ERROR'; Write-ErrLog 'SELFTEST' $Name "failed $err"; Write-Host "FAIL  $Name $err" -ForegroundColor Red }
    }
    function Throws([scriptblock]$Sb) { try { & $Sb | Out-Null; $false } catch { $true } }
    $A = [Text.Encoding]::ASCII
    # hashing (vectors computed with Python mmh3/hashlib)
    Assert 'mmh3("foo")' { [WebInv.Hash]::Mmh3($A.GetBytes('foo')) -eq -156908512 }
    Assert 'mmh3("")' { [WebInv.Hash]::Mmh3($A.GetBytes('')) -eq 0 }
    Assert 'mmh3("hello world")' { [WebInv.Hash]::Mmh3($A.GetBytes('hello world')) -eq 1586663183 }
    $vec = New-Object byte[] 768; for ($i = 0; $i -lt 768; $i++) { $vec[$i] = [byte]($i % 256) }
    Assert 'favicon hash (base64.encodebytes semantics)' { [WebInv.Hash]::FaviconHash($vec) -eq 1836528006 }
    Assert 'md5 empty' { [WebInv.Hash]::Md5Hex([byte[]]@()) -eq 'd41d8cd98f00b204e9800998ecf8427e' }
    Assert 'md5 55/56/64 byte padding edges' { ([WebInv.Hash]::Md5Hex($A.GetBytes('a' * 55)) -eq 'ef1772b6dff9a122358552954ad0df65') -and ([WebInv.Hash]::Md5Hex($A.GetBytes('a' * 56)) -eq '3b0c8ac703f828b04c6c197006d17218') -and ([WebInv.Hash]::Md5Hex($A.GetBytes('a' * 64)) -eq '014842d480b571495a4a0363793f7367') }
    Assert 'md5 768-byte vector' { [WebInv.Hash]::Md5Hex($vec) -eq 'e6899eaaf06fd702f3ed3f988eb19362' }
    Assert 'sha256 platform' { [WebInv.Hash]::Sha256Hex($vec) -eq 'f3a25aa93aa2fbba28d79260535bbd6a5eb0fc1c24a8b0f04e12b484c1dfe363' }
    Assert 'sha256 managed' { [WebInv.Hash]::Hex([WebInv.Hash]::Sha256Managed($vec)) -eq 'f3a25aa93aa2fbba28d79260535bbd6a5eb0fc1c24a8b0f04e12b484c1dfe363' }
    Assert 'sha256 managed empty' { [WebInv.Hash]::Hex([WebInv.Hash]::Sha256Managed([byte[]]@())) -eq 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
    # ports
    Assert 'ports list+range' { (Expand-Ports '80,443,8000-8002').Count -eq 5 }
    Assert 'ports keyword web' { (Expand-Ports 'web').Count -eq 26 }
    Assert 'ports dedupe' { (Expand-Ports '80,80,web').Count -eq 26 }
    Assert 'ports invalid 0' { Throws { Expand-Ports '0' } }
    Assert 'ports invalid 70000' { Throws { Expand-Ports '70000' } }
    Assert 'ports reversed range' { Throws { Expand-Ports '90-80' } }
    # host specs
    Assert 'cidr /30' { (Get-SpecRanges '10.0.0.0/30').Count -eq 4 }
    Assert 'cidr /32' { (Get-SpecRanges '10.0.0.7/32').Count -eq 1 }
    Assert 'cidr non-aligned base' { $r = Get-SpecRanges '10.0.0.77/24'; $r.Ranges[0][0] -eq [WebInv.Util]::Ip4('10.0.0.0') }
    Assert 'full dash range' { (Get-SpecRanges '10.0.0.250-10.0.1.5').Count -eq 12 }
    Assert 'last-octet range' { (Get-SpecRanges '10.0.0.1-50').Count -eq 50 }
    Assert 'nmap octets' { (Get-SpecRanges '192.168.0-1.1-2').Count -eq 4 }
    Assert 'nmap octets with list' { (Get-SpecRanges '192.168.3-5,7.1').Count -eq 4 }
    Assert 'bad octet 300' { Throws { Get-SpecRanges '10.0.0.300' } }
    Assert 'bad cidr /33' { Throws { Get-SpecRanges '10.0.0.0/33' } }
    Assert 'hostname spec' { $r = Get-SpecRanges 'web01.corp.local'; $r.Names[0] -eq 'web01.corp.local' }
    Assert 'ipv6 spec' { $r = Get-SpecRanges '::1'; $r.Names[0] -eq '::1' }
    Assert 'garbage spec' { Throws { Get-SpecRanges 'bad host!' } }
    Assert 'partial numeric refused (no inet_aton surprises)' { (Throws { Get-SpecRanges '7.1' }) -and (Throws { Get-SpecRanges '443' }) -and (Throws { Get-SpecRanges '10.0.0' }) }
    Assert 'split host:ports' { $h = Split-HostPort 'web01:80,443'; $h.Spec -eq 'web01' -and $h.Ports -eq '80,443' }
    Assert 'split [v6]:port' { $h = Split-HostPort '[fe80::1]:8443'; $h.Spec -eq 'fe80::1' -and $h.Ports -eq '8443' }
    Assert 'split url' { $h = Split-HostPort 'https://app.corp:8443/x'; $h.Spec -eq 'app.corp' -and $h.Ports -eq '8443' -and $h.Scheme -eq 'https' }
    Assert 'split cidr:port' { $h = Split-HostPort '10.0.0.0/24:80'; $h.Spec -eq '10.0.0.0/24' -and $h.Ports -eq '80' }
    # exclusion / scope sets
    $set = New-Object WebInv.RangeSet
    Add-SpecToSet $set '10.1.0.0/16'; Add-SpecToSet $set 'printer01.corp.local'; Add-SpecToSet $set '192.168.1.1-20'
    Assert 'rangeset cidr hit' { $set.Contains('10.1.200.3', '') }
    Assert 'rangeset miss' { -not $set.Contains('10.2.0.1', 'x') }
    Assert 'rangeset name hit' { $set.Contains('10.9.9.9', 'PRINTER01.corp.local') }
    Assert 'rangeset octet range' { $set.Contains('192.168.1.20', '') -and -not $set.Contains('192.168.1.21', '') }
    Assert 'ip4 strict' { [WebInv.Util]::Ip4('1.2.3') -eq -1 -and [WebInv.Util]::Ip4('1.2.3.256') -eq -1 -and [WebInv.Util]::Ip4('255.255.255.255') -eq 4294967295 }
    # DER: Go-format DN (vector taken from Recog x509_subjects examples) and SANs
    $der = [Convert]::FromBase64String($script:SelfTestCertB64)
    $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$der)
    Assert 'Go-format subject DN' { [WebInv.Der]::GoName($c.SubjectName.RawData) -eq 'CN=127.0.0.1,OU=Endpoint Health,O=Duo Security\, Inc.,L=Ann Arbor,ST=Michigan,C=US,1.2.840.113549.1.9.1=#0c1e656e64706f696e746865616c74684064756f73656375726974792e636f6d' }
    Assert 'SAN parse (DNS/IP v4+v6/email)' { ([WebInv.Der]::SubjectAltNames($c) -join ' ') -eq 'DNS:web01.lab.local DNS:*.lab.local IP:10.1.2.3 IP:::1 EMAIL:a@b.c' }
    # TLS ClientHello framing
    foreach ($mode in 'tls13', 'tls12', 'tls11', 'tls10', 'ssl3', 'weak') {
        $m = $mode
        Assert "ClientHello framing $m" {
            $b = [WebInv.Tls]::BuildClientHello($m, 'app.example.com')
            $recLen = ($b[3] * 256) + $b[4]; $hsLen = ($b[6] * 65536) + ($b[7] * 256) + $b[8]
            $b[0] -eq 0x16 -and $recLen -eq ($b.Length - 5) -and $hsLen -eq ($recLen - 4) -and $b[5] -eq 1
        }
    }
    Assert 'ClientHello SNI omitted for IP' { $a = [WebInv.Tls]::BuildClientHello('tls12', '10.0.0.1'); $n = [WebInv.Tls]::BuildClientHello('tls12', 'a.example'); $a.Length -lt $n.Length }
    Assert 'weak suite classifier' { [WebInv.Tls]::IsWeakSuite(0x0005) -and [WebInv.Tls]::IsWeakSuite(0x000A) -and -not [WebInv.Tls]::IsWeakSuite(0xC02F) }
    # rule engine
    Assert 'builtin rules loaded' { [WebInv.Matcher]::Count -gt 300 }
    $o = New-Object WebInv.Observation; $o.Port = 443
    $o.Add('header:server', 'Microsoft-IIS/10.0'); $o.Add('header:x-aspnet-version', '4.0.30319'); $o.Add('title', 'IIS Windows Server'); $o.Add('scriptsrc', '/js/jquery-1.12.4.min.js')
    $d = [WebInv.Matcher]::Evaluate($o)
    Assert 'detect IIS + version + CPE' { @($d | Where-Object { $_.Name -eq 'Microsoft IIS' -and $_.Version -eq '10.0' -and $_.Cpe -like 'cpe:2.3:a:microsoft:internet_information_services:10.0:*' }).Count -eq 1 }
    Assert 'merge carries DefaultPage flag' { @($d | Where-Object { $_.Name -eq 'Microsoft IIS' -and $_.Flag -match 'DefaultPage' }).Count -eq 1 }
    Assert 'detect jQuery version from script src' { @($d | Where-Object { $_.Name -eq 'jQuery' -and $_.Version -eq '1.12.4' }).Count -eq 1 }
    Assert 'os hint from IIS' { @($d | Where-Object { $_.Kind -eq 'os' -and $_.Name -eq 'Microsoft Windows' }).Count -eq 1 }
    $o2 = New-Object WebInv.Observation; $o2.Port = 8080; $o2.Add('header:x-jenkins', '2.401.3')
    Assert 'implies (Jenkins -> Java)' { @([WebInv.Matcher]::Evaluate($o2) | Where-Object { $_.Name -eq 'Java' }).Count -eq 1 }
    $o3 = New-Object WebInv.Observation; $o3.Port = 5985; $o3.Add('header:server', 'Microsoft-HTTPAPI/2.0')
    Assert 'port-scoped rule (WinRM)' { @([WebInv.Matcher]::Evaluate($o3) | Where-Object { $_.Name -eq 'Microsoft WinRM' }).Count -eq 1 }
    $o4 = New-Object WebInv.Observation; $o4.Port = 80; $o4.Add('header:server', 'Microsoft-HTTPAPI/2.0')
    Assert 'port-scoped rule not on 80' { @([WebInv.Matcher]::Evaluate($o4) | Where-Object { $_.Name -eq 'Microsoft WinRM' }).Count -eq 0 }
    $o5 = New-Object WebInv.Observation; $o5.Add('path:/certsrv/.status', '401'); $o5.Add('status', '200'); $o5.Add('path:/certsrv/.auth', 'Negotiate')
    Assert 'AND/NOT conditions (AD CS)' { @([WebInv.Matcher]::Evaluate($o5) | Where-Object { $_.Name -eq 'AD CS Web Enrollment' }).Count -eq 1 }
    $o5.Add('status', '401')
    Assert 'NOT condition blocks site-wide 401' { @([WebInv.Matcher]::Evaluate($o5) | Where-Object { $_.Name -eq 'AD CS Web Enrollment' }).Count -eq 0 }
    Assert 'CPE 2.2 -> 2.3' { [WebInv.Matcher]::NormalizeCpe('cpe:/a:apache:http_server:{v}', '2.4.58') -eq 'cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*' }
    # CPE supplement: reviewed NVD names, applied when a Recog/Wappalyzer pack is imported
    Assert 'CPE key (escapes, URI encoding)' { ([WebInv.Matcher]::CpeKey('cpe:2.3:a:joomla:joomla\!:3.9.1') -eq 'a:joomla:joomla!') -and ([WebInv.Matcher]::CpeKey('cpe:/a:treck:tcp%2fip:-') -eq 'a:treck:tcp/ip') -and ([WebInv.Matcher]::CpeKey('nope') -eq '') }
    $sup = [WebInv.Json]::Parse($CpeSupplementJson)
    Assert 'CPE supplement parses (fill, replace, aliases, platforms)' { @($sup['fill']).Count -gt 400 -and @($sup['replace']).Count -ge 1 -and @($sup['aliases']).Count -gt 100 -and @($sup['platforms']).Count -gt 10 -and @($sup['fill'] | Where-Object { [string]$_['p'] -notmatch '^cpe:2\.3:[aho]:([^:\\]|\\.)+:([^:\\]|\\.)+:\{v\}$' }).Count -eq 0 }
    $cpk = [WebInv.Matcher]::ReadPack('{"name":"cpetest","rules":[{"id":"c1","f":"x","r":"a","out":[{"n":"Ninja Forms","k":90}]},{"id":"c2","f":"x","r":"b","out":[{"n":"Mattermost","p":"cpe:2.3:a:jenkins:mattermost:*:*:*:*:*:*:*:*","k":90}]},{"id":"c3","f":"x","r":"c","out":[{"n":"Mattermost","p":"cpe:2.3:a:mattermost:mattermost:*","k":90}]},{"id":"c4","f":"x","r":"d","out":[{"n":"Ninja Forms","p":"cpe:2.3:a:other:thing:*","k":90}]},{"id":"c5","f":"x","r":"e","out":[{"n":"{1}","k":90}]},{"id":"c6","f":"x","r":"f","out":[{"t":"os","n":"Ninja Forms","k":90}]},{"id":"c7","f":"x","r":"g","out":[{"n":"Ninja Forms","v":"3","k":90}]}]}')
    $cpr = [WebInv.Matcher]::ApplyCpeSupplement($cpk, $CpeSupplementJson)
    Assert 'CPE supplement fills only missing CPEs (not for a fixed version) and corrects only the known-wrong one' {
        $cpr[0] -eq 1 -and $cpr[1] -eq 1 -and $cpk.Rules[0].Out[0].P -eq 'cpe:2.3:a:ninjaforms:ninja_forms:{v}' -and $cpk.Rules[1].Out[0].P -eq 'cpe:2.3:a:mattermost:mattermost_server:{v}' -and
        $cpk.Rules[2].Out[0].P -eq 'cpe:2.3:a:mattermost:mattermost:*' -and $cpk.Rules[3].Out[0].P -eq 'cpe:2.3:a:other:thing:*' -and -not $cpk.Rules[4].Out[0].P -and -not $cpk.Rules[5].Out[0].P -and -not $cpk.Rules[6].Out[0].P }
    $bpk = [WebInv.Matcher]::ReadPack($BuiltinRulesJson); $fk = @{}; foreach ($cpe1 in $sup['fill']) { $fk[[string]$cpe1['t'] + '|' + [string]$cpe1['n']] = 1 }
    $nocpe = 0
    foreach ($cprule in $bpk.Rules) { foreach ($cpo in @(if ($cprule.Out) { $cprule.Out } else { $cprule })) { $cpt = if ($cpo.T) { $cpo.T } else { 'service' }; if ($cpo.N -and -not $cpo.P -and $fk.ContainsKey($cpt + '|' + $cpo.N)) { $nocpe++ } } }
    Assert 'built-in rules carry the supplement CPEs' { $nocpe -eq 0 }
    Assert 'Ruby regex conversion' { [WebInv.Matcher]::FromRuby('(?m-ix:^a\h[[:digit:]])') -eq '(?s-ix:^a[0-9A-Fa-f][0-9])' }
    Assert 'JavaScript regex conversion' { ([WebInv.Matcher]::FromJs('^IMPERIA\s([\d\.\_]+)') -eq '^IMPERIA\s([\d\._]+)') -and ([WebInv.Matcher]::FromJs('a[^]b\A') -eq 'a[\s\S]bA') }
    Assert 'absolute-anchor option (JS semantics)' { ([regex]::new('^b', [WebInv.Matcher]::Opts('ia'))).IsMatch("a`nb") -eq $false -and ([regex]::new('^b', [WebInv.Matcher]::Opts('i'))).IsMatch("a`nb") }
    $stPack = [WebInv.Matcher]::ReadPack('{"name":"selftest","rules":[{"id":"st:carrier","f":"selftest.text","r":"Parcel","n":"ST Carrier","c":"Shipping carriers","rc":["Ecommerce"],"k":90},{"id":"st:shop","f":"selftest.shop","r":"cart","n":"ST Shop","c":"Ecommerce","k":90}]}')
    [void][WebInv.Matcher]::Load($stPack, (New-Object 'System.Collections.Generic.List[string]'))
    $o6 = New-Object WebInv.Observation; $o6.Add('selftest.text', 'Parcel tracking')
    Assert 'requiresCategory gate drops ungated hit' { @([WebInv.Matcher]::Evaluate($o6) | Where-Object { $_.Name -eq 'ST Carrier' }).Count -eq 0 }
    $o6.Add('selftest.shop', 'cart')
    Assert 'requiresCategory gate passes with category present' { @([WebInv.Matcher]::Evaluate($o6) | Where-Object { $_.Name -eq 'ST Carrier' }).Count -eq 1 }
    $tested = 0; $fails = @([WebInv.Matcher]::TestExamples([ref]$tested))
    $bFails = @($fails | Where-Object { $_ -like 'b:*' })
    Assert ("built-in rule examples") { $bFails.Count -eq 0 }
    foreach ($f in $fails) { Write-RunLog "example failure: $f" $(if ($f -like 'b:*') { 'ERROR' } else { 'WARN' }) }
    if ($fails.Count -gt $bFails.Count) { Write-Host ("note: {0} example mismatches in companion rule packs (see run log); run -TestRules for detail" -f ($fails.Count - $bFails.Count)) -ForegroundColor Yellow }
    Write-RunLog ("rule examples tested: {0}; failures: {1} (built-in {2})" -f $tested, $fails.Count, $bFails.Count)
    # output safety
    Assert 'CSV formula guard' { [WebInv.Util]::CsvSafe('=HYPERLINK("x")') -eq '''=HYPERLINK("x")' -and [WebInv.Util]::CsvSafe('ok') -eq 'ok' }
    Assert 'console control-char strip' { [WebInv.Util]::Printable(("a" + [char]27 + "[31mb"), 50) -eq 'a.[31mb' }
    Assert 'html encode' { [WebInv.Util]::Html('<script>') -eq '&lt;script&gt;' }
    Assert 'mysql greeting parse' { [WebInv.Util]::MySqlVersion([byte[]]@(0x4a, 0, 0, 0, 0x0a, 0x38, 0x2e, 0x30, 0x2e, 0x33, 0x36, 0)) -eq '8.0.36' }
    Assert 'tls mismatch strings present' { $script:MismatchStrings.Count -ge 4 }
    # PHP2Shell advisory status by advertised version (fixed 8.5.12/8.4.27/8.3.36/8.2.35; <=8.1 no upstream fix)
    $p2s = $Advisories | Where-Object { $_.Id -eq 'PHP2Shell' }
    $st = { param($v) [WebInv.Advisory]::Status($v, [string[]]$p2s.Fixed, $p2s.MinBranch) }
    Assert 'PHP2Shell: 8.3.6 vulnerable, 8.2.34 vulnerable' { (& $st '8.3.6') -eq 'vulnerable' -and (& $st '8.2.34') -eq 'vulnerable' }
    Assert 'PHP2Shell: fixed releases and later patches are fixed' { (& $st '8.5.12') -eq 'fixed' -and (& $st '8.4.27') -eq 'fixed' -and (& $st '8.3.40') -eq 'fixed' -and (& $st '8.2.35') -eq 'fixed' }
    Assert 'PHP2Shell: 8.1 and older are eol-branch' { (& $st '8.1.34') -eq 'eol' -and (& $st '7.4.33') -eq 'eol' -and (& $st '5.6.40') -eq 'eol' }
    Assert 'PHP2Shell: newer branch / garbage' { (& $st '8.6.0') -eq 'newer' -and (& $st 'x.y') -eq 'unknown' }
    Assert 'PHP2Shell: header regex splits vendor suffix' { ('PHP/8.1.2-1ubuntu2.20' -match $p2s.Regex) -and $Matches[1] -eq '8.1.2' -and $Matches[2] -eq '-1ubuntu2.20' }
    Assert 'PHP2Shell: mod_php inferred only from Apache Server token' { ('Apache/2.4.58 (Ubuntu) PHP/8.3.6' -match $p2s.HighRisk) -and -not ('PHP/8.3.6' -match $p2s.HighRisk) }
    Assert 'HTML report neutralises hostile titles' {
        $tmpCsv = Join-Path ([IO.Path]::GetTempPath()) ('wi-selftest-{0}.csv' -f [guid]::NewGuid().ToString('N'))
        $tmpHtml = [IO.Path]::ChangeExtension($tmpCsv, '.html')
        try {
            [pscustomobject]@{ Url = 'http://x/'; Title = '</script><script>alert(1)</script>'; IsWeb = 'True'; Flags = '<img src=x onerror=alert(1)>' } | Export-Csv -LiteralPath $tmpCsv -NoTypeInformation
            New-HtmlReport -CsvFile $tmpCsv -HtmlFile $tmpHtml -Meta @{ RunId = 'selftest'; Tag = '<b>' }
            $h = [IO.File]::ReadAllText($tmpHtml)
            $dataPart = $h.Substring($h.IndexOf('id="data">'))
            $dataPart = $dataPart.Substring(0, $dataPart.IndexOf('</script>'))
            ($dataPart -notmatch '<script|<img|onerror=alert\(1\)>') -and ($h -notmatch '<b>')
        }
        finally { Remove-Item -LiteralPath $tmpCsv, $tmpHtml -ErrorAction SilentlyContinue }
    }
    Assert 'JSON reader (case-sensitive keys)' { $j = [WebInv.Json]::Parse('{"a":1,"A":[true,null,"x\"y"]}'); $j.Count -eq 2 -and $j['A'][2] -eq 'x"y' }
    # ---- v2.1 performance components: each must reproduce the behaviour of the code it replaced ----
    Assert 'prefilter: alternation becomes an OR of literal sets' { $d = [WebInv.Lit]::Requirement('aem-(?:GridColumn|apps/)|AEMMode'); $d.Count -eq 3 -and $d[2][0] -eq 'aemmode' -and $d[0][1] -eq 'gridcolumn' }
    Assert 'prefilter: unsupported syntax imposes no requirement' { $null -eq [WebInv.Lit]::Requirement('(?x) a b c') -and $null -eq [WebInv.Lit]::Requirement('ab|c') -and $null -eq [WebInv.Lit]::Requirement('x[a-z-[aeiou]]yz') }
    Assert 'prefilter: optional and repeated atoms are not required' { [WebInv.Lit]::Required('nginx(?:/([\d.]+))?') -eq 'nginx' -and [WebInv.Lit]::Required('ab*cde') -eq 'cde' -and $null -eq [WebInv.Lit]::Required('ab?cd') }
    Assert 'prefilter: case folding (Kelvin sign and long s fold to k/s)' { [WebInv.Lit]::Fold(("WOR" + [char]0x212A + [char]0x017F)) -eq 'works' }
    Assert 'prefilter: identical detections with the prefilter on and off' {
        $same = $true
        foreach ($ob in @($o, $o2, $o3, $o5, $o6)) {
            [WebInv.Matcher]::Prefilter = $true; $a = (@([WebInv.Matcher]::Evaluate($ob)) | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Name, $_.Version, $_.Cpe, $_.Evidence }) -join ';'
            [WebInv.Matcher]::Prefilter = $false; $b = (@([WebInv.Matcher]::Evaluate($ob)) | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Name, $_.Version, $_.Cpe, $_.Evidence }) -join ';'
            if ($a -ne $b) { $same = $false }
        }
        [WebInv.Matcher]::Prefilter = $true
        $same
    }
    Assert 'HTTP parse: status, merged headers, charset, title' {
        $raw = [Text.Encoding]::GetEncoding(28591).GetBytes("HTTP/1.1 302 Found`r`nSet-Cookie: a=1`r`nset-cookie: b=2`r`nContent-Type: text/html; charset=iso-8859-1`r`n`r`n<title> caf" + [char]0xE9 + "  x </title>")
        $r = [WebInv.Html]::Parse($raw)
        $r.IsHttp -and $r.Code -eq 302 -and $r.Headers['set-cookie'] -eq "a=1`nb=2" -and $r.List.Count -eq 3 -and $r.Title -eq ('caf' + [char]0xE9 + ' x')
    }
    Assert 'HTTP parse: non-HTTP bytes become a banner' { $r = [WebInv.Html]::Parse($A.GetBytes("SSH-2.0-OpenSSH_9.6`r`n")); -not $r.IsHttp -and $r.Banner -like 'SSH-2.0-OpenSSH_9.6*' }
    Assert 'JSON writer: types, nesting and HTML-safe escaping' {
        $line = [WebInv.Out]::JsonLine([string[]]@('Port', 'IsWeb', 'Title', 'Detections', 'Empty'), [object[]]@(443, $true, '<b>"x"</b>', [object[]]@([ordered]@{ Name = 'nginx'; Confidence = 85 }), $null))
        $j = $line | ConvertFrom-Json
        $j.Port -eq 443 -and $j.IsWeb -eq $true -and $j.Title -eq '<b>"x"</b>' -and $j.Detections[0].Confidence -eq 85 -and $null -eq $j.Empty -and $line.Contains([string][char]92 + 'u003c') -and -not $line.Contains('<')
    }
    Assert 'CSV writer: same quoting, flattening and formula guard as before' {
        [WebInv.Out]::CsvLine([object[]]@($null, 'a"b', 5, $true, "x`r`ny", '=1+1'), $true) -eq ('"","a""b","5","True","x y","' + "'" + '=1+1"')
    }
    Assert 'scheduler: per-host cap, round-robin, late results discarded' {
        $sc = [WebInv.Sched]::new([string[]]@("a`t10.0.0.1`t80`t", "a`t10.0.0.1`t443`t", "b`t10.0.0.2`t80`t"), 2, 3)
        $t0 = $sc.Take(0); $t1 = $sc.Take(1); $t2 = $sc.Take(2)
        $ok = ($t0 -like "*10.0.0.1`t80*") -and ($t1 -like "*10.0.0.2*") -and ($t2 -like "*10.0.0.1`t443*") -and $sc.Queued -eq 0 -and $sc.Running -eq 3
        $ok = $ok -and $sc.Done(0, $t0, 'r0') -and -not $sc.Done(0, $t0, 'again') -and ($sc.Abandon(2) -eq $t2) -and -not $sc.Done(2, $t2, 'late') -and $sc.Running -eq 1
        $n = $sc.NextResult(); $ok -and $n[1] -eq 'r0' -and $null -eq $sc.NextResult() -and $null -eq $sc.Take(0)
    }
    Assert 'job builder: port-major order, exclusions, de-duplication' {
        $ex = New-Object WebInv.RangeSet; $ex.AddName('10.0.0.2'); $sc = New-Object WebInv.RangeSet
        $jb = [WebInv.JobBuilder]::new($ex, $sc, @{}, $false)
        $rg = New-Object System.Collections.Generic.List[object]; $rg.Add([long[]]@([WebInv.Util]::Ip4('10.0.0.1'), [WebInv.Util]::Ip4('10.0.0.3')))
        $jb.Add($rg, (New-Object System.Collections.Generic.List[string]), [int[]]@(80, 443), '', 't'); $jb.Add($rg, (New-Object System.Collections.Generic.List[string]), [int[]]@(80), '', 't')
        (@([WebInv.JobBuilder]::Format($jb.Jobs)) -join ',') -eq '10.0.0.1:80,10.0.0.3:80,10.0.0.1:443,10.0.0.3:443' -and $jb.Excluded -eq 2
    }
    Assert 'DNS sliding window: every name answered or timed out on its own clock' {
        try {
            [WebInv.Net]::Resolver = [WebInv.Net]::FakeResolver(0, 0, 5)
            $e = New-Object 'System.Collections.Generic.Dictionary[string,string]'
            $r = [WebInv.Net]::ResolveMany([string[]]@(1..40 | ForEach-Object { "n$_.test" }), 2000, 8, $e)
            [WebInv.Net]::Resolver = [WebInv.Net]::FakeResolver(100, 3000, 5)
            $e2 = New-Object 'System.Collections.Generic.Dictionary[string,string]'
            $r2 = [WebInv.Net]::ResolveMany([string[]]@('slow1.test', 'slow2.test'), 150, 8, $e2)
            $r.Count -eq 40 -and $e.Count -eq 0 -and $r2.Count -eq 0 -and $e2['slow1.test'] -like 'DNS timeout*'
        }
        finally { [WebInv.Net]::Resolver = $null }
    }
    Assert 'connect: listening port open, released port closed (RST)' {
        $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $l.Start(); $lp = $l.LocalEndpoint.Port
        $st = $null; $c = [WebInv.Net]::Connect('127.0.0.1', $lp, 2000, [ref]$st); [WebInv.Net]::SafeClose($c); $open = $st
        $l.Stop(); $st = $null; $c = [WebInv.Net]::Connect('127.0.0.1', $lp, 3000, [ref]$st); [WebInv.Net]::SafeClose($c)
        $open -eq 'open' -and $st -eq 'closed'
    }
    Assert 'silence: a listener that never answers is reported as a zero-byte timeout' {
        $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $l.Start(); $lp = $l.LocalEndpoint.Port
        try {
            $req = $A.GetBytes("GET / HTTP/1.1`r`nHost: x`r`n`r`n")
            $p = [WebInv.Net]::Probe('127.0.0.1', $lp, $false, 'x', $req, 300, 65536, 0, 0)
            $t = [WebInv.Net]::Probe('127.0.0.1', $lp, $true, 'x', $req, 300, 65536, 0, 0)
            $s = [WebInv.Tls]::Scan('127.0.0.1', $lp, 'x', 300, $true, $true)
            $p.TimedOut -and $p.BytesIn -eq 0 -and $t.TimedOut -and $t.BytesIn -eq 0 -and $t.TlsError -and -not $s.IsTls -and $s.Probes -eq 5
        }
        finally { $l.Stop() }
    }
    Invoke-ExtrasSelfTest
    Invoke-StoreSelfTest
    $total = $script:StPass + $script:StFail
    $c = if ($script:StFail) { 'Red' } else { 'Green' }
    Write-Host ("Self-test: {0}/{1} passed (SHA-256 provider: {2})" -f $script:StPass, $total, [WebInv.Hash]::Sha256Provider) -ForegroundColor $c
    Write-RunLog ("Self-test: {0}/{1} passed" -f $script:StPass, $total)
    if ($script:StFail) { $script:ExitCode = 1 }
}
$script:SelfTestCertB64 = 'MIIEiTCCA3GgAwIBAgIURZiyZOhvJeTNgPCSAFlEg5pq16IwDQYJKoZIhvcNAQELBQAwga4xCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhNaWNoaWdhbjESMBAGA1UEBwwJQW5uIEFyYm9yMRswGQYDVQQKDBJEdW8gU2VjdXJpdHksIEluYy4xGDAWBgNVBAsMD0VuZHBvaW50IEhlYWx0aDESMBAGA1UEAwwJMTI3LjAuMC4xMS0wKwYJKoZIhvcNAQkBFh5lbmRwb2ludGhlYWx0aEBkdW9zZWN1cml0eS5jb20wHhcNMjYxMDIzMjMzNjM5WhcNMjYxMTIyMjMzNjM5WjCBrjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1pY2hpZ2FuMRIwEAYDVQQHDAlBbm4gQXJib3IxGzAZBgNVBAoMEkR1byBTZWN1cml0eSwgSW5jLjEYMBYGA1UECwwPRW5kcG9pbnQgSGVhbHRoMRIwEAYDVQQDDAkxMjcuMC4wLjExLTArBgkqhkiG9w0BCQEWHmVuZHBvaW50aGVhbHRoQGR1b3NlY3VyaXR5LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMV1yLcNPqc/vZ8lEDwSBbmzH+38SxjKluEhPK6DbdzcnLMzsQqGIil5F/SNuZLhJ/5VhT+7Y/kOVjWQjfWhppLMv9+7ihSuZ+oU7+LzM1WUq31AmLH6VdTN1e0w/6EpWPjmcksmCe6YADaWe8nP35B5jsiRwn6I2rcMU3lhfGbOFb7KeQYKBmv2skPLFtgtwGi1/PZXuSqcxnBMdrfr3g9W9F/5Es5U/FD5n6pKGeXyRrtJDwxXvDenAUAZh6kXfB5+iFcC3eEpqeLzM3uDhXUn9U1Oz5i1P7JHiu4bigEtxupGYYDIBCMYJEZ8+vZuQrzNi2GkxEhY49rgv9Ut5VUCAwEAAaOBnDCBmTAdBgNVHQ4EFgQUGSZFdZmRbwnODl8Aqu/EdO9NVmgwHwYDVR0jBBgwFoAUGSZFdZmRbwnODl8Aqu/EdO9NVmgwDwYDVR0TAQH/BAUwAwEB/zBGBgNVHREEPzA9gg93ZWIwMS5sYWIubG9jYWyCCyoubGFiLmxvY2FshwQKAQIDhxAAAAAAAAAAAAAAAAAAAAABgQVhQGIuYzANBgkqhkiG9w0BAQsFAAOCAQEABsxrbca+eQ26mkbpOQaDsErx04ii+3QajrhGHJo6QsDSYIVinaoS0Hoea6yISI0Um/49tgVyUT+AlMPhsUJzcUxSebZFMtIugHe55j+gWV+0eCsbE/n84Y4iYSZg+QwaWHT2zHkpZZT8HtvzFkoZENSMeqxbV0+uTp0Ghfi0aEp2YlG2rznq94s5tb5BPtzEjIjrPROovq5t0fgqvgjqyHoX3pJYFO73Pm1yju3WCyKl3nluzyE7HQusnxYRTkrvdJKvePKMKSdZNq24tibwOzfg8nJ15chRJoRBT5g+wYQw8x6YfEYdKEVlOeHwInalEE/nufmIi5a092wuz/ua8g=='
#endregion


#region ---------- Main ----------
$script:MismatchStrings = @(
    'The plain HTTP request was sent to HTTPS port',      # nginx
    "You're speaking plain HTTP to an SSL-enabled server", # Apache httpd
    'This combination of host and port requires TLS',     # Go net/http
    'Client sent an HTTP request to an HTTPS server',     # Go net/http
    'speaking plain HTTP to an SSL',                      # Apache variants
    'HTTP request to an HTTPS server',                    # misc
    'plain HTTP request was sent to HTTPS')

$isWindows_ = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
$script:Operator = '{0}\{1}' -f [Environment]::UserDomainName, [Environment]::UserName
Write-RunLog ("WebInventory v{0} started by {1} on {2}; PowerShell {3} ({4}); CLR {5}; OS {6}; cwd {7}" -f $ScriptVersion, $script:Operator, [Environment]::MachineName, $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, [Environment]::Version, [Environment]::OSVersion.VersionString, $LogDir)
$script:SecretParams = @('SnmpCommunity', 'SnmpCredential', 'SnmpPrivPassword', 'ProxyCredential')
$paramDump = foreach ($k in ($MyInvocation.MyCommand.Parameters.Keys | Sort-Object)) {
    if (@('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'ProgressAction', 'WhatIf', 'Confirm') -contains $k) { continue }
    $v = Get-Variable -Name $k -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $v -or "$v" -eq '' -or ($v -is [switch] -and -not $v)) { continue }
    # secrets never reach the run log (the store archives it)
    $shown = if ($script:SecretParams -contains $k) { '<redacted>' } else { (@($v) -join ',') }
    '{0}={1}{2}' -f $k, $shown, $(if ($Explicit.Contains($k)) { '' } else { '(default)' })
}
Write-RunLog ('Effective parameters: ' + ($paramDump -join '; '))

# ---------- utility modes that need no targets ----------
if ($ImportRules) {
    try { Invoke-ImportRules } catch { Stop-Fatal "Rule import failed: $($_.Exception.Message)" }
    Close-Logs; exit $script:ExitCode
}
$storeOptionsOnly = $Store -and -not ($Target -or $TargetFile -or $HostFile) -and ($Explicit.Contains('SnapshotEvery') -or $Explicit.Contains('AnchorEventLog') -or $Explicit.Contains('AnchorCertificate'))
if ($ImportRun -or $StoreQuery -or $VerifyStore -or $RebuildStore -or $StoreMerge -or $StoreSplit -or $RegisterEventSource -or $storeOptionsOnly) { Invoke-StoreMode; Close-Logs; exit $script:ExitCode }
Initialize-Rules
if ($SelfTest) { Invoke-SelfTest; Close-Logs; exit $script:ExitCode }
if ($ExportRules) {
    [IO.File]::WriteAllText($ExportRules, $BuiltinRulesJson, $script:Utf8NoBom)
    Write-Host "Embedded rule pack written to $ExportRules (edit, rename to WebInventory.rules.<name>.json, keep next to the script)" -ForegroundColor Cyan
    Close-Logs; exit 0
}
if ($TestRules) { Invoke-TestRules; Close-Logs; exit $script:ExitCode }

# ---------- opt-in probe options (refused before anything is sent) ----------
if ($NoJa4s -and -not $TlsFingerprint) { Stop-Fatal '-NoJa4s goes with -TlsFingerprint.' }
$snmpCred = $null
if (-not $Snmp -and ($SnmpCommunity -or $SnmpCredential -or $SnmpPrivPassword -or $SnmpVersion -or $SnmpPrivProtocol)) { Stop-Fatal 'SNMP options were given without -Snmp.' }
if ($Snmp) {
    if ($Proxy) { Stop-Fatal '-Snmp uses UDP, which an HTTP CONNECT proxy cannot carry. Run SNMP from a host with direct reach, or drop -Snmp.' }
    if ($SnmpCommunity -and $SnmpCredential) { Stop-Fatal 'Give either -SnmpCommunity (v1/v2c) or -SnmpCredential (v3), not both.' }
    $ver = if ($SnmpVersion) { $SnmpVersion } elseif ($SnmpCommunity) { '2c' } else { '3' }
    if ($ver -ne '3' -and -not $SnmpCommunity) { Stop-Fatal ("-SnmpVersion {0} needs -SnmpCommunity. WebInventory never guesses a community string." -f $ver) }
    if ($ver -eq '3' -and $SnmpCommunity) { Stop-Fatal '-SnmpVersion 3 uses -SnmpCredential, not a community.' }
    if ($SnmpPrivPassword -and -not $SnmpCredential) { Stop-Fatal '-SnmpPrivPassword needs -SnmpCredential.' }
    $snmpCred = @{ Version = $ver; Community = [string]$SnmpCommunity; User = ''; AuthProtocol = $SnmpAuthProtocol; AuthPassword = ''; PrivProtocol = 'None'; PrivPassword = '' }
    if ($SnmpCredential) {
        $snmpCred.User = $SnmpCredential.UserName.TrimStart('\')
        $snmpCred.AuthPassword = $SnmpCredential.GetNetworkCredential().Password
        if ($SnmpPrivPassword) {
            $snmpCred.PrivPassword = (New-Object System.Net.NetworkCredential('', $SnmpPrivPassword)).Password
            $snmpCred.PrivProtocol = if ($SnmpPrivProtocol) { $SnmpPrivProtocol } else { 'AES' }
            if (-not $snmpCred.AuthPassword) { Stop-Fatal 'SNMPv3 privacy needs an authentication password too (authPriv).' }
        }
        elseif ($SnmpPrivProtocol -and $SnmpPrivProtocol -ne 'None') { Stop-Fatal ("-SnmpPrivProtocol {0} needs -SnmpPrivPassword." -f $SnmpPrivProtocol) }
        foreach ($pw in @($snmpCred.AuthPassword, $snmpCred.PrivPassword)) { if ($pw -and $pw.Length -lt 8) { Stop-Fatal 'SNMPv3 passwords must be at least 8 characters (RFC 3414).' } }
    }
    $snmpMode = if ($ver -ne '3') { "v$ver community" } elseif (-not $SnmpCredential) { 'v3 engine discovery only (no credentials)' } else { 'v3 user ' + $(if ($snmpCred.PrivPassword) { "authPriv $SnmpAuthProtocol/$($snmpCred.PrivProtocol)" } elseif ($snmpCred.AuthPassword) { "authNoPriv $SnmpAuthProtocol" } else { 'noAuthNoPriv' }) }
}

# ---------- preflight (logged; fail-closed on conditions that would corrupt results) ----------
$netRelease = $null
$fips = 'n/a'; $schannelState = 'n/a'; $sigState = 'n/a'
if ($isWindows_) {
    try { $netRelease = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop).Release } catch { }
    try { $fv = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -ErrorAction Stop).Enabled; $fips = if ($fv -eq 1) { 'ENFORCED' } else { 'off' } } catch { $fips = 'off' }
    $sc = foreach ($p in 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3') {
        $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\Client"
        $s = 'os-default'
        try { $pr = Get-ItemProperty $k -ErrorAction Stop; if ($null -ne $pr.Enabled) { $s = if ($pr.Enabled -eq 0) { 'disabled' } else { 'enabled' } }; if ($pr.DisabledByDefault -eq 1 -and $s -ne 'disabled') { $s += '(off-by-default)' } } catch { }
        '{0}={1}' -f $p, $s
    }
    $schannelState = $sc -join ', '
}
try { $sig = Get-AuthenticodeSignature -LiteralPath $PSCommandPath -ErrorAction Stop; $sigState = '{0}{1}' -f $sig.Status, $(if ($sig.SignerCertificate) { " by $($sig.SignerCertificate.Subject)" } else { '' }) } catch { $sigState = 'unavailable' }
$execPol = 'n/a'; try { $execPol = [string](Get-ExecutionPolicy) } catch { }
if ($PSVersionTable.PSEdition -ne 'Core' -and $netRelease -and $netRelease -lt 461808) { Stop-Fatal ".NET Framework 4.7.2 or later is required (registry Release=$netRelease)." }
if ([WebInv.Hash]::Mmh3([Text.Encoding]::ASCII.GetBytes('foo')) -ne -156908512) { Stop-Fatal 'mmh3 self-check failed; favicon hashes would be wrong.' }
[void][WebInv.Hash]::Sha256Hex([byte[]]@(1, 2, 3))
# Schannel protocol set: explicit on Windows PowerShell (AppContext defaults are legacy for powershell.exe), OS default on PS7
$sslProto = 0
if ($PSVersionTable.PSEdition -ne 'Core') {
    $sslProto = 3072 -bor 768 -bor 192
    $build = [Environment]::OSVersion.Version.Build
    if ($netRelease -ge 528040 -and $build -ge 20348) { $sslProto = $sslProto -bor 12288 }   # TLS 1.3: .NET 4.8 + Server 2022 / Windows 11
}
Write-RunLog ("Preflight: .NET release={0}; FIPS policy={1}; Schannel client: {2}; SslProtocols={3}; SHA-256 provider={4}; execution policy={5}; script signature={6}" -f $netRelease, $fips, $schannelState, $sslProto, [WebInv.Hash]::Sha256Provider, $execPol, $sigState)
if ($fips -eq 'ENFORCED') { Write-RunLog 'FIPS policy enforced: favicon MD5 uses the built-in managed implementation (content matching only).' }

# ---------- HTTP CONNECT proxy (jump host): every TCP connection of the scan is tunnelled ----------
$proxyLabel = ''
if ($Proxy) {
    $pu = $null
    if (-not [Uri]::TryCreate($Proxy, [UriKind]::Absolute, [ref]$pu) -or $pu.Scheme -ne 'http' -or -not $pu.Host) { Stop-Fatal "-Proxy '$Proxy': expected http://host:port (an HTTP CONNECT proxy)" }
    if ($pu.UserInfo) { Stop-Fatal '-Proxy: put credentials in -ProxyCredential, not in the URL' }
    $ph = $pu.Host.Trim('[', ']'); $pip = $null
    if (-not [Net.IPAddress]::TryParse($ph, [ref]$pip)) {
        $pe = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $pr = [WebInv.Net]::ResolveMany([string[]]@($ph), [Math]::Max(2000, $TimeoutMs * 2), 1, $pe)
        if (-not $pr.ContainsKey($ph)) { Stop-Fatal "-Proxy: cannot resolve '$ph'" }
        $pip = [Net.IPAddress]::Parse(@($pr[$ph])[0])
    }
    $proxyLabel = '{0}:{1}' -f $ph, $pu.Port
    $pst = $null; $pc = [WebInv.Net]::Connect($pip.ToString(), $pu.Port, [Math]::Max(3000, $TimeoutMs), [ref]$pst); [WebInv.Net]::SafeClose($pc)
    if ($pst -ne 'open') { Stop-Fatal ("-Proxy {0} ({1}) is not reachable: {2}" -f $proxyLabel, $pip, $pst) }
    [WebInv.Net]::ProxyIp = $pip.ToString(); [WebInv.Net]::ProxyPort = $pu.Port
    if ($ProxyCredential) {
        $nc = $ProxyCredential.GetNetworkCredential()
        $user = if ($nc.Domain) { '{0}\{1}' -f $nc.Domain, $nc.UserName } else { $nc.UserName }
        [WebInv.Net]::ProxyAuthorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($user + ':' + $nc.Password))
    }
    Write-RunLog ("Proxy: all TCP connections via HTTP CONNECT to {0} ({1}){2}; names resolve on this host" -f $proxyLabel, $pip, $(if ($ProxyCredential) { ' with Basic authentication' } else { '' }))
}

# ---------- opt-in probes: compiled only when used ----------
$useExtras = $TlsFingerprint -or $Smb -or $Rdp -or $Snmp -or $Screenshot
if ($useExtras) { try { Initialize-Extras } catch { Stop-Fatal "Extras compile failed: $($_.Exception.Message)" } }
if ($Snmp) {
    $sc = New-Object WebInv.SnmpCredential
    foreach ($k in @($snmpCred.Keys)) { $sc.$k = $snmpCred[$k] }
    $snmpCred = $sc
    Write-RunLog ("SNMP: UDP 161, {0}" -f $snmpMode)
}
$script:BrowserExe = $null
if ($Screenshot) {
    try { $script:BrowserExe = Find-Browser } catch { Stop-Fatal "-Screenshot: $($_.Exception.Message)" }
    Write-RunLog ("Screenshots: {0} (after the scan; {1} at a time; {2})" -f $script:BrowserExe, $ScreenshotThreads, $ScreenshotSize)
}
$script:JsonNames = [string[]]@($Columns + 'Detections')

# ---------- targets ----------
if (-not $Target -and -not $TargetFile -and -not $HostFile) { Stop-Fatal 'No targets. Use -Target, -TargetFile or -HostFile (or set them in -ConfigFile).' }
try {
    $portSpec = (@($Port) + @((Read-ListFile $PortFile 'Port') | ForEach-Object { $_.Text }) | Where-Object { $_ }) -join ','
    $DefaultPorts = Expand-Ports $portSpec
}
catch { Stop-Fatal "Port specification error: $($_.Exception.Message)" }

$ExSet = New-Object WebInv.RangeSet
$ScopeSet = New-Object WebInv.RangeSet
$inputErrors = New-Object System.Collections.Generic.List[string]
try {
    foreach ($x in (@($Exclude | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Text = $_; Src = '-Exclude' } }) + @(Read-ListFile $ExcludeFile 'Exclude'))) {
        try { foreach ($sp in (Get-SpecList $x.Text)) { foreach ($rg in $sp.Ranges) { $ExSet.AddRange($rg[0], $rg[1]) }; foreach ($nm in $sp.Names) { $ExSet.AddName($nm) } } } catch { $inputErrors.Add(('{0}: exclusion ''{1}'': {2}' -f $x.Src, $x.Text, $_.Exception.Message)) }
    }
    foreach ($x in (@($Scope | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Text = $_; Src = '-Scope' } }) + @(Read-ListFile $ScopeFile 'Scope'))) {
        try { foreach ($sp in (Get-SpecList $x.Text)) { foreach ($rg in $sp.Ranges) { $ScopeSet.AddRange($rg[0], $rg[1]) }; foreach ($nm in $sp.Names) { $ScopeSet.AddName($nm) } } } catch { $inputErrors.Add(('{0}: scope ''{1}'': {2}' -f $x.Src, $x.Text, $_.Exception.Message)) }
    }
}
catch { Stop-Fatal $_.Exception.Message }
if ($inputErrors.Count) { foreach ($e in $inputErrors) { Write-ErrLog 'INPUT' '-' $e }; Stop-Fatal ("{0} invalid exclusion/scope entries (see error log). Scope and exclusions are never partially applied." -f $inputErrors.Count) }

$entries = New-Object System.Collections.Generic.List[object]
# PowerShell turns `-Target web01:80,443` into @('web01:80','443'): glue bare port tokens back onto the preceding host:ports entry
$cliTargets = New-Object System.Collections.Generic.List[string]
foreach ($t in @($Target | Where-Object { $_ })) {
    foreach ($tok in ($t -split '\s+')) {
        if (-not $tok) { continue }
        if ($tok.StartsWith('-')) { $inputErrors.Add("-Target: '$tok' looks like an unknown parameter (check spelling); it was not treated as a target") ; continue }
        $prev = if ($cliTargets.Count) { $cliTargets[$cliTargets.Count - 1] } else { '' }
        if ($prev -and $tok -match '^(?:\d{1,5}(?:-\d{1,5})?|web|web-extended|mgmt)$' -and $prev -match '(?:^\[[^\]]+\]|^[^:\[]+):[\w,\-]+$' -and $prev -notmatch '^https?://') {
            $cliTargets[$cliTargets.Count - 1] = $prev + ',' + $tok; continue
        }
        $cliTargets.Add($tok)
    }
}
foreach ($tok in $cliTargets) { $entries.Add([pscustomobject]@{ Text = $tok; Src = '-Target' }) }
try { foreach ($e in @(Read-ListFile $TargetFile 'Target')) { $entries.Add($e) }; foreach ($e in @(Read-ListFile $HostFile 'Host')) { $entries.Add($e) } } catch { Stop-Fatal $_.Exception.Message }

$parsed = New-Object System.Collections.Generic.List[object]
$hostTotal = [long]0
foreach ($e in $entries) {
    try {
        $hp = Split-HostPort $e.Text
        $ports = if ($hp.Ports) { Expand-Ports $hp.Ports } else { $DefaultPorts }
        foreach ($spec in (Get-SpecList $hp.Spec)) {
            $hostTotal += $spec.Count
            if ($hostTotal -gt $MaxTargets -and -not $Force) { Stop-Fatal ("Target list expands beyond -MaxTargets {0} hosts (at {1} '{2}'). Narrow the scope or pass -Force." -f $MaxTargets, $e.Src, $e.Text) }
            $parsed.Add(@{ Spec = $spec; Ports = $ports; Scheme = $hp.Scheme; Src = $e.Src; Raw = $e.Text })
        }
    }
    catch { $inputErrors.Add(('{0}: ''{1}'': {2}' -f $e.Src, $e.Text, $_.Exception.Message)) }
}
if ($inputErrors.Count) {
    foreach ($ie in $inputErrors) { Write-ErrLog 'INPUT' '-' $ie }
    if (-not $SkipInvalidInput) { Stop-Fatal ("{0} invalid target entries (first: {1}). Fix them or pass -SkipInvalidInput." -f $inputErrors.Count, $inputErrors[0]) }
    Write-Host ("WARNING: skipped {0} invalid target entries (see error log)" -f $inputErrors.Count) -ForegroundColor Yellow
}

# DNS (parallel, bounded); unresolved names are logged, not fatal
$names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($p in $parsed) { foreach ($n in $p.Spec.Names) { $tmp = $null; if (-not [Net.IPAddress]::TryParse($n, [ref]$tmp) -and -not $ExSet.ContainsName($n)) { [void]$names.Add($n) } } }
$dnsErr = New-Object 'System.Collections.Generic.Dictionary[string,string]'
$resolved = @{}
if ($names.Count) {
    $swDns = [Diagnostics.Stopwatch]::StartNew()
    $r = [WebInv.Net]::ResolveMany([string[]]@($names), [Math]::Max(2000, $TimeoutMs * 2), 32, $dnsErr)
    foreach ($k in $r.Keys) { $resolved[$k] = $r[$k] }
    foreach ($k in $dnsErr.Keys) { Write-ErrLog 'DNS' $k $dnsErr[$k] }
    Write-RunLog ("DNS: {0} names, {1} resolved, {2} failed in {3} ms" -f $names.Count, $resolved.Count, $dnsErr.Count, $swDns.ElapsedMilliseconds)
}

# Build jobs (port-major within each entry => natural round-robin across hosts)
$jb = [WebInv.JobBuilder]::new($ExSet, $ScopeSet, $resolved, [bool]$AllAddresses)
# protocol checks first: they own their host:port (a plain check of 445 / 3389 / 161 from -Port is then skipped)
$protoJobs = @(@{ On = [bool]$Smb; Port = 445; Scheme = 'smb' }, @{ On = [bool]$Rdp; Port = 3389; Scheme = 'rdp' }, @{ On = [bool]$Snmp; Port = 161; Scheme = 'snmp' })
foreach ($p in $parsed) { if (@('smb', 'rdp', 'snmp') -contains $p.Scheme) { $jb.Add($p.Spec.Ranges, $p.Spec.Names, [int[]]@($p.Ports), [string]$p.Scheme, [string]$p.Src) } }
foreach ($pj in $protoJobs) { if ($pj.On) { foreach ($p in $parsed) { $jb.Add($p.Spec.Ranges, $p.Spec.Names, [int[]]@($pj.Port), $pj.Scheme, ('-' + (Get-Culture).TextInfo.ToTitleCase($pj.Scheme))) } } }
foreach ($p in $parsed) { if (@('smb', 'rdp', 'snmp') -notcontains $p.Scheme) { $jb.Add($p.Spec.Ranges, $p.Spec.Names, [int[]]@($p.Ports), [string]$p.Scheme, [string]$p.Src) } }
foreach ($x in @('smb', 'rdp', 'snmp')) { if (@($parsed | Where-Object { $_.Scheme -eq $x }).Count -and -not (Get-Variable -Name $x -ValueOnly)) { Stop-Fatal ("{0}:// targets need -{1}" -f $x, (Get-Culture).TextInfo.ToTitleCase($x)) } }
$Jobs = $jb.Jobs; $hostSet = $jb.Hosts; $excludedCount = $jb.Excluded; $outOfScope = $jb.OutOfScope
if ($outOfScope.Count) {
    $i = 0; foreach ($o in $outOfScope) { if (++$i -gt 1000) { Write-ErrLog 'SCOPE' '-' ("... {0} more" -f ($outOfScope.Count - 1000)); break }; Write-ErrLog 'SCOPE' $o 'outside authorised -Scope' }
    if (-not $DropOutOfScope) { Stop-Fatal ("{0} targets fall outside the authorised -Scope (first: {1}). Nothing was scanned. Fix the target list or pass -DropOutOfScope." -f $outOfScope.Count, $outOfScope[0]) }
    Write-Host ("WARNING: dropped {0} out-of-scope targets (see error log)" -f $outOfScope.Count) -ForegroundColor Yellow
}
Write-RunLog ("Scope: entries={0}; hosts={1}; host:port checks={2}; excluded={3}; out-of-scope dropped={4}; unresolved={5}; default ports={6}" -f $entries.Count, $hostSet.Count, $Jobs.Count, $excludedCount, $outOfScope.Count, $dnsErr.Count, ($DefaultPorts -join ','))

# ---------- resume ----------
$script:RunId = $script:Stamp
$doneKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
if ($Resume) {
    if (-not (Test-Path -LiteralPath $Resume -PathType Leaf)) { Stop-Fatal "Resume file not found: $Resume" }
    $rp = (Resolve-Path -LiteralPath $Resume).ProviderPath
    if ((Split-Path -Leaf $rp) -notmatch '^WebInventory_(.+)_progress\.txt$') { Stop-Fatal "Resume file must be a WebInventory_<RunId>_progress.txt file" }
    $script:RunId = $Matches[1]
    $OutputDir = Split-Path -Parent $rp
    foreach ($l in [IO.File]::ReadAllLines($rp)) { if ($l) { [void]$doneKeys.Add($l.Trim()) } }
    $before = $Jobs.Count
    $Jobs = New-Object System.Collections.Generic.List[string] (, [string[]]@($Jobs | Where-Object { $p = $_.Split("`t"); -not $doneKeys.Contains(('{0}|{1}|{2}' -f $p[0], $p[1], $p[2])) }))
    Write-RunLog ("Resume: RunId={0}; {1} checks already done; {2} of {3} remain" -f $script:RunId, $doneKeys.Count, $Jobs.Count, $before)
    Write-Host ("Resuming run {0}: {1} of {2} checks remain" -f $script:RunId, $Jobs.Count, $before) -ForegroundColor Cyan
}

if ($ListTargets) {
    [WebInv.JobBuilder]::Format($Jobs)
    $msg = "ListTargets: {0} checks across {1} hosts ({2} excluded, {3} out-of-scope dropped, {4} unresolved). Nothing was sent." -f $Jobs.Count, $hostSet.Count, $excludedCount, $outOfScope.Count, $dnsErr.Count
    Write-RunLog $msg; Write-Host $msg -ForegroundColor Cyan
    Close-Logs; exit 0
}
if ($Jobs.Count -eq 0) { Write-RunLog 'Nothing to scan.' 'WARN'; Write-Host 'Nothing to scan (all targets excluded, unresolved, or already done).' -ForegroundColor Yellow; Close-Logs; exit $(if ($script:ErrTotal) { 2 } else { 0 }) }

if ($Proxy) {
    # one CONNECT to the first check: a proxy that wants authentication (407) would otherwise fail every check
    $fj = $Jobs[0].Split("`t"); $pst = $null
    $pc = [WebInv.Net]::Connect($fj[1], [int]$fj[2], $TimeoutMs, [ref]$pst); [WebInv.Net]::SafeClose($pc)
    if ($pst -eq 'error' -and [WebInv.Net]::ProxyLastRefusal -match ' 407') { Stop-Fatal ("-Proxy {0} requires authentication: pass -ProxyCredential ({1})" -f $proxyLabel, [WebInv.Net]::ProxyLastRefusal) }
    if ($pst -eq 'error') { Write-RunLog ("Proxy pre-check CONNECT {0}:{1} was refused: {2}" -f $fj[1], $fj[2], [WebInv.Net]::ProxyLastRefusal) 'WARN' }
    [WebInv.Net]::ProxyRefusals = 0; [WebInv.Net]::ProxyLastRefusal = ''
}
if ($Store -and -not $NoStore) {
    # fail before scanning if the store could never take this run (engine not available here, newer format, wrong engine)
    # (checked without loading the store engine: nothing store-related is compiled before the scan has finished)
    $script:StorePath = Resolve-StorePath $Store
    $esentHere = $isWindows_ -and (Test-Path -LiteralPath (Join-Path ([Environment]::SystemDirectory) 'esent.dll'))
    try {
        $sj = Join-Path $script:StorePath 'STORE.json'
        if (Test-Path -LiteralPath $sj) {
            $sjo = [IO.File]::ReadAllText($sj) | ConvertFrom-Json
            if ($sjo.engine -eq 'esent' -and -not $esentHere) { throw "the store at $($script:StorePath) uses ESENT, which this system does not have" }
            if ($StoreEngine -ne 'Auto' -and $sjo.engine -ne $StoreEngine.ToLowerInvariant()) { throw "the store uses the $($sjo.engine) engine (switch with -RebuildStore -StoreEngine $StoreEngine)" }
        }
        elseif ($StoreEngine -eq 'Esent' -and -not $esentHere) { throw 'ESENT (esent.dll) is not available on this system; use -StoreEngine File' }
    }
    catch { Stop-Fatal ("-Store: {0}" -f $_.Exception.Message) }
    Write-RunLog ("Store: {0} (runs are added after they complete)" -f $script:StorePath)
}
if (-not (Test-Path -LiteralPath $OutputDir)) { try { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null } catch { Stop-Fatal "Cannot create -OutputDir '$OutputDir': $($_.Exception.Message)" } }
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).ProviderPath
try { Open-Outputs $OutputDir $script:RunId } catch { Stop-Fatal "Cannot open output files in '$OutputDir': $($_.Exception.Message)" }

# ---------- worker configuration (shared, read-only except the synchronized rDNS cache) ----------
$Cfg = @{
    RunId = $script:RunId; Tag = [string]$Tag; Columns = $Columns; UserAgent = $UserAgent
    TimeoutMs = $TimeoutMs; Retries = $Retries; MaxBodyBytes = $MaxBodyBytes; MaxRedirects = $MaxRedirects; BannerWaitMs = $BannerWaitMs
    DelayMs = $DelayMs; JitterMs = $JitterMs; SslProto = $sslProto; TlsPorts = $TlsHintPorts; HttpPorts = $HttpPorts
    NoTlsScan = [bool]$NoTlsScan; NoFavicon = [bool]$NoFavicon; NoExtras = [bool]$NoExtras; Options = [bool]$Options
    IdentifyPaths = [bool]$IdentifyPaths; PathList = $IdentifyPathList; ProbeSans = [bool]$ProbeSans; MaxSans = $MaxSans
    ReverseDns = [bool]$ReverseDns; FollowOffHost = [bool]$FollowOffHost; Exclude = $ExSet; Scope = $ScopeSet
    MinConfidence = $MinConfidence; CertWarnDays = $CertWarnDays; Advisories = $Advisories; MgmtCategories = $MgmtCategories; MismatchStrings = $script:MismatchStrings
    RdnsCache = [hashtable]::Synchronized(@{}); VhostSeen = [hashtable]::Synchronized(@{})
    TlsFingerprint = [bool]$TlsFingerprint; Ja4s = ([bool]$TlsFingerprint -and -not $NoJa4s); Snmp = $snmpCred; Proxy = [bool]$Proxy
}
$ops = 3 + $Retries + 7 + $MaxRedirects + 5 + $(if ($Options) { 1 } else { 0 }) + $(if ($IdentifyPaths) { $IdentifyPathList.Count } else { 0 }) + $(if ($ProbeSans) { $MaxSans * (2 + $MaxRedirects) } else { 0 }) + $(if ($TlsFingerprint) { 10 } else { 0 })
$budgetMs = [long]$ops * ($TimeoutMs * 3 + $DelayMs + $JitterMs + $BannerWaitMs) + 30000
$banner = "WebInventory v{0}: {1} checks across {2} hosts ({3} excluded{4}). Pace={5} threads={6} per-host={7} timeout={8}ms. Authorised scope only." -f $ScriptVersion, $Jobs.Count, $hostSet.Count, $excludedCount, $(if ($ScopeSet.IsEmpty) { ', no -Scope set' } else { ', scope enforced' }), $Pace, $Threads, $MaxPerHost, $TimeoutMs
Write-RunLog $banner; Write-RunLog ("Outputs: {0} ; {1} ; {2}; watchdog budget {3} ms per check" -f $script:CsvPath, $script:JsonlPath, $script:ProgressPath, $budgetMs)
if (-not $Quiet) { Write-Host $banner -ForegroundColor Cyan }

# warm the certificate chain engine once: dozens of first TLS handshakes initialising it at the same moment stalled
# for seconds (measured) and made servers time out, losing HTTPS services under load
Write-RunLog ("TLS/chain engine warm-up: {0} ms" -f [WebInv.Net]::WarmUp([Convert]::FromBase64String($script:SelfTestCertB64))) 'DEBUG'

# ---------- dispatcher ----------
# Threads long-lived workers pull checks from a C# scheduler (per-host cap, round-robin across hosts) and push results to
# a queue this thread waits on. No per-check PowerShell instance, no polling.
$counts = @{ open = 0; closed = 0; filtered = 0; error = 0; web = 0; rows = 0; requests = 0 }
# The worker functions are registered once in an InitialSessionState: every runspace shares one compiled copy.
# (Defining them inside each runspace's script made PowerShell background-compile them once per runspace.)
$workerIss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$loopParts = New-Object System.Collections.Generic.List[string]
foreach ($st in $WorkerScript.Ast.EndBlock.Statements) {
    if ($st -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        $fb = $st.Body.Extent.Text; $fb = $fb.Substring(1, $fb.Length - 2)
        if ($st.Parameters) { $fb = 'param(' + (@($st.Parameters | ForEach-Object { $_.Extent.Text }) -join ', ') + ")`n" + $fb }
        $workerIss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $st.Name, $fb))
    }
    else { $loopParts.Add($st.Extent.Text) }
}
$loopText = $WorkerScript.Ast.ParamBlock.Extent.Text + "`n" + ($loopParts -join "`n")
$pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $workerIss, $Host)
$pool.Open()
$sched = [WebInv.Sched]::new([string[]]$Jobs.ToArray(), $MaxPerHost, $Threads)
$workers = New-Object System.Collections.Generic.List[object]
$sw = [Diagnostics.Stopwatch]::StartNew()
$lastProgress = -1000; $doneCount = 0; $total = $Jobs.Count
$script:LoopCompleted = $false; $stopDispatch = $false; $script:TimeLimitHit = $false; $abandoned = 0

function Start-Worker {
    param([int]$Id)
    $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
    [void]$ps.AddScript($loopText).AddArgument($sched).AddArgument($Cfg).AddArgument($Id)
    [pscustomobject]@{ Id = $Id; PS = $ps; Handle = $ps.BeginInvoke(); Stopping = $false }
}

function Format-JobId([string]$JobLine) { $p = $JobLine.Split("`t"); '{0}({1}):{2}' -f $p[0], $p[1], $p[2] }

function Complete-Result {
    param([string]$JobLine, $Res)
    if ($counts.ContainsKey($Res.State)) { $counts[$Res.State]++ } else { $counts.error++ }
    $counts.requests += $Res.Requests
    foreach ($l in $Res.Logs) { Write-RunLog $l 'DEBUG' }
    foreach ($e in $Res.Errors) { Write-ErrLog $e[0] $e[1] $e[2] }
    foreach ($row in $Res.Rows) {
        $counts.rows++
        if ($row.IsWeb) { $counts.web++ }
        try { Write-ResultRow $row } catch { Write-ErrLog 'IO' $row.Url ("write failed: {0}" -f $_.Exception.Message) }
        Write-RunLog ("HIT {0} web={1} status={2} products=[{3}] flags=[{4}]" -f $row.Url, $row.IsWeb, $row.StatusCode, $row.Products, $row.Flags)
        if ($row.IsWeb -or $row._SchannelIncompatible -or $ShowNonWeb -or @('smb', 'rdp', 'snmp') -contains $row.Scheme) { Write-Hit $row }
        if ($PassThru) { $o = [ordered]@{}; foreach ($c in $Columns) { $o[$c] = $row[$c] }; [pscustomobject]$o }
    }
    if ($Res.State -ne 'error') { $p = $JobLine.Split("`t"); $script:ProgW.WriteLine(('{0}|{1}|{2}' -f $p[0], $p[1], $p[2])) }
}

function Receive-Results {
    while ($null -ne ($item = $sched.NextResult())) { Complete-Result $item[0] $item[1]; $script:doneCount++ }
}

try {
    $wantWorkers = [Math]::Min($Threads, $total)
    for ($i = 0; $i -lt $wantWorkers; $i++) { $workers.Add((Start-Worker $i)) }
    while ($true) {
        [void]$sched.Wait(250)
        Receive-Results
        if ($MaxRuntimeMinutes -gt 0 -and -not $stopDispatch -and $sw.Elapsed.TotalMinutes -ge $MaxRuntimeMinutes) {
            $stopDispatch = $true; $script:TimeLimitHit = $true
            $abandoned += $sched.Stop()
            Write-RunLog ("-MaxRuntimeMinutes {0} reached: no new checks dispatched; {1} left for -Resume" -f $MaxRuntimeMinutes, $abandoned) 'WARN'
        }
        # watchdog: a check running past its budget gets its worker stopped (and replaced)
        foreach ($slot in $sched.Overdue($budgetMs)) {
            $w = $workers | Where-Object { $_.Id -eq $slot -and -not $_.Stopping } | Select-Object -First 1
            if (-not $w) { continue }
            $w.Stopping = $true
            $cur = $sched.Current($slot)
            if ($cur) { Write-ErrLog 'WORKER' (Format-JobId $cur) ("watchdog: check exceeded {0} ms; stopping it" -f $budgetMs) }
            [void]$w.PS.BeginStop($null, $null)
        }
        # finished or failed workers
        foreach ($w in $workers.ToArray()) {
            if (-not $w.Handle.IsCompleted) { continue }
            $failMsg = $null
            try { [void]$w.PS.EndInvoke($w.Handle) } catch { $failMsg = $_.Exception.Message }
            $lost = $sched.Abandon($w.Id)
            foreach ($e in $w.PS.Streams.Error) { Write-ErrLog 'WORKER' $(if ($lost) { Format-JobId $lost } else { "worker $($w.Id)" }) ("stream error: {0}" -f $e) }
            if ($lost) {
                Write-ErrLog 'WORKER' (Format-JobId $lost) ("worker failed: {0}" -f $(if ($failMsg) { $failMsg } else { 'worker exited during the check' }))
                $counts.error++; $doneCount++
            }
            elseif ($failMsg) { Write-ErrLog 'WORKER' "worker $($w.Id)" ("worker failed outside a check (not restarted): {0}" -f $failMsg) }
            try { $w.PS.Dispose() } catch { }
            [void]$workers.Remove($w)
            # replace a worker lost to the watchdog or a crash mid-check; one that died without a check is not respawned
            if ($lost -and -not $sched.Stopped -and $sched.Queued -gt 0) { $workers.Add((Start-Worker $w.Id)) }
        }
        if ($workers.Count -eq 0) {
            Receive-Results
            if ($sched.Queued -gt 0) { $left = $sched.Stop(); $abandoned += $left; Write-ErrLog 'WORKER' '-' ("all workers exited with {0} checks still queued" -f $left) }
            break
        }
        if (-not $NoProgress -and ($sw.ElapsedMilliseconds - $lastProgress) -ge 500) {
            $lastProgress = $sw.ElapsedMilliseconds
            $rate = if ($sw.Elapsed.TotalSeconds -gt 0) { $doneCount / $sw.Elapsed.TotalSeconds } else { 0 }
            $eta = if ($rate -gt 0) { [TimeSpan]::FromSeconds([int](($total - $doneCount) / $rate)).ToString() } else { '?' }
            Write-Progress -Activity 'WebInventory' -Status ("{0}/{1} checks | web {2} | open {3} | in flight {4} | ETA {5}" -f $doneCount, $total, $counts.web, $counts.open, $sched.Running, $eta) -PercentComplete ([Math]::Min(100, [int](100 * $doneCount / [Math]::Max(1, $total))))
        }
    }
    $script:LoopCompleted = $true
}
finally {
    if (-not $NoProgress) { Write-Progress -Activity 'WebInventory' -Completed }
    $interrupted = -not $script:LoopCompleted
    if ($interrupted) {
        $queuedLeft = $sched.Queued; $runningLeft = $sched.Running
        [void]$sched.Stop()
        foreach ($x in $workers) { try { [void]$x.PS.BeginStop($null, $null) } catch { } }
        Write-RunLog ("INTERRUPTED: {0} checks in flight and {1} queued were not completed; re-run with -Resume `"{2}`"" -f $runningLeft, $queuedLeft, $script:ProgressPath) 'WARN'
        try { [void]$pool.BeginClose($null, $null) } catch { }
    }
    else { try { $pool.Close(); $pool.Dispose() } catch { } }
    Close-Outputs

    # ---------- finalize: HTML, delta, summary, manifest ----------
    $outputs = New-Object System.Collections.Generic.List[string]
    $outputs.Add($script:CsvPath); $outputs.Add($script:JsonlPath); $outputs.Add($script:ProgressPath)
    $elapsed = $sw.Elapsed
    $shots = $null
    if ($Screenshot -and -not $interrupted -and -not $script:TimeLimitHit) {
        try {
            $shots = Invoke-Screenshots -CsvFile $script:CsvPath
            if ($script:ShotIndexPath -and (Test-Path -LiteralPath $script:ShotIndexPath)) {
                $outputs.Add($script:ShotIndexPath)
                foreach ($f in $shots.Values) { $outputs.Add((Join-Path $OutputDir $f)) }
            }
        }
        catch { Write-ErrLog 'SCREENSHOT' '-' ("screenshot phase failed: {0} | {1}" -f $_.Exception.Message, ($_.ScriptStackTrace -replace '\s+', ' ')) }
    }
    if (-not $NoHtml) {
        try {
            $script:HtmlPath = Join-Path $OutputDir ("WebInventory_{0}.html" -f $script:RunId)
            $meta = @{ RunId = $script:RunId; Tag = [string]$Tag; Started = $script:ScriptStart.ToString('yyyy-MM-dd HH:mm'); Duration = ('{0:hh\:mm\:ss}' -f $elapsed); Operator = $script:Operator; Computer = [Environment]::MachineName; Version = $ScriptVersion }
            New-HtmlReport -CsvFile $script:CsvPath -HtmlFile $script:HtmlPath -Meta $meta -Screenshots $shots
            $outputs.Add($script:HtmlPath)
        }
        catch { Write-ErrLog 'IO' 'html' ("HTML report failed: {0}" -f $_.Exception.Message) }
    }
    $deltaMsg = ''
    if ($BaselineCsv) {
        try {
            $bl = $BaselineCsv
            if ($bl -eq 'auto') {
                $bl = @(Get-ChildItem -LiteralPath $OutputDir -Filter 'WebInventory_*.csv' -File | Where-Object { $_.Name -notlike '*_delta.csv' -and $_.FullName -ne $script:CsvPath } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object { $_.FullName })
                if (-not $bl) { $bl = $null; Write-RunLog 'BaselineCsv auto: no previous run found' 'WARN' } else { $bl = $bl[0] }
            }
            if ($bl) {
                if (-not (Test-Path -LiteralPath $bl)) { throw "baseline not found: $bl" }
                $script:DeltaPath = Join-Path $OutputDir ("WebInventory_{0}_delta.csv" -f $script:RunId)
                $dc = Compare-Baseline -BaselinePath $bl -CurrentCsv $script:CsvPath -DeltaPath $script:DeltaPath
                $deltaMsg = "Delta vs {0}: {1} new, {2} removed, {3} changed -> {4}" -f (Split-Path -Leaf $bl), $dc.New, $dc.Removed, $dc.Changed, $script:DeltaPath
                Write-RunLog $deltaMsg; $outputs.Add($script:DeltaPath)
            }
        }
        catch { Write-ErrLog 'IO' 'delta' ("baseline comparison failed: {0}" -f $_.Exception.Message) }
    }
    try { $outputs.Add((Write-RunInfo -Complete (-not $interrupted -and -not $script:TimeLimitHit) -Interrupted $interrupted -TimeLimit $script:TimeLimitHit -Rows $counts.rows)) }
    catch { Write-ErrLog 'IO' 'run.json' ("run.json failed: {0}" -f $_.Exception.Message) }
    $errSummary = if ($script:ErrTotal) { ($script:ErrCounts.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join ' ' } else { 'none' }
    $summary = "{0} in {1:hh\:mm\:ss}: {2}/{3} checks; web={4} open={5} closed={6} filtered={7} worker-errors={8}; rows={9}; requests={10}; rule-regex-timeouts={11}; logged errors: {12}" -f $(if ($interrupted) { 'INTERRUPTED' } elseif ($script:TimeLimitHit) { 'TIME LIMIT' } else { 'Done' }), $elapsed, $doneCount, $total, $counts.web, $counts.open, $counts.closed, $counts.filtered, $counts.error, $counts.rows, $counts.requests, [WebInv.Matcher]::Timeouts, $errSummary
    Write-RunLog $summary
    if ($Proxy) {
        $pmsg = "Proxy {0}: {1} CONNECT requests refused or failed{2}" -f $proxyLabel, [WebInv.Net]::ProxyRefusals, $(if ([WebInv.Net]::ProxyRefusals) { '; last: ' + [WebInv.Net]::ProxyLastRefusal } else { '' })
        Write-RunLog $pmsg $(if ([WebInv.Net]::ProxyRefusals) { 'WARN' } else { 'INFO' })
        if ([WebInv.Net]::ProxyRefusals) { Write-Host $pmsg -ForegroundColor Yellow }
    }
    if ([WebInv.Net]::LocalWaits -gt 0) { Write-RunLog ("Local socket exhaustion: {0} connects backed off and retried, {1} gave up (see error log)" -f [WebInv.Net]::LocalWaits, [WebInv.Net]::LocalFailures) 'WARN' }
    Write-RunLog ("Outputs: " + ($outputs -join ' ; '))
    Write-Host $summary -ForegroundColor $(if ($interrupted -or $script:TimeLimitHit) { 'Yellow' } else { 'Cyan' })
    if ($deltaMsg) { Write-Host $deltaMsg -ForegroundColor Cyan }
    Write-Host ("Results: {0}{1}" -f $script:CsvPath, $(if ($script:HtmlPath) { " | $($script:HtmlPath)" } else { '' })) -ForegroundColor Cyan
    Write-Host ("Logs:    {0} | {1}" -f $RunLogPath, $ErrLogPath) -ForegroundColor DarkGray
    if ($interrupted -or $script:TimeLimitHit) { Write-Host ("Resume:  re-run the same command with -Resume '{0}'" -f $script:ProgressPath) -ForegroundColor Yellow }
    $script:ExitCode = if ($interrupted -or $script:TimeLimitHit) { 3 } elseif ($script:ErrTotal -gt 0) { 2 } else { 0 }
    Close-Logs
    try {
        $script:ManifestPath = Join-Path $OutputDir ("WebInventory_{0}_manifest.txt" -f $script:RunId)
        Write-Manifest -Files (@($outputs) + @($RunLogPath, $ErrLogPath)) -Path $script:ManifestPath
    }
    catch { Write-Host "Manifest failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    # ---------- inventory store (after the run is finished and its files are final) ----------
    if ($Store -and -not $NoStore) {
        if ($interrupted -or $script:TimeLimitHit) { Write-Host ("Store: run not complete, not added. Resume it (-Resume) and it is added when it completes.") -ForegroundColor Yellow }
        elseif (-not (Invoke-StoreIngest -RunId $script:RunId -Dir $OutputDir)) { if ($script:ExitCode -lt 2) { $script:ExitCode = 2 } }
    }
}
exit $script:ExitCode
#endregion
