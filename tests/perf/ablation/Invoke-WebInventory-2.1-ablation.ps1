<#
.SYNOPSIS
    Invoke-WebInventory.ps1 v2.0.2 - non-intrusive web service discovery and fingerprinting (CMDB-lite).

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
.PARAMETER Resume
    Path to a WebInventory_<RunId>_progress.txt from an interrupted run. Re-run with the same target
    arguments plus -Resume; completed checks are skipped and results append to the original CSV/JSONL.
.PARAMETER ConfigFile
    .psd1 of parameter values (data only, parsed with Import-PowerShellDataFile). Command line wins.
.PARAMETER BaselineCsv
    Previous results CSV to diff against ('auto' = newest WebInventory_*.csv in -OutputDir).
.PARAMETER ImportRules
    Convert a Rapid7 Recog xml directory or a webappanalyzer 'src' directory into a rule pack and exit.
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
    .\Invoke-WebInventory.ps1 -SelfTest
.EXAMPLE
    .\Invoke-WebInventory.ps1 -ImportRules .\recog\xml                     # builds WebInventory.rules.recog.json
.NOTES
    Version 2.0.2. Windows PowerShell 5.1 + .NET Framework 4.7.2+ (4.8 for TLS 1.3 via Schannel). Also runs on PowerShell 7.
    Exit codes: 0 = clean; 1 = fatal / refused to start; 2 = completed, errors logged; 3 = interrupted or -MaxRuntimeMinutes hit.
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
    [switch]$TestRules
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '2.0.2'
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
        public static TcpClient Connect(string ip, int port, int timeoutMs, out string state)
        {
            IPAddress addr;
            if (!SelectConnect || !IPAddress.TryParse(ip, out addr)) return ConnectAsyncWait(ip, port, timeoutMs, out state);
            Socket s = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                s.NoDelay = true;
                s.Blocking = false;
                try { s.Connect(new IPEndPoint(addr, port)); }
                catch (SocketException se)
                {
                    if (se.SocketErrorCode != SocketError.WouldBlock && se.SocketErrorCode != SocketError.InProgress && se.SocketErrorCode != SocketError.AlreadyInProgress)
                    {
                        state = se.SocketErrorCode == SocketError.ConnectionRefused ? "closed" : "filtered";
                        s.Close(); return null;
                    }
                    System.Collections.ArrayList w = new System.Collections.ArrayList(), e = new System.Collections.ArrayList();
                    w.Add(s); e.Add(s);
                    Socket.Select(null, w, e, (int)Math.Min(int.MaxValue, Math.Max(1, timeoutMs) * 1000L));
                    if (w.Count == 0 && e.Count == 0) { state = "filtered"; s.Close(); return null; }   // no answer within the timeout
                    int err = (int)s.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error);
                    if (err != 0 || e.Count > 0)
                    {
                        state = (err == (int)SocketError.ConnectionRefused || err == 111 || err == 61) ? "closed" : "filtered";
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
            while (q + 4 <= ee)
            {
                int et = (d[q] << 8) | d[q + 1]; int len2 = (d[q + 2] << 8) | d[q + 3]; int eb = q + 4;
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
        public const string EngineVersion = "2.0.2";

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
{"name":"builtin","version":"2.0.2","source":"WebInventory curated rules (Recog/Wappalyzer/Nmap-inspired; patterns written for this tool)","license":"Same as script","rules":[
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
{"id":"b:modssl-comp","f":"header:server","r":"mod_ssl/([\\d.]+)","n":"mod_ssl","c":"Library","v":"{1}","k":80},
{"id":"b:php-comp","f":"header:server","r":"PHP/([\\d.]+)","n":"PHP","c":"Language","v":"{1}","p":"cpe:2.3:a:php:php:{v}","k":85},
{"id":"b:nginx","f":"header:server","r":"^nginx(?:/([\\d.]+))?","n":"nginx","c":"Web server","v":"{1}","p":"cpe:2.3:a:f5:nginx:{v}","k":95,"ex":"nginx/1.18.0 (Ubuntu)","exv":"1.18.0"},
{"id":"b:openresty","f":"header:server","r":"^openresty(?:/([\\d.]+))?","n":"OpenResty","c":"Web server","v":"{1}","p":"cpe:2.3:a:openresty:openresty:{v}","im":["nginx"],"k":95},
{"id":"b:tengine","f":"header:server","r":"^Tengine(?:/([\\d.]+))?","n":"Tengine","c":"Web server","v":"{1}","k":90},
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
{"id":"b:uvicorn","f":"header:server","r":"^uvicorn","n":"Uvicorn","c":"App server","im":["Python"],"k":90},
{"id":"b:tornado","f":"header:server","r":"^TornadoServer/([\\d.]+)","n":"Tornado","c":"App server","v":"{1}","im":["Python"],"k":90},
{"id":"b:cherrypy","f":"header:server","r":"^CherryPy/([\\d.]+)","n":"CherryPy","c":"App server","v":"{1}","im":["Python"],"k":90},
{"id":"b:cowboy","f":"header:server","r":"^Cowboy","n":"Cowboy","c":"App server","k":85},
{"id":"b:ohs","f":"header:server","r":"^Oracle-HTTP-Server","n":"Oracle HTTP Server","c":"Web server","p":"cpe:2.3:a:oracle:http_server:*","k":90},
{"id":"b:weblogic-hdr","f":"header:server","r":"WebLogic(?: Server)? ?([\\d.]+)?","n":"Oracle WebLogic Server","c":"App server","v":"{1}","p":"cpe:2.3:a:oracle:weblogic_server:{v}","k":90},
{"id":"b:ibmhttp","f":"header:server","r":"^IBM_HTTP_Server(?:/([\\d.]+))?","n":"IBM HTTP Server","c":"Web server","v":"{1}","p":"cpe:2.3:a:ibm:http_server:{v}","k":90},
{"id":"b:websphere","f":"header:server","r":"WebSphere Application Server/([\\d.]+)","n":"IBM WebSphere Application Server","c":"App server","v":"{1}","p":"cpe:2.3:a:ibm:websphere_application_server:{v}","k":90},
{"id":"b:webseal","f":"header:server","r":"^WebSEAL/([\\d.]+)","n":"IBM Security Verify Access (WebSEAL)","c":"Identity","v":"{1}","k":90},
{"id":"b:glassfish","f":"header:server","r":"GlassFish Server[^/\\d]*([\\d.]+)?","n":"Eclipse GlassFish","c":"App server","v":"{1}","p":"cpe:2.3:a:eclipse:glassfish:{v}","k":90},
{"id":"b:payara","f":"header:server","r":"^Payara","n":"Payara Server","c":"App server","k":90},
{"id":"b:wildfly-srv","f":"header:server","r":"^WildFly/(\\d+)","n":"WildFly","c":"App server","v":"{1}","p":"cpe:2.3:a:redhat:wildfly:{v}","k":90},
{"id":"b:resin","f":"header:server","r":"^Resin/([\\d.]+)","n":"Caucho Resin","c":"App server","v":"{1}","k":90},
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
{"id":"b:wingftp","f":"header:server","r":"^Wing FTP Server","n":"Wing FTP Server","c":"File transfer","k":90},
{"id":"b:akamai","f":"header:server","r":"^AkamaiGHost","n":"Akamai","c":"CDN/WAF","k":95},
{"id":"b:cloudflare","f":"header:server","r":"^cloudflare","n":"Cloudflare","c":"CDN/WAF","k":95},
{"id":"b:sucuri","f":"header:server","r":"^Sucuri/Cloudproxy","n":"Sucuri","c":"CDN/WAF","k":95},
{"id":"b:s3","f":"header:server","r":"^AmazonS3","n":"Amazon S3","c":"Storage","k":95},
{"id":"b:awselb","f":"header:server","r":"^awselb/([\\d.]+)","n":"AWS Elastic Load Balancing","c":"Load balancer","k":95},
{"id":"b:azappgw","f":"header:server","r":"^Microsoft-Azure-Application-Gateway","n":"Azure Application Gateway","c":"Load balancer","k":95},
{"id":"b:bigip-srv","f":"header:server","r":"^BIG-?IP","o":"i","n":"F5 BIG-IP","c":"Load balancer","p":"cpe:2.3:a:f5:big-ip_local_traffic_manager:*","k":90},
{"id":"b:fortios","f":"header:server","r":"^xxxxxxxx-xxxxx$","out":[{"n":"Fortinet FortiOS","c":"Firewall","p":"cpe:2.3:o:fortinet:fortios:*","k":95},{"t":"hw","n":"Fortinet FortiGate","c":"Firewall","k":85}]},
{"id":"b:sonicwall-srv","f":"header:server","r":"^SonicWALL","o":"i","n":"SonicWall SonicOS","c":"Firewall","p":"cpe:2.3:o:sonicwall:sonicos:*","k":90},
{"id":"b:checkpoint-srv","f":"header:server","r":"^Check Point SVN foundation","n":"Check Point Gaia","c":"Firewall","k":85},
{"id":"b:ciscoios","f":"header:server","r":"^cisco-IOS","o":"i","t":"os","n":"Cisco IOS","c":"Network device","p":"cpe:2.3:o:cisco:ios:*","k":90},
{"id":"b:appweb","f":"header:server","r":"^(?:Mbedthis|Embedthis)-(?:Appweb|http)(?:/([\\d.]+))?","n":"Embedthis Appweb","c":"Embedded web server","v":"{1}","k":90},
{"id":"b:goahead","f":"header:server","r":"^GoAhead","n":"GoAhead","c":"Embedded web server","k":90},
{"id":"b:boa","f":"header:server","r":"^Boa/([\\d.]+)","n":"Boa","c":"Embedded web server","v":"{1}","k":90},
{"id":"b:lwip","f":"header:server","r":"^lwIP","n":"lwIP","c":"Embedded web server","k":90},
{"id":"b:minihttpd","f":"header:server","r":"^mini_httpd(?:/([\\d.]+))?","n":"mini_httpd","c":"Embedded web server","v":"{1}","k":90},
{"id":"b:thttpd","f":"header:server","r":"^thttpd(?:/([\\d.]+\\w*))?","n":"thttpd","c":"Embedded web server","v":"{1}","k":90},
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
{"id":"b:varnish-srv","f":"header:server","r":"^Varnish","n":"Varnish","c":"Proxy","k":90},
{"id":"b:envoy","f":"header:server","r":"^envoy$","n":"Envoy","c":"Proxy","p":"cpe:2.3:a:envoyproxy:envoy:*","k":95},
{"id":"b:istio","f":"header:server","r":"^istio-envoy","n":"Istio","c":"Container platform","im":["Envoy"],"k":95},
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
{"id":"b:passenger","f":"header:x-powered-by","r":"Phusion Passenger(?: \\(mod_rails/mod_rack\\))? ?([\\d.]+)?","n":"Phusion Passenger","c":"App server","v":"{1}","k":90},
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
{"id":"b:kong-hdr","f":"header:x-kong-proxy-latency","r":"","n":"Kong Gateway","c":"Proxy","k":90},
{"id":"b:envoy-hdr","f":"header:x-envoy-upstream-service-time","r":"","n":"Envoy","c":"Proxy","p":"cpe:2.3:a:envoyproxy:envoy:*","k":90},
{"id":"b:cf-ray","f":"header:cf-ray","r":"","n":"Cloudflare","c":"CDN/WAF","k":95},
{"id":"b:cloudfront","f":"header:x-amz-cf-id","r":"","n":"Amazon CloudFront","c":"CDN/WAF","k":95},
{"id":"b:cloudfront-via","f":"header:via","r":"CloudFront","o":"i","n":"Amazon CloudFront","c":"CDN/WAF","k":90},
{"id":"b:afd","f":"header:x-azure-ref","r":"","n":"Azure Front Door","c":"CDN/WAF","k":90},
{"id":"b:imperva-hdr","f":"header:x-iinfo","r":"","n":"Imperva","c":"CDN/WAF","k":95},
{"id":"b:sucuri-hdr","f":"header:x-sucuri-id","r":"","n":"Sucuri","c":"CDN/WAF","k":95},
{"id":"b:fastly","f":"header:x-fastly-request-id","r":"","n":"Fastly","c":"CDN/WAF","k":95},
{"id":"b:akamai-hdr","f":"header:x-akamai-transformed","r":"","n":"Akamai","c":"CDN/WAF","k":90},
{"id":"b:varnish-hdr","f":"header:x-varnish","r":"","n":"Varnish","c":"Proxy","k":90},
{"id":"b:varnish-via","f":"header:via","r":"varnish","o":"i","n":"Varnish","c":"Proxy","k":85},
{"id":"b:squid-via","f":"header:via","r":"\\(squid/([\\d.]+)\\)","n":"Squid","c":"Proxy","v":"{1}","p":"cpe:2.3:a:squid-cache:squid:{v}","k":90},
{"id":"b:netscaler-via","f":"header:via","r":"NS-CACHE","n":"Citrix NetScaler ADC","c":"Load balancer","k":85},
{"id":"b:artifactory-id","f":"header:x-artifactory-id","r":"","n":"JFrog Artifactory","c":"DevOps","p":"cpe:2.3:a:jfrog:artifactory:*","k":95},
{"id":"b:jfrog-ver","f":"header:x-jfrog-version","r":"Artifactory/([\\d.]+)","n":"JFrog Artifactory","c":"DevOps","v":"{1}","p":"cpe:2.3:a:jfrog:artifactory:{v}","k":100},
{"id":"b:docker-reg","f":"header:docker-distribution-api-version","r":"registry/","n":"Docker Registry","c":"Container platform","k":100},
{"id":"b:gitlab-meta","f":"header:x-gitlab-meta","r":"","n":"GitLab","c":"CI/CD","p":"cpe:2.3:a:gitlab:gitlab:*","k":95},
{"id":"b:gitlab-fc","f":"header:x-gitlab-feature-category","r":"","n":"GitLab","c":"CI/CD","p":"cpe:2.3:a:gitlab:gitlab:*","k":95},
{"id":"b:plex","f":"header:x-plex-protocol","r":"","n":"Plex Media Server","c":"Media","k":95,"flag":"ShadowIT"},
{"id":"b:graylog-hdr","f":"header:x-graylog-node-id","r":"","n":"Graylog","c":"SIEM","k":95},
{"id":"b:teamcity","f":"header:teamcity-node-id","r":"","n":"JetBrains TeamCity","c":"CI/CD","p":"cpe:2.3:a:jetbrains:teamcity:*","k":85},
{"id":"b:datapower","f":"header:x-backside-transport","r":"^(?:OK|FAIL)","n":"IBM DataPower Gateway","c":"Proxy","k":85},
{"id":"b:oracle-ecid","f":"header:x-oracle-dms-ecid","r":"","n":"Oracle Fusion Middleware","c":"App server","k":80},
{"id":"b:litespeed-cache","f":"header:x-litespeed-cache","r":"","n":"LiteSpeed Web Server","c":"Web server","k":85},
{"id":"b:wp-redirect","f":"header:x-redirect-by","r":"^WordPress","n":"WordPress","c":"CMS","p":"cpe:2.3:a:wordpress:wordpress:*","im":["PHP"],"k":95},
{"id":"b:wp-pingback","f":"header:x-pingback","r":"xmlrpc\\.php","n":"WordPress","c":"CMS","p":"cpe:2.3:a:wordpress:wordpress:*","im":["PHP"],"k":90},
{"id":"b:wp-link","f":"header:link","r":"rel=\"https://api\\.w\\.org/\"","n":"WordPress","c":"CMS","p":"cpe:2.3:a:wordpress:wordpress:*","im":["PHP"],"k":95},
{"id":"b:t-iis-default","f":"title","r":"^(?:IIS Windows Server|IIS Windows|IIS7|IIS8|Microsoft Internet Information Services \\d+)$","n":"Microsoft IIS","c":"Web server","p":"cpe:2.3:a:microsoft:internet_information_services:*","k":90,"flag":"DefaultPage"},
{"id":"b:t-apache-default","f":"title","r":"^Apache2 (Ubuntu|Debian) Default Page","out":[{"n":"Apache HTTP Server","c":"Web server","p":"cpe:2.3:a:apache:http_server:*","k":90,"flag":"DefaultPage"},{"t":"os","n":"{1} Linux","c":"OS","k":70}]},
{"id":"b:t-apache-test","f":"title","r":"^(?:Test Page for the (?:Apache )?HTTP Server|HTTP Server Test Page)","n":"Apache HTTP Server","c":"Web server","p":"cpe:2.3:a:apache:http_server:*","k":85,"flag":"DefaultPage"},
{"id":"b:t-nginx-default","f":"title","r":"^Welcome to nginx!?$","n":"nginx","c":"Web server","p":"cpe:2.3:a:f5:nginx:*","k":90,"flag":"DefaultPage"},
{"id":"b:t-openresty-default","f":"title","r":"^Welcome to OpenResty!?$","n":"OpenResty","c":"Web server","k":90,"flag":"DefaultPage"},
{"id":"b:t-tomcat","f":"title","r":"^Apache Tomcat(?:/([\\d.]+))?","n":"Apache Tomcat","c":"App server","v":"{1}","p":"cpe:2.3:a:apache:tomcat:{v}","k":95,"flag":"DefaultPage","ex":"Apache Tomcat/9.0.65","exv":"9.0.65"},
{"id":"b:t-wildfly","f":"title","r":"^Welcome to (?:WildFly|JBoss)","n":"JBoss/WildFly","c":"App server","k":90,"flag":"DefaultPage"},
{"id":"b:t-distro-default","f":"title","r":"^Welcome to (?:CentOS|AlmaLinux|Rocky Linux|Fedora|Red Hat Enterprise Linux)","flag":"DefaultPage","k":80},
{"id":"b:t-dirlist","f":"title","r":"^(?:Index of /|Directory listing for /|Directory Listing For /)","o":"i","flag":"DirectoryListing","k":95},
{"id":"b:t-phpinfo","f":"title","r":"^phpinfo\\(\\)","flag":"PhpInfoExposed","k":95},
{"id":"b:t-swagger","f":"title","r":"^Swagger UI","n":"Swagger UI","c":"Web application","k":95,"flag":"APIDocs"},
{"id":"b:t-owa","f":"title","r":"^Outlook(?: Web App)?$","n":"Microsoft Exchange Server","c":"Mail","p":"cpe:2.3:a:microsoft:exchange_server:*","k":80},
{"id":"b:t-adcs","f":"title","r":"Microsoft Active Directory Certificate Services","n":"AD CS Web Enrollment","c":"Identity","k":100,"flag":"ADCSWebEnrollment"},
{"id":"b:t-rdweb","f":"title","r":"^(?:RD Web Access|RemoteApp and Desktop Connection|Work Resources)$","n":"Microsoft RD Web Access","c":"Remote access","k":90},
{"id":"b:t-wac","f":"title","r":"^Windows Admin Center","n":"Windows Admin Center","c":"Admin panel","p":"cpe:2.3:a:microsoft:windows_admin_center:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-ssrs","f":"title","r":"SQL Server Reporting Services|^Report Viewer$|^Reporting Services","n":"Microsoft SQL Server Reporting Services","c":"Web application","k":90},
{"id":"b:t-pbirs","f":"title","r":"^Power BI Report Server","n":"Power BI Report Server","c":"Web application","k":95},
{"id":"b:t-jenkins","f":"title","r":"\\[Jenkins\\]$|^Jenkins$","n":"Jenkins","c":"CI/CD","p":"cpe:2.3:a:jenkins:jenkins:*","k":90},
{"id":"b:t-gitlab","f":"title","r":"(?:^|\u00b7 )GitLab$","n":"GitLab","c":"CI/CD","p":"cpe:2.3:a:gitlab:gitlab:*","k":90},
{"id":"b:t-gitea","f":"title","r":"Gitea(?:: Git with a cup of tea)?$","n":"Gitea","c":"CI/CD","p":"cpe:2.3:a:gitea:gitea:*","k":85},
{"id":"b:t-gogs","f":"title","r":"\\bGogs\\b","n":"Gogs","c":"CI/CD","k":85},
{"id":"b:t-jira","f":"title","r":"\\b(?:JIRA|Jira)\\b","n":"Atlassian Jira","c":"Collaboration","p":"cpe:2.3:a:atlassian:jira:*","k":75},
{"id":"b:t-confluence","f":"title","r":"\\bConfluence\\b","n":"Atlassian Confluence","c":"Collaboration","p":"cpe:2.3:a:atlassian:confluence_server:*","k":75},
{"id":"b:t-bitbucket","f":"title","r":"\\bBitbucket\\b","n":"Atlassian Bitbucket","c":"CI/CD","p":"cpe:2.3:a:atlassian:bitbucket:*","k":75},
{"id":"b:t-bamboo","f":"title","r":"\\bBamboo\\b","n":"Atlassian Bamboo","c":"CI/CD","k":70},
{"id":"b:t-teamcity","f":"title","r":"\\bTeamCity\\b","n":"JetBrains TeamCity","c":"CI/CD","p":"cpe:2.3:a:jetbrains:teamcity:*","k":85},
{"id":"b:t-sonarqube","f":"title","r":"\\bSonarQube\\b","n":"SonarQube","c":"DevOps","p":"cpe:2.3:a:sonarsource:sonarqube:*","k":90},
{"id":"b:t-nexus","f":"title","r":"Nexus Repository","n":"Sonatype Nexus Repository","c":"DevOps","k":90},
{"id":"b:t-artifactory","f":"title","r":"\\bArtifactory\\b|^JFrog","n":"JFrog Artifactory","c":"DevOps","k":85},
{"id":"b:t-awx","f":"title","r":"^(?:Ansible (?:Tower|AWX)|AWX|Ansible Automation Platform)","n":"Ansible AWX/Tower","c":"DevOps","k":90,"flag":"MgmtInterface"},
{"id":"b:t-foreman","f":"title","r":"^Foreman$|Red Hat Satellite","n":"Foreman/Red Hat Satellite","c":"DevOps","k":85,"flag":"MgmtInterface"},
{"id":"b:t-puppet","f":"title","r":"Puppet Enterprise","n":"Puppet Enterprise","c":"DevOps","k":90},
{"id":"b:t-grafana","f":"title","r":"^Grafana$","n":"Grafana","c":"Monitoring","p":"cpe:2.3:a:grafana:grafana:*","k":90},
{"id":"b:t-kibana","f":"title","r":"^(?:Kibana|Elastic)$","n":"Kibana","c":"Monitoring","p":"cpe:2.3:a:elastic:kibana:*","k":85},
{"id":"b:t-prometheus","f":"title","r":"^Prometheus(?: Time Series Collection and Processing Server)?$","n":"Prometheus","c":"Monitoring","p":"cpe:2.3:a:prometheus:prometheus:*","k":90},
{"id":"b:t-alertmanager","f":"title","r":"^Alertmanager$","n":"Prometheus Alertmanager","c":"Monitoring","k":90},
{"id":"b:t-zabbix","f":"title","r":"\\bZabbix\\b","n":"Zabbix","c":"Monitoring","p":"cpe:2.3:a:zabbix:zabbix:*","k":85,"flag":"MgmtInterface"},
{"id":"b:t-nagios","f":"title","r":"^Nagios","n":"Nagios","c":"Monitoring","p":"cpe:2.3:a:nagios:nagios:*","k":85},
{"id":"b:t-icinga","f":"title","r":"^Icinga Web","n":"Icinga Web","c":"Monitoring","k":90},
{"id":"b:t-cacti","f":"title","r":"^Login to Cacti","n":"Cacti","c":"Monitoring","p":"cpe:2.3:a:cacti:cacti:*","k":95},
{"id":"b:t-librenms","f":"title","r":"\\bLibreNMS\\b","n":"LibreNMS","c":"Monitoring","k":90},
{"id":"b:t-observium","f":"title","r":"\\bObservium\\b","n":"Observium","c":"Monitoring","k":90},
{"id":"b:t-checkmk","f":"title","r":"\\bCheckmk\\b|Check_MK","n":"Checkmk","c":"Monitoring","k":90},
{"id":"b:t-whatsup","f":"title","r":"WhatsUp Gold","n":"Progress WhatsUp Gold","c":"Monitoring","p":"cpe:2.3:a:progress:whatsup_gold:*","k":95},
{"id":"b:t-orion","f":"title","r":"SolarWinds Orion|Orion Platform","n":"SolarWinds Orion","c":"Monitoring","p":"cpe:2.3:a:solarwinds:orion_platform:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-kuma","f":"title","r":"^Uptime Kuma","n":"Uptime Kuma","c":"Monitoring","k":90},
{"id":"b:t-netdata","f":"title","r":"^netdata","o":"i","n":"Netdata","c":"Monitoring","k":85},
{"id":"b:t-cadvisor","f":"title","r":"^cAdvisor","n":"cAdvisor","c":"Monitoring","k":90},
{"id":"b:t-graylog","f":"title","r":"^Graylog","n":"Graylog","c":"SIEM","k":90},
{"id":"b:t-splunk","f":"title","r":"\\bSplunk\\b","n":"Splunk","c":"SIEM","p":"cpe:2.3:a:splunk:splunk:*","k":85},
{"id":"b:t-wazuh","f":"title","r":"\\bWazuh\\b","n":"Wazuh","c":"SIEM","k":90},
{"id":"b:t-nessus","f":"title","r":"^Nessus","n":"Tenable Nessus","c":"Security","p":"cpe:2.3:a:tenable:nessus:*","k":90},
{"id":"b:t-tenablesc","f":"title","r":"Tenable\\.sc|SecurityCenter","n":"Tenable.sc","c":"Security","k":90},
{"id":"b:t-nexpose","f":"title","r":"Nexpose|InsightVM","n":"Rapid7 Nexpose/InsightVM","c":"Security","p":"cpe:2.3:a:rapid7:nexpose:*","k":90},
{"id":"b:t-gsa","f":"title","r":"Greenbone Security Assistant|\\bOpenVAS\\b","n":"Greenbone/OpenVAS","c":"Security","k":90},
{"id":"b:t-idrac","f":"title","r":"iDRAC ?(\\d+)?|Integrated Dell Remote Access Controller","out":[{"n":"Dell iDRAC","c":"Out-of-band mgmt","v":"{1}","k":95,"flag":"MgmtInterface"},{"t":"hw","n":"Dell PowerEdge server","c":"Server hardware","k":70}]},
{"id":"b:t-ilo","f":"title","r":"\\biLO ?(\\d)?\\b|Integrated Lights-Out","out":[{"n":"HPE iLO","c":"Out-of-band mgmt","v":"{1}","k":90,"flag":"MgmtInterface"},{"t":"hw","n":"HPE ProLiant server","c":"Server hardware","k":70}]},
{"id":"b:t-xcc","f":"title","r":"XClarity Controller|Lenovo XClarity","n":"Lenovo XClarity Controller","c":"Out-of-band mgmt","k":90,"flag":"MgmtInterface"},
{"id":"b:t-supermicro","f":"title","r":"Supermicro","n":"Supermicro BMC","c":"Out-of-band mgmt","k":80,"flag":"MgmtInterface"},
{"id":"b:t-cimc","f":"title","r":"Cisco Integrated Management Controller|^Cisco IMC","n":"Cisco IMC","c":"Out-of-band mgmt","k":90,"flag":"MgmtInterface"},
{"id":"b:t-esxi","f":"title","r":"VMware ESXi","n":"VMware ESXi","c":"Virtualization","p":"cpe:2.3:o:vmware:esxi:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-vcenter","f":"title","r":"vSphere|ID_VC_Welcome|VMware vCenter","n":"VMware vCenter Server","c":"Virtualization","p":"cpe:2.3:a:vmware:vcenter_server:*","k":85,"flag":"MgmtInterface"},
{"id":"b:t-horizon","f":"title","r":"^VMware Horizon","n":"VMware Horizon","c":"Remote access","p":"cpe:2.3:a:vmware:horizon:*","k":95},
{"id":"b:t-proxmox","f":"title","r":"Proxmox Virtual Environment|Proxmox Backup Server","n":"Proxmox","c":"Virtualization","k":95,"flag":"MgmtInterface"},
{"id":"b:t-nutanix","f":"title","r":"\\bNutanix\\b","n":"Nutanix Prism","c":"Virtualization","k":85,"flag":"MgmtInterface"},
{"id":"b:t-xen","f":"title","r":"XenServer|Citrix Hypervisor|XenCenter","n":"Citrix Hypervisor","c":"Virtualization","k":85,"flag":"MgmtInterface"},
{"id":"b:t-portainer","f":"title","r":"^Portainer","n":"Portainer","c":"Container platform","p":"cpe:2.3:a:portainer:portainer:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-k8sdash","f":"title","r":"Kubernetes Dashboard","n":"Kubernetes Dashboard","c":"Container platform","k":95,"flag":"MgmtInterface"},
{"id":"b:t-argocd","f":"title","r":"^Argo CD","n":"Argo CD","c":"Container platform","p":"cpe:2.3:a:linuxfoundation:argo-cd:*","k":95},
{"id":"b:t-rancher","f":"title","r":"^Rancher$","n":"Rancher","c":"Container platform","k":90,"flag":"MgmtInterface"},
{"id":"b:t-harbor","f":"title","r":"^Harbor$","n":"Harbor","c":"Container platform","k":90},
{"id":"b:t-openshift","f":"title","r":"OpenShift","n":"Red Hat OpenShift","c":"Container platform","k":85},
{"id":"b:t-traefik","f":"title","r":"^Traefik","n":"Traefik","c":"Proxy","k":90},
{"id":"b:t-consul","f":"title","r":"Consul by HashiCorp","n":"HashiCorp Consul","c":"DevOps","k":95},
{"id":"b:t-vault","f":"title","r":"^Vault$","n":"HashiCorp Vault","c":"Security","k":80},
{"id":"b:t-nomad","f":"title","r":"^Nomad$","n":"HashiCorp Nomad","c":"Container platform","k":80},
{"id":"b:t-minio","f":"title","r":"MinIO Console|^MinIO$","n":"MinIO","c":"Storage","k":90},
{"id":"b:t-pma","f":"title","r":"phpMyAdmin","n":"phpMyAdmin","c":"Admin panel","p":"cpe:2.3:a:phpmyadmin:phpmyadmin:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-adminer","f":"title","r":"\\bAdminer\\b","n":"Adminer","c":"Admin panel","k":90,"flag":"MgmtInterface"},
{"id":"b:t-pgadmin","f":"title","r":"pgAdmin","n":"pgAdmin","c":"Admin panel","k":90,"flag":"MgmtInterface"},
{"id":"b:t-mongoexpress","f":"title","r":"Mongo Express","n":"mongo-express","c":"Admin panel","k":95,"flag":"MgmtInterface"},
{"id":"b:t-rabbitmq","f":"title","r":"RabbitMQ Management","n":"RabbitMQ","c":"Messaging","p":"cpe:2.3:a:vmware:rabbitmq:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-activemq","f":"title","r":"Apache ActiveMQ","n":"Apache ActiveMQ","c":"Messaging","p":"cpe:2.3:a:apache:activemq:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-solr","f":"title","r":"Solr Admin","n":"Apache Solr","c":"Search","p":"cpe:2.3:a:apache:solr:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-airflow","f":"title","r":"\\bAirflow\\b","n":"Apache Airflow","c":"DevOps","p":"cpe:2.3:a:apache:airflow:*","k":85},
{"id":"b:t-nifi","f":"title","r":"^NiFi$","n":"Apache NiFi","c":"DevOps","p":"cpe:2.3:a:apache:nifi:*","k":90},
{"id":"b:t-jupyter","f":"title","r":"^(?:Jupyter(?:Lab| Notebook|Hub)?|Home Page - Select or create a notebook)","n":"Jupyter","c":"DevOps","k":90,"flag":"ShadowIT"},
{"id":"b:t-rstudio","f":"title","r":"^RStudio","n":"RStudio Server","c":"DevOps","k":90},
{"id":"b:t-mlflow","f":"title","r":"^MLflow","n":"MLflow","c":"DevOps","k":90},
{"id":"b:t-roundcube","f":"title","r":"Roundcube Webmail","n":"Roundcube Webmail","c":"Mail","p":"cpe:2.3:a:roundcube:webmail:*","k":95},
{"id":"b:t-zimbra","f":"title","r":"\\bZimbra\\b","n":"Zimbra Collaboration","c":"Mail","p":"cpe:2.3:a:zimbra:collaboration:*","k":90},
{"id":"b:t-nextcloud","f":"title","r":"\\bNextcloud\\b","n":"Nextcloud","c":"Collaboration","p":"cpe:2.3:a:nextcloud:nextcloud_server:*","k":90},
{"id":"b:t-owncloud","f":"title","r":"\\bownCloud\\b","n":"ownCloud","c":"Collaboration","k":90},
{"id":"b:t-mattermost","f":"title","r":"\\bMattermost\\b","n":"Mattermost","c":"Messaging","k":90},
{"id":"b:t-rocketchat","f":"title","r":"Rocket\\.Chat","n":"Rocket.Chat","c":"Messaging","k":90},
{"id":"b:t-redmine","f":"title","r":"\\bRedmine\\b","n":"Redmine","c":"Collaboration","p":"cpe:2.3:a:redmine:redmine:*","k":85},
{"id":"b:t-bugzilla","f":"title","r":"\\bBugzilla\\b","n":"Bugzilla","c":"Collaboration","k":85},
{"id":"b:t-keycloak","f":"title","r":"\\bKeycloak\\b","n":"Keycloak","c":"Identity","p":"cpe:2.3:a:redhat:keycloak:*","k":90},
{"id":"b:t-pvwa","f":"title","r":"Password Vault|PasswordVault","n":"CyberArk PVWA","c":"Identity","k":85},
{"id":"b:t-secretserver","f":"title","r":"\\bSecret Server\\b","n":"Delinea Secret Server","c":"Identity","k":85},
{"id":"b:t-manageengine","f":"title","r":"\\bManageEngine ([\\w ]+?)(?:\\s*[-|]|$)","n":"ManageEngine {1}","c":"Admin panel","k":80},
{"id":"b:t-moveit","f":"title","r":"MOVEit Transfer","n":"Progress MOVEit Transfer","c":"File transfer","p":"cpe:2.3:a:progress:moveit_transfer:*","k":95},
{"id":"b:t-goanywhere","f":"title","r":"GoAnywhere","n":"Fortra GoAnywhere MFT","c":"File transfer","p":"cpe:2.3:a:fortra:goanywhere_managed_file_transfer:*","k":90},
{"id":"b:t-guac","f":"title","r":"Guacamole","n":"Apache Guacamole","c":"Remote access","p":"cpe:2.3:a:apache:guacamole:*","k":90},
{"id":"b:t-openvpnas","f":"title","r":"OpenVPN Access Server|^OpenVPN","n":"OpenVPN Access Server","c":"VPN","k":85},
{"id":"b:t-nodered","f":"title","r":"^Node-RED","n":"Node-RED","c":"DevOps","k":90,"flag":"MgmtInterface"},
{"id":"b:t-odoo","f":"title","r":"\\bOdoo\\b","n":"Odoo","c":"Web application","k":85},
{"id":"b:t-veeam","f":"title","r":"Veeam Backup","n":"Veeam Backup & Replication","c":"Backup","k":90,"flag":"MgmtInterface"},
{"id":"b:t-netapp","f":"title","r":"NetApp|ONTAP System Manager|OnCommand System Manager","n":"NetApp ONTAP","c":"Storage","k":85,"flag":"MgmtInterface"},
{"id":"b:t-synology","f":"title","r":"\\bSynology\\b|DiskStation","n":"Synology DSM","c":"Storage","p":"cpe:2.3:o:synology:diskstation_manager:*","k":85,"flag":"MgmtInterface"},
{"id":"b:t-qnap","f":"title","r":"\\bQNAP\\b","n":"QNAP QTS","c":"Storage","k":85,"flag":"MgmtInterface"},
{"id":"b:t-unisphere","f":"title","r":"\\bUnisphere\\b","n":"Dell EMC Unisphere","c":"Storage","k":85,"flag":"MgmtInterface"},
{"id":"b:t-pure","f":"title","r":"Pure Storage","n":"Pure Storage","c":"Storage","k":85,"flag":"MgmtInterface"},
{"id":"b:t-pfsense","f":"title","r":"\\bpfSense\\b","n":"Netgate pfSense","c":"Firewall","p":"cpe:2.3:a:netgate:pfsense:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-opnsense","f":"title","r":"\\bOPNsense\\b","n":"OPNsense","c":"Firewall","p":"cpe:2.3:a:opnsense:opnsense:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-forti","f":"title","r":"\\bForti(Gate|Web|Mail|Manager|Analyzer|ADC|Authenticator|SIEM|NAC|Proxy|Sandbox)\\b","n":"Fortinet Forti{1}","c":"Firewall","k":90,"flag":"MgmtInterface"},
{"id":"b:t-sonicwall","f":"title","r":"SonicWall|SonicWALL","n":"SonicWall SonicOS","c":"Firewall","p":"cpe:2.3:o:sonicwall:sonicos:*","k":85},
{"id":"b:t-sophos","f":"title","r":"\\bSophos\\b","n":"Sophos Firewall","c":"Firewall","k":80},
{"id":"b:t-watchguard","f":"title","r":"Fireware XTM|WatchGuard","n":"WatchGuard Firebox","c":"Firewall","k":85},
{"id":"b:t-zyxel","f":"title","r":"ZyWALL|\\bZyxel\\b|ZyXEL","n":"Zyxel","c":"Network device","k":80},
{"id":"b:t-globalprotect","f":"title","r":"GlobalProtect","n":"Palo Alto GlobalProtect","c":"VPN","p":"cpe:2.3:o:paloaltonetworks:pan-os:*","k":95},
{"id":"b:t-citrixgw","f":"title","r":"Citrix Gateway|NetScaler Gateway|NetScaler AAA|Citrix ADC","n":"Citrix Gateway","c":"VPN","k":90},
{"id":"b:t-storefront","f":"title","r":"Citrix StoreFront|Citrix Receiver","n":"Citrix StoreFront","c":"Remote access","k":90},
{"id":"b:t-bigip","f":"title","r":"BIG-IP|F5 Networks","n":"F5 BIG-IP","c":"Load balancer","k":85},
{"id":"b:t-barracuda","f":"title","r":"\\bBarracuda\\b","n":"Barracuda","c":"Firewall","k":80},
{"id":"b:t-gaia","f":"title","r":"\\bGaia\\b|Check Point","n":"Check Point Gaia","c":"Firewall","k":80},
{"id":"b:t-snx","f":"title","r":"SSL Network Extender","n":"Check Point Mobile Access","c":"VPN","k":90},
{"id":"b:t-ivanti","f":"title","r":"Pulse Connect Secure|Ivanti Connect Secure|Pulse Secure","n":"Ivanti Connect Secure","c":"VPN","p":"cpe:2.3:a:ivanti:connect_secure:*","k":95},
{"id":"b:t-asa","f":"title","r":"SSL VPN Service|Cisco ASDM","n":"Cisco ASA","c":"VPN","k":75},
{"id":"b:t-ise","f":"title","r":"Identity Services Engine","n":"Cisco ISE","c":"Identity","p":"cpe:2.3:a:cisco:identity_services_engine:*","k":95,"flag":"MgmtInterface"},
{"id":"b:t-cucm","f":"title","r":"Cisco Unified (?:Communications|CM)","n":"Cisco Unified Communications Manager","c":"VoIP","k":90},
{"id":"b:t-ciscoprime","f":"title","r":"Cisco Prime","n":"Cisco Prime","c":"Network device","k":90,"flag":"MgmtInterface"},
{"id":"b:t-unifi","f":"title","r":"UniFi Network|UniFi OS|^UniFi","n":"Ubiquiti UniFi","c":"Network device","k":90,"flag":"MgmtInterface"},
{"id":"b:t-routeros","f":"title","r":"RouterOS","out":[{"t":"os","n":"MikroTik RouterOS","c":"Network device","p":"cpe:2.3:o:mikrotik:routeros:*","k":90},{"n":"MikroTik WebFig","c":"Network device","k":85,"flag":"MgmtInterface"}]},
{"id":"b:t-jweb","f":"title","r":"J-Web|Juniper Networks Web Management","n":"Juniper J-Web","c":"Network device","k":90,"flag":"MgmtInterface"},
{"id":"b:t-aruba","f":"title","r":"\\bAruba\\b","n":"Aruba","c":"Network device","k":70},
{"id":"b:t-ruckus","f":"title","r":"\\bRuckus\\b","n":"Ruckus","c":"Network device","k":70},
{"id":"b:t-luci","f":"title","r":"\\bLuCI\\b|OpenWrt","n":"OpenWrt LuCI","c":"Network device","k":85},
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
{"id":"b:t-metasys","f":"title","r":"\\bMetasys\\b","n":"Johnson Controls Metasys","c":"Building automation","k":90,"flag":"MgmtInterface"},
{"id":"b:t-niagara","f":"title","r":"\\bNiagara\\b","n":"Tridium Niagara","c":"Building automation","k":75},
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
{"id":"b:body-citrixgw","f":"body","r":"/vpn/index\\.html|/logon/LogonPoint/","n":"Citrix Gateway","c":"VPN","k":85},
{"id":"b:body-ivanti","f":"body","r":"/dana-na/","n":"Ivanti Connect Secure","c":"VPN","p":"cpe:2.3:a:ivanti:connect_secure:*","k":90},
{"id":"b:body-asa","f":"body","r":"/\\+CSCOE\\+/","n":"Cisco ASA","c":"VPN","p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:*","k":90},
{"id":"b:body-fortivpn","f":"body","r":"/remote/login|/remote/logincheck|ftnt-fortinet","n":"Fortinet FortiOS","c":"Firewall","p":"cpe:2.3:o:fortinet:fortios:*","k":85},
{"id":"b:body-next","f":"body","r":"__NEXT_DATA__","n":"Next.js","c":"Framework","im":["React"],"k":90},
{"id":"b:body-nuxt","f":"body","r":"window\\.__NUXT__","n":"Nuxt.js","c":"Framework","im":["Vue.js"],"k":90},
{"id":"b:body-angular","f":"body","r":"ng-version=\"([\\d.]+)\"","n":"Angular","c":"JavaScript libraries","v":"{1}","k":95},
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
{"id":"b:body-reqtoken","f":"body","r":"name=\"__RequestVerificationToken\"","n":"ASP.NET MVC","c":"Framework","im":["ASP.NET"],"k":70},
{"id":"b:body-swagger","f":"body","r":"swagger-ui(?:-bundle)?\\.js|id=\"swagger-ui\"","n":"Swagger UI","c":"Web application","k":90,"flag":"APIDocs"},
{"id":"b:body-azappgw","f":"body","r":"Microsoft-Azure-Application-Gateway","n":"Azure Application Gateway","c":"Load balancer","k":90},
{"id":"b:js-jquery","f":"scriptsrc","r":"jquery[.-]([\\d]+\\.[\\d]+\\.[\\d]+)(?:\\.slim)?(?:\\.min)?\\.js","o":"i","n":"jQuery","c":"JavaScript libraries","v":"{1}","p":"cpe:2.3:a:jquery:jquery:{v}","k":95,"ex":"/static/js/jquery-3.5.1.min.js","exv":"3.5.1"},
{"id":"b:js-jquery-ver","f":"scriptsrc","r":"jquery(?:\\.min)?\\.js\\?ver=([\\d.]+)","o":"i","n":"jQuery","c":"JavaScript libraries","v":"{1}","p":"cpe:2.3:a:jquery:jquery:{v}","k":85},
{"id":"b:js-jqueryui","f":"scriptsrc","r":"jquery-ui[.-]([\\d]+\\.[\\d]+\\.[\\d]+)(?:\\.min)?\\.js","o":"i","n":"jQuery UI","c":"JavaScript libraries","v":"{1}","p":"cpe:2.3:a:jqueryui:jquery_ui:{v}","k":95},
{"id":"b:js-angularjs","f":"scriptsrc","r":"angular(?:js)?/([\\d.]+)/angular(?:\\.min)?\\.js","n":"AngularJS","c":"JavaScript libraries","v":"{1}","p":"cpe:2.3:a:angularjs:angular.js:{v}","k":95},
{"id":"b:js-bootstrap","f":"scriptsrc","r":"bootstrap(?:\\.bundle)?(?:\\.min)?\\.js(?:\\?v(?:er)?=([\\d.]+))?","n":"Bootstrap","c":"JavaScript libraries","v":"{1}","k":75},
{"id":"b:js-wp","f":"scriptsrc","r":"/wp-(?:content|includes)/","n":"WordPress","c":"CMS","p":"cpe:2.3:a:wordpress:wordpress:*","im":["PHP"],"k":90},
{"id":"b:meta-wp","f":"meta:generator","r":"^WordPress ?([\\d.]+)?","n":"WordPress","c":"CMS","v":"{1}","p":"cpe:2.3:a:wordpress:wordpress:{v}","im":["PHP"],"k":100,"ex":"WordPress 6.4.2","exv":"6.4.2"},
{"id":"b:meta-joomla","f":"meta:generator","r":"^Joomla!? ?([\\d.]+)?","n":"Joomla","c":"CMS","v":"{1}","im":["PHP"],"k":100},
{"id":"b:meta-drupal","f":"meta:generator","r":"^Drupal ?(\\d+)?","n":"Drupal","c":"CMS","v":"{1}","p":"cpe:2.3:a:drupal:drupal:{v}","im":["PHP"],"k":100},
{"id":"b:meta-mediawiki","f":"meta:generator","r":"^MediaWiki ?([\\d.]+)?","n":"MediaWiki","c":"CMS","v":"{1}","p":"cpe:2.3:a:mediawiki:mediawiki:{v}","im":["PHP"],"k":100},
{"id":"b:meta-sharepoint","f":"meta:generator","r":"Microsoft SharePoint","n":"Microsoft SharePoint","c":"Collaboration","p":"cpe:2.3:a:microsoft:sharepoint_server:*","k":95},
{"id":"b:meta-typo3","f":"meta:generator","r":"TYPO3 ?(?:CMS)? ?([\\d.]+)?","n":"TYPO3","c":"CMS","v":"{1}","p":"cpe:2.3:a:typo3:typo3:{v}","k":95},
{"id":"b:meta-hugo","f":"meta:generator","r":"^Hugo ([\\d.]+)","n":"Hugo","c":"CMS","v":"{1}","k":95},
{"id":"b:meta-jekyll","f":"meta:generator","r":"^Jekyll v([\\d.]+)","n":"Jekyll","c":"CMS","v":"{1}","k":95},
{"id":"b:meta-dokuwiki","f":"meta:generator","r":"DokuWiki","n":"DokuWiki","c":"CMS","im":["PHP"],"k":95},
{"id":"b:meta-ghost","f":"meta:generator","r":"^Ghost ([\\d.]+)","n":"Ghost","c":"CMS","v":"{1}","k":95},
{"id":"b:meta-plone","f":"meta:generator","r":"^Plone","n":"Plone","c":"CMS","k":95},
{"id":"b:meta-docusaurus","f":"meta:generator","r":"^Docusaurus v([\\d.]+)","n":"Docusaurus","c":"CMS","v":"{1}","k":95},
{"id":"b:meta-mkdocs","f":"meta:generator","r":"^mkdocs-([\\d.]+)","o":"i","n":"MkDocs","c":"CMS","v":"{1}","k":95},
{"id":"b:meta-moodle","f":"meta:generator","r":"Moodle","n":"Moodle","c":"Web application","im":["PHP"],"k":95},
{"id":"b:meta-confluence","f":"meta:generator","r":"Confluence","n":"Atlassian Confluence","c":"Collaboration","k":90},
{"id":"b:meta-appname-jira","f":"meta:application-name","r":"^JIRA$","n":"Atlassian Jira","c":"Collaboration","p":"cpe:2.3:a:atlassian:jira:*","k":95},
{"id":"b:c-aspnet","f":"cookiename","r":"^ASP\\.NET_SessionId$","n":"ASP.NET","c":"Framework","p":"cpe:2.3:a:microsoft:asp.net:*","k":90},
{"id":"b:c-aspnetcore","f":"cookiename","r":"^\\.AspNetCore\\.","n":"ASP.NET Core","c":"Framework","k":90},
{"id":"b:c-asp","f":"cookiename","r":"^ASPSESSIONID","n":"Classic ASP","c":"Framework","k":90},
{"id":"b:c-php","f":"cookiename","r":"^PHPSESSID$","n":"PHP","c":"Language","p":"cpe:2.3:a:php:php:*","k":85},
{"id":"b:c-java","f":"cookiename","r":"^JSESSIONID$","n":"Java","c":"Language","k":70},
{"id":"b:c-coldfusion","f":"cookiename","r":"^(?:CFID|CFTOKEN)$","n":"Adobe ColdFusion","c":"App server","p":"cpe:2.3:a:adobe:coldfusion:*","k":90},
{"id":"b:c-laravel","f":"cookiename","r":"^laravel_session$","n":"Laravel","c":"Framework","im":["PHP"],"k":95},
{"id":"b:c-codeigniter","f":"cookiename","r":"^ci_session$","n":"CodeIgniter","c":"Framework","im":["PHP"],"k":90},
{"id":"b:c-django","f":"cookiename","r":"^csrftoken$","n":"Django","c":"Framework","im":["Python"],"k":60},
{"id":"b:c-gitlab","f":"cookiename","r":"^_gitlab_session$","n":"GitLab","c":"CI/CD","p":"cpe:2.3:a:gitlab:gitlab:*","k":95},
{"id":"b:c-gitea","f":"cookiename","r":"^i_like_gitea$","n":"Gitea","c":"CI/CD","p":"cpe:2.3:a:gitea:gitea:*","k":95},
{"id":"b:c-gogs","f":"cookiename","r":"^i_like_gogs$","n":"Gogs","c":"CI/CD","k":95},
{"id":"b:c-redmine","f":"cookiename","r":"^_redmine_session$","n":"Redmine","c":"Collaboration","k":95},
{"id":"b:c-moodle","f":"cookiename","r":"^MoodleSession","n":"Moodle","c":"Web application","k":95},
{"id":"b:c-roundcube","f":"cookiename","r":"^roundcube_sessid$","n":"Roundcube Webmail","c":"Mail","k":95},
{"id":"b:c-zimbra","f":"cookiename","r":"^ZM_(?:TEST|AUTH_TOKEN)$","n":"Zimbra Collaboration","c":"Mail","k":95},
{"id":"b:c-jira","f":"cookiename","r":"^atlassian\\.xsrf\\.token$","n":"Atlassian Jira","c":"Collaboration","k":80},
{"id":"b:c-bigip","f":"cookiename","r":"^BIGipServer","n":"F5 BIG-IP","c":"Load balancer","p":"cpe:2.3:a:f5:big-ip_local_traffic_manager:*","k":95},
{"id":"b:c-f5apm","f":"cookiename","r":"^(?:MRHSession|LastMRH_Session|F5_ST|F5_fullWT)$","n":"F5 BIG-IP APM","c":"VPN","p":"cpe:2.3:a:f5:big-ip_access_policy_manager:*","k":95},
{"id":"b:c-netscaler","f":"cookiename","r":"^NSC_|^citrix_ns_id","n":"Citrix NetScaler ADC","c":"Load balancer","k":95},
{"id":"b:c-awselb","f":"cookiename","r":"^AWSALB|^AWSELB","n":"AWS Elastic Load Balancing","c":"Load balancer","k":95},
{"id":"b:c-arr","f":"cookiename","r":"^ARRAffinity","n":"Microsoft Application Request Routing","c":"Load balancer","k":85},
{"id":"b:c-imperva","f":"cookiename","r":"^(?:incap_ses_|visid_incap_|nlbi_)","n":"Imperva","c":"CDN/WAF","k":95},
{"id":"b:c-cloudflare","f":"cookiename","r":"^(?:__cfduid|__cf_bm|cf_clearance)$","n":"Cloudflare","c":"CDN/WAF","k":95},
{"id":"b:c-barracuda","f":"cookiename","r":"^barra_counter_session","n":"Barracuda WAF","c":"CDN/WAF","k":95},
{"id":"b:c-f5asm","f":"cookiename","r":"^TS[0-9a-f]{6,8}$","n":"F5 Advanced WAF (ASM)","c":"CDN/WAF","k":70},
{"id":"b:c-akamaibm","f":"cookiename","r":"^(?:ak_bmsc|bm_sv|bm_sz)$","n":"Akamai Bot Manager","c":"CDN/WAF","k":90},
{"id":"b:c-asavpn","f":"cookiename","r":"^webvpn","n":"Cisco ASA","c":"VPN","p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:*","k":90},
{"id":"b:c-ivanti","f":"cookiename","r":"^(?:DSSignInURL|DSID|DSLastAccess|DSFirstAccess)$","n":"Ivanti Connect Secure","c":"VPN","p":"cpe:2.3:a:ivanti:connect_secure:*","k":95},
{"id":"b:c-fortivpn","f":"cookiename","r":"^(?:SVPNCOOKIE|SVPNNETWORKCOOKIE)$","n":"Fortinet FortiOS","c":"Firewall","p":"cpe:2.3:o:fortinet:fortios:*","k":95},
{"id":"b:c-nexpose","f":"cookiename","r":"^nexposeCCSessionID","n":"Rapid7 Nexpose/InsightVM","c":"Security","k":95},
{"id":"b:c-splunk","f":"cookiename","r":"^splunkweb_csrf_token_","n":"Splunk","c":"SIEM","p":"cpe:2.3:a:splunk:splunk:*","k":95},
{"id":"b:c-grafana","f":"cookiename","r":"^grafana_session$","n":"Grafana","c":"Monitoring","p":"cpe:2.3:a:grafana:grafana:*","k":95},
{"id":"b:c-zabbix","f":"cookiename","r":"^zbx_session(?:id)?$","n":"Zabbix","c":"Monitoring","k":95},
{"id":"b:c-owa","f":"cookiename","r":"^(?:X-OWA-CANARY|X-BackEndCookie)$","n":"Microsoft Exchange Server","c":"Mail","p":"cpe:2.3:a:microsoft:exchange_server:*","k":90},
{"id":"b:c-adfs","f":"cookiename","r":"^MSIS","n":"Microsoft AD FS","c":"Identity","k":90},
{"id":"b:c-rdweb","f":"cookiename","r":"^TSWA","n":"Microsoft RD Web Access","c":"Remote access","k":85},
{"id":"b:c-siteminder","f":"cookiename","r":"^SMSESSION$","n":"Broadcom SiteMinder","c":"Identity","k":90},
{"id":"b:c-webseal","f":"cookiename","r":"^PD-[SH]-SESSION-ID$","n":"IBM Security Verify Access (WebSEAL)","c":"Identity","k":90},
{"id":"b:c-oam","f":"cookiename","r":"^(?:ObSSOCookie|OAMAuthnCookie)","n":"Oracle Access Manager","c":"Identity","k":90},
{"id":"b:c-keycloak","f":"cookiename","r":"^(?:KEYCLOAK_|AUTH_SESSION_ID$)","n":"Keycloak","c":"Identity","k":85},
{"id":"b:c-sap","f":"cookiename","r":"^(?:sap-usercontext|MYSAPSSO2|SAP_SESSIONID)","n":"SAP NetWeaver Application Server","c":"App server","k":90},
{"id":"b:c-peoplesoft","f":"cookiename","r":"^PS_(?:TOKEN|LOGINLIST|DEVICEFEATURES)$","n":"Oracle PeopleSoft","c":"Web application","k":90},
{"id":"b:c-rack","f":"cookiename","r":"^rack\\.session$","n":"Ruby Rack","c":"Framework","k":70},
{"id":"b:c-connectsid","f":"cookiename","r":"^connect\\.sid$","n":"Express","c":"Framework","im":["Node.js"],"k":75},
{"id":"b:c-wp","f":"cookiename","r":"^(?:wordpress_|wp-settings-)","n":"WordPress","c":"CMS","im":["PHP"],"k":90},
{"id":"b:c-drupal","f":"cookiename","r":"^S?SESS[0-9a-f]{32}$","n":"Drupal","c":"CMS","im":["PHP"],"k":70},
{"id":"b:a-tomcatmgr","f":"auth","r":"realm=\"Tomcat Manager Application\"","n":"Apache Tomcat Manager","c":"Admin panel","im":["Apache Tomcat"],"k":100,"flag":"MgmtInterface"},
{"id":"b:a-nagios","f":"auth","r":"realm=\"Nagios Access\"","n":"Nagios","c":"Monitoring","k":95},
{"id":"b:a-jmx","f":"auth","r":"realm=\"JBoss JMX Console\"","n":"JBoss JMX Console","c":"Admin panel","k":100,"flag":"MgmtInterface"},
{"id":"b:l-ivanti","f":"location","r":"/dana-na/","n":"Ivanti Connect Secure","c":"VPN","p":"cpe:2.3:a:ivanti:connect_secure:*","k":95},
{"id":"b:l-asa","f":"location","r":"/\\+CSCOE\\+/","n":"Cisco ASA","c":"VPN","p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:*","k":95},
{"id":"b:l-fortivpn","f":"location","r":"/remote/login","n":"Fortinet FortiOS","c":"Firewall","p":"cpe:2.3:o:fortinet:fortios:*","k":90},
{"id":"b:l-gp","f":"location","r":"/global-protect/","n":"Palo Alto GlobalProtect","c":"VPN","p":"cpe:2.3:o:paloaltonetworks:pan-os:*","k":95},
{"id":"b:l-owa","f":"location","r":"/owa/?(?:$|[?#])|/owa/auth/","o":"i","n":"Microsoft Exchange Server","c":"Mail","p":"cpe:2.3:a:microsoft:exchange_server:*","k":85},
{"id":"b:l-ecp","f":"location","r":"/ecp/","o":"i","n":"Microsoft Exchange Server","c":"Mail","k":80},
{"id":"b:l-adfs","f":"location","r":"/adfs/ls","o":"i","n":"Microsoft AD FS","c":"Identity","k":90},
{"id":"b:l-rdweb","f":"location","r":"/RDWeb","o":"i","n":"Microsoft RD Web Access","c":"Remote access","k":90},
{"id":"b:l-storefront","f":"location","r":"/Citrix/\\w+Web","o":"i","n":"Citrix StoreFront","c":"Remote access","k":90},
{"id":"b:l-citrixgw","f":"location","r":"/vpn/index\\.html|/logon/LogonPoint","n":"Citrix Gateway","c":"VPN","k":90},
{"id":"b:l-f5apm","f":"location","r":"/my\\.policy|/my\\.logon\\.php","n":"F5 BIG-IP APM","c":"VPN","k":90},
{"id":"b:l-tmui","f":"location","r":"/tmui/","n":"F5 BIG-IP TMUI","c":"Load balancer","k":95,"flag":"MgmtInterface"},
{"id":"b:l-pvwa","f":"location","r":"/PasswordVault","o":"i","n":"CyberArk PVWA","c":"Identity","k":95},
{"id":"b:l-ssrs","f":"location","r":"/Reports/|/ReportServer","o":"i","n":"Microsoft SQL Server Reporting Services","c":"Web application","k":85},
{"id":"b:l-certsrv","f":"location","r":"/certsrv","o":"i","n":"AD CS Web Enrollment","c":"Identity","k":85,"flag":"ADCSWebEnrollment"},
{"id":"b:l-prom","f":"location","r":"^/graph$|/graph$","n":"Prometheus","c":"Monitoring","k":75},
{"id":"b:l-vcenter","f":"location","r":"/websso/SAML2/SSO/","n":"VMware vCenter Server","c":"Virtualization","p":"cpe:2.3:a:vmware:vcenter_server:*","k":90,"flag":"MgmtInterface"},
{"id":"b:l-hik","f":"location","r":"/doc/page/login\\.asp","t":"hw","n":"Hikvision camera/NVR","c":"Camera/IoT","k":85},
{"id":"b:l-luci","f":"location","r":"/cgi-bin/luci","n":"OpenWrt LuCI","c":"Network device","k":90},
{"id":"b:l-webfig","f":"location","r":"/webfig/","n":"MikroTik WebFig","c":"Network device","k":90,"flag":"MgmtInterface"},
{"id":"b:x-sonicwall","f":"cert.subject","r":"HTTPS Management Certificate for SonicWALL","n":"SonicWall SonicOS","c":"Firewall","k":95},
{"id":"b:x-asa","f":"cert.subject","r":"CN=ASA Temporary Self Signed Certificate","n":"Cisco ASA","c":"VPN","k":95},
{"id":"b:x-splunk","f":"cert.subject","r":"CN=SplunkServerDefaultCert|O=SplunkUser","n":"Splunk","c":"SIEM","k":95,"flag":"DefaultCert"},
{"id":"b:x-nessus","f":"cert.subject","r":"O=Nessus Users United","n":"Tenable Nessus","c":"Security","k":95,"flag":"DefaultCert"},
{"id":"b:x-pfsense","f":"cert.subject","r":"pfSense webConfigurator Self-Signed","n":"Netgate pfSense","c":"Firewall","k":95,"flag":"DefaultCert"},
{"id":"b:x-proxmox","f":"cert.issuer","r":"CN=Proxmox Virtual Environment|O=PVE Cluster Manager CA","n":"Proxmox","c":"Virtualization","k":95},
{"id":"b:x-wac","f":"cert.subject","r":"CN=Windows Admin Center","n":"Windows Admin Center","c":"Admin panel","k":95,"flag":"MgmtInterface"},
{"id":"b:x-k8s","f":"cert.issuer","r":"CN=(?:kubernetes|kube-ca)(?:,|$)","n":"Kubernetes","c":"Container platform","k":85},
{"id":"b:x-vmware","f":"cert.issuer","r":"OU=VMware Engineering|O=VMware Installer","n":"VMware ESXi","c":"Virtualization","k":80,"flag":"DefaultCert"},
{"id":"b:x-idrac","f":"cert.subject","r":"OU=Remote Access Group,O=Dell Inc\\.","n":"Dell iDRAC","c":"Out-of-band mgmt","k":90,"flag":"MgmtInterface"},
{"id":"b:x-ilo","f":"cert.subject","r":"CN=ILO","o":"i","n":"HPE iLO","c":"Out-of-band mgmt","k":80,"flag":"MgmtInterface"},
{"id":"b:x-supermicro","f":"cert.subject","r":"O=Super Micro Computer","n":"Supermicro BMC","c":"Out-of-band mgmt","k":90,"flag":"MgmtInterface"},
{"id":"b:x-synology","f":"cert.subject","r":"O=Synology Inc\\.","n":"Synology DSM","c":"Storage","k":85},
{"id":"b:x-ubiquiti","f":"cert.subject","r":"O=Ubiquiti","n":"Ubiquiti","c":"Network device","k":85},
{"id":"b:x-paloalto","f":"cert.subject","r":"O=Palo Alto Networks","n":"Palo Alto Networks PAN-OS","c":"Firewall","k":80},
{"id":"b:x-fortinet","f":"cert.subject","r":"O=Fortinet","n":"Fortinet FortiOS","c":"Firewall","k":85},
{"id":"b:x-opensslde","f":"cert.subject","r":"O=Internet Widgits Pty Ltd","flag":"DefaultCert","k":95},
{"id":"b:x-modssl","f":"cert.subject","r":"O=SomeOrganization|OU=SomeOrganizationalUnit","flag":"DefaultCert","k":95},
{"id":"b:x-plesk","f":"cert.subject","r":"CN=Plesk","n":"Plesk","c":"Admin panel","k":85},
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
{"id":"b:p-owa2","f":"path:/owa/auth/logon.aspx.body","r":"/owa/auth/","n":"Microsoft Exchange Server","c":"Mail","k":90},
{"id":"b:p-certsrv-t","f":"path:/certsrv/.title","r":"Microsoft Active Directory Certificate Services","n":"AD CS Web Enrollment","c":"Identity","k":100,"flag":"ADCSWebEnrollment"},
{"id":"b:p-certsrv-401","f":"path:/certsrv/.status","r":"^401$","and":[{"f":"status","r":"^401$","not":true},{"f":"path:/certsrv/.auth","r":"^(?:NTLM|Negotiate)"}],"n":"AD CS Web Enrollment","c":"Identity","k":85,"flag":"ADCSWebEnrollment"},
{"id":"b:p-adfs","f":"path:/adfs/ls/idpinitiatedsignon.aspx.body","r":"/adfs/portal/|AD FS|idpinitiatedsignon","o":"i","n":"Microsoft AD FS","c":"Identity","k":90},
{"id":"b:p-rdweb","f":"path:/RDWeb/.body","r":"RD Web Access|TSWA|RDWeb","o":"i","n":"Microsoft RD Web Access","c":"Remote access","k":90},
{"id":"b:p-fortivpn","f":"path:/remote/login.body","r":"fgt_lang|ftnt|/remote/logincheck|FortiToken","o":"i","n":"Fortinet FortiOS","c":"Firewall","p":"cpe:2.3:o:fortinet:fortios:*","k":90},
{"id":"b:p-gp","f":"path:/global-protect/login.esp.body","r":"GlobalProtect","n":"Palo Alto GlobalProtect","c":"VPN","p":"cpe:2.3:o:paloaltonetworks:pan-os:*","k":95},
{"id":"b:p-asa","f":"path:/+CSCOE+/logon.html.body","r":"webvpn|CSCOE|SSL VPN Service","o":"i","n":"Cisco ASA","c":"VPN","p":"cpe:2.3:o:cisco:adaptive_security_appliance_software:*","k":90},
{"id":"b:p-ivanti","f":"path:/dana-na/auth/url_default/welcome.cgi.body","r":"dana-na|Pulse Secure|Ivanti","o":"i","n":"Ivanti Connect Secure","c":"VPN","p":"cpe:2.3:a:ivanti:connect_secure:*","k":90},
{"id":"b:p-citrixgw","f":"path:/vpn/index.html.body","r":"Citrix|NetScaler","o":"i","n":"Citrix Gateway","c":"VPN","k":85},
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
{"id":"b:p-oidc-kc","f":"path:/.well-known/openid-configuration.body","r":"\"issuer\"\\s*:\\s*\"[^\"]*/realms/","n":"Keycloak","c":"Identity","k":90},
{"id":"b:p-oidc-adfs","f":"path:/.well-known/openid-configuration.body","r":"\"issuer\"\\s*:\\s*\"[^\"]*/adfs","o":"i","n":"Microsoft AD FS","c":"Identity","k":95},
{"id":"b:p-tomcatmgr","f":"path:/manager/html.auth","r":"realm=\"Tomcat Manager Application\"","n":"Apache Tomcat Manager","c":"Admin panel","im":["Apache Tomcat"],"k":100,"flag":"MgmtInterface"},
{"id":"b:p-registry","f":"path:/v2/.header:docker-distribution-api-version","r":"registry/","n":"Docker Registry","c":"Container platform","k":100}
]}
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
    function Get-BodyText([byte[]]$Body, [string]$ContentType) {
        if (-not $Body -or $Body.Length -eq 0) { return '' }
        $enc = $null
        if ($ContentType -match 'charset\s*=\s*"?([\w\-]+)') { try { $enc = [Text.Encoding]::GetEncoding($Matches[1]) } catch { $enc = $null } }
        if (-not $enc) {
            $sniff = [Text.Encoding]::ASCII.GetString($Body, 0, [Math]::Min(2048, $Body.Length))
            if ($sniff -match '<meta[^>]+charset\s*=\s*["'']?([\w\-]+)') { try { $enc = [Text.Encoding]::GetEncoding($Matches[1]) } catch { $enc = $null } }
        }
        if (-not $enc) { $enc = [Text.Encoding]::UTF8 }
        $enc.GetString($Body)
    }
    function ConvertFrom-Raw([byte[]]$Raw) {
        if ($Cfg.CsParse) { return [WebInv.Html]::Parse($Raw) }
        $o = @{ IsHttp = $false; Code = 0; Headers = @{}; List = (New-Object System.Collections.Generic.List[object]); Body = [byte[]]@(); Text = ''; Banner = '' }
        if ($Raw -and $Raw.Length -ge 5 -and $Raw[0] -eq 72 -and $Raw[1] -eq 84 -and $Raw[2] -eq 84 -and $Raw[3] -eq 80 -and $Raw[4] -eq 47) {
            $head = $null
            $o.Body = [WebInv.Net]::Body($Raw, [ref]$head)
            $lines = $head -split "`r?`n"
            $o.IsHttp = $true
            if ($lines[0] -match '^HTTP/\d(?:\.\d)?\s+(\d{3})') { $o.Code = [int]$Matches[1] }
            for ($i = 1; $i -lt $lines.Count; $i++) {
                $l = $lines[$i]; $ix = $l.IndexOf(':')
                if ($ix -le 0) { continue }
                $k = $l.Substring(0, $ix).Trim().ToLowerInvariant(); $v = $l.Substring($ix + 1).Trim()
                [void]$o.List.Add(@($k, $v))
                if ($o.Headers.ContainsKey($k)) { $o.Headers[$k] = $o.Headers[$k] + "`n" + $v } else { $o.Headers[$k] = $v }
            }
            $o.Text = Get-BodyText $o.Body ([string]$o.Headers['content-type'])
        }
        elseif ($Raw -and $Raw.Length -gt 0) { $o.Banner = [WebInv.Util]::BannerText($Raw, 512) }
        $o
    }
    function Invoke-Fetch([bool]$Tls, [string]$Method, [string]$Path, [string]$HostHdr, [string]$Ip, [int]$Port, [string]$Sni, [int]$BannerWait) {
        Wait-Pace
        $stats.Requests++
        $r = [WebInv.Net]::Probe($Ip, $Port, $Tls, $Sni, (New-Req $Method $Path $HostHdr), $Cfg.TimeoutMs, $Cfg.MaxBodyBytes, $Cfg.SslProto, $BannerWait)
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
    function Get-Title([string]$Html) {
        if ($Cfg.CsParse) { return [WebInv.Html]::Title($Html) }
        if ($Html -match '(?is)<title[^>]*>(.*?)</title>') {
            $t = [Net.WebUtility]::HtmlDecode(($Matches[1] -replace '\s+', ' ').Trim())
            if ($t.Length -gt 200) { $t = $t.Substring(0, 200) }
            return $t
        }
        ''
    }
    function Get-MetaPairs([string]$Html) {
        $out = New-Object System.Collections.Generic.List[object]
        $n = 0
        foreach ($m in [regex]::Matches($Html, '(?is)<meta\s[^>]*>')) {
            if (++$n -gt 64) { break }
            $tag = $m.Value
            $nm = [regex]::Match($tag, '(?is)\b(?:name|property|http-equiv)\s*=\s*(?:"([^"]*)"|''([^'']*)''|([^\s>]+))')
            $ct = [regex]::Match($tag, '(?is)\bcontent\s*=\s*(?:"([^"]*)"|''([^'']*)''|([^\s>]+))')
            if (-not $nm.Success -or -not $ct.Success) { continue }
            $name = ($nm.Groups[1].Value + $nm.Groups[2].Value + $nm.Groups[3].Value).ToLowerInvariant()
            $content = [Net.WebUtility]::HtmlDecode($ct.Groups[1].Value + $ct.Groups[2].Value + $ct.Groups[3].Value)
            [void]$out.Add(@($name, $content))
        }
        , $out.ToArray()
    }
    function Get-ScriptSrcs([string]$Html) {
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($Html, '(?is)<script[^>]+\bsrc\s*=\s*["'']?([^"''\s>]+)')) { if ($out.Count -ge 64) { break }; [void]$out.Add($m.Groups[1].Value) }
        , $out.ToArray()
    }
    function Add-HeaderObs($Obs, [string]$Prefix, [string]$Name, [string]$Value) {
        if ($Cfg.CsParse) { [WebInv.Html]::AddHeader($Obs, $Prefix, $Name, $Value); return }
        $Obs.Add(('{0}header:{1}' -f $Prefix, $Name), $Value)
        if ($Name -eq 'set-cookie') {
            $Obs.Add(('{0}setcookie' -f $Prefix), $Value)
            $nv = ($Value -split ';')[0]; $eq = $nv.IndexOf('=')
            if ($eq -gt 0) {
                $cn = $nv.Substring(0, $eq).Trim()
                $Obs.Add(('{0}cookiename' -f $Prefix), $cn)
                $Obs.Add(('{0}cookie:{1}' -f $Prefix, $cn.ToLowerInvariant()), $nv.Substring($eq + 1))
            }
        }
        elseif ($Name -eq 'www-authenticate') { $Obs.Add(('{0}auth' -f $Prefix), $Value) }
    }
    function Add-BodyObs($Obs, [string]$Prefix, $Resp) {
        if ($Cfg.CsParse) { [WebInv.Html]::AddBody($Obs, $Prefix, $Resp); return }
        $Obs.Add(('{0}status' -f $Prefix), [string]$Resp.Code)
        foreach ($h in $Resp.List) { Add-HeaderObs $Obs $Prefix $h[0] $h[1] }
        $text = $Resp.Text
        if ($text) {
            $Obs.Add(('{0}body' -f $Prefix), $text)
            $t = Get-Title $text; if ($t) { $Obs.Add(('{0}title' -f $Prefix), $t) }
        }
    }

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
        if ($Cfg.CsParse) { $Row.Title = $fin.Resp.Title; $metas = $fin.Resp.Metas } else { $Row.Title = Get-Title $text; $metas = Get-MetaPairs $text }
        foreach ($mp in $metas) { if ($mp[0] -eq 'generator') { $Row.Generator = $mp[1]; break } }
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
        if ($Cfg.CsParse) {
            $hr = [WebInv.HttpResp[]]@(foreach ($hop in $Web.Hops) { $hop.Resp })
            [WebInv.Html]::AddWeb($Obs, $hr, [string[]]@($Web.Locations), [string]$Web.FinalUrl)
            return
        }
        foreach ($hop in $Web.Hops) { foreach ($pair in $hop.Resp.List) { Add-HeaderObs $Obs '' $pair[0] $pair[1] } }
        foreach ($l in $Web.Locations) { $Obs.Add('location', $l) }
        $fin = $Web.Final
        $Obs.Add('status', [string]$fin.Resp.Code)
        $Obs.Add('url', $Web.FinalUrl)
        $text = $fin.Resp.Text
        if ($text) {
            $Obs.Add('body', $text)
            $t = Get-Title $text; if ($t) { $Obs.Add('title', $t) }
            foreach ($mp in (Get-MetaPairs $text)) { $Obs.Add(('meta:{0}' -f $mp[0]), $mp[1]) }
            foreach ($s in (Get-ScriptSrcs $text)) { $Obs.Add('scriptsrc', $s) }
        }
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
    $result = @{ State = 'error'; Rows = $rows; Logs = $logs; Errors = $errs; Requests = 0; Ms = 0 }
    $swJob = [Diagnostics.Stopwatch]::StartNew()
    try {
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
        if ($state -ne 'open') { return $result }

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
        $silent = ($Cfg.SilentParallel -and $order.Count -ge 2 -and $silentN -eq $order.Count)
        if ($silent) { Add-Log 'silent listener (no bytes to HTTP or TLS before timeout); raw TLS probes sent in parallel' }
        if (-not $Cfg.NoTlsScan -and -not $serverFirst -and -not $plainWeb -and (($sch -and $sch.TlsOk) -or $tlsHsFail)) {
            Wait-Pace
            $rawTls = [WebInv.Tls]::Scan($J.Ip, $J.Port, $J.Host, $Cfg.TimeoutMs, $true, $silent)
            $stats.Requests += $rawTls.Probes
            if ($rawTls.Errors) { Add-Log ('tls-scan: {0}' -f $rawTls.Errors) }
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
        if ($Cfg.ReverseDns) {
            $ptr = $null
            if ($Cfg.RdnsCache.ContainsKey($J.Ip)) { $ptr = $Cfg.RdnsCache[$J.Ip] }
            else { $ptr = [WebInv.Net]::ReverseLookup($J.Ip, $Cfg.TimeoutMs); $Cfg.RdnsCache[$J.Ip] = $ptr }
            foreach ($r in $rows) { $r.ReverseDns = [string]$ptr }
        }
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
    'Flags', 'Advisories', 'Banner', 'Notes')

function ConvertTo-CsvField {
    param($Value)
    if ($null -eq $Value) { return '""' }
    $s = [string]$Value
    $s = $s -replace "[\r\n]+", ' '
    if (-not $NoCsvSanitize) { $s = [WebInv.Util]::CsvSafe($s) }
    '"' + $s.Replace('"', '""') + '"'
}

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
    param($Row)
    if ($script:CsWriter) {
        $n = $Columns.Count
        $cv = New-Object object[] $n
        for ($i = 0; $i -lt $n; $i++) { $cv[$i] = $Row[$Columns[$i]] }
        $jv = New-Object object[] ($n + 1)
        [Array]::Copy($cv, $jv, $n)
        $jv[$n] = [object[]]@($Row['_Detections'])
        $script:CsvW.WriteLine([WebInv.Out]::CsvLine($cv, -not $NoCsvSanitize))
        $script:JsonW.WriteLine([WebInv.Out]::JsonLine($script:JsonNames, $jv))
        return
    }
    $vals = foreach ($c in $Columns) { ConvertTo-CsvField $Row[$c] }
    $script:CsvW.WriteLine(($vals -join ','))
    $o = [ordered]@{}
    foreach ($c in $Columns) { $o[$c] = $Row[$c] }
    $o['Detections'] = @($Row['_Detections'])
    $script:JsonW.WriteLine(([pscustomobject]$o | ConvertTo-Json -Compress -Depth 5))
}

function Write-Hit {
    param($Row)
    if ($Quiet) { return }
    $P = { param($s, $n) [WebInv.Util]::Printable([string]$s, $n) }
    $tag = '[+]'; $tagColor = 'Green'
    if (-not $Row.IsWeb) { if ($Row._SchannelIncompatible) { $tag = '[!]'; $tagColor = 'Yellow' } else { $tag = '[~]'; $tagColor = 'DarkYellow' } }
    $host_ = if ($Row.Vhost) { '{0} (vhost of {1})' -f $Row.Host, $Row.VhostOf } else { '' }
    $tls = ''
    if ($Row.TlsVersion -or $Row.TlsSupported) {
        $cn = if ($Row.CertSubject -match 'CN=([^,]+)') { $Matches[1] } else { '' }
        $v = if ($Row.TlsVersion) { $Row.TlsVersion } else { 'raw:' + $Row.TlsSupported }
        $tls = ' [{0}{1} {2} {3}d]' -f $v, $(if ($Row.Http2 -eq $true) { ' h2' } else { '' }), (& $P $cn 40), $Row.CertDaysLeft
    }
    $main = if ($Row.IsWeb) {
        '{0} [{1}] [{2}] [{3}] [{4}]' -f $Row.Url, $Row.StatusCode, (& $P $Row.Server 60), (& $P $Row.Title 70), (& $P $Row.Products 120)
    } else {
        '{0} [{1}] [{2}] [{3}]' -f $Row.Url, $Row.Service, (& $P $Row.Products 100), (& $P $Row.Banner 80)
    }
    Write-Host ($tag + ' ') -ForegroundColor $tagColor -NoNewline
    Write-Host ($main + $tls + $(if ($host_) { " $host_" } else { '' })) -NoNewline
    if ($Row.Flags) {
        $crit = $Row.Flags -match 'CertExpired|WeakCipher|CleartextAuth|ADCSWebEnrollment|DirectoryListing|PhpInfoExposed|SchannelIncompatible|WeakTLS:SSL3|PHP2Shell:(?:vulnerable|eol)'
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
        $lines.Add(('{0}  {1}  {2}' -f [WebInv.Hash]::Sha256Hex($b), $b.Length, (Split-Path -Leaf $f)))
    }
    [IO.File]::WriteAllLines($Path, $lines.ToArray(), $script:Utf8NoBom)
}
#endregion

#region ---------- Self-contained HTML report (offline; no external fonts/scripts) ----------
function New-HtmlReport {
    param([string]$CsvFile, [string]$HtmlFile, [hashtable]$Meta)
    $rows = @(Import-Csv -LiteralPath $CsvFile)
    $data = @($rows | ForEach-Object {
            [ordered]@{ u = $_.Url; h = $_.Host; ip = $_.IP; p = $_.Port; sv = $_.Service; w = $_.IsWeb; s = $_.StatusCode; t = $_.Title; srv = $_.Server
                pr = $_.Products; c = $_.Categories; os = $_.OsHint; hw = $_.Hardware; tls = $_.TlsVersion; tsup = $_.TlsSupported; h2 = $_.Http2
                cd = $_.CertDaysLeft; cs = $_.CertSubject; ci = $_.CertIssuer; san = $_.CertSANs; f = $_.Flags; fav = $_.FaviconMmh3; cpe = $_.CPEs
                vh = $_.VhostOf; rd = $_.ReverseDns; au = $_.Auth; fu = $_.FinalUrl; rc = $_.RedirectChain; b = $_.Banner; n = $_.Notes; adv = $_.Advisories } })
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
tr.onclick=function(){var n=tr.nextSibling;if(n&&n.className==='d'){n.remove();return}var dr=el('tr','d'),td=el('td');td.colSpan=7;var lines=[['Host',r.h],['IP',r.ip],['Port',r.p],['Reverse DNS',r.rd],['Service',r.sv],['Final URL',r.fu],['Redirects',r.rc],['Server',r.srv],['Auth',r.au],['Categories',r.c],['OS hint',r.os],['Hardware',r.hw],['CPEs',r.cpe],['TLS supported',r.tsup],['Cert subject',r.cs],['Cert issuer',r.ci],['SANs',r.san],['Favicon mmh3',r.fav],['Advisories',r.adv],['Banner',r.b],['Notes',r.n]].filter(function(x){return x[1]}).map(function(x){return x[0]+': '+x[1]}).join('\n');td.appendChild(el('pre',null,lines));dr.appendChild(td);tr.parentNode.insertBefore(dr,tr.nextSibling)};
tb.appendChild(tr)})}
Array.prototype.forEach.call(document.querySelectorAll('th'),function(th){th.onclick=function(){var k=th.getAttribute('data-k');if(sortK===k)sortD=-sortD;else{sortK=k;sortD=1}render()}});
q.oninput=render;sv.onchange=render;
document.getElementById('th').onclick=function(){var r=document.documentElement,c=r.getAttribute('data-theme');r.setAttribute('data-theme',c==='dark'?'light':(c==='light'?'dark':(matchMedia('(prefers-color-scheme: dark)').matches?'light':'dark')))};
render()})();
</script></body></html>
'@
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
$paramDump = foreach ($k in ($MyInvocation.MyCommand.Parameters.Keys | Sort-Object)) {
    if (@('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'ProgressAction', 'WhatIf', 'Confirm') -contains $k) { continue }
    $v = Get-Variable -Name $k -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $v -or "$v" -eq '' -or ($v -is [switch] -and -not $v)) { continue }
    '{0}={1}{2}' -f $k, (@($v) -join ','), $(if ($Explicit.Contains($k)) { '' } else { '(default)' })
}
Write-RunLog ('Effective parameters: ' + ($paramDump -join '; '))

# ---------- utility modes that need no targets ----------
if ($ImportRules) {
    try { Invoke-ImportRules } catch { Stop-Fatal "Rule import failed: $($_.Exception.Message)" }
    Close-Logs; exit $script:ExitCode
}
Initialize-Rules
if ($SelfTest) { Invoke-SelfTest; Close-Logs; exit $script:ExitCode }
if ($ExportRules) {
    [IO.File]::WriteAllText($ExportRules, $BuiltinRulesJson, $script:Utf8NoBom)
    Write-Host "Embedded rule pack written to $ExportRules (edit, rename to WebInventory.rules.<name>.json, keep next to the script)" -ForegroundColor Cyan
    Close-Logs; exit 0
}
if ($TestRules) { Invoke-TestRules; Close-Logs; exit $script:ExitCode }

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
# A/B switches for the performance suite (tests/perf): WEBINV_PERF_OFF=prefilter,sched,silence,parse,writer,dns,warmup,ramp,jobs,connect
$script:PerfOff = @(([string]$env:WEBINV_PERF_OFF).Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
if ($script:PerfOff.Count) { Write-RunLog ('Performance features disabled for benchmarking: ' + ($script:PerfOff -join ',')) 'WARN' }
[WebInv.Matcher]::Prefilter = ($script:PerfOff -notcontains 'prefilter')
[WebInv.Net]::SlidingDns = ($script:PerfOff -notcontains 'dns')
[WebInv.Net]::SelectConnect = ($script:PerfOff -notcontains 'connect')
$script:CsWriter = ($script:PerfOff -notcontains 'writer')
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
if ($script:PerfOff -notcontains 'jobs') {
    $jb = [WebInv.JobBuilder]::new($ExSet, $ScopeSet, $resolved, [bool]$AllAddresses)
    foreach ($p in $parsed) { $jb.Add($p.Spec.Ranges, $p.Spec.Names, [int[]]@($p.Ports), [string]$p.Scheme, [string]$p.Src) }
    $Jobs = $jb.Jobs; $hostSet = $jb.Hosts; $excludedCount = $jb.Excluded; $outOfScope = $jb.OutOfScope
}
else {
$Jobs = New-Object System.Collections.Generic.List[string]
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$hostSet = New-Object 'System.Collections.Generic.HashSet[string]'
$excludedCount = 0; $outOfScope = New-Object System.Collections.Generic.List[string]
foreach ($p in $parsed) {
    $pairs = New-Object System.Collections.Generic.List[object]
    foreach ($rg in $p.Spec.Ranges) { for ($n = $rg[0]; $n -le $rg[1]; $n++) { $ip = [WebInv.Util]::Ip4ToString($n); $pairs.Add(@($ip, $ip)) } }
    foreach ($nm in $p.Spec.Names) {
        $tmp = $null
        if ([Net.IPAddress]::TryParse($nm, [ref]$tmp)) { $pairs.Add(@($nm, $tmp.ToString())); continue }
        if ($ExSet.ContainsName($nm)) { $excludedCount++; continue }
        if (-not $resolved.ContainsKey($nm)) { continue }
        $addrs = @($resolved[$nm])
        $v4 = @($addrs | Where-Object { $_ -notmatch ':' })
        $pick = if ($AllAddresses) { $addrs } elseif ($v4.Count) { @($v4[0]) } else { @($addrs[0]) }
        foreach ($a in $pick) { $pairs.Add(@($nm, $a)) }
    }
    $keep = New-Object System.Collections.Generic.List[object]
    foreach ($pr in $pairs) {
        if ($ExSet.Contains($pr[1], $pr[0])) { $excludedCount++; continue }
        if (-not $ScopeSet.IsEmpty -and -not $ScopeSet.Contains($pr[1], $pr[0])) { $outOfScope.Add(('{0} ({1}) from {2}' -f $pr[0], $pr[1], $p.Src)); continue }
        $keep.Add($pr)
    }
    foreach ($port in $p.Ports) {
        foreach ($pr in $keep) {
            $key = '{0}|{1}|{2}' -f $pr[0], $pr[1], $port
            if ($seen.Add($key)) { $Jobs.Add(("{0}`t{1}`t{2}`t{3}" -f $pr[0], $pr[1], $port, $p.Scheme)); [void]$hostSet.Add($pr[1]) }
        }
    }
}
}
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
    CsParse = ($script:PerfOff -notcontains 'parse'); SilentParallel = ($script:PerfOff -notcontains 'silence')
}
$ops = 3 + $Retries + 7 + $MaxRedirects + 5 + $(if ($Options) { 1 } else { 0 }) + $(if ($IdentifyPaths) { $IdentifyPathList.Count } else { 0 }) + $(if ($ProbeSans) { $MaxSans * (2 + $MaxRedirects) } else { 0 })
$budgetMs = [long]$ops * ($TimeoutMs * 3 + $DelayMs + $JitterMs + $BannerWaitMs) + 30000
$banner = "WebInventory v{0}: {1} checks across {2} hosts ({3} excluded{4}). Pace={5} threads={6} per-host={7} timeout={8}ms. Authorised scope only." -f $ScriptVersion, $Jobs.Count, $hostSet.Count, $excludedCount, $(if ($ScopeSet.IsEmpty) { ', no -Scope set' } else { ', scope enforced' }), $Pace, $Threads, $MaxPerHost, $TimeoutMs
Write-RunLog $banner; Write-RunLog ("Outputs: {0} ; {1} ; {2}; watchdog budget {3} ms per check" -f $script:CsvPath, $script:JsonlPath, $script:ProgressPath, $budgetMs)
if (-not $Quiet) { Write-Host $banner -ForegroundColor Cyan }

if ($script:PerfOff -notcontains 'warmup') { Write-RunLog ("TLS/chain engine warm-up: {0} ms" -f [WebInv.Net]::WarmUp([Convert]::FromBase64String($script:SelfTestCertB64))) 'DEBUG' }

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
$workerText = $WorkerScript.ToString()
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
        if ($row.IsWeb -or $row._SchannelIncompatible -or $ShowNonWeb) { Write-Hit $row }
        if ($PassThru) { $o = [ordered]@{}; foreach ($c in $Columns) { $o[$c] = $row[$c] }; [pscustomobject]$o }
    }
    if ($Res.State -ne 'error') { $p = $JobLine.Split("`t"); $script:ProgW.WriteLine(('{0}|{1}|{2}' -f $p[0], $p[1], $p[2])) }
}

function Receive-Results {
    while ($null -ne ($item = $sched.NextResult())) { Complete-Result $item[0] $item[1]; $script:doneCount++ }
}

try {
  if ($script:PerfOff -contains 'sched') {
    # v2.0.2 dispatch model (benchmark A/B only): one PowerShell instance per check, 20 ms polling
    $queue = New-Object 'System.Collections.Generic.Queue[string]'; foreach ($j in $Jobs) { $queue.Enqueue($j) }
    $inflight = New-Object System.Collections.Generic.List[object]; $perHost = @{}
    while ($queue.Count -gt 0 -or $inflight.Count -gt 0) {
        $scan = 0; $limit = $queue.Count
        while ($inflight.Count -lt $Threads -and $queue.Count -gt 0 -and $scan -lt $limit) {
            $j = $queue.Dequeue(); $scan++
            $ip = $j.Split("`t")[1]
            $n = if ($perHost.ContainsKey($ip)) { $perHost[$ip] } else { 0 }
            if ($n -ge $MaxPerHost) { $queue.Enqueue($j); continue }
            $perHost[$ip] = $n + 1
            $one = [WebInv.Sched]::new([string[]]@($j), 64, 1)
            $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
            [void]$ps.AddScript($workerText).AddArgument($one).AddArgument($Cfg).AddArgument(0)
            $inflight.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Job = $j; Ip = $ip; One = $one })
        }
        $done = New-Object System.Collections.Generic.List[object]
        foreach ($x in $inflight) { if ($x.Handle.IsCompleted) { $done.Add($x) } }
        if ($done.Count -eq 0) { Start-Sleep -Milliseconds 20 }
        foreach ($d in $done) {
            try { [void]$d.PS.EndInvoke($d.Handle) } catch { }
            $item = $d.One.NextResult()
            if ($null -ne $item) { Complete-Result $item[0] $item[1] } else { $counts.error++ }
            $doneCount++
            try { $d.PS.Dispose() } catch { }
            $perHost[$d.Ip] = $perHost[$d.Ip] - 1
            [void]$inflight.Remove($d)
        }
    }
    $workers.Clear()
  }
  else {
    # slow start: 8 workers, +8 every 100 ms, so runspace creation and the first TLS handshakes do not all collide
    $wantWorkers = [Math]::Min($Threads, $total); $nextId = 0
    $ramp = ($script:PerfOff -notcontains 'ramp')
    while ($true) {
        if ($nextId -lt $wantWorkers -and -not $sched.Stopped -and $sched.Queued -gt 0) {
            $allowed = if ($ramp) { [Math]::Min($wantWorkers, 8 + 8 * [int][Math]::Floor($sw.ElapsedMilliseconds / 100)) } else { $wantWorkers }
            while ($nextId -lt $allowed) { $workers.Add((Start-Worker $nextId)); $nextId++ }
        }
        [void]$sched.Wait($(if ($nextId -lt $wantWorkers) { 50 } else { 250 }))
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
        if ($workers.Count -eq 0 -and ($nextId -ge $wantWorkers -or $sched.Stopped -or $sched.Queued -eq 0)) {
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
    if (-not $NoHtml) {
        try {
            $script:HtmlPath = Join-Path $OutputDir ("WebInventory_{0}.html" -f $script:RunId)
            $meta = @{ RunId = $script:RunId; Tag = [string]$Tag; Started = $script:ScriptStart.ToString('yyyy-MM-dd HH:mm'); Duration = ('{0:hh\:mm\:ss}' -f $elapsed); Operator = $script:Operator; Computer = [Environment]::MachineName; Version = $ScriptVersion }
            New-HtmlReport -CsvFile $script:CsvPath -HtmlFile $script:HtmlPath -Meta $meta
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
    $errSummary = if ($script:ErrTotal) { ($script:ErrCounts.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join ' ' } else { 'none' }
    $summary = "{0} in {1:hh\:mm\:ss}: {2}/{3} checks; web={4} open={5} closed={6} filtered={7} worker-errors={8}; rows={9}; requests={10}; rule-regex-timeouts={11}; logged errors: {12}" -f $(if ($interrupted) { 'INTERRUPTED' } elseif ($script:TimeLimitHit) { 'TIME LIMIT' } else { 'Done' }), $elapsed, $doneCount, $total, $counts.web, $counts.open, $counts.closed, $counts.filtered, $counts.error, $counts.rows, $counts.requests, [WebInv.Matcher]::Timeouts, $errSummary
    Write-RunLog $summary
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
}
exit $script:ExitCode
#endregion
