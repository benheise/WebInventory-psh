
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
