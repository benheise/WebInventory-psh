
#region ---------- Extras: opt-in probes and screenshots (compiled only when a run uses one of them) ----------
$ExtrasSource = @'
__EXTRAS_CS__
'@

function Initialize-Extras {
    if ('WebInv.Extras' -as [type]) {
        if ([WebInv.Extras]::Version -ne $ScriptVersion) { throw ("WebInv extras v{0} are already loaded in this PowerShell session (script is v{1}). Open a new PowerShell window." -f [WebInv.Extras]::Version, $ScriptVersion) }
    }
    else {
        $swc = [Diagnostics.Stopwatch]::StartNew()
        $addType = @{ TypeDefinition = $ExtrasSource; ErrorAction = 'Stop'; IgnoreWarnings = $true }   # see the engine compile
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
    $script:ShotMeta = @{}
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
            if ($prev.ContainsKey($r.Url)) {
                # an image a previous session of this run took (resumed run); index files before v2.5 lack the newer columns
                $pv = $prev[$r.Url]
                $o = [ordered]@{}; foreach ($c in 'Url', 'Host', 'IP', 'Port', 'File', 'Sha256', 'Bytes', 'Status', 'Reason', 'PageTitle', 'PageRequests', 'BlockedOrigins', 'ProxyRefused', 'Ms', 'BrowserUrl', 'BrowserStatus', 'Capture') { $o[$c] = [string]$pv.$c }
                $out.Add([pscustomobject]$o); $index[$r.Url] = ($pv.File -replace '\\', '/'); $script:ShotMeta[[string]$r.Url] = @('ok', [string]$pv.Reason)
                continue
            }
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
                $sha = ''; $bytes = 0; $img = $null
                if ($status -like 'ok*' -and (Test-Path -LiteralPath $j.File)) { $b = [IO.File]::ReadAllBytes($j.File); $bytes = $b.Length; $sha = [WebInv.Hash]::Sha256Hex($b); $img = [WebInv.Png]::Analyze($b) }
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
                # does the image show this service? (the page the browser ended on, its HTTP status, pixels, title)
                # the page the main document came from (MainUrl; location.href is chrome-error://... on the browser's error page)
                $fin = [string]$j.Cap.FinalUrl
                $land = if ($j.Cap.MainUrl -match '^https?://') { [string]$j.Cap.MainUrl } else { $fin }
                $landIn = $true
                if ($land -match '^https?://') { try { $lu = [Uri]$land; $landIn = $allow.ContainsKey(('{0}:{1}' -f $lu.Host.Trim('[', ']'), $lu.Port).ToLowerInvariant()) } catch { $landIn = $true } }
                $cls = [WebInv.ShotCheck]::Classify([string]$status, [bool]$bytes, $img, [string]$j.Q.Row.Title, [string]$j.Cap.Title, [string]$j.Q.Row.StatusCode, [int]$j.Cap.MainStatus, $(if ($landIn) { $fin } else { $land }), $landIn, [string]$j.Q.Row.BodyLength, ($denied.ToArray() -join ';'), [int]$j.Cap.TextLength)
                $out.Add([pscustomobject][ordered]@{ Url = $j.Q.Row.Url; Host = $j.Q.Row.Host; IP = $j.Q.Row.IP; Port = $j.Q.Row.Port
                        File = $(if ($bytes) { '{0}/{1}' -f $folderName, $j.Q.Name } else { '' }); Sha256 = $sha; Bytes = $bytes; Status = $cls[0]; Reason = [WebInv.Util]::Printable($cls[1], 400)
                        PageTitle = [WebInv.Util]::Printable($j.Cap.Title, 200); PageRequests = $pageReq; BlockedOrigins = ($denied.ToArray() -join ';'); ProxyRefused = $j.Proxy.Denied; Ms = $j.Sw.ElapsedMilliseconds
                        BrowserUrl = [WebInv.Util]::Printable($fin, 400); BrowserStatus = $(if ($j.Cap.MainStatus -gt 0) { $j.Cap.MainStatus } else { '' }); Capture = $status
                    })
                if ($bytes) { $index[$j.Q.Row.Url] = '{0}/{1}' -f $folderName, $j.Q.Name }
                $script:ShotMeta[[string]$j.Q.Row.Url] = @($cls[0], [string]$cls[1])
                if ($status -notlike 'ok*') { Write-ErrLog 'SCREENSHOT' $j.Q.Row.Url $status }
                elseif ($cls[0] -ne 'ok') { Write-RunLog ("screenshot {0}: {1} - {2}" -f $j.Q.Row.Url, $cls[0], $cls[1]) 'WARN' }
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
        # the same image for pages the scan saw with different titles: a shared error or proxy page, not each service
        $titleOf = @{}; foreach ($r in $rows) { $titleOf[[string]$r.Url] = ([string]$r.Title).ToLowerInvariant() -replace '[^\p{L}\p{N}]', '' }
        foreach ($g in @($out | Where-Object { $_.Sha256 } | Group-Object Sha256 | Where-Object { $_.Count -gt 1 })) {
            $titles = @($g.Group | ForEach-Object { $titleOf[[string]$_.Url] } | Where-Object { $_ } | Sort-Object -Unique)
            if ($titles.Count -lt 2) { continue }
            foreach ($o in $g.Group) {
                if ($o.Status -ne 'ok') { continue }
                $others = @($g.Group | Where-Object { $_.Url -ne $o.Url } | ForEach-Object { $_.Url })
                $o.Status = 'suspect'; $o.Reason = [WebInv.Util]::Printable(('the same image as {0}, whose page the scan saw with a different title' -f ($others -join ', ')), 400)
                $script:ShotMeta[[string]$o.Url] = @($o.Status, $o.Reason)
                Write-RunLog ("screenshot {0}: suspect - {1}" -f $o.Url, $o.Reason) 'WARN'
            }
        }
        if ($out.Count) {
            $lines = @($out | Sort-Object { [string]$_.File } | ConvertTo-Csv -NoTypeInformation)
            [IO.File]::WriteAllLines($script:ShotIndexPath, [string[]]$lines, $script:Utf8Bom)
        }
    }
    $ok = @($out | Where-Object { $_.Status -eq 'ok' }).Count
    $cnt = @{}; foreach ($o in $out) { $cnt[$o.Status] = 1 + [int]$cnt[$o.Status] }
    $msg = 'Screenshots: {0} of {1} web services captured and checked (ok {2}, blank {3}, suspect {4}, failed {5}) -> {6}' -f @($out | Where-Object { $_.Bytes }).Count, $rows.Count, $ok, [int]$cnt['blank'], [int]$cnt['suspect'], [int]$cnt['failed'], $folder
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
    # -Cname: the UDP path end to end against a loopback responder (name compression, NXDOMAIN, silence)
    Assert 'extras: CNAME chain over UDP (loopback DNS responder: chain, no CNAME, not in DNS, no answer)' {
        $tab = New-Object 'System.Collections.Generic.Dictionary[string,string[]]'
        $tab['www.example.test'] = [string[]]@('edge.example.net', 'lb7.cdn.example'); $tab['plain.example.test'] = [string[]]@(); $tab['quiet.example.test'] = [string[]]@('SILENT')
        $rsp = [WebInv.DnsTestResponder]::new($tab)
        try {
            $srv = "127.0.0.1:$($rsp.Port)"; $e1 = $null; $e2 = $null; $e3 = $null; $e4 = $null
            $c1 = [WebInv.Cname]::Chain('www.example.test', $srv, 1500, [ref]$e1)
            $c2 = [WebInv.Cname]::Chain('plain.example.test', $srv, 1500, [ref]$e2)
            $c3 = [WebInv.Cname]::Chain('missing.example.test', $srv, 1500, [ref]$e3)
            $c4 = [WebInv.Cname]::Chain('quiet.example.test', $srv, 600, [ref]$e4)
            $me = New-Object 'System.Collections.Generic.Dictionary[string,string]'
            $m = [WebInv.Cname]::Many([string[]]@('www.example.test', 'plain.example.test', 'missing.example.test'), $srv, 1500, 4, $me)
            ((@($c1) -join '>') -eq 'edge.example.net>lb7.cdn.example') -and $null -eq $e1 -and @($c2).Count -eq 0 -and $null -ne $c2 -and $null -eq $e2 -and
            $null -ne $c3 -and @($c3).Count -eq 0 -and $null -eq $e3 -and $null -eq $c4 -and $e4 -like '*no answer*' -and
            $m['www.example.test'] -eq 'edge.example.net;lb7.cdn.example' -and $m['plain.example.test'] -eq '' -and $m['missing.example.test'] -eq '' -and $me.Count -eq 0
        }
        finally { $rsp.Dispose() }
    }
    Assert 'extras: DNS message parsing (query layout, pointer loop refused, chain order from unordered records)' {
        $q = [WebInv.Cname]::BuildQuery(0x1234, 'a.bc', 1)
        $loop = [byte[]]@(0x12, 0x34, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, 2, 0xC0, 12)
        $rc = 0; $tc = $false; $er = $null
        $pl = [WebInv.Cname]::Parse($loop, [ref]$rc, [ref]$tc, [ref]$er)
        $recs = New-Object 'System.Collections.Generic.List[string[]]'
        $recs.Add([string[]]@('b.example.', 'c.example.')); $recs.Add([string[]]@('A.example', 'b.example')); $recs.Add([string[]]@('c.example', 'd.example'))
        ((($q | ForEach-Object { '{0:x2}' -f $_ }) -join '') -eq '123401000001000000000000016102626300000100 01'.Replace(' ', '')) -and
        $null -eq $pl -and $er -like '*malformed*' -and ((@([WebInv.Cname]::Follow($recs)) -join '>') -eq 'b.example>c.example>d.example') -and
        ([WebInv.Cname]::ParseServer('[::1]:5353').Port -eq 5353) -and ([WebInv.Cname]::ParseServer('2001:db8::53').Port -eq 53)
    }
    # -Screenshot checks: PNG decoding (every filter type), one-colour detection, and the classification rules
    Assert 'extras: PNG decoder (all five filter types round-trip) and one-colour share' {
        $w = 37; $h = 23; $rgb = New-Object byte[] ($w * $h * 3)
        for ($i = 0; $i -lt $rgb.Length; $i++) { $rgb[$i] = [byte](($i * 7 + [Math]::Floor($i / 111) * 13) % 256) }
        $png = [WebInv.Png]::Encode($w, $h, $rgb)
        $px = $null; $pw = 0; $ph = 0; $bpp = 0
        $ok = [WebInv.Png]::Decode($png, [ref]$px, [ref]$pw, [ref]$ph, [ref]$bpp)
        $same = $ok -and $pw -eq $w -and $ph -eq $h -and $bpp -eq 3 -and ([BitConverter]::ToString($px) -eq [BitConverter]::ToString($rgb))
        $white = New-Object byte[] (64 * 48 * 3); for ($i = 0; $i -lt $white.Length; $i++) { $white[$i] = 255 }
        $aw = [WebInv.Png]::Analyze([WebInv.Png]::Encode(64, 48, $white))
        for ($i = 0; $i -lt 300; $i++) { $white[$i] = 0 }
        $ad = [WebInv.Png]::Analyze([WebInv.Png]::Encode(64, 48, $white))
        $same -and $aw[2] -eq 1000 -and $aw[3] -eq 0xffffff -and $ad[2] -lt 995 -and $null -eq [WebInv.Png]::Analyze([byte[]]@(1, 2, 3))
    }
    Assert 'extras: screenshot classification (failed, off-scope, browser error page, blank, suspect, ok)' {
        $one = [int[]]@(1366, 768, 1000, 0xffffff, 1); $mostly = [int[]]@(1366, 768, 997, 0xffffff, 40); $busy = [int[]]@(1366, 768, 610, 0xffffff, 300)
        $k = { param($cap, $has, $img, $st, $bt, $ss, $bs, $fu, $fin, $bl, $blk, $tl) [WebInv.ShotCheck]::Classify($cap, $has, $img, $st, $bt, $ss, $bs, $fu, $fin, $bl, $blk, $tl) }
        $r1 = & $k 'failed: net::ERR_BLOCKED_BY_CLIENT' $false $null 'A' '' '302' 0 '' $true '0' 'login.example.com:80' -1
        $r2 = & $k 'ok' $true $busy 'App' '' '200' 403 'https://login.example.com/' $false '10' '' -1
        $r3 = & $k 'ok' $true $busy 'App' '' '200' 403 'chrome-error://chromewebdata/' $true '10' '' -1
        $r4 = & $k 'ok' $true $one '' '' '200' 200 'http://h/' $true '0' '' 0
        $r5 = & $k 'ok' $true $one 'App' 'App' '200' 200 'http://h/' $true '512' 'cdn.example.org:80;x.example:443;y.example:443' 0
        $r6 = & $k 'ok' $true $mostly 'App' 'App' '200' 503 'http://h/' $true '512' '' 0
        $r7 = & $k 'ok' $true $busy 'Grafana' 'Proxy Error' '200' 200 'http://h/' $true '512' '' 9
        $r8 = & $k 'ok' $true $busy 'Grafana' 'Home - Grafana' '200' 200 'http://h/' $true '512' '' 9
        $r9 = & $k 'ok-timeout' $true $busy 'App' 'App' '200' 200 'http://h/' $true '512' '' 9
        $r10 = & $k 'ok' $true $mostly 'It works' 'It works' '200' 200 'http://h/' $true '45' '' 8
        $r1[0] -eq 'failed' -and $r1[1] -like '*ERR_BLOCKED_BY_CLIENT*login.example.com:80*' -and $r2[0] -eq 'failed' -and $r2[1] -like '*https://login.example.com*outside*' -and
        $r3[0] -eq 'failed' -and $r3[1] -like '*own error page (HTTP 403)*' -and $r4[0] -eq 'blank' -and $r4[1] -like '*0-byte body*' -and
        $r5[0] -eq 'blank' -and $r5[1] -like '*#ffffff*' -and $r5[1] -like '*3 origins*' -and $r6[0] -eq 'suspect' -and $r6[1] -like '*HTTP 503*HTTP 200*one colour*' -and
        $r7[0] -eq 'suspect' -and $r7[1] -like "*'Proxy Error'*" -and $r8[0] -eq 'ok' -and $r9[0] -eq 'ok' -and $r9[1] -like '*load event*' -and $r10[0] -eq 'ok'
    }
}
#endregion
