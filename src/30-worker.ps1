
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

    function Complete-Row($Row, $Obs, $Dets) {
        # $Dets: an evaluation of exactly these observations (-VersionPaths already made one), else evaluated here
        $dets = if ($null -ne $Dets) { $Dets } else { [WebInv.Matcher]::Evaluate($Obs) }
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
        $preDets = $null
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
        # ---- 8b. optional version paths: the documented version URL of a product detected here without a version
        #          (after every observation of this row is in, so the evaluation can be handed to Complete-Row) ----
        if ($Cfg.VersionPaths -and $web) {
            $preDets = [WebInv.Matcher]::Evaluate($obs)
            $vp = [WebInv.Matcher]::VersionPaths($preDets, $Cfg.MinConfidence, 4)
            if ($vp.Length) {
                $hits = New-Object System.Collections.Generic.List[string]
                foreach ($p in $vp) {
                    if ($Cfg.IdentifyPaths -and $Cfg.PathList -contains $p) { continue }   # already requested and observed
                    $pr = Invoke-Fetch $oTls 'GET' $p $oHost $oIp $oPort $oSni 0
                    if (-not $pr.Resp.IsHttp) { continue }
                    if ($pr.Resp.Code -eq 200) { Add-BodyObs $obs ('path:{0}.' -f $p) $pr.Resp }
                    [void]$hits.Add(('{0}={1}' -f $p, $pr.Resp.Code))
                }
                $row.VersionPaths = ($hits -join ';')
                $preDets = $null   # the observations changed: Complete-Row evaluates again
            }
        }
        Complete-Row $row $obs $preDets
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
