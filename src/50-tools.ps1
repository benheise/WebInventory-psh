
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

# Cloud / CDN IP ranges (WebInventory.cloud.json next to the script, or -CloudFile): offline lookup of every service's IP.
# The companion file is loaded when the first service on a public address is found (internal scans never need it);
# a -CloudFile is loaded before the scan, so a bad file stops the run before anything is sent.
$script:CloudOn = $false; $script:CloudPending = $null; $script:CloudEnabled = $false
function Initialize-Cloud {
    [WebInv.Cloud]::Clear(); $script:CloudOn = $false; $script:CloudPending = $null; $script:CloudEnabled = $false
    if ($NoCloud) { Write-RunLog 'Cloud ranges: off (-NoCloud)'; return }
    $f = if ($CloudFile) { $CloudFile } elseif ($PSScriptRoot) { Join-Path $PSScriptRoot 'WebInventory.cloud.json' } else { $null }
    if (-not $f -or -not (Test-Path -LiteralPath $f -PathType Leaf)) {
        if ($CloudFile) { Stop-Fatal "Cloud ranges file not found: $CloudFile" }
        Write-RunLog 'Cloud ranges: WebInventory.cloud.json is not next to the script; the Cloud columns stay empty'
        return
    }
    $script:CloudPending = (Resolve-Path -LiteralPath $f).ProviderPath
    $script:CloudEnabled = $true
    if ($CloudFile) { Import-CloudRanges }
    else { Write-RunLog ("Cloud ranges: {0} (loaded when the first service on a public address answers)" -f $script:CloudPending) }
}

function Import-CloudRanges {
    $full = $script:CloudPending; $script:CloudPending = $null
    if (-not $full) { return }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $errs = New-Object 'System.Collections.Generic.List[string]'
    try {
        $bytes = [IO.File]::ReadAllBytes($full)
        $pack = [WebInv.Cloud]::Read([Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)); $n = [WebInv.Cloud]::Load($pack, $errs)
    }
    catch {
        $m = "cloud ranges could not be read: $($_.Exception.Message)"
        $script:CloudEnabled = $false
        if ($CloudFile) { Stop-Fatal "-CloudFile ${full}: $m" }
        Write-ErrLog 'CLOUD' $full $m; return
    }
    foreach ($e in $errs) { Write-ErrLog 'CLOUD' $full $e }
    $script:CloudOn = $n -gt 0
    if (-not $script:CloudOn) { $script:CloudEnabled = $false }
    Write-RunLog ("cloud ranges v{0}: {1} prefixes ({2} IPv4, {3} IPv6) sha256={4} file={5} ({6} ms)" -f $pack.Version, $n, @($pack.V4).Count, @($pack.V6).Count, [WebInv.Hash]::Sha256Hex($bytes), $full, $sw.ElapsedMilliseconds)
    $d = [datetime]::MinValue
    if ([datetime]::TryParseExact([string]$pack.Version, 'yyyy.MM.dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d) -and ((Get-Date) - $d).TotalDays -gt 45) {
        Write-RunLog ("cloud ranges are {0:0} days old (v{1}); providers move ranges often: refresh WebInventory.cloud.json" -f ((Get-Date) - $d).TotalDays, $pack.Version) 'WARN'
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
    # version-only outputs: they add a version to a product another rule detected, and nothing else
    $voPack = [WebInv.Matcher]::ReadPack('{"name":"votest","rules":[{"id":"st:vo-det","f":"selftest.det","r":"Acme","n":"ST Acme","c":"Web application","p":"cpe:2.3:a:stacme:acme:*","k":80},{"id":"st:vo-ver","f":"selftest.page","r":"Acme v(\\d+\\.\\d+\\.\\d+)","n":"ST Acme","v":"{1}","p":"cpe:2.3:a:stacme:acme:{v}","vo":true},{"id":"st:vo-det2","f":"selftest.det2","r":"Beta ([\\d.]+)","n":"ST Beta","v":"{1}","p":"cpe:2.3:a:stbeta:beta:{v}","k":80},{"id":"st:vo-ver2","f":"selftest.page","r":"Beta v(\\d+\\.\\d+\\.\\d+)","n":"ST Beta","v":"{1}","p":"cpe:2.3:a:stbeta:beta:{v}","vo":true},{"id":"st:vo-gate","f":"selftest.det3","r":"Gamma","n":"ST Gamma","c":"Shipping carriers","rc":["Ecommerce"],"p":"cpe:2.3:a:stgamma:gamma:*","k":80},{"id":"st:vo-ver3","f":"selftest.page","r":"Gamma v(\\d+\\.\\d+\\.\\d+)","n":"ST Gamma","v":"{1}","p":"cpe:2.3:a:stgamma:gamma:{v}","vo":true}]}')
    [void][WebInv.Matcher]::Load($voPack, (New-Object 'System.Collections.Generic.List[string]'))
    $vo1 = New-Object WebInv.Observation; $vo1.Add('selftest.page', 'Acme v1.2.3 Beta v3.1.4 Gamma v5.6.7')
    Assert 'version-only rule never creates a detection' { @([WebInv.Matcher]::Evaluate($vo1) | Where-Object { $_.Name -like 'ST *' }).Count -eq 0 }
    $vo2 = New-Object WebInv.Observation; $vo2.Add('selftest.page', 'Acme v1.2.3'); $vo2.Add('selftest.det', 'Acme')
    $vo3 = New-Object WebInv.Observation; $vo3.Add('selftest.det', 'Acme'); $vo3.Add('selftest.page', 'Acme v1.2.3')
    $voA = @([WebInv.Matcher]::Evaluate($vo2) | Where-Object { $_.Name -eq 'ST Acme' }); $voB = @([WebInv.Matcher]::Evaluate($vo3) | Where-Object { $_.Name -eq 'ST Acme' })
    Assert 'version-only rule adds its version to the detected product (either order), not its confidence or category' {
        $voA.Count -eq 1 -and $voB.Count -eq 1 -and $voA[0].Version -eq '1.2.3' -and $voB[0].Version -eq '1.2.3' -and $voA[0].Cpe -eq 'cpe:2.3:a:stacme:acme:1.2.3:*:*:*:*:*:*:*' -and
        $voA[0].Confidence -eq 80 -and $voB[0].Confidence -eq 80 -and $voA[0].Category -eq 'Web application' -and $voB[0].Category -eq 'Web application' }
    $vo4 = New-Object WebInv.Observation; $vo4.Add('selftest.page', 'Beta v3.1.4'); $vo4.Add('selftest.det2', 'Beta 2.0')
    Assert 'version-only rule never replaces a version a detection rule captured' { @([WebInv.Matcher]::Evaluate($vo4) | Where-Object { $_.Name -eq 'ST Beta' -and $_.Version -eq '2.0' }).Count -eq 1 }
    $voPack2 = [WebInv.Matcher]::ReadPack('{"name":"votest2","rules":[{"id":"st:vo-fix","f":"selftest.fav","r":"^ab12$","n":"ST Delta","v":"1.5.0+","p":"cpe:/a:stdelta:delta:1.5.0","k":80},{"id":"st:vo-ver4","f":"selftest.page","r":"Delta v(\\d+\\.\\d+\\.\\d+)","n":"ST Delta","v":"{1}","p":"cpe:2.3:a:stdelta:delta:{v}","vo":true}]}')
    [void][WebInv.Matcher]::Load($voPack2, (New-Object 'System.Collections.Generic.List[string]'))
    $vo6 = New-Object WebInv.Observation; $vo6.Add('selftest.fav', 'ab12'); $vo6.Add('selftest.page', 'Delta v1.6.20')
    Assert 'a captured version-only version replaces one written into a rule (favicon "1.5.0+")' { @([WebInv.Matcher]::Evaluate($vo6) | Where-Object { $_.Name -eq 'ST Delta' -and $_.Version -eq '1.6.20' -and $_.Cpe -eq 'cpe:2.3:a:stdelta:delta:1.6.20:*:*:*:*:*:*:*' }).Count -eq 1 }
    $vo5 = New-Object WebInv.Observation; $vo5.Add('selftest.page', 'Gamma v5.6.7'); $vo5.Add('selftest.det3', 'Gamma')
    Assert 'version-only rule does not lift a requiresCategory gate' { @([WebInv.Matcher]::Evaluate($vo5) | Where-Object { $_.Name -eq 'ST Gamma' }).Count -eq 0 }
    # -VersionPaths: a version-only rule's fixed path is asked for only when its product is detected without a version
    $vpErr = New-Object 'System.Collections.Generic.List[string]'
    $vpPack = [WebInv.Matcher]::ReadPack('{"name":"vptest","rules":[{"id":"st:vpdet","f":"selftest.vp","r":"^zeta(?: (\\d+\\.\\d+))?$","n":"ST Zeta","c":"Web application","v":"{1}","k":80},{"id":"st:vp","f":"path:/st/ver.body","get":"/st/ver","r":"^v(\\d+\\.\\d+)$","n":"ST Zeta","v":"{1}","vo":true},{"id":"st:vpbad1","f":"path:/st/x.body","get":"/st/x","r":"x","n":"ST Zeta","c":"Web application","k":80},{"id":"st:vpbad2","f":"path:/st/../x.body","get":"/st/../x","r":"x","n":"ST Zeta","v":"{0}","vo":true}]}')
    [void][WebInv.Matcher]::Load($vpPack, $vpErr)
    $vp1 = New-Object WebInv.Observation; $vp1.Add('selftest.vp', 'zeta')
    $vp2 = New-Object WebInv.Observation; $vp2.Add('selftest.vp', 'zeta 1.2')
    $vp3 = New-Object WebInv.Observation; $vp3.Add('selftest.vp', 'eta')
    Assert 'version path asked only for a detected product without a version' {
        (@([WebInv.Matcher]::VersionPaths([WebInv.Matcher]::Evaluate($vp1), 50, 4)) -join ',') -eq '/st/ver' -and
        @([WebInv.Matcher]::VersionPaths([WebInv.Matcher]::Evaluate($vp2), 50, 4)).Count -eq 0 -and
        @([WebInv.Matcher]::VersionPaths([WebInv.Matcher]::Evaluate($vp3), 50, 4)).Count -eq 0 }
    $vp1.Add('path:/st/ver.body', 'v3.4')
    Assert 'version path response adds the version; a path on a detection rule or with dot segments is refused' {
        @([WebInv.Matcher]::Evaluate($vp1) | Where-Object { $_.Name -eq 'ST Zeta' -and $_.Version -eq '3.4' }).Count -eq 1 -and
        @($vpErr | Where-Object { $_ -like 'st:vpbad1:*' }).Count -eq 1 -and @($vpErr | Where-Object { $_ -like 'st:vpbad2:*' }).Count -eq 1 }
    # cloud / CDN ranges: longest prefix wins, IPv4, IPv6 and IPv4-mapped addresses, malformed entries skipped
    Assert 'cloud ranges: longest-prefix match over IPv4/IPv6, mapped addresses, no match outside, bad entries reported' {
        $cj = '{"format":1,"version":"2026.01.02","names":["","AWS","us-east-1","EC2","Azure","eastus","AppService","Cloudflare","CDN"],' +
              '"v4":["3.0.0.0/8|1|2|0","3.5.0.0/16|1|2|3","20.0.0.0/8|4|5|0","20.1.2.0/24|4|5|6","20.1.2.3/32|4|0|6","104.16.0.0/13|7|0|8","bad|1|1|1","1.2.3.0/24|99|0|0"],' +
              '"v6":["2600:1f00::/24|1|0|0","2606:4700::/32|7|0|8","2600:1f18:1234::/48|1|2|3"]}'
        $ce = New-Object 'System.Collections.Generic.List[string]'
        $n = [WebInv.Cloud]::Load([WebInv.Cloud]::Read($cj), $ce)
        $f = { param($ip) $r = [WebInv.Cloud]::Find($ip); if ($r) { $r -join '/' } else { '-' } }
        $ok = $n -eq 9 -and $ce.Count -ge 2 -and (& $f '3.5.1.1') -eq 'AWS/us-east-1/EC2' -and (& $f '3.9.1.1') -eq 'AWS/us-east-1/' -and
            (& $f '20.1.2.4') -eq 'Azure/eastus/AppService' -and (& $f '20.1.2.3') -eq 'Azure//AppService' -and (& $f '20.200.0.1') -eq 'Azure/eastus/' -and
            (& $f '104.23.255.255') -eq 'Cloudflare//CDN' -and (& $f '104.24.0.0') -eq '-' -and (& $f '8.8.8.8') -eq '-' -and (& $f '10.0.0.1') -eq '-' -and
            (& $f '2606:4700::1111') -eq 'Cloudflare//CDN' -and (& $f '2600:1f18:1234:5::1') -eq 'AWS/us-east-1/EC2' -and (& $f '2600:1f18:9999::1') -eq 'AWS//' -and
            (& $f '::ffff:3.5.1.1') -eq 'AWS/us-east-1/EC2' -and (& $f 'not-an-ip') -eq '-' -and (& $f '') -eq '-'
        [WebInv.Cloud]::Clear()
        $priv = @('10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '0.0.0.0', '224.0.0.1', 'fd00::1', 'fe80::1', '::1', '::', 'ff02::1', '::ffff:10.0.0.1', 'bad') | Where-Object { -not [WebInv.Cloud]::IsPrivate($_) }
        $pub = @('172.32.0.1', '172.15.255.255', '100.128.0.1', '8.8.8.8', '2606:4700::1', '::ffff:3.5.1.1') | Where-Object { [WebInv.Cloud]::IsPrivate($_) }
        $ok -and -not [WebInv.Cloud]::Loaded -and @($priv).Count -eq 0 -and @($pub).Count -eq 0
    }
    # the shipped ranges (next to the script): they load, and the first and last entry of each family are found again
    $shippedCloud = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'WebInventory.cloud.json' } else { '' }
    if ($shippedCloud -and (Test-Path -LiteralPath $shippedCloud)) {
        Assert 'cloud ranges: the shipped WebInventory.cloud.json loads and finds its own entries' {
            $cp = [WebInv.Cloud]::Read([IO.File]::ReadAllText($shippedCloud))
            $n = [WebInv.Cloud]::Load($cp, (New-Object 'System.Collections.Generic.List[string]'))
            $good = $n -gt 1000
            foreach ($e in @($cp.V4[0], $cp.V4[-1], $cp.V6[0], $cp.V6[-1])) {
                $fld = $e.Split('|'); $net = $fld[0].Split('/')[0]
                $r = [WebInv.Cloud]::Find($net)   # a more specific range may start at the same address: any provider counts
                if (-not $r -or -not $r[0]) { $good = $false }
            }
            [WebInv.Cloud]::Clear()
            $good
        }
    }
    # o=b: the value is base64 text and the regex runs on its decoding (n8n's n8n:config:sentry meta tag)
    $b64Pack = [WebInv.Matcher]::ReadPack('{"name":"b64test","rules":[{"id":"st:b64","f":"selftest.b64","o":"b","r":"\"rel\":\"st@(\\d+\\.\\d+\\.\\d+)\"","n":"ST Epsilon","v":"{1}","c":"Web application","k":80}]}')
    [void][WebInv.Matcher]::Load($b64Pack, (New-Object 'System.Collections.Generic.List[string]'))
    $b1 = New-Object WebInv.Observation; $b1.Add('selftest.b64', 'eyJyZWwiOiJzdEA0LjUuNiJ9')
    $b2 = New-Object WebInv.Observation; $b2.Add('selftest.b64', '{"rel":"st@4.5.6"}'); $b2.Add('selftest.b64', 'not base64!')
    Assert 'base64 rule (o=b) matches the decoded value only' {
        @([WebInv.Matcher]::Evaluate($b1) | Where-Object { $_.Name -eq 'ST Epsilon' -and $_.Version -eq '4.5.6' }).Count -eq 1 -and
        @([WebInv.Matcher]::Evaluate($b2) | Where-Object { $_.Name -eq 'ST Epsilon' }).Count -eq 0 }
    $tested = 0; $fails = @([WebInv.Matcher]::TestExamples([ref]$tested))
    $bFails = @($fails | Where-Object { $_ -like 'b:*' -or $_ -like 'v:*' })
    Assert ("built-in rule examples") { $bFails.Count -eq 0 }
    foreach ($f in $fails) { Write-RunLog "example failure: $f" $(if ($f -like 'b:*' -or $f -like 'v:*') { 'ERROR' } else { 'WARN' }) }
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
    Invoke-ShipSelfTest
    Invoke-StoreSelfTest
    $total = $script:StPass + $script:StFail
    $c = if ($script:StFail) { 'Red' } else { 'Green' }
    Write-Host ("Self-test: {0}/{1} passed (SHA-256 provider: {2})" -f $script:StPass, $total, [WebInv.Hash]::Sha256Provider) -ForegroundColor $c
    Write-RunLog ("Self-test: {0}/{1} passed" -f $script:StPass, $total)
    if ($script:StFail) { $script:ExitCode = 1 }
}
$script:SelfTestCertB64 = '__SELFTEST_CERT__'
#endregion
