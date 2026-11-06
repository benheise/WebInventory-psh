param(
    [Parameter(Mandatory)][string]$Script,      # built Invoke-WebInventory.ps1 (its engine and embedded rules are used)
    [Parameter(Mandatory)][string[]]$Capture,   # capture folders written by vlab.py (capture.json + *.body)
    [string]$PackDir,                           # folder with WebInventory.rules.*.json (default: next to the script)
    [string]$Json,                              # also write the detections (name, version, CPE) per capture to this file
    [switch]$VersionPaths                       # as -VersionPaths: serve recorded version URLs (vpath*) the engine asks for
)
# Feeds what vlab.py recorded from a real product into the scanner's own matcher, the same way a scan builds its
# observations (headers of every hop, redirect locations, final status/url/body/title/meta/script sources, the 404
# probe's body and Server/X-Powered-By, robots.txt, the favicon hash), and prints the detections with their versions.
$ErrorActionPreference = 'Stop'
$Capture = @($Capture | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$code = Get-Content -Raw -LiteralPath $Script
if ($code -notmatch "(?s)\`$EngineSource = @'\r?\n(.*?)\r?\n'@") { throw 'engine block not found' }
if (-not ('WebInv.Matcher' -as [type])) { Add-Type -TypeDefinition $Matches[1] }
if ($code -notmatch "(?s)\`$BuiltinRulesJson = @'\r?\n(.*?)\r?\n'@") { throw 'built-in rules not found' }
$builtin = $Matches[1]
[WebInv.Matcher]::Clear()
$errs = New-Object 'System.Collections.Generic.List[string]'
[void][WebInv.Matcher]::Load([WebInv.Matcher]::ReadPack($builtin), $errs)
if (-not $PackDir) { $PackDir = Split-Path -Parent (Resolve-Path -LiteralPath $Script) }
foreach ($f in Get-ChildItem -LiteralPath $PackDir -Filter 'WebInventory.rules.*.json') {
    [void][WebInv.Matcher]::Load([WebInv.Matcher]::ReadPack([IO.File]::ReadAllText($f.FullName)), $errs)
}
if ($errs.Count) { Write-Warning ("{0} rule load errors" -f $errs.Count) }

function New-Resp($Status, $Headers, [string]$BodyFile) {
    $r = New-Object WebInv.HttpResp
    $r.IsHttp = $true; $r.Code = [int]$Status
    foreach ($h in $Headers) {
        $n = ([string]$h[0]).ToLowerInvariant(); $v = [string]$h[1]
        $r.List.Add([string[]]@($n, $v))
        if ($r.Headers.ContainsKey($n)) { $r.Headers[$n] = [string]$r.Headers[$n] + "`n" + $v } else { $r.Headers[$n] = $v }
    }
    if ($BodyFile -and (Test-Path -LiteralPath $BodyFile)) {
        $r.Body = [IO.File]::ReadAllBytes($BodyFile); $r.Text = [Text.Encoding]::UTF8.GetString($r.Body)
    }
    $r
}

$script:out = @()
foreach ($dir in $Capture) {
    if (-not (Test-Path -LiteralPath (Join-Path $dir 'capture.json'))) { continue }
    $cap = Get-Content -Raw -LiteralPath (Join-Path $dir 'capture.json') | ConvertFrom-Json
    $obs = New-Object WebInv.Observation
    $port = [int](Get-Content -LiteralPath (Join-Path $dir 'port') -ErrorAction SilentlyContinue)
    $obs.Port = $port
    $hops = New-Object 'System.Collections.Generic.List[WebInv.HttpResp]'
    $locs = New-Object 'System.Collections.Generic.List[string]'
    $i = 0
    foreach ($h in $cap.hops) {
        $hops.Add((New-Resp $h.status $h.headers (Join-Path $dir ("hop{0}.body" -f $i))))
        foreach ($p in $h.headers) { if ($p[0] -ieq 'location') { $locs.Add([string]$p[1]) } }
        $i++
    }
    $last = $cap.hops[-1].path
    [WebInv.Html]::AddWeb($obs, $hops.ToArray(), $locs, ('http://127.0.0.1:{0}{1}' -f $port, $last))
    $fav = $cap.extras.favicon
    if ($fav -and $fav.status -eq 200 -and $fav.md5) { $obs.Add('favicon.md5', $fav.md5) }
    $rb = $cap.extras.robots
    if ($rb -and $rb.status -eq 200) {
        $t = [IO.File]::ReadAllText((Join-Path $dir 'robots.body'))
        if ($t -match '(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:') { $obs.Add('robots', $(if ($t.Length -gt 8192) { $t.Substring(0, 8192) } else { $t })) }
    }
    $nf = $cap.extras.notfound
    if ($nf -and $nf.status) {
        foreach ($p in $nf.headers) { if ($p[0] -ieq 'server' -or $p[0] -ieq 'x-powered-by') { [WebInv.Html]::AddHeader($obs, '', ([string]$p[0]).ToLowerInvariant(), [string]$p[1]) } }
        $t = [IO.File]::ReadAllText((Join-Path $dir 'notfound.body'))
        if ($t) { $obs.Add('body', $(if ($t.Length -gt 32768) { $t.Substring(0, 32768) } else { $t })) }
    }
    $dets = [WebInv.Matcher]::Evaluate($obs)
    # -VersionPaths: serve the recorded version URLs the engine asks for (only for a product detected without a version)
    $asked = @()
    if ($VersionPaths) {
        $want = [WebInv.Matcher]::VersionPaths($dets, 50, 4)
        $vps = @($cap.extras.PSObject.Properties | Where-Object { $_.Name -like 'vpath*' -and $_.Value.status })
        foreach ($w in $want) {
            $asked += $w
            $vp = $vps | Where-Object { $_.Value.path -eq $w } | Select-Object -First 1
            if ($vp -and [int]$vp.Value.status -eq 200) {
                [WebInv.Html]::AddBody($obs, ('path:{0}.' -f $w), (New-Resp $vp.Value.status $vp.Value.headers (Join-Path $dir ('{0}.body' -f $vp.Name))))
            }
        }
        if ($asked.Count) { $dets = [WebInv.Matcher]::Evaluate($obs) }
    }
    if ($Json) { $script:out += [pscustomobject]@{ capture = $dir; asked = @($asked); detections = @(foreach ($d in $dets) { if ($d.Kind -ne 'flag' -and $d.Confidence -ge 50) { [pscustomobject]@{ kind = $d.Kind; name = $d.Name; version = $d.Version; cpe = $d.Cpe } } }) } }
    $list = foreach ($d in $dets) { if ($d.Kind -ne 'flag' -and $d.Confidence -ge 50) { '{0}{1} [{2}]' -f $d.Name, $(if ($d.Version) { ' ' + $d.Version } else { '' }), $d.Source } }
    '{0}: {1}{2}' -f $dir, ($list -join '; '), $(if ($asked.Count) { ' [asked: ' + ($asked -join ', ') + ']' } else { '' })
}
if ($Json) { $script:out | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Json -Encoding utf8 }
