<#
  WebInventory micro-benchmarks (attribution for the macro suite).
  pwsh -File micro.ps1 -Script <Invoke-WebInventory.ps1> -Out <result.json> [-Iterations 20]
  Loads the engine, rule packs and the worker/output functions *from the given script* (so a baseline and a
  candidate are measured with their own code), fetches a fixed corpus from the running lab, and times:
    eval.<page>        rule evaluation per observation (Matcher.Evaluate), per field breakdown for the SPA page
    parse.<page>       response parsing + observation building (ConvertFrom-Raw, Add-WebObs, Set-HttpFields)
    row.write          one result row to CSV + JSONL (Write-ResultRow)
    dispatch.job       one no-op check through the dispatcher machinery (PowerShell instance + worker script)
  Requires lab/start-lab.sh to be running.
#>
param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][string]$Out, [int]$Iterations = 20, [string]$CorpusOut)
$ErrorActionPreference = 'Stop'
$src = [IO.File]::ReadAllText($Script)
$dir = Split-Path -Parent (Resolve-Path $Script)
if ($src -notmatch "(?s)\`$EngineSource = @'\r?\n(.*?)\r?\n'@") { throw 'engine not found' }
Add-Type -TypeDefinition $Matches[1]
if ($src -notmatch "(?s)\`$BuiltinRulesJson = @'\r?\n(.*?)\r?\n'@") { throw 'builtin rules not found' }
$errs = [System.Collections.Generic.List[string]]::new()
$sw = [Diagnostics.Stopwatch]::StartNew()
[void][WebInv.Matcher]::Load([WebInv.Matcher]::ReadPack($Matches[1]), $errs)
foreach ($f in Get-ChildItem $dir -Filter 'WebInventory.rules.*.json') { [void][WebInv.Matcher]::Load([WebInv.Matcher]::ReadPack([IO.File]::ReadAllText($f.FullName)), $errs) }
$loadMs = $sw.ElapsedMilliseconds
$res = [ordered]@{ script = $Script; rules = [WebInv.Matcher]::Count; rule_load_ms = $loadMs; ps = $PSVersionTable.PSVersion.ToString() }

# ---- pull functions out of the script (worker scriptblock + output region) ----
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
$wsAst = $ast.Find({ param($a) $a -is [System.Management.Automation.Language.AssignmentStatementAst] -and $a.Left.Extent.Text -eq '$WorkerScript' }, $true)
$workerText = $wsAst.Right.Expression.ScriptBlock.Extent.Text
$workerText = $workerText.Substring(1, $workerText.Length - 2)
$wsb = [scriptblock]::Create($workerText)
$fns = $wsb.Ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($fn in $fns) { . ([scriptblock]::Create($fn.Extent.Text)) }
foreach ($name in 'ConvertTo-CsvField', 'Write-ResultRow') {
    $fa = $ast.Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $name }, $true)
    . ([scriptblock]::Create($fa.Extent.Text))
}
$colAst = $ast.Find({ param($a) $a -is [System.Management.Automation.Language.AssignmentStatementAst] -and $a.Left.Extent.Text -eq '$Columns' }, $true)
$Columns = Invoke-Expression $colAst.Right.Extent.Text
$NoCsvSanitize = $false

# ---- worker context the functions expect ----
$Cfg = @{ UserAgent = 'bench'; TimeoutMs = 3000; MaxBodyBytes = 262144; SslProto = 0; DelayMs = 0; JitterMs = 0; MaxRedirects = 5; Columns = $Columns
    RunId = 'bench'; Tag = ''; MismatchStrings = @(); FollowOffHost = $false; MinConfidence = 50; CertWarnDays = 30; Advisories = @(); MgmtCategories = @()
    CsParse = $true; SilentParallel = $true
}
$script:CsWriter = $true; $script:JsonNames = [string[]]@($Columns + 'Detections')
$stats = @{ Requests = 0 }; $logs = [System.Collections.Generic.List[string]]::new(); $notes = [System.Collections.Generic.List[string]]::new()
$errs2 = [System.Collections.Generic.List[object]]::new(); Set-Variable -Name errs -Value $errs2

function Measure-Ms([scriptblock]$Body, [int]$N) {
    & $Body | Out-Null   # warm-up
    $t = [System.Collections.Generic.List[double]]::new()
    for ($i = 0; $i -lt $N; $i++) { $s = [Diagnostics.Stopwatch]::StartNew(); & $Body | Out-Null; $t.Add($s.Elapsed.TotalMilliseconds) }
    $a = $t.ToArray(); [Array]::Sort($a); [Math]::Round($a[[int]($a.Length / 2)], 3)
}

$corpus = [ordered]@{
    corp = @('127.0.10.1', 19080, $false, '/'); wordpress = @('127.0.10.2', 19081, $false, '/'); spa = @('127.0.10.3', 19082, $false, '/')
    jenkins = @('127.0.10.4', 19443, $true, '/login?from=%2F'); iis = @('127.0.0.1', 18080, $false, '/'); shop = @('127.0.0.1', 18091, $false, '/')
}
$evalSpa = $null
foreach ($k in $corpus.Keys) {
    $c = $corpus[$k]
    $J = @{ Host = $c[0]; Ip = $c[0]; Port = $c[1]; Scheme = '' }; $TargetId = $k
    $hostHdr = Get-HostHdr $c[0] $c[1] $c[2]
    $f = Invoke-Fetch $c[2] 'GET' $c[3] $hostHdr $c[0] $c[1] $c[0] 0
    if (-not $f.Resp.IsHttp) { throw "lab fixture $k did not answer (is lab/start-lab.sh running?)" }
    $raw = $f.Raw.Raw
    if ($CorpusOut) { [void](New-Item -ItemType Directory -Force $CorpusOut); [IO.File]::WriteAllBytes((Join-Path $CorpusOut "$k.raw"), $raw) }
    $hops = [System.Collections.Generic.List[object]]::new(); $hops.Add($f)
    $web = @{ Hops = $hops; Final = $f; Url = 'http://x/'; FinalUrl = 'http://x/'; Chain = [System.Collections.Generic.List[string]]::new(); Locations = [System.Collections.Generic.List[string]]::new() }
    $res["parse.$k.ms"] = Measure-Ms {
        $r = ConvertFrom-Raw $raw
        $h = @{ Raw = $f.Raw; Resp = $r; Tls = $c[2]; Ip = $c[0]; Port = $c[1]; Sni = $c[0]; HostHdr = $hostHdr }
        $hl = [System.Collections.Generic.List[object]]::new(); $hl.Add($h)
        $w = @{ Hops = $hl; Final = $h; Url = 'http://x/'; FinalUrl = 'http://x/'; Chain = $web.Chain; Locations = $web.Locations }
        $row = New-Row; Set-HttpFields $row $w
        $o = New-Object WebInv.Observation; $o.Port = $c[1]; Add-WebObs $o $w
    } $Iterations
    $obs = New-Object WebInv.Observation; $obs.Port = $c[1]; Add-WebObs $obs $web
    $res["eval.$k.ms"] = Measure-Ms { [WebInv.Matcher]::Evaluate($obs) } $Iterations
    $res["eval.$k.detections"] = (([WebInv.Matcher]::Evaluate($obs)) | ForEach-Object { $_.ToString() }) -join '; '
    $res["bytes.$k"] = $raw.Length
    if ($k -eq 'spa') { $evalSpa = $obs }
}
# per-field attribution on the SPA page
foreach ($fld in @($evalSpa.F.Keys)) {
    $one = New-Object WebInv.Observation; $one.Port = $evalSpa.Port
    foreach ($v in $evalSpa.F[$fld]) { $one.Add($fld, $v) }
    $ms = Measure-Ms { [WebInv.Matcher]::Evaluate($one) } ([Math]::Max(5, [int]($Iterations / 2)))
    if ($ms -ge 0.5) { $res["eval.spa.field.$fld.ms"] = $ms }
}

# ---- one result row to CSV + JSONL ----
$J = @{ Host = '127.0.10.3'; Ip = '127.0.10.3'; Port = 19082; Scheme = '' }
$row = New-Row; Set-HttpFields $row $web
$det = [WebInv.Matcher]::Evaluate($evalSpa)
Complete-Row $row $evalSpa
$script:CsvW = [IO.StreamWriter]::new([IO.Stream]::Null); $script:JsonW = [IO.StreamWriter]::new([IO.Stream]::Null)
$res['row.write.ms'] = Measure-Ms { Write-ResultRow $row } ($Iterations * 5)
$res['row.detections'] = @($row._Detections).Count

# ---- dispatcher: per-check overhead on a closed port (RST), 200 checks through the script's own dispatch model ----
$pool = [RunspaceFactory]::CreateRunspacePool(1, 4); $pool.Open()
$cfgNoop = @{ Retries = 0; TimeoutMs = 500 }
$jobsN = 200
$newModel = $workerText -match 'param\(\$Sched'
if ($newModel) {
    # same construction as the scanner: worker functions shared through an InitialSessionState, small loop script
    $pool.Close()
    $sess = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault(); $parts = @()
    foreach ($st in $wsb.Ast.EndBlock.Statements) {
        if ($st -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            $fb = $st.Body.Extent.Text; $fb = $fb.Substring(1, $fb.Length - 2)
            if ($st.Parameters) { $fb = 'param(' + (@($st.Parameters | ForEach-Object { $_.Extent.Text }) -join ', ') + ")`n" + $fb }
            $sess.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($st.Name, $fb))
        } else { $parts += $st.Extent.Text }
    }
    $loop = $wsb.Ast.ParamBlock.Extent.Text + "`n" + ($parts -join "`n")
    $pool = [RunspaceFactory]::CreateRunspacePool(1, 4, $sess, $Host); $pool.Open()
    $sch = [WebInv.Sched]::new([string[]]@(1..$jobsN | ForEach-Object { "127.0.0.1`t127.0.0.1`t18999`t" }), 64, 1)
    $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
    [void]$ps.AddScript($loop).AddArgument($sch).AddArgument($cfgNoop).AddArgument(0)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    [void]$ps.EndInvoke($ps.BeginInvoke()); $ps.Dispose()
}
else {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $jobsN; $i++) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($workerText).AddArgument("127.0.0.1`t127.0.0.1`t18999`t").AddArgument($cfgNoop)
        [void]$ps.EndInvoke($ps.BeginInvoke()); $ps.Dispose()
    }
}
$res['dispatch.perjob.ms'] = [Math]::Round($sw.Elapsed.TotalMilliseconds / $jobsN, 3)
$res['dispatch.model'] = $(if ($newModel) { 'long-lived worker' } else { 'PowerShell instance per check' })
$pool.Close()

# ---- DNS: 600 names, 5% take 1500 ms, the rest 20 ms, 32 in flight (fake resolver; candidate only) ----
if ([WebInv.Net].GetField('Resolver')) {
    [WebInv.Net]::Resolver = [WebInv.Net]::FakeResolver(5, 1500, 20)
    $names = [string[]]@(1..600 | ForEach-Object { "host$_.corp.example" })
    foreach ($mode in $true, $false) {
        [WebInv.Net]::SlidingDns = $mode
        $e = [System.Collections.Generic.Dictionary[string, string]]::new()
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = [WebInv.Net]::ResolveMany($names, 3000, 32, $e)
        $res["dns.$(if ($mode) { 'sliding' } else { 'batched' }).ms"] = $sw.ElapsedMilliseconds
        $res["dns.$(if ($mode) { 'sliding' } else { 'batched' }).resolved"] = $r.Count
    }
    [WebInv.Net]::Resolver = $null; [WebInv.Net]::SlidingDns = $true
}

# ---- rule evaluation with the prefilter off (candidate only): same observations ----
if ([WebInv.Matcher].GetField('Prefilter')) {
    [WebInv.Matcher]::Prefilter = $false
    $res['eval.spa.noprefilter.ms'] = Measure-Ms { [WebInv.Matcher]::Evaluate($evalSpa) } $Iterations
    [WebInv.Matcher]::Prefilter = $true
    $res['rules.prefiltered'] = [WebInv.Matcher]::PrefilteredRules
}
$res | ConvertTo-Json | Set-Content -LiteralPath $Out -Encoding utf8
$res.GetEnumerator() | Where-Object { $_.Key -notlike '*.detections' } | ForEach-Object { '{0,-40} {1}' -f $_.Key, $_.Value }
