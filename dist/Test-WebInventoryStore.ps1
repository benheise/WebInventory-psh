<#
.SYNOPSIS
    Validates the WebInventory inventory store on THIS Windows host: ESENT engine against the portable engine,
    hard kills during ingest, verification, rebuild. Sends no network traffic.

.DESCRIPTION
    Run once on the scanner host (Windows PowerShell 5.1) before relying on -Store, and again after a Windows
    feature update. Every step runs Invoke-WebInventory.ps1 in a child process, exactly as a scheduled task would.
      1. Invoke-WebInventory.ps1 -SelfTest (includes ESENT conformance, ESENT-vs-portable digests, crash repair)
      2. Three synthetic runs of -Services services ingested into an ESENT store and a File store: every change and
         state digest in the two ledgers must be identical
      3. Hard kills (Stop-Process -Force) of an ESENT ingest at several points; the next open must finish the run
         with digests identical to an uninterrupted ingest
      4. -VerifyStore on the ESENT store; -RebuildStore to File and back to ESENT, digests unchanged
      5. v2.3: -Backfill into an ESENT store (final inventory equals in-order ingest); event-log anchoring of the
         ledger when the 'WebInventory' event source exists or can be registered (needs an elevated prompt once)
    Writes a report to Test-WebInventoryStore_<stamp>.log in the current folder. Exit 0 = all passed.

.EXAMPLE
    .\Test-WebInventoryStore.ps1 -Script .\Invoke-WebInventory.ps1 -Services 20000
#>
[CmdletBinding()]
param(
    [string]$Script = '',   # default: Invoke-WebInventory.ps1 next to this file (set below; $PSScriptRoot is empty in
                            # parameter defaults under Windows PowerShell 5.1 -File)
    [ValidateRange(100, 1000000)][int]$Services = 20000,
    [string]$Work = (Join-Path ([IO.Path]::GetTempPath()) ('webinv-store-validate-' + (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [switch]$Keep
)
$ErrorActionPreference = 'Stop'
if (-not $Script) { $Script = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Invoke-WebInventory.ps1' }
$Script = (Resolve-Path -LiteralPath $Script).ProviderPath
$exe = (Get-Process -Id $PID).Path
$logPath = Join-Path (Get-Location).ProviderPath ('Test-WebInventoryStore_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$results = New-Object System.Collections.Generic.List[object]
function Write-Report([string]$Text, [string]$Color = 'Gray') { Write-Host $Text -ForegroundColor $Color; Add-Content -LiteralPath $logPath -Value $Text }
function Add-Result([string]$Name, [bool]$Ok, [string]$Detail) {
    $results.Add([pscustomobject]@{ Check = $Name; Result = $(if ($Ok) { 'PASS' } else { 'FAIL' }); Detail = $Detail })
    Write-Report ('{0}  {1}  {2}' -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $Detail) $(if ($Ok) { 'Green' } else { 'Red' })
}
function Invoke-Wi([string[]]$Arguments, [int]$TimeoutSec = 3600) {
    $out = Join-Path $Work ('wi-{0}.out' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $Script)) + @($Arguments | ForEach-Object { if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ } })
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $exe -ArgumentList $argList -WorkingDirectory $Work -RedirectStandardOutput $out -RedirectStandardError ($out + '.err') -NoNewWindow -PassThru
    $null = $p.Handle   # Windows PowerShell only reports ExitCode if the handle was opened while the process ran
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { Stop-Process -Id $p.Id -Force; throw "timed out: $($Arguments -join ' ')" }
    [pscustomobject]@{ Code = $p.ExitCode; Text = ((Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath ($out + '.err') -Raw -ErrorAction SilentlyContinue)); Seconds = $sw.Elapsed.TotalSeconds }
}
function Get-Digests([string]$Root) {
    $lines = foreach ($l in [IO.File]::ReadAllLines((Join-Path $Root 'archive\ledger.jsonl'))) {
        $o = $l | ConvertFrom-Json
        if ($o.type -eq 'run') { '{0}:{1}:{2}:{3}' -f $o.seq, $o.runId, $o.changesDigest, $o.stateDigest }
    }
    ($lines -join "`n")
}
function Get-FinalState([string]$Root) {
    $last = ''
    foreach ($l in [IO.File]::ReadAllLines((Join-Path $Root 'archive\ledger.jsonl'))) {
        $o = $l | ConvertFrom-Json
        if (($o.type -eq 'run' -or $o.type -eq 'correction') -and $o.stateDigest) { $last = $o.stateDigest }
        elseif ($o.type -eq 'rebase') { $last = @($o.plan)[-1].stateDigest }
    }
    $last
}
function Start-Ingest([string]$Store, [string]$Run) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $Script), '-Store', ('"{0}"' -f $Store), '-StoreEngine', 'Esent', '-ImportRun', ('"{0}"' -f $Run), '-Quiet')
    $p = Start-Process -FilePath $exe -ArgumentList $argList -WorkingDirectory $Work -NoNewWindow -PassThru
    $null = $p.Handle
    $p
}

New-Item -ItemType Directory -Path $Work -Force | Out-Null
Write-Report ("WebInventory store validation  {0}  host={1}  OS={2}  PowerShell {3}  script={4}" -f (Get-Date).ToString('s'), $env:COMPUTERNAME, [Environment]::OSVersion.VersionString, $PSVersionTable.PSVersion, $Script) 'Cyan'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not (Test-Path (Join-Path $env:SystemRoot 'System32\esent.dll'))) { Write-Report 'esent.dll not found: this check is for Windows hosts.' 'Red'; exit 1 }

try {
    # 1. self-test
    $r = Invoke-Wi @('-SelfTest')
    $m = [regex]::Match($r.Text, 'Self-test: (\d+)/(\d+) passed')
    # the ESENT checks must have run (they are skipped where esent.dll is missing)
    $stLog = Get-ChildItem -LiteralPath $Work -Filter 'WebInventory_*_run.log' | Sort-Object LastWriteTime | Select-Object -Last 1
    $stText = if ($stLog) { [IO.File]::ReadAllText($stLog.FullName) } else { '' }
    $esentChecks = ([regex]::Matches($stText, 'SELFTEST PASS store: .*(esent|ESENT)')).Count
    Add-Result 'self-test (includes ESENT conformance, cross-engine digests, crash repair)' ($r.Code -eq 0 -and $m.Success -and $m.Groups[1].Value -eq $m.Groups[2].Value -and $esentChecks -ge 5) ('{0}; {1} ESENT checks passed' -f $m.Value, $esentChecks)

    # synthetic runs, generated by the engine itself in a child process
    $gen = Join-Path $Work 'gen.ps1'
    $runsDir = Join-Path $Work 'runs'
    # literal text with placeholders (an expandable string would expand $StoreSource in the regex)
    $genText = @'
$code = [IO.File]::ReadAllText('__SCRIPT__')
if ($code -notmatch "(?s)\`$StoreSource = @'\r?\n(.*?)\r?\n'@") { throw 'store engine not found in the script' }
$addType = @{ TypeDefinition = $Matches[1]; IgnoreWarnings = $true }
if ($PSVersionTable.PSEdition -ne 'Core') { $addType.ReferencedAssemblies = @('System.Core') }
Add-Type @addType
[void][WebInv.StoreSelfTest]::WriteRuns('__RUNS__', __N__)
'@
    $genText.Replace('__SCRIPT__', ($Script -replace "'", "''")).Replace('__RUNS__', ($runsDir -replace "'", "''")).Replace('__N__', [string]$Services) | Set-Content -LiteralPath $gen -Encoding UTF8
    $p = Start-Process -FilePath $exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $gen)) -NoNewWindow -PassThru
    $null = $p.Handle; $p.WaitForExit()
    if ($p.ExitCode -ne 0 -or -not (Test-Path (Join-Path $runsDir 'run3'))) { throw 'generating synthetic runs failed' }
    $runs = @(Get-ChildItem -LiteralPath $runsDir -Directory | Sort-Object Name | ForEach-Object { $_.FullName })

    # 2. ESENT vs File, same three runs
    $times = @{}
    foreach ($eng in 'Esent', 'File') {
        $root = Join-Path $Work "store-$eng"
        $times[$eng] = @()
        foreach ($run in $runs) {
            $r = Invoke-Wi @('-Store', $root, '-StoreEngine', $eng, '-RetireAfter', '2', '-ImportRun', $run)
            if ($r.Code -ne 0) { throw "$eng ingest of $run failed: $($r.Text)" }
            $times[$eng] += $r.Seconds
        }
    }
    $dE = Get-Digests (Join-Path $Work 'store-Esent'); $dF = Get-Digests (Join-Path $Work 'store-File')
    Add-Result ("ESENT and File engines: identical change/state digests for 3 runs of {0} services" -f $Services) ($dE -eq $dF -and $dE.Length -gt 0) ('ingest seconds ESENT {0} | File {1}' -f (($times['Esent'] | ForEach-Object { '{0:0.0}' -f $_ }) -join '/'), (($times['File'] | ForEach-Object { '{0:0.0}' -f $_ }) -join '/'))

    # 3. hard kills during an ESENT ingest of run 2
    $base = Join-Path $Work 'kill-base'
    $r = Invoke-Wi @('-Store', $base, '-StoreEngine', 'Esent', '-RetireAfter', '2', '-ImportRun', $runs[0])
    $want = (Get-Digests (Join-Path $Work 'store-Esent')).Split("`n")[0..1] -join "`n"
    $full = $times['Esent'][1]
    foreach ($frac in 0.25, 0.5, 0.75, 0.9) {
        $kroot = Join-Path $Work ('kill-{0}' -f [int]($frac * 100))
        Copy-Item -LiteralPath $base -Destination $kroot -Recurse
        $p = Start-Ingest $kroot $runs[1]
        Start-Sleep -Milliseconds ([int]($full * $frac * 1000))
        $killed = -not $p.HasExited
        if ($killed) { Stop-Process -Id $p.Id -Force; $p.WaitForExit() }
        $r = Invoke-Wi @('-Store', $kroot, '-ImportRun', $runs[1])
        $got = Get-Digests $kroot
        Add-Result ("hard kill at ~{0:P0} of an ESENT ingest, then reopen" -f $frac) ($r.Code -eq 0 -and $got -eq $want) $(if ($killed) { 'killed; ' + $(if ($r.Text -match 'finishing run') { 'finished as pending' } elseif ($r.Text -match 'already in the store') { 'already complete' } else { 're-ingested' }) } else { 'ingest finished before the kill' })
    }

    # 4. verify, rebuild across engines
    $eroot = Join-Path $Work 'store-Esent'
    $r = Invoke-Wi @('-Store', $eroot, '-VerifyStore')
    Add-Result 'VerifyStore on the ESENT store' ($r.Code -eq 0 -and $r.Text -match 'VERIFIED') (([regex]::Matches($r.Text, '(?m)^(ok|FAIL|note).*$') | ForEach-Object { $_.Value.Trim() }) -join ' | ')
    $r1 = Invoke-Wi @('-Store', $eroot, '-RebuildStore', '-StoreEngine', 'File')
    $r2 = Invoke-Wi @('-Store', $eroot, '-RebuildStore', '-StoreEngine', 'Esent')
    $r3 = Invoke-Wi @('-Store', $eroot, '-VerifyStore')
    Add-Result 'RebuildStore ESENT -> File -> ESENT keeps every digest' ($r1.Code -eq 0 -and $r2.Code -eq 0 -and $r3.Code -eq 0 -and (Get-Digests $eroot) -eq $dE) ('{0:0.0}s / {1:0.0}s' -f $r1.Seconds, $r2.Seconds)

    # 5. v2.3: backfill on ESENT; event-log anchoring
    $broot = Join-Path $Work 'backfill-Esent'
    foreach ($run in $runs[0], $runs[2]) { $r = Invoke-Wi @('-Store', $broot, '-StoreEngine', 'Esent', '-RetireAfter', '2', '-ImportRun', $run); if ($r.Code -ne 0) { throw "backfill setup failed: $($r.Text)" } }
    $r = Invoke-Wi @('-Store', $broot, '-ImportRun', $runs[1], '-Backfill')
    $v = Invoke-Wi @('-Store', $broot, '-VerifyStore')
    Add-Result 'Backfill of an older run into an ESENT store: same final inventory as in-order ingest, verified' ($r.Code -eq 0 -and $v.Code -eq 0 -and (Get-FinalState $broot) -eq (Get-FinalState $eroot)) ('{0:0.0}s' -f $r.Seconds)
    $src = $false
    try { $src = [System.Diagnostics.EventLog]::SourceExists('WebInventory') } catch { $src = $false }
    if (-not $src) { $reg = Invoke-Wi @('-RegisterEventSource'); $src = $reg.Code -eq 0 }
    if ($src) {
        $aroot = Join-Path $Work 'anchor-Esent'
        $r = Invoke-Wi @('-Store', $aroot, '-StoreEngine', 'Esent', '-AnchorEventLog', '-ImportRun', $runs[0])
        $v = Invoke-Wi @('-Store', $aroot, '-VerifyStore')
        Add-Result 'ledger heads written to the Application event log and checked by VerifyStore' ($r.Code -eq 0 -and $v.Code -eq 0 -and $v.Text -match 'event-log entries match the ledger') (([regex]::Matches($v.Text, '(?m)^(ok|FAIL|note)\s+anchors.*$') | ForEach-Object { $_.Value.Trim() }) -join ' | ')
    }
    else { Write-Report "SKIP  event-log anchoring: the 'WebInventory' event source is not registered (run once, elevated: .\Invoke-WebInventory.ps1 -RegisterEventSource)" 'Yellow' }
}
catch { Add-Result 'validation run' $false $_.Exception.Message }
finally {
    $fails = @($results | Where-Object Result -eq 'FAIL').Count
    Write-Report ('{0}: {1} checks, {2} failed. Report: {3}' -f $(if ($fails) { 'FAILED' } else { 'ALL PASSED' }), $results.Count, $fails, $logPath) $(if ($fails) { 'Red' } else { 'Cyan' })
    if (-not $Keep -and -not $fails) { Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue } else { Write-Report "Work folder kept: $Work" }
}
exit $(if (@($results | Where-Object Result -eq 'FAIL').Count) { 1 } else { 0 })
