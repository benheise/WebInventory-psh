#region ---------- Inventory store: history across runs (ESENT working database + append-only archive) ----------
# Nothing here runs during a scan. After a complete run the finished output files are archived and applied to the
# store; -ImportRun / -StoreQuery / -VerifyStore / -RebuildStore work on the store without scanning.
# The store engine (ESENT interop, history logic) is compiled on first use only, so a scan runs the same engine
# with or without -Store and nothing store-related is loaded until the scan has finished.
$StoreSource = @'
__STORE_CS__
'@
function Initialize-StoreEngine {
    if ('WebInv.InventoryStore' -as [type]) {
        if ([WebInv.StoreUtil]::Version -ne $ScriptVersion) { throw ("store engine v{0} is already loaded in this PowerShell session (script is v{1}); open a new PowerShell window" -f [WebInv.StoreUtil]::Version, $ScriptVersion) }
        return
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $addType = @{ TypeDefinition = $StoreSource; ErrorAction = 'Stop'; IgnoreWarnings = $true; WarningAction = 'SilentlyContinue' }   # see the engine compile
    if ($PSVersionTable.PSEdition -ne 'Core') { $addType.ReferencedAssemblies = @('System.Core') }
    Add-Type @addType
    if ($script:RunLog) { Write-RunLog ("Store engine compiled in {0} ms" -f $sw.ElapsedMilliseconds) 'DEBUG' }
}
function Resolve-StorePath([string]$Path) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path) }
function Format-Iso([datetime]$T) { ([DateTimeOffset]$T).ToString('yyyy-MM-ddTHH:mm:sszzz', [Globalization.CultureInfo]::InvariantCulture) }

# run.json: when, how (probe switches) and by whom the run was made. The store uses it for timestamps, for keeping
# values a probe that was switched off did not collect, and to refuse incomplete runs.
function Write-RunInfo {
    param([bool]$Complete, [bool]$Interrupted, [bool]$TimeLimit, [int]$Rows, [int]$ExitCode)
    $path = Join-Path $OutputDir ("WebInventory_{0}_run.json" -f $script:RunId)
    $started = Format-Iso $script:ScriptStart
    $sessions = New-Object System.Collections.Generic.List[object]
    # v2.6: the run's UUID (the Tideline run_id) is made once and kept by every session of a resumed run
    $uuid = [guid]::NewGuid().ToString()
    $eng = [string]$Engagement
    if (Test-Path -LiteralPath $path) {
        try {
            $old = [IO.File]::ReadAllText($path) | ConvertFrom-Json
            if ($old.startedAt) { $started = [string]$old.startedAt }
            if ($old.runUuid) { $uuid = [string]$old.runUuid }
            if ($old.engagement -and -not $eng) { $eng = [string]$old.engagement }
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
            throttle = (Get-ThrottleSummary)
        })
    $checks = 0
    if ($script:ProgressPath -and (Test-Path -LiteralPath $script:ProgressPath)) { foreach ($l in [IO.File]::ReadLines($script:ProgressPath)) { if ($l.Trim()) { $checks++ } } }
    $info = [ordered]@{
        format = 1; runId = $script:RunId; runUuid = $uuid; startedAt = $started; finishedAt = (Format-Iso (Get-Date)); complete = $Complete; synthesized = $false
        scanner = "WebInventory $ScriptVersion"; tag = [string]$Tag; engagement = $(if ($eng) { $eng } else { $null }); exitCode = $ExitCode
        operator = $script:Operator; computer = [Environment]::MachineName; checks = $checks
        profile = [ordered]@{
            tlsScan = (-not $NoTlsScan); favicon = (-not $NoFavicon); extras = (-not $NoExtras); options = [bool]$Options
            identifyPaths = [bool]$IdentifyPaths; versionPaths = [bool]$VersionPaths; probeSans = [bool]$ProbeSans; reverseDns = [bool]$ReverseDns
            tlsFingerprint = [bool]$TlsFingerprint; ja4s = ([bool]$TlsFingerprint -and -not $NoJa4s); smb = [bool]$Smb; rdp = [bool]$Rdp; snmp = [bool]$Snmp; screenshot = [bool]$Screenshot
            cname = [bool]$Cname; cloud = [bool]$script:CloudEnabled; apiDocPaths = [bool]$ApiDocPaths
        }
        settings = [ordered]@{ pace = $Pace; threads = $Threads; maxPerHost = $MaxPerHost; timeoutMs = $TimeoutMs; retries = $Retries; ports = $Port; allAddresses = [bool]$AllAddresses
            proxy = $(if ($Proxy) { $proxyLabel } else { '' }); snmp = $(if ($Snmp) { $snmpMode } else { '' })
            cloudRanges = $(if ($script:CloudOn) { [string][WebInv.Cloud]::Version } elseif ($script:CloudEnabled) { 'not needed (no public address)' } else { '' }); dnsServer = [string]$DnsServer
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
        while ((Test-Path -LiteralPath "$base.csv") -or (Test-Path -LiteralPath "$base.jsonl") -or (Test-Path -LiteralPath "$base.html") -or (Test-Path -LiteralPath "$base.provenance.json")) { $n++; $base = '{0}_{1}' -f $stem, $n }
        Write-QueryCsv $q "$base.csv"
        Write-JsonlRows -Path "$base.jsonl" -Names ([string[]]$q.Columns) -Rows $q.Rows
        $files = @("$base.csv", "$base.jsonl")
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
