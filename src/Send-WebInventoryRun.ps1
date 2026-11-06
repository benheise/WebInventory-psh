<#
.SYNOPSIS
    Sends finished WebInventory runs to Tideline, resumes deliveries that stopped, shows a run's status at Tideline,
    or writes a bundle to carry to Tideline by hand. Sends nothing to scanned hosts.

.DESCRIPTION
    A run is shipped as a signed envelope: a manifest naming every part with its SHA-256, then the parts (the run's
    JSONL files, run.json, manifest, logs and screenshots, unchanged; NDJSON and text gzip-compressed), over HTTPS
    with mutual TLS. The sensor certificate authenticates the host and signs the manifest (ES256); the server must
    chain to the pinned Tideline root. Only complete runs are shipped, and only when every file still matches the
    run's own manifest.

    Delivery state is kept in WebInventory_<RunId>_ship-state.json next to the run. A later call sends only the parts
    Tideline lists as missing, so it is safe to run on a schedule over a whole output folder: runs already delivered
    are skipped.

    Exit codes: 0 = every run delivered (or already delivered); 1 = refused before sending (arguments, certificate,
    an incomplete or changed run); 2 = delivery failed, retry later (network, server busy); 3 = Tideline refused a run.

.PARAMETER Path
    Run folders (every run in them), or any file of a run (its run.json, CSV, JSONL, manifest or ship-state).
.PARAMETER ShipTo
    Tideline ingest URL (https://host:8443).
.PARAMETER ShipCertThumbprint
    Sensor certificate in LocalMachine\My or CurrentUser\My. Default: the newest valid urn:tideline:sensor:<id>
    certificate there with its private key.
.PARAMETER ShipCertPath
    PFX file instead of the certificate store (default off Windows: ~/.config/webinventory/tideline-sensor.pfx).
.PARAMETER ShipCertPasswordFile
    File whose first line is the PFX password.
.PARAMETER ShipCaFile
    Tideline root CA (PEM). Default: the root Register-WebInventorySensor.ps1 saved.
.PARAMETER Engagement
    Engagement id for runs made without one (a run made for an engagement keeps it).
.PARAMETER Export
    Write one bundle file (zip: manifest, signature, the sensor's certificate chain, the parts) instead of
    sending; for a host that cannot reach Tideline. One run per bundle.
.PARAMETER Status
    Ask Tideline for the state of each run (runs never shipped to this URL are listed as such).
.PARAMETER Force
    Send again a run this URL already confirmed (Tideline answers with the state it holds).
.PARAMETER Retries
    Attempts after the first per run (default 3; waits 5 s, 15 s, 45 s).

.EXAMPLE
    .\Send-WebInventoryRun.ps1 D:\scans -ShipTo https://tideline.corp.example:8443
.EXAMPLE
    .\Send-WebInventoryRun.ps1 D:\scans\WebInventory_20261106_140211_run.json -Export E:\carry\scan01.zip
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][string[]]$Path,
    [string]$ShipTo,
    [string]$ShipCertThumbprint,
    [string]$ShipCertPath,
    [string]$ShipCertPasswordFile,
    [string]$ShipCaFile,
    [string]$Engagement,
    [string]$Export,
    [switch]$Status,
    [switch]$Force,
    [ValidateRange(0, 10)][int]$Retries = 3,
    [ValidateRange(5, 600)][int]$TimeoutSec = 60
)
$ErrorActionPreference = 'Stop'
$ScriptVersion = '__VERSION__'

$ShipSource = @'
__SHIP_CS__
'@

__SHIP_PS__

function Write-Line([string]$Text, [string]$Color = 'Gray') { Write-Host $Text -ForegroundColor $Color }
function Stop-Refused([string]$Text) { Write-Line "REFUSED: $Text" 'Red'; exit 1 }
function Get-Inner($e) { Get-InnerMessage $e }

if ($Export -and ($ShipTo -or $Status)) { Stop-Refused '-Export writes a bundle instead of sending; give it without -ShipTo / -Status' }
if (-not $Export -and -not $ShipTo) { Stop-Refused 'give -ShipTo <https://tideline:8443>, or -Export <bundle.zip>' }
if ($ShipCertPasswordFile -and -not $ShipCertPath) { Stop-Refused '-ShipCertPasswordFile goes with -ShipCertPath' }
if ($Engagement -and -not (Test-EngagementId $Engagement)) { Stop-Refused "-Engagement '$Engagement': letters, digits, '.', '_' and '-', up to 64" }
try { Initialize-ShipCode $ScriptVersion } catch { Stop-Refused "shipping code compile failed: $(Get-Inner $_)" }
$uri = $null
if ($ShipTo) { try { $uri = ConvertTo-TidelineUri $ShipTo } catch { Stop-Refused "-ShipTo: $(Get-Inner $_)" } }
try { $cert = Resolve-ShipCert $ShipCertThumbprint $ShipCertPath $ShipCertPasswordFile } catch { Stop-Refused "sensor certificate: $(Get-Inner $_)" }
try { $roots = Resolve-ShipRoots $ShipCaFile } catch { if ($Export) { $roots = $null } else { Stop-Refused (Get-Inner $_) } }
try { [void][WebInv.SensorCert]::SignatureHeader([byte[]]@(0), $cert) } catch { Stop-Refused (Get-Inner $_) }
$sensor = [WebInv.SensorCert]::SensorId($cert)

$runs = New-Object System.Collections.Generic.List[string]
$swept = New-Object 'System.Collections.Generic.HashSet[string]'   # found by listing a folder (not named one by one)
foreach ($p in $Path) {
    try {
        $isDir = Test-Path -LiteralPath $p -PathType Container
        foreach ($r in (Get-RunJsonPaths $p)) { if (-not $runs.Contains($r)) { $runs.Add($r); if ($isDir) { [void]$swept.Add($r) } } }
    }
    catch { Stop-Refused (Get-Inner $_) }
}
if (-not $runs.Count) { Write-Line 'No runs found (WebInventory_*_run.json).' 'Yellow'; exit 0 }
if ($Export -and $runs.Count -ne 1) { Stop-Refused ("-Export takes one run ({0} found); name its run.json" -f $runs.Count) }
Write-Line ("WebInventory {0}: {1} run(s); sensor {2} (certificate {3}, valid until {4:u})" -f $ScriptVersion, $runs.Count, $sensor, $cert.Thumbprint, $cert.NotAfter) 'Cyan'

if ($Export) {
    try {
        $run = [WebInv.ShipRun]::Collect($runs[0])
        foreach ($n in $run.Notes) { Write-Line ("  {0}" -f $n) 'DarkGray' }
        $out = [IO.Path]::GetFullPath($Export)
        $n = [WebInv.Shipper]::Export($run, $cert, $roots, [string]$Engagement, $out, $ScriptVersion)
        Write-Line ("Bundle for run {0}: {1} parts -> {2} ({3:N0} bytes)" -f $run.ToolRun, $n, $out, (Get-Item -LiteralPath $out).Length) 'Cyan'
        exit 0
    }
    catch { Stop-Refused (Get-Inner $_) }
}

$sh = New-Object WebInv.Shipper
$sh.Target = $uri; $sh.Cert = $cert; $sh.Roots = $roots; $sh.Retries = $Retries; $sh.TimeoutMs = $TimeoutSec * 1000; $sh.ToolVersion = $ScriptVersion
if ($env:WEBINV_SHIP_RETRY_MS) { $sh.RetryDelayMs = [int]$env:WEBINV_SHIP_RETRY_MS }   # tests only
if ($env:WEBINV_SHIP_CHUNK_BYTES) { [WebInv.ShipRun]::ChunkBytes = [long]$env:WEBINV_SHIP_CHUNK_BYTES }   # tests only
$worst = 0
foreach ($rj in $runs) {
    $label = Split-Path -Leaf $rj
    if (-not $Status -and -not $Force -and $sh.DeliveredBefore($rj)) { Write-Line ("{0}: already delivered" -f $label) 'Green'; continue }
    try { $run = [WebInv.ShipRun]::Collect($rj) }
    catch {
        $why = Get-Inner $_
        # a folder sweep passes over runs that are still going or were interrupted; a run named on its own is refused
        if ($swept.Contains($rj) -and $why -match 'is not complete') { Write-Line ("{0}: skipped: {1}" -f $label, $why) 'DarkGray'; continue }
        Write-Line ("{0}: not shipped: {1}" -f $label, $why) 'Yellow'; if ($worst -lt 1) { $worst = 1 }; continue
    }
    if ($Status) {
        $e = $sh.Entry($run)
        if (-not $e) { Write-Line ("{0}: run {1} never shipped to {2}" -f $label, $run.ToolRun, $uri); continue }
        try {
            $r = $sh.Status($e.Str('run_id'))
            Write-Line ("{0}: run {1} (Tideline run {2}): local state {3}; Tideline HTTP {4} {5}" -f $label, $run.ToolRun, $e.Str('run_id'), $e.Str('state'), $r.Status, $r.Text.Trim())
        }
        catch { Write-Line ("{0}: status query failed: {1}" -f $label, (Get-Inner $_)) 'Yellow'; if ($worst -lt 2) { $worst = 2 } }
        continue
    }
    foreach ($n in $run.Notes) { Write-Line ("  {0}" -f $n) 'DarkGray' }
    try { $res = $sh.Ship($run, [string]$Engagement, [bool]$Force) }
    catch { Write-Line ("{0}: not shipped: {1}" -f $label, (Get-Inner $_)) 'Yellow'; if ($worst -lt 1) { $worst = 1 }; continue }
    foreach ($l in $res.Log) { Write-Line ("  {0}" -f $l) 'DarkGray' }
    if ($res.Ok) { Write-Line ("{0}: {1} (Tideline run {2})" -f $label, $(if ($res.AlreadyComplete) { 'already delivered' } else { 'delivered' }), $res.RunId) 'Green' }
    elseif ($res.Retryable) { Write-Line ("{0}: delivery failed, retry later: {1}" -f $label, $res.Error) 'Yellow'; if ($worst -lt 2) { $worst = 2 } }
    else { Write-Line ("{0}: refused by Tideline: {1}" -f $label, $res.Error) 'Red'; $worst = 3 }
}
exit $worst
