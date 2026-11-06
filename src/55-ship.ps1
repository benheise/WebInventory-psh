#region ---------- Tideline shipping (-ShipTo): compiled only when used ----------
$ShipSource = @'
__SHIP_CS__
'@

__SHIP_PS__

# before the scan: everything shipping needs is checked here, so a scan never runs for hours and then cannot deliver.
# Nothing is sent to Tideline until the run is complete.
function Initialize-Shipping {
    try { $script:ShipUri = ConvertTo-TidelineUri $ShipTo } catch { Stop-Fatal "-ShipTo: $(Get-InnerMessage $_)" }
    try { Initialize-ShipCode $ScriptVersion } catch { Stop-Fatal "Shipping code compile failed: $(Get-InnerMessage $_)" }
    try { $script:ShipCert = Resolve-ShipCert $ShipCertThumbprint $ShipCertPath $ShipCertPasswordFile } catch { Stop-Fatal "-ShipTo: sensor certificate: $(Get-InnerMessage $_)" }
    try { $script:ShipRoots = Resolve-ShipRoots $ShipCaFile } catch { Stop-Fatal "-ShipTo: $(Get-InnerMessage $_)" }
    # the key must be usable by this account now, not only when the run ends
    try { [void][WebInv.SensorCert]::SignatureHeader([byte[]]@(0), $script:ShipCert) } catch { Stop-Fatal "-ShipTo: $(Get-InnerMessage $_)" }
    $script:ShipSensor = [WebInv.SensorCert]::SensorId($script:ShipCert)
    $left = ($script:ShipCert.NotAfter - (Get-Date)).TotalHours
    Write-RunLog ("Tideline: after the run, ship to {0} as sensor {1} (certificate {2}, valid until {3:u}; root {4})" -f $script:ShipUri, $script:ShipSensor, $script:ShipCert.Thumbprint, $script:ShipCert.NotAfter, $script:ShipRoots[0].Subject)
    if ($left -lt 48) { Write-RunLog ("Tideline: the sensor certificate expires in {0:N0} hours; renew it (Register-WebInventorySensor.ps1 -Renew)" -f $left) 'WARN' }
}

# after the run (and the store ingest): ship it; $false when it could not be delivered
function Invoke-Shipping {
    $rj = Join-Path $OutputDir ("WebInventory_{0}_run.json" -f $script:RunId)
    $sh = New-Object WebInv.Shipper
    $sh.Target = $script:ShipUri; $sh.Cert = $script:ShipCert; $sh.Roots = $script:ShipRoots; $sh.Retries = $ShipRetries; $sh.ToolVersion = $ScriptVersion
    if ($env:WEBINV_SHIP_RETRY_MS) { $sh.RetryDelayMs = [int]$env:WEBINV_SHIP_RETRY_MS }   # tests only
    if ($env:WEBINV_SHIP_CHUNK_BYTES) { [WebInv.ShipRun]::ChunkBytes = [long]$env:WEBINV_SHIP_CHUNK_BYTES }   # tests only
    try {
        $run = [WebInv.ShipRun]::Collect($rj)
        foreach ($n in $run.Notes) { Write-Host ("Tideline: {0}" -f $n) -ForegroundColor DarkGray }
        $res = $sh.Ship($run, [string]$Engagement, $false)
    }
    catch {
        Write-Host ("Tideline: not shipped: {0}" -f (Get-InnerMessage $_)) -ForegroundColor Red
        return $false
    }
    foreach ($l in $res.Log) { Write-Host ("Tideline: {0}" -f $l) -ForegroundColor DarkGray }
    if ($res.Ok) {
        Write-Host ("Tideline: run {0} delivered to {1} as sensor {2} ({3} parts)" -f $res.RunId, $script:ShipUri, $res.Sensor, $res.PartsTotal) -ForegroundColor Cyan
        return $true
    }
    $state = Join-Path $OutputDir ("WebInventory_{0}_ship-state.json" -f $script:RunId)
    if ($res.Retryable) { Write-Host ("Tideline: delivery failed ({0}); retry later: Send-WebInventoryRun.ps1 '{1}' -ShipTo {2}  (state: {3})" -f $res.Error, $OutputDir, $script:ShipUri, $state) -ForegroundColor Yellow }
    else { Write-Host ("Tideline: Tideline refused the run: {0} (state: {1})" -f $res.Error, $state) -ForegroundColor Red }
    $false
}

# -NvdFeed on a scan run: this run's services joined offline with NVD/KEV/EPSS, the same matching as
# -StoreQuery Vulnerabilities; WebInventory_<RunId>_vulns.csv / .jsonl / .provenance.json are part of the run
function Invoke-RunVulnerabilities {
    param([string]$CsvFile)
    Initialize-StoreEngine
    [void][WebInv.Vulns]::SetAliases($CpeSupplementJson)
    $svcs = New-Object 'System.Collections.Generic.List[WebInv.Vulns+Service]'
    foreach ($r in @(Import-Csv -LiteralPath $CsvFile)) {
        if (-not $r.CPEs) { continue }
        $s = New-Object 'WebInv.Vulns+Service'
        $s.Host = $r.Host; $s.Ip = $r.IP; $s.Port = $r.Port; $s.Url = $r.Url; $s.Status = 'Active'; $s.Products = $r.Products; $s.EntityId = ''
        foreach ($c in ($r.CPEs -split ';')) { $x = [WebInv.Cpe]::Parse($c.Trim()); if ($x) { $s.Cpes.Add($x) } }
        if ($s.Cpes.Count) { $svcs.Add($s) }
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $q = [WebInv.Vulns]::Run($svcs, [string[]]$script:NvdFeeds, [string]$script:KevPath, [string]$script:EpssPath, (New-Object 'System.Collections.Generic.List[WebInv.RowFilter]'), '', [string]$script:RunId)
    foreach ($m in $q.Messages) { Write-RunLog ("Vulnerabilities: {0}" -f $m) }
    $base = Join-Path $OutputDir ("WebInventory_{0}_vulns" -f $script:RunId)
    Write-QueryCsv $q "$base.csv"
    Write-JsonlRows -Path "$base.jsonl" -Names ([string[]]$q.Columns) -Rows $q.Rows
    [IO.File]::WriteAllText("$base.provenance.json", $q.Provenance + "`n", $script:Utf8NoBom)
    $msg = "Vulnerabilities: {0} service-CVE rows for {1} services with a CPE in {2:N1} s -> {3}.csv" -f $q.Rows.Count, $svcs.Count, $sw.Elapsed.TotalSeconds, $base
    Write-RunLog $msg
    if (-not $Quiet) { Write-Host $msg -ForegroundColor Cyan }
    @("$base.csv", "$base.jsonl", "$base.provenance.json")
}
#endregion

#region ---------- shipping self-test (part of -SelfTest; no network) ----------
function Invoke-ShipSelfTest {
    try { Initialize-ShipCode $ScriptVersion } catch { Assert 'Tideline: shipping code compiles' { $false }; return }
    Assert 'Tideline: shipping code compiles' { $true }
    $X = 'System.Security.Cryptography.X509Certificates'
    function New-TestCert([string]$Cn, [string[]]$Uris, $Issuer, [string]$Eku, [bool]$Ca) {
        $k = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $req = New-Object "$X.CertificateRequest" ("CN=$Cn", $k, [Security.Cryptography.HashAlgorithmName]::SHA256)
        if ($Uris) { $b = New-Object "$X.SubjectAlternativeNameBuilder"; foreach ($u in $Uris) { $b.AddUri([Uri]$u) }; $req.CertificateExtensions.Add($b.Build()) }
        if ($Eku) { $o = New-Object Security.Cryptography.OidCollection; [void]$o.Add((New-Object Security.Cryptography.Oid $Eku)); $req.CertificateExtensions.Add((New-Object "$X.X509EnhancedKeyUsageExtension" ($o, $false))) }
        if ($Ca) { $req.CertificateExtensions.Add((New-Object "$X.X509BasicConstraintsExtension" ($true, $false, 0, $true))) }
        $nb = [DateTimeOffset]::UtcNow.AddMinutes(-5); $na = [DateTimeOffset]::UtcNow.AddDays(30)
        if ($Issuer) { $c = $req.Create($Issuer, $nb, $na, [byte[]]@(1, 2, 3, 4, 5, 6, 7, 8)); return [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($c, $k) }
        $req.CreateSelfSigned($nb, $na)
    }
    Assert 'Tideline: JSON reads and writes back the same ASCII bytes' {
        $q = [char]92; $t = '{"a":[1,2.5,true,null,"' + $q + 'u00e9' + $q + '"x' + $q + $q + 'y"],"b":{},"c":-7}'
        [WebInv.TJson]::Write([WebInv.TJson]::Parse($t)) -ceq $t
    }
    Assert 'Tideline: sensor id from the urn:tideline:sensor URI name; two ids are refused' {
        $a = New-TestCert 'wi-self' @('urn:tideline:sensor:wi-self') $null '1.3.6.1.5.5.7.3.2' $false
        $b = New-TestCert 'x' @('urn:tideline:sensor:one', 'urn:tideline:sensor:two') $null $null $false
        $c = New-TestCert 'x' @('https://example.invalid/') $null $null $false
        [WebInv.SensorCert]::SensorId($a) -eq 'wi-self' -and [WebInv.SensorCert]::ClientAuth($a) -and $null -eq [WebInv.SensorCert]::SensorId($b) -and $null -eq [WebInv.SensorCert]::SensorId($c)
    }
    Assert 'Tideline: ES256 manifest signature (P1363) verifies; changed bytes do not' {
        $a = New-TestCert 'wi-self' @('urn:tideline:sensor:wi-self') $null $null $false
        $data = [Text.Encoding]::ASCII.GetBytes('{"schema":"tideline-envelope/1"}')
        $h = [WebInv.SensorCert]::SignatureHeader($data, $a)
        $sig = [Convert]::FromBase64String(($h -split 'sig=')[1])
        $pub = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($a)
        $h -like 'alg=ES256; enc=p1363; sig=*' -and $sig.Length -eq 64 -and $pub.VerifyData($data, $sig, [Security.Cryptography.HashAlgorithmName]::SHA256) -and
            -not $pub.VerifyData([Text.Encoding]::ASCII.GetBytes('{"schema":"tideline-envelope/2"}'), $sig, [Security.Cryptography.HashAlgorithmName]::SHA256)
    }
    Assert 'Tideline: the server must chain to the pinned root, not another' {
        $root = New-TestCert 'Test Root' $null $null $null $true
        $other = New-TestCert 'Other Root' $null $null $null $true
        $leaf = New-TestCert 'localhost' $null $root '1.3.6.1.5.5.7.3.1' $false
        $r1 = New-Object "$X.X509Certificate2Collection"; [void]$r1.Add((New-Object "$X.X509Certificate2" (, $root.RawData)))
        $r2 = New-Object "$X.X509Certificate2Collection"; [void]$r2.Add((New-Object "$X.X509Certificate2" (, $other.RawData)))
        $w1 = ''; $w2 = ''
        [WebInv.PinnedTls]::ChainsTo($leaf, $null, $r1, $true, [ref]$w1) -and -not [WebInv.PinnedTls]::ChainsTo($leaf, $null, $r2, $true, [ref]$w2) -and $w2 -match 'pinned root'
    }
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('wi-ship-st-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    try {
        $id = '20260102_030405'; $stem = Join-Path $dir "WebInventory_$id"
        $lines = @('{"Host":"a","Port":80}', '{"Host":"b","Port":443}', '{"Host":"c","Port":8080}')
        [IO.File]::WriteAllText("$stem.jsonl", (($lines -join "`n") + "`n"), $script:Utf8NoBom)
        [IO.File]::WriteAllText("${stem}_errors.jsonl", '', $script:Utf8NoBom)
        $info = [ordered]@{ format = 1; runId = $id; runUuid = '11111111-2222-4333-8444-555555555555'; startedAt = '2026-01-02T03:04:05+01:00'; finishedAt = '2026-01-02T03:14:05+01:00'
            complete = $true; scanner = 'WebInventory 2.6.0'; engagement = 'eng-1'; exitCode = 0; computer = 'HOST'; profile = [ordered]@{ tlsScan = $true }; sessions = @() }
        [IO.File]::WriteAllText("${stem}_run.json", (ConvertTo-Json -InputObject $info -Depth 4), $script:Utf8NoBom)
        $wm = { $m = @('# test manifest', '# sha256  bytes  file'); foreach ($f in "$stem.jsonl", "${stem}_errors.jsonl", "${stem}_run.json") { $b = [IO.File]::ReadAllBytes($f); $m += ('{0}  {1}  {2}' -f [WebInv.Hash]::Sha256Hex($b), $b.Length, (Split-Path -Leaf $f)) }; [IO.File]::WriteAllLines("${stem}_manifest.txt", [string[]]$m, $script:Utf8NoBom) }
        & $wm
        Assert 'Tideline: a run folder becomes services, errors, run.json and manifest parts; deterministic manifest' {
            $r = [WebInv.ShipRun]::Collect("${stem}_run.json")
            $k = @($r.Parts | ForEach-Object { if ($_.Kind -eq 'artifact') { 'artifact:' + $_.Role } else { $_.Kind } }) -join ','
            $m1 = $r.Manifest('wi-self', $r.RunUuid, 'eng-1'); $m2 = ([WebInv.ShipRun]::Collect("${stem}_run.json")).Manifest('wi-self', $r.RunUuid, 'eng-1')
            $mt = [Text.Encoding]::ASCII.GetString($m1)
            $k -eq 'services,errors,artifact:run-info,artifact:tool-manifest' -and $r.Parts[0].Records -eq 3 -and $r.Parts[1].Records -eq 0 -and
                [WebInv.SensorCert]::Sha256Hex($m1) -eq [WebInv.SensorCert]::Sha256Hex($m2) -and $mt -like '*"started":"2026-01-02T02:04:05Z"*' -and $mt -like '*"run_id":"11111111-2222-4333-8444-555555555555"*'
        }
        Assert 'Tideline: a large NDJSON file goes as chunks that end at line ends and add up to the file' {
            $old = [WebInv.ShipRun]::ChunkBytes
            try {
                [WebInv.ShipRun]::ChunkBytes = 30
                $r = [WebInv.ShipRun]::Collect("${stem}_run.json")
                $ch = @($r.Parts | Where-Object { $_.Kind -eq 'services' })
                $all = [IO.File]::ReadAllBytes("$stem.jsonl")
                $ok = $ch.Count -eq 3 -and ($ch | Measure-Object Bytes -Sum).Sum -eq $all.Length -and ($ch | Measure-Object Records -Sum).Sum -eq 3
                foreach ($c in $ch) { $ok = $ok -and $all[$c.Offset + $c.Bytes - 1] -eq 10 -and $c.Chunks -eq 3 -and $c.FileSha256 -eq [WebInv.SensorCert]::Sha256Hex($all) }
                $ok
            }
            finally { [WebInv.ShipRun]::ChunkBytes = $old }
        }
        Assert 'Tideline: an NDJSON part is uploaded gzip-compressed and decompresses to the file' {
            $r = [WebInv.ShipRun]::Collect("${stem}_run.json")
            $gz = [WebInv.ShipRun]::Body($r.Parts[0])
            $in = New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream (, $gz)), [IO.Compression.CompressionMode]::Decompress)
            $out = New-Object IO.MemoryStream; $in.CopyTo($out)
            [WebInv.SensorCert]::Sha256Hex($out.ToArray()) -eq [WebInv.SensorCert]::Sha256Hex([IO.File]::ReadAllBytes("$stem.jsonl")) -and $gz[0] -eq 0x1f -and $gz[1] -eq 0x8b
        }
        Assert 'Tideline: a file changed after the run manifest, or an incomplete run, is refused' {
            [IO.File]::AppendAllText("$stem.jsonl", '{"Host":"d","Port":1}' + "`n")
            $changed = try { [void][WebInv.ShipRun]::Collect("${stem}_run.json"); $false } catch { (Get-InnerMessage $_) -match 'changed after the run' }
            & $wm
            $info.complete = $false; [IO.File]::WriteAllText("${stem}_run.json", (ConvertTo-Json -InputObject $info -Depth 4), $script:Utf8NoBom)
            $partial = try { [void][WebInv.ShipRun]::Collect("${stem}_run.json"); $false } catch { (Get-InnerMessage $_) -match 'not complete' }
            $changed -and $partial
        }
    }
    finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    Assert 'Tideline: engagement ids and URLs are checked' {
        (Test-EngagementId 'eng-2026.014_a') -and -not (Test-EngagementId 'bad id') -and -not (Test-EngagementId '-x') -and
            $(try { [void](ConvertTo-TidelineUri 'http://x:8443'); $false } catch { $true }) -and $(try { [void](ConvertTo-TidelineUri 'https://u:p@x:8443'); $false } catch { $true }) -and
            (ConvertTo-TidelineUri 'https://tideline.example:8443').Port -eq 8443
    }
}
#endregion
