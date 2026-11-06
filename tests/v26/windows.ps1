<#
Tideline sensor on Windows PowerShell 5.1, against a real step-ca (CI: GitHub's Windows runner, elevated).
  Register-WebInventorySensor.ps1 -Token: certreq.exe key (ECDSA P-256, non-exportable) in the machine key store,
  certificate in LocalMachine\My, intermediate in LocalMachine\CA, root pinned in %ProgramData%\WebInventory;
  -GrantKeyAccess; a scan with -ShipTo using those defaults (Schannel client authentication with the CNG key);
  Send-WebInventoryRun.ps1 -Status / -Export; -Renew -Force through step-ca's rekey endpoint (mutual TLS with the
  current certificate), the old certificate and key removed, the key's readers carried over; shipping again.
  windows.ps1 [-Work <dir>]       downloads step-ca and step (pinned SHA-256); needs python with pip
#>
param([string]$Work = (Join-Path ([IO.Path]::GetTempPath()) 'wi-tideline-win'))
# Continue: under Windows PowerShell 5.1 a native tool's stderr line (step, pip) would otherwise end the script
$ErrorActionPreference = 'Continue'
trap { Write-Host ("::error title=Tideline (Windows) script::{0} | {1}" -f $_.Exception.Message, ($_.InvocationInfo.PositionMessage -replace '\r?\n', ' ')); exit 1 }
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dist = Join-Path $repo 'dist'
$ps = (Get-Process -Id $PID).Path
if (Test-Path -LiteralPath $Work) { Remove-Item -LiteralPath $Work -Recurse -Force }
New-Item -ItemType Directory -Path $Work -Force | Out-Null
$script:pass = 0; $script:fail = 0
function Pass([string]$T) { $script:pass++; Write-Host "PASS $T" -ForegroundColor Green; Write-Host "::notice title=Tideline (Windows)::$T" }
function Fail([string]$T, [string]$File) {
    $script:fail++; Write-Host "FAIL $T" -ForegroundColor Red; Write-Host ("::error title=Tideline (Windows)::{0}" -f ($T -replace '::', ': :'))
    if ($File -and (Test-Path -LiteralPath $File)) {
        $tail = @(Get-Content -LiteralPath $File -Tail 12)
        $tail | ForEach-Object { Write-Host "     | $_" }
        Write-Host ("::warning title=detail::{0}" -f (($tail -join ' | ') -replace '::', ': :' -replace '%', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min(1500, $_.Length)) }))
    }
}
function Run([string]$Name, [string]$Script, [string[]]$Arguments) {
    $out = Join-Path $Work "$Name.txt"
    $p = Start-Process -FilePath $ps -ArgumentList (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Script) + $Arguments) -WorkingDirectory $Work -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError "$out.err"
    if ((Test-Path "$out.err") -and (Get-Item "$out.err").Length) { Get-Content "$out.err" | Add-Content $out }
    $p.ExitCode
}
function Quote([string]$S) { '"' + $S + '"' }

# ---- tools: step-ca and step (pinned), python packages for the mock
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$bin = Join-Path $Work 'bin'; New-Item -ItemType Directory -Path $bin -Force | Out-Null
$dl = @(
    @{ Url = 'https://github.com/smallstep/certificates/releases/download/v0.30.2/step-ca_windows_0.30.2_amd64.zip'; Sha = '89912b33a2100e21dab58ed2f8740e6b61556edf5cf135b860f713506f1ccb71' },
    @{ Url = 'https://github.com/smallstep/cli/releases/download/v0.30.2/step_windows_0.30.2_amd64.zip'; Sha = 'e4b71d4f1cc6c538fdb4f2b3070bfcccc6f214cc9b71bfdf699c8cdb1c4997b8' })
foreach ($d in $dl) {
    $zip = Join-Path $Work (Split-Path -Leaf $d.Url)
    Invoke-WebRequest -Uri $d.Url -OutFile $zip -UseBasicParsing -ErrorAction Stop
    $h = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($h -ne $d.Sha) { throw "$zip has SHA-256 $h, expected $($d.Sha)" }
    Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $Work 'x') -Force -ErrorAction Stop
}
$stepCa = @(Get-ChildItem (Join-Path $Work 'x') -Recurse -Filter step-ca.exe)[0].FullName
$step = @(Get-ChildItem (Join-Path $Work 'x') -Recurse -Filter step.exe)[0].FullName
& python -m pip install --quiet --disable-pip-version-check cryptography jsonschema 2>&1 | Out-Null

# ---- a CA like the platform's: JWK provisioner, 30-day certificates
$env:STEPPATH = Join-Path $Work 'ca'
$pw = Join-Path $Work 'pw.txt'; [IO.File]::WriteAllText($pw, 'test-only-password')
& $step ca init --name 'Tideline CI CA' --dns localhost --dns 127.0.0.1 --address 127.0.0.1:19100 --provisioner sensors@tideline --password-file $pw --provisioner-password-file $pw --deployment-type standalone 2>&1 | Out-File (Join-Path $Work 'init.txt')
if (-not (Test-Path (Join-Path $env:STEPPATH 'config\ca.json'))) { throw ("step ca init failed: " + ((Get-Content (Join-Path $Work 'init.txt')) -join ' | ')) }
$caJson = Join-Path $env:STEPPATH 'config\ca.json'
& python -c "import json,sys; p=sys.argv[1]; c=json.load(open(p)); [pr.__setitem__('claims', {'defaultTLSCertDuration':'720h','maxTLSCertDuration':'720h','minTLSCertDuration':'5m'}) for pr in c['authority']['provisioners']]; json.dump(c, open(p,'w'), indent=2)" $caJson
$rootCrt = Join-Path $env:STEPPATH 'certs\root_ca.crt'; $interCrt = Join-Path $env:STEPPATH 'certs\intermediate_ca.crt'
$caProc = Start-Process -FilePath $stepCa -ArgumentList @((Quote $caJson), '--password-file', (Quote $pw)) -NoNewWindow -PassThru -RedirectStandardOutput (Join-Path $Work 'ca.log') -RedirectStandardError (Join-Path $Work 'ca.err')
$procs = @($caProc)
try {
    for ($i = 0; $i -lt 50; $i++) { $hl = & $step ca health --ca-url https://127.0.0.1:19100 --root $rootCrt 2>$null; if ($hl -match 'ok') { break }; Start-Sleep -Milliseconds 300 }
    $fp = (& $step certificate fingerprint $rootCrt).Trim()

    # the shipping code, to inspect certificates from this test
    $code = [IO.File]::ReadAllText((Join-Path $dist 'Invoke-WebInventory.ps1'))
    if ($code -notmatch "(?s)\`$ShipSource = @'\r?\n(.*?)\r?\n'@") { throw 'shipping code not found' }
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -TypeDefinition $Matches[1] -ReferencedAssemblies System.Core, System.IO.Compression -IgnoreWarnings
    function Get-SensorCerts { $st = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine'); $st.Open('ReadOnly'); try { @($st.Certificates | Where-Object { [WebInv.SensorCert]::SensorId($_) -eq 'wi-ci01' }) } finally { $st.Close() } }
    function Get-KeyAcl($c) { $k = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c); try { $n = $k.Key.UniqueName } finally { $k.Dispose() }; (Get-Acl -LiteralPath (Join-Path $env:ProgramData "Microsoft\Crypto\Keys\$n")).Access | ForEach-Object { [string]$_.IdentityReference } }
    function Test-Exportable($c) { try { [void]$c.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12); $true } catch { $false } }

    # ---- enroll
    $tok = (& $step ca token wi-ci01 --san urn:tideline:sensor:wi-ci01 --ca-url https://127.0.0.1:19100 --root $rootCrt --provisioner sensors@tideline --password-file $pw 2>$null).Trim()
    $rc = Run 'enroll' (Join-Path $dist 'Register-WebInventorySensor.ps1') @('-Token', $tok, '-GrantKeyAccess', (Quote 'NT AUTHORITY\NETWORK SERVICE'))
    $certs = @(Get-SensorCerts)
    $pinned = Join-Path $env:ProgramData 'WebInventory\tideline-root.crt'
    $pinFp = if (Test-Path $pinned) { [WebInv.SensorCert]::Sha256Hex([WebInv.SensorCert]::LoadPem($pinned)[0].RawData) } else { '' }
    $ca = New-Object Security.Cryptography.X509Certificates.X509Store('CA', 'LocalMachine'); $ca.Open('ReadOnly'); $interIn = @($ca.Certificates | Where-Object { $_.Subject -like '*Tideline CI CA Intermediate*' }).Count; $ca.Close()
    if ($rc -eq 0 -and $certs.Count -eq 1 -and $certs[0].HasPrivateKey -and $pinFp -eq $fp -and $interIn -ge 1) { Pass ("enrolled with certreq: {0} in LocalMachine\My, root pinned ({1}), intermediate in LocalMachine\CA" -f $certs[0].Thumbprint, $fp.Substring(0, 16)) }
    else { Fail ("enroll (exit $rc, $($certs.Count) certificates, pin $pinFp, intermediate $interIn)") (Join-Path $Work 'enroll.txt') }
    if ($certs.Count -ne 1) { throw 'enrollment failed; the remaining checks need its certificate' }
    $c1 = $certs[0]
    $k1 = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c1)
    if ($k1 -is [Security.Cryptography.ECDsaCng] -and $k1.KeySize -eq 256 -and $k1.Key.IsMachineKey -and -not (Test-Exportable $c1) -and $k1.Key.ExportPolicy -eq 0) { Pass ("key: ECDSA P-256, machine key ({0}), export refused" -f $k1.Key.Provider) } else { Fail ("key properties: {0} {1} machine={2} exportable={3}" -f $k1.GetType().Name, $k1.KeySize, $k1.Key.IsMachineKey, (Test-Exportable $c1)) }
    $rq = New-Object Security.Cryptography.X509Certificates.X509Store('REQUEST', 'LocalMachine'); $rq.Open('ReadOnly'); $left = @($rq.Certificates | Where-Object { $_.FriendlyName -like 'Tideline sensor request*' }).Count; $rq.Close()
    if ($left -eq 0) { Pass 'no pending certreq request left in LocalMachine\REQUEST' } else { Fail "$left pending request(s) left in LocalMachine\REQUEST" }
    $acl = @(Get-KeyAcl $c1)
    if ($acl -contains 'NT AUTHORITY\NETWORK SERVICE') { Pass 'key readable by NT AUTHORITY\NETWORK SERVICE (-GrantKeyAccess)' } else { Fail ("key ACL: {0}" -f ($acl -join ', ')) }

    # ---- a target, and a Tideline mock with step-ca's server certificate
    & $step ca certificate localhost (Join-Path $Work 'srv.crt') (Join-Path $Work 'srv.key') --san localhost --san 127.0.0.1 --provisioner sensors@tideline --password-file $pw --ca-url https://127.0.0.1:19100 --root $rootCrt 2>&1 | Out-Null
    [IO.File]::WriteAllText((Join-Path $Work 'client-ca.pem'), ([IO.File]::ReadAllText($rootCrt) + [IO.File]::ReadAllText($interCrt)))
    $procs += Start-Process -FilePath python -ArgumentList @('-m', 'http.server', '18080', '--bind', '127.0.0.1') -WorkingDirectory $Work -NoNewWindow -PassThru -RedirectStandardOutput (Join-Path $Work 'web.log') -RedirectStandardError (Join-Path $Work 'web.err')
    $procs += Start-Process -FilePath python -ArgumentList @((Quote (Join-Path $repo 'lab\tideline_mock.py')), 'serve', '--port', '18960', '--cert', (Quote (Join-Path $Work 'srv.crt')), '--key', (Quote (Join-Path $Work 'srv.key')),
        '--client-ca', (Quote (Join-Path $Work 'client-ca.pem')), '--data', (Quote (Join-Path $Work 'mock')), '--schemas', (Quote (Join-Path $repo 'schemas')), '--sensors', 'wi-ci01', '--ready', (Quote (Join-Path $Work 'mock.ready'))) `
        -NoNewWindow -PassThru -RedirectStandardOutput (Join-Path $Work 'mock.log') -RedirectStandardError (Join-Path $Work 'mock.err')
    for ($i = 0; $i -lt 100 -and -not (Test-Path (Join-Path $Work 'mock.ready')); $i++) { Start-Sleep -Milliseconds 100 }

    # ---- scan and ship with the defaults enrollment left (certificate found by its sensor name, pinned root)
    $out = Join-Path $Work 'out'
    $rc = Run 'scan' (Join-Path $dist 'Invoke-WebInventory.ps1') @('-Target', '127.0.0.1:18080', '-OutputDir', (Quote $out), '-NoProgress', '-ShipTo', 'https://localhost:18960', '-Engagement', 'eng-ci')
    $rj = @(Get-ChildItem $out -Filter 'WebInventory_*_run.json')[0].FullName
    $recv = & python (Join-Path $repo 'tests\v26\received.py') --data (Join-Path $Work 'mock') --run-json $rj 2>&1
    if ($rc -eq 0 -and (Get-Content (Join-Path $Work 'scan.txt') -Raw) -match 'delivered.*as sensor wi-ci01' -and $LASTEXITCODE -eq 0) { Pass ("scan shipped over Schannel with the machine key: {0}" -f ("$recv".Substring(0, [Math]::Min(150, "$recv".Length)))) }
    else { Fail ("scan + ship (exit $rc): $recv") (Join-Path $Work 'scan.txt') }
    $rc = Run 'status' (Join-Path $dist 'Send-WebInventoryRun.ps1') @((Quote $out), '-ShipTo', 'https://localhost:18960', '-Status')
    if ($rc -eq 0 -and (Get-Content (Join-Path $Work 'status.txt') -Raw) -match '"state": "verified"') { Pass 'Send-WebInventoryRun -Status: verified' } else { Fail "status (exit $rc)" (Join-Path $Work 'status.txt') }
    $bundle = Join-Path $Work 'bundle.zip'
    $rc = Run 'export' (Join-Path $dist 'Send-WebInventoryRun.ps1') @((Quote $rj), '-Export', (Quote $bundle))
    $vb = & python (Join-Path $repo 'lab\tideline_mock.py') verify-bundle $bundle --ca $rootCrt --schemas (Join-Path $repo 'schemas') 2>&1
    if ($rc -eq 0 -and $LASTEXITCODE -eq 0) { Pass ("export bundle verifies offline (chain from the machine store): {0}" -f ("$vb" -replace '^.*: run', 'run')) } else { Fail "export (exit $rc): $vb" (Join-Path $Work 'export.txt') }

    # ---- renew now: new key through rekey (mutual TLS with the current certificate), old one removed
    $rc = Run 'renew' (Join-Path $dist 'Register-WebInventorySensor.ps1') @('-Renew', '-Force')
    $certs = @(Get-SensorCerts)
    $c2 = $certs | Select-Object -First 1
    $ok = $rc -eq 0 -and $certs.Count -eq 1 -and $c2.Thumbprint -ne $c1.Thumbprint -and -not (Test-Exportable $c2)
    $acl2 = if ($c2) { @(Get-KeyAcl $c2) } else { @() }
    $k2 = if ($c2) { [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c2) } else { $null }
    $newKey = $k2 -and $k2.Key.UniqueName -ne $k1.Key.UniqueName
    $oldKeyGone = -not (Test-Path (Join-Path $env:ProgramData ("Microsoft\Crypto\Keys\{0}" -f $k1.Key.UniqueName)))
    if ($ok -and $newKey -and $oldKeyGone -and $acl2 -contains 'NT AUTHORITY\NETWORK SERVICE') { Pass ("renewed: {0} -> {1}, new non-exportable key, previous certificate and key removed, NETWORK SERVICE kept" -f $c1.Thumbprint.Substring(0, 8), $c2.Thumbprint.Substring(0, 8)) }
    else { Fail ("renew (exit $rc, $($certs.Count) certificates, new key $newKey, old key gone $oldKeyGone, ACL $($acl2 -join ','))") (Join-Path $Work 'renew.txt') }
    $out2 = Join-Path $Work 'out2'
    $rc = Run 'scan2' (Join-Path $dist 'Invoke-WebInventory.ps1') @('-Target', '127.0.0.1:18080', '-OutputDir', (Quote $out2), '-NoProgress', '-ShipTo', 'https://localhost:18960')
    if ($rc -eq 0 -and (Get-Content (Join-Path $Work 'scan2.txt') -Raw) -match 'delivered') { Pass 'shipped with the renewed certificate' } else { Fail "ship after renewal (exit $rc)" (Join-Path $Work 'scan2.txt') }
    $rc = Run 'notdue' (Join-Path $dist 'Register-WebInventorySensor.ps1') @('-Renew')
    if ($rc -eq 0 -and (Get-Content (Join-Path $Work 'notdue.txt') -Raw) -match 'renewal due after') { Pass '-Renew when not due changes nothing' } else { Fail "renew not due (exit $rc)" (Join-Path $Work 'notdue.txt') }
    $rc = Run 'show' (Join-Path $dist 'Register-WebInventorySensor.ps1') @('-Show')
    if ($rc -eq 0 -and (Get-Content (Join-Path $Work 'show.txt') -Raw) -match 'sensor wi-ci01') { Pass '-Show' } else { Fail "show (exit $rc)" (Join-Path $Work 'show.txt') }
}
finally {
    foreach ($p in $procs) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch { } }
    foreach ($c in @(Get-SensorCerts)) { try { $st = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine'); $st.Open('ReadWrite'); $st.Remove($c); $st.Close() } catch { } }
}
Write-Host ("Tideline (Windows): {0} passed, {1} failed" -f $script:pass, $script:fail)
exit $(if ($script:fail) { 1 } else { 0 })
