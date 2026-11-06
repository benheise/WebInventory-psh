<#
.SYNOPSIS
    Enrolls this host as a Tideline sensor with step-ca, renews its certificate with a new key, or shows it.
    Nothing to install: certreq.exe and .NET Framework 4.7.2 on Windows, .NET on PowerShell 7 elsewhere.

.DESCRIPTION
    Enroll (-Token): the Tideline administrator makes a one-time token on the CA, for example
        step ca token wi-scan01 --san urn:tideline:sensor:wi-scan01
    and hands it over (it is valid for five minutes). The token names the CA, the root fingerprint and the sensor's
    names. This script fetches the root by that fingerprint, checks the CA's TLS certificate against it, creates
    the key, sends a certificate request with the token, and installs the certificate:
      - Windows: certreq.exe creates a non-exportable ECDSA P-256 key in the machine key store and binds the
        issued certificate to it in LocalMachine\My (run elevated). The CA's intermediate goes to LocalMachine\CA.
      - Elsewhere: an ECDSA P-256 key and the certificate in ~/.config/webinventory/tideline-sensor.pfx (mode 0600).
    The pinned root goes to %ProgramData%\WebInventory\tideline-root.crt (~/.config/webinventory/ elsewhere), with
    tideline-sensor.json recording the CA URL. Invoke-WebInventory.ps1 -ShipTo and Send-WebInventoryRun.ps1 use both
    by default.

    Renew (-Renew): when a third or less of the certificate's lifetime is left (or with -Force), a new key and a
    request go to step-ca's rekey endpoint over mutual TLS with the current certificate; step-ca copies the
    certificate's names, so a renewal cannot change the sensor's identity. The previous certificate and its key are
    then removed (-KeepPrevious keeps them). Schedule it daily; a certificate that has expired cannot renew and must
    be enrolled again with a new token.

    Exit codes: 0 = done or not due; 1 = refused (arguments, token, elevation, no certificate); 2 = the CA refused or
    could not be reached.

.PARAMETER Token
    One-time token from 'step ca token' (JWK provisioner).
.PARAMETER Renew
    Renew the current sensor certificate with a new key (when due, or with -Force).
.PARAMETER Show
    Show the sensor certificate(s), the pinned root and the CA URL.
.PARAMETER CaUrl
    The CA (https://ca:9000). Default: from the token; for -Renew from tideline-sensor.json.
.PARAMETER NotAfter
    Requested lifetime, for example 720h (the CA's provisioner limits apply).
.PARAMETER Thumbprint
    -Renew: the certificate to renew (default: the newest valid sensor certificate).
.PARAMETER PfxPath
    Off Windows: where the certificate and key are kept (default ~/.config/webinventory/tideline-sensor.pfx).
.PARAMETER GrantKeyAccess
    Windows: accounts that may use the private key (for example the account of the scheduled scan), besides
    SYSTEM and Administrators.
.PARAMETER KeepPrevious
    -Renew: leave the previous certificate and key in place.
.PARAMETER Force
    -Renew: renew now, whatever time is left.

.EXAMPLE
    .\Register-WebInventorySensor.ps1 -Token (Get-Content .\token.txt) -GrantKeyAccess 'CORP\svc-webinv'
.EXAMPLE
    .\Register-WebInventorySensor.ps1 -Renew
#>
[CmdletBinding(DefaultParameterSetName = 'Show')]
param(
    [Parameter(ParameterSetName = 'Enroll', Mandatory = $true)][string]$Token,
    [Parameter(ParameterSetName = 'Renew', Mandatory = $true)][switch]$Renew,
    [Parameter(ParameterSetName = 'Show')][switch]$Show,
    [string]$CaUrl,
    [string]$NotAfter,
    [Parameter(ParameterSetName = 'Renew')][string]$Thumbprint,
    [string]$PfxPath,
    [string[]]$GrantKeyAccess,
    [Parameter(ParameterSetName = 'Renew')][switch]$KeepPrevious,
    [Parameter(ParameterSetName = 'Renew')][switch]$Force,
    [ValidateRange(5, 600)][int]$TimeoutSec = 30
)
$ErrorActionPreference = 'Stop'
$ScriptVersion = '__VERSION__'

$ShipSource = @'
__SHIP_CS__
'@

__SHIP_PS__

$onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
function Write-Line([string]$Text, [string]$Color = 'Gray') { Write-Host $Text -ForegroundColor $Color }
function Stop-With([int]$Code, [string]$Text) { Write-Line $(if ($Code -eq 1) { "REFUSED: $Text" } else { "FAILED: $Text" }) 'Red'; exit $Code }
function Get-Inner($e) { Get-InnerMessage $e }
function ConvertFrom-B64Url([string]$S) { $t = $S.Replace('-', '+').Replace('_', '/'); switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }; [Convert]::FromBase64String($t) }

try { Initialize-ShipCode $ScriptVersion } catch { Stop-With 1 "shipping code compile failed: $(Get-Inner $_)" }
$dir = Get-TidelineDir
$rootFile = Join-Path $dir 'tideline-root.crt'
$infoFile = Join-Path $dir 'tideline-sensor.json'
if (-not $PfxPath) { $PfxPath = Join-Path $dir 'tideline-sensor.pfx' }
if ($onWindows -and $PSBoundParameters.ContainsKey('PfxPath')) { Stop-With 1 '-PfxPath is for hosts without a Windows certificate store; on Windows the key stays in the machine key store' }
if ($GrantKeyAccess -and -not $onWindows) { Stop-With 1 '-GrantKeyAccess is for Windows (the PFX is readable by its owner only)' }
$timeout = $TimeoutSec * 1000

function Test-Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

function Get-CaBase([string]$Url) {
    $u = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne 'https') { throw "'$Url' is not an https:// CA URL" }
    $p = $u.AbsolutePath -replace '/1\.0/sign$', '' -replace '/$', ''
    [Uri]($u.GetLeftPart([UriPartial]::Authority) + $p + '/')
}

# a CA call; $Client = $null for enrollment, the current certificate for rekey (mutual TLS)
function Invoke-Ca([Uri]$Base, [string]$Method, [string]$Path, [string]$Json, $Client, $Roots) {
    $pin = New-Object WebInv.PinnedTls; $pin.Roots = $Roots
    $h = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $body = $null
    if ($null -ne $Json) { $h['Content-Type'] = 'application/json'; $body = [Text.Encoding]::UTF8.GetBytes($Json) }
    $path = $Base.AbsolutePath.TrimEnd('/') + $Path
    [WebInv.Https]::Send($Base, $Method, $path, $h, $body, $Client, $pin, $timeout)
}
function Get-CaError($r) { $j = $r.Json; $m = if ($j -and $j.Str('message')) { $j.Str('message') } else { $r.Text.Trim() }; "HTTP {0}: {1}" -f $r.Status, $m }

# the root from the CA, accepted only when its SHA-256 is the fingerprint the token carries; then the CA's own TLS
# certificate must chain to it and name the host
function Get-PinnedRoot([Uri]$Base, [string]$Fingerprint) {
    $pin = New-Object WebInv.PinnedTls; $pin.Bootstrap = $true
    $r = [WebInv.Https]::Send($Base, 'GET', ($Base.AbsolutePath.TrimEnd('/') + '/root/' + $Fingerprint), $null, $null, $null, $pin, $timeout)
    if ($r.Status -ne 200) { throw ("fetching the root: {0}" -f (Get-CaError $r)) }
    $pem = $r.Json.Str('ca')
    if (-not $pem) { throw 'the CA answered without a root certificate' }
    $der = @([WebInv.SensorCert]::PemBlocks($pem, 'CERTIFICATE'))
    if ($der.Count -ne 1) { throw 'the CA answered with no single root certificate' }
    $fp = [WebInv.SensorCert]::Sha256Hex($der[0])
    if ($fp -ne $Fingerprint.ToLowerInvariant()) { throw "the root the CA sent has fingerprint $fp, the token names $Fingerprint" }
    $roots = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    [void]$roots.Add((New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]$der[0])))
    $pin.Roots = $roots
    $why = ''
    if (-not $pin.Check([ref]$why)) { throw "the CA's TLS certificate does not check out against that root: $why" }
    $roots
}

function Save-TidelineFiles($Roots, [Uri]$Base, [string]$Sensor, $Cert) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        if (-not $onWindows) { [IO.File]::SetUnixFileMode($dir, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute') }
    }
    [IO.File]::WriteAllText($rootFile, [WebInv.SensorCert]::Pem($Roots[0].RawData, 'CERTIFICATE'), (New-Object Text.UTF8Encoding($false)))
    $info = [ordered]@{ format = 1; caUrl = $Base.ToString().TrimEnd('/'); rootFingerprint = [WebInv.SensorCert]::Sha256Hex($Roots[0].RawData); sensor = $Sensor
        thumbprint = $Cert.Thumbprint; notBefore = $Cert.NotBefore.ToUniversalTime().ToString('o'); notAfter = $Cert.NotAfter.ToUniversalTime().ToString('o')
        store = $(if ($onWindows) { 'LocalMachine\My' } else { $PfxPath }); updated = (Get-Date).ToUniversalTime().ToString('o'); by = "Register-WebInventorySensor $ScriptVersion" }
    [IO.File]::WriteAllText($infoFile, ((ConvertTo-Json -InputObject $info) + "`n"), (New-Object Text.UTF8Encoding($false)))
}

# ---- Windows: certreq.exe makes a non-exportable ECDSA P-256 key in the machine key store ----
function New-WindowsRequest([string]$Subject, [string[]]$Sans, [string]$Work) {
    $sanText = @(foreach ($s in $Sans) {
            $ip = $null
            if ($s -match '^[a-z][a-z0-9+.-]*:' -and $s -notmatch '@') { 'url={0}' -f $s }
            elseif ([Net.IPAddress]::TryParse($s, [ref]$ip)) { 'ipaddress={0}' -f $s }
            elseif ($s -match '@') { 'email={0}' -f $s }
            else { 'dns={0}' -f $s }
        })
    $inf = @('[Version]', 'Signature="$Windows NT$"', '', '[NewRequest]', ('Subject = "CN={0}"' -f $Subject),
        'KeyAlgorithm = ECDSA_P256', 'KeyLength = 256', 'HashAlgorithm = SHA256', 'MachineKeySet = TRUE', 'Exportable = FALSE',
        'ProviderName = "Microsoft Software Key Storage Provider"', 'KeyUsage = "CERT_DIGITAL_SIGNATURE_KEY_USAGE"', 'RequestType = PKCS10',
        'SMIME = FALSE', ('FriendlyName = "Tideline sensor {0}"' -f $Subject), '', '[EnhancedKeyUsageExtension]', 'OID = 1.3.6.1.5.5.7.3.2', '',
        '[Extensions]', '2.5.29.17 = "{text}"')
    foreach ($t in $sanText) { $inf += ('_continue_ = "{0}&"' -f $t) }
    $infPath = Join-Path $Work 'sensor.inf'; $reqPath = Join-Path $Work 'sensor.req'
    [IO.File]::WriteAllLines($infPath, [string[]]$inf, [Text.Encoding]::ASCII)
    $out = & certreq.exe -new -q -machine $infPath $reqPath 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $reqPath)) { throw ("certreq -new failed ({0}): {1}" -f $LASTEXITCODE, (($out | Out-String) -replace '\s+', ' ').Trim()) }
    $b64 = ([IO.File]::ReadAllText($reqPath) -replace '-----[A-Z ]+-----', '' -replace '\s', '')
    [WebInv.SensorCert]::Pem([Convert]::FromBase64String($b64), 'CERTIFICATE REQUEST')
}
function Install-WindowsCert([string]$LeafPem, [string[]]$ChainPem, [string]$Work) {
    $crt = Join-Path $Work 'sensor.crt'
    [IO.File]::WriteAllText($crt, $LeafPem, [Text.Encoding]::ASCII)
    $out = & certreq.exe -accept -q -machine $crt 2>&1
    if ($LASTEXITCODE -ne 0) { throw ("certreq -accept failed ({0}): {1}" -f $LASTEXITCODE, (($out | Out-String) -replace '\s+', ' ').Trim()) }
    $leaf = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]@([WebInv.SensorCert]::PemBlocks($LeafPem, 'CERTIFICATE'))[0])
    $st = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine'); $st.Open('ReadOnly')
    try { $c = @($st.Certificates.Find('FindByThumbprint', $leaf.Thumbprint, $false))[0] } finally { $st.Close() }
    if (-not $c -or -not $c.HasPrivateKey) { throw "the certificate $($leaf.Thumbprint) is not in LocalMachine\My with its key after certreq -accept" }
    # intermediates, so that Schannel sends the chain
    $ca = New-Object Security.Cryptography.X509Certificates.X509Store('CA', 'LocalMachine'); $ca.Open('ReadWrite')
    try { foreach ($p in $ChainPem) { foreach ($d in [WebInv.SensorCert]::PemBlocks($p, 'CERTIFICATE')) { $x = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]$d); if ($x.Thumbprint -ne $leaf.Thumbprint -and $x.Subject -ne $x.Issuer) { $ca.Add($x) } } } } finally { $ca.Close() }
    $c
}
function Get-KeyFile($Cert) {
    $k = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Cert)
    try { $name = $k.Key.UniqueName } finally { $k.Dispose() }
    Join-Path $env:ProgramData ('Microsoft\Crypto\Keys\{0}' -f $name)
}
function Grant-Key($Cert, [string[]]$Accounts) {
    if (-not $Accounts) { return }
    $f = Get-KeyFile $Cert
    $acl = Get-Acl -LiteralPath $f
    foreach ($a in $Accounts) {
        $sid = (New-Object Security.Principal.NTAccount($a)).Translate([Security.Principal.SecurityIdentifier])
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'Read', 'Allow')))
        Write-Line ("  key readable by {0}" -f $a)
    }
    Set-Acl -LiteralPath $f -AclObject $acl
}
function Test-NotExportable($Cert) {
    try { [void]$Cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12); $false } catch { $true }
}
function Remove-WindowsCert($Cert) {
    $st = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine'); $st.Open('ReadWrite')
    try {
        $k = $null; try { $k = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Cert) } catch { }
        $st.Remove($Cert)
        if ($k) { try { $k.Key.Delete() } finally { $k.Dispose() } }
    }
    finally { $st.Close() }
}

# ---- elsewhere: a key in memory, written with the certificate to a PFX readable by the owner only ----
function New-PortableRequest([string]$Subject, [string[]]$Sans) {
    $ec = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $req = [Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=$Subject", $ec, [Security.Cryptography.HashAlgorithmName]::SHA256)
    $b = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    foreach ($s in $Sans) {
        $ip = $null
        if ($s -match '^[a-z][a-z0-9+.-]*:' -and $s -notmatch '@') { $b.AddUri([Uri]$s) }
        elseif ([Net.IPAddress]::TryParse($s, [ref]$ip)) { $b.AddIpAddress($ip) }
        elseif ($s -match '@') { $b.AddEmailAddress($s) }
        else { $b.AddDnsName($s) }
    }
    $req.CertificateExtensions.Add($b.Build())
    @{ Key = $ec; Pem = [WebInv.SensorCert]::Pem($req.CreateSigningRequest(), 'CERTIFICATE REQUEST') }
}
function Save-Pfx($Key, [string]$LeafPem, [string[]]$ChainPem) {
    $leaf = [Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]@([WebInv.SensorCert]::PemBlocks($LeafPem, 'CERTIFICATE'))[0])
    $with = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($leaf, $Key)
    $col = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    [void]$col.Add($with)
    foreach ($p in $ChainPem) { foreach ($d in [WebInv.SensorCert]::PemBlocks($p, 'CERTIFICATE')) { $x = [Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$d); if ($x.Thumbprint -ne $leaf.Thumbprint -and $x.Subject -ne $x.Issuer) { [void]$col.Add($x) } } }
    $bytes = $col.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, '')
    $pdir = Split-Path -Parent $PfxPath
    if (-not (Test-Path -LiteralPath $pdir)) { New-Item -ItemType Directory -Path $pdir -Force | Out-Null; [IO.File]::SetUnixFileMode($pdir, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute') }
    $tmp = $PfxPath + '.new'
    [IO.File]::WriteAllBytes($tmp, [byte[]]@()); [IO.File]::SetUnixFileMode($tmp, [IO.UnixFileMode]'UserRead, UserWrite')
    [IO.File]::WriteAllBytes($tmp, $bytes)
    if ($KeepPrevious -and (Test-Path -LiteralPath $PfxPath)) { Copy-Item -LiteralPath $PfxPath -Destination ($PfxPath + '.previous') -Force }
    Move-Item -LiteralPath $tmp -Destination $PfxPath -Force
    [WebInv.SensorCert]::LoadPfx($PfxPath, '')
}

function Show-Cert($C, [string]$Where) {
    Write-Line ("  {0}  sensor {1}  {2}  valid {3:u} to {4:u}  {5}" -f $C.Thumbprint, [WebInv.SensorCert]::SensorId($C), $C.Subject, $C.NotBefore, $C.NotAfter, $Where)
}

# ======================================================================== -Show
if ($PSCmdlet.ParameterSetName -eq 'Show') {
    Write-Line ("Tideline sensor files: {0}" -f $dir) 'Cyan'
    if (Test-Path -LiteralPath $infoFile) { Get-Content -LiteralPath $infoFile | ForEach-Object { Write-Line "  $_" } } else { Write-Line '  (not enrolled: no tideline-sensor.json)' }
    if (Test-Path -LiteralPath $rootFile) { $r = [WebInv.SensorCert]::LoadPem($rootFile)[0]; Write-Line ("Pinned root: {0} (sha256 {1})" -f $r.Subject, [WebInv.SensorCert]::Sha256Hex($r.RawData)) }
    Write-Line 'Sensor certificates:' 'Cyan'
    if ($onWindows) {
        foreach ($loc in 'LocalMachine', 'CurrentUser') {
            $st = New-Object Security.Cryptography.X509Certificates.X509Store('My', $loc); $st.Open('ReadOnly')
            try { foreach ($c in $st.Certificates) { if ([WebInv.SensorCert]::SensorId($c)) { Show-Cert $c ("$loc\My" + $(if ($c.HasPrivateKey) { '' } else { ' (no key)' })) } } } finally { $st.Close() }
        }
    }
    elseif (Test-Path -LiteralPath $PfxPath) { Show-Cert ([WebInv.SensorCert]::LoadPfx($PfxPath, '')) $PfxPath }
    exit 0
}

if ($onWindows -and -not (Test-Admin)) { Stop-With 1 'run from an elevated PowerShell: the key and certificate go to the machine store (LocalMachine\My)' }
$work = Join-Path ([IO.Path]::GetTempPath()) ('wi-sensor-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    # ==================================================================== enroll
    if ($PSCmdlet.ParameterSetName -eq 'Enroll') {
        $parts = $Token.Trim().Split('.')
        if ($parts.Count -ne 3) { Stop-With 1 'the token is not a JWT (three dot-separated parts)' }
        try { $claims = [Text.Encoding]::UTF8.GetString((ConvertFrom-B64Url $parts[1])) | ConvertFrom-Json } catch { Stop-With 1 "the token payload is not readable: $(Get-Inner $_)" }
        $exp = [DateTimeOffset]::FromUnixTimeSeconds([long]$claims.exp)
        if ($exp -lt [DateTimeOffset]::UtcNow) { Stop-With 1 ("the token expired at {0:u}; ask for a new one (tokens are valid for five minutes)" -f $exp.UtcDateTime) }
        $sans = @($claims.sans | Where-Object { $_ })
        $urns = @($sans | Where-Object { $_ -like "$([WebInv.SensorCert]::UrnPrefix)*" })
        if ($urns.Count -ne 1) { Stop-With 1 ("the token must name exactly one {0}<id> (it names: {1}); make it with --san {0}<id>" -f [WebInv.SensorCert]::UrnPrefix, ($sans -join ', ')) }
        $sensor = $urns[0].Substring([WebInv.SensorCert]::UrnPrefix.Length)
        if (-not [WebInv.SensorCert]::ValidId($sensor)) { Stop-With 1 "sensor id '$sensor': letters, digits, '.', '_' and '-', up to 64" }
        $sub = [string]$claims.sub
        if (-not $sub -or $sub -match '["=,+;<>\\]') { Stop-With 1 "the token subject '$sub' cannot be a certificate subject" }
        $fp = [string]$claims.sha
        if ($fp -notmatch '^[0-9a-fA-F]{64}$') { Stop-With 1 'the token carries no root fingerprint (sha); make it with step ca token' }
        try { $base = Get-CaBase $(if ($CaUrl) { $CaUrl } else { [string]$claims.aud }) } catch { Stop-With 1 (Get-Inner $_) }
        Write-Line ("Enrolling sensor {0} with {1} (token for {2}, expires {3:u})" -f $sensor, $base, $sub, $exp.UtcDateTime) 'Cyan'
        try { $roots = Get-PinnedRoot $base $fp } catch { Stop-With 2 (Get-Inner $_) }
        Write-Line ("  root {0} matches the token's fingerprint; the CA's certificate chains to it" -f $roots[0].Subject)
        $req = if ($onWindows) { @{ Pem = (New-WindowsRequest $sub $sans $work) } } else { New-PortableRequest $sub $sans }
        $body = [ordered]@{ csr = $req.Pem; ott = $Token.Trim() }
        if ($NotAfter) { $body.notAfter = $NotAfter }
        try { $r = Invoke-Ca $base 'POST' '/1.0/sign' (ConvertTo-Json -InputObject $body -Compress) $null $roots } catch { Stop-With 2 (Get-Inner $_) }
        if ($r.Status -ne 201 -and $r.Status -ne 200) { Stop-With 2 ("the CA refused the request: {0}" -f (Get-CaError $r)) }
        $j = $r.Json
        $chain = @(); $cc = $j.Arr('certChain'); if ($cc) { $chain = @($cc | ForEach-Object { [string]$_ }) } elseif ($j.Str('ca')) { $chain = @($j.Str('ca')) }
        if ($onWindows) {
            $cert = Install-WindowsCert $j.Str('crt') $chain $work
            Grant-Key $cert $GrantKeyAccess
            Write-Line ("  key: ECDSA P-256 in the machine key store, {0}" -f $(if (Test-NotExportable $cert) { 'not exportable' } else { 'EXPORTABLE (unexpected)' }))
            $where = 'LocalMachine\My'
        }
        else { $cert = Save-Pfx $req.Key $j.Str('crt') $chain; $where = $PfxPath }
        Save-TidelineFiles $roots $base $sensor $cert
        Write-Line ("Enrolled: sensor {0}, certificate {1} in {2}, valid until {3:u}" -f $sensor, $cert.Thumbprint, $where, $cert.NotAfter) 'Green'
        Write-Line ("  pinned root: {0}" -f $rootFile)
        Write-Line '  renew daily from a scheduled task: Register-WebInventorySensor.ps1 -Renew'
        exit 0
    }

    # ==================================================================== renew
    if (-not (Test-Path -LiteralPath $infoFile) -or -not (Test-Path -LiteralPath $rootFile)) { Stop-With 1 "not enrolled here ($infoFile / $rootFile missing): enroll with -Token first" }
    $info = Get-Content -Raw -LiteralPath $infoFile | ConvertFrom-Json
    $roots = [WebInv.SensorCert]::LoadPem($rootFile)
    try { $base = Get-CaBase $(if ($CaUrl) { $CaUrl } else { [string]$info.caUrl }) } catch { Stop-With 1 (Get-Inner $_) }
    if ($onWindows) { $err = ''; $old = [WebInv.SensorCert]::Find($Thumbprint, [ref]$err); if (-not $old) { Stop-With 1 $err } }
    else { if (-not (Test-Path -LiteralPath $PfxPath)) { Stop-With 1 "no sensor certificate at $PfxPath" }; $old = [WebInv.SensorCert]::LoadPfx($PfxPath, '') }
    $sensor = [WebInv.SensorCert]::SensorId($old)
    $life = ($old.NotAfter - $old.NotBefore).TotalSeconds
    $left = ($old.NotAfter - (Get-Date)).TotalSeconds
    if ($left -le 0) { Stop-With 1 ("certificate {0} expired at {1:u}; it cannot renew. Enroll again with a new token." -f $old.Thumbprint, $old.NotAfter) }
    if (-not $Force -and $left -gt $life / 3) { Write-Line ("Sensor {0}: certificate {1} valid until {2:u}; renewal due after {3:u} (-Force renews now)" -f $sensor, $old.Thumbprint, $old.NotAfter, $old.NotAfter.AddSeconds(-$life / 3)) 'Cyan'; exit 0 }
    Write-Line ("Renewing sensor {0} (certificate {1}, valid until {2:u}) with a new key at {3}" -f $sensor, $old.Thumbprint, $old.NotAfter, $base) 'Cyan'
    $cn = if ($old.Subject -match 'CN=([^,]+)') { $Matches[1] } else { $sensor }
    $sans = @([WebInv.SensorCert]::Uris($old))
    $req = if ($onWindows) { @{ Pem = (New-WindowsRequest $cn $sans $work) } } else { New-PortableRequest $cn $sans }
    try { $r = Invoke-Ca $base 'POST' '/1.0/rekey' (ConvertTo-Json -InputObject ([ordered]@{ csr = $req.Pem }) -Compress) $old $roots } catch { Stop-With 2 (Get-Inner $_) }
    if ($r.Status -ne 201 -and $r.Status -ne 200) { Stop-With 2 ("the CA refused the renewal: {0}" -f (Get-CaError $r)) }
    $j = $r.Json
    $chain = @(); $cc = $j.Arr('certChain'); if ($cc) { $chain = @($cc | ForEach-Object { [string]$_ }) } elseif ($j.Str('ca')) { $chain = @($j.Str('ca')) }
    if ($onWindows) {
        $cert = Install-WindowsCert $j.Str('crt') $chain $work
        $grant = @($GrantKeyAccess)
        if (-not $grant.Count) {
            # the accounts that could read the previous key keep that right on the new one
            try { $grant = @((Get-Acl -LiteralPath (Get-KeyFile $old)).Access | Where-Object { $_.FileSystemRights -match 'Read' -and $_.AccessControlType -eq 'Allow' } | ForEach-Object { [string]$_.IdentityReference } | Where-Object { $_ -notmatch '^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators)$' } | Select-Object -Unique) } catch { $grant = @() }
        }
        Grant-Key $cert $grant
        $where = 'LocalMachine\My'
    }
    else { $cert = Save-Pfx $req.Key $j.Str('crt') $chain; $where = $PfxPath }
    if ([WebInv.SensorCert]::SensorId($cert) -ne $sensor) { Stop-With 2 ("the renewed certificate names sensor {0}, not {1}; it was installed but not used ({2})" -f [WebInv.SensorCert]::SensorId($cert), $sensor, $cert.Thumbprint) }
    if ($onWindows -and -not $KeepPrevious) { Remove-WindowsCert $old; Write-Line ("  previous certificate {0} and its key removed" -f $old.Thumbprint) }
    Save-TidelineFiles $roots $base $sensor $cert
    Write-Line ("Renewed: sensor {0}, certificate {1} in {2}, valid until {3:u}" -f $sensor, $cert.Thumbprint, $where, $cert.NotAfter) 'Green'
    exit 0
}
finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
