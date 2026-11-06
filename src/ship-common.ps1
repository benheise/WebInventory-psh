#region ---------- Tideline shipping: shared by Invoke-WebInventory.ps1, Send-WebInventoryRun.ps1, Register-WebInventorySensor.ps1 ----------
function Get-TidelineDir {
    # where Register-WebInventorySensor.ps1 keeps the pinned root, the sensor record and (off Windows) the sensor PFX
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { Join-Path $env:ProgramData 'WebInventory' }
    else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.config/webinventory' }
}
function Get-TidelineDefault([string]$Name) {
    $p = Join-Path (Get-TidelineDir) $Name
    if (Test-Path -LiteralPath $p -PathType Leaf) { $p } else { $null }
}

function Initialize-ShipCode([string]$Version) {
    if ('WebInv.Shipper' -as [type]) {
        if ([WebInv.ShipInfo]::Version -ne $Version) { throw ("WebInv shipping code v{0} is already loaded in this PowerShell session (script is v{1}). Open a new PowerShell window." -f [WebInv.ShipInfo]::Version, $Version) }
        return
    }
    $addType = @{ TypeDefinition = $ShipSource; ErrorAction = 'Stop'; IgnoreWarnings = $true; WarningAction = 'SilentlyContinue' }
    if ($PSVersionTable.PSEdition -ne 'Core') {
        Add-Type -AssemblyName System.IO.Compression
        $addType.ReferencedAssemblies = @('System.Core', 'System.IO.Compression')
    }
    Add-Type @addType
    [WebInv.Https]::UserAgent = "WebInventory/$Version (authorized asset inventory)"
}

function Get-InnerMessage($ErrorRecord) {
    $x = if ($ErrorRecord -is [Exception]) { $ErrorRecord } else { $ErrorRecord.Exception }
    while ($x -is [System.Management.Automation.MethodInvocationException] -and $x.InnerException) { $x = $x.InnerException }
    $x.Message
}

function Test-EngagementId([string]$Id) { $Id -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' }

function ConvertTo-TidelineUri([string]$Url) {
    $u = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne 'https' -or -not $u.Host) { throw "'$Url' is not an https:// URL" }
    if ($u.UserInfo) { throw "'$Url': no credentials in the URL (the sensor certificate authenticates)" }
    if ($u.Query -or $u.Fragment) { throw "'$Url': no query or fragment" }
    $u
}

# the sensor certificate: a PFX (-ShipCertPath), one thumbprint, or the newest valid sensor certificate in the stores
function Resolve-ShipCert([string]$Thumbprint, [string]$Path, [string]$PasswordFile) {
    if ($Thumbprint -and $Path) { throw 'give the certificate thumbprint or the PFX path, not both' }
    if (-not $Thumbprint -and -not $Path -and [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $Path = Get-TidelineDefault 'tideline-sensor.pfx' }
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "certificate file not found: $Path" }
        $pw = ''
        if ($PasswordFile) {
            if (-not (Test-Path -LiteralPath $PasswordFile -PathType Leaf)) { throw "password file not found: $PasswordFile" }
            $pw = ([IO.File]::ReadAllLines((Resolve-Path -LiteralPath $PasswordFile).ProviderPath) | Select-Object -First 1)
            if ($null -eq $pw) { $pw = '' }
        }
        $c = [WebInv.SensorCert]::LoadPfx((Resolve-Path -LiteralPath $Path).ProviderPath, $pw)
    }
    else {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'no sensor certificate: pass -ShipCertPath (a PFX), or enroll with Register-WebInventorySensor.ps1' }
        $err = ''
        $c = [WebInv.SensorCert]::Find($Thumbprint, [ref]$err)
        if (-not $c) { throw $err }
    }
    if (-not [WebInv.SensorCert]::SensorId($c)) { throw ("certificate {0} has no single {1}<id> name" -f $c.Thumbprint, [WebInv.SensorCert]::UrnPrefix) }
    $now = Get-Date
    if ($c.NotAfter -lt $now -or $c.NotBefore -gt $now) { throw ("certificate {0} is not valid now (valid {1:u} to {2:u})" -f $c.Thumbprint, $c.NotBefore, $c.NotAfter) }
    $c
}

function Resolve-ShipRoots([string]$CaFile) {
    if (-not $CaFile) { $CaFile = Get-TidelineDefault 'tideline-root.crt' }
    if (-not $CaFile) { throw ("no Tideline root CA: pass -ShipCaFile, or enroll with Register-WebInventorySensor.ps1 (it saves the root to {0})" -f (Join-Path (Get-TidelineDir) 'tideline-root.crt')) }
    if (-not (Test-Path -LiteralPath $CaFile -PathType Leaf)) { throw "CA file not found: $CaFile" }
    [WebInv.SensorCert]::LoadPem((Resolve-Path -LiteralPath $CaFile).ProviderPath)
}

# the run.json of a run folder or of any file of the run (newest run when a folder holds several)
function Get-RunJsonPaths([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "not found: $Path" }
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) { return @(Get-ChildItem -LiteralPath $item.FullName -Filter 'WebInventory_*_run.json' -File | Sort-Object Name | ForEach-Object { $_.FullName }) }
    if ($item.Name -match '^WebInventory_(.+?)(?:_run\.json|\.jsonl|\.csv|_manifest\.txt|_progress\.txt|_ship-state\.json)$') {
        $rj = Join-Path $item.DirectoryName ('WebInventory_{0}_run.json' -f $Matches[1])
        if (Test-Path -LiteralPath $rj) { return @($rj) }
        throw "the run.json of $($item.Name) is missing ($rj)"
    }
    throw "$Path is not a run folder or a WebInventory run file"
}
#endregion
