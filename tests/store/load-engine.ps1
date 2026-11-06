# Dot-source to load the WebInv store engine (C#) from a built Invoke-WebInventory.ps1 into this session.
param([string]$Script = (Join-Path $PSScriptRoot '../../dist/Invoke-WebInventory.ps1'))
$code = [IO.File]::ReadAllText((Resolve-Path $Script))
if ($code -notmatch "(?s)\`$StoreSource = @'\r?\n(.*?)\r?\n'@") { throw 'store block not found' }
if (-not ('WebInv.InventoryStore' -as [type])) { Add-Type -TypeDefinition $Matches[1] -IgnoreWarnings }
