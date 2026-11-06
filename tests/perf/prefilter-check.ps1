<#
  Prefilter safety check: the literal prefilter must never change what the rule engine reports.
  pwsh -File prefilter-check.ps1 -Script <Invoke-WebInventory.ps1> [-CorpusDir <dir of *.raw HTTP responses>]
  1. literal-extraction spot checks (expected values)
  2. every rule that carries an example: the example (embedded in noise) evaluated with the prefilter on and off
  3. optional corpus of raw responses: full observations evaluated on and off
  Any difference fails the check (exit 1).
#>
param([Parameter(Mandatory)][string]$Script, [string]$CorpusDir)
$ErrorActionPreference = 'Stop'
$src = [IO.File]::ReadAllText($Script)
$dir = Split-Path -Parent (Resolve-Path $Script)
if ($src -notmatch "(?s)\`$EngineSource = @'\r?\n(.*?)\r?\n'@") { throw 'engine not found' }
Add-Type -TypeDefinition $Matches[1]
if ($src -notmatch "(?s)\`$BuiltinRulesJson = @'\r?\n(.*?)\r?\n'@") { throw 'builtin rules not found' }
$errs = [System.Collections.Generic.List[string]]::new()
[void][WebInv.Matcher]::Load([WebInv.Matcher]::ReadPack($Matches[1]), $errs)
foreach ($f in Get-ChildItem $dir -Filter 'WebInventory.rules.*.json') { [void][WebInv.Matcher]::Load([WebInv.Matcher]::ReadPack([IO.File]::ReadAllText($f.FullName)), $errs) }
$fail = 0
"rules={0} with required literal={1}" -f [WebInv.Matcher]::Count, [WebInv.Matcher]::PrefilteredRules

# 1. extraction spot checks: pattern -> expected literal ('' = none)
$bs = [char]92
$cases = [ordered]@{
    'jquery[.-]([\d.]+)' = 'jquery'; '(?i)WordPress\s+([\d.]+)' = 'wordpress'; 'a|b' = ''; 'foo(bar)?bazz' = 'bazz'
    'ab*cde' = 'cde'; 'x{2}yz' = ''; '<meta[^>]+generator' = 'generator'; '(?x) a b c' = ''; '[abc]def\.js' = 'def.js'
    ('{0}p{{Lu}}abcd' -f $bs) = 'abcd'; 'ab?cd' = ''; 'abc+d' = 'abc'; 'nginx(?:/([\d.]+))?' = 'nginx'; '^Apache$' = 'apache'
    'ab{0,1}cdef' = 'cdef'; '(?<v>\d+)\.(\d+)kit' = 'kit'; 'x[a-z-[aeiou]]yz' = ''; 'abc{2,}xyz' = 'abc'
}
foreach ($k in $cases.Keys) {
    $got = [string][WebInv.Lit]::Required($k)
    if ($got -ne $cases[$k]) { $fail++; "FAIL literal: {0} -> '{1}' (expected '{2}')" -f $k, $got, $cases[$k] }
}

$dnf = [ordered]@{
    '(?:Diese <a href=[^>]+bigware\.de|<a href=[^>]+/main_bigware_\d+\.php)' = 'diese <a href=&bigware.de|<a href=&/main_bigware_&.php'
    'aem-(?:GridColumn|apps/)|AEMMode' = 'aem-&gridcolumn|aem-&apps/|aemmode'
    '<script[^>].*hybris.*.js' = '<script&hybris'; 'foo(?=bar)baz' = 'foo&baz'; 'a(?i:bcd)e' = 'bcd'; 'x(?:abc|)yzw' = 'yzw'
    '(?:abc|de)' = ''; 'abc|' = ''
}
foreach ($k in $dnf.Keys) {
    $d = [WebInv.Lit]::Requirement($k)
    $got = if ($d) { ($d | ForEach-Object { $_ -join '&' }) -join '|' } else { '' }
    if ($got -ne $dnf[$k]) { $fail++; "FAIL requirement: {0} -> '{1}' (expected '{2}')" -f $k, $got, $dnf[$k] }
}

function Compare-Eval($obs, [string]$what) {
    [WebInv.Matcher]::Prefilter = $true;  $a = @([WebInv.Matcher]::Evaluate($obs) | ForEach-Object { '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $_.Kind, $_.Name, $_.Version, $_.Cpe, $_.Flag, $_.Source, $_.Evidence })
    [WebInv.Matcher]::Prefilter = $false; $b = @([WebInv.Matcher]::Evaluate($obs) | ForEach-Object { '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $_.Kind, $_.Name, $_.Version, $_.Cpe, $_.Flag, $_.Source, $_.Evidence })
    [WebInv.Matcher]::Prefilter = $true
    if (($a -join "`n") -ne ($b -join "`n")) { $script:fail++; "FAIL equivalence ({0}):`n  on : {1}`n  off: {2}" -f $what, ($a -join ' ; '), ($b -join ' ; ') }
}

# 2. rule examples embedded in noise (case-flipped noise exercises the folding)
$pack = Get-ChildItem $dir -Filter 'WebInventory.rules.*.json' | ForEach-Object { [WebInv.Matcher]::ReadPack([IO.File]::ReadAllText($_.FullName)) }
$n = 0
foreach ($p in $pack) {
    foreach ($r in $p.Rules) {
        if (-not $r.Ex) { continue }
        $o = [WebInv.Observation]::new(); $o.Port = 80
        $o.Add($r.F, ('xX ' + $r.Ex + ' Yy'))
        $o.Add($r.F, $r.Ex.ToUpperInvariant())
        Compare-Eval $o $r.Id
        $n++
    }
}
"example observations compared: $n"

# 3. raw response corpus
if ($CorpusDir) {
    $c = 0
    foreach ($f in Get-ChildItem $CorpusDir -Filter '*.raw') {
        $resp = [WebInv.Html]::Parse([IO.File]::ReadAllBytes($f.FullName))
        $o = [WebInv.Observation]::new(); $o.Port = 443
        [WebInv.Html]::AddWeb($o, [WebInv.HttpResp[]]@($resp), [string[]]@(), 'https://corpus/')
        Compare-Eval $o $f.Name; $c++
    }
    "corpus responses compared: $c"
}
if ($fail) { "PREFILTER CHECK FAILED: $fail"; exit 1 } else { 'prefilter check passed' }
