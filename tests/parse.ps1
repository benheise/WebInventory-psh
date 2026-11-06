param($Path)
$t = $null; $e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$t, [ref]$e)
if ($e) { $e | ForEach-Object { "{0}:{1} {2}" -f $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message } } else { "parse OK ($($t.Count) tokens)" }
