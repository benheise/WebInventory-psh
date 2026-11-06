param([string]$Dist)
$src = Get-Content -Raw (Join-Path $Dist 'Invoke-WebInventory.ps1')
if ($src -match "(?s)\`$EngineSource = @'\r?\n(.*?)\r?\n'@") { Add-Type -TypeDefinition $Matches[1] }
$sw = [Diagnostics.Stopwatch]::StartNew()
$errs = [System.Collections.Generic.List[string]]::new()
foreach ($f in Get-ChildItem $Dist -Filter 'WebInventory.rules.*.json') { [void][WebInv.Matcher]::Load([WebInv.Matcher]::ReadPack([IO.File]::ReadAllText($f.FullName)), $errs) }
"loaded {0} rules in {1} ms" -f [WebInv.Matcher]::Count, $sw.ElapsedMilliseconds
$body = ('<html><head><title>Portal</title><script src="/js/jquery-3.5.1.min.js"></script><meta name="generator" content="WordPress 6.1"></head><body>' + ('<div class="row"><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p></div>' * 1500) + '</body></html>')
$o = [WebInv.Observation]::new(); $o.Port = 443
$o.Add('header:server', 'nginx/1.24.0'); $o.Add('header:x-powered-by', 'PHP/8.1.2'); $o.Add('body', $body); $o.Add('title', 'Portal')
$o.Add('scriptsrc', '/js/jquery-3.5.1.min.js'); $o.Add('meta:generator', 'WordPress 6.1'); $o.Add('cookiename', 'PHPSESSID'); $o.Add('setcookie', 'PHPSESSID=1; path=/')
[void][WebInv.Matcher]::Evaluate($o)
$sw.Restart(); $n = 20
for ($i = 0; $i -lt $n; $i++) { $d = [WebInv.Matcher]::Evaluate($o) }
"body {0} KB: {1:N1} ms per page evaluation; detections: {2}; regex timeouts: {3}" -f [int]($body.Length / 1024), ($sw.ElapsedMilliseconds / $n), (($d | ForEach-Object { $_.ToString() }) -join ', '), [WebInv.Matcher]::Timeouts
