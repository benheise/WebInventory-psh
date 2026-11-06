
#region ---------- Output schema and writers ----------
$Columns = @(
    'RunId', 'ScanTag', 'ScannedAt', 'Host', 'IP', 'Port', 'ReverseDns', 'Vhost', 'VhostOf', 'State', 'IsWeb', 'Service', 'Scheme', 'Url', 'FinalUrl',
    'StatusCode', 'Title', 'Server', 'PoweredBy', 'Generator', 'ContentType', 'BodyLength', 'BodySha256', 'ResponseMs', 'RedirectChain',
    'Auth', 'Cookies', 'CookieFlagIssues', 'MissingSecHeaders', 'HstsMaxAge', 'AltSvc',
    'Products', 'Technologies', 'Categories', 'CPEs', 'OsHint', 'Hardware',
    'FaviconPath', 'FaviconMmh3', 'FaviconMd5', 'Robots', 'SecurityTxt', 'AllowedMethods', 'RiskyMethods', 'IdentifiedPaths',
    'TlsVersion', 'TlsCipher', 'TlsKeyExchange', 'TlsSupported', 'TlsCiphersByVersion', 'TlsWeakCipher', 'Alpn', 'Http2',
    'CertSubject', 'CertIssuer', 'CertSANs', 'CertNotBefore', 'CertNotAfter', 'CertDaysLeft', 'CertSelfSigned', 'CertSigAlg',
    'CertKeyAlg', 'CertKeySize', 'CertSerial', 'CertSha1', 'CertSha256', 'CertPolicyErrors', 'CertChainStatus', 'CertSource',
    'Flags', 'Advisories', 'Banner', 'Notes',
    # v2.3 (appended so existing CSV consumers keep their column positions)
    'DeviceName', 'Domain', 'ProtocolInfo', 'Jarm', 'Ja4s',
    # v2.4 (appended)
    'VersionPaths',
    # v2.5 (appended)
    'Cname', 'Cloud', 'CloudRegion', 'CloudService')

# a results CSV with at least one data row (exit code 4 of a resumed run counts earlier sessions' rows)
function Test-CsvHasRows([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
    $sr = New-Object IO.StreamReader($Path)
    try { [void]$sr.ReadLine(); while ($null -ne ($l = $sr.ReadLine())) { if ($l.Trim()) { return $true } }; return $false } finally { $sr.Dispose() }
}

function Open-Outputs {
    param([string]$Dir, [string]$RunId)
    $script:CsvPath = Join-Path $Dir ("WebInventory_{0}.csv" -f $RunId)
    $script:JsonlPath = Join-Path $Dir ("WebInventory_{0}.jsonl" -f $RunId)
    $script:ProgressPath = Join-Path $Dir ("WebInventory_{0}_progress.txt" -f $RunId)
    $newCsv = -not (Test-Path -LiteralPath $script:CsvPath)
    $script:CsvW = New-Object System.IO.StreamWriter($script:CsvPath, $true, $script:Utf8Bom); $script:CsvW.AutoFlush = $true
    if ($newCsv) { $script:CsvW.WriteLine((($Columns | ForEach-Object { '"' + $_ + '"' }) -join ',')) }
    $script:JsonW = New-Object System.IO.StreamWriter($script:JsonlPath, $true, $script:Utf8NoBom); $script:JsonW.AutoFlush = $true
    $script:ProgW = New-Object System.IO.StreamWriter($script:ProgressPath, $true, $script:Utf8NoBom); $script:ProgW.AutoFlush = $true
}

function Close-Outputs {
    foreach ($n in 'CsvW', 'JsonW', 'ProgW') {
        $w = Get-Variable -Name $n -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($w) { try { $w.Flush(); $w.Dispose() } catch { } }
        Set-Variable -Name $n -Scope Script -Value $null
    }
}

function Write-ResultRow {
    # CSV + JSONL lines are built in C# (WebInv.Out): same quoting/flattening/formula guard as v2.0, JSON with the
    # same types as ConvertTo-Json and HTML-sensitive characters escaped
    param($Row)
    $n = $Columns.Count
    $cv = New-Object object[] $n
    for ($i = 0; $i -lt $n; $i++) { $cv[$i] = $Row[$Columns[$i]] }
    $jv = New-Object object[] ($n + 1)
    [Array]::Copy($cv, $jv, $n)
    $jv[$n] = [object[]]@($Row['_Detections'])
    $script:CsvW.WriteLine([WebInv.Out]::CsvLine($cv, -not $NoCsvSanitize))
    $script:JsonW.WriteLine([WebInv.Out]::JsonLine($script:JsonNames, $jv))
}

function Write-Hit {
    param($Row)
    if ($Quiet) { return }
    $P = { param($s, $n) [WebInv.Util]::Printable([string]$s, $n) }
    $tag = '[+]'; $tagColor = 'Green'
    $proto = @('smb', 'rdp', 'snmp') -contains $Row.Scheme
    if (-not $Row.IsWeb -and -not $proto) { if ($Row._SchannelIncompatible) { $tag = '[!]'; $tagColor = 'Yellow' } else { $tag = '[~]'; $tagColor = 'DarkYellow' } }
    $host_ = if ($Row.Vhost) { '{0} (vhost of {1})' -f $Row.Host, $Row.VhostOf } else { '' }
    $tls = ''
    if (($Row.TlsVersion -or $Row.TlsSupported) -and -not $proto) {
        $cn = if ($Row.CertSubject -match 'CN=([^,]+)') { $Matches[1] } else { '' }
        $v = if ($Row.TlsVersion) { $Row.TlsVersion } else { 'raw:' + $Row.TlsSupported }
        $tls = ' [{0}{1} {2} {3}d]' -f $v, $(if ($Row.Http2 -eq $true) { ' h2' } else { '' }), (& $P $cn 40), $Row.CertDaysLeft
    }
    $main = if ($Row.IsWeb) {
        '{0} [{1}] [{2}] [{3}] [{4}]' -f $Row.Url, $Row.StatusCode, (& $P $Row.Server 60), (& $P $Row.Title 70), (& $P $Row.Products 120)
    } elseif ($proto) {
        $what = @($Row.DeviceName, $Row.OsHint, $Row.Products, $(if ($Row.Scheme -eq 'snmp') { $Row.Banner })) | Where-Object { $_ } | Select-Object -Unique
        '{0} [{1}] [{2}] [{3}]' -f $Row.Url, (& $P (($what) -join ' | ') 140), (& $P $Row.ProtocolInfo 120), $(if ($Row.CertSubject -match 'CN=([^,]+)') { 'cert ' + (& $P $Matches[1] 40) + ' ' + $Row.CertDaysLeft + 'd' } else { '-' })
    } else {
        '{0} [{1}] [{2}] [{3}]' -f $Row.Url, $Row.Service, (& $P $Row.Products 100), (& $P $Row.Banner 80)
    }
    Write-Host ($tag + ' ') -ForegroundColor $tagColor -NoNewline
    Write-Host ($main + $tls + $(if ($host_) { " $host_" } else { '' })) -NoNewline
    if ($Row.Flags) {
        $crit = $Row.Flags -match 'CertExpired|WeakCipher|CleartextAuth|ADCSWebEnrollment|DirectoryListing|PhpInfoExposed|SchannelIncompatible|WeakTLS:SSL3|PHP2Shell:(?:vulnerable|eol)|SMBv1|RdpStandardSecurity'
        Write-Host (' !' + (& $P $Row.Flags 160)) -ForegroundColor $(if ($crit) { 'Red' } else { 'Yellow' })
    }
    else { Write-Host '' }
}
#endregion

#region ---------- Baseline delta ----------
function Compare-Baseline {
    param([string]$BaselinePath, [string]$CurrentCsv, [string]$DeltaPath)
    $fields = @('IP', 'Scheme', 'StatusCode', 'Title', 'Server', 'Products', 'CertSha256', 'CertNotAfter', 'TlsSupported', 'FaviconMmh3', 'Flags', 'Advisories')
    $old = @{}; foreach ($r in (Import-Csv -LiteralPath $BaselinePath)) { $old['{0}|{1}' -f $r.Host, $r.Port] = $r }
    $new = @{}; foreach ($r in (Import-Csv -LiteralPath $CurrentCsv)) { $new['{0}|{1}' -f $r.Host, $r.Port] = $r }
    $delta = New-Object System.Collections.Generic.List[object]
    foreach ($k in $new.Keys) {
        if (-not $old.ContainsKey($k)) { $delta.Add([pscustomobject]@{ Change = 'NEW'; Key = $k; Field = ''; Old = ''; New = ('{0} {1}' -f $new[$k].Url, $new[$k].Products) }); continue }
        foreach ($f in $fields) {
            $ov = [string]$old[$k].$f; $nv = [string]$new[$k].$f
            if ($ov -ne $nv) { $delta.Add([pscustomobject]@{ Change = 'CHANGED'; Key = $k; Field = $f; Old = $ov; New = $nv }) }
        }
    }
    foreach ($k in $old.Keys) { if (-not $new.ContainsKey($k)) { $delta.Add([pscustomobject]@{ Change = 'REMOVED'; Key = $k; Field = ''; Old = ('{0} {1}' -f $old[$k].Url, $old[$k].Products); New = '' }) } }
    $delta | Sort-Object Change, Key, Field | Export-Csv -LiteralPath $DeltaPath -NoTypeInformation -Encoding UTF8
    @{ New = @($delta | Where-Object Change -eq 'NEW').Count; Removed = @($delta | Where-Object Change -eq 'REMOVED').Count; Changed = @($delta | Where-Object Change -eq 'CHANGED' | Select-Object -ExpandProperty Key -Unique).Count }
}
#endregion

#region ---------- Integrity manifest (SHA-256 of every output, for audit evidence) ----------
function Write-Manifest {
    param([string[]]$Files, [string]$Path)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('# WebInventory {0} manifest  RunId={1}  created={2}  host={3}  user={4}' -f $ScriptVersion, $script:RunId, (Get-Date).ToString('o'), [Environment]::MachineName, $script:Operator))
    $lines.Add('# sha256  bytes  file')
    foreach ($f in $Files) {
        if (-not $f -or -not (Test-Path -LiteralPath $f)) { continue }
        $b = [IO.File]::ReadAllBytes($f)
        # files in a subfolder of the output folder (screenshots) keep their relative path
        $base = (Split-Path -Parent $Path) + [IO.Path]::DirectorySeparatorChar
        $name = if ($f.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { $f.Substring($base.Length) } else { Split-Path -Leaf $f }
        $lines.Add(('{0}  {1}  {2}' -f [WebInv.Hash]::Sha256Hex($b), $b.Length, $name))
    }
    [IO.File]::WriteAllLines($Path, $lines.ToArray(), $script:Utf8NoBom)
}
#endregion

#region ---------- Self-contained HTML report (offline; no external fonts/scripts) ----------
function New-HtmlReport {
    param([string]$CsvFile, [string]$HtmlFile, [hashtable]$Meta, [hashtable]$Screenshots)
    $rows = @(Import-Csv -LiteralPath $CsvFile)
    $data = @($rows | ForEach-Object {
            [ordered]@{ u = $_.Url; h = $_.Host; ip = $_.IP; p = $_.Port; sv = $_.Service; w = $_.IsWeb; s = $_.StatusCode; t = $_.Title; srv = $_.Server
                pr = $_.Products; c = $_.Categories; os = $_.OsHint; hw = $_.Hardware; tls = $_.TlsVersion; tsup = $_.TlsSupported; h2 = $_.Http2
                cd = $_.CertDaysLeft; cs = $_.CertSubject; ci = $_.CertIssuer; san = $_.CertSANs; f = $_.Flags; fav = $_.FaviconMmh3; cpe = $_.CPEs
                vh = $_.VhostOf; rd = $_.ReverseDns; au = $_.Auth; fu = $_.FinalUrl; rc = $_.RedirectChain; b = $_.Banner; n = $_.Notes; adv = $_.Advisories
                dn = $_.DeviceName; dom = $_.Domain; pi = $_.ProtocolInfo; jarm = $_.Jarm; ja4s = $_.Ja4s
                cn = $_.Cname; cl = (@($_.Cloud, $_.CloudRegion, $_.CloudService) | Where-Object { $_ }) -join ' / '
                shot = $(if ($Screenshots -and $Screenshots.ContainsKey([string]$_.Url)) { $Screenshots[[string]$_.Url] } else { '' })
                shs = $(if ($script:ShotMeta -and $script:ShotMeta.ContainsKey([string]$_.Url)) { $script:ShotMeta[[string]$_.Url][0] } else { '' })
                shr = $(if ($script:ShotMeta -and $script:ShotMeta.ContainsKey([string]$_.Url)) { $script:ShotMeta[[string]$_.Url][1] } else { '' }) } })
    # strip control characters (ANSI escapes etc. from hostile headers) - they are inert in textContent but unreadable
    foreach ($o in $data) { foreach ($k in @($o.Keys)) { $o[$k] = [WebInv.Util]::Printable([string]$o[$k], 8000) } }
    $json = if ($data.Count) { ConvertTo-Json -InputObject $data -Compress -Depth 3 } else { '[]' }
    # neutralise anything that could terminate the script element or be parsed as markup
    $bs = '\'
    $json = $json.Replace('<', $bs + 'u003c').Replace('>', $bs + 'u003e').Replace('&', $bs + 'u0026')
    $metaJson = (ConvertTo-Json -InputObject $Meta -Compress -Depth 3).Replace('<', $bs + 'u003c').Replace('>', $bs + 'u003e').Replace('&', $bs + 'u0026')
    $html = $script:HtmlTemplate.Replace('__DATA__', $json).Replace('__META__', $metaJson)
    [IO.File]::WriteAllText($HtmlFile, $html, $script:Utf8NoBom)
}

$script:HtmlTemplate = @'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Web Inventory Report</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--ink:#16181d;--muted:#5d6472;--line:#e3e6eb;--accent:#2457c5;--ok:#1f7a4d;--warn:#a15c00;--bad:#b42318;--chip:#eef1f6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1115;--panel:#171a21;--ink:#e7e9ee;--muted:#9aa3b2;--line:#2a2f3a;--accent:#7aa2ff;--ok:#4cc38a;--warn:#f0b35a;--bad:#ff7a6e;--chip:#222734}}
:root[data-theme="dark"]{--bg:#0f1115;--panel:#171a21;--ink:#e7e9ee;--muted:#9aa3b2;--line:#2a2f3a;--accent:#7aa2ff;--ok:#4cc38a;--warn:#f0b35a;--bad:#ff7a6e;--chip:#222734}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
header{padding:20px 24px 8px}h1{margin:0;font-size:20px;font-weight:650}.meta{color:var(--muted);font-size:12.5px;margin-top:4px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;padding:12px 24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.card b{display:block;font-size:22px;font-variant-numeric:tabular-nums}.card span{color:var(--muted);font-size:12px}
.lists{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px;padding:0 24px 12px}
.list{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.list h3{margin:0 0 8px;font-size:13px;color:var(--muted);font-weight:600}
.bar{display:flex;align-items:center;gap:8px;margin:3px 0;font-size:12.5px;cursor:pointer}.bar i{display:block;height:8px;background:var(--accent);border-radius:4px;opacity:.75}.bar em{font-style:normal;color:var(--muted);margin-left:auto;font-variant-numeric:tabular-nums}
.tools{display:flex;gap:8px;flex-wrap:wrap;padding:4px 24px 10px;align-items:center}input,select,button{font:inherit;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:7px 10px}
input{flex:1;min-width:200px}.count{color:var(--muted);font-size:12.5px}
.wrap{padding:0 24px 24px;overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:12.8px}th{position:sticky;top:0;background:var(--panel);cursor:pointer;white-space:nowrap;color:var(--muted);font-weight:600}
tr.r:hover{background:var(--chip)}td.u{min-width:190px;max-width:300px;word-break:break-all}td.t{max-width:260px}.chip{display:inline-block;background:var(--chip);border-radius:6px;padding:1px 6px;margin:1px 2px 1px 0;font-size:11.5px}
.chip.bad{color:var(--bad)}.chip.warn{color:var(--warn)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
tr.d td{background:var(--bg)}pre{margin:0;white-space:pre-wrap;word-break:break-word;font:12px/1.4 ui-monospace,Consolas,monospace}
@media (max-width:640px){header,.cards,.lists,.tools,.wrap{padding-left:16px;padding-right:16px}}
</style></head><body>
<header><h1>Web Inventory Report</h1><div class="meta" id="meta"></div></header>
<section class="cards" id="cards"></section>
<section class="lists"><div class="list"><h3>Top products</h3><div id="lp"></div></div><div class="list"><h3>Flags</h3><div id="lf"></div></div><div class="list"><h3>Categories</h3><div id="lc"></div></div></section>
<div class="tools"><input id="q" placeholder="Filter (host, product, title, flag, CPE...)"><select id="sv"><option value="">All services</option><option value="web">Web only</option><option value="tls">TLS only</option><option value="other">Non-web</option></select><button id="th" type="button">Theme</button><span class="count" id="cnt"></span></div>
<div class="wrap"><table><thead><tr><th data-k="u">URL</th><th data-k="s">Status</th><th data-k="t">Title</th><th data-k="pr">Products</th><th data-k="tls">TLS</th><th data-k="cd">Cert days</th><th data-k="f">Flags</th></tr></thead><tbody id="tb"></tbody></table></div>
<script type="application/json" id="data">__DATA__</script><script type="application/json" id="metadata">__META__</script>
<script>
(function(){
var D=JSON.parse(document.getElementById('data').textContent),M=JSON.parse(document.getElementById('metadata').textContent);
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
var crit=/CertExpired|WeakCipher|CleartextAuth|ADCSWebEnrollment|DirectoryListing|PhpInfoExposed|SchannelIncompatible|SSL3|PHP2Shell:(?:vulnerable|eol)/;
var meta=document.getElementById('meta');meta.textContent='Run '+(M.RunId||'')+(M.Tag?' \u00b7 '+M.Tag:'')+' \u00b7 '+(M.Started||'')+' \u00b7 '+(M.Duration||'')+' \u00b7 '+(M.Operator||'')+' on '+(M.Computer||'')+' \u00b7 v'+(M.Version||'');
var web=D.filter(function(r){return r.w==='True'}),hosts={},tlsN=0,flagged=0,exp=0,mg=0,adv=0;
D.forEach(function(r){hosts[r.ip]=1;if(r.tls||r.tsup)tlsN++;if(r.f)flagged++;var d=parseInt(r.cd,10);if(!isNaN(d)&&d<=30)exp++;if(/MgmtInterface/.test(r.f))mg++;if(/PHP2Shell:(vulnerable|eol)/.test(r.f))adv++});
[['Web services',web.length],['Hosts',Object.keys(hosts).length],['Open services',D.length],['TLS endpoints',tlsN],['Flagged',flagged],['Certs \u2264 30 days',exp],['Mgmt interfaces',mg],['Advisory exposures',adv],['In cloud / CDN ranges',D.filter(function(r){return r.cl}).length]].forEach(function(c){var d=el('div','card');d.appendChild(el('b',null,c[1]));d.appendChild(el('span',null,c[0]));document.getElementById('cards').appendChild(d)});
function tally(key,split){var m={};D.forEach(function(r){(r[key]||'').split(split).forEach(function(x){x=x.trim();if(!x)return;if(key==='f')x=x.split(':')[0];m[x]=(m[x]||0)+1})});return Object.keys(m).map(function(k){return[k,m[k]]}).sort(function(a,b){return b[1]-a[1]}).slice(0,12)}
function bars(id,list){var box=document.getElementById(id),max=list.length?list[0][1]:1;list.forEach(function(p){var b=el('div','bar');var i=el('i');i.style.width=Math.max(4,Math.round(120*p[1]/max))+'px';b.appendChild(i);b.appendChild(el('span',null,p[0]));b.appendChild(el('em',null,p[1]));b.onclick=function(){q.value=p[0];render()};box.appendChild(b)});if(!list.length)box.appendChild(el('span','count','none'))}
bars('lp',tally('pr',';'));bars('lf',tally('f',';'));bars('lc',tally('c',';'));
var q=document.getElementById('q'),sv=document.getElementById('sv'),tb=document.getElementById('tb'),sortK='u',sortD=1;
function match(r){var f=q.value.toLowerCase(),s=sv.value;if(s==='web'&&r.w!=='True')return false;if(s==='tls'&&!(r.tls||r.tsup))return false;if(s==='other'&&r.w==='True')return false;if(!f)return true;return Object.keys(r).some(function(k){return(r[k]||'').toLowerCase().indexOf(f)>=0})}
function render(){tb.textContent='';var rows=D.filter(match).sort(function(a,b){var x=a[sortK]||'',y=b[sortK]||'';var nx=parseFloat(x),ny=parseFloat(y);if(!isNaN(nx)&&!isNaN(ny))return(nx-ny)*sortD;return x.localeCompare(y)*sortD});
document.getElementById('cnt').textContent=rows.length+' of '+D.length+' rows';
rows.forEach(function(r){var tr=el('tr','r');var u=el('td','u',r.u+(r.vh?'  (vhost of '+r.vh+')':''));tr.appendChild(u);tr.appendChild(el('td',null,r.s||r.sv));tr.appendChild(el('td','t',r.t||r.b));
var p=el('td');(r.pr||'').split(';').forEach(function(x){if(x.trim())p.appendChild(el('span','chip',x.trim()))});tr.appendChild(p);
tr.appendChild(el('td',null,(r.tls||'')+(r.h2==='True'?' h2':'')+(r.tsup&&!r.tls?' raw:'+r.tsup:'')));
var d=parseInt(r.cd,10),cd=el('td',isNaN(d)?null:(d<0?'bad':(d<=30?'warn':'ok')),r.cd);tr.appendChild(cd);
var fl=el('td');(r.f||'').split(';').forEach(function(x){if(x)fl.appendChild(el('span','chip '+(crit.test(x)?'bad':'warn'),x))});tr.appendChild(fl);
tr.onclick=function(){var n=tr.nextSibling;if(n&&n.className==='d'){n.remove();return}var dr=el('tr','d'),td=el('td');td.colSpan=7;var lines=[['Host',r.h],['IP',r.ip],['Port',r.p],['Reverse DNS',r.rd],['CNAME',(r.cn||'').split(';').join(' > ')],['Cloud',r.cl],['Service',r.sv],['Device name',r.dn],['Domain',r.dom],['Protocol',r.pi],['Final URL',r.fu],['Redirects',r.rc],['Server',r.srv],['Auth',r.au],['Categories',r.c],['OS hint',r.os],['Hardware',r.hw],['CPEs',r.cpe],['TLS supported',r.tsup],['Cert subject',r.cs],['Cert issuer',r.ci],['SANs',r.san],['Favicon mmh3',r.fav],['JARM',r.jarm],['JA4S',r.ja4s],['Advisories',r.adv],['Banner',r.b],['Notes',r.n]].filter(function(x){return x[1]}).map(function(x){return x[0]+': '+x[1]}).join('\n');td.appendChild(el('pre',null,lines));if(r.shs&&r.shs!=='ok'){td.appendChild(el('div','chip '+(r.shs==='failed'?'bad':'warn'),'Screenshot '+r.shs+(r.shr?': '+r.shr:'')))}if(r.shot&&/^[\w.\-]+\/[\w.\-]+\.png$/.test(r.shot)){var a=el('a');a.href=r.shot;a.target='_blank';a.rel='noopener';var im=el('img');im.src=r.shot;im.alt='screenshot of '+r.u;im.loading='lazy';im.style.maxWidth='min(100%,960px)';im.style.border='1px solid var(--bd,#888)';a.appendChild(im);td.appendChild(a)}dr.appendChild(td);tr.parentNode.insertBefore(dr,tr.nextSibling)};
tb.appendChild(tr)})}
Array.prototype.forEach.call(document.querySelectorAll('th'),function(th){th.onclick=function(){var k=th.getAttribute('data-k');if(sortK===k)sortD=-sortD;else{sortK=k;sortD=1}render()}});
q.oninput=render;sv.onchange=render;
document.getElementById('th').onclick=function(){var r=document.documentElement,c=r.getAttribute('data-theme');r.setAttribute('data-theme',c==='dark'?'light':(c==='light'?'dark':(matchMedia('(prefers-color-scheme: dark)').matches?'light':'dark')))};
render()})();
</script></body></html>
'@
#endregion
