
#region ---------- Port sets and protocol hints ----------
$PortSets = @{
    'web'          = @(80, 81, 443, 591, 2082, 2083, 2086, 2087, 3000, 4443, 5000, 5601, 7001, 7443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9443, 10000)
    'web-extended' = @(80, 81, 82, 88, 280, 300, 443, 444, 591, 593, 800, 832, 981, 1010, 1080, 1311, 2000, 2082, 2083, 2086, 2087, 2095, 2096, 2381, 2480,
        3000, 3001, 3128, 3333, 4000, 4243, 4443, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5480, 5601, 5800, 5985, 5986, 6443, 6543,
        7000, 7001, 7080, 7396, 7443, 7474, 8000, 8001, 8002, 8006, 8008, 8009, 8010, 8042, 8060, 8069, 8080, 8081, 8082, 8083, 8086, 8088, 8089,
        8090, 8091, 8118, 8123, 8172, 8180, 8181, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8530, 8531, 8834, 8880, 8888, 8983, 9000, 9001, 9043,
        9060, 9080, 9090, 9091, 9100, 9200, 9443, 9800, 9981, 10000, 10250, 10443, 12443, 15672, 16080, 18080, 18091, 18092, 20720, 28017)
    'mgmt'         = @(80, 443, 1311, 2381, 4443, 5480, 5985, 5986, 6443, 8006, 8080, 8443, 8834, 9090, 9443, 10000, 10443)
}
# TLS-first on these; plaintext-first everywhere else (auto-switch either way)
$TlsHintPorts = @(443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 1311, 2083, 2087, 2381, 3269, 4443, 5061, 5480, 5986, 6443, 7443,
    8006, 8443, 8531, 8834, 9043, 9443, 10250, 10443, 12443)
# HTTP servers never speak first: skip the NULL-probe banner wait on these
$HttpPorts = @(80, 81, 443, 591, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090)
# Passive version advisories: evaluated against versions the server itself advertises (Server / X-Powered-By).
# Status is "likely exposed by version", never a test of exploitability; vendor builds may carry backported fixes.
$Advisories = @(
    @{
        Id = 'PHP2Shell'; Product = 'PHP'; Cves = 'CVE-2026-109618, CVE-2026-109619'
        Regex = '(?i)\bPHP/(\d+\.\d+\.\d+)([^\s;,)]*)'      # group1 = version, group2 = vendor/package suffix
        Fixed = @('8.5.12', '8.4.27', '8.3.36', '8.2.35')    # PHP security releases of 2026-10-21
        MinBranch = '8.2'                                    # 8.1 and older: no upstream release (source backports / vendor packages only)
        HighRisk = '(?i)^Apache\b.*\bPHP/'                   # PHP token in an Apache Server header => mod_php (highest-risk SAPI per PHP)
        HighRiskLabel = 'mod_php'
        Note = 'Fixed in 8.5.12/8.4.27/8.3.36/8.2.35 (2026-10-21); <=8.1 needs a vendor/backported build. Follow-on CVE-2026-115560 (session upload progress) awaits a later release; interim mitigation session.upload_progress.enabled=0.'
    }
)
# Detections in these categories raise the MgmtInterface flag
$MgmtCategories = @('Out-of-band mgmt', 'Admin panel', 'Virtualization', 'Firewall', 'Network device', 'Load balancer', 'Storage', 'Backup', 'Building automation', 'Power')
# -IdentifyPaths: fixed list of public landing/version endpoints used ONLY to confirm product identity/version
$IdentifyPathList = @(
    '/owa/auth/logon.aspx', '/certsrv/', '/adfs/ls/idpinitiatedsignon.aspx', '/RDWeb/', '/remote/login', '/global-protect/login.esp',
    '/+CSCOE+/logon.html', '/dana-na/auth/url_default/welcome.cgi', '/vpn/index.html', '/version', '/api/health', '/api/v1/status/buildinfo',
    '/rest/applinks/1.0/manifest', '/.well-known/openid-configuration', '/manager/html', '/v2/')
# v2.7 -ApiDocPaths: API documents and consoles, and Docker files, GET only. A path counts only when its 200 body holds the
# document's own keywords (Match); NotHtml refuses an HTML page there (a site's catch-all page is not a YAML file).
# GraphQL introspection is a POST and is not sent.
$ApiDocPathList = @(
    @{ Path = '/openapi.json'; Kind = 'openapi'; Flag = 'ApiDocsExposed'; NotHtml = $true; Match = '"(openapi|swagger)"\s*:\s*"[23]' }
    @{ Path = '/swagger.json'; Kind = 'openapi'; Flag = 'ApiDocsExposed'; NotHtml = $true; Match = '"(openapi|swagger)"\s*:\s*"[23]' }
    @{ Path = '/v3/api-docs'; Kind = 'openapi'; Flag = 'ApiDocsExposed'; NotHtml = $true; Match = '"(openapi|swagger)"\s*:\s*"[23]' }
    @{ Path = '/v2/api-docs'; Kind = 'openapi'; Flag = 'ApiDocsExposed'; NotHtml = $true; Match = '"(openapi|swagger)"\s*:\s*"[23]' }
    @{ Path = '/swagger/v1/swagger.json'; Kind = 'openapi'; Flag = 'ApiDocsExposed'; NotHtml = $true; Match = '"(openapi|swagger)"\s*:\s*"[23]' }
    @{ Path = '/openapi.yaml'; Kind = 'openapi'; Flag = 'ApiDocsExposed'; NotHtml = $true; Match = '(?m)^(openapi|swagger)\s*:\s*["'']?[23]' }
    @{ Path = '/swagger-ui/index.html'; Kind = 'swagger-ui'; Flag = 'ApiDocsExposed'; NotHtml = $false; Match = 'SwaggerUIBundle|swagger-ui-bundle\.js' }
    @{ Path = '/swagger-ui.html'; Kind = 'swagger-ui'; Flag = 'ApiDocsExposed'; NotHtml = $false; Match = 'SwaggerUIBundle|swagger-ui-bundle\.js|springfox' }
    @{ Path = '/redoc'; Kind = 'redoc'; Flag = 'ApiDocsExposed'; NotHtml = $false; Match = '<redoc\b|redoc\.standalone\.js' }
    @{ Path = '/graphiql'; Kind = 'graphiql'; Flag = 'ApiDocsExposed'; NotHtml = $false; Match = 'graphiql(\.min)?\.(js|css)|GraphiQL\.create' }
    @{ Path = '/playground'; Kind = 'graphql-playground'; Flag = 'ApiDocsExposed'; NotHtml = $false; Match = 'GraphQLPlayground|graphql-playground' }
    @{ Path = '/docker-compose.yml'; Kind = 'docker-compose'; Flag = 'DockerFileExposed'; NotHtml = $true; Match = '(?m)^services\s*:\s*$[\s\S]*^\s+(image|build)\s*:' }
    @{ Path = '/docker-compose.yaml'; Kind = 'docker-compose'; Flag = 'DockerFileExposed'; NotHtml = $true; Match = '(?m)^services\s*:\s*$[\s\S]*^\s+(image|build)\s*:' }
    @{ Path = '/Dockerfile'; Kind = 'dockerfile'; Flag = 'DockerFileExposed'; NotHtml = $true; Match = '(?im)^FROM\s+[a-z0-9][\w./:@-]*(\s+AS\s+\w+)?\s*$' }
)
# v2.7 Appliance column: detections in these categories (and every hardware detection) name the device itself
$ApplianceCategories = @('Firewall', 'Network device', 'Network devices', 'Load balancer', 'Load balancers', 'Storage', 'NAS', 'Router',
    'Broadband Router', 'Switch', 'VPN', 'Security Appliance', 'Network Appliance', 'Network Management Device', 'SD-WAN Appliance',
    'Out-of-band mgmt', 'Lights Out Management', 'Power', 'Power Device', 'Building automation', 'Printer', 'IP Camera', 'Appliance')
#endregion

#region ---------- Target / port / exclusion parsing (nmap-compatible syntax) ----------
function Read-ListFile {
    param([string]$Path, [string]$What)
    if (-not $Path) { return @() }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$What file not found: $Path" }
    $n = 0
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($line in [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $Path).ProviderPath)) {
        $n++
        $t = ($line -replace '#.*$', '').Trim()
        if (-not $t) { continue }
        foreach ($tok in ($t -split '\s+')) { if ($tok) { $out.Add([pscustomobject]@{ Text = $tok; Src = ('{0}:{1}' -f (Split-Path -Leaf $Path), $n) }) } }
    }
    $out.ToArray()
}

function Expand-Ports {
    param([string]$Spec)
    $set = New-Object 'System.Collections.Generic.SortedSet[int]'
    foreach ($p in ($Spec -split '[,\s]+' | Where-Object { $_ })) {
        $pl = $p.ToLowerInvariant()
        if ($PortSets.ContainsKey($pl)) { foreach ($x in $PortSets[$pl]) { [void]$set.Add($x) } }
        elseif ($pl -eq 'all') { for ($x = 1; $x -le 65535; $x++) { [void]$set.Add($x) } }
        elseif ($p -match '^(\d{1,5})-(\d{1,5})$') {
            $a = [int]$Matches[1]; $b = [int]$Matches[2]
            if ($a -lt 1 -or $b -gt 65535 -or $a -gt $b) { throw "Bad port range '$p'" }
            for ($x = $a; $x -le $b; $x++) { [void]$set.Add($x) }
        }
        elseif ($p -match '^\d{1,5}$' -and [int]$p -ge 1 -and [int]$p -le 65535) { [void]$set.Add([int]$p) }
        else { throw "Bad port '$p' (use numbers, ranges or: web, web-extended, mgmt, all)" }
    }
    if ($set.Count -eq 0) { throw "Empty port specification '$Spec'" }
    , @($set)
}

function Expand-Octet {
    param([string]$Octet)
    $set = New-Object 'System.Collections.Generic.SortedSet[int]'
    foreach ($part in $Octet.Split(',')) {
        if ($part -match '^(\d*)-(\d*)$') {
            $a = if ($Matches[1]) { [int]$Matches[1] } else { 0 }
            $b = if ($Matches[2]) { [int]$Matches[2] } else { 255 }
            if ($a -gt $b -or $b -gt 255) { throw "Bad octet range '$part'" }
            for ($x = $a; $x -le $b; $x++) { [void]$set.Add($x) }
        }
        elseif ($part -match '^\d{1,3}$' -and [int]$part -le 255) { [void]$set.Add([int]$part) }
        else { throw "Bad octet '$part'" }
    }
    , @($set)
}

# Returns @{ Ranges = List[long[]]; Names = List[string]; Count = long } without expanding addresses
function Get-SpecRanges {
    param([string]$Spec)
    $Spec = $Spec.Trim()
    $out = @{ Ranges = (New-Object System.Collections.Generic.List[object]); Names = (New-Object System.Collections.Generic.List[string]); Count = [long]0 }
    $ipRx = '\d{1,3}(?:\.\d{1,3}){3}'
    if ($Spec -match "^($ipRx)/(\d{1,2})$") {
        $base = [WebInv.Util]::Ip4($Matches[1]); $bits = [int]$Matches[2]
        if ($base -lt 0 -or $bits -gt 32) { throw "Bad CIDR '$Spec'" }
        $size = [long]1 -shl (32 - $bits)
        $start = $base - ($base % $size)
        $out.Ranges.Add([long[]]@($start, ($start + $size - 1))); $out.Count = $size
    }
    elseif ($Spec -match "^($ipRx)-($ipRx)$") {
        $a = [WebInv.Util]::Ip4($Matches[1]); $b = [WebInv.Util]::Ip4($Matches[2])
        if ($a -lt 0 -or $b -lt 0 -or $a -gt $b) { throw "Bad range '$Spec'" }
        $out.Ranges.Add([long[]]@($a, $b)); $out.Count = $b - $a + 1
    }
    elseif ($Spec -match '^[\d,\-]+(?:\.[\d,\-]+){3}$') {
        $o = @(); foreach ($part in $Spec.Split('.')) { $o += , (Expand-Octet $part) }
        $count = [long]$o[0].Count * $o[1].Count * $o[2].Count * $o[3].Count
        $out.Count = $count
        if ($count -gt $MaxTargets -and -not $Force) { throw "Spec '$Spec' expands to $count hosts (> -MaxTargets $MaxTargets). Narrow it or use -Force." }
        foreach ($a in $o[0]) { foreach ($b in $o[1]) { foreach ($c in $o[2]) {
            # coalesce contiguous last-octet runs into ranges
            $runStart = -1; $prev = -2
            foreach ($d in $o[3]) {
                if ($d -ne $prev + 1) {
                    if ($runStart -ge 0) { $out.Ranges.Add([long[]]@(([long]$a * 16777216 + $b * 65536 + $c * 256 + $runStart), ([long]$a * 16777216 + $b * 65536 + $c * 256 + $prev))) }
                    $runStart = $d
                }
                $prev = $d
            }
            if ($runStart -ge 0) { $out.Ranges.Add([long[]]@(([long]$a * 16777216 + $b * 65536 + $c * 256 + $runStart), ([long]$a * 16777216 + $b * 65536 + $c * 256 + $prev))) }
        } } }
    }
    elseif ($Spec -match '^[\d.]+$') {
        # never hand a partial numeric to the resolver: '7.1' would become 7.0.0.1 and '443' 0.0.1.187
        throw "Ambiguous numeric target '$Spec' (not a full IPv4 address). If it came from 'host:80,443' or an octet range like '10.0.3-5,7.1', quote the whole value."
    }
    elseif ($Spec -match '^[A-Za-z0-9_](?:[A-Za-z0-9_.\-]*[A-Za-z0-9_])?\.?$' -or $Spec -match '^[0-9A-Fa-f:.]+(%\w+)?$') {
        $ip6 = $null
        if ($Spec.Contains(':') -and -not [Net.IPAddress]::TryParse($Spec, [ref]$ip6)) { throw "Bad IPv6 address '$Spec'" }
        $out.Names.Add($Spec.TrimEnd('.')); $out.Count = 1
    }
    else { throw "Unrecognised host specification '$Spec'" }
    $out
}

# A single token may hold a comma-separated list ('10.0.0.1,10.0.0.9'); nmap octet specs ('192.168.3-5,7.1') are tried whole first
function Get-SpecList {
    param([string]$Text)
    try { return , @(Get-SpecRanges $Text) }
    catch {
        if (-not $Text.Contains(',')) { throw }
        $first = $_
        $list = @()
        foreach ($piece in ($Text -split ',' | Where-Object { $_ })) {
            try { $list += , (Get-SpecRanges $piece) } catch { throw $first }
        }
        return , $list
    }
}

function Split-HostPort {
    param([string]$Entry)
    $e = $Entry.Trim()
    if ($e -match '^(https?)://') {
        try { $u = [Uri]$e } catch { throw "Bad URL '$e'" }
        return @{ Spec = $u.Host.Trim('[', ']'); Ports = "$($u.Port)"; Scheme = $u.Scheme }
    }
    if ($e -match '^(smb|rdp|snmp)://([^/]+)/?$') {
        # protocol URL: the service on a non-standard port (default 445 / 3389 / 161)
        $sch = $Matches[1].ToLowerInvariant(); $auth = $Matches[2]
        $dflt = @{ smb = '445'; rdp = '3389'; snmp = '161' }[$sch]
        if ($auth -match '^\[([^\]]+)\](?::(\d{1,5}))?$') { return @{ Spec = $Matches[1]; Ports = $(if ($Matches[2]) { $Matches[2] } else { $dflt }); Scheme = $sch } }
        if ($auth -match '^([^:\[\]]+)(?::(\d{1,5}))?$') { return @{ Spec = $Matches[1]; Ports = $(if ($Matches[2]) { $Matches[2] } else { $dflt }); Scheme = $sch } }
        throw "Bad URL '$e'"
    }
    if ($e -match '^\[([0-9a-fA-F:.%\w]+)\](?::([\d,\-]+))?$') { return @{ Spec = $Matches[1]; Ports = $Matches[2]; Scheme = '' } }
    if (($e.Split(':')).Count -gt 2) { return @{ Spec = $e; Ports = $null; Scheme = '' } }                       # bare IPv6
    if ($e -match '^([^:\s]+):([\w,\-]+)$') { return @{ Spec = $Matches[1]; Ports = $Matches[2]; Scheme = '' } }
    @{ Spec = $e; Ports = $null; Scheme = '' }
}

function Add-SpecToSet {
    param([WebInv.RangeSet]$Set, [string]$Spec)
    $r = Get-SpecRanges $Spec
    foreach ($x in $r.Ranges) { $Set.AddRange($x[0], $x[1]) }
    foreach ($n in $r.Names) { $Set.AddName($n) }
}

function Format-UriHost { param([string]$H) if ($H.Contains(':')) { "[$H]" } else { $H } }
#endregion
