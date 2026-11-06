#!/usr/bin/env python3
"""Cross-check the scanner's cloud-range lookup (WebInv.Cloud, C#) against a longest-prefix match in Python's ipaddress
module over the same WebInventory.cloud.json: random addresses inside random ranges, at range edges, and anywhere.

usage: oracle.py [--pack dist/WebInventory.cloud.json] [--script dist/Invoke-WebInventory.ps1] [--n 20000] [--seed 1]
                 [--shell pwsh|powershell]   (powershell: Windows PowerShell 5.1, .NET Framework)
"""
import argparse, ipaddress, json, os, random, subprocess, sys, tempfile

ap = argparse.ArgumentParser()
ap.add_argument('--pack', default='dist/WebInventory.cloud.json'); ap.add_argument('--script', default='dist/Invoke-WebInventory.ps1')
ap.add_argument('--n', type=int, default=20000); ap.add_argument('--seed', type=int, default=1); ap.add_argument('--shell', default='pwsh')
a = ap.parse_args()
rnd = random.Random(a.seed)
pack = json.load(open(a.pack, encoding='utf-8'))
names = pack['names']
tab = {4: {}, 6: {}}
ents = []
for fam in ('v4', 'v6'):
    for e in pack[fam]:
        n, p, r, s = e.split('|')
        net = ipaddress.ip_network(n)
        tab[net.version].setdefault(net.prefixlen, {}).setdefault(int(net.network_address), (names[int(p)], names[int(r)], names[int(s)]))
        ents.append(net)


def lpm(ip):
    a_ = ipaddress.ip_address(ip)
    bits = a_.max_prefixlen; v = int(a_)
    for plen in sorted(tab[a_.version], reverse=True):
        k = (v >> (bits - plen)) << (bits - plen) if plen else 0
        hit = tab[a_.version][plen].get(k)
        if hit:
            return '/'.join(hit)
    return '-'


ips = []
for i in range(a.n):
    k = i % 4
    if k == 3:
        ips.append(str(ipaddress.IPv4Address(rnd.getrandbits(32))) if rnd.random() < 0.7 else str(ipaddress.IPv6Address(rnd.getrandbits(128))))
        continue
    net = rnd.choice(ents)
    lo, hi = int(net.network_address), int(net.broadcast_address)
    v = lo if k == 0 else hi if k == 1 else rnd.randint(lo, hi)
    for d in (0, -1, 1) if k < 2 else (0,):   # range edges and their neighbours
        x = v + d
        if 0 <= x < (1 << net.max_prefixlen):
            ips.append(str(ipaddress.ip_address(x) if net.version == 6 else ipaddress.IPv4Address(x)))
want = [lpm(ip) for ip in ips]
tmp = tempfile.mkdtemp(prefix='wi-cloud-oracle-')
ipf = os.path.join(tmp, 'ips.txt'); open(ipf, 'w').write('\n'.join(ips) + '\n')
ps = os.path.join(tmp, 'look.ps1')
open(ps, 'w').write(r'''param($Script, $Pack, $Ips, $OutFile)
$code = [IO.File]::ReadAllText($Script)
if ($code -notmatch "(?s)\`$EngineSource = @'\r?\n(.*?)\r?\n'@") { throw 'no engine' }
$at = @{ TypeDefinition = $Matches[1]; IgnoreWarnings = $true }
if ($PSVersionTable.PSEdition -ne 'Core') { $at.ReferencedAssemblies = @('System.Core', 'System.Security', 'System.Runtime.Serialization', 'System.Xml') }
Add-Type @at -WarningAction SilentlyContinue   # newer .NET marks some engine APIs obsolete: warnings only
$sw = [Diagnostics.Stopwatch]::StartNew()
[void][WebInv.Cloud]::Load([WebInv.Cloud]::Read([IO.File]::ReadAllText($Pack)), $null)
[Console]::Error.WriteLine("load ms " + $sw.ElapsedMilliseconds)
$sw.Restart()
$out = New-Object System.Text.StringBuilder
foreach ($ip in [IO.File]::ReadAllLines($Ips)) { if (-not $ip) { continue }; $r = [WebInv.Cloud]::Find($ip); [void]$out.AppendLine($(if ($r) { $r -join '/' } else { '-' })) }
[Console]::Error.WriteLine("lookup ms " + $sw.ElapsedMilliseconds)
[IO.File]::WriteAllText($OutFile, $out.ToString())
''')
outf = os.path.join(tmp, 'found.txt')
r = subprocess.run([a.shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps, os.path.abspath(a.script), os.path.abspath(a.pack), ipf, outf], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
sys.stderr.write(r.stdout)
got = open(outf).read().splitlines() if os.path.exists(outf) else []
sys.stderr.write(r.stderr)
bad = [(ip, w, g) for ip, w, g in zip(ips, want, got) if w != g]
hits = sum(1 for w in want if w != '-')
print('%d addresses (%d inside a published range): %d mismatches%s' % (len(ips), hits, len(bad) + abs(len(got) - len(ips)), '' if len(got) == len(ips) else ' (output length differs)'))
for b in bad[:10]:
    print('  %s want %s got %s' % b)
sys.exit(1 if bad or len(got) != len(ips) else 0)
