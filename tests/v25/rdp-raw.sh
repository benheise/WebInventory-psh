#!/usr/bin/env bash
# -Rdp: a TLS 1.0-only RDP server (which the PowerShell 7 / OpenSSL client refuses, like a hardened Windows host)
# still gives its certificate through the raw ClientHello; an NLA server keeps the Schannel path.
# usage: rdp-raw.sh <workdir> <cert.pem> <key.pem> [script]
set -u
W=${1:?workdir}; CRT=${2:?cert}; KEY=${3:?key}; SCRIPT=$(readlink -f "${4:-$(dirname "$0")/../../dist/Invoke-WebInventory.ps1}")
LAB=$(cd "$(dirname "$0")/../../lab" && pwd)
rm -rf "$W"; mkdir -p "$W/out"; cd "$W"
python3 "$LAB/fakerdp.py" 13389 tls "$CRT" "$KEY" --tls10 > rdp10.log 2>&1 & P1=$!
python3 "$LAB/fakerdp.py" 13390 nla "$CRT" "$KEY" > rdp.log 2>&1 & P2=$!
trap 'kill $P1 $P2 2>/dev/null' EXIT
sleep 1
printf 'rdp://127.0.0.1:13389\nrdp://127.0.0.1:13390\n' > t.txt
pwsh -NoProfile -File "$SCRIPT" -TargetFile t.txt -Rdp -OutputDir "$W/out" -NoProgress -Quiet -NoHtml > scan.txt 2>&1
python3 - "$W" <<'P'
import csv, glob, sys
rows = {r["Port"]: r for f in glob.glob(sys.argv[1] + "/out/WebInventory_*.csv") for r in csv.DictReader(open(f, encoding="utf-8-sig"))}
a, b = rows.get("13389", {}), rows.get("13390", {})
checks = [
  ("TLS 1.0-only RDP server: certificate through the raw ClientHello", a.get("CertSource") == "rdp-raw" and a.get("TlsVersion") == "TLS1.0" and "CN=localhost" in a.get("CertSubject", "")),
  ("TLS 1.0-only RDP server: WeakTLS flag and the note in ProtocolInfo", "WeakTLS:TLS1.0" in a.get("Flags", "") and "raw ClientHello" in a.get("ProtocolInfo", "")),
  ("NLA server: Schannel path unchanged (CertSource rdp, NTLM build)", b.get("CertSource") == "rdp" and "osBuild=10.0.20348" in b.get("ProtocolInfo", "")),
]
ok = 0
for n, r in checks:
    print(("PASS " if r else "FAIL ") + n); ok += r
print("rdp-raw: %d/%d" % (ok, len(checks)))
sys.exit(0 if ok == len(checks) else 1)
P
