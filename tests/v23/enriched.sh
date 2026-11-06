#!/usr/bin/env bash
# Store gating of the v2.3 probes: a run with -TlsFingerprint after runs without it records Enriched (not Changed);
# a later run without it keeps the values (no Changed/removed); -NoJa4s keeps Ja4s. usage: enriched.sh <workdir> [script]
set -u
W=${1:?workdir}; SCRIPT=$(readlink -f "${2:-$(dirname "$0")/../../dist/Invoke-WebInventory.ps1}")
rm -rf "$W"; mkdir -p "$W"; cd "$W"
python3 - "$W" <<'P'
import json, os, sys
W = sys.argv[1]
def run(name, rid, day, jarm, ja4s, prof):
    d = os.path.join(W, name); os.makedirs(d)
    rows = []
    for i, port in enumerate((443, 8443)):
        r = {"RunId": rid, "Host": "10.0.0.%d" % (i + 1), "IP": "10.0.0.%d" % (i + 1), "Port": port, "Vhost": False, "State": "open", "IsWeb": True,
             "Service": "https", "Scheme": "https", "Url": "https://10.0.0.%d:%d/" % (i + 1, port), "Title": "App", "TlsVersion": "TLS1.3", "CertSha256": "c" * 64,
             "Jarm": jarm, "Ja4s": ja4s, "Notes": ""}
        rows.append(r)
    with open(os.path.join(d, "WebInventory_%s.jsonl" % rid), "w") as f:
        for r in rows: f.write(json.dumps(r) + "\n")
    with open(os.path.join(d, "WebInventory_%s_progress.txt" % rid), "w") as f:
        for r in rows: f.write("%s|%s|%d\n" % (r["Host"], r["IP"], r["Port"]))
    p = {"tlsScan": True, "favicon": True, "extras": True, "options": False, "identifyPaths": False, "probeSans": False, "reverseDns": False}
    p.update(prof)
    json.dump({"format": 1, "runId": rid, "startedAt": "2026-10-%02dT10:00:00+00:00" % day, "finishedAt": "2026-10-%02dT10:05:00+00:00" % day, "complete": True,
               "synthesized": False, "scanner": "WebInventory 2.3.0", "tag": "", "operator": "t", "computer": "t", "checks": 2, "profile": p}, open(os.path.join(d, "WebInventory_%s_run.json" % rid), "w"))
J = "2ad2ad0002ad2ad00042d42d00000045d9c61f898d3d72d7a153fdd2347f3c"; S = "t130200_1302_a56c5b993250"
run("r1", "20261001_100000", 1, "", "", {})
run("r2", "20261002_100000", 2, J, S, {"tlsFingerprint": True, "ja4s": True})
run("r3", "20261003_100000", 3, "", "", {})
run("r4", "20261004_100000", 4, J, "", {"tlsFingerprint": True})
run("r5", "20261005_100000", 5, J.replace("2ad", "3ad", 1), S, {"tlsFingerprint": True, "ja4s": True})
P
pass=0; fail=0
for r in 1 2 3 4 5; do pwsh -NoProfile -File "$SCRIPT" -Store "$W/st" -StoreEngine File -ImportRun "$W/r$r" > "$W/imp$r.out" 2>&1; done
pwsh -NoProfile -File "$SCRIPT" -Store "$W/st" -StoreQuery Changes -OutputDir "$W/q" -NoHtml > /dev/null 2>&1
python3 - "$W" <<'P'
import csv, glob, sys
rows = list(csv.DictReader(open(glob.glob(sys.argv[1] + "/q/*changes*.csv")[0], encoding="utf-8-sig")))
by = {}
for r in rows: by.setdefault(r["RunId"], set()).add((r["Change"], r["Field"]))
checks = [
  ("run 2 (first -TlsFingerprint): Enriched Jarm+Ja4s, no Changed", by.get("20261002_100000") == {("Enriched", "Jarm"), ("Enriched", "Ja4s")}),
  ("run 3 (without -TlsFingerprint): no events (values kept)", "20261003_100000" not in by),
  ("run 4 (-NoJa4s): no events (Ja4s kept)", "20261004_100000" not in by),
  ("run 5 (different JARM): Changed Jarm", by.get("20261005_100000") == {("Changed", "Jarm")}),
]
ok = 0
for name, res in checks:
    print(("PASS " if res else "FAIL ") + name); ok += res
print("enriched: %d/%d" % (ok, len(checks)))
sys.exit(0 if ok == len(checks) else 1)
P
