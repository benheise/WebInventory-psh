#!/usr/bin/env bash
# Store gating of the v2.5 fields: the first run with cloud ranges and -Cname records Enriched (not Changed); a run
# without them keeps the values; a real change is Changed. usage: gating.sh <workdir> [script]
set -u
W=${1:?workdir}; SCRIPT=$(readlink -f "${2:-$(dirname "$0")/../../dist/Invoke-WebInventory.ps1}")
rm -rf "$W"; mkdir -p "$W"; cd "$W"
python3 - "$W" <<'P'
import json, os, sys
W = sys.argv[1]
def run(name, rid, day, cloud, cname, prof):
    d = os.path.join(W, name); os.makedirs(d)
    rows = []
    for i, port in enumerate((443, 8443)):
        r = {"RunId": rid, "Host": "app%d.example.test" % (i + 1), "IP": "52.0.0.%d" % (i + 1), "Port": port, "Vhost": False, "State": "open", "IsWeb": True,
             "Service": "https", "Scheme": "https", "Url": "https://app%d.example.test:%d/" % (i + 1, port), "Title": "App", "TlsVersion": "TLS1.3",
             "Cname": cname, "Cloud": cloud[0], "CloudRegion": cloud[1], "CloudService": cloud[2], "Notes": ""}
        rows.append(r)
    with open(os.path.join(d, "WebInventory_%s.jsonl" % rid), "w") as f:
        for r in rows: f.write(json.dumps(r) + "\n")
    with open(os.path.join(d, "WebInventory_%s_progress.txt" % rid), "w") as f:
        for r in rows: f.write("%s|%s|%d\n" % (r["Host"], r["IP"], r["Port"]))
    p = {"tlsScan": True, "favicon": True, "extras": True, "options": False, "identifyPaths": False, "probeSans": False, "reverseDns": False}
    p.update(prof)
    json.dump({"format": 1, "runId": rid, "startedAt": "2026-10-%02dT10:00:00+00:00" % day, "finishedAt": "2026-10-%02dT10:05:00+00:00" % day, "complete": True,
               "synthesized": False, "scanner": "WebInventory 2.5.0", "tag": "", "operator": "t", "computer": "t", "checks": 2, "profile": p}, open(os.path.join(d, "WebInventory_%s_run.json" % rid), "w"))
NONE = ("", "", ""); AWS = ("AWS", "us-east-1", "EC2"); AWS2 = ("AWS", "us-east-1", "ELB")
run("r1", "20261001_100000", 1, NONE, "", {})
run("r2", "20261002_100000", 2, AWS, "lb1.elb.amazonaws.com", {"cloud": True, "cname": True})
run("r3", "20261003_100000", 3, NONE, "", {})
run("r4", "20261004_100000", 4, AWS2, "", {"cloud": True})
run("r5", "20261005_100000", 5, AWS2, "lb2.elb.amazonaws.com", {"cloud": True, "cname": True})
P
for r in 1 2 3 4 5; do pwsh -NoProfile -File "$SCRIPT" -Store "$W/st" -StoreEngine File -ImportRun "$W/r$r" > "$W/imp$r.out" 2>&1; done
pwsh -NoProfile -File "$SCRIPT" -Store "$W/st" -StoreQuery Changes -OutputDir "$W/q" -NoHtml > /dev/null 2>&1
python3 - "$W" <<'P'
import csv, glob, sys
rows = list(csv.DictReader(open(glob.glob(sys.argv[1] + "/q/*changes*.csv")[0], encoding="utf-8-sig")))
by = {}
for r in rows: by.setdefault(r["RunId"], set()).add((r["Change"], r["Field"]))
checks = [
  ("run 2 (first run with cloud ranges and -Cname): Enriched Cloud, CloudRegion, CloudService, Cname; no Changed",
   by.get("20261002_100000") == {("Enriched", "Cloud"), ("Enriched", "CloudRegion"), ("Enriched", "CloudService"), ("Enriched", "Cname")}),
  ("run 3 (without either): no events (values kept)", "20261003_100000" not in by),
  ("run 4 (cloud only, service moved): Changed CloudService; Cname kept", by.get("20261004_100000") == {("Changed", "CloudService")}),
  ("run 5 (-Cname, new chain): Changed Cname", by.get("20261005_100000") == {("Changed", "Cname")}),
]
ok = 0
for name, res in checks:
    print(("PASS " if res else "FAIL ") + name); ok += res
print("gating v2.5: %d/%d" % (ok, len(checks)))
if ok != len(checks): print(sorted(by.items()))
sys.exit(0 if ok == len(checks) else 1)
P
