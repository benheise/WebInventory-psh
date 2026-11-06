#!/usr/bin/env python3
"""Accuracy gate for performance work: compares two WebInventory result sets field by field.

usage: golden.py <reference-dir> <candidate-dir> [--quiet]
Each dir holds one run's WebInventory_*.csv and WebInventory_*.jsonl. Rows are keyed by Host|IP|Port|Vhost.
Volatile fields (run id, timestamps, measured response time) are ignored; everything else must be identical,
including detections, versions, CPEs, flags, advisories, TLS matrix, certificate fields and notes.
Exit code 0 = identical, 1 = differences (printed), 2 = usage/IO error.
"""
import csv, glob, json, os, sys

VOLATILE = {"RunId", "ScanTag", "ScannedAt", "ResponseMs"}
# Which job claims a SAN vhost first (IP target vs hostname target) is a race; the vhost row itself must exist and match.
RACY = {"VhostOf"}


def load(d):
    c = [p for p in glob.glob(os.path.join(d, "WebInventory_*.csv")) if not p.endswith("_delta.csv")]
    j = glob.glob(os.path.join(d, "WebInventory_*.jsonl"))
    if len(c) != 1 or len(j) != 1:
        raise SystemExit("expected exactly one CSV and one JSONL in %s (found %d/%d)" % (d, len(c), len(j)))
    rows = {}
    with open(c[0], encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            rows[(r["Host"], r["IP"], r["Port"], r["Vhost"])] = r
    js = {}
    with open(j[0], encoding="utf-8") as f:
        for line in f:
            if line.strip():
                o = json.loads(line)
                js[(str(o["Host"]), str(o["IP"]), str(o["Port"]), str(o["Vhost"]))] = o
    return rows, js


def norm_json(o):
    o = dict(o)
    for k in VOLATILE | RACY:
        o.pop(k, None)
    # Port/Vhost may be serialised as number/bool or string depending on the writer; compare as text for keys only
    return o


def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    quiet = "--quiet" in sys.argv
    ra, ja = load(sys.argv[1]); rb, jb = load(sys.argv[2])
    diffs = []
    for k in sorted(set(ra) | set(rb)):
        if k not in rb: diffs.append("MISSING in candidate: %s" % "|".join(k)); continue
        if k not in ra: diffs.append("EXTRA in candidate: %s" % "|".join(k)); continue
        for col in ra[k]:
            if col in VOLATILE or col in RACY: continue
            if ra[k][col] != rb[k].get(col):
                diffs.append("CSV %s %s: %r -> %r" % ("|".join(k), col, ra[k][col][:160], (rb[k].get(col) or "")[:160]))
    for k in sorted(set(ja) | set(jb)):
        if k not in ja or k not in jb:
            diffs.append("JSONL key mismatch: %s" % "|".join(k)); continue
        a, b = norm_json(ja[k]), norm_json(jb[k])
        # columns a newer version appended are fine while empty (v2.3: DeviceName, Domain, ProtocolInfo, Jarm, Ja4s)
        for extra in [x for x in b if x not in a and b[x] in ("", None)]:
            b.pop(extra)
        if a != b:
            for col in sorted(set(a) | set(b)):
                if a.get(col) != b.get(col):
                    diffs.append("JSONL %s %s: %s -> %s" % ("|".join(k), col, json.dumps(a.get(col))[:200], json.dumps(b.get(col))[:200]))
    print("golden: %d rows reference, %d rows candidate, %d differences" % (len(ra), len(rb), len(diffs)))
    if not quiet:
        for d in diffs[:60]: print("  " + d)
        if len(diffs) > 60: print("  ... %d more" % (len(diffs) - 60))
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
