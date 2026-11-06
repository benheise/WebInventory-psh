#!/usr/bin/env python3
"""Compare two WebInventory result CSVs field by field (rows keyed by Host|IP|Port|Vhost), ignoring volatile fields."""
import csv, sys
IGN = {"RunId", "ScanTag", "ScannedAt", "ResponseMs", "BodySha256", "BodyLength", "CertDaysLeft"}
extra = set(sys.argv[3].split(",")) if len(sys.argv) > 3 and sys.argv[3] else set()
def load(p):
    with open(p, encoding="utf-8-sig") as f:
        return {(r["Host"], r["IP"], r["Port"], r["Vhost"]): r for r in csv.DictReader(f)}
a, b = load(sys.argv[1]), load(sys.argv[2])
bad = 0
for k in sorted(set(a) | set(b)):
    if k not in a or k not in b:
        print("ONLY IN", "A" if k in a else "B", k); bad += 1; continue
    for f in a[k]:
        if f in IGN or f in extra: continue
        if a[k][f] != b.get(k, {}).get(f):
            print("DIFF", k, f, repr(a[k][f])[:120], "!=", repr(b[k].get(f))[:120]); bad += 1
print("rows A=%d B=%d differences=%d" % (len(a), len(b), bad))
sys.exit(1 if bad else 0)
