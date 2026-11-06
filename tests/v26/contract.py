#!/usr/bin/env python3
"""Validates WebInventory JSONL files (and Tideline manifests) against schemas/*.schema.json.

  python3 tests/v26/contract.py FILE_OR_FOLDER...      kind from the file name; a folder: every WebInventory JSONL in it
Exit 0 when every line of every file is valid. Needs the jsonschema package."""
import json, pathlib, re, sys
from jsonschema import Draft202012Validator

root = pathlib.Path(__file__).resolve().parents[2]
schemas = {p.name[:-len(".schema.json")]: json.loads(p.read_text(encoding="utf-8")) for p in (root / "schemas").glob("*.schema.json")}
validators = {k: Draft202012Validator(v) for k, v in schemas.items()}
for v in schemas.values():
    Draft202012Validator.check_schema(v)

def kind_of(name):
    if re.match(r"^WebInventory_.+_delta\.jsonl$", name): return "webinventory.delta-1"
    if re.match(r"^WebInventory_.+_screenshots\.jsonl$", name): return "webinventory.screenshot-1"
    if re.match(r"^WebInventory_.+_vulns\.jsonl$", name) or re.match(r"^WebInventory_store_vulnerabilities_.+\.jsonl$", name): return "webinventory.vuln-1"
    if re.match(r"^WebInventory_.+_errors\.jsonl$", name): return "webinventory.error-1"
    if re.match(r"^WebInventory_store_", name): return None
    if re.match(r"^WebInventory_[^_]+_[^_]+\.jsonl$", name): return "webinventory.service-1"
    if name.endswith("manifest.json"): return "tideline-envelope-1"
    return None

files = []
for a in sys.argv[1:]:
    p = pathlib.Path(a)
    files += sorted(x for x in p.rglob("*.jsonl")) if p.is_dir() else [p]
bad = total = lines = 0
per = {}
for f in files:
    k = kind_of(f.name)
    if not k: continue
    total += 1; per[k] = per.get(k, 0) + 1
    text = f.read_text(encoding="utf-8")
    docs = [text] if k == "tideline-envelope-1" else text.splitlines()
    for i, line in enumerate(docs, 1):
        if not line.strip(): continue
        lines += 1
        try: d = json.loads(line)
        except Exception as e:
            bad += 1; print("FAIL %s:%d not JSON: %s" % (f, i, e)); continue
        errs = sorted(validators[k].iter_errors(d), key=lambda e: list(e.path))
        if errs:
            bad += 1
            if bad <= int(__import__("os").environ.get("CONTRACT_SHOW", "20")): print("FAIL %s:%d %s: %s" % (f, i, "/".join(map(str, errs[0].path)), errs[0].message[:200]))
print("contract: %d files (%s), %d records, %d invalid" % (total, ", ".join("%s %d" % kv for kv in sorted(per.items())), lines, bad))
sys.exit(1 if bad else 0)
