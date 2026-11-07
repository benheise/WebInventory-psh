#!/usr/bin/env python3
"""What a Tideline mock received for a run, against the run's own files: every part byte-identical (chunks
reassembled), state verified, the expected kinds present.

  received.py --data MOCKDATA --run-json RUN.json [--kinds services,errors,...] [--state verified]
Prints one summary line; exit 0 when everything matches."""
import argparse, collections, hashlib, json, os, pathlib, sys

ap = argparse.ArgumentParser()
ap.add_argument("--data", required=True); ap.add_argument("--run-json", required=True)
ap.add_argument("--kinds", default=""); ap.add_argument("--state", default="verified")
a = ap.parse_args()
rj = pathlib.Path(a.run_json); info = json.loads(rj.read_text(encoding="utf-8-sig"))
runs = [json.loads(p.read_text()) for p in pathlib.Path(a.data, "runs").glob("*/state.json")]
# 2.6.1: the envelope no longer carries the tool's own run id (tool_run); match on run.json's runUuid, or for a run
# made before 2.6 on the tool manifest's SHA-256, which the envelope does carry
def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
_tm = _sha(rj.parent / ("WebInventory_%s_manifest.txt" % info["runId"]))
mine = [r for r in runs if (info.get("runUuid") and r["run_id"] == info["runUuid"]) or
        (not info.get("runUuid") and _tm and r["manifest"].get("tool_manifest_sha256") == _tm)]
if len(mine) != 1:
    print("received: %d runs for %s at the mock" % (len(mine), info["runId"])); sys.exit(1)
r = mine[0]; m = r["manifest"]; rd = pathlib.Path(a.data, "runs", r["run_id"])
problems = []
# the envelope against Tideline's own schema (vendored in schemas/, see schemas/VENDORED.txt): 2.6.0 also wrote a
# tool_run field, which tideline-envelope/1 refuses
try:
    import jsonschema
    _env = json.loads((pathlib.Path(__file__).resolve().parents[2] / "schemas" / "tideline-envelope.1.json").read_text(encoding="utf-8"))
    for _e in jsonschema.Draft202012Validator(_env).iter_errors(m):
        problems.append("envelope fails tideline-envelope/1: %s" % _e.message)
except ImportError:
    problems.append("jsonschema is not installed: cannot check the envelope against tideline-envelope/1")
if r["state"] != a.state: problems.append("state %s, expected %s" % (r["state"], a.state))
if info.get("runUuid") and r["run_id"] != info["runUuid"]: problems.append("run_id %s is not run.json runUuid %s" % (r["run_id"], info["runUuid"]))
files = collections.defaultdict(list)
for p in m["parts"]:
    f = rd / ("part-%04d" % p["n"])
    if not f.exists(): problems.append("part %d not received" % p["n"]); continue
    files[p["name"]].append((p.get("chunk", 1), f.read_bytes(), p))
logs = {pathlib.Path(s.get(k, "")).name: s.get(k) for s in info.get("sessions", []) for k in ("runLog", "errorLog") if s.get(k)}
for name, chunks in files.items():
    data = b"".join(c[1] for c in sorted(chunks, key=lambda c: c[0]))
    local = rj.parent / name
    if not local.exists() and name in logs: local = pathlib.Path(logs[name])
    if not local.exists(): problems.append("%s: no local file" % name); continue
    if local.read_bytes() != data: problems.append("%s: received bytes differ from the local file" % name)
    if len(chunks) > 1 and hashlib.sha256(data).hexdigest() != chunks[0][2]["file_sha256"]: problems.append("%s: file_sha256 wrong" % name)
kinds = sorted({p["kind"] if p["kind"] != "artifact" else "artifact:" + p["role"] for p in m["parts"]})
for k in [x for x in a.kinds.split(",") if x]:
    if k not in kinds: problems.append("kind %s missing" % k)
chunked = sum(1 for c in files.values() if len(c) > 1)
print("received: run %s %s, %d parts (%d files%s), kinds %s, engagement %s, exit_code %s%s" % (
    r["run_id"], r["state"], len(m["parts"]), len(files), ", %d chunked" % chunked if chunked else "", ",".join(kinds),
    m.get("engagement"), m.get("exit_code"), "" if not problems else " -- " + "; ".join(problems)))
sys.exit(1 if problems else 0)
