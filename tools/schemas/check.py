#!/usr/bin/env python3
"""Checks the vendored Tideline schemas in schemas/ against what src/ writes (tools/schemas/vendor.sh copies them in).

  service    the properties are $Columns (src/40-output.ps1) in order, then Detections; the integer columns are
             integers; each detection's properties are what src/30-worker.ps1 writes, in order
  vuln       the properties are VulnMatch.Columns (src/vuln.cs) in order
  screenshot the properties are the screenshot index columns (src/35-extras.ps1) in order
  delta      Change, Key, Field, Old, New;   error: time, level, category, target, message
  envelope   minor 1 or later (the part fields WebInventory 2.6.1 sends) and no tool_run
  all        required = the properties not marked x-since-minor (fields added in a minor are optional), x-since-minor
             not above the schema's x-minor, and SHA256SUMS matches the files
Exit 0 when they all hold."""
import hashlib, json, pathlib, re, sys

root = pathlib.Path(__file__).resolve().parents[2]
src, sdir = root / "src", root / "schemas"
problems = []

def ps_list(text, var):
    text = re.sub(r"(?m)^\s*#.*$", "", text)   # comment lines inside a list may hold parentheses
    m = re.search(r"\$" + re.escape(var) + r" = @\((.*?)\)\s*\n", text, re.S)
    if not m: sys.exit("list $%s not found" % var)
    return re.findall(r"'([^']+)'", m.group(1))

output = (src / "40-output.ps1").read_text(encoding="utf-8")
columns = ps_list(output, "Columns")
integers = set(ps_list(output, "script:JsonlIntegers"))
vuln_cs = (src / "vuln.cs").read_text(encoding="utf-8")
vcols = re.findall(r'"([^"]+)"', re.search(r"public static readonly string\[\] Columns = \{(.*?)\};", vuln_cs, re.S).group(1))
extras = (src / "35-extras.ps1").read_text(encoding="utf-8")
shot_cols = re.findall(r"'([^']+)'", re.search(r"foreach \(\$c in ('Url', 'Host'.*?)\) \{ \$o\[\$c\]", extras).group(1))
worker = (src / "30-worker.ps1").read_text(encoding="utf-8")
det_keys = re.findall(r"(\w+) = \$d\.\w+", re.search(r"\$detOut\.Add\(\[ordered\]@\{(.*?)\}\)", worker).group(1))

# ---- the files are the vendored ones
sums = {}
for line in (sdir / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    if line.strip():
        h, name = line.split(None, 1)
        sums[name.strip()] = h
files = sorted(p.name for p in sdir.glob("*.json"))
if sorted(sums) != files:
    problems.append("SHA256SUMS lists %s but schemas/ holds %s" % (sorted(sums), files))
for name, h in sums.items():
    p = sdir / name
    if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() != h:
        problems.append("%s does not match SHA256SUMS (edited after vendoring?)" % name)
vendored = sdir / "VENDORED.txt"
if not vendored.exists():
    problems.append("schemas/VENDORED.txt is missing (vendor with tools/schemas/vendor.sh)")

def schema(name, sid):
    d = json.loads((sdir / name).read_text(encoding="utf-8"))
    if d.get("x-tideline-schema") != sid or d.get("$id") != "urn:tideline:schema:" + sid:
        problems.append("%s: id is not %s" % (name, sid))
    return d

def check_required(label, d, minor):
    props = d.get("properties", {})
    since = {k for k, v in props.items() if isinstance(v, dict) and "x-since-minor" in v}
    want = [k for k in props if k not in since]
    if sorted(d.get("required", [])) != sorted(want):
        problems.append("%s: required %s, expected the properties without x-since-minor %s" % (label, d.get("required"), want))
    for k in since:
        if props[k]["x-since-minor"] > minor:
            problems.append("%s.%s: x-since-minor %s is above x-minor %s" % (label, k, props[k]["x-since-minor"], minor))

def expect_props(label, d, want):
    got = list(d.get("properties", {}))
    if got != want:
        missing = [c for c in want if c not in got]
        extra = [c for c in got if c not in want]
        problems.append("%s: properties differ from src/ (missing %s, extra %s%s)" % (label, missing, extra, "; order differs" if not missing and not extra else ""))

def is_int(s):
    if not isinstance(s, dict): return False
    t = s.get("type")
    if t == "integer" or (isinstance(t, list) and "integer" in t): return True
    return any(is_int(x) for x in s.get("oneOf", []) + s.get("anyOf", []))

# ---- service
svc = schema("webinventory.service.1.json", "webinventory.service/1")
m = svc.get("x-minor", 0)
expect_props("service", svc, columns + ["Detections"])
check_required("service", svc, m)
for c in sorted((integers | {"Port"}) & set(svc.get("properties", {}))):
    if not is_int(svc["properties"][c]):
        problems.append("service.%s: the script writes an integer, the schema does not allow one" % c)
det = svc["properties"].get("Detections", {})
items = det.get("items") or next((x["items"] for x in det.get("anyOf", []) + det.get("oneOf", []) if isinstance(x, dict) and "items" in x), {})
expect_props("service Detections", items, det_keys)
check_required("service Detections", items, m)

# ---- the mirrored files
for name, sid, want in (("webinventory.vuln.1.json", "webinventory.vuln/1", vcols),
                        ("webinventory.screenshot.1.json", "webinventory.screenshot/1", shot_cols),
                        ("webinventory.delta.1.json", "webinventory.delta/1", ["Change", "Key", "Field", "Old", "New"]),
                        ("webinventory.error.1.json", "webinventory.error/1", ["time", "level", "category", "target", "message"])):
    d = schema(name, sid)
    label = sid.split(".")[1].split("/")[0]
    expect_props(label, d, want)
    check_required(label, d, d.get("x-minor", 0))

# ---- envelope
env = schema("tideline-envelope.1.json", "tideline-envelope/1")
if env.get("x-minor", 0) < 1:
    problems.append("tideline-envelope/1 is minor %s; WebInventory 2.6.1 sends the minor-1 part fields" % env.get("x-minor", 0))
if "tool_run" in env.get("properties", {}):
    problems.append("tideline-envelope/1 lists tool_run; WebInventory keeps it in run.json")

for p in problems:
    print("FAIL " + p)
at = vendored.read_text(encoding="utf-8").split(" at ", 1)[1].split(" by ", 1)[0] if vendored.exists() else "?"
print("schemas: %d files vendored from Tideline %s; service %d columns + Detections (%d fields), vuln %d, screenshot %d; %d problems"
      % (len(files), at, len(columns), len(det_keys), len(vcols), len(shot_cols), len(problems)))
sys.exit(1 if problems else 0)
