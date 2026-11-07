#!/usr/bin/env python3
"""Assemble dist/Invoke-WebInventory.ps1 from src/ parts (engine C#, rules JSON, PowerShell sections)."""
import base64, hashlib, json, pathlib, re, subprocess, sys

root = pathlib.Path(__file__).resolve().parent
src = root / "src"
dist = root / "dist"
dist.mkdir(exist_ok=True)

engine = (src / "engine.cs").read_text(encoding="utf-8")
# the inventory store compiles separately and only when used (a scan without -Store never loads it)
store = "\n".join((src / n).read_text(encoding="utf-8").rstrip("\n") for n in ("store.cs", "inventory.cs", "invstore.cs", "invstore2.cs", "vuln.cs", "storetest.cs"))
# opt-in probes (JARM/JA4S, SMB, RDP, SNMP, screenshot scope proxy): compiled only when a run enables one of them
extras = (src / "extras.cs").read_text(encoding="utf-8")
# Tideline shipping (C# + PowerShell helpers): compiled only with -ShipTo; also the core of the two companion scripts
version = re.search(r"\$ScriptVersion = '([^']+)'", (src / "10-header.ps1").read_text(encoding="utf-8")).group(1)
ship = (src / "ship.cs").read_text(encoding="utf-8").replace("__SHIP_VERSION__", version)
ship_ps = (src / "ship-common.ps1").read_text(encoding="utf-8").rstrip("\n")
rules = (src / "builtin-rules.json").read_text(encoding="utf-8")
json.loads(rules)  # fail fast on invalid JSON
# version-only rules (tools/version/gen_rules.py) are part of the built-in pack: appended after the curated rules
vr_path = src / "version-rules.json"
if vr_path.exists():
    vr = json.loads(vr_path.read_text(encoding="utf-8"))["rules"]
    if vr:
        assert rules.rstrip().endswith("\n]}"), "builtin-rules.json must end with a line holding ]}"
        rules = rules.rstrip()[:-3] + ",\n" + ",\n".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) for r in vr) + "\n]}\n"
        json.loads(rules)
cpesup = (src / "cpe-supplement.json").read_text(encoding="utf-8")
json.loads(cpesup)
for blob, name in ((engine, "engine.cs"), (store, "store sources"), (extras, "extras.cs"), (ship, "ship.cs"), (rules, "builtin-rules.json"), (cpesup, "cpe-supplement.json")):
    if "\n'@" in blob:
        sys.exit(f"{name} contains a line starting with '@ which would terminate the here-string")

cert_pem = pathlib.Path(sys.argv[1]).read_text() if len(sys.argv) > 1 else (src / "selftest-cert.pem").read_text()
der_b64 = "".join(l for l in cert_pem.splitlines() if l and not l.startswith("-----"))
base64.b64decode(der_b64)

parts = []
for name in ["10-header.ps1", "20-input.ps1", "30-worker.ps1", "35-extras.ps1", "40-output.ps1", "45-store.ps1", "50-tools.ps1", "55-ship.ps1", "60-main.ps1"]:
    parts.append((src / name).read_text(encoding="utf-8"))
script = "\n".join(parts)
script = script.replace("__ENGINE_CS__", engine.rstrip("\n"), 1)
script = script.replace("__STORE_CS__", store.rstrip("\n"), 1)
script = script.replace("__EXTRAS_CS__", extras.rstrip("\n"), 1)
script = script.replace("__SHIP_CS__", ship.rstrip("\n"), 1)
script = script.replace("__SHIP_PS__", ship_ps, 1)
script = script.replace("__BUILTIN_RULES__", rules.rstrip("\n"), 1)
script = script.replace("__CPE_SUPPLEMENT__", cpesup.rstrip("\n"), 1)
script = script.replace("__SELFTEST_CERT__", der_b64, 1)
# v2.7: pin the companion rule packs shipped in dist/ (canonical bytes: no BOM, LF line endings)
def canonical_sha256(b):
    t = b.decode("utf-8")
    if t.startswith("\ufeff"):
        t = t[1:]
    return hashlib.sha256(t.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")).hexdigest()
pins = "; ".join("'%s' = '%s'" % (f.name, canonical_sha256(f.read_bytes())) for f in sorted(dist.glob("WebInventory.rules.*.json")))
assert pins, "no companion rule packs in dist/"
script = script.replace("__COMPANION_PINS__", pins, 1)
assert "__COMPANION_PINS__" not in script and "__SHIP_CS__" not in script and "__SHIP_PS__" not in script and "__EXTRAS_CS__" not in script and "__ENGINE_CS__" not in script and "__STORE_CS__" not in script and "__BUILTIN_RULES__" not in script and "__CPE_SUPPLEMENT__" not in script and "__SELFTEST_CERT__" not in script
# Windows line endings + UTF-8 BOM: Windows PowerShell 5.1 reads BOM-less files as ANSI
script = script.replace("\r\n", "\n").replace("\n", "\r\n")
out = dist / "Invoke-WebInventory.ps1"
out.write_bytes(b"\xef\xbb\xbf" + script.encode("utf-8"))
print(f"{out}  {out.stat().st_size} bytes  sha256={hashlib.sha256(out.read_bytes()).hexdigest()}")

# store validation helper ships next to the script (Windows line endings + BOM for Windows PowerShell 5.1)
tv = (src / "Test-WebInventoryStore.ps1").read_text(encoding="utf-8").replace("\r\n", "\n").replace("\n", "\r\n")
(dist / "Test-WebInventoryStore.ps1").write_bytes(b"\xef\xbb\xbf" + tv.encode("utf-8"))

# Tideline companions: each is self-contained (the same shipping code as the script), to copy to a host on its own
for name in ("Send-WebInventoryRun.ps1", "Register-WebInventorySensor.ps1"):
    t = (src / name).read_text(encoding="utf-8")
    t = t.replace("__SHIP_CS__", ship.rstrip("\n"), 1).replace("__SHIP_PS__", ship_ps, 1).replace("__VERSION__", version, 1)
    assert "__SHIP_CS__" not in t and "__SHIP_PS__" not in t and "__VERSION__" not in t
    t = t.replace("\r\n", "\n").replace("\n", "\r\n")
    out = dist / name
    out.write_bytes(b"\xef\xbb\xbf" + t.encode("utf-8"))
    print(f"{out}  {out.stat().st_size} bytes")
