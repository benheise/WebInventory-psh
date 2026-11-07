#!/usr/bin/env python3
"""Writes schemas/*.schema.json (JSON Schema 2020-12) from the column lists in src/, so the record schemas always
describe what the script writes. Run after a column is added; tests/v26/contract.py checks real output against them.

  tideline-envelope-1     the manifest of a shipped run (Tideline's run envelope)
  webinventory.service-1  WebInventory_<RunId>.jsonl, one service per line (the results)
  webinventory.delta-1    WebInventory_<RunId>_delta.jsonl (-BaselineCsv)
  webinventory.screenshot-1  WebInventory_<RunId>_screenshots.jsonl (-Screenshot)
  webinventory.vuln-1     WebInventory_<RunId>_vulns.jsonl (-NvdFeed on a scan run)
  webinventory.error-1    WebInventory_<RunId>_errors.jsonl (errors and warnings of the run)
"""
import json, pathlib, re, sys

root = pathlib.Path(__file__).resolve().parents[2]
src = root / "src"
out = root / "schemas"
out.mkdir(exist_ok=True)

def ps_list(text, var):
    text = re.sub(r"(?m)^\s*#.*$", "", text)   # comment lines inside a list may hold parentheses
    m = re.search(r"\$" + re.escape(var) + r" = @\((.*?)\)\s*\n", text, re.S)
    if not m:
        sys.exit("list $%s not found" % var)
    return re.findall(r"'([^']+)'", m.group(1))

output = (src / "40-output.ps1").read_text(encoding="utf-8")
columns = ps_list(output, "Columns")
integers = set(ps_list(output, "script:JsonlIntegers"))
vuln_cs = (src / "vuln.cs").read_text(encoding="utf-8")
vcols = re.findall(r'"([^"]+)"', re.search(r"public static readonly string\[\] Columns = \{(.*?)\};", vuln_cs, re.S).group(1))
extras = (src / "35-extras.ps1").read_text(encoding="utf-8")
shot_cols = re.findall(r"'([^']+)'", re.search(r"foreach \(\$c in ('Url', 'Host'.*?)\) \{ \$o\[\$c\]", extras).group(1))

S = "https://json-schema.org/draft/2020-12/schema"
# ids as the shared contract (tideline-schemas) writes them: $id urn:tideline:schema:<id>, repeated in x-tideline-schema,
# so the schemas name no repository
def sid(name):   # webinventory.service-1 -> webinventory.service/1
    stem, ver = name.rsplit("-", 1)
    return stem + "/" + ver
STR = {"type": "string"}
INT_OR_EMPTY = {"anyOf": [{"type": "integer"}, {"const": ""}]}
BOOL_OR_EMPTY = {"anyOf": [{"type": "boolean"}, {"const": ""}]}

def schema(name, title, desc, props, required, extra=True):
    return {"$schema": S, "$id": "urn:tideline:schema:" + sid(name), "x-tideline-schema": sid(name), "title": title, "description": desc, "type": "object",
            "required": required, "properties": props, "additionalProperties": extra}

# ---- services: the results JSONL (types as the script has written them since v2.0)
svc_int = {"Port"}
svc_int_or_empty = {"StatusCode", "BodyLength", "ResponseMs", "FaviconMmh3", "CertDaysLeft", "CertKeySize"}
svc_bool = {"Vhost", "IsWeb"}
svc_bool_or_empty = {"Http2", "CertSelfSigned"}
props = {}
for c in columns:
    props[c] = ({"type": "integer", "minimum": 0, "maximum": 65535} if c in svc_int else INT_OR_EMPTY if c in svc_int_or_empty
                else {"type": "boolean"} if c in svc_bool else BOOL_OR_EMPTY if c in svc_bool_or_empty else STR)
det = {"type": "object", "required": ["Kind", "Name"], "additionalProperties": True,
       "properties": {"Kind": STR, "Name": STR, "Version": STR, "Category": STR, "Confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                      "Cpe": STR, "Source": STR, "Evidence": STR}}
props["Detections"] = {"anyOf": [{"type": "array", "items": det}, {"type": "null"}]}
service = schema("webinventory.service-1", "WebInventory service (results JSONL line)",
                 "One line of WebInventory_<RunId>.jsonl: the CSV's %d columns with JSON types, plus Detections (each detection's "
                 "product, version, confidence, CPE, rule source and evidence). Columns added in a later 2.x release are a minor "
                 "version and appear as extra properties; runs of earlier releases lack the newer columns." % len(columns),
                 props, ["RunId", "ScannedAt", "Host", "IP", "Port", "State", "IsWeb", "Scheme", "Url"])

def mirrored(name, title, desc, cols, enums=None, required=None):
    p = {}
    for c in cols:
        p[c] = INT_OR_EMPTY if c in integers else STR
        if enums and c in enums:
            p[c] = {"enum": enums[c]}
    return schema(name, title, desc + " Values are the CSV's cells as text (without the CSV's formula guard); counts, ports, "
                  "sizes and durations are integers when the cell holds one, \"\" when it is empty.", p, required or cols, True)

delta = mirrored("webinventory.delta-1", "WebInventory delta line", "One line of WebInventory_<RunId>_delta.jsonl: a change against "
                 "the -BaselineCsv run. Key is host|port; Field and Old are empty for NEW, Field and New for REMOVED.",
                 ["Change", "Key", "Field", "Old", "New"], {"Change": ["NEW", "CHANGED", "REMOVED"]})
shots = mirrored("webinventory.screenshot-1", "WebInventory screenshot index line", "One line of WebInventory_<RunId>_screenshots.jsonl: "
                 "a capture and its check (Status ok, blank, suspect or failed, with Reason). File is the PNG's path relative to "
                 "the output folder, empty when no image was taken.", shot_cols, {"Status": ["ok", "blank", "suspect", "failed"]},
                 ["Url", "Host", "IP", "Port", "File", "Sha256", "Status"])
vulns = mirrored("webinventory.vuln-1", "WebInventory vulnerability line", "One line of WebInventory_<RunId>_vulns.jsonl (-NvdFeed on a "
                 "scan run) or of a -StoreQuery Vulnerabilities JSONL: one service and CVE, matched offline from the service's CPE and "
                 "version, with CISA KEV and FIRST EPSS when given.", vcols, None, ["Host", "IP", "Port", "Url", "Cpe", "Cve"])
errors = schema("webinventory.error-1", "WebInventory error or warning", "One line of WebInventory_<RunId>_errors.jsonl: what the run's "
                "error log holds (level error or fatal, with the category and the target) and the run log's warnings (level warning).",
                {"time": {"type": "string"}, "level": {"enum": ["error", "warning", "fatal"]}, "category": STR, "target": STR, "message": STR},
                ["time", "level", "category", "target", "message"], False)

ID = "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
SHA = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
part = {"type": "object", "additionalProperties": False,
        "required": ["n", "kind", "media", "name", "bytes", "sha256", "encoding"],
        "properties": {
            "n": {"type": "integer", "minimum": 1},
            "kind": {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,31}$", "description": "a record kind (NDJSON) or artifact"},
            "schema": {"type": "string", "pattern": "^[a-z][a-z0-9.-]*/[0-9]+$", "description": "record schema of an NDJSON part"},
            "role": {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,31}$", "description": "what an artifact is: run-info, tool-manifest, vuln-provenance, log, screenshot"},
            "media": {"type": "string", "maxLength": 100},
            "name": {"type": "string", "minLength": 1, "maxLength": 400, "description": "the file's path in the run folder (forward slashes)"},
            "records": {"type": "integer", "minimum": 0},
            "bytes": {"type": "integer", "minimum": 0, "description": "size before compression"},
            "sha256": dict(SHA, description="SHA-256 of the part before compression (for a whole file: as in the tool's own manifest)"),
            "encoding": {"enum": ["gzip", "identity"], "description": "Content-Encoding of the upload"},
            "chunk": {"type": "integer", "minimum": 1}, "chunks": {"type": "integer", "minimum": 2},
            "file_bytes": {"type": "integer", "minimum": 0}, "file_sha256": SHA},
        "allOf": [
            {"if": {"properties": {"kind": {"const": "artifact"}}}, "then": {"required": ["role"]}, "else": {"required": ["schema", "records"]}},
            {"if": {"required": ["chunk"]}, "then": {"required": ["chunks", "file_bytes", "file_sha256"]}}]}
envelope = {"$schema": S, "$id": "urn:tideline:schema:tideline-envelope/1", "x-tideline-schema": "tideline-envelope/1", "title": "Tideline run envelope (manifest)",
            "description": "The manifest a sensor sends with POST /v1/runs, signed (ES256) over its exact bytes in the Tideline-Signature "
                           "header. Each part is then uploaded with PUT /v1/runs/{run_id}/parts/{n}. See SHIPPING.md.",
            "type": "object", "additionalProperties": False,
            "required": ["schema", "run_id", "tool", "tool_version", "sensor", "engagement", "job_id", "started", "finished", "exit_code", "profile", "tool_manifest_sha256", "parts"],
            "properties": {
                "schema": {"const": "tideline-envelope/1"},
                "run_id": {"type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},
                "tool": {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,31}$"},
                "tool_version": {"type": "string", "maxLength": 40},
                "tool_run": {"type": "string", "maxLength": 100, "description": "the tool's own run id (WebInventory: yyyyMMdd_HHmmss)"},
                "sensor": {"type": "string", "pattern": ID, "description": "must equal the sensor id in the client certificate"},
                "engagement": {"anyOf": [{"type": "string", "pattern": ID}, {"type": "null"}]},
                "job_id": {"anyOf": [{"type": "string", "maxLength": 100}, {"type": "null"}]},
                "started": {"type": "string", "pattern": "^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$"},
                "finished": {"type": "string", "pattern": "^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$"},
                "exit_code": {"anyOf": [{"type": "integer", "minimum": 0, "maximum": 255}, {"type": "null"}], "description": "the scan's exit code (store and shipping stages not included); null for runs made before 2.6"},
                "profile": {"type": "object", "description": "the run.json profile, unchanged"},
                "tool_manifest_sha256": SHA,
                "parts": {"type": "array", "minItems": 1, "maxItems": 100000, "items": part}}}

docs = {"tideline-envelope-1": envelope, "webinventory.service-1": service, "webinventory.delta-1": delta,
        "webinventory.screenshot-1": shots, "webinventory.vuln-1": vulns, "webinventory.error-1": errors}
for name, d in docs.items():
    (out / (name + ".schema.json")).write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("schemas: %s (service: %d columns + Detections; vuln: %d; screenshot: %d)" % (", ".join(docs), len(columns), len(vcols), len(shot_cols)))
