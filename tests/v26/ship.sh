#!/usr/bin/env bash
# Tideline shipping, end to end: Invoke-WebInventory.ps1 -ShipTo and Send-WebInventoryRun.ps1 against
# lab/tideline_mock.py (mutual TLS, sensor from the certificate, ES256 manifest signature, per-part SHA-256,
# record schemas, fault injection).
#   ship.sh <workdir> [pwsh] [browser]     needs the lab (lab/start-lab.sh) and python3 with cryptography + jsonschema
set -u
W=$(cd "$(dirname "$0")/../.." && pwd); WD=${1:?workdir}; PS=${2:-pwsh}; BROWSER=${3:-}
INV=$W/dist/Invoke-WebInventory.ps1; SEND=$W/dist/Send-WebInventoryRun.ps1
rm -rf "$WD"; mkdir -p "$WD"; P=$WD/pki
python3 "$W/tests/v26/mkcerts.py" "$P" > /dev/null
pass=0; fail=0
ok() { pass=$((pass+1)); echo "PASS $1"; }
bad() {
    fail=$((fail+1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' "$2" | tail -8
    # on GitHub Actions the details become an annotation (job logs are not always at hand)
    if [ -n "${GITHUB_ACTIONS:-}" ] && [ -n "${2:-}" ]; then echo "::warning title=detail of FAIL ${1%% *}::$(tail -6 "$2" | tr '\n' '|' | sed 's/::/: :/g' | cut -c1-1500)"; fi
    true
}
MOCKS=()
trap 'kill ${MOCKS[*]} 2>/dev/null; true' EXIT
mock() {   # mock <name> <port> [serve options]; CERT/KEY pick the server certificate
    local n=$1 port=$2; shift 2
    mkdir -p "$WD/$n"
    python3 "$W/lab/tideline_mock.py" serve --port "$port" --cert "${CERT:-$P/server.crt}" --key "${KEY:-$P/server.key}" \
        --client-ca "$P/client-ca.pem" --data "$WD/$n/data" --schemas "$W/schemas" --log "$WD/$n/req.jsonl" --ready "$WD/$n/ready" "$@" > "$WD/$n/mock.log" 2>&1 &
    MOCKS+=($!)
    for _ in $(seq 100); do [ -f "$WD/$n/ready" ] && return 0; sleep 0.1; done
    echo "mock $n did not start"; cat "$WD/$n/mock.log"; return 1
}
scan() {   # scan <dir> args...  (exit code in <dir>/exit)
    local d=$1; shift; mkdir -p "$d"
    (cd "$d" && "$PS" -NoProfile -File "$INV" -OutputDir "$d/out" -NoProgress -Quiet "$@" > "$d/stdout.txt" 2>&1; echo $? > "$d/exit")
}
send() {   # send <dir> args...  (exit code in <dir>/send.exit, output in send.txt)
    local d=$1; shift; mkdir -p "$d"
    (cd "$d" && "$PS" -NoProfile -File "$SEND" "$@" > "$d/send.txt" 2>&1; echo $? > "$d/send.exit")
}
rc() { cat "$1"; }
runjson() { ls "$1"/out/WebInventory_*_run.json 2>/dev/null | head -1; }
puts() { python3 -c "import json,sys; print(sum(1 for l in open(sys.argv[1]) if json.loads(l)['method']==sys.argv[2]))" "$1" "$2"; }
LAB='127.0.0.1:18080,18081,18443'
PFX=(-ShipCertPath "$P/sensor.pfx" -ShipCaFile "$P/root.crt")

# offline vulnerability feeds: one nginx CVE (the lab's nginx 1.18.0 is affected), KEV and EPSS
F=$WD/feeds; mkdir -p "$F"
python3 - "$F" <<'PY'
import json, sys
d = sys.argv[1]
cve = {"id": "CVE-2021-23017", "published": "2021-06-01T13:15:07.853", "lastModified": "2024-11-21T05:51:11.210", "vulnStatus": "Modified",
       "descriptions": [{"lang": "en", "value": "A security issue in nginx resolver (test fixture)."}],
       "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.7, "baseSeverity": "HIGH"}}]},
       "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                          "versionStartIncluding": "0.6.18", "versionEndExcluding": "1.20.1"}]}]}]}
json.dump({"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [{"cve": cve}]}, open(d + "/nvdcve-2.0-2021.json", "w"))
json.dump({"vulnerabilities": [{"cveID": "CVE-2021-23017", "dateAdded": "2026-01-15", "dueDate": "2026-02-05", "knownRansomwareCampaignUse": "Unknown"}]}, open(d + "/kev.json", "w"))
open(d + "/epss.csv", "w").write("#model_version:v2025.03.14,score_date:2026-11-01T00:00:00+0000\ncve,epss,percentile\nCVE-2021-23017,0.71,0.98\n")
PY

echo "=== 1. scan + ship: services, delta, screenshots, vulns, errors, run.json, manifest, logs, images"
mock m1 18943 --sensors wi-test01 --engagements eng-test
scan "$WD/base" -Target "$LAB"
scan "$WD/s1" -Target "$LAB" -BaselineCsv "$(ls "$WD"/base/out/WebInventory_*.csv | grep -v _delta | head -1)" -NvdFeed "$F" -KevFile "$F/kev.json" -EpssFile "$F/epss.csv" \
    -ShipTo https://localhost:18943 "${PFX[@]}" -Engagement eng-test
KINDS=services,delta,vulns,errors,artifact:run-info,artifact:tool-manifest,artifact:vuln-provenance,artifact:log
if [ "$(rc "$WD/s1/exit")" = 0 ] && python3 "$W/tests/v26/received.py" --data "$WD/m1/data" --run-json "$(runjson "$WD/s1")" --kinds "$KINDS" > "$WD/s1/recv.txt"; then
    ok "1 delivered and byte-identical: $(cat "$WD/s1/recv.txt" | cut -c1-200)"; else bad "1 scan+ship (exit $(rc "$WD/s1/exit"))" "$WD/s1/stdout.txt"; cat "$WD/s1/recv.txt" 2>/dev/null; fi
python3 - "$(runjson "$WD/s1")" > "$WD/s1/vulns.txt" <<'PY' && ok "1b per-run vulnerabilities: $(cat "$WD/s1/vulns.txt")" || bad "1b per-run vulnerabilities" "$WD/s1/vulns.txt"
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1].replace("_run.json", "_vulns.jsonl"))]
assert rows and all(r["Cve"] == "CVE-2021-23017" and r["Kev"] and r["Epss"] for r in rows), rows
assert all(isinstance(r["Port"], int) for r in rows)
print("%d rows (%s), KEV and EPSS filled, Port a number" % (len(rows), ", ".join(sorted(r["Url"] for r in rows))))
PY
python3 "$W/tests/v26/contract.py" "$WD/s1/out" > "$WD/s1/contract.txt" 2>&1 && ok "1c contract: $(tail -1 "$WD/s1/contract.txt")" || bad "1c contract" "$WD/s1/contract.txt"
if [ -n "$BROWSER" ]; then
    # screenshots (an ok page and a blank one): the index JSONL and every image
    python3 "$W/lab/shotcases.py" 18600 > /dev/null 2>&1 & MOCKS+=($!)
    printf "@{ BrowserPath = '%s'; BrowserArgument = @('--no-sandbox') }\n" "$BROWSER" > "$WD/shot.psd1"
    sleep 1
    scan "$WD/s1d" -Target '127.0.0.1:18080,18600' -Screenshot -ConfigFile "$WD/shot.psd1" -ShipTo https://localhost:18943 "${PFX[@]}" -Engagement eng-test
    [ "$(rc "$WD/s1d/exit")" = 0 ] && python3 "$W/tests/v26/received.py" --data "$WD/m1/data" --run-json "$(runjson "$WD/s1d")" --kinds screenshots,artifact:screenshot > "$WD/s1d/recv.txt" \
        && python3 "$W/tests/v26/contract.py" "$WD/s1d/out" > "$WD/s1d/contract.txt" && ok "1d screenshots: $(cut -c1-170 "$WD/s1d/recv.txt"); $(tail -1 "$WD/s1d/contract.txt")" || bad "1d screenshots (exit $(rc "$WD/s1d/exit"))" "$WD/s1d/stdout.txt"
fi

echo "=== 2. shipping changes no output row (same scan without -ShipTo), and adds only ship-state.json"
scan "$WD/s2" -Target "$LAB" -BaselineCsv "$(ls "$WD"/base/out/WebInventory_*.csv | grep -v _delta | head -1)" -NvdFeed "$F" -KevFile "$F/kev.json" -EpssFile "$F/epss.csv" -Engagement eng-test
python3 "$W/tests/perf/golden.py" "$WD/s2/out" "$WD/s1/out" > "$WD/s2/golden.txt" 2>&1
f1=$(cd "$WD/s1/out" && ls | sed -E 's/WebInventory_[0-9]{8}_[0-9]{6}/X/' | sort | tr '\n' ' '); f2=$(cd "$WD/s2/out" && ls | sed -E 's/WebInventory_[0-9]{8}_[0-9]{6}/X/' | sort | tr '\n' ' ')
extra=$(comm -13 <(echo "$f2" | tr ' ' '\n' | sort) <(echo "$f1" | tr ' ' '\n' | sort) | tr '\n' ' ')
if grep -q ' 0 differences' "$WD/s2/golden.txt" && [ "$extra" = "X_ship-state.json " ]; then ok "2 $(tail -1 "$WD/s2/golden.txt"); extra file: $extra"; else bad "2 A/B: extra [$extra]" "$WD/s2/golden.txt"; fi

echo "=== 3-5. Send-WebInventoryRun: already delivered; -Force; -Status"
before=$(puts "$WD/m1/req.jsonl" POST)
send "$WD/s3" "$WD/s1/out" -ShipTo https://localhost:18943 "${PFX[@]}"
[ "$(rc "$WD/s3/send.exit")" = 0 ] && grep -q 'already delivered' "$WD/s3/send.txt" && [ "$(puts "$WD/m1/req.jsonl" POST)" = "$before" ] && ok "3 a delivered run is not sent again (no request)" || bad "3 already delivered" "$WD/s3/send.txt"
putsbefore=$(puts "$WD/m1/req.jsonl" PUT)
send "$WD/s4" "$WD/s1/out" -ShipTo https://localhost:18943 "${PFX[@]}" -Force
[ "$(rc "$WD/s4/send.exit")" = 0 ] && grep -q 'already has run' "$WD/s4/send.txt" && [ "$(puts "$WD/m1/req.jsonl" PUT)" = "$putsbefore" ] && ok "4 -Force: Tideline answers that it holds the run (same manifest)" || bad "4 -Force" "$WD/s4/send.txt"
send "$WD/s5" "$WD/s1/out" -ShipTo https://localhost:18943 "${PFX[@]}" -Status
[ "$(rc "$WD/s5/send.exit")" = 0 ] && grep -q '"state": "verified"' "$WD/s5/send.txt" && ok "5 -Status: $(grep -o 'local state [a-z]*' "$WD/s5/send.txt" | head -1), Tideline verified" || bad "5 -Status" "$WD/s5/send.txt"

echo "=== 6. connection dropped mid-upload: exit 2, then a later call sends only the missing parts"
mock m6 18944 --fault drop:put:3
scan "$WD/s6" -Target "$LAB" -ShipTo https://localhost:18944 "${PFX[@]}" -ShipRetries 0
p1=$(puts "$WD/m6/req.jsonl" PUT)
send "$WD/s6" "$WD/s6/out" -ShipTo https://localhost:18944 "${PFX[@]}"
p2=$(puts "$WD/m6/req.jsonl" PUT); n=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))['parts']))" "$(ls "$WD"/m6/data/runs/*/manifest.json)")
if [ "$(rc "$WD/s6/exit")" = 2 ] && [ "$(rc "$WD/s6/send.exit")" = 0 ] && [ $((p2 - p1)) = $((n - 2)) ] && python3 "$W/tests/v26/received.py" --data "$WD/m6/data" --run-json "$(runjson "$WD/s6")" > "$WD/s6/recv.txt"; then
    ok "6 scan exit 2 after $p1 PUTs; Send resumed with $((p2 - p1)) of $n parts; run complete and identical"; else bad "6 resume (scan $(rc "$WD/s6/exit"), send $(rc "$WD/s6/send.exit"), PUT $p1 then $p2 of $n)" "$WD/s6/send.txt"; fi

echo "=== 7. server busy once (503): retried within the same call"
mock m7 18945 --fault put:2:503:1
WEBINV_SHIP_RETRY_MS=200 scan "$WD/s7" -Target "$LAB" -ShipTo https://localhost:18945 "${PFX[@]}" -ShipRetries 1
[ "$(rc "$WD/s7/exit")" = 0 ] && grep -q 'retrying' "$WD/s7/stdout.txt" && python3 "$W/tests/v26/received.py" --data "$WD/m7/data" --run-json "$(runjson "$WD/s7")" > /dev/null && ok "7 503 then delivered in one call (exit 0)" || bad "7 retry" "$WD/s7/stdout.txt"

echo "=== 8. Tideline unreachable when the scan ends: exit 2, results intact, state kept"
scan "$WD/s8" -Target "$LAB" -ShipTo https://localhost:18999 "${PFX[@]}" -ShipRetries 0
st=$(python3 -c "import json,sys; e=list(json.load(open(sys.argv[1]))['targets'].values())[0]; print(e['state'], '|', e['last_error'][:60])" "$(ls "$WD"/s8/out/*_ship-state.json)" 2>/dev/null)
[ "$(rc "$WD/s8/exit")" = 2 ] && [ -s "$(ls "$WD"/s8/out/WebInventory_*.jsonl | head -1)" ] && echo "$st" | grep -q '^receiving' && ok "8 exit 2; state: $st" || bad "8 unreachable ($st)" "$WD/s8/stdout.txt"

echo "=== 9. a file changed after the run: refused before sending (exit 1)"
cp -r "$WD/s7/out" "$WD/s9out"; rm -f "$WD"/s9out/*_ship-state.json
j=$(ls "$WD"/s9out/WebInventory_*.jsonl | grep -v -E '_(errors|delta|vulns|screenshots)\.jsonl' | head -1); sed -i 's/nginx/NGINX/' "$j"
send "$WD/s9" "$WD/s9out" -ShipTo https://localhost:18943 "${PFX[@]}"
[ "$(rc "$WD/s9/send.exit")" = 1 ] && grep -q "changed after the run's manifest" "$WD/s9/send.txt" && ok "9 $(grep -o '[^ ]*jsonl changed after[^;]*' "$WD/s9/send.txt" | head -1 | cut -c1-110)" || bad "9 changed file" "$WD/s9/send.txt"

echo "=== 10-11. sensor not active; certificate from another CA: refused by Tideline (exit 3)"
send "$WD/s10" "$WD/s6/out" -ShipTo https://localhost:18943 -ShipCertPath "$P/sensor-other.pfx" -ShipCaFile "$P/root.crt" -Force
[ "$(rc "$WD/s10/send.exit")" = 3 ] && grep -q 'HTTP 403' "$WD/s10/send.txt" && ok "10 $(grep -o 'HTTP 403[^"]*' "$WD/s10/send.txt" | head -1 | cut -c1-90)" || bad "10 inactive sensor" "$WD/s10/send.txt"
# (TLS 1.3: the server checks the client certificate after the client's handshake is done, so it shows as a reset,
#  which is retried: exit 2 with a hint; under TLS 1.2 it is a handshake error: exit 3)
WEBINV_SHIP_RETRY_MS=100 send "$WD/s11" "$WD/s6/out" -ShipTo https://localhost:18943 -ShipCertPath "$P/sensor-rogue.pfx" -ShipCaFile "$P/root.crt" -Force -Retries 1
e11=$(rc "$WD/s11/send.exit")
{ [ "$e11" = 3 ] || { [ "$e11" = 2 ] && grep -q 'may not accept the sensor certificate' "$WD/s11/send.txt"; }; } && ok "11 rogue client certificate refused (exit $e11): $(grep -o 'attempt 2: .*' "$WD/s11/send.txt" | head -1 | cut -c1-120)" || bad "11 rogue client cert" "$WD/s11/send.txt"

echo "=== 12-14. unusable certificates: refused before the scan (exit 1, nothing scanned)"
for c in expired:'not valid now' nourn:'urn:tideline:sensor' rsa:'ECDSA'; do
    name=${c%%:*}; want=${c#*:}
    scan "$WD/s12$name" -Target "$LAB" -ShipTo https://localhost:18943 -ShipCertPath "$P/sensor-$name.pfx" -ShipCaFile "$P/root.crt"
    [ "$(rc "$WD/s12$name/exit")" = 1 ] && grep -q "$want" "$WD/s12$name/stdout.txt" && ! ls "$WD/s12$name/out"/*.csv > /dev/null 2>&1 && ok "12 $name: $(grep -o 'FATAL: .*' "$WD/s12$name/stdout.txt" | head -1 | cut -c1-110)" || bad "12 $name" "$WD/s12$name/stdout.txt"
done

echo "=== 15-16. a server that does not chain to the pinned root, or does not name the host: refused"
CERT=$P/server-rogue.crt KEY=$P/server-rogue.key mock m15 18946
send "$WD/s15" "$WD/s6/out" -ShipTo https://localhost:18946 "${PFX[@]}"
[ "$(rc "$WD/s15/send.exit")" = 3 ] && grep -q 'pinned root' "$WD/s15/send.txt" && ok "15 $(grep -o 'does not chain[^(]*' "$WD/s15/send.txt" | head -1)" || bad "15 pin" "$WD/s15/send.txt"
CERT=$P/server-wrongname.crt KEY=$P/server-wrongname.key mock m16 18947
send "$WD/s16" "$WD/s6/out" -ShipTo https://localhost:18947 "${PFX[@]}"
[ "$(rc "$WD/s16/send.exit")" = 3 ] && grep -q 'does not name the host' "$WD/s16/send.txt" && ok "16 name mismatch refused" || bad "16 name" "$WD/s16/send.txt"

echo "=== 17. same run, different manifest (another engagement): 409, exit 3"
mock m17 18948
scan "$WD/s17" -Target "$LAB"
send "$WD/s17" "$WD/s17/out" -ShipTo https://localhost:18948 "${PFX[@]}" -Engagement eng-a
cp "$WD/s17/send.txt" "$WD/s17/send1.txt"; rm -f "$WD"/s17/out/*_ship-state.json
send "$WD/s17" "$WD/s17/out" -ShipTo https://localhost:18948 "${PFX[@]}" -Engagement eng-b
[ "$(cat "$WD/s17/send.exit")" = 3 ] && grep -q '409' "$WD/s17/send.txt" && grep -q 'delivered' "$WD/s17/send1.txt" && ok "17 first delivered for eng-a; the eng-b manifest refused with 409" || bad "17 conflict" "$WD/s17/send.txt"

echo "=== 18. sensor not assigned to the engagement: 403, exit 3"
send "$WD/s18" "$WD/s6/out" -ShipTo https://localhost:18943 "${PFX[@]}" -Engagement eng-other
[ "$(rc "$WD/s18/send.exit")" = 3 ] && grep -q 'not assigned to engagement' "$WD/s18/send.txt" && ok "18 engagement not assigned: 403" || bad "18 engagement" "$WD/s18/send.txt"

echo "=== 19. a record that fails its schema: 422 with the line number, exit 3"
cp -r "$WD/s17/out" "$WD/s19out"; rm -f "$WD"/s19out/*_ship-state.json
python3 - "$WD/s19out" <<'PY'
import hashlib, pathlib, sys
d = pathlib.Path(sys.argv[1])
j = [p for p in d.glob("WebInventory_*.jsonl") if p.stem.count("_") == 2][0]
j.write_bytes(j.read_bytes() + b'{"RunId":"x","Port":"not a number"}\n')
m = next(d.glob("*_manifest.txt"))
b = j.read_bytes()
m.write_text("\n".join(("%s  %d  %s" % (hashlib.sha256(b).hexdigest(), len(b), j.name)) if l.endswith("  " + j.name) else l for l in m.read_text().split("\n")))
PY
mock m19 18951
send "$WD/s19" "$WD/s19out" -ShipTo https://localhost:18951 "${PFX[@]}" -Engagement eng-c
[ "$(rc "$WD/s19/send.exit")" = 3 ] && grep -q 'HTTP 422' "$WD/s19/send.txt" && grep -q 'lines \[4\]' "$WD/s19/send.txt" && ok "19 $(grep -o 'HTTP 422.*' "$WD/s19/send.txt" | head -1 | cut -c1-120)" || bad "19 schema" "$WD/s19/send.txt"

echo "=== 20. a results file above the part size goes as chunks, split at line ends"
mock m20 18949
WEBINV_SHIP_CHUNK_BYTES=4000 scan "$WD/s20" -Target "$LAB" -ShipTo https://localhost:18949 "${PFX[@]}"
[ "$(rc "$WD/s20/exit")" = 0 ] && python3 "$W/tests/v26/received.py" --data "$WD/m20/data" --run-json "$(runjson "$WD/s20")" > "$WD/s20/recv.txt" && grep -q chunked "$WD/s20/recv.txt" && ok "20 $(cut -c1-150 "$WD/s20/recv.txt")" || bad "20 chunks" "$WD/s20/recv.txt"

echo "=== 21. export bundle: verifies offline; a changed byte is caught"
send "$WD/s21" "$(runjson "$WD/s1")" -Export "$WD/s21/bundle.zip" "${PFX[@]}"
python3 "$W/lab/tideline_mock.py" verify-bundle "$WD/s21/bundle.zip" --ca "$P/root.crt" --schemas "$W/schemas" > "$WD/s21/verify.txt" 2>&1; v1=$?
python3 - "$WD/s21/bundle.zip" "$WD/s21/tampered.zip" <<'PY'
import sys, zipfile
src, dst = zipfile.ZipFile(sys.argv[1]), zipfile.ZipFile(sys.argv[2], "w")
for i in src.infolist():
    b = src.read(i)
    if i.filename == "parts/0001.gz":
        import gzip; b = gzip.compress(gzip.decompress(b).replace(b"nginx", b"NGINX"))
    dst.writestr(i, b)
dst.close()
PY
python3 "$W/lab/tideline_mock.py" verify-bundle "$WD/s21/tampered.zip" --ca "$P/root.crt" --schemas "$W/schemas" > "$WD/s21/verify2.txt" 2>&1; v2=$?
[ "$(rc "$WD/s21/send.exit")" = 0 ] && [ $v1 = 0 ] && [ $v2 = 1 ] && ok "21 $(tail -1 "$WD/s21/verify.txt" | sed 's#.*/##' | cut -c1-110); tampered: $(grep FAIL "$WD/s21/verify2.txt" | head -1 | cut -c1-70)" || bad "21 bundle ($v1/$v2)" "$WD/s21/verify.txt"

echo "=== 22. an incomplete run: refused when named, skipped in a folder sweep"
mkdir -p "$WD/s22out"; cp "$WD"/s17/out/* "$WD/s22out/"; rm -f "$WD"/s22out/*_ship-state.json
python3 - "$(ls "$WD"/s22out/*_run.json)" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p, encoding="utf-8-sig")); d["complete"] = False; json.dump(d, open(p, "w"))
PY
send "$WD/s22a" "$(ls "$WD"/s22out/*_run.json)" -ShipTo https://localhost:18949 "${PFX[@]}"
send "$WD/s22b" "$WD/s22out" -ShipTo https://localhost:18949 "${PFX[@]}"
[ "$(rc "$WD/s22a/send.exit")" = 1 ] && [ "$(rc "$WD/s22b/send.exit")" = 0 ] && grep -q 'skipped' "$WD/s22b/send.txt" && ok "22 named: exit 1; swept: skipped, exit 0" || bad "22 incomplete" "$WD/s22a/send.txt"

echo "=== 23-24. PFX with a password file; option checks"
mock m23 18950
scan "$WD/s23" -Target 127.0.0.1:18080 -ShipTo https://localhost:18950 -ShipCertPath "$P/sensor-pw.pfx" -ShipCertPasswordFile "$P/pfx-password.txt" -ShipCaFile "$P/root.crt"
[ "$(rc "$WD/s23/exit")" = 0 ] && grep -q 'delivered' "$WD/s23/stdout.txt" && ok "23 PFX with -ShipCertPasswordFile" || bad "23 pfx password" "$WD/s23/stdout.txt"
scan "$WD/s24a" -Target 127.0.0.1:18080 -ShipCaFile "$P/root.crt"
scan "$WD/s24b" -Target 127.0.0.1:18080 -Engagement 'bad id!'
scan "$WD/s24c" -Target 127.0.0.1:18080 -ShipTo http://localhost:18950 "${PFX[@]}"
[ "$(rc "$WD/s24a/exit")" = 1 ] && [ "$(rc "$WD/s24b/exit")" = 1 ] && [ "$(rc "$WD/s24c/exit")" = 1 ] && grep -q 'without -ShipTo' "$WD/s24a/stdout.txt" && grep -q 'https://' "$WD/s24c/stdout.txt" && ok "24 option checks: -ShipCaFile alone, bad -Engagement, http:// URL (exit 1)" || bad "24 options" "$WD/s24c/stdout.txt"

echo "=== 25. nothing answered: still shipped, exit 4 kept, exit_code 4 in the envelope"
scan "$WD/s25" -Target 127.0.0.1:18999 -ShipTo https://localhost:18950 "${PFX[@]}"
[ "$(rc "$WD/s25/exit")" = 4 ] && python3 "$W/tests/v26/received.py" --data "$WD/m23/data" --run-json "$(runjson "$WD/s25")" > "$WD/s25/recv.txt" && grep -q 'exit_code 4' "$WD/s25/recv.txt" && ok "25 exit 4; $(cut -c1-140 "$WD/s25/recv.txt")" || bad "25 nothing answered" "$WD/s25/stdout.txt"

echo "=== 26. errors part: an unresolved name is an error line"
scan "$WD/s26" -Target '127.0.0.1:18080 no-such-host.invalid' -ShipTo https://localhost:18950 "${PFX[@]}"
python3 - "$(runjson "$WD/s26")" > "$WD/s26/err.txt" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1].replace("_run.json", "_errors.jsonl"))]
assert any(r["level"] == "error" and r["category"] == "DNS" and r["target"] == "no-such-host.invalid" for r in rows), rows
print("%d lines, first: %s %s %s" % (len(rows), rows[0]["level"], rows[0]["category"], rows[0]["target"]))
PY
[ "$(rc "$WD/s26/exit")" = 2 ] && [ $? = 0 ] && grep -q DNS "$WD/s26/err.txt" && python3 "$W/tests/v26/received.py" --data "$WD/m23/data" --run-json "$(runjson "$WD/s26")" > /dev/null && ok "26 exit 2; errors.jsonl $(cat "$WD/s26/err.txt"); delivered" || bad "26 errors part" "$WD/s26/err.txt"

echo "ship scenario: $pass passed, $fail failed"
[ $fail = 0 ]
