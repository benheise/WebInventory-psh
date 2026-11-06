#!/usr/bin/env bash
# Register-WebInventorySensor.ps1 against a real step-ca (PowerShell 7, PFX path), then shipping with what it saved.
#   register.sh <workdir> <dir with step and step-ca> [pwsh]
# Starts its own CA on 127.0.0.1:19100 and a Tideline mock on 18960 whose certificates come from that CA.
set -u
W=$(cd "$(dirname "$0")/../.." && pwd); WD=${1:?workdir}; B=${2:?step bin dir}; PS=${3:-pwsh}
REG=$W/dist/Register-WebInventorySensor.ps1; INV=$W/dist/Invoke-WebInventory.ps1
rm -rf "$WD"; mkdir -p "$WD/home"
export STEPPATH=$WD/ca HOME_SENSOR=$WD/home
pass=0; fail=0
ok() { pass=$((pass+1)); echo "PASS $1"; }
bad() {
    fail=$((fail+1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' "$2" | tail -8
    # on GitHub Actions the details become an annotation (job logs are not always at hand)
    if [ -n "${GITHUB_ACTIONS:-}" ] && [ -n "${2:-}" ]; then echo "::warning title=detail of FAIL ${1%% *}::$(tail -6 "$2" | tr '\n' '|' | sed 's/::/: :/g' | cut -c1-1500)"; fi
    true
}
PIDS=(); trap 'kill ${PIDS[*]} 2>/dev/null; true' EXIT
echo "test-only-password" > "$WD/pw.txt"
"$B/step" ca init --name "Tideline Test CA" --dns localhost --dns 127.0.0.1 --address 127.0.0.1:19100 --provisioner sensors@tideline \
    --password-file "$WD/pw.txt" --provisioner-password-file "$WD/pw.txt" --deployment-type standalone > "$WD/init.txt" 2>&1 || { cat "$WD/init.txt"; exit 1; }
python3 - "$STEPPATH/config/ca.json" <<'PY'
import json, sys
p = sys.argv[1]; c = json.load(open(p))
for pr in c["authority"]["provisioners"]:
    pr["claims"] = {"defaultTLSCertDuration": "720h", "maxTLSCertDuration": "720h", "minTLSCertDuration": "5m"}
json.dump(c, open(p, "w"), indent=2)
PY
"$B/step-ca" "$STEPPATH/config/ca.json" --password-file "$WD/pw.txt" > "$WD/ca.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do curl -s --cacert "$STEPPATH/certs/root_ca.crt" https://127.0.0.1:19100/health 2>/dev/null | grep -q ok && break; sleep 0.2; done
FP=$("$B/step" certificate fingerprint "$STEPPATH/certs/root_ca.crt")
tok() { "$B/step" ca token "$1" "${@:2}" --ca-url https://127.0.0.1:19100 --root "$STEPPATH/certs/root_ca.crt" --provisioner sensors@tideline --password-file "$WD/pw.txt" 2>/dev/null; }
reg() { local n=$1; shift; (cd "$WD" && HOME=$HOME_SENSOR "$PS" -NoProfile -File "$REG" "$@" > "$WD/$n.txt" 2>&1; echo $? > "$WD/$n.exit"); }
rc() { cat "$WD/$1.exit"; }
CFG=$HOME_SENSOR/.config/webinventory

echo "=== enroll with a one-time token"
T=$(tok wi-reg01 --san urn:tideline:sensor:wi-reg01)
reg enroll -Token "$T"
mode=$(stat -c %a "$CFG/tideline-sensor.pfx" 2>/dev/null); dmode=$(stat -c %a "$CFG" 2>/dev/null)
rootfp=$("$B/step" certificate fingerprint "$CFG/tideline-root.crt" 2>/dev/null)
if [ "$(rc enroll)" = 0 ] && [ "$mode" = 600 ] && [ "$dmode" = 700 ] && [ "$rootfp" = "$FP" ] && grep -q '"sensor": "wi-reg01"' "$CFG/tideline-sensor.json"; then
    ok "enrolled: PFX mode $mode (folder $dmode), pinned root = the CA's ($FP), $(grep -o 'valid until [^ ]* [^ ]*' "$WD/enroll.txt")"; else bad "enroll (exit $(rc enroll), mode $mode/$dmode)" "$WD/enroll.txt"; fi
openssl pkcs12 -in "$CFG/tideline-sensor.pfx" -passin pass: -nokeys -clcerts 2>/dev/null | openssl x509 -noout -ext subjectAltName,extendedKeyUsage > "$WD/cert.txt" 2>&1
openssl pkcs12 -in "$CFG/tideline-sensor.pfx" -passin pass: -nocerts -nodes 2>/dev/null | openssl ec -noout -text 2>/dev/null | grep -q 'prime256v1' && grep -q 'URI:urn:tideline:sensor:wi-reg01' "$WD/cert.txt" && grep -q 'Client Authentication' "$WD/cert.txt" \
    && ok "certificate: ECDSA P-256 key, URI:urn:tideline:sensor:wi-reg01, client authentication" || bad "certificate contents" "$WD/cert.txt"

echo "=== the same token again (one-time), an expired token, a token without a sensor name"
reg again -Token "$T"
[ "$(rc again)" = 2 ] && grep -q 'the CA refused' "$WD/again.txt" && ok "token reuse refused by the CA: $(grep -o 'HTTP [0-9]*: .*' "$WD/again.txt" | head -1 | cut -c1-90)" || bad "token reuse" "$WD/again.txt"
python3 - "$T" > "$WD/expired.tok" <<'PY'
import base64, json, sys
h, p, s = sys.argv[1].split(".")
d = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))); d["exp"] = 1000
print(h + "." + base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=") + "." + s)
PY
reg expired -Token "$(cat "$WD/expired.tok")"
[ "$(rc expired)" = 1 ] && grep -q 'expired' "$WD/expired.txt" && ok "expired token refused before contacting the CA" || bad "expired token" "$WD/expired.txt"
reg nourn -Token "$(tok wi-reg02)"
[ "$(rc nourn)" = 1 ] && grep -q 'exactly one urn:tideline:sensor' "$WD/nourn.txt" && ok "token without urn:tideline:sensor:<id> refused" || bad "token without urn" "$WD/nourn.txt"
python3 - "$(tok wi-reg03 --san urn:tideline:sensor:wi-reg03)" > "$WD/badfp.tok" <<'PY'
import base64, json, sys
h, p, s = sys.argv[1].split(".")
d = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))); d["sha"] = "0" * 64
print(h + "." + base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=") + "." + s)
PY
reg badfp -Token "$(cat "$WD/badfp.tok")"
[ "$(rc badfp)" = 2 ] && grep -qi 'fingerprint\|root' "$WD/badfp.txt" && ok "root fingerprint not the token's: refused ($(grep -o 'FAILED: .*' "$WD/badfp.txt" | cut -c1-80))" || bad "fingerprint" "$WD/badfp.txt"

echo "=== show; renew when not due; renew now (new key, same sensor)"
reg show -Show
[ "$(rc show)" = 0 ] && grep -q 'sensor wi-reg01' "$WD/show.txt" && ok "-Show lists the certificate and the pinned root" || bad "show" "$WD/show.txt"
reg notdue -Renew
[ "$(rc notdue)" = 0 ] && grep -q 'renewal due after' "$WD/notdue.txt" && ok "-Renew before a third of the lifetime is left: nothing done" || bad "renew not due" "$WD/notdue.txt"
k1=$(openssl pkcs12 -in "$CFG/tideline-sensor.pfx" -passin pass: -nocerts -nodes 2>/dev/null | openssl ec -pubout 2>/dev/null | sha256sum | cut -c1-16)
t1=$(python3 -c "import json; print(json.load(open('$CFG/tideline-sensor.json'))['thumbprint'])")
reg renew -Renew -Force
k2=$(openssl pkcs12 -in "$CFG/tideline-sensor.pfx" -passin pass: -nocerts -nodes 2>/dev/null | openssl ec -pubout 2>/dev/null | sha256sum | cut -c1-16)
t2=$(python3 -c "import json; print(json.load(open('$CFG/tideline-sensor.json'))['thumbprint'])")
openssl pkcs12 -in "$CFG/tideline-sensor.pfx" -passin pass: -nokeys -clcerts 2>/dev/null | openssl x509 -noout -ext subjectAltName > "$WD/cert2.txt" 2>&1
[ "$(rc renew)" = 0 ] && [ "$k1" != "$k2" ] && [ "$t1" != "$t2" ] && grep -q 'URI:urn:tideline:sensor:wi-reg01' "$WD/cert2.txt" && [ "$(stat -c %a "$CFG/tideline-sensor.pfx")" = 600 ] \
    && ok "renewed through step-ca rekey: new key ($k1 -> $k2), new certificate, same sensor name, PFX still 0600" || bad "renew" "$WD/renew.txt"

echo "=== ship with what enrollment saved (no certificate or CA options)"
"$B/step" ca certificate localhost "$WD/srv.crt" "$WD/srv.key" --san localhost --san 127.0.0.1 --provisioner sensors@tideline --password-file "$WD/pw.txt" \
    --ca-url https://127.0.0.1:19100 --root "$STEPPATH/certs/root_ca.crt" > "$WD/srv.txt" 2>&1
cat "$STEPPATH/certs/root_ca.crt" "$STEPPATH/certs/intermediate_ca.crt" > "$WD/client-ca.pem"
python3 "$W/lab/tideline_mock.py" serve --port 18960 --cert "$WD/srv.crt" --key "$WD/srv.key" --client-ca "$WD/client-ca.pem" --data "$WD/mock" \
    --schemas "$W/schemas" --sensors wi-reg01 --ready "$WD/mock.ready" > "$WD/mock.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -f "$WD/mock.ready" ] && break; sleep 0.1; done
(cd "$WD" && HOME=$HOME_SENSOR "$PS" -NoProfile -File "$INV" -Target 127.0.0.1:18080 -OutputDir "$WD/out" -NoProgress -Quiet -ShipTo https://localhost:18960 > "$WD/scan.txt" 2>&1; echo $? > "$WD/scan.exit")
[ "$(rc scan)" = 0 ] && grep -q 'delivered.*as sensor wi-reg01' "$WD/scan.txt" && python3 "$W/tests/v26/received.py" --data "$WD/mock" --run-json "$(ls "$WD"/out/*_run.json)" > "$WD/recv.txt" \
    && ok "scan shipped with the enrolled certificate and pinned root: $(cut -c1-110 "$WD/recv.txt")" || bad "ship with enrolled cert" "$WD/scan.txt"
echo "register scenario: $pass passed, $fail failed"
[ $fail = 0 ]
