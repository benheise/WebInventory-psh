#!/usr/bin/env bash
# Scenario tests for Invoke-WebInventory.ps1 against the local lab. Usage: scenarios.sh <pwsh> <script> <workdir>
PWSH="$1"; SCRIPT="$2"; WORK="$3"
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1 (got '$2', want '$3')"; fail=$((fail+1)); fi; }
run() { (cd "$WORK" && "$PWSH" -NoProfile -File "$SCRIPT" "$@" > last.out 2>&1); echo $?; }
newdir() { rm -rf "$WORK"; mkdir -p "$WORK"; }

newdir
rc=$(run -Target 127.0.0.1:18080 -Scope 10.0.0.0/8 -NoProgress)
check "scope violation refuses to start (exit 1)" "$rc" "1"
check "scope violation: no results CSV written" "$(ls "$WORK"/WebInventory_*.csv 2>/dev/null | wc -l)" "0"
check "scope violation logged" "$(grep -c '\[SCOPE\]' "$WORK"/*_error.log)" "1"

newdir
rc=$(run 127.0.0.1:18080,18999 10.9.9.9:80 -Scope 127.0.0.0/8 -DropOutOfScope -NoProgress -NoHtml)
check "-DropOutOfScope continues; drops are logged (exit 2)" "$rc" "2"
check "-DropOutOfScope scanned only in-scope host" "$(grep -c '10.9.9.9' "$WORK"/WebInventory_*.csv)" "0"

newdir
rc=$(run -Target 10.0.0.300 -NoProgress)
check "invalid target fails closed (exit 1)" "$rc" "1"
rc=$(run 10.0.0.300 127.0.0.1:18080 -SkipInvalidInput -NoProgress -NoHtml)
check "-SkipInvalidInput proceeds (exit 2: errors logged)" "$rc" "2"

newdir
rc=$(run '127.0.0.1,127.0.0.2' 127.0.0.0/30 '127.0.1-2.1-2' -Port 80,443 -Exclude 127.0.0.0,127.0.0.3 -ListTargets)
check "ListTargets exit 0" "$rc" "0"
check "expansion: comma list + CIDR + octets, minus exclusions, x2 ports" "$(grep -c ':80$\|:443$' "$WORK"/last.out)" "12"

newdir
rc=$(run -Target 10.0.0.0/8 -ListTargets)
check "MaxTargets guard (exit 1)" "$rc" "1"
rc=$(run -Target 10.0.0.0/15 -Port 80 -ListTargets -Force)
check "-Force overrides MaxTargets" "$rc" "0"

newdir
cat > "$WORK/weekly.psd1" <<'EOF'
@{
    Target    = @('127.0.0.1:18080,18443')
    TimeoutMs = 2000
    Tag       = 'FromConfig'
    NoHtml    = $true
}
EOF
rc=$(run -ConfigFile weekly.psd1 -NoProgress)
check "config-driven run (exit 0)" "$rc" "0"
check "config Tag applied" "$(grep -c 'FromConfig' "$WORK"/WebInventory_*.csv)" "2"
echo "@{ Tagg = 'x'; Target = '127.0.0.1' }" > "$WORK/bad.psd1"
rc=$(run -ConfigFile bad.psd1)
check "unknown config key refused (exit 1)" "$rc" "1"

newdir
# interrupt mid-run (tarpit + slow timeouts), then resume
(cd "$WORK" && timeout -s INT 6 "$PWSH" -NoProfile -File "$SCRIPT" -Target 127.0.0.1:18087,18080,18443,18022 -TimeoutMs 4000 -Threads 1 -MaxPerHost 1 -NoProgress > int.out 2>&1); rc=$?
prog=$(ls "$WORK"/WebInventory_*_progress.txt | head -1)
check "interrupted run leaves a progress file" "$( [ -f "$prog" ] && echo yes)" "yes"
done1=$(wc -l < "$prog")
rc=$(run -Target 127.0.0.1:18087,18080,18443,18022 -TimeoutMs 4000 -Threads 1 -MaxPerHost 1 -NoProgress -Resume "$prog")
check "resume completes (exit 0)" "$rc" "0"
check "resume finished all 4 checks" "$(wc -l < "$prog")" "4"
check "resume appended to the same CSV (header once)" "$(grep -c '"RunId","ScanTag"' "$WORK"/WebInventory_*.csv | head -1)" "1"
echo "      (checks done before interrupt: $done1)"

newdir
run -Target 127.0.0.1:18080 -NoProgress -NoHtml > /dev/null
sleep 1
rc=$(run -Target 127.0.0.1:18080,18443 -NoProgress -NoHtml -BaselineCsv auto)
check "baseline auto run (exit 0)" "$rc" "0"
check "delta shows the new HTTPS service" "$(grep -c '"NEW"' "$WORK"/*_delta.csv)" "1"

newdir
n=$(cd "$WORK" && "$PWSH" -NoProfile -Command "@(& '$SCRIPT' -Target 127.0.0.1:18080,18443 -PassThru -Quiet -NoProgress -NoHtml).Count" 2>/dev/null | tail -1)
check "-PassThru emits one object per row" "$n" "2"

newdir
rc=$(run -Target 127.0.0.1:18999 -NoProgress)
check "closed port only: exit 4 (nothing answered), nothing printed as a hit" "$rc:$(grep -c '^\[+\]' "$WORK"/last.out)" "4:0"
check "nothing answered is logged" "$(grep -c 'NOTHING ANSWERED' "$WORK"/*_run.log)" "1"
rc=$(run -Target no-such-host.invalid -NoProgress -NoHtml)
check "every target name unresolved: exit 4" "$rc" "4"
rc=$(run -Target '127.0.0.1:18080,18999' -NoProgress -NoHtml)
check "one service answers: exit 0 again" "$rc" "0"
rc=$(run -Target 127.0.0.1:18080 -DnsServer 127.0.0.1 -NoProgress)
check "-DnsServer without -Cname is refused (exit 1)" "$rc" "1"
rc=$(run -Target 127.0.0.1:18080 -CloudFile missing-ranges.json -NoProgress)
check "-CloudFile that does not exist is refused (exit 1)" "$rc" "1"

newdir
n=$(cd "$WORK" && "$PWSH" -NoProfile -Command "@(& '$SCRIPT' -Target 127.0.0.1:18080,18443 -ListTargets) -match ':184|:180' | Measure-Object | Select-Object -ExpandProperty Count" 2>/dev/null | tail -1)
check "PowerShell comma-split host:ports is re-joined" "$n" "2"
rc=$(cd "$WORK" && "$PWSH" -NoProfile -Command "& '$SCRIPT' -Target 10.0.3-5,7.1 -ListTargets; exit \$LASTEXITCODE" > last.out 2>&1; echo $?)
check "unquoted octet list fails closed instead of scanning 7.0.0.1" "$rc" "1"
rc=$(run 127.0.0.1:18080 -Treads 4 -ListTargets)
check "misspelled parameter is refused, not scanned" "$rc" "1"

# ---------------- v2.7 ----------------
jl() { ls "$WORK"/WebInventory_*[0-9].jsonl | head -1; }
col() {  # col <port> <column>: that row's value
    python3 -c 'import json,sys
for l in open(sys.argv[1]):
    r=json.loads(l)
    if str(r["Port"])==sys.argv[2]: print(r[sys.argv[3]] if r[sys.argv[3]] is not None else ""); break' "$(jl)" "$1" "$2"
}
newdir
UALOG="${LAB_UA_LOG:-/tmp/wi-lab-ua.log}"; : > "$UALOG"
rc=$(run -Target 127.0.0.1:18100,18101,18102,18103,18104,18105,18106,18107,18108 -ApiDocPaths -IdentifyPaths -VersionPaths -Options -ExplainFingerprint -UserAgent 'WI-UA-CHECK/2.7' -NoProgress -NoHtml)
check "v2.7 lab run completes (exit 0)" "$rc" "0"
check "Cloudflare block page -> WafBlocked:Cloudflare" "$(col 18100 Flags | grep -o 'WafBlocked:Cloudflare')" "WafBlocked:Cloudflare"
check "Akamai block page -> WafBlocked:Akamai" "$(col 18101 Flags | grep -o 'WafBlocked:Akamai')" "WafBlocked:Akamai"
check "BIG-IP ASM block page (HTTP 200) -> WafBlocked:F5" "$(col 18102 Flags | grep -o 'WafBlocked:F5')" "WafBlocked:F5"
check "Cloudflare 530 'error code: 1016' -> OriginDnsError" "$(col 18103 Flags | grep -o 'OriginDnsError')" "OriginDnsError"
check "-ApiDocPaths: OpenAPI, Swagger UI, GraphiQL and docker-compose found" "$(col 18104 ApiDocPaths)" "/openapi.json=openapi;/swagger-ui/index.html=swagger-ui;/graphiql=graphiql;/docker-compose.yml=docker-compose"
check "-ApiDocPaths: ApiDocsExposed and DockerFileExposed flags" "$(col 18104 Flags | grep -o 'ApiDocsExposed\|DockerFileExposed' | paste -sd, -)" "ApiDocsExposed,DockerFileExposed"
check "-ApiDocPaths: a site that answers 200 for every path gives no hit" "$(col 18105 ApiDocPaths)" ""
check "-ApiDocPaths: no WafBlocked on an ordinary 200 site" "$(col 18105 Flags | grep -c WafBlocked)" "0"
check "429s: the row's Notes say it was throttled" "$(col 18106 Notes | grep -c 'throttled: 0 timeouts, 0 resets')" "1"
check "429s: run.json sessions[].throttle counts them" "$(python3 -c 'import json,glob,sys; t=json.load(open(glob.glob(sys.argv[1]+"/*_run.json")[0]))["sessions"][-1]["throttle"]; print(t["http429"]>=3, t["throttledChecks"])' "$WORK")" "True 1"
check "every request to the recorder carries -UserAgent (main, favicon, robots, security.txt, 404, OPTIONS, -IdentifyPaths, -VersionPaths, -ApiDocPaths)" "$(cut -f3 "$UALOG" | sort -u | paste -sd'|' -)" "WI-UA-CHECK/2.7"
check "the recorder saw the -VersionPaths and -ApiDocPaths requests" "$(grep -c $'^GET\t/api/version\t\|^GET\t/openapi.json\t\|^OPTIONS\t/\t' "$UALOG")" "3"
check "Appliance: the iDRAC, with CentOS left in OsHint" "$(col 18108 Appliance)|$(col 18108 OsHint | grep -o CentOS | head -1)" "Dell iDRAC|CentOS"
check "Detections carry the rule ids behind them" "$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    r=json.loads(l)
    if str(r["Port"])=="18108": print(any("b:t-idrac" in (d.get("Rules") or "") for d in r["Detections"]))' "$(jl)")" "True"
check "-ExplainFingerprint: FP-MATCH per rule output and the RESULT line" "$(grep -c '^FP-MATCH builtin b:t-idrac title=Integrated Dell Remote Access Controller' "$WORK"/*_explain.log)|$(grep -c '^RESULT service Dell iDRAC conf=95 rules=b:t-idrac$' "$WORK"/*_explain.log)" "2|1"
check "run.json profile records apiDocPaths" "$(python3 -c 'import json,glob,sys; print(json.load(open(glob.glob(sys.argv[1]+"/*_run.json")[0]))["profile"]["apiDocPaths"])' "$WORK")" "True"

# companion rule packs are pinned (canonical SHA-256: CRLF and a BOM still verify; any other change is refused)
PK="${WORK}_pk"; rm -rf "$PK"; mkdir -p "$PK"; cp "$(dirname "$SCRIPT")"/Invoke-WebInventory.ps1 "$(dirname "$SCRIPT")"/WebInventory.rules.*.json "$PK/"
python3 - "$PK/WebInventory.rules.recog.json" <<'PY'
import sys; p=sys.argv[1]; b=open(p,'rb').read().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'); open(p,'wb').write(b'\xef\xbb\xbf'+b)
PY
newdir
rc=$(cd "$WORK" && "$PWSH" -NoProfile -File "$PK/Invoke-WebInventory.ps1" -Target 127.0.0.1:18080 -NoProgress -NoHtml > last.out 2>&1; echo $?)
check "a pack with CRLF line endings and a BOM still verifies and loads" "$(grep -c 'differs from the one this release' "$WORK"/*_error.log)|$(grep -c "rules 'recog'.*loaded" "$WORK"/*_run.log)" "0|1"
python3 - "$PK/WebInventory.rules.wappalyzer.json" <<'PY'
import sys; p=sys.argv[1]; s=open(p,encoding='utf-8').read(); i=s.index('"rules"'); open(p,'w',encoding='utf-8',newline='').write(s[:i]+'"x":"y",'+s[i:])
PY
newdir
rc=$(cd "$WORK" && "$PWSH" -NoProfile -File "$PK/Invoke-WebInventory.ps1" -Target 127.0.0.1:18080 -NoProgress -NoHtml > last.out 2>&1; echo $?)
check "a companion pack with one field added is refused and logged" "$(grep -c 'WebInventory.rules.wappalyzer.json differs from the one this release was built with' "$WORK"/*_error.log)|$(grep -c "rules 'wappalyzer'.*loaded" "$WORK"/*_run.log)" "1|0"
newdir
rc=$(cd "$WORK" && "$PWSH" -NoProfile -File "$PK/Invoke-WebInventory.ps1" -Target 127.0.0.1:18080 -AllowModifiedRules -NoProgress -NoHtml > last.out 2>&1; echo $?)
check "-AllowModifiedRules loads it, with a warning" "$(grep -c "rules 'wappalyzer'.*loaded" "$WORK"/*_run.log)|$(grep -c 'loaded because of -AllowModifiedRules' "$WORK"/*_run.log)" "1|1"
rm -rf "$PK"

echo "scenarios: $pass passed, $fail failed"
