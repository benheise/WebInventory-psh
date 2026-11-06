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
rc=$(run 10.0.0.300 127.0.0.1:18999 -SkipInvalidInput -NoProgress -NoHtml)
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
check "closed port only: exit 0, nothing printed as a hit" "$rc:$(grep -c '^\[+\]' "$WORK"/last.out)" "0:0"

newdir
n=$(cd "$WORK" && "$PWSH" -NoProfile -Command "@(& '$SCRIPT' -Target 127.0.0.1:18080,18443 -ListTargets) -match ':184|:180' | Measure-Object | Select-Object -ExpandProperty Count" 2>/dev/null | tail -1)
check "PowerShell comma-split host:ports is re-joined" "$n" "2"
rc=$(cd "$WORK" && "$PWSH" -NoProfile -Command "& '$SCRIPT' -Target 10.0.3-5,7.1 -ListTargets; exit \$LASTEXITCODE" > last.out 2>&1; echo $?)
check "unquoted octet list fails closed instead of scanning 7.0.0.1" "$rc" "1"
rc=$(run 127.0.0.1:18080 -Treads 4 -ListTargets)
check "misspelled parameter is refused, not scanned" "$rc" "1"

echo "scenarios: $pass passed, $fail failed"
