#!/usr/bin/env bash
# Runs a command with the lab up, then tears the lab down (so no lab process outlives the job).
#   with-lab.sh <certdir> <command> [args...]
# Environment: FARM_HOSTS (50), FARM_PITS_N (20), LAT_MS (10 = one-way, i.e. 20 ms RTT via latproxy)
set -u
CERTS=${1:?certdir}; shift
HERE=$(cd "$(dirname "$0")" && pwd)
"$HERE/start-lab.sh" "$CERTS" "${FARM_HOSTS:-50}" "${FARM_PITS_N:-20}" "${LAT_MS:-10}" > "${LAB_LOG:-/dev/null}" 2>&1 &
LAB=$!
for i in $(seq 1 100); do
    n=$(ss -ltn | grep -c ':1[89][0-9][0-9][0-9] ')
    [ "$n" -ge 400 ] && break
    sleep 0.2
done
sleep 0.5
"$@"; rc=$?
kill -TERM $LAB 2>/dev/null; wait $LAB 2>/dev/null
"$HERE/stop-lab.sh" >/dev/null 2>&1
exit $rc
