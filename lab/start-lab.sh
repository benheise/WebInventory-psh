#!/usr/bin/env bash
# Starts the full benchmark/regression lab in the foreground (run it in the background; Ctrl+C or stop-lab.sh stops it).
#   start-lab.sh <certdir> [farm-hosts=50] [tarpit-hosts=20] [one-way-latency-ms=10]
# Fixtures: lab.py (18080-18096, 18021/18022/18306 banners, 18087 tarpit, 18097 slow app), faketls.py 18447,
# openssl s_server 18445 (TLS1.0 + anon DH, FortiGate cert) and 18446 (TLS1.0-1.2, RSA-AES128-SHA only),
# farm.py (127.0.10.x web farm, 127.0.11.x tarpits), latproxy.py (127.0.20.x = farm + latency),
# iptables DROP on 127.0.31.0/24 (filtered ports: SYN goes unanswered).
set -u
CERTS=${1:?certdir}; FARM=${2:-50}; PITS=${3:-20}; LAT=${4:-10}
HERE=$(cd "$(dirname "$0")" && pwd)
grep -q 'app1.lab.test' /etc/hosts || echo '127.0.0.1 app1.lab.test app2.lab.test' >> /etc/hosts
iptables -C INPUT -d 127.0.31.0/24 -p tcp --syn -j DROP 2>/dev/null || iptables -I INPUT -d 127.0.31.0/24 -p tcp --syn -j DROP
pids=()
python3 "$HERE/lab.py" "$CERTS" & pids+=($!)
python3 "$HERE/faketls.py" "$CERTS/weak.pem" 18447 & pids+=($!)
openssl s_server -quiet -accept 18445 -cert "$CERTS/weak.pem" -key "$CERTS/weak.key" -tls1 \
    -cipher 'ECDHE-RSA-AES128-SHA:ADH-AES128-SHA:@SECLEVEL=0' -www >/dev/null 2>&1 & pids+=($!)
openssl s_server -quiet -accept 18446 -cert "$CERTS/lab.pem" -key "$CERTS/lab.key" -no_tls1_3 \
    -cipher 'AES128-SHA:@SECLEVEL=0' -www >/dev/null 2>&1 & pids+=($!)
python3 "$HERE/farm.py" "$CERTS" "$FARM" "$PITS" & pids+=($!)
python3 "$HERE/latproxy.py" "$LAT" "$FARM" 19080 19081 19082 19443 & pids+=($!)
trap 'kill ${pids[*]} 2>/dev/null; iptables -D INPUT -d 127.0.31.0/24 -p tcp --syn -j DROP 2>/dev/null; exit 0' INT TERM
wait
