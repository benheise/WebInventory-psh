#!/usr/bin/env bash
# Stops everything start-lab.sh started.
pkill -f '[l]ab/lab.py'; pkill -f '[f]aketls.py'; pkill -f '[f]arm.py'; pkill -f '[l]atproxy.py'
pkill -f 'openssl s_server -quiet -accept 1844[56]'
iptables -D INPUT -d 127.0.31.0/24 -p tcp --syn -j DROP 2>/dev/null
sed -i '/app1.lab.test/d' /etc/hosts
echo "lab stopped"
