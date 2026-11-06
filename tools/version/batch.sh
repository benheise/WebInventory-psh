#!/usr/bin/env bash
# runs every case x tag in cases.json (or the names given), removing each image afterwards to save disk
#   TAGKEY=<key>   use another tag list of each case (default: tags)
#   KEEP_IMAGES=1  keep the images (to scan the containers again later)
cd "$(dirname "$0")"
names="$*"
[ -z "$names" ] && names=$(python3 -c "import json;print(' '.join(c['name'] for c in json.load(open('cases.json'))))")
for n in $names; do
  for t in $(python3 -c "import json,os;print(' '.join(next(c for c in json.load(open('cases.json')) if c['name']=='$n').get(os.environ.get('TAGKEY','tags'),[])))"); do
    echo "=== $n $t $(date +%T)"
    timeout 1500 python3 vlab.py run --case "$n" --tag "$t" 2>&1 | tail -40
  done
  [ -n "$KEEP_IMAGES" ] && continue
  img=$(python3 -c "import json;print(next(c for c in json.load(open('cases.json')) if c['name']=='$n')['image'])")
  docker images --format '{{.Repository}}:{{.Tag}}' | grep -F "$img:" | xargs -r docker rmi -f >/dev/null 2>&1
  docker image prune -f >/dev/null 2>&1
  df -h / | tail -1
done
echo "=== done $(date +%T)"
